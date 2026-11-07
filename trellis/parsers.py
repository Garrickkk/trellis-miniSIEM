"""Parsers: turn raw log lines into normalized Events.

Each parser has a `name`, a `can_parse(sample)` check used for auto-detecting
a file's format, and `parse_lines(lines)` which yields Events. Lines a parser
doesn't recognize are skipped, not errors: real logs are full of noise.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Iterable, Iterator
from urllib.parse import unquote_plus

from .event import Event

LOCAL_TZ = datetime.now().astimezone().tzinfo


# --------------------------------------------------------------------------
# Linux auth.log / secure (sshd, sudo, useradd, su)
# --------------------------------------------------------------------------

# Classic syslog: "Oct 31 23:59:01 web01 sshd[1234]: message"
SYSLOG_CLASSIC = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
# RFC 3339 syslog (default on Ubuntu 24.04+, Debian 12+):
# "2026-10-31T23:59:01.123456+07:00 web01 sshd[1234]: message"
SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

IP = r"(?P<ip>[0-9a-fA-F:.]+)"

# Every SSH pattern is anchored to the END of the message. The username is
# attacker-controlled and may contain spaces, so an attacker can log in as
# "x from 10.0.0.5 port 22" to plant a fake address in the line. sshd appends
# the real "from <ip> port <n>" after the username, so the last one is the
# only trustworthy one. (fail2ban had this exact class of bug.)
SSH_TAIL = rf" from {IP} port (?P<port>\d+)(?: ssh2)?(?: \[preauth\])?$"
SSH_METHOD = r"(?P<method>password|publickey|keyboard-interactive/pam|hostbased|none)"

# (event_type, regex) - checked in order, first match wins
AUTH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh_failed_login", re.compile(
        rf"^Failed {SSH_METHOD} for (?P<invalid>invalid user )?(?P<user>.*?){SSH_TAIL}")),
    ("ssh_invalid_user", re.compile(
        rf"^Invalid user (?P<user>.*?) from {IP}(?: port (?P<port>\d+))?(?: \[preauth\])?$")),
    # Accepted logins are for real accounts, whose names can't contain spaces,
    # so \S+ is safe here and the ": ED25519 SHA256:..." key suffix is allowed.
    ("ssh_login_success", re.compile(
        rf"^Accepted {SSH_METHOD} for (?P<user>\S+) from {IP} port (?P<port>\d+)"
        rf"(?: ssh2)?(?:: .*)?$")),
    ("ssh_max_auth_exceeded", re.compile(
        rf"^(?:error: )?maximum authentication attempts exceeded for "
        rf"(?:invalid user )?(?P<user>.*?){SSH_TAIL}")),
    # sudo writes "<user> : <reason> ; TTY=..." for refusals and failures, and
    # "<user> : TTY=..." for commands that actually ran. Refusals must be
    # checked first or they look like successful commands.
    ("sudo_not_allowed", re.compile(
        r"^\s*(?P<user>\S+) : (?P<reason>command not allowed|user NOT in sudoers|"
        r"user NOT authorized on host)\b")),
    ("sudo_attempts_exhausted", re.compile(
        r"^\s*(?P<user>\S+) : (?P<attempts>\d+) incorrect password attempts?\b")),
    ("sudo_command", re.compile(
        r"^\s*(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
        r"USER=(?P<target_user>\S+) ; (?:.*? ; )?COMMAND=(?P<command>.*)$")),
    ("sudo_auth_failure", re.compile(
        r"pam_unix\(sudo:auth\): authentication failure;.*?(?:ruser|user)=(?P<user>\S+)")),
    ("user_created", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("user_deleted", re.compile(r"delete user '(?P<user>[^']+)'")),
    ("group_member_added", re.compile(
        r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
    ("su_session", re.compile(
        r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<target_user>\S+?)"
        r"(?:\(uid=\d+\))? by (?P<user>\S*?)(?:\(uid=\d+\))?$")),
]

SUMMARIES = {
    "ssh_failed_login": "SSH login failed for {user} from {src_ip}",
    "ssh_invalid_user": "SSH attempt with non-existent user {user} from {src_ip}",
    "ssh_login_success": "SSH login succeeded for {user} from {src_ip}",
    "ssh_max_auth_exceeded": "Too many SSH auth attempts for {user} from {src_ip}",
    "sudo_command": "{user} ran as {target_user}: {command}",
    "sudo_auth_failure": "Wrong sudo password for {user}",
    "sudo_not_allowed": "{user} tried to use sudo without permission",
    "sudo_attempts_exhausted": "{user} gave up on sudo after {attempts} wrong passwords",
    "user_created": "New local user created: {user}",
    "user_deleted": "Local user deleted: {user}",
    "group_member_added": "{user} added to group {group}",
    "su_session": "{user} switched to {target_user} with su",
}


def _classic_timestamp(month: str, day: str, time: str, now: datetime | None = None) -> datetime:
    """Classic syslog lines have no year or timezone. Assume the current year
    in local time, and if that lands in the future (a December log read in
    January), it must have been last year."""
    now = now or datetime.now(LOCAL_TZ)
    # Walk back up to 4 years: "Feb 29" only exists in leap years, and a
    # December line read in January belongs to last year.
    for year in range(now.year, now.year - 5, -1):
        try:
            ts = datetime.strptime(f"{year} {month} {day} {time}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        ts = ts.replace(tzinfo=LOCAL_TZ)
        if ts <= now + timedelta(days=1):
            return ts
    raise ValueError(f"impossible syslog date: {month} {day}")


def _iso_timestamp(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Normalize what older Pythons' fromisoformat rejects: "+0700" offsets
    # and more than 6 fractional-second digits.
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    ts = datetime.fromisoformat(text)
    return ts if ts.tzinfo else ts.replace(tzinfo=LOCAL_TZ)


def _safe_parse(parse_line, lines: Iterable[str]) -> Iterator[Event]:
    """Run parse_line over lines, skipping any line that raises. Logs are
    written by many programs (and sometimes by attackers); one weird line
    must not stop the whole ingest."""
    for line in lines:
        try:
            ev = parse_line(line)
        except (ValueError, KeyError, TypeError, OverflowError):
            continue
        if ev:
            yield ev


class AuthLogParser:
    name = "auth"

    def can_parse(self, sample: list[str]) -> bool:
        syslog_lines = hits = 0
        for line in sample:
            m = SYSLOG_CLASSIC.match(line) or SYSLOG_ISO.match(line)
            if not m:
                continue
            syslog_lines += 1
            if re.match(r"(sshd|sudo|su|useradd|userdel|usermod|passwd|"
                        r"systemd-logind|CRON|cron|login|gpasswd)", m["proc"]):
                hits += 1
        # Mostly syslog-shaped, with at least one auth program in it
        return hits > 0 and syslog_lines >= max(len(sample) // 2, 1)

    def parse_line(self, line: str) -> Event | None:
        line = line.rstrip("\n")
        m = SYSLOG_ISO.match(line)
        if m:
            ts = _iso_timestamp(m["ts"])
        else:
            m = SYSLOG_CLASSIC.match(line)
            if not m:
                return None
            ts = _classic_timestamp(m["month"], m["day"], m["time"])

        msg = m["msg"]
        for event_type, pattern in AUTH_PATTERNS:
            pm = pattern.search(msg)
            if not pm:
                continue
            fields = {k: v for k, v in pm.groupdict().items() if v is not None}
            src_ip = fields.pop("ip", "")
            user = fields.pop("user", "")
            if fields.pop("invalid", None):
                fields["invalid_user"] = True
            fields["process"] = m["proc"]
            summary = SUMMARIES[event_type].format(
                user=user or "?", src_ip=src_ip or "?",
                target_user=fields.get("target_user", "?"),
                command=fields.get("command", "?"), group=fields.get("group", "?"),
                attempts=fields.get("attempts", "?"))
            return Event(timestamp=ts, source=self.name, event_type=event_type,
                         host=m["host"], src_ip=src_ip, user=user,
                         message=summary, raw=line, extra=fields)
        return None

    def parse_lines(self, lines: Iterable[str]) -> Iterator[Event]:
        yield from _safe_parse(self.parse_line, lines)


# --------------------------------------------------------------------------
# Web server access logs (nginx / Apache "combined" format)
# --------------------------------------------------------------------------

# 203.0.113.9 - - [31/Oct/2026:23:59:01 +0700] "GET /x HTTP/1.1" 404 153 "-" "curl/8.5"
# Quoted fields allow backslash escapes: Apache logs a " inside the URL as \"
# (nginx uses \x22). Without this, a request containing a quote would fail to
# parse and silently vanish, which is an easy way to hide an attack.
QUOTED = r'(?:[^"\\]|\\.)*'
COMBINED = re.compile(
    rf'^(?P<ip>\S+) \S+ (?P<authuser>\S+) \[(?P<ts>[^\]]+)\] '
    rf'"(?P<request>{QUOTED})" (?P<status>\d{{3}}) (?P<bytes>\d+|-)'
    rf'(?: "(?P<referer>{QUOTED})" "(?P<ua>{QUOTED})")?'
)
LOG_ESCAPE = re.compile(r'\\x([0-9a-fA-F]{2})|\\(.)')


def unescape_log(text: str) -> str:
    """Undo web-server log escaping: \x22 -> ", \" -> ", \\ -> \\."""
    return LOG_ESCAPE.sub(lambda m: chr(int(m[1], 16)) if m[1] else m[2], text)


def decode_url(path: str) -> str:
    """URL-decode up to 3 times. Attackers encode payloads (%27 for ', or
    double-encoded %2527) to slip past filters that only look for the plain
    text; detection rules should match the decoded form."""
    for _ in range(3):
        decoded = unquote_plus(path)
        if decoded == path:
            break
        path = decoded
    return path


class WebAccessLogParser:
    name = "web"

    def __init__(self, host: str = "web"):
        self.host = host

    def can_parse(self, sample: list[str]) -> bool:
        hits = sum(1 for line in sample if COMBINED.match(line))
        return hits > 0 and hits >= len(sample) // 2

    def parse_line(self, line: str) -> Event | None:
        line = line.rstrip("\n")
        m = COMBINED.match(line)
        if not m:
            return None
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
        request = unescape_log(m["request"])
        parts = request.split(" ")
        if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
            # a raw space inside the path is invalid HTTP but attackers send it
            method, path, protocol = parts[0], " ".join(parts[1:-1]), parts[-1]
        elif len(parts) == 2:
            method, path, protocol = parts[0], parts[1], ""
        else:  # malformed request line - common with scanners, keep it
            method, path, protocol = "", request, ""
        status = int(m["status"])
        extra = {
            "method": method, "path": path, "path_decoded": decode_url(path),
            "protocol": protocol,
            "status": status, "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
            "referer": unescape_log(m["referer"] or ""),
            "user_agent": unescape_log(m["ua"] or ""),
        }
        user = "" if m["authuser"] == "-" else m["authuser"]
        return Event(timestamp=ts, source=self.name, event_type="http_request",
                     host=self.host, src_ip=m["ip"], user=user,
                     message=f"{method} {path} -> {status}", raw=line, extra=extra)

    def parse_lines(self, lines: Iterable[str]) -> Iterator[Event]:
        yield from _safe_parse(self.parse_line, lines)


# --------------------------------------------------------------------------
# GrapeVine scan results (github.com/Garrickkk/GrapeVine)
# --------------------------------------------------------------------------

GV_HEADER = re.compile(r"^Scanning (?P<target>\S+?)(?: \((?P<ip>[^)]+)\))?: \d+ port")
GV_PORT = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open|closed|filtered)"
    r"(?:\s+(?P<service>\S+))?(?:\s+(?P<version>.+))?$"
)


class GrapeVineParser:
    """Reads GrapeVine's normal text output, saved with
    `python grapevine.py <target> > scan.txt`. Also accepts JSON lines
    ({"target": ..., "port": ..., "state": ..., "service": ...}) so a future
    GrapeVine --json flag works without changes here.

    GrapeVine's output has no timestamp, so the scan time comes from the
    caller (the file's modification time when ingesting a file)."""

    name = "grapevine"
    snapshot = True   # each file is a complete scan, rewritten rather than appended

    def __init__(self, scan_time: datetime | None = None, scan_id: str = ""):
        self.scan_time = scan_time
        # Identifies one scan run (the engine uses file path + modification
        # time). The new-open-port rule uses it to tell the first scan of a
        # host (the baseline) from later ones without comparing timestamps.
        self.scan_id = scan_id

    def can_parse(self, sample: list[str]) -> bool:
        if any(GV_HEADER.match(line) for line in sample):
            return True
        try:
            first = json.loads(sample[0]) if sample else None
        except (ValueError, IndexError):
            return False
        return isinstance(first, dict) and "port" in first and "state" in first

    def parse_lines(self, lines: Iterable[str]) -> Iterator[Event]:
        ts = self.scan_time or datetime.now(LOCAL_TZ)
        base_id = self.scan_id or ts.isoformat()
        target = ""
        self._scan_no = 0
        for line in lines:
            line = line.rstrip("\n")
            stripped = line.strip()
            if stripped.startswith("{"):
                yield from self._json_line(stripped, ts)
                continue
            header = GV_HEADER.match(stripped)
            if header:
                target = header["ip"] or header["target"]
                self._scan_no += 1
                continue
            m = GV_PORT.match(stripped)
            if not m or not target:
                continue
            port, state = int(m["port"]), m["state"]
            service = (m["service"] or "").rstrip("?")
            yield self._event(ts, target, port, m["proto"], state, service,
                              (m["version"] or "").strip(),
                              guessed=(m["service"] or "").endswith("?"), raw=line,
                              scan_id=f"{base_id}#{self._scan_no}")

    def _json_line(self, line: str, default_ts: datetime) -> Iterator[Event]:
        try:
            d = json.loads(line)
            if not isinstance(d, dict) or "port" not in d or "state" not in d:
                return
            ts = _iso_timestamp(d["timestamp"]) if d.get("timestamp") else default_ts
            port = int(d["port"])
        except (ValueError, TypeError):
            return  # malformed line: skip it, don't crash the ingest
        yield self._event(ts, str(d.get("target") or d.get("ip") or ""), port,
                          str(d.get("proto", "tcp")), str(d["state"]),
                          str(d.get("service", "")), str(d.get("version", "")),
                          guessed=False, raw=line,
                          scan_id=str(d.get("scan_id") or self.scan_id or ts.isoformat()))

    def _event(self, ts, target, port, proto, state, service, version, guessed, raw,
               scan_id) -> Event:
        label = f"{port}/{proto} {state}" + (f" ({service})" if service else "")
        return Event(
            timestamp=ts, source=self.name, event_type=f"port_{state}",
            host=target, message=f"{target}: {label}", raw=raw,
            extra={"target": target, "port": port, "proto": proto, "state": state,
                   "service": service, "version": version, "service_guessed": guessed,
                   "scan_id": scan_id},
        )


PARSERS = {"auth": AuthLogParser, "web": WebAccessLogParser, "grapevine": GrapeVineParser}


def detect_parser(sample: list[str]):
    """Guess a file's format from its first lines. Returns a parser instance
    or None. GrapeVine is checked first because its header is unambiguous."""
    sample = [line for line in sample if line.strip()]
    for cls in (GrapeVineParser, AuthLogParser, WebAccessLogParser):
        parser = cls()
        if parser.can_parse(sample):
            return parser
    return None
