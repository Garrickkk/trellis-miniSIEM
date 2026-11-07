"""Regression tests for the bugs found in the November 2026 review.

Every bug has at least one test here that failed before its fix. Some
parametrized cases are controls instead: legitimate input that must keep
working, to check a fix didn't over-correct (e.g. real SQL injection is still
caught after the "C#" false positive was removed)."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from trellis.engine import Pipeline
from trellis.event import Event
from trellis.parsers import AuthLogParser, WebAccessLogParser
from trellis.rules import Detector, load_rules
from trellis.storage import Storage
from trellis.web import create_app

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
SYSLOG = "2026-10-31T11:00:00+07:00 web01 "


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "t.db")


def ingest(db, *files):
    store = Storage(db)
    try:
        return Pipeline(store, RULES).ingest(files)
    finally:
        store.close()


def alert_ids(db, rule_id=""):
    store = Storage(db)
    try:
        return [a["rule_id"] for a in store.list_alerts(rule_id=rule_id, limit=500)]
    finally:
        store.close()


def scan(path: Path, ports: list[int], mtime: int) -> Path:
    lines = ["Scanning web01 (10.0.0.10): 1024 port(s)", ""]
    lines += [f"{p}/tcp    open      {'mysql' if p == 3306 else 'unknown'}" for p in ports]
    path.write_text("\n".join(lines) + "\n")
    os.utime(path, (mtime, mtime))
    return path


# ---- parsers -----------------------------------------------------------------

def test_ssh_username_cannot_spoof_source_ip():
    """An attacker logging in as 'x from 10.0.0.5 port 22' must not get the
    attack blamed on 10.0.0.5."""
    ev = AuthLogParser().parse_line(
        SYSLOG + "sshd[1]: Failed password for invalid user x from 10.0.0.5 port 22 "
        "from 203.0.113.9 port 4444 ssh2")
    assert ev.src_ip == "203.0.113.9"
    assert ev.user == "x from 10.0.0.5 port 22"

    ev = AuthLogParser().parse_line(
        SYSLOG + "sshd[1]: Invalid user y from 10.0.0.5 from 203.0.113.9 port 4444")
    assert ev.src_ip == "203.0.113.9"


def test_ssh_preauth_and_key_suffixes_still_parse():
    a = AuthLogParser()
    ev = a.parse_line(SYSLOG + "sshd[1]: error: maximum authentication attempts exceeded "
                      "for invalid user admin from 1.2.3.4 port 5555 ssh2 [preauth]")
    assert ev.event_type == "ssh_max_auth_exceeded" and ev.src_ip == "1.2.3.4"
    ev = a.parse_line(SYSLOG + "sshd[1]: Accepted publickey for deploy from 10.0.0.5 "
                      "port 50122 ssh2: ED25519 SHA256:abcdef")
    assert ev.event_type == "ssh_login_success" and ev.user == "deploy"
    ev = a.parse_line(SYSLOG + "sshd[1]: Failed none for invalid user x from 1.2.3.4 port 1 ssh2")
    assert ev.event_type == "ssh_failed_login"


@pytest.mark.parametrize("msg, expected", [
    ("bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
     "sudo_not_allowed"),
    ("bob : command not allowed ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
     "sudo_not_allowed"),
    ("bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
     "sudo_attempts_exhausted"),
    ("bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls",
     "sudo_command"),
    ("bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; ENV=A=b ; COMMAND=/bin/ls",
     "sudo_command"),
])
def test_refused_sudo_is_not_a_successful_command(msg, expected):
    ev = AuthLogParser().parse_line(SYSLOG + "sudo: " + msg)
    assert ev.event_type == expected


def test_unauthorized_sudo_rule_fires(db, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(SYSLOG + "sudo: bob : user NOT in sudoers ; TTY=pts/0 ; "
                   "PWD=/home/bob ; USER=root ; COMMAND=/bin/bash\n")
    ingest(db, log)
    rules = alert_ids(db)
    assert "sudo-not-allowed" in rules
    assert "sudo-root-shell" not in rules   # it was refused, nobody got a shell


def test_apache_escaped_quote_is_not_dropped(db, tmp_path):
    """A request containing a double quote must parse, and the SQLi inside
    must still be detected."""
    log = tmp_path / "access.log"
    log.write_text(r'192.0.2.1 - - [31/Oct/2026:10:00:00 +0700] '
                   r'"GET /p?id=1\" OR 1=1-- HTTP/1.1" 200 10 "-" "curl/8"' "\n")
    result = ingest(db, log)
    assert result.events == 1
    assert "web-sql-injection" in alert_ids(db)


def test_nginx_hex_escapes_are_decoded():
    ev = WebAccessLogParser().parse_line(
        r'1.2.3.4 - - [31/Oct/2026:10:00:00 +0700] "GET /a?q=\x22x HTTP/1.1" 200 1 "-" "a\x22b"')
    assert ev.extra["path_decoded"] == '/a?q="x'
    assert ev.extra["user_agent"] == 'a"b'


def test_one_bad_line_does_not_crash_ingest(db, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Oct 31 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "Feb 30 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "Oct 31 10:00:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 23 ssh2\n")
    assert ingest(db, log).events == 2   # the impossible date is skipped


def test_feb_29_lands_in_a_leap_year():
    ev = AuthLogParser().parse_line(
        "Feb 29 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")
    assert ev is not None and ev.timestamp.month == 2 and ev.timestamp.day == 29


def test_iso_offset_without_colon_and_nanoseconds():
    ev = AuthLogParser().parse_line(
        "2026-10-31T11:00:00.123456789+0700 web01 sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2")
    assert ev.timestamp.utcoffset() == timedelta(hours=7)


# ---- rules -------------------------------------------------------------------

@pytest.mark.parametrize("path, is_sqli", [
    ("/search?q=C%23", False),          # searching for the C# language
    ("/blog/rock-and-roll--", False),
    ("/p?id=1%27%20OR%20%271%27%3D%271", True),
    ("/p?id=1%20OR%201%3D1", True),
    ("/login?user=admin%27--", True),
])
def test_sqli_rule_precision(db, tmp_path, path, is_sqli):
    log = tmp_path / "access.log"
    log.write_text(f'10.0.0.5 - - [31/Oct/2026:10:00:00 +0700] "GET {path} HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n')
    ingest(db, log)
    assert ("web-sql-injection" in alert_ids(db)) is is_sqli


def test_root_shell_rule_ignores_ls_dash_i(db, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(SYSLOG + "sudo: deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/ls -i\n")
    ingest(db, log)
    assert "sudo-root-shell" not in alert_ids(db)


# ---- engine: suppression and GrapeVine baselines -----------------------------

def test_suppression_survives_separate_runs(db, tmp_path):
    """'Remind at most once a week' must hold even when each day's scan is
    ingested by a separate run of the program."""
    day1 = scan(tmp_path / "mon.txt", [3306], mtime=1_000_000)
    day2 = scan(tmp_path / "tue.txt", [3306], mtime=1_000_000 + 86400)
    ingest(db, day1)
    ingest(db, day2)
    assert alert_ids(db, "risky-service-exposed") == ["risky-service-exposed"]


def test_closed_alert_is_not_reopened_by_suppression(db, tmp_path):
    ingest(db, scan(tmp_path / "a.txt", [3306], mtime=1_000_000))
    store = Storage(db)
    store.set_alert_status(store.list_alerts()[0]["id"], "closed")
    store.close()
    ingest(db, scan(tmp_path / "b.txt", [3306], mtime=1_000_000 + 60))
    assert len(alert_ids(db, "risky-service-exposed")) == 2   # a fresh alert


def test_scan_file_overwritten_in_place(db, tmp_path):
    """`grapevine ... > scans/today.txt` every day reuses the same file
    (same inode). Each rewrite is a whole new scan."""
    f = scan(tmp_path / "today.txt", [22, 80], mtime=1_000_000)
    ingest(db, f)
    old_size = f.stat().st_size
    # Truncate + rewrite, like a shell redirect. The new scan must be at least
    # as long as the old one: a shorter file looked "truncated" and was
    # re-read by luck, which hid the bug.
    with open(f, "w") as fh:
        fh.write("Scanning web01 (10.0.0.10): 1024 port(s)\n\n"
                 "22/tcp    open      unknown\n80/tcp    open      unknown\n"
                 "4444/tcp  open      unknown\n")
    os.utime(f, (1_000_000 + 86400,) * 2)
    assert f.stat().st_size > old_size
    result = ingest(db, f)
    assert result.events == 3
    assert alert_ids(db, "new-open-port") == ["new-open-port"]
    assert ingest(db, f).events == 0    # unchanged file: nothing re-read


def test_scans_with_identical_timestamps(db, tmp_path):
    base = scan(tmp_path / "base.txt", [22], mtime=5000)
    later = scan(tmp_path / "later.txt", [22, 4444], mtime=5000)
    ingest(db, base, later)
    assert alert_ids(db, "new-open-port") == ["new-open-port"]


def test_baseline_scan_never_alerts_on_new_ports(db, tmp_path):
    ingest(db, scan(tmp_path / "first.txt", [22, 80, 443, 3306], mtime=5000))
    assert alert_ids(db, "new-open-port") == []


def test_malformed_grapevine_json_is_skipped(db, tmp_path):
    f = tmp_path / "scan.jsonl"
    f.write_text('{"target": "10.0.0.10", "port": 22, "state": "open"}\n'
                 '{"target": "10.0.0.10", "port": "abc", "state": "open"}\n'
                 '[1, 2, 3]\n')
    assert ingest(db, f).events == 1


def test_detector_sweep_forgets_old_groups(db):
    store = Storage(db)
    det = Detector(RULES, store)
    t0 = datetime(2026, 10, 31, tzinfo=timezone.utc)
    for i in range(50):   # 50 different IPs, one failed login each
        det.process(Event(t0, "auth", "ssh_failed_login", src_ip=f"198.51.100.{i}", user="root"))
    assert len(det.windows) > 0
    det.process(Event(t0 + timedelta(days=1), "auth", "http_request", src_ip="1.1.1.1"))
    det.sweep()
    assert len(det.windows) == 0
    store.close()


# ---- storage -----------------------------------------------------------------

def test_search_treats_wildcards_literally(db, tmp_path):
    log = tmp_path / "access.log"
    log.write_text('1.2.3.4 - - [31/Oct/2026:10:00:00 +0700] "GET /a_b HTTP/1.1" 200 1 "-" "x"\n'
                   '1.2.3.4 - - [31/Oct/2026:10:00:01 +0700] "GET /axb HTTP/1.1" 200 1 "-" "x"\n')
    ingest(db, log)
    store = Storage(db)
    assert [r["message"] for r in store.search_events(q="a_b")] == ["GET /a_b -> 200"]
    assert store.search_events(q="100%") == []
    store.close()


def test_old_database_is_migrated(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE file_state (path TEXT PRIMARY KEY, inode INTEGER, offset INTEGER NOT NULL)")
    conn.commit()
    conn.close()
    store = Storage(path)
    store.set_file_state("/x", 1, 2, 3)
    assert store.get_file_state("/x") == (1, 2, 3)
    store.close()


# ---- web ---------------------------------------------------------------------

@pytest.fixture
def client(db, tmp_path):
    log = tmp_path / "access.log"
    log.write_text('6.6.6.6 - - [31/Oct/2026:10:00:00 +0700] "GET /.env HTTP/1.1" '
                   '404 1 "-" "<script>alert(1)</script> nikto"\n')
    ingest(db, log)
    return create_app(db, RULES).test_client()


def test_bad_page_number_is_not_a_500(client):
    assert client.get("/events?page=abc").status_code == 200
    assert client.get("/events?page=-5").status_code == 200


@pytest.mark.parametrize("origin, ok", [
    ("http://localhost", True),
    ("http://localhost:50000", False),   # used to pass a prefix check
    ("http://localhost.evil.example", False),
    ("https://localhost", False),
    ("http://evil.example", False),
])
def test_status_change_requires_same_origin(client, origin, ok):
    r = client.post("/alerts/1/status", data={"status": "closed"}, headers={"Origin": origin})
    assert (r.status_code == 302) is ok


@pytest.mark.parametrize("target", ["https://evil.example/", "//evil.example/", "/\\evil.example"])
def test_no_open_redirect(client, target):
    r = client.post("/alerts/1/status", data={"status": "open", "next": target},
                    headers={"Origin": "http://localhost"})
    assert r.headers["Location"].endswith("/alerts/1")


def test_log_content_is_html_escaped(client):
    """Attackers control log text; it must never render as HTML."""
    for page in ("/events", "/alerts/1", "/"):
        html = client.get(page).get_data(as_text=True)
        assert "<script>alert(1)</script>" not in html
