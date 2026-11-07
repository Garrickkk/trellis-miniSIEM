"""Parser tests: raw log lines in, normalized Events out."""

from datetime import datetime

from trellis.parsers import (AuthLogParser, GrapeVineParser, WebAccessLogParser,
                              decode_url, detect_parser)


class TestAuthLogParser:
    def setup_method(self):
        self.p = AuthLogParser()

    def test_iso_failed_password(self):
        ev = self.p.parse_line(
            "2026-10-31T11:02:10+07:00 web01 sshd[4410]: "
            "Failed password for invalid user admin from 203.0.113.45 port 40011 ssh2")
        assert ev.event_type == "ssh_failed_login"
        assert ev.src_ip == "203.0.113.45"
        assert ev.user == "admin"
        assert ev.host == "web01"
        assert ev.extra["invalid_user"] is True
        assert ev.timestamp.year == 2026 and ev.timestamp.hour == 11

    def test_classic_syslog_no_year(self):
        ev = self.p.parse_line(
            "Oct 31 14:30:17 web01 sshd[8007]: Accepted password for deploy "
            "from 192.0.2.77 port 51033 ssh2")
        assert ev.event_type == "ssh_login_success"
        assert ev.user == "deploy"
        assert ev.src_ip == "192.0.2.77"

    def test_sudo_command(self):
        ev = self.p.parse_line(
            "2026-10-31T14:31:00+07:00 web01 sudo: deploy : TTY=pts/1 ; "
            "PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
        assert ev.event_type == "sudo_command"
        assert ev.user == "deploy"
        assert ev.extra["target_user"] == "root"
        assert ev.extra["command"] == "/bin/bash"

    def test_user_added_to_group(self):
        ev = self.p.parse_line(
            "2026-10-31T14:32:31+07:00 web01 gpasswd[8121]: add 'support' to group 'sudo'")
        assert ev.event_type == "group_member_added"
        assert ev.user == "support"
        assert ev.extra["group"] == "sudo"

    def test_ignores_unrelated_lines(self):
        assert self.p.parse_line("2026-10-31T10:00:00+07:00 web01 CRON[1]: pam_unix session") is None
        assert self.p.parse_line("total garbage") is None


class TestWebAccessLogParser:
    def setup_method(self):
        self.p = WebAccessLogParser()

    def test_combined_format(self):
        ev = self.p.parse_line(
            '192.0.2.77 - - [31/Oct/2026:13:50:02 +0700] "GET /.env HTTP/1.1" '
            '200 412 "-" "Mozilla/5.00 (Nikto/2.5.0)"')
        assert ev.source == "web"
        assert ev.src_ip == "192.0.2.77"
        assert ev.extra["method"] == "GET"
        assert ev.extra["path"] == "/.env"
        assert ev.extra["status"] == 200
        assert "Nikto" in ev.extra["user_agent"]

    def test_url_is_decoded(self):
        ev = self.p.parse_line(
            "203.0.113.99 - - [31/Oct/2026:13:55:10 +0700] "
            '"GET /p?id=7%27%20UNION%20SELECT%201 HTTP/1.1" 200 10 "-" "x"')
        assert "union select" in ev.extra["path_decoded"].lower()

    def test_malformed_request_line(self):
        ev = self.p.parse_line(
            '10.0.0.1 - - [31/Oct/2026:10:00:00 +0700] "GET" 400 0 "-" "-"')
        assert ev is not None and ev.extra["status"] == 400


def test_decode_url_double_encoded():
    assert decode_url("%2527") == "'"
    assert decode_url("..%2f..%2fetc%2fpasswd") == "../../etc/passwd"


class TestGrapeVineParser:
    def test_parses_scan_output(self):
        lines = [
            "Scanning web01 (10.0.0.10): 1024 port(s), concurrent, 100 threads",
            "",
            "PORT      STATE     SERVICE         VERSION",
            "22/tcp    open      ssh             OpenSSH 9.6p1",
            "4444/tcp  open      unknown",
            "80/tcp    closed",
        ]
        events = list(GrapeVineParser(scan_time=datetime.now().astimezone()).parse_lines(lines))
        opens = [e for e in events if e.event_type == "port_open"]
        assert len(opens) == 2
        first = opens[0]
        assert first.extra["target"] == "10.0.0.10"
        assert first.extra["port"] == 22
        assert first.extra["service"] == "ssh"

    def test_json_lines(self):
        line = '{"target": "10.0.0.10", "port": 6379, "state": "open", "service": "redis"}'
        events = list(GrapeVineParser().parse_lines([line]))
        assert events[0].extra["port"] == 6379
        assert events[0].extra["service"] == "redis"


class TestAutoDetect:
    def test_detects_each_format(self):
        auth = ["2026-10-31T11:02:10+07:00 web01 sshd[4410]: Failed password for root from 1.2.3.4 port 22 ssh2"]
        web = ['1.2.3.4 - - [31/Oct/2026:13:50:02 +0700] "GET / HTTP/1.1" 200 1 "-" "x"']
        gv = ["Scanning web01 (10.0.0.10): 1024 port(s), concurrent, 100 threads"]
        assert detect_parser(auth).name == "auth"
        assert detect_parser(web).name == "web"
        assert detect_parser(gv).name == "grapevine"
        assert detect_parser(["nonsense line"]) is None
