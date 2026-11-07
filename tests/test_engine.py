"""End-to-end tests: real sample log files through the full pipeline."""

import os
from pathlib import Path

import pytest

from trellis.engine import Pipeline
from trellis.rules import load_rules
from trellis.storage import Storage

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture
def pipe(tmp_path):
    store = Storage(tmp_path / "t.db")
    yield Pipeline(store, load_rules(ROOT / "rules"))
    store.close()


def alerts_by_rule(store):
    return {r["rule_id"] for r in store.list_alerts(limit=500)}


def test_auth_log_scenarios(pipe):
    result = pipe.ingest([SAMPLES / "auth.log"])
    assert result.events > 0
    rules = alerts_by_rule(pipe.storage)
    # SSH bot hitting many invalid users -> password spraying and/or brute force
    assert "ssh-password-spray" in rules or "ssh-brute-force" in rules
    # deploy brute-forced then logged in
    assert "ssh-brute-force-success" in rules
    # post-compromise actions
    assert "sudo-suspicious-command" in rules
    assert "local-user-created" in rules
    assert "user-added-to-admin-group" in rules
    # admin's direct root login
    assert "ssh-root-login" in rules


def test_web_log_scenarios(pipe):
    pipe.ingest([SAMPLES / "access.log"])
    rules = alerts_by_rule(pipe.storage)
    assert "web-scanner-user-agent" in rules   # Nikto + sqlmap
    assert "web-sql-injection" in rules
    assert "web-xss" in rules
    assert "web-path-traversal" in rules
    assert "web-sensitive-file-probe" in rules
    assert "web-login-brute-force" in rules


def test_grapevine_new_port(pipe, tmp_path):
    # Copy the two scans and give them increasing mtimes, because GrapeVine
    # output has no timestamp of its own.
    base = tmp_path / "base.txt"
    base.write_text((SAMPLES / "scan-baseline.txt").read_text())
    os.utime(base, (1000, 1000))
    pipe.ingest([base])

    latest = tmp_path / "latest.txt"
    latest.write_text((SAMPLES / "scan-latest.txt").read_text())
    os.utime(latest, (100000, 100000))
    pipe.ingest([latest])

    rules = alerts_by_rule(pipe.storage)
    assert "new-open-port" in rules      # 4444 and 6379 are new
    assert "risky-service-exposed" in rules   # redis

    # The baseline ports (22, 80, 443, 3306) must NOT raise new-port alerts
    new_port_alerts = pipe.storage.list_alerts(rule_id="new-open-port", limit=50)
    ports = set()
    for a in new_port_alerts:
        for e in pipe.storage.alert_events(a["id"]):
            import json
            ports.add(json.loads(e["extra"])["port"])
    assert ports == {4444, 6379}


def test_reingest_is_idempotent(pipe):
    first = pipe.ingest([SAMPLES / "auth.log"])
    second = pipe.ingest([SAMPLES / "auth.log"])   # same file, nothing new
    assert first.events > 0
    assert second.events == 0   # offset tracking means no double-counting


def test_unknown_format_is_skipped(pipe, tmp_path):
    junk = tmp_path / "junk.log"
    junk.write_text("this is not a log file\njust some text\n")
    result = pipe.ingest([junk])
    assert str(junk) in result.skipped_files
    assert result.events == 0
