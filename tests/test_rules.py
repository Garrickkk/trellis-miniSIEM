"""Rule and detection-engine tests, using synthetic events so each rule type
is exercised in isolation."""

from datetime import datetime, timedelta, timezone

import pytest

from trellis.event import Event
from trellis.rules import (Detector, RuleError, compile_condition, load_rules,
                            rule_from_dict)
from trellis.storage import Storage

T0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


EVENT_FIELDS = {"source", "event_type", "host", "src_ip", "user", "message", "raw", "extra", "id"}


def ev(dt_offset=0, **kw):
    kw.setdefault("source", "auth")
    kw.setdefault("event_type", "ssh_failed_login")
    extra = kw.pop("extra", {})
    # Anything that isn't a top-level Event field goes into extra, the way a
    # real parser would store source-specific fields like status or path.
    for key in [k for k in kw if k not in EVENT_FIELDS]:
        extra[key] = kw.pop(key)
    return Event(timestamp=T0 + timedelta(seconds=dt_offset), extra=extra, **kw)


@pytest.fixture
def store(tmp_path):
    s = Storage(tmp_path / "t.db")
    yield s
    s.close()


# ---- conditions ------------------------------------------------------------

def test_condition_operators():
    assert compile_condition("status", 404)(ev(status=404, source="web"))
    assert compile_condition("status|gte", 400)(ev(status=500, source="web"))
    assert not compile_condition("status|gte", 400)(ev(status=200, source="web"))
    assert compile_condition("user|not", "root")(ev(user="deploy"))
    assert not compile_condition("user|not", "root")(ev(user="root"))
    assert compile_condition("path|contains", "../")(ev(path="/a/../b", source="web"))
    assert compile_condition("event_type", ["a", "b"])(ev(event_type="b"))
    assert compile_condition("ua|regex", "nikto|sqlmap")(ev(ua="x Nikto/2.5"))


def test_bad_regex_rejected():
    with pytest.raises(RuleError):
        compile_condition("path|regex", "(unclosed")


def test_rule_validation():
    with pytest.raises(RuleError):
        rule_from_dict({"id": "x", "name": "x", "type": "bogus", "severity": "high"})
    with pytest.raises(RuleError):
        rule_from_dict({"id": "x", "name": "x", "type": "match", "severity": "HUGE"})
    with pytest.raises(RuleError):  # sequence needs >= 2 steps
        rule_from_dict({"id": "x", "name": "x", "type": "sequence", "severity": "high",
                        "steps": [{"where": {"a": 1}}]})


# ---- match -----------------------------------------------------------------

def test_match_rule(store):
    rule = rule_from_dict({"id": "root", "name": "root login", "type": "match",
                           "severity": "high", "where": {"event_type": "ssh_login_success",
                           "user": "root"}, "group_by": ["src_ip"]})
    det = Detector([rule], store)
    assert not det.process(ev(event_type="ssh_login_success", user="deploy"))
    hits = det.process(ev(event_type="ssh_login_success", user="root", src_ip="1.2.3.4"))
    assert len(hits) == 1 and hits[0].rule.id == "root"


# ---- threshold -------------------------------------------------------------

def test_threshold_fires_at_n(store):
    rule = rule_from_dict({"id": "bf", "name": "bf", "type": "threshold", "severity": "high",
                           "where": {"event_type": "ssh_failed_login"},
                           "group_by": ["src_ip"], "threshold": 5, "window": 60})
    det = Detector([rule], store)
    fired = []
    for i in range(5):
        fired += det.process(ev(i, src_ip="9.9.9.9"))
    assert len(fired) == 1
    assert len(fired[0].events) == 5


def test_threshold_respects_window(store):
    rule = rule_from_dict({"id": "bf", "name": "bf", "type": "threshold", "severity": "high",
                           "where": {"event_type": "ssh_failed_login"},
                           "group_by": ["src_ip"], "threshold": 3, "window": 10})
    det = Detector([rule], store)
    fired = []
    for t in (0, 5, 20, 25, 28):  # first two expire before the last three
        fired += det.process(ev(t, src_ip="9.9.9.9"))
    assert len(fired) == 1


def test_threshold_distinct_counts_unique(store):
    rule = rule_from_dict({"id": "spray", "name": "spray", "type": "threshold",
                           "severity": "high", "where": {"event_type": "ssh_failed_login"},
                           "group_by": ["src_ip"], "distinct": "user", "threshold": 3,
                           "window": 300})
    det = Detector([rule], store)
    fired = []
    for u in ("alice", "alice", "alice"):  # same user repeated: only 1 distinct
        fired += det.process(ev(src_ip="7.7.7.7", user=u))
    assert not fired
    for u in ("bob", "carol"):
        fired += det.process(ev(src_ip="7.7.7.7", user=u))
    assert len(fired) == 1


# ---- sequence --------------------------------------------------------------

def test_sequence_detects_brute_then_success(store):
    rule = rule_from_dict({"id": "bfs", "name": "bfs", "type": "sequence", "severity": "critical",
                           "group_by": ["src_ip"], "window": 900,
                           "steps": [{"where": {"event_type": "ssh_failed_login"}, "min_count": 3},
                                     {"where": {"event_type": "ssh_login_success"}}]})
    det = Detector([rule], store)
    fired = []
    for i in range(3):
        fired += det.process(ev(i, src_ip="5.5.5.5"))
    assert not fired  # failures alone don't trip it
    fired += det.process(ev(10, event_type="ssh_login_success", src_ip="5.5.5.5"))
    assert len(fired) == 1
    assert fired[0].events[-1].event_type == "ssh_login_success"


def test_sequence_needs_enough_of_first_step(store):
    rule = rule_from_dict({"id": "bfs", "name": "bfs", "type": "sequence", "severity": "critical",
                           "group_by": ["src_ip"], "window": 900,
                           "steps": [{"where": {"event_type": "ssh_failed_login"}, "min_count": 5},
                                     {"where": {"event_type": "ssh_login_success"}}]})
    det = Detector([rule], store)
    fired = []
    for i in range(2):  # only 2 failures, need 5
        fired += det.process(ev(i, src_ip="5.5.5.5"))
    fired += det.process(ev(10, event_type="ssh_login_success", src_ip="5.5.5.5"))
    assert not fired


# ---- new_value -------------------------------------------------------------

def test_new_value_with_baseline(store):
    rule = rule_from_dict({"id": "np", "name": "new port", "type": "new_value",
                           "severity": "medium", "where": {"event_type": "port_open"},
                           "fields": ["target", "port"], "baseline_by": "target"})
    det = Detector([rule], store)
    # First scan (baseline) at T0: nothing should alert
    base = [ev(0, source="grapevine", event_type="port_open", host="h",
               extra={"target": "h", "port": p}) for p in (22, 80, 443)]
    fired = []
    for e in base:
        fired += det.process(e)
    assert not fired
    # Later scan with a new port 4444: that one alerts, the known ones don't
    later = [ev(3600, source="grapevine", event_type="port_open", host="h",
                extra={"target": "h", "port": p}) for p in (22, 80, 4444)]
    fired = []
    for e in later:
        fired += det.process(e)
    assert len(fired) == 1
    assert fired[0].events[0].extra["port"] == 4444


# ---- suppression -----------------------------------------------------------

def test_match_suppression_folds_repeats(store):
    rule = rule_from_dict({"id": "r", "name": "r", "type": "match", "severity": "low",
                           "where": {"event_type": "x"}, "group_by": ["src_ip"],
                           "suppress": 600})
    det = Detector([rule], store)
    first = det.process(ev(0, event_type="x", src_ip="1.1.1.1"))
    assert len(first) == 1 and first[0].extend_alert_id is None
    det.record_alert(first[0], alert_id=42)
    again = det.process(ev(60, event_type="x", src_ip="1.1.1.1"))
    assert again[0].extend_alert_id == 42  # folded, not a new alert


# ---- loading the shipped rules ---------------------------------------------

def test_shipped_rules_load():
    from pathlib import Path
    rules = load_rules(Path(__file__).resolve().parent.parent / "rules")
    assert len(rules) >= 15
    assert all(r.id and r.name for r in rules)
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))  # unique ids
