"""Detection rules: loading YAML rules and evaluating them against events.

Four rule types, from simplest to most interesting:

  match      one event is suspicious on its own (a SQL injection attempt)
  threshold  N matching events from the same group inside a time window
             (5 failed logins from one IP in 60 s). With `distinct`, counts
             unique values instead (one IP trying 10 different usernames)
  sequence   ordered steps from the same group inside a window
             (many failed logins, THEN a successful one = likely compromise)
  new_value  a value never seen before (a port that wasn't open last scan)

Conditions in `where` use a small Sigma-inspired syntax:

  event_type: ssh_failed_login         equals
  event_type: [a, b]                   equals any of
  path|contains: "../"                 substring (list = any of)
  path|regex: "union\\s+select"        regular expression, case-insensitive
  user_agent|startswith: sqlmap
  status|gte: 400                      numeric >=, also gt, lte, lt
  user|not: root                       not equal (list = none of)

All conditions in a `where` block must hold (AND). For OR, write separate
rules or use a list of values.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from .event import Event

RULE_TYPES = ("match", "threshold", "sequence", "new_value")
SEVERITIES = ("info", "low", "medium", "high", "critical")


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------
# Conditions
# --------------------------------------------------------------------------

def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def compile_condition(key: str, expected: Any) -> Callable[[Event], bool]:
    fname, _, op = key.partition("|")
    op = op or "eq"
    values = _as_list(expected)

    if op == "eq":
        wanted = {str(v).lower() for v in values}
        return lambda ev: str(ev.get(fname) if ev.get(fname) is not None else "").lower() in wanted
    if op == "not":
        banned = {str(v).lower() for v in values}
        return lambda ev: str(ev.get(fname) if ev.get(fname) is not None else "").lower() not in banned
    if op == "contains":
        needles = [str(v).lower() for v in values]
        return lambda ev: any(n in str(ev.get(fname) or "").lower() for n in needles)
    if op == "startswith":
        prefixes = tuple(str(v).lower() for v in values)
        return lambda ev: str(ev.get(fname) or "").lower().startswith(prefixes)
    if op == "regex":
        try:
            patterns = [re.compile(str(v), re.IGNORECASE) for v in values]
        except re.error as exc:
            raise RuleError(f"bad regex in {key!r}: {exc}") from None
        return lambda ev: any(p.search(str(ev.get(fname) or "")) for p in patterns)
    if op in ("gt", "gte", "lt", "lte"):
        limit = _num(expected)
        if limit is None:
            raise RuleError(f"{key!r} needs a number")
        cmp = {"gt": float.__gt__, "gte": float.__ge__,
               "lt": float.__lt__, "lte": float.__le__}[op]

        def numeric(ev: Event) -> bool:
            n = _num(ev.get(fname))
            return n is not None and cmp(n, limit)
        return numeric
    raise RuleError(f"unknown operator {op!r} in {key!r}")


def compile_where(where: dict | None) -> Callable[[Event], bool]:
    if not where:
        return lambda ev: True
    if not isinstance(where, dict):
        raise RuleError("'where' must be a mapping of field: value")
    checks = [compile_condition(k, v) for k, v in where.items()]
    return lambda ev: all(check(ev) for check in checks)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

@dataclass
class Step:
    matches: Callable[[Event], bool]
    min_count: int = 1


@dataclass
class Rule:
    id: str
    name: str
    type: str
    severity: str
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    matches: Callable[[Event], bool] = lambda ev: True
    group_by: list[str] = field(default_factory=list)
    window: float = 60.0           # seconds
    threshold: int = 1
    distinct: str = ""             # threshold: count unique values of this field
    steps: list[Step] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)   # new_value
    baseline_by: str = ""          # new_value: first batch per value of this field only learns
    baseline_batch: str = ""       # new_value: field naming the batch (e.g. scan_id)
    suppress: float = 600.0        # seconds to fold repeats into the same alert
    enabled: bool = True

    def group_key(self, ev: Event) -> str:
        return "|".join(str(ev.get(f) or "") for f in self.group_by)


def rule_from_dict(d: dict, origin: str = "") -> Rule:
    where = f" (in {origin})" if origin else ""
    for key in ("id", "name", "type", "severity"):
        if key not in d:
            raise RuleError(f"rule missing '{key}'{where}: {d.get('id', d)}")
    if d["type"] not in RULE_TYPES:
        raise RuleError(f"rule {d['id']}: type must be one of {RULE_TYPES}{where}")
    if d["severity"] not in SEVERITIES:
        raise RuleError(f"rule {d['id']}: severity must be one of {SEVERITIES}{where}")

    rule = Rule(
        id=str(d["id"]), name=d["name"], type=d["type"], severity=d["severity"],
        description=d.get("description", "").strip(),
        mitre=[str(m) for m in _as_list(d.get("mitre", []))],
        matches=compile_where(d.get("where")),
        group_by=_as_list(d.get("group_by", [])),
        window=float(d.get("window", 60)),
        threshold=int(d.get("threshold", 1)),
        distinct=d.get("distinct", ""),
        fields=_as_list(d.get("fields", [])),
        baseline_by=d.get("baseline_by", ""),
        baseline_batch=d.get("baseline_batch", ""),
        suppress=float(d.get("suppress", 600)),
        enabled=bool(d.get("enabled", True)),
    )
    if rule.type == "sequence":
        steps = d.get("steps") or []
        if len(steps) < 2:
            raise RuleError(f"rule {rule.id}: a sequence needs at least 2 steps{where}")
        rule.steps = [Step(compile_where(s.get("where")), int(s.get("min_count", 1)))
                      for s in steps]
    if rule.type == "new_value" and not rule.fields:
        raise RuleError(f"rule {rule.id}: new_value needs 'fields'{where}")
    return rule


def load_rules(path: str | Path) -> list[Rule]:
    """Load every *.yml / *.yaml file in a directory (or a single file)."""
    path = Path(path)
    files = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    rules, ids = [], set()
    for f in files:
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        for d in _as_list(data):
            rule = rule_from_dict(d, origin=f.name)
            if rule.id in ids:
                raise RuleError(f"duplicate rule id {rule.id!r} in {f.name}")
            ids.add(rule.id)
            if rule.enabled:
                rules.append(rule)
    return rules


# --------------------------------------------------------------------------
# Detection engine
# --------------------------------------------------------------------------

@dataclass
class Detection:
    """What the engine hands back: create a new alert, or extend an existing one."""
    rule: Rule
    events: list[Event]
    group_key: str
    extend_alert_id: int | None = None


class Detector:
    """Stateful rule evaluation. Feed events in time order with `process()`.

    State (sliding windows, sequence progress, suppression) lives in memory,
    so it resets when the program restarts. new_value state is persisted in
    the database because a baseline must survive restarts to be useful.
    """

    def __init__(self, rules: list[Rule], storage):
        self.rules = rules
        self.storage = storage
        # (rule_id, group) -> deque of events inside the window
        self.windows: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
        # (rule_id, group, step_index) -> deque of events for sequence rules
        self.seq: dict[tuple[str, str, int], deque[Event]] = defaultdict(deque)
        # (rule_id, group) -> (alert_id, time of last event folded in)
        self.active: dict[tuple[str, str], tuple[int, Any]] = {}
        self.rules_by_id = {r.id: r for r in rules}
        self._seen = 0
        self._latest: datetime | None = None

    SWEEP_EVERY = 5000

    def process(self, ev: Event) -> list[Detection]:
        out = []
        for rule in self.rules:
            det = getattr(self, f"_{rule.type}")(rule, ev)
            if det:
                out.append(det)
        if self._latest is None or ev.timestamp > self._latest:
            self._latest = ev.timestamp
        self._seen += 1
        if self._seen % self.SWEEP_EVERY == 0:
            self.sweep()
        return out

    def sweep(self) -> None:
        """Forget per-group state that can no longer matter. Without this, a
        long-running `watch` keeps a little state for every IP it has ever
        seen, and internet-facing servers see a lot of IPs."""
        if self._latest is None:
            return
        now = self._latest

        def stale(rule_id: str, ts, attr: str) -> bool:
            rule = self.rules_by_id.get(rule_id)
            return rule is None or now - ts > timedelta(seconds=getattr(rule, attr))

        for key in [k for k, q in self.windows.items() if not q or stale(k[0], q[-1].timestamp, "window")]:
            del self.windows[key]
        for key in [k for k, q in self.seq.items() if not q or stale(k[0], q[-1].timestamp, "window")]:
            del self.seq[key]
        for key in [k for k, (_, last) in self.active.items() if stale(k[0], last, "suppress")]:
            del self.active[key]

    def record_alert(self, det: Detection, alert_id: int) -> None:
        """Called after the caller stores a new alert, to start suppression."""
        last = max(e.timestamp for e in det.events)
        self.active[(det.rule.id, det.group_key)] = (alert_id, last)

    # -- suppression ------------------------------------------------------

    def _suppressed(self, rule: Rule, group: str, ev: Event) -> Detection | None:
        """If this group already has a recent alert, fold the event into it.

        Checks memory first, then the database, so suppression still works
        when the program is restarted between runs (e.g. ingesting a new
        scan every day must not re-raise last week's still-open alert)."""
        key = (rule.id, group)
        entry = self.active.get(key)
        if entry is None:
            row = self.storage.recent_alert(rule.id, group)
            if row is not None:
                entry = (row["id"], datetime.fromtimestamp(row["last_seen"], tz=timezone.utc))
        if entry is not None:
            alert_id, last = entry
            if ev.timestamp - last <= timedelta(seconds=rule.suppress):
                self.active[key] = (alert_id, max(last, ev.timestamp))
                return Detection(rule, [ev], group, extend_alert_id=alert_id)
            self.active.pop(key, None)
        return None

    # -- rule types -------------------------------------------------------

    def _match(self, rule: Rule, ev: Event) -> Detection | None:
        if not rule.matches(ev):
            return None
        group = rule.group_key(ev)
        if rule.group_by:
            folded = self._suppressed(rule, group, ev)
            if folded:
                return folded
        return Detection(rule, [ev], group)

    def _threshold(self, rule: Rule, ev: Event) -> Detection | None:
        if not rule.matches(ev):
            return None
        group = rule.group_key(ev)
        folded = self._suppressed(rule, group, ev)
        if folded:
            return folded

        win = self.windows[(rule.id, group)]
        win.append(ev)
        cutoff = ev.timestamp - timedelta(seconds=rule.window)
        while win and win[0].timestamp < cutoff:
            win.popleft()

        count = len({str(e.get(rule.distinct)) for e in win}) if rule.distinct else len(win)
        if count >= rule.threshold:
            events = list(win)
            win.clear()
            return Detection(rule, events, group)
        return None

    def _sequence(self, rule: Rule, ev: Event) -> Detection | None:
        group = rule.group_key(ev)
        last = len(rule.steps) - 1
        cutoff = ev.timestamp - timedelta(seconds=rule.window)

        # Remember this event for every non-final step it satisfies
        for i, step in enumerate(rule.steps[:-1]):
            if step.matches(ev):
                q = self.seq[(rule.id, group, i)]
                q.append(ev)
                while q and q[0].timestamp < cutoff:
                    q.popleft()

        if not rule.steps[last].matches(ev):
            return None

        # Final step seen: walk backwards checking each earlier step happened,
        # in order, inside the window.
        boundary = ev.timestamp
        chain: list[Event] = [ev]
        for i in range(last - 1, -1, -1):
            q = self.seq[(rule.id, group, i)]
            hits = [e for e in q if cutoff <= e.timestamp <= boundary and e is not ev]
            if len(hits) < rule.steps[i].min_count:
                return None
            chain = hits + chain
            boundary = min(e.timestamp for e in hits)

        for i in range(last):
            self.seq[(rule.id, group, i)].clear()
        folded = self._suppressed(rule, group, ev)
        return folded or Detection(rule, chain, group)

    def _new_value(self, rule: Rule, ev: Event) -> Detection | None:
        if not rule.matches(ev):
            return None
        if any(ev.get(f) in (None, "") for f in rule.fields):
            return None
        value = "|".join(str(ev.get(f)) for f in rule.fields)

        if rule.baseline_by:
            # The first batch (scan) ever seen for this target is the baseline:
            # learn its values quietly. Every open port on a host you just
            # started monitoring is "new", and alerting on all of them is noise.
            # Batches are compared by identity (scan_id), not by timestamp, so
            # two scans that happen to share a timestamp are still told apart.
            batch = str(ev.get(rule.baseline_batch) or "") if rule.baseline_batch else ""
            batch = batch or ev.timestamp.isoformat()
            key = str(ev.get(rule.baseline_by))
            if self.storage.baseline_batch(rule.id, key, batch) == batch:
                self.storage.seen_before(rule.id, value, ev.timestamp)
                return None

        if self.storage.seen_before(rule.id, value, ev.timestamp):
            return None
        return Detection(rule, [ev], value)
