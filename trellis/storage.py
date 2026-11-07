"""SQLite storage for events, alerts and ingestion state.

SQLite is enough for a single-machine SIEM: one file, no server, and it
handles millions of rows. Timestamps are stored twice: as an ISO string for
reading and as a Unix epoch float for fast range queries and sorting.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .event import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    ts_epoch    REAL NOT NULL,
    source      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    host        TEXT,
    src_ip      TEXT,
    user        TEXT,
    message     TEXT,
    raw         TEXT,
    extra       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    rule_name   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    mitre       TEXT,
    description TEXT,
    group_key   TEXT,
    src_ip      TEXT,
    user        TEXT,
    host        TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    event_count INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_last ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_group ON alerts(rule_id, group_key, last_seen);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);

-- values already seen by new_value rules (e.g. host:port pairs)
CREATE TABLE IF NOT EXISTS seen_values (
    rule_id    TEXT NOT NULL,
    value      TEXT NOT NULL,
    first_seen REAL NOT NULL,
    PRIMARY KEY (rule_id, value)
);

-- the first batch (e.g. GrapeVine scan) seen per key for new_value rules
-- with a baseline; values from that batch are learned, not alerted on
CREATE TABLE IF NOT EXISTS baselines (
    rule_id TEXT NOT NULL,
    key     TEXT NOT NULL,
    batch   TEXT NOT NULL,
    PRIMARY KEY (rule_id, key)
);

-- how far into each log file we've read, so re-running ingest
-- (or restarting watch mode) never stores the same line twice
CREATE TABLE IF NOT EXISTS file_state (
    path   TEXT PRIMARY KEY,
    inode  INTEGER,
    offset INTEGER NOT NULL,
    mtime  INTEGER          -- nanoseconds; detects rewritten snapshot files
);
"""

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _epoch(ts: datetime) -> float:
    return ts.timestamp()


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat()


class Storage:
    def __init__(self, path: str | Path = "trellis.db"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")   # dashboard can read while ingest writes
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Bring databases made by older versions up to the current schema."""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(file_state)")}
        if "mtime" not in cols:
            self.conn.execute("ALTER TABLE file_state ADD COLUMN mtime INTEGER")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def commit(self) -> None:
        self.conn.commit()

    # ---- events ---------------------------------------------------------

    def add_event(self, ev: Event) -> int:
        cur = self.conn.execute(
            "INSERT INTO events (ts, ts_epoch, source, event_type, host, src_ip, user,"
            " message, raw, extra) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (_iso(ev.timestamp), _epoch(ev.timestamp), ev.source, ev.event_type,
             ev.host, ev.src_ip, ev.user, ev.message, ev.raw, json.dumps(ev.extra)))
        ev.id = cur.lastrowid
        return ev.id

    def search_events(self, q: str = "", source: str = "", event_type: str = "",
                      src_ip: str = "", since: float | None = None,
                      limit: int = 200, offset: int = 0) -> list[sqlite3.Row]:
        sql, args = "SELECT * FROM events WHERE 1=1", []
        if q:
            # escape LIKE wildcards so searching "50%" or "a_b" is literal
            esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += " AND (message LIKE ? ESCAPE '\\' OR raw LIKE ? ESCAPE '\\')"
            args += [f"%{esc}%", f"%{esc}%"]
        for col, val in (("source", source), ("event_type", event_type), ("src_ip", src_ip)):
            if val:
                sql += f" AND {col} = ?"   # column names are fixed above, never user input
                args.append(val)
        if since is not None:
            sql += " AND ts_epoch >= ?"
            args.append(since)
        sql += " ORDER BY ts_epoch DESC, id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        return self.conn.execute(sql, args).fetchall()

    def distinct(self, column: str) -> list[str]:
        assert column in ("source", "event_type")
        rows = self.conn.execute(f"SELECT DISTINCT {column} FROM events ORDER BY 1")
        return [r[0] for r in rows]

    # ---- alerts ---------------------------------------------------------

    def add_alert(self, rule, events: list[Event], group_key: str = "") -> int:
        first = min(e.timestamp for e in events)
        last = max(e.timestamp for e in events)
        ref = events[-1]
        cur = self.conn.execute(
            "INSERT INTO alerts (rule_id, rule_name, severity, mitre, description, group_key,"
            " src_ip, user, host, first_seen, last_seen, event_count, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rule.id, rule.name, rule.severity, ",".join(rule.mitre), rule.description,
             group_key, ref.src_ip, ref.user, ref.host, _epoch(first), _epoch(last),
             len(events), datetime.now(timezone.utc).timestamp()))
        alert_id = cur.lastrowid
        self.conn.executemany(
            "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?,?)",
            [(alert_id, e.id) for e in events if e.id is not None])
        return alert_id

    def extend_alert(self, alert_id: int, events: list[Event]) -> None:
        """Fold more events into an existing alert instead of raising a new one.
        This is alert suppression: 500 failed logins from one IP should be one
        alert with 500 events, not 100 alerts."""
        last = max(e.timestamp for e in events)
        self.conn.executemany(
            "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?,?)",
            [(alert_id, e.id) for e in events if e.id is not None])
        self.conn.execute(
            "UPDATE alerts SET last_seen = MAX(last_seen, ?),"
            " event_count = (SELECT COUNT(*) FROM alert_events WHERE alert_id = ?)"
            " WHERE id = ?", (_epoch(last), alert_id, alert_id))

    def recent_alert(self, rule_id: str, group_key: str) -> sqlite3.Row | None:
        """The latest not-closed alert for this rule and group, used to keep
        suppression working across separate runs of the program."""
        return self.conn.execute(
            "SELECT id, last_seen FROM alerts WHERE rule_id = ? AND group_key = ?"
            " AND status != 'closed' ORDER BY last_seen DESC LIMIT 1",
            (rule_id, group_key)).fetchone()

    def list_alerts(self, severity: str = "", status: str = "", rule_id: str = "",
                    limit: int = 200) -> list[sqlite3.Row]:
        sql, args = "SELECT * FROM alerts WHERE 1=1", []
        for col, val in (("severity", severity), ("status", status), ("rule_id", rule_id)):
            if val:
                sql += f" AND {col} = ?"
                args.append(val)
        sql += " ORDER BY last_seen DESC, id DESC LIMIT ?"
        args.append(limit)
        return self.conn.execute(sql, args).fetchall()

    def get_alert(self, alert_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    def alert_events(self, alert_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT e.* FROM events e JOIN alert_events ae ON ae.event_id = e.id"
            " WHERE ae.alert_id = ? ORDER BY e.ts_epoch, e.id", (alert_id,)).fetchall()

    def set_alert_status(self, alert_id: int, status: str) -> None:
        if status not in ("open", "acknowledged", "closed"):
            raise ValueError(f"bad status: {status}")
        self.conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        self.conn.commit()

    # ---- new_value rule state -------------------------------------------

    def seen_before(self, rule_id: str, value: str, ts: datetime) -> bool:
        """Record `value` as seen and return whether it had been seen already."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO seen_values (rule_id, value, first_seen) VALUES (?,?,?)",
            (rule_id, value, _epoch(ts)))
        return cur.rowcount == 0

    def baseline_batch(self, rule_id: str, key: str, batch: str) -> str:
        """Return the baseline batch for `key`, recording `batch` as the
        baseline if this key has never been seen."""
        self.conn.execute(
            "INSERT OR IGNORE INTO baselines (rule_id, key, batch) VALUES (?,?,?)",
            (rule_id, key, batch))
        return self.conn.execute(
            "SELECT batch FROM baselines WHERE rule_id = ? AND key = ?",
            (rule_id, key)).fetchone()[0]

    # ---- file ingestion state -------------------------------------------

    def get_file_state(self, path: str) -> tuple[int | None, int, int | None]:
        row = self.conn.execute(
            "SELECT inode, offset, mtime FROM file_state WHERE path = ?", (path,)).fetchone()
        return (row["inode"], row["offset"], row["mtime"]) if row else (None, 0, None)

    def set_file_state(self, path: str, inode: int, offset: int,
                       mtime: int | None = None) -> None:
        self.conn.execute(
            "INSERT INTO file_state (path, inode, offset, mtime) VALUES (?,?,?,?)"
            " ON CONFLICT(path) DO UPDATE SET inode = excluded.inode,"
            " offset = excluded.offset, mtime = excluded.mtime",
            (path, inode, offset, mtime))

    # ---- dashboard statistics -------------------------------------------

    def stats(self, since: float) -> dict[str, Any]:
        c = self.conn
        one = lambda sql, *a: c.execute(sql, a).fetchone()[0]
        return {
            "events_total": one("SELECT COUNT(*) FROM events"),
            "events_window": one("SELECT COUNT(*) FROM events WHERE ts_epoch >= ?", since),
            "alerts_open": one("SELECT COUNT(*) FROM alerts WHERE status = 'open'"),
            "alerts_window": one("SELECT COUNT(*) FROM alerts WHERE last_seen >= ?", since),
            "by_severity": {r[0]: r[1] for r in c.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE status = 'open'"
                " GROUP BY severity")},
            "top_rules": c.execute(
                "SELECT rule_name, severity, COUNT(*) AS n FROM alerts"
                " WHERE last_seen >= ? GROUP BY rule_id ORDER BY n DESC LIMIT 6",
                (since,)).fetchall(),
            "top_attackers": c.execute(
                "SELECT src_ip, COUNT(*) AS alerts, GROUP_CONCAT(DISTINCT severity) AS sevs"
                " FROM alerts"
                " WHERE src_ip != '' AND last_seen >= ? GROUP BY src_ip"
                " ORDER BY alerts DESC LIMIT 8", (since,)).fetchall(),
            "by_source": c.execute(
                "SELECT source, COUNT(*) AS n FROM events WHERE ts_epoch >= ?"
                " GROUP BY source ORDER BY n DESC", (since,)).fetchall(),
        }

    def timeline(self, since: float, until: float, buckets: int = 24) -> list[dict]:
        """Event and alert counts per time bucket, for the overview chart."""
        width = max((until - since) / buckets, 1)
        ev = dict(self.conn.execute(
            "SELECT CAST((ts_epoch - ?) / ? AS INTEGER) AS b, COUNT(*) FROM events"
            " WHERE ts_epoch >= ? AND ts_epoch < ? GROUP BY b", (since, width, since, until)))
        al = dict(self.conn.execute(
            "SELECT CAST((last_seen - ?) / ? AS INTEGER) AS b, COUNT(*) FROM alerts"
            " WHERE last_seen >= ? AND last_seen < ? GROUP BY b", (since, width, since, until)))
        return [{"start": since + i * width, "events": ev.get(i, 0), "alerts": al.get(i, 0)}
                for i in range(buckets)]

    def latest_event_time(self) -> float | None:
        return self.conn.execute("SELECT MAX(ts_epoch) FROM events").fetchone()[0]
