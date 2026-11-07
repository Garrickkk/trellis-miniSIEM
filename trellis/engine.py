"""The pipeline: read files -> parse -> store -> detect -> alert.

Batch mode (`ingest`) reads everything, sorts it by time, then runs
detection, so rules that span files (a scan in the web log followed by a
login in auth.log) still see events in the right order. Watch mode tails
files like `tail -F`, processing new lines as they're written.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

from .event import Event
from .parsers import LOCAL_TZ, PARSERS, GrapeVineParser, detect_parser
from .rules import Detection, Detector, Rule
from .storage import Storage

AlertCallback = Callable[[int, Detection], None]


@dataclass
class IngestResult:
    events: int = 0
    new_alerts: int = 0
    skipped_files: list[str] = field(default_factory=list)


class Pipeline:
    def __init__(self, storage: Storage, rules: list[Rule],
                 on_alert: AlertCallback | None = None):
        self.storage = storage
        self.detector = Detector(rules, storage)
        self.on_alert = on_alert

    def process(self, events: Iterable[Event]) -> IngestResult:
        result = IngestResult()
        for ev in sorted(events, key=lambda e: e.timestamp):
            self.storage.add_event(ev)
            result.events += 1
            for det in self.detector.process(ev):
                if det.extend_alert_id is not None:
                    self.storage.extend_alert(det.extend_alert_id, det.events)
                    continue
                alert_id = self.storage.add_alert(det.rule, det.events, det.group_key)
                self.detector.record_alert(det, alert_id)
                result.new_alerts += 1
                if self.on_alert:
                    self.on_alert(alert_id, det)
        self.storage.commit()
        return result

    # ---- files ----------------------------------------------------------

    def read_new_events(self, path: str | Path, log_type: str | None = None) -> list[Event] | None:
        """Parse lines added to `path` since we last read it.
        Returns None if the format couldn't be recognized."""
        path = str(Path(path).resolve())
        st = os.stat(path)
        inode, offset, mtime = self.storage.get_file_state(path)
        unchanged = (inode == st.st_ino and offset == st.st_size and mtime == st.st_mtime_ns)
        if unchanged:
            return []
        if st.st_size == 0:
            return []  # empty file: nothing to read, and nothing to detect a format from

        parser = self._parser_for(path, log_type, st)
        if parser is None:
            return None

        if getattr(parser, "snapshot", False):
            # Scan results are rewritten in place (`grapevine ... > scan.txt`),
            # not appended, so any change means a whole new scan: read it all.
            offset = 0
        elif inode != st.st_ino or st.st_size < offset:
            offset = 0  # new file, or it was rotated / truncated: start over
        if st.st_size == offset:
            self.storage.set_file_state(path, st.st_ino, offset, st.st_mtime_ns)
            return []

        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read()
        if getattr(parser, "snapshot", False):
            end = len(data)  # a finished scan may not end with a newline
        else:
            # Only consume complete lines; a half-written last line waits for next time
            end = data.rfind(b"\n") + 1
            if end == 0:
                return []
        lines = data[:end].decode("utf-8", errors="replace").splitlines()
        self.storage.set_file_state(path, st.st_ino, offset + end, st.st_mtime_ns)
        return list(parser.parse_lines(lines))

    def _parser_for(self, path: str, log_type: str | None, st: os.stat_result):
        if log_type:
            parser = PARSERS[log_type]()
        else:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                head = [f.readline() for _ in range(30)]
            parser = detect_parser(head)
        if isinstance(parser, GrapeVineParser):
            # GrapeVine output has no timestamp: the scan happened when the file
            # was written. Path + mtime identifies this particular scan run.
            parser.scan_time = datetime.fromtimestamp(st.st_mtime, tz=LOCAL_TZ)
            parser.scan_id = f"{path}@{st.st_mtime_ns}"
        return parser

    def ingest(self, paths: Iterable[str | Path], log_type: str | None = None) -> IngestResult:
        events: list[Event] = []
        skipped = []
        for p in paths:
            parsed = self.read_new_events(p, log_type)
            if parsed is None:
                skipped.append(str(p))
            else:
                events.extend(parsed)
        result = self.process(events)
        result.skipped_files = skipped
        return result

    def watch(self, paths: list[str | Path], log_type: str | None = None,
              interval: float = 1.0, stop: Callable[[], bool] = lambda: False) -> None:
        """Poll files for new lines forever (Ctrl+C to stop). Polling is used
        instead of inotify so it works the same on Linux, macOS and Windows."""
        while not stop():
            for p in paths:
                if not os.path.exists(p):
                    continue
                parsed = self.read_new_events(p, log_type)
                if parsed:
                    self.process(parsed)
            time.sleep(interval)
