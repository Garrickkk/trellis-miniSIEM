"""The normalized event schema every parser produces.

Different log formats say the same things in different ways. A failed SSH
login, a 404 from nginx and an open port found by GrapeVine all become an
Event with the same fields, so detection rules only have to understand one
shape of data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    timestamp: datetime          # when it happened (timezone-aware)
    source: str                  # which parser produced it: auth, web, grapevine
    event_type: str              # what happened, e.g. ssh_failed_login
    host: str = ""               # machine that logged it
    src_ip: str = ""             # who caused it, if known
    user: str = ""               # account involved, if any
    message: str = ""            # short human-readable summary
    raw: str = ""                # original log line, kept for investigation
    extra: dict[str, Any] = field(default_factory=dict)  # source-specific fields
    id: int | None = None        # set once stored in the database

    def get(self, name: str) -> Any:
        """Look up a field by name for rule matching.

        Top-level fields come first, then `extra`, so a rule can say
        `status: 404` without knowing it lives in extra.
        """
        if name in ("timestamp", "source", "event_type", "host", "src_ip",
                    "user", "message", "raw", "id"):
            return getattr(self, name)
        return self.extra.get(name)
