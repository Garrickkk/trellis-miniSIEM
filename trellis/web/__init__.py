"""Flask web dashboard for browsing events and triaging alerts."""

from __future__ import annotations

import time
from datetime import datetime
from urllib.parse import urlsplit

from flask import Flask, abort, g, jsonify, redirect, render_template, request, url_for

from ..parsers import LOCAL_TZ
from ..rules import Rule
from ..storage import SEVERITY_ORDER, Storage

RANGES = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": None}


def create_app(db_path: str, rules: list[Rule] | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    rules = rules or []
    rules_by_id = {r.id: r for r in rules}

    def db() -> Storage:
        if "db" not in g:
            g.db = Storage(app.config["DB_PATH"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        store = g.pop("db", None)
        if store:
            store.close()

    # ---- template helpers -----------------------------------------------

    @app.template_filter("ts")
    def fmt_ts(epoch: float | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        if epoch is None:
            return "-"
        return datetime.fromtimestamp(epoch, tz=LOCAL_TZ).strftime(fmt)

    @app.template_filter("ago")
    def fmt_ago(epoch: float | None) -> str:
        if epoch is None:
            return "-"
        s = int(time.time() - epoch)
        if s < 0:
            return "just now"
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if s >= size:
                return f"{s // size}{unit} ago"
        return f"{s}s ago"

    @app.template_filter("mitre_url")
    def mitre_url(tid: str) -> str:
        return "https://attack.mitre.org/techniques/" + tid.strip().replace(".", "/") + "/"

    @app.template_filter("worst")
    def worst(sevs: str) -> str:
        return max((sevs or "info").split(","), key=lambda s: SEVERITY_ORDER.get(s, 0))

    @app.context_processor
    def globals_():
        return {"range_key": request.args.get("range", "24h"), "RANGES": RANGES}

    def window() -> tuple[float, float, str]:
        key = request.args.get("range", "24h")
        if key not in RANGES:
            key = "24h"
        now = time.time()
        if RANGES[key] is None:
            first = db().conn.execute("SELECT MIN(ts_epoch) FROM events").fetchone()[0]
            return (first or now - 86400), now, key
        return now - RANGES[key], now, key

    # ---- pages ----------------------------------------------------------

    @app.route("/")
    def overview():
        since, until, key = window()
        stats = db().stats(since)
        timeline = db().timeline(since, until, buckets=36)
        recent = db().list_alerts(limit=8)
        latest = db().latest_event_time()
        return render_template("overview.html", stats=stats, timeline=timeline,
                               peak=max([b["events"] for b in timeline] + [1]),
                               recent=recent, latest=latest, since=since, until=until)

    @app.route("/alerts")
    def alerts():
        args = {k: request.args.get(k, "") for k in ("severity", "status", "rule_id")}
        if "status" not in request.args:
            args["status"] = "open"
        rows = db().list_alerts(**args, limit=500)
        return render_template("alerts.html", alerts=rows, f=args, rules=rules)

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id: int):
        alert = db().get_alert(alert_id)
        if alert is None:
            abort(404)
        events = db().alert_events(alert_id)
        others = []
        if alert["src_ip"]:
            others = db().conn.execute(
                "SELECT * FROM alerts WHERE src_ip = ? AND id != ? ORDER BY last_seen DESC"
                " LIMIT 10", (alert["src_ip"], alert_id)).fetchall()
        return render_template("alert_detail.html", alert=alert, events=events,
                               rule=rules_by_id.get(alert["rule_id"]), others=others)

    def same_origin() -> bool:
        """CSRF check: the form must come from this dashboard. Compares scheme
        and host:port exactly (a prefix check would let http://localhost:50000
        pass for a dashboard on :5000). Browsers always send Origin on
        cross-site POSTs, so a request with neither header isn't from a
        malicious page."""
        source = request.headers.get("Origin") or request.headers.get("Referer")
        if not source:
            return True
        ours, theirs = urlsplit(request.host_url), urlsplit(source)
        return (theirs.scheme, theirs.netloc) == (ours.scheme, ours.netloc)

    def safe_next(target: str | None) -> str | None:
        """Only follow redirects to paths on this site (no open redirect)."""
        if target and target.startswith("/") and not target.startswith(("//", "/\\")):
            return target
        return None

    @app.post("/alerts/<int:alert_id>/status")
    def set_status(alert_id: int):
        if not same_origin():
            abort(403)
        try:
            db().set_alert_status(alert_id, request.form.get("status", ""))
        except ValueError:
            abort(400)
        return redirect(safe_next(request.form.get("next"))
                        or url_for("alert_detail", alert_id=alert_id))

    @app.route("/events")
    def events():
        f = {k: request.args.get(k, "").strip()
             for k in ("q", "source", "event_type", "src_ip")}
        page = max(request.args.get("page", 1, type=int) or 1, 1)  # junk -> page 1
        per_page = 100
        rows = db().search_events(**f, limit=per_page + 1, offset=(page - 1) * per_page)
        return render_template("events.html", events=rows[:per_page], f=f, page=page,
                               has_next=len(rows) > per_page,
                               sources=db().distinct("source"),
                               types=db().distinct("event_type"))

    @app.route("/rules")
    def rules_page():
        counts = dict(db().conn.execute(
            "SELECT rule_id, COUNT(*) FROM alerts GROUP BY rule_id").fetchall())
        ordered = sorted(rules, key=lambda r: (-SEVERITY_ORDER[r.severity], r.id))
        return render_template("rules.html", rules=ordered, counts=counts)

    # ---- JSON API (for scripts, or a future frontend) -------------------

    @app.route("/api/stats")
    def api_stats():
        since, _, _ = window()
        s = db().stats(since)
        for k in ("top_rules", "top_attackers", "by_source"):
            s[k] = [dict(r) for r in s[k]]
        return jsonify(s)

    @app.route("/api/alerts")
    def api_alerts():
        rows = db().list_alerts(severity=request.args.get("severity", ""),
                                status=request.args.get("status", ""), limit=500)
        return jsonify([dict(r) for r in rows])

    return app
