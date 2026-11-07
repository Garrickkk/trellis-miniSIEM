"""Command-line interface.

  python -m trellis ingest LOG [LOG ...]      read logs once (only new lines on re-runs)
  python -m trellis watch LOG [LOG ...]       follow logs live, alerting in the terminal
  python -m trellis serve                     web dashboard on http://127.0.0.1:5000
  python -m trellis rules                     check and list detection rules
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

from . import __version__
from .engine import Pipeline
from .parsers import LOCAL_TZ, PARSERS
from .rules import Detection, RuleError, load_rules
from .storage import Storage

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = ROOT / "rules"

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[93m",
          "low": "\033[94m", "info": "\033[90m"}
RESET, DIM = "\033[0m", "\033[2m"


def use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        os.system("")  # enables ANSI escape codes in the Windows console
    return sys.stdout.isatty()


def print_alert(alert_id: int, det: Detection, color: bool) -> None:
    sev = det.rule.severity
    ev = det.events[-1]
    when = ev.timestamp.astimezone(LOCAL_TZ).strftime("%H:%M:%S")
    tag = f" {sev.upper():<8} "
    who = " ".join(x for x in (ev.src_ip, ev.user and f"user={ev.user}",
                               ev.source == "grapevine" and ev.host) if x)
    if color:
        tag = f"{COLORS[sev]}{tag}{RESET}"
        print(f"{DIM}{when}{RESET} {tag} {det.rule.name} {DIM}#{alert_id}{RESET}  "
              f"{who}  {DIM}({len(det.events)} events){RESET}")
    else:
        print(f"{when} [{sev.upper()}] {det.rule.name} #{alert_id}  {who}  ({len(det.events)} events)")


def make_pipeline(args) -> Pipeline:
    try:
        rules = load_rules(args.rules)
    except (RuleError, OSError) as exc:
        sys.exit(f"error loading rules: {exc}")
    color = use_color()
    on_alert = None if getattr(args, "quiet", False) else (lambda i, d: print_alert(i, d, color))
    return Pipeline(Storage(args.db), rules, on_alert=on_alert)


def check_files(paths: list[str]) -> list[str]:
    missing = [p for p in paths if not os.path.isfile(p)]
    if missing:
        sys.exit("error: file not found: " + ", ".join(missing))
    return paths


# ---- commands --------------------------------------------------------------

def cmd_ingest(args) -> int:
    pipe = make_pipeline(args)
    result = pipe.ingest(check_files(args.files), log_type=args.type)
    for f in result.skipped_files:
        print(f"warning: couldn't recognize the format of {f}; try --type "
              f"{{{','.join(PARSERS)}}}", file=sys.stderr)
    print(f"\nIngested {result.events} events, {result.new_alerts} new alerts -> {args.db}")
    return 0


def cmd_watch(args) -> int:
    pipe = make_pipeline(args)
    if args.serve:
        start_server_thread(args)
    print(f"Watching {len(args.files)} file(s) with {len(pipe.detector.rules)} rules. "
          f"Ctrl+C to stop.\n")
    try:
        if args.from_start:
            pipe.ingest([f for f in args.files if os.path.exists(f)], log_type=args.type)
        else:
            # skip what's already in the files; only alert on new lines
            for f in args.files:
                if os.path.exists(f):
                    st = os.stat(f)
                    pipe.storage.set_file_state(str(Path(f).resolve()), st.st_ino, st.st_size,
                                                st.st_mtime_ns)
            pipe.storage.commit()
        pipe.watch(args.files, log_type=args.type, interval=args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def start_server_thread(args) -> None:
    from .web import create_app
    app = create_app(args.db, load_rules(args.rules))
    t = threading.Thread(target=lambda: app.run(host=args.host, port=args.port,
                                                use_reloader=False), daemon=True)
    t.start()
    print(f"Dashboard: http://{args.host}:{args.port}")


def cmd_serve(args) -> int:
    from .web import create_app
    app = create_app(args.db, load_rules(args.rules))
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        if args.debug:
            # Flask's debugger runs arbitrary Python from the browser
            sys.exit("error: refusing --debug on a non-local --host; the debugger "
                     "would let anyone on the network run code on this machine")
        print("warning: the dashboard has no login. Anyone who can reach "
              f"{args.host}:{args.port} can read your logs.", file=sys.stderr)
    print(f"Dashboard: http://{args.host}:{args.port}  (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def cmd_rules(args) -> int:
    try:
        rules = load_rules(args.rules)
    except (RuleError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    order = ["critical", "high", "medium", "low", "info"]
    for r in sorted(rules, key=lambda r: (order.index(r.severity), r.id)):
        mitre = ",".join(r.mitre)
        print(f"{r.severity:<9}{r.type:<10}{r.id:<30}{mitre}")
    print(f"\n{len(rules)} rules OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trellis", description="A small SIEM: logs in, alerts out.")
    p.add_argument("--version", action="version", version=f"trellis {__version__}")
    p.add_argument("--db", default="trellis.db", help="SQLite database file (default trellis.db)")
    p.add_argument("--rules", default=str(DEFAULT_RULES), help="rules directory or file")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_files(sp):
        sp.add_argument("files", nargs="+", help="log files (auth.log, access.log, GrapeVine output)")
        sp.add_argument("--type", choices=list(PARSERS), help="force a log format instead of auto-detecting")
        sp.add_argument("-q", "--quiet", action="store_true", help="don't print alerts")

    def add_server(sp):
        sp.add_argument("--host", default="127.0.0.1")
        sp.add_argument("--port", type=int, default=5000)

    sp = sub.add_parser("ingest", help="read log files once")
    add_files(sp)
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("watch", help="follow log files and alert live")
    add_files(sp)
    add_server(sp)
    sp.add_argument("--from-start", action="store_true", help="also process lines already in the files")
    sp.add_argument("--interval", type=float, default=1.0, help="seconds between checks (default 1)")
    sp.add_argument("--serve", action="store_true", help="run the dashboard at the same time")
    sp.set_defaults(func=cmd_watch)

    sp = sub.add_parser("serve", help="run the web dashboard")
    add_server(sp)
    sp.add_argument("--debug", action="store_true")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("rules", help="validate and list rules")
    sp.set_defaults(func=cmd_rules)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
