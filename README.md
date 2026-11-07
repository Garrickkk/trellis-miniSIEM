# Trellis

A small SIEM written in Python. It reads SSH, web server and
[GrapeVine](https://github.com/Garrickkk/grapevine-scanner) scan logs, normalizes them
into one event format, correlates them with detection rules, and shows alerts
on a web dashboard.

I built it to learn how SIEMs like Splunk and Wazuh work under the hood. It's
the companion project to GrapeVine, my network scanner.

## Features

- **Three log sources**, auto-detected: Linux `auth.log` (SSH, sudo, user
  changes), nginx/Apache access logs, and GrapeVine scan output.
- **Four rule types**: `match` (one suspicious event), `threshold` (N events in
  a time window), `sequence` (ordered steps, like failed logins followed by a
  success), and `new_value` (like a port that wasn't open in the last scan).
- **20 detection rules** in YAML for SSH brute force, privilege escalation, web
  attacks and newly exposed services, each mapped to MITRE ATT&CK.
- **Web dashboard** to triage alerts, see the events behind each one, and
  search all events.
- **Live mode** that follows log files and alerts as new lines are written.

## Quick start

Requires Python 3.10+.

```bash
pip install -r requirements.txt

python -m trellis ingest samples/auth.log samples/access.log
python -m trellis ingest samples/scan-baseline.txt
python -m trellis ingest samples/scan-latest.txt

python -m trellis serve        # open http://127.0.0.1:5000
```

The samples contain one full attack: web recon, an SSH brute force that
succeeds, a root shell, a backdoor account, and a new open port found by the
next GrapeVine scan. They're dated 31 October 2026, so set the dashboard's time
range to **all**.

## Usage

```bash
python -m trellis ingest LOG [LOG ...]   # read logs once (safe to re-run)
python -m trellis watch LOG [LOG ...]    # follow logs live; add --serve for the dashboard
python -m trellis serve                  # run the dashboard
python -m trellis rules                  # validate and list the rules
```

Real logs work the same way, for example `/var/log/auth.log` or
`/var/log/nginx/access.log`. For GrapeVine, save a scan with
`python grapevine.py <target> > scan.txt` and ingest the file. The first scan
of each host becomes its baseline, and later scans alert on what changed.

## Writing rules

Rules live in `rules/`. This one alerts when an IP fails five SSH logins and
then gets in:

```yaml
- id: ssh-brute-force-success
  name: Successful SSH login after brute force
  severity: critical
  mitre: [T1110, T1078]
  type: sequence
  group_by: [src_ip]
  window: 900
  steps:
    - where: {event_type: ssh_failed_login}
      min_count: 5
    - where: {event_type: ssh_login_success}
```

Conditions support exact values, lists, and the operators `|contains`,
`|startswith`, `|regex`, `|not`, `|gt`, `|gte`, `|lt` and `|lte`.

## How it works

```
log files → parsers → normalized events → SQLite → detection engine → alerts → dashboard
```

Every parser produces the same event shape, so rules don't care which log a
field came from. That's what lets one rule correlate a web scan with an SSH
login from the same IP.

Attackers control part of what ends up in logs, so the parsers are defensive:
an SSH username can't be used to spoof the source IP, escaped quotes in a URL
can't hide a request from the parser, and log text is always escaped on the
dashboard.

## Tests

```bash
pip install pytest
pytest
```
