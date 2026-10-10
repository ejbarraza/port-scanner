# port-scanner

A small, fast, dependency-free TCP port scanner in Python. Point it at a host
or a whole subnet and get open ports, service banners, and a clean report —
as text, JSON, CSV, or a styled HTML page.

Zero third-party dependencies: just the standard library. No root required
(plain TCP connect scans, no raw sockets).

> 📄 [IT Projects one-pager (PDF)](docs/it-projects-one-pager.pdf) —
> this project plus the homelab network audit and 21 documented Windows 11
> administration labs, in a one-page resume-ready summary.

## Features

- **TCP connect scanning** — threaded for speed (200 parallel probes by default)
- **Flexible targets** — single IP, hostname, or CIDR subnet (`192.168.1.0/24`)
- **Scan profiles** — `--quick` (top ~50 ports), default (common service ports),
  `--full` (all 65,535), or a custom `--ports 20-100` / `22,80,443` spec
- **Banner grabbing** — captures spontaneous service greetings (SSH, SMTP, FTP…)
- **HTTP probing** — sends `HEAD /` on web ports and extracts the status line
  plus the `Server` header
- **Reverse DNS** — resolves hostnames for each target
- **Four report formats** — text, JSON, CSV, and a styled HTML page
- **Live progress + timing stats** on stderr (never pollutes piped output)
- **Graceful Ctrl+C** — interrupts cleanly and still renders partial results

## Quick start

```bash
# scan a host's common service ports
python3 scanner.py 192.168.1.1

# quick sweep of a subnet, HTML report
python3 scanner.py 192.168.1.0/24 --quick -o report.html

# full 65k-port scan of one host, JSON output
python3 scanner.py 10.0.0.5 --full --timeout 0.5 --workers 400 \
    --format json -o scan.json

# custom port spec, CSV to stdout
python3 scanner.py example.com --ports 20-100 --format csv
```

Sample output:

```
scanning 192.168.1.1 (192.168.1.1) — 61 ports...

192.168.1.1 (router.lan)
  PORT   SERVICE      BANNER
  22     ssh          SSH-2.0-OpenSSH_9.2
  80     http         HTTP/1.1 200 OK | nginx/1.24.0
  443    https        HTTP/1.1 200 OK | nginx/1.24.0

1 host(s), 3 open port(s), 2.4s elapsed
```

## How it works

Each probe is a plain `connect()` call with a configurable timeout — the same
technique as `nmap -sT`, but without any privileged operations. Open ports get
a follow-up read for a spontaneous banner; web ports with no banner receive a
`HEAD /` request so the `Server` header can be fingerprinted. ThreadPoolExecutor
fans the probes out (default 200 workers); a lock-guarded counter prints
progress to stderr every 100 probes.

OS fingerprinting is deliberately absent: real fingerprinting needs raw sockets
and root, and guessing from banners is dishonest. What you see is what the
network said.

## Project layout

```
scanner.py              # the whole scanner (stdlib only)
tests/test_scanner.py   # 23 tests, loopback-only, no external network
```

Run the tests with:

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -q
```

## Ethics

Only scan hosts and networks you own or have explicit written permission to
test. Unauthorized scanning can violate computer-misuse law and your ISP's
terms of service. This tool is built for learning, homelabs, and authorized
audits — the way you'd use it in an IT networking course.

## License

MIT — see [LICENSE](LICENSE).
