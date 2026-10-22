# port-scanner

A small, fast, dependency-free TCP port scanner in Python. Point it at a host
or a whole subnet and get open ports, service banners, and a clean report —
as text, JSON, CSV, or a styled HTML page.

Zero third-party dependencies: just the standard library. No root required
(plain TCP connect scans, no raw sockets).

Version 2 is an evidence-grade audit tool: every port gets an explicit
verdict instead of a binary open/non-open, open findings are confirmed
with a second probe, per-host control ports act as quality controls, and
every report ships with a chain-of-custody manifest. Say "not detected in
N attempts", never "absent".

> 📄 [IT Projects one-pager (PDF)](docs/it-projects-one-pager.pdf) —
> this project plus the homelab network audit, 31 documented Windows 11
> administration walkthroughs, and CIS-27 cybersecurity lab work.

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
- **Graceful Ctrl+C** — interrupts cleanly and renders partial results,
  explicitly marked partial
- **Per-port verdicts** — `confirmed-open`, `open-single-probe`, `closed`,
  `filtered-timeout`, `error` (with error class), plus attempt counts and
  per-port latency. A timeout is not a closed port.
- **Confirmatory re-probes** — open ports are probed a second time on a
  separate connection before they count as confirmed (`--no-confirm` to skip)
- **Quality controls** — every host gets a probe of an expected-closed
  control port (19999); if it does not come back closed, the host's
  results are flagged QC-failed and indeterminate
- **Retries + rate limiting** — `--retries` retries filtered-timeout ports
  with jittered backoff; `--rate-limit` caps connects per second; workers
  are capped to stay under the file-descriptor limit
- **Safe-by-default UX** — non-loopback targets require a scope
  confirmation (or `--yes`), `--auth-ref` records the authorization
  basis, and every run appends to a hash-chained journal
  (`--verify-chain` checks it). Very large scans need an explicit `--yes`.
- **Reporting** — a skim summary on every report, a chain-of-custody
  manifest (operator, auth ref, tool version + git commit, exact CLI
  invocation, scope + report hashes), `--redact` for publishable samples
  (redaction map stays local), and `--resurvey` to re-scan only
  indeterminate hosts with detection history (`detected 1/2 passes`)
- **Self-test** — `python3 scanner.py --self-test` runs the loopback
  self-check (open/closed verdicts, control QC, parsing)

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

# loopback self-check, then verify the run journal
python3 scanner.py --self-test
python3 scanner.py --verify-chain
```

Sample output:

```
Port scan summary
  1 host(s), 61 port verdict(s), 3 open port(s), 2.4s elapsed
  verdicts — closed: 58, confirmed-open: 3

192.168.1.1 (router.lan)  [confidence: confirmed]
  PORT   SERVICE      VERDICT         BANNER
  22     ssh          confirmed-open  SSH-2.0-OpenSSH_9.2
  80     http         confirmed-open  HTTP/1.1 200 OK | nginx/1.24.0
  443    https        confirmed-open  HTTP/1.1 200 OK | nginx/1.24.0

1 host(s), 3 open port(s), 2.4s elapsed
```

## How it works

Each probe is a plain `connect()` call with a configurable timeout — the same
technique as `nmap -sT`, but without any privileged operations. The
`connect_ex()` return code is classified into a verdict: 0 → open, refused →
closed, timeout → filtered-timeout, anything else → error with its class.
Open ports get a confirmatory re-probe on a separate connection, and every
host gets a probe of an expected-closed control port (19999) as a quality
control — if it does not come back closed, the host's results are flagged
QC-failed and indeterminate. Open ports get a follow-up read for a
spontaneous banner; web ports with no banner receive a `HEAD /` request so
the `Server` header can be fingerprinted. ThreadPoolExecutor fans the probes
out (default 200 workers, capped to stay under the file-descriptor limit);
a lock-guarded counter prints progress to stderr every 100 probes.

Every report carries a skim summary and a chain-of-custody manifest
(operator, auth ref, tool version + git commit, exact CLI invocation,
scope + report hashes). The redaction map is never embedded — it stays
local with the operator.

OS fingerprinting is deliberately absent: real fingerprinting needs raw sockets
and root, and guessing from banners is dishonest. What you see is what the
network said.

## Exit codes

- `0` — clean run (all hosts QC-passed, no indeterminate findings)
- `1` — usage error, or a scan that could not run
- `2` — a control-port QC check failed, or any host came back indeterminate
- `3` — interrupted run; the report is partial

## Report v2 migration note

Report version 2 changes the schema: per-port verdicts replace the binary
open/non-open model, JSON gains `summary` + `manifest`, and CSV gains
verdict / confidence / attempts / latency / error / passes / detections
columns. Old consumers that counted only `open` will report "all clear" on
a scan that was mostly errors — check `verdict_counts` and `confidence`
instead. The `open_ports` list is kept for backward compatibility.

## Real-VM validation

CI covers loopback and mocked sockets only. The manual checklist in
[docs/vm-validation.md](docs/vm-validation.md) validates the scanner
against a real Windows 11 VM in NAT and bridged modes with the firewall
on.

## Project layout

```
scanner.py              # the whole scanner (stdlib only)
tests/test_scanner.py   # 50 tests, loopback-only, no external network
```

Run the tests with:

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -q
```

## Ethics

Only scan hosts and networks you own or have explicit written permission to
test. Unauthorized scanning can violate computer-misuse law and your ISP's
terms of service. This tool is built for authorized engagements —
learning, homelabs, and the way you'd use it in an IT networking course.

## License

MIT — see [LICENSE](LICENSE).
