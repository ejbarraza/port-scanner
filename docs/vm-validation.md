# Real-VM validation (manual, outside CI)

CI covers loopback and mocked sockets only. This checklist validates the
scanner against a real Windows 11 VM, where NAT queuing, the host
firewall, and real services produce the verdicts CI cannot.

## Setup

- VM: Windows 11 (64-bit) VirtualBox VM (the CIS-25 lab VM works).
- Modes: run the whole checklist twice — once with the VM on NAT
  networking, once on bridged networking.
- Firewall: Windows Firewall ON for both runs.
- Baseline services: enable one known listener on the VM (e.g. an
  HTTP server on 8000, or SSH if installed). Note its port here:
  expected-open port: ____
- From the host, confirm you can reach the VM IP: `ping <vm-ip>`.

## Steps

1. Loopback self-test on the host running the scan:
   `python3 scanner.py --self-test` — expect PASS.
2. Single-host scan of the VM IP, common ports:
   `python3 scanner.py <vm-ip> --auth-ref <lab/ticket>`
   Expect: the known listener is `confirmed-open`; the run exits 0
   unless indeterminate ports appear.
3. Full scan of the VM IP (all 65,535 ports) in NAT mode. Record:
   verdict counts, QC result, elapsed, exit code.
4. Repeat step 3 in bridged mode. Record the same.
5. Compare NAT vs bridged verdicts. Any port that flips between
   `filtered-timeout` and `closed` across runs is an unstable verdict —
   note it as a sampling limitation, not a finding.
6. Confirm the journal: `python3 scanner.py --verify-chain`
   — expect "chain intact".
7. Resurvey: re-run with `--resurvey <previous JSON report>`
   against the same VM; confirm `passes`/`detections` appear and
   indeterminate hosts are the only ones re-scanned.

## Results log

| Date | VM mode | Known-open port verdict | Verdict counts | QC | Exit code | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| | NAT | | | | | |
| | Bridged | | | | | |

## Rules

- Never run this checklist against a network you do not own or have
  explicit permission to test.
- Report IPv6 as an untested gap (the scanner is IPv4-only), not a pass.
- A powered-off or snapshotted VM is a sampling gap, not a closed network.
