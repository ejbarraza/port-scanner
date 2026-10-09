# Lab Finding — <subnet> subnet audit

**Date:** YYYY-MM-DD
**Environment:** VirtualBox NAT network, host scanner run from `CIS25VM3` (Windows 11, 64-bit)
**Tool:** [port-scanner](../scanner.py) (terminal output captured — screenshot attached as `subnet-scan-terminal.png`)

## Objective

Audit the virtual lab subnet for exposed services — map every reachable host,
list open ports, and write one-line remediation notes per finding. Contained
inside the NAT subnet: safe to probe, nothing leaves the VM.

## Method

```powershell
ipconfig                       # found gateway 10.0.2.2, DNS 10.0.2.3, host 10.0.2.15
python scanner.py 10.0.2.0/24 --quick
```

## Findings

| Host | Open ports | Service | Assessment |
|------|-----------|---------|------------|
| 10.0.2.2 | — | gateway | VirtualBox gateway — expected, not a vulnerability |
| 10.0.2.15 | 135 (msrpc), 445 (smb) | Windows file sharing | Standard on Windows. 445 = SMB, the EternalBlue/WannaCry port: keep patched, disable if unused |

*(Fill in from your report.)*

## Remediation notes

- Port 445 open on the host: verified Windows is fully patched; SMBv1 disabled
  (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`).
- Port 135 (MSRPC): standard Windows RPC — no action; left enabled for local services.

## Lessons

- First scan run stalled for ~25 min: the scanner did a reverse-DNS lookup on
  all 254 addresses and each dead host burned seconds waiting on DNS timeouts.
  Fixed upstream by only resolving hosts with actual open ports
  ([commit fc72415](https://github.com/ejbarraza/port-scanner)).
- Real scanners separate *host discovery* (who's alive) from *port scanning*
  (what's open) — now I know why.

---
One file per scan. Link from the resume as: **"Virtual Lab Network Audit —
documented subnet audits with findings + remediation (docs/lab-findings/)"**
