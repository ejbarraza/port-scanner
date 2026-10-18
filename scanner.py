#!/usr/bin/env python3
"""
port-scanner — a small, fast, dependency-free TCP port scanner.

TCP connect scans (no raw sockets, no root required), threaded for speed,
with banner grabbing, HTTP service probing, reverse DNS, and
text / JSON / CSV / HTML reports.

Version 2 is an evidence-grade audit tool: every port gets an explicit
verdict (confirmed-open / open-single-probe / closed / filtered-timeout /
error) instead of a binary open/non-open, open findings are confirmed with
a second probe, per-host control ports act as quality controls, and every
report ships with a chain-of-custody manifest. Say "not detected in N
attempts", never "absent".

Usage:
    python3 scanner.py 192.168.1.1
    python3 scanner.py 192.168.1.0/24 --quick -o report.html
    python3 scanner.py example.com --ports 1-1024 --format json -o out.json
    python3 scanner.py 10.0.0.5 --full --timeout 0.5 --workers 400
    python3 scanner.py --self-test            # loopback self-check
    python3 scanner.py --verify-chain        # verify the run journal

Exit codes: 0 clean, 1 usage/error, 2 QC failed or indeterminate
findings, 3 partial (interrupted) results.

Only scan hosts and networks you own or have explicit permission to test.
Non-loopback targets require a scope confirmation (or --yes), and every
run is appended to a hash-chained journal.
"""

import argparse
import copy
import csv
import errno
import getpass
import hashlib
import html
import io
import ipaddress
import json
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    import resource
except ImportError:  # non-Unix platforms
    resource = None

__version__ = "2.0.0"
REPORT_VERSION = 2

SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 79: "finger",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
    123: "ntp", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    162: "snmp-trap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 515: "printer", 587: "smtp-submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2121: "ftp-proxy",
    2181: "zookeeper", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    5060: "sip", 5432: "postgres", 5672: "rabbitmq", 5900: "vnc",
    5985: "winrm", 6379: "redis", 6443: "kubernetes", 7001: "cassandra",
    8000: "http-alt", 8008: "http-alt", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9100: "jetdirect",
    9200: "elasticsearch", 27017: "mongodb",
}

# The ~50 most commonly open TCP ports (quick profile).
QUICK_PORTS = [
    21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 119, 135, 139, 143,
    161, 389, 443, 445, 465, 514, 515, 587, 636, 993, 995, 1080,
    1433, 1521, 1723, 2049, 2121, 2181, 3000, 3306, 3389, 5060,
    5432, 5672, 5900, 5985, 6379, 6443, 7001, 8000, 8008, 8080,
    8443, 8888, 9000, 9100, 9200, 27017,
]

# Ports where an HTTP HEAD probe is worth trying when no banner arrives.
HTTP_PORTS = {80, 8000, 8008, 8080, 8888, 8443, 8000, 3000, 9000}

MAX_SUBNET_SIZE = 4096
# A probe of this port is expected to come back closed; it is the
# per-host quality-control check. 19999 is unassigned and almost never
# listened on, so a non-closed result means something is off with the
# scan path, not the target.
CONTROL_CLOSED_PORT = 19999
# Scans larger than this need an explicit --yes (range block).
RANGE_BLOCK_PROBES = 100_000
DEFAULT_JOURNAL = os.path.expanduser("~/.port-scanner/journal.jsonl")

# Verdicts: confirmed-open (two independent connects), open-single-probe
# (open once, confirmation failed or disabled), closed (refused),
# filtered-timeout (no answer within timeout), error (classified failure).
VERDICTS = ("confirmed-open", "open-single-probe", "closed",
            "filtered-timeout", "error")


def parse_ports(spec):
    """'80' / '20-100' / '22,80,443' -> sorted list of valid ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_targets(spec):
    """IP, hostname, or CIDR -> list of IP strings to scan."""
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.num_addresses == 1:
            return [str(net.network_address)]
        if net.num_addresses > MAX_SUBNET_SIZE:
            sys.exit(f"subnet too large ({net.num_addresses} addresses); "
                     f"limit is {MAX_SUBNET_SIZE} — narrow the range")
        return [str(h) for h in net.hosts()]
    try:
        return [socket.gethostbyname(spec)]
    except socket.gaierror:
        sys.exit(f"cannot resolve target: {spec}")


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def is_loopback_ip(ip):
    """True for loopback addresses (127.0.0.0/8, ::1, localhost)."""
    if ip == "localhost":
        return True
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _classify_connect(rc):
    """connect_ex() return code -> (verdict, error class).

    0 means the handshake completed. A refusal is a definite closed.
    A timeout is *not* a closed port: it means no answer arrived, which
    is why it gets its own verdict instead of collapsing into non-open.
    """
    if rc == 0:
        return ("open", None)
    if rc == errno.ECONNREFUSED:
        return ("closed", "refused")
    if rc in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
        return ("filtered-timeout", "timeout")
    if rc in (errno.EHOSTUNREACH, errno.ENETUNREACH,
              errno.EHOSTDOWN, errno.ENETDOWN):
        return ("error", "unreachable")
    if rc == errno.EACCES:
        return ("error", "permission")
    return ("error", f"errno-{rc}")


def _read_banner(sock, timeout):
    """Best-effort read of a service's spontaneous greeting."""
    try:
        sock.settimeout(timeout)
        data = sock.recv(512)
        return data.decode(errors="replace").strip().split("\n")[0][:120]
    except (socket.timeout, OSError):
        return ""


def _http_probe(sock, timeout):
    """Send HEAD / and extract the status line + Server header."""
    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
        sock.settimeout(timeout)
        data = sock.recv(1024).decode(errors="replace")
    except OSError:
        return ""
    lines = data.replace("\r\n", "\n").split("\n")
    status = lines[0].strip() if lines else ""
    server = ""
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
        if line == "":
            break
    return " | ".join(p for p in (status, server) if p)[:160]


def _connect_once(ip, port, timeout):
    """One TCP connect attempt -> (verdict, error, latency_ms, banner).

    Verdict is "open" / "closed" / "filtered-timeout" / "error"; callers
    decide whether "open" becomes confirmed-open or open-single-probe.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        t0 = time.time()
        rc = sock.connect_ex((ip, port))
        latency = round((time.time() - t0) * 1000, 1)
        verdict, error = _classify_connect(rc)
        banner = ""
        if verdict == "open":
            banner = _read_banner(sock, timeout)
            if not banner and port in HTTP_PORTS:
                banner = _http_probe(sock, timeout)
        return verdict, error, latency, banner
    except OSError as e:
        return "error", f"oserror-{getattr(e, 'errno', 'unknown')}", None, ""
    finally:
        sock.close()


def probe_port_detailed(ip, port, timeout, retries=0, confirm=True,
                        rate_limiter=None):
    """Probe one port with retries + confirmatory re-probe.

    Returns a dict: port, service, verdict, error, attempts,
    latency_ms, banner. Retries apply to filtered-timeout only, with
    jittered exponential backoff. An open port is re-probed once on a
    separate connection: open twice -> confirmed-open, otherwise
    open-single-probe.
    """
    attempts = 0
    verdict, error, latency, banner = "closed", None, None, ""
    while True:
        attempts += 1
        if rate_limiter is not None:
            rate_limiter.acquire()
        verdict, error, latency, banner = _connect_once(ip, port, timeout)
        if verdict == "open":
            if confirm:
                if rate_limiter is not None:
                    rate_limiter.acquire()
                c_verdict, _, _, _ = _connect_once(ip, port, timeout)
                attempts += 1
                verdict = ("confirmed-open" if c_verdict == "open"
                           else "open-single-probe")
            else:
                verdict = "open-single-probe"
            break
        if verdict == "filtered-timeout" and attempts <= retries:
            backoff = min(0.05 * (2 ** (attempts - 1))
                          + random.uniform(0, 0.05), 1.0)
            time.sleep(backoff)
            continue
        break
    return {"port": port,
            "service": SERVICE_NAMES.get(port, ""),
            "verdict": verdict,
            "error": error,
            "attempts": attempts,
            "latency_ms": latency,
            "banner": banner}


def probe_port(ip, port, timeout):
    """Backward-compatible wrapper: banner string for an open port, else None."""
    d = probe_port_detailed(ip, port, timeout, retries=0, confirm=False)
    if d["verdict"] in ("confirmed-open", "open-single-probe"):
        return d["banner"]
    return None


class RateLimiter:
    """Thread-safe connects-per-second cap."""

    def __init__(self, per_second):
        self.interval = 1.0 / float(per_second)
        self.lock = threading.Lock()
        self.next_ok = 0.0

    def acquire(self):
        with self.lock:
            now = time.time()
            wait = self.next_ok - now
            if wait > 0:
                time.sleep(wait)
                self.next_ok += self.interval
            else:
                self.next_ok = now + self.interval


class Progress:
    """Thread-safe stderr progress counter."""

    def __init__(self, total):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()
        self.start = time.time()

    def tick(self):
        with self.lock:
            self.done += 1
            if self.done % 100 == 0 or self.done == self.total:
                elapsed = max(time.time() - self.start, 1e-6)
                sys.stderr.write(
                    f"\r  {self.done}/{self.total} probes "
                    f"({self.done / elapsed:.0f}/s)")
                sys.stderr.flush()

    def finish(self):
        sys.stderr.write("\n")
        sys.stderr.flush()


def _effective_workers(workers):
    """Cap workers so the process stays under its file-descriptor limit."""
    eff = max(1, int(workers))
    if resource is not None:
        try:
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            eff = max(1, min(eff, soft - 64))
        except (ValueError, OSError):
            pass
    return eff


def scan_host(ip, ports, timeout, workers, progress=None, retries=0,
              confirm=True, control_ports=True, rate_limit=None):
    """Scan one host; return a result dict with per-port verdicts.

    On Ctrl+C the pending probes are cancelled instead of drained and
    the result is returned with partial=True, so an interrupted scan
    still yields marked-partial evidence instead of nothing.
    """
    limiter = RateLimiter(rate_limit) if rate_limit else None
    eff_workers = _effective_workers(workers)
    port_results = {}
    partial = False

    def work(port):
        d = probe_port_detailed(ip, port, timeout, retries=retries,
                                confirm=confirm, rate_limiter=limiter)
        if progress is not None:
            progress.tick()
        return d

    pool = ThreadPoolExecutor(max_workers=eff_workers)
    futures = []
    try:
        futures = [pool.submit(work, port) for port in ports]
        for fut in futures:
            d = fut.result()
            port_results[d["port"]] = d
    except KeyboardInterrupt:
        for fut in futures:
            fut.cancel()
        partial = True
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    ordered = [port_results[p] for p in sorted(port_results)]
    open_ports = [{"port": d["port"], "service": d["service"],
                   "banner": d["banner"],
                   "verdict": d["verdict"]}
                  for d in ordered
                  if d["verdict"] in ("confirmed-open", "open-single-probe")]

    # Quality control: an expected-closed port must come back closed.
    # If it does not, the scan path itself is suspect and the host's
    # results are flagged indeterminate, not trusted.
    qc = {"control_port": CONTROL_CLOSED_PORT,
          "control_verdict": None, "passed": True}
    attempts = sum(d["attempts"] for d in ordered)
    if control_ports:
        c = probe_port_detailed(ip, CONTROL_CLOSED_PORT, timeout,
                                retries=0, confirm=False,
                                rate_limiter=limiter)
        attempts += c["attempts"]
        qc["control_verdict"] = c["verdict"]
        qc["passed"] = (c["verdict"] == "closed")

    verdict_counts = {}
    for d in ordered:
        verdict_counts[d["verdict"]] = verdict_counts.get(d["verdict"], 0) + 1
    verdicts = [d["verdict"] for d in ordered]
    if not qc["passed"]:
        confidence = "indeterminate"
    elif any(v in ("filtered-timeout", "error") for v in verdicts):
        confidence = "indeterminate"
    elif any(v == "open-single-probe" for v in verdicts):
        confidence = "single-probe"
    else:
        confidence = "confirmed"

    # Reverse-DNS only hosts worth naming: a lookup against a dead host can
    # stall for seconds on DNS timeouts, which would serialize a subnet sweep.
    hostname = reverse_dns(ip) if open_ports else ""
    return {"host": ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "ports": ordered,
            "verdict_counts": verdict_counts,
            "confidence": confidence,
            "qc": qc,
            "partial": partial,
            "attempts": attempts}


# ---------------------------------------------------------------- outputs

def _rows_for_host(r):
    """Uniform per-port rows from either the v2 `ports` list or legacy
    `open_ports`, so formatters accept both shapes."""
    if r.get("ports"):
        return r["ports"]
    return [{"port": p["port"], "service": p.get("service", ""),
             "banner": p.get("banner", ""),
             "verdict": p.get("verdict", "confirmed-open"),
             "error": p.get("error"), "attempts": p.get("attempts", 1),
             "latency_ms": p.get("latency_ms"),
             "passes": p.get("passes"), "detections": p.get("detections")}
            for p in r.get("open_ports", [])]


def build_summary(results, elapsed, partial):
    """Skim layer: scope, verdict totals, QC failures, top findings."""
    verdict_counts = {}
    open_total = 0
    ports_total = 0
    qc_failed = []
    top = []
    for r in results:
        counts = r.get("verdict_counts")
        if counts is None:  # legacy shape: derive from open_ports
            counts = {"confirmed-open": len(r.get("open_ports", []))}
        for k, v in counts.items():
            verdict_counts[k] = verdict_counts.get(k, 0) + v
        rows = _rows_for_host(r)
        ports_total += len(rows)
        for p in rows:
            if p["verdict"] in ("confirmed-open", "open-single-probe"):
                open_total += 1
                if len(top) < 10:
                    top.append({"host": r["host"], "port": p["port"],
                                "service": p.get("service", ""),
                                "verdict": p["verdict"],
                                "banner": p.get("banner", "")})
        if r.get("qc") and not r["qc"].get("passed", True):
            qc_failed.append(r["host"])
    return {"hosts_scanned": len(results),
            "ports_scanned": ports_total,
            "open_ports": open_total,
            "verdict_counts": verdict_counts,
            "qc_failed_hosts": qc_failed,
            "partial": partial,
            "elapsed_s": round(elapsed, 2),
            "top_findings": top}


def _host_line(r):
    title = r["host"] + (f" ({r['hostname']})" if r.get("hostname") else "")
    if r.get("confidence"):
        title += f"  [confidence: {r['confidence']}]"
    if r.get("qc") and not r["qc"].get("passed", True):
        title += "  [QC FAILED: control port did not come back closed]"
    if r.get("partial"):
        title += "  [PARTIAL]"
    return title


def format_text(results, elapsed, summary=None, manifest=None, partial=False):
    out = []
    if summary is None:
        summary = build_summary(results, elapsed, partial)
    out.append("Port scan summary")
    out.append(f"  {summary['hosts_scanned']} host(s), "
               f"{summary['ports_scanned']} port verdict(s), "
               f"{summary['open_ports']} open port(s), "
               f"{elapsed:.1f}s elapsed")
    if summary["verdict_counts"]:
        counts = ", ".join(f"{k}: {v}"
                           for k, v in sorted(summary["verdict_counts"].items()))
        out.append(f"  verdicts — {counts}")
    if summary["qc_failed_hosts"]:
        out.append("  QC FAILED hosts: " + ", ".join(summary["qc_failed_hosts"]))
    if summary["partial"]:
        out.append("  PARTIAL RESULTS — scan interrupted; "
                   "treat findings as incomplete")
    out.append("")
    for r in results:
        out.append(_host_line(r))
        open_ports = r.get("open_ports", [])
        if not open_ports:
            attempts = r.get("attempts")
            if attempts:
                out.append(f"  no open ports detected in {attempts} attempts")
            else:
                out.append("  no open ports found")
        else:
            out.append(f"  {'PORT':<7}{'SERVICE':<13}{'VERDICT':<18}BANNER")
            for p in open_ports:
                verdict = p.get("verdict", "confirmed-open")
                banner = p["banner"]
                if p.get("passes", 1) > 1:
                    banner += (f" [detected {p.get('detections', '?')}"
                               f"/{p['passes']} passes]")
                out.append(f"  {p['port']:<7}{p['service']:<13}"
                           f"{verdict:<18}{banner}")
        out.append("")
    total_open = sum(len(r.get("open_ports", [])) for r in results)
    out.append(f"{len(results)} host(s), {total_open} open port(s), "
               f"{elapsed:.1f}s elapsed")
    if manifest is not None:
        out.append("")
        out.append("--- manifest ---")
        out.append(json.dumps(manifest, indent=2, sort_keys=True))
    return "\n".join(out)


def _canonical_json(obj):
    return json.dumps(obj, indent=2, sort_keys=True)


def format_json(results, elapsed, summary=None, manifest=None, partial=False):
    if summary is None:
        summary = build_summary(results, elapsed, partial)
    doc = {"report_version": REPORT_VERSION,
           "generated": datetime.now(timezone.utc).isoformat(),
           "elapsed_s": round(elapsed, 2),
           "summary": summary,
           "hosts": results}
    if manifest is not None:
        doc["manifest"] = manifest
    return _canonical_json(doc)


def format_csv(results):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["host", "hostname", "port", "service", "verdict",
                "confidence", "attempts", "latency_ms", "error",
                "passes", "detections", "banner"])
    for r in results:
        for p in _rows_for_host(r):
            w.writerow([r["host"], r.get("hostname", ""), p["port"],
                        p.get("service", ""), p.get("verdict", ""),
                        r.get("confidence", ""), p.get("attempts", ""),
                        p.get("latency_ms", ""), p.get("error", ""),
                        p.get("passes", ""), p.get("detections", ""),
                        p.get("banner", "")])
    return buf.getvalue()


def format_html(results, elapsed, summary=None, manifest=None, partial=False):
    if summary is None:
        summary = build_summary(results, elapsed, partial)
    counts = ", ".join(f"{html.escape(k)}: {v}"
                       for k, v in sorted(summary["verdict_counts"].items()))
    head = (f"<p>Summary: {summary['hosts_scanned']} host(s), "
            f"{summary['ports_scanned']} port verdict(s), "
            f"{summary['open_ports']} open port(s), "
            f"{elapsed:.1f}s elapsed.<br>Verdicts: {counts}.</p>")
    if summary["qc_failed_hosts"]:
        head += ("<p><strong>QC FAILED hosts:</strong> "
                 + ", ".join(html.escape(h)
                             for h in summary["qc_failed_hosts"]) + "</p>")
    if summary["partial"]:
        head += ("<p><strong>PARTIAL RESULTS</strong> — scan interrupted; "
                 "treat findings as incomplete.</p>")
    rows = []
    for r in results:
        title = html.escape(r["host"])
        if r.get("hostname"):
            title += f" ({html.escape(r['hostname'])})"
        rows.append(f"<h2>{title}</h2>")
        if r.get("confidence"):
            rows.append(f"<p>Confidence: {html.escape(r['confidence'])}</p>")
        if r.get("qc") and not r["qc"].get("passed", True):
            rows.append("<p><strong>QC FAILED:</strong> control port did "
                        "not come back closed.</p>")
        host_rows = _rows_for_host(r)
        if not host_rows:
            rows.append("<p>No ports scanned.</p>")
            continue
        trs = "".join(
            f"<tr><td>{p['port']}</td>"
            f"<td>{html.escape(p.get('service', ''))}</td>"
            f"<td>{html.escape(p.get('verdict', ''))}</td>"
            f"<td>{html.escape(p.get('banner', ''))}</td></tr>"
            for p in host_rows)
        rows.append(
            f"<table><tr><th>Port</th><th>Service</th>"
            f"<th>Verdict</th><th>Banner</th></tr>{trs}</table>")
    manifest_html = ""
    if manifest is not None:
        manifest_html = ("<h2>Manifest</h2><pre>"
                         + html.escape(_canonical_json(manifest))
                         + "</pre>")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Port scan report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1em; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 2em; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
th {{ background: #f0f0f0; }}
.meta {{ color: #666; }}
</style></head><body>
<h1>Port scan report</h1>
<p class="meta">Generated {html.escape(datetime.now(timezone.utc).isoformat())}
&middot; {len(results)} host(s) &middot; {elapsed:.1f}s elapsed</p>
{head}
{''.join(rows)}
{manifest_html}
</body></html>
"""


# ---------------------------------------------------------------- manifest, journal, redaction, resurvey

def get_git_commit():
    """Short git commit of this checkout, or 'unknown' outside a repo."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stderr=subprocess.DEVNULL, timeout=5)
        return out.decode().strip()
    except Exception:
        return "unknown"


def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def build_manifest(argv, auth_ref, scope_hash, report_hash, partial, redacted):
    """Chain-of-custody manifest: who, what, how, and what the report is.

    The redaction map is never embedded: it is listed as withheld, and
    the operator keeps it locally.
    """
    try:
        operator = getpass.getuser()
    except Exception:
        operator = "unknown"
    return {"report_version": REPORT_VERSION,
            "tool": f"port-scanner {__version__}",
            "git_commit": get_git_commit(),
            "generated": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "auth_ref": auth_ref or "",
            "argv": list(argv),
            "scope_hash": scope_hash,
            "report_hash": report_hash,
            "partial": partial,
            "redacted": redacted,
            "redaction_map": "withheld"}


def _journal_hash(entry, prev_hash):
    payload = json.dumps(entry, sort_keys=True) + (prev_hash or "")
    return hashlib.sha256(payload.encode()).hexdigest()


def journal_append(path, entry):
    """Append one entry to the hash-chained run journal.

    Each entry's hash covers the entry plus the previous entry's hash,
    so deleting or editing an entry breaks every later hash.
    """
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    prev_hash = ""
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    prev_hash = json.loads(line).get("entry_hash", prev_hash)
                except json.JSONDecodeError:
                    continue
    entry = dict(entry)
    entry["prev_hash"] = prev_hash
    entry["entry_hash"] = _journal_hash(entry, prev_hash)
    with open(path, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify_journal_chain(path):
    """Return (ok, message) for the journal's hash chain."""
    if not os.path.exists(path):
        return False, f"journal not found: {path}"
    prev_hash = ""
    count = 0
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, f"entry {i}: not valid JSON"
            if entry.get("prev_hash", "") != prev_hash:
                return False, f"entry {i}: prev_hash mismatch — chain broken"
            expected = _journal_hash(
                {k: v for k, v in entry.items() if k != "entry_hash"},
                prev_hash)
            if entry.get("entry_hash") != expected:
                return False, f"entry {i}: entry_hash mismatch — tampered"
            prev_hash = entry["entry_hash"]
            count += 1
    return True, f"{count} entr{'y' if count == 1 else 'ies'}, chain intact"


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")


def redact_report(results):
    """Replace host identities with tokens; scrub IPs + versions in banners.

    Returns (redacted_results, redaction_map). The map is kept locally
    by the operator and must never be published alongside the report.
    """
    redacted = copy.deepcopy(results)
    token_for = {}

    def token(value):
        if value not in token_for:
            token_for[value] = f"host-{len(token_for) + 1}"
        return token_for[value]

    mapping = {}
    for r in redacted:
        if r.get("host"):
            mapping[r["host"]] = token(r["host"])
            r["host"] = mapping[r["host"]]
        if r.get("hostname"):
            mapping[r["hostname"]] = token(r["hostname"])
            r["hostname"] = mapping[r["hostname"]]
        # ports and open_ports are separate dicts: scrub both.
        seen = set()
        for p in list(r.get("ports", [])) + list(r.get("open_ports", [])):
            if id(p) in seen:
                continue
            seen.add(id(p))
            banner = p.get("banner", "")
            banner = _IPV4_RE.sub("REDACTED-IP", banner)
            banner = _VERSION_RE.sub("vN", banner)
            p["banner"] = banner
    return redacted, mapping


def load_previous_report(path):
    with open(path) as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or "hosts" not in doc:
        sys.exit(f"not a port-scanner JSON report: {path}")
    return doc


def resurvey_targets(doc):
    """Hosts from a previous report that need re-scanning: any host
    whose confidence was indeterminate."""
    jobs = []
    for h in doc.get("hosts", []):
        if h.get("confidence") == "indeterminate":
            ports = [p["port"] for p in h.get("ports", [])
                     or [{"port": p["port"]} for p in h.get("open_ports", [])]]
            jobs.append((h["host"], sorted(set(ports))))
    return jobs


def merge_resurvey(prev_doc, new_results):
    """Merge a resurvey into the previous report, adding per-port
    detection history (detections / passes). Hosts that were not
    re-scanned carry over unchanged."""
    prev_by_host = {h["host"]: h for h in prev_doc.get("hosts", [])}
    merged = []
    for nr in new_results:
        prev = prev_by_host.get(nr["host"], {})
        prev_ports = {p["port"]: p for p in prev.get("ports", [])}
        for p in nr.get("ports", []):
            old = prev_ports.get(p["port"], {})
            if old.get("passes"):
                prev_passes = old["passes"]
                prev_detections = old.get("detections", 0)
            else:
                prev_passes = 1
                prev_detections = (1 if old.get("verdict")
                                   in ("confirmed-open", "open-single-probe")
                                   else 0)
            p["passes"] = prev_passes + 1
            p["detections"] = prev_detections + (
                1 if p["verdict"] in ("confirmed-open", "open-single-probe")
                else 0)
        merged.append(nr)
    resurveyed = {r["host"] for r in new_results}
    for h in prev_doc.get("hosts", []):
        if h["host"] not in resurveyed:
            merged.append(h)
    try:
        merged.sort(key=lambda r: ipaddress.ip_address(r["host"]))
    except ValueError:
        merged.sort(key=lambda r: r["host"])
    return merged


# ---------------------------------------------------------------- main

def build_parser():
    ap = argparse.ArgumentParser(
        description="Dependency-free TCP port scanner — evidence-grade "
                    "audit tool (report v2)")
    ap.add_argument("target", nargs="?",
                    help="IP, hostname, or CIDR subnet (e.g. 192.168.1.0/24)")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--ports", default=None,
                       help="'80', '20-100', or '22,80,443' "
                            "(default: common service ports)")
    group.add_argument("--quick", action="store_true",
                       help="scan the ~50 most common ports")
    group.add_argument("--full", action="store_true",
                       help="scan all 65535 ports")
    ap.add_argument("--timeout", type=float, default=1.0,
                    help="per-connection timeout in seconds (default: 1.0)")
    ap.add_argument("--workers", type=int, default=200,
                    help="parallel connections (default: 200)")
    ap.add_argument("--retries", type=int, default=0,
                    help="retry filtered-timeout ports N times (default: 0)")
    ap.add_argument("--no-confirm", action="store_true",
                    help="skip the confirmatory re-probe of open ports")
    ap.add_argument("--no-control", action="store_true",
                    help="skip the per-host control-port quality check")
    ap.add_argument("--rate-limit", type=float, default=None,
                    help="max connects per second (default: uncapped)")
    ap.add_argument("--auth-ref", default="",
                    help="authorization reference: ticket, scope doc, or "
                         "course lab (recorded in the manifest)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the scope-confirmation prompt "
                         "(for scripted runs)")
    ap.add_argument("--journal", default=DEFAULT_JOURNAL,
                    help="hash-chained run journal path "
                         f"(default: {DEFAULT_JOURNAL})")
    ap.add_argument("--verify-chain", action="store_true",
                    help="verify the run journal's hash chain and exit")
    ap.add_argument("--self-test", action="store_true",
                    help="run the loopback self-check and exit")
    ap.add_argument("--redact", action="store_true",
                    help="replace host identities with tokens in the "
                         "report; the redaction map stays local")
    ap.add_argument("--resurvey", default=None, metavar="PREV_REPORT.json",
                    help="re-scan only indeterminate hosts from a "
                         "previous JSON report and merge detection history")
    ap.add_argument("--format", choices=["text", "json", "csv", "html"],
                    default="text", help="output format (default: text)")
    ap.add_argument("-o", "--output", default=None,
                    help="write report to file instead of stdout")
    return ap


def confirm_scope(targets, total_probes, auth_ref, output, yes):
    """Pre-scan gate for non-loopback targets.

    Prints the authorization checklist and requires the operator to
    type YES (or pass --yes). This documents a decision; it cannot
    verify ownership or consent. Very large scans additionally need
    an explicit --yes (range block).
    """
    non_loopback = [t for t in targets if not is_loopback_ip(t)]
    if not non_loopback:
        return
    if total_probes > RANGE_BLOCK_PROBES and not yes:
        sys.exit(
            f"refusing: {total_probes} probes exceeds the range block "
            f"({RANGE_BLOCK_PROBES}) — narrow the scope or rerun with "
            f"--yes to confirm you intend a scan this large")
    sys.stderr.write("Pre-scan checklist:\n")
    sys.stderr.write(f"  authorization basis: {auth_ref or '(not provided)'}\n")
    sys.stderr.write(f"  scope: {len(targets)} host(s), {total_probes} probes\n")
    sys.stderr.write(f"  output: {output or 'stdout'}\n")
    sys.stderr.write("  abort: Ctrl-C keeps partial results, marked partial\n")
    if yes:
        sys.stderr.write("  confirmation skipped via --yes\n")
        return
    if not sys.stdin.isatty():
        sys.exit("non-interactive shell: rerun with --yes to confirm scope")
    answer = input("Type YES to confirm this scan is authorized: ").strip()
    if answer != "YES":
        sys.exit("aborted by operator")


def run_self_test():
    """Loopback self-check: open/closed verdicts, control QC, journal."""
    import socketserver

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b"SSH-2.0-SelfTest\r\n")

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    checks = []
    try:
        d = probe_port_detailed("127.0.0.1", port, 1.0, confirm=True)
        checks.append(("open port -> confirmed-open",
                       d["verdict"] == "confirmed-open"))
        closed = probe_port_detailed("127.0.0.1", port + 1, 0.5,
                                     confirm=False)
        checks.append(("closed port -> closed",
                       closed["verdict"] == "closed"))
        r = scan_host("127.0.0.1", [port], 1.0, 10)
        checks.append(("control port QC passes",
                       r["qc"]["passed"] is True))
        checks.append(("parse_ports sanity",
                       parse_ports("22,80-81") == [22, 80, 81]))
    finally:
        srv.shutdown()
    ok = all(passed for _, passed in checks)
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
    print("self-test: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 2


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.verify_chain:
        ok, msg = verify_journal_chain(args.journal)
        print(msg)
        return 0 if ok else 2
    if args.self_test:
        return run_self_test()
    if not args.target and not args.resurvey:
        build_parser().error("target is required (unless --self-test, "
                             "--verify-chain, or --resurvey is used)")

    # Resolve the port list up front so --resurvey jobs can override it
    # per host below.
    if args.full:
        default_ports = list(range(1, 65536))
    elif args.quick:
        default_ports = QUICK_PORTS
    elif args.ports:
        default_ports = parse_ports(args.ports)
    else:
        default_ports = sorted(SERVICE_NAMES)
    if not default_ports and not args.resurvey:
        sys.exit("no valid ports selected")

    prev_doc = None
    prev_hash = None
    if args.resurvey:
        prev_doc = load_previous_report(args.resurvey)
        with open(args.resurvey, "rb") as f:
            prev_hash = hashlib.sha256(f.read()).hexdigest()
        jobs = resurvey_targets(prev_doc)
        if not jobs:
            print("resurvey: no indeterminate hosts in previous report")
            return 0
        jobs = [(ip, ports or default_ports) for ip, ports in jobs]
    else:
        targets = parse_targets(args.target)
        jobs = [(ip, default_ports) for ip in targets]

    total_probes = sum(len(ports) for _, ports in jobs)
    all_ips = [ip for ip, _ in jobs]
    confirm_scope(all_ips, total_probes, args.auth_ref, args.output,
                  args.yes)
    if len(jobs) > 1 or total_probes > 100:
        print(f"scanning {len(jobs)} host(s) "
              f"({total_probes} probes)...", file=sys.stderr)

    results = []
    start = time.time()
    progress = (Progress(total_probes)
                if total_probes >= 200 else None)
    partial = False
    try:
        for ip, ports in jobs:
            r = scan_host(ip, ports, args.timeout, args.workers,
                          progress, retries=args.retries,
                          confirm=not args.no_confirm,
                          control_ports=not args.no_control,
                          rate_limit=args.rate_limit)
            if r["partial"]:
                partial = True
            results.append(r)
    except KeyboardInterrupt:
        partial = True
        print("\ninterrupted — showing partial results", file=sys.stderr)
    elapsed = time.time() - start
    if progress is not None:
        progress.finish()
    if partial:
        for r in results:
            r.setdefault("partial", True)

    if prev_doc is not None:
        results = merge_resurvey(prev_doc, results)

    redaction_map = None
    if args.redact:
        results, redaction_map = redact_report(results)

    summary = build_summary(results, elapsed, partial)
    target_label = args.target or f"resurvey:{args.resurvey}"
    scope_text = (f"{target_label}\nports={','.join(str(p) for p in default_ports)}"
                  + (f"\nresurvey_of={prev_hash}" if prev_hash else ""))
    # Report hash covers the body without the manifest, so the manifest
    # can attest to the report it ships with.
    if args.format == "json":
        body = format_json(results, elapsed, summary=summary, partial=partial)
        report_hash = sha256_text(body)
        manifest = build_manifest(sys.argv, args.auth_ref,
                                  sha256_text(scope_text), report_hash,
                                  partial, args.redact)
        report = format_json(results, elapsed, summary=summary,
                             manifest=manifest, partial=partial)
    elif args.format == "csv":
        body = format_csv(results)
        report_hash = sha256_text(body)
        manifest = build_manifest(sys.argv, args.auth_ref,
                                  sha256_text(scope_text), report_hash,
                                  partial, args.redact)
        report = body + "# manifest: " + json.dumps(manifest, sort_keys=True) + "\n"
    elif args.format == "html":
        body = format_html(results, elapsed, summary=summary, partial=partial)
        report_hash = sha256_text(body)
        manifest = build_manifest(sys.argv, args.auth_ref,
                                  sha256_text(scope_text), report_hash,
                                  partial, args.redact)
        report = format_html(results, elapsed, summary=summary,
                             manifest=manifest, partial=partial)
    else:
        body = format_text(results, elapsed, summary=summary, partial=partial)
        report_hash = sha256_text(body)
        manifest = build_manifest(sys.argv, args.auth_ref,
                                  sha256_text(scope_text), report_hash,
                                  partial, args.redact)
        report = format_text(results, elapsed, summary=summary,
                             manifest=manifest, partial=partial)

    out_path = args.output
    if args.format == "html" and out_path is None:
        out_path = (f"port-scan-"
                    f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.html")
    if out_path:
        with open(out_path, "w") as f:
            f.write(report)
        print(f"report written to {out_path}")
        if redaction_map is not None:
            map_path = out_path + ".redaction-map.json"
            with open(map_path, "w") as f:
                json.dump(redaction_map, f, indent=2, sort_keys=True)
            print(f"redaction map written to {map_path} (keep local, "
                  f"never publish)")
    else:
        print(report)
        if redaction_map is not None:
            sys.stderr.write(
                "redaction map (local only, not part of the report): "
                + json.dumps(redaction_map, sort_keys=True) + "\n")

    journal_append(args.journal, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": f"port-scanner {__version__}",
        "target": target_label,
        "hosts": len(results),
        "probes": total_probes,
        "auth_ref": args.auth_ref,
        "output": out_path or "stdout",
        "report_hash": report_hash,
        "partial": partial,
        "redacted": args.redact,
    })

    if partial:
        return 3
    if any(not r.get("qc", {}).get("passed", True) for r in results):
        return 2
    if any(r.get("confidence") == "indeterminate" for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
