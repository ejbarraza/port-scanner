#!/usr/bin/env python3
"""
port-scanner — a small, fast, dependency-free TCP port scanner.

TCP connect scans (no raw sockets, no root required), threaded for speed,
with banner grabbing, HTTP service probing, reverse DNS, and
text / JSON / CSV / HTML reports.

Usage:
    python3 scanner.py 192.168.1.1
    python3 scanner.py 192.168.1.0/24 --quick -o report.html
    python3 scanner.py example.com --ports 1-1024 --format json -o out.json
    python3 scanner.py 10.0.0.5 --full --timeout 0.5 --workers 400

Only scan hosts and networks you own or have explicit permission to test.
"""

import argparse
import csv
import html
import io
import ipaddress
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

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


def probe_port(ip, port, timeout):
    """Return the banner string for an open port, else None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) != 0:
            return None
        banner = _read_banner(sock, timeout)
        if not banner and port in HTTP_PORTS:
            banner = _http_probe(sock, timeout)
        return banner
    except OSError:
        return None
    finally:
        sock.close()


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


def scan_host(ip, ports, timeout, workers, progress=None):
    """Scan one host; return a result dict."""
    open_ports = []

    def work(port):
        banner = probe_port(ip, port, timeout)
        if progress is not None:
            progress.tick()
        if banner is None:
            return None
        return {"port": port,
                "service": SERVICE_NAMES.get(port, ""),
                "banner": banner}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(work, ports):
            if result is not None:
                open_ports.append(result)
    open_ports.sort(key=lambda r: r["port"])
    # Reverse-DNS only hosts worth naming: a lookup against a dead host can
    # stall for seconds on DNS timeouts, which would serialize a subnet sweep.
    hostname = reverse_dns(ip) if open_ports else ""
    return {"host": ip,
            "hostname": hostname,
            "open_ports": open_ports}


# ---------------------------------------------------------------- outputs

def format_text(results, elapsed):
    out = []
    for r in results:
        title = r["host"] + (f" ({r['hostname']})" if r["hostname"] else "")
        out.append(title)
        if not r["open_ports"]:
            out.append("  no open ports found")
        else:
            out.append(f"  {'PORT':<7}{'SERVICE':<13}BANNER")
            for p in r["open_ports"]:
                out.append(f"  {p['port']:<7}{p['service']:<13}{p['banner']}")
        out.append("")
    total_open = sum(len(r["open_ports"]) for r in results)
    out.append(f"{len(results)} host(s), {total_open} open port(s), "
               f"{elapsed:.1f}s elapsed")
    return "\n".join(out)


def format_json(results, elapsed):
    return json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": round(elapsed, 2),
        "hosts": results,
    }, indent=2)


def format_csv(results):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["host", "hostname", "port", "service", "banner"])
    for r in results:
        for p in r["open_ports"]:
            w.writerow([r["host"], r["hostname"], p["port"],
                        p["service"], p["banner"]])
    return buf.getvalue()


def format_html(results, elapsed):
    rows = []
    for r in results:
        title = html.escape(r["host"])
        if r["hostname"]:
            title += f" ({html.escape(r['hostname'])})"
        if not r["open_ports"]:
            rows.append(f"<h2>{title}</h2><p>No open ports found.</p>")
            continue
        trs = "".join(
            f"<tr><td>{p['port']}</td>"
            f"<td>{html.escape(p['service'])}</td>"
            f"<td>{html.escape(p['banner'])}</td></tr>"
            for p in r["open_ports"])
        rows.append(
            f"<h2>{title}</h2>"
            f"<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>"
            f"{trs}</table>")
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
{''.join(rows)}
</body></html>
"""


# ---------------------------------------------------------------- main

def build_parser():
    ap = argparse.ArgumentParser(
        description="Dependency-free TCP port scanner")
    ap.add_argument("target",
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
    ap.add_argument("--format", choices=["text", "json", "csv", "html"],
                    default="text", help="output format (default: text)")
    ap.add_argument("-o", "--output", default=None,
                    help="write report to file instead of stdout")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)

    targets = parse_targets(args.target)
    if args.full:
        ports = list(range(1, 65536))
    elif args.quick:
        ports = QUICK_PORTS
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = sorted(SERVICE_NAMES)
    if not ports:
        sys.exit("no valid ports selected")

    total_probes = len(targets) * len(ports)
    progress = Progress(total_probes) if total_probes >= 200 else None
    if len(targets) > 1 or len(ports) > 100:
        print(f"scanning {len(targets)} host(s) x {len(ports)} ports "
              f"({total_probes} probes)...", file=sys.stderr)

    results = []
    start = time.time()
    try:
        for ip in targets:
            results.append(scan_host(ip, ports, args.timeout,
                                    args.workers, progress))
    except KeyboardInterrupt:
        print("\ninterrupted — showing partial results", file=sys.stderr)
    elapsed = time.time() - start
    if progress is not None:
        progress.finish()

    if args.format == "json":
        report = format_json(results, elapsed)
    elif args.format == "csv":
        report = format_csv(results)
    elif args.format == "html":
        report = format_html(results, elapsed)
    else:
        report = format_text(results, elapsed)

    out_path = args.output
    if args.format == "html" and out_path is None:
        out_path = (f"port-scan-"
                    f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.html")
    if out_path:
        with open(out_path, "w") as f:
            f.write(report)
        print(f"report written to {out_path}")
    else:
        print(report)


if __name__ == "__main__":
    main()
