"""Tests for scanner.py — all local, no network beyond loopback."""
import json
import os
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner


# ---------------------------------------------------------------- helpers

class BannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-TestServer\r\n")


def start_tcp_server(handler_cls=BannerHandler):
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    srv.allow_reuse_address = True
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


class QuietHTTP(BaseHTTPRequestHandler):
    server_version = "TestHTTP/1.0"

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def start_http_server():
    srv = HTTPServer(("127.0.0.1", 0), QuietHTTP)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


# ---------------------------------------------------------------- parsing

def test_parse_ports_single():
    assert scanner.parse_ports("80") == [80]


def test_parse_ports_range():
    assert scanner.parse_ports("20-22") == [20, 21, 22]


def test_parse_ports_list():
    assert scanner.parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_mixed():
    assert scanner.parse_ports("22, 80-81") == [22, 80, 81]


def test_parse_ports_invalid_dropped():
    assert scanner.parse_ports("0,99999") == []


def test_parse_ports_rejects_garbage():
    with pytest.raises(ValueError):
        scanner.parse_ports("abc")


def test_parse_targets_single_ip():
    assert scanner.parse_targets("127.0.0.1") == ["127.0.0.1"]


def test_parse_targets_hostname():
    assert scanner.parse_targets("localhost") == ["127.0.0.1"]


def test_parse_targets_cidr():
    assert scanner.parse_targets("127.0.0.0/30") == ["127.0.0.1", "127.0.0.2"]


def test_parse_targets_cidr_32():
    assert scanner.parse_targets("10.0.0.5/32") == ["10.0.0.5"]


def test_parse_targets_too_large():
    with pytest.raises(SystemExit):
        scanner.parse_targets("10.0.0.0/8")


def test_parse_targets_unresolvable(monkeypatch):
    def boom(host):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "gethostbyname", boom)
    with pytest.raises(SystemExit):
        scanner.parse_targets("no-such-host.invalid.")


# ---------------------------------------------------------------- scanning

def test_open_port_found():
    srv, port = start_tcp_server()
    try:
        assert scanner.probe_port("127.0.0.1", port, 1.0) is not None
    finally:
        srv.shutdown()


def test_closed_port_not_found():
    srv, port = start_tcp_server()
    srv.shutdown()
    srv.server_close()
    assert scanner.probe_port("127.0.0.1", port, 0.5) is None


def test_banner_grabbed():
    srv, port = start_tcp_server()
    try:
        banner = scanner.probe_port("127.0.0.1", port, 1.0)
        assert banner is not None and "SSH-2.0-TestServer" in banner
    finally:
        srv.shutdown()


def test_http_probe_extracts_server_header():
    srv, port = start_http_server()
    scanner.HTTP_PORTS.add(port)
    try:
        banner = scanner.probe_port("127.0.0.1", port, 1.0)
        assert banner is not None
        assert "200" in banner and "TestHTTP" in banner
    finally:
        scanner.HTTP_PORTS.discard(port)
        srv.shutdown()


def test_scan_host_result_shape():
    srv, port = start_tcp_server()
    try:
        r = scanner.scan_host("127.0.0.1", [port], 1.0, 10)
        assert r["host"] == "127.0.0.1"
        assert len(r["open_ports"]) == 1
        assert r["open_ports"][0]["port"] == port
    finally:
        srv.shutdown()


def test_reverse_dns_loopback():
    name = scanner.reverse_dns("127.0.0.1")
    assert isinstance(name, str)  # usually 'localhost', '' is acceptable


def test_scan_host_skips_rdns_when_no_open_ports(monkeypatch):
    calls = []

    def fake_rdns(ip):
        calls.append(ip)
        return "x"

    monkeypatch.setattr(scanner, "reverse_dns", fake_rdns)
    srv, port = start_tcp_server()
    srv.shutdown()
    srv.server_close()
    r = scanner.scan_host("127.0.0.1", [port], 0.5, 10)
    assert r["open_ports"] == []
    assert r["hostname"] == ""
    assert calls == []


def test_scan_host_rdns_when_open_ports(monkeypatch):
    calls = []
    monkeypatch.setattr(scanner, "reverse_dns",
                        lambda ip: calls.append(ip) or "deadbeef")
    srv, port = start_tcp_server()
    try:
        r = scanner.scan_host("127.0.0.1", [port], 1.0, 10)
        assert len(r["open_ports"]) == 1
        assert r["hostname"] == "deadbeef"
        assert calls == ["127.0.0.1"]
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- outputs

def _sample_results():
    return [{"host": "127.0.0.1", "hostname": "localhost",
             "open_ports": [{"port": 22, "service": "ssh",
                             "banner": "SSH-2.0-OpenSSH"}]}]


def test_format_json_roundtrip():
    doc = json.loads(scanner.format_json(_sample_results(), 1.5))
    assert doc["hosts"][0]["open_ports"][0]["port"] == 22
    assert doc["elapsed_s"] == 1.5


def test_format_csv_header_and_row():
    out = scanner.format_csv(_sample_results())
    lines = out.strip().split("\n")
    assert lines[0] == ("host,hostname,port,service,verdict,confidence,"
                        "attempts,latency_ms,error,passes,detections,banner")
    assert "127.0.0.1" in lines[1] and "22" in lines[1]


def test_format_html_escapes():
    evil = [{"host": "1.2.3.4", "hostname": "",
             "open_ports": [{"port": 80, "service": "",
                             "banner": "<script>alert(1)</script>"}]}]
    out = scanner.format_html(evil, 0.1)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_format_text_lists_open_ports():
    out = scanner.format_text(_sample_results(), 0.2)
    assert "22" in out and "ssh" in out


def test_quick_ports_sane():
    assert 20 <= len(scanner.QUICK_PORTS) <= 100
    assert scanner.QUICK_PORTS == sorted(set(scanner.QUICK_PORTS))
    assert all(1 <= p <= 65535 for p in scanner.QUICK_PORTS)
    for must in (21, 22, 80, 443, 3306, 3389):
        assert must in scanner.QUICK_PORTS


# ---------------------------------------------------------------- v2: verdicts, QC, journal, redaction, resurvey

class FakeSocket:
    """Socket double driven by a class-level port -> outcome list.

    Each outcome is an int connect_ex return code, or the string
    "timeout" to raise socket.timeout, or "oserror" to raise OSError.
    """
    outcomes = {}

    def __init__(self, *a, **k):
        self._port = None

    def settimeout(self, t):
        pass

    def connect_ex(self, addr):
        self._port = addr[1]
        queue = FakeSocket.outcomes.get(addr[1], [])
        if not queue:
            return 111  # default: refused
        outcome = queue.pop(0)
        if outcome == "timeout":
            raise socket.timeout("timed out")
        if outcome == "oserror":
            raise OSError(99, "fake error")
        return outcome

    def recv(self, n):
        return b""

    def sendall(self, data):
        pass

    def close(self):
        pass


def test_verdict_open_confirmed():
    srv, port = start_tcp_server()
    try:
        d = scanner.probe_port_detailed("127.0.0.1", port, 1.0, confirm=True)
        assert d["verdict"] == "confirmed-open"
        assert d["attempts"] == 2
    finally:
        srv.shutdown()


def test_verdict_open_single_probe_without_confirm():
    srv, port = start_tcp_server()
    try:
        d = scanner.probe_port_detailed("127.0.0.1", port, 1.0, confirm=False)
        assert d["verdict"] == "open-single-probe"
        assert d["attempts"] == 1
    finally:
        srv.shutdown()


def test_verdict_closed_is_refused():
    srv, port = start_tcp_server()
    srv.shutdown()
    srv.server_close()
    d = scanner.probe_port_detailed("127.0.0.1", port, 0.5, confirm=False)
    assert d["verdict"] == "closed"
    assert d["error"] == "refused"


def test_verdict_filtered_timeout_mocked(monkeypatch):
    FakeSocket.outcomes = {9999: [110]}
    monkeypatch.setattr(scanner.socket, "socket", FakeSocket)
    d = scanner.probe_port_detailed("127.0.0.1", 9999, 0.1,
                                    retries=0, confirm=False)
    assert d["verdict"] == "filtered-timeout"
    assert d["error"] == "timeout"


def test_verdict_error_unreachable_mocked(monkeypatch):
    FakeSocket.outcomes = {9998: [113]}
    monkeypatch.setattr(scanner.socket, "socket", FakeSocket)
    d = scanner.probe_port_detailed("127.0.0.1", 9998, 0.1, confirm=False)
    assert d["verdict"] == "error"
    assert d["error"] == "unreachable"


def test_retry_on_timeout_then_open(monkeypatch):
    FakeSocket.outcomes = {9997: [110, 0, 0]}
    monkeypatch.setattr(scanner.socket, "socket", FakeSocket)
    d = scanner.probe_port_detailed("127.0.0.1", 9997, 0.1,
                                    retries=1, confirm=True)
    assert d["verdict"] == "confirmed-open"
    assert d["attempts"] == 3  # timeout + open + confirmatory re-probe


def test_probe_port_wrapper_compat():
    srv, port = start_tcp_server()
    try:
        assert scanner.probe_port("127.0.0.1", port, 1.0) is not None
    finally:
        srv.shutdown()
    srv2, port2 = start_tcp_server()
    srv2.shutdown()
    srv2.server_close()
    assert scanner.probe_port("127.0.0.1", port2, 0.5) is None


def test_control_port_qc_passes_on_loopback():
    srv, port = start_tcp_server()
    try:
        r = scanner.scan_host("127.0.0.1", [port], 1.0, 10)
        assert r["qc"]["passed"] is True
        assert r["qc"]["control_verdict"] == "closed"
        assert r["confidence"] == "confirmed"
    finally:
        srv.shutdown()


def test_control_port_qc_failure_flags_host(monkeypatch):
    real = scanner.probe_port_detailed

    def fake(ip, port, timeout, **kw):
        if port == scanner.CONTROL_CLOSED_PORT:
            return {"port": port, "service": "", "verdict": "confirmed-open",
                    "error": None, "attempts": 2, "latency_ms": 0.1,
                    "banner": ""}
        return real(ip, port, timeout, **kw)

    monkeypatch.setattr(scanner, "probe_port_detailed", fake)
    srv, port = start_tcp_server()
    try:
        r = scanner.scan_host("127.0.0.1", [port], 1.0, 10)
        assert r["qc"]["passed"] is False
        assert r["confidence"] == "indeterminate"
    finally:
        srv.shutdown()


def test_indeterminate_when_filtered_timeout(monkeypatch):
    FakeSocket.outcomes = {9999: [110]}
    monkeypatch.setattr(scanner.socket, "socket", FakeSocket)
    r = scanner.scan_host("127.0.0.1", [9999], 0.1, 10, control_ports=False)
    assert r["verdict_counts"] == {"filtered-timeout": 1}
    assert r["confidence"] == "indeterminate"


def test_empty_results_shape():
    srv, port = start_tcp_server()
    srv.shutdown()
    srv.server_close()
    r = scanner.scan_host("127.0.0.1", [port], 0.5, 10)
    assert r["open_ports"] == []
    assert r["verdict_counts"] == {"closed": 1}
    assert r["confidence"] == "confirmed"


def test_malformed_binary_banner_does_not_crash():
    class BinaryHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b"\xff\xfe\x00binary\x00junk")

    srv = socketserver.TCPServer(("127.0.0.1", 0), BinaryHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        d = scanner.probe_port_detailed("127.0.0.1", port, 1.0,
                                        confirm=False)
        assert d["verdict"] == "open-single-probe"
        assert isinstance(d["banner"], str)
    finally:
        srv.shutdown()


def test_accept_then_hang_returns_bannerless_open():
    class HangHandler(socketserver.BaseRequestHandler):
        def handle(self):
            time.sleep(5)

    srv = socketserver.TCPServer(("127.0.0.1", 0), HangHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        start = time.time()
        d = scanner.probe_port_detailed("127.0.0.1", port, 0.3,
                                        confirm=False)
        assert d["verdict"] == "open-single-probe"
        assert d["banner"] == ""
        assert time.time() - start < 3
    finally:
        srv.shutdown()


def test_invalid_cidr_exits():
    with pytest.raises(SystemExit):
        scanner.parse_targets("999.999.999.999/24")


def test_rate_limiter_spacing():
    limiter = scanner.RateLimiter(5)  # 5/sec -> 0.2s spacing
    start = time.time()
    limiter.acquire()
    limiter.acquire()
    assert time.time() - start >= 0.19


def test_scale_mocked_254_hosts(monkeypatch):
    FakeSocket.outcomes = {}
    monkeypatch.setattr(scanner.socket, "socket", FakeSocket)
    total_closed = 0
    for i in range(254):
        r = scanner.scan_host(f"10.0.2.{i + 1}", list(range(1, 11)), 0.1,
                              50, control_ports=False, confirm=False)
        total_closed += r["verdict_counts"].get("closed", 0)
    assert total_closed == 254 * 10


def test_journal_chain_and_tamper(tmp_path):
    path = str(tmp_path / "journal.jsonl")
    scanner.journal_append(path, {"target": "127.0.0.1", "n": 1})
    scanner.journal_append(path, {"target": "127.0.0.1", "n": 2})
    ok, msg = scanner.verify_journal_chain(path)
    assert ok, msg
    lines = open(path).read().splitlines()
    tampered = json.loads(lines[0])
    tampered["n"] = 99
    lines[0] = json.dumps(tampered)
    open(path, "w").write("\n".join(lines) + "\n")
    ok, msg = scanner.verify_journal_chain(path)
    assert not ok


def test_manifest_fields():
    m = scanner.build_manifest(["scanner.py", "127.0.0.1"], "TICKET-1",
                               "abc", "def", False, False)
    assert m["report_version"] == scanner.REPORT_VERSION
    assert m["auth_ref"] == "TICKET-1"
    assert m["scope_hash"] == "abc"
    assert m["report_hash"] == "def"
    assert m["redaction_map"] == "withheld"
    assert m["tool"].startswith("port-scanner ")


def test_redact_replaces_host_and_scrubs_banner():
    results = [{"host": "192.168.1.5", "hostname": "mypc.lan",
                "open_ports": [{"port": 80, "service": "http",
                                "banner": "Apache/2.4.52 (Ubuntu) "
                                          "see 192.168.1.5",
                                "verdict": "confirmed-open"}],
                "ports": [{"port": 80, "service": "http",
                           "banner": "Apache/2.4.52 (Ubuntu) "
                                     "see 192.168.1.5",
                           "verdict": "confirmed-open", "error": None,
                           "attempts": 2, "latency_ms": 1.0}]}]
    redacted, mapping = scanner.redact_report(results)
    assert redacted[0]["host"] == "host-1"
    assert redacted[0]["hostname"] == "host-2"
    assert "192.168.1.5" not in json.dumps(redacted)
    assert "mypc.lan" not in json.dumps(redacted)
    assert mapping["192.168.1.5"] == "host-1"
    assert "2.4.52" not in json.dumps(redacted)  # versions generalized


def test_resurvey_merge_detection_history():
    prev = {"hosts": [{"host": "10.0.0.1", "confidence": "indeterminate",
                       "ports": [{"port": 22, "verdict": "confirmed-open",
                                  "service": "ssh", "banner": "",
                                  "error": None, "attempts": 2,
                                  "latency_ms": 1.0},
                                 {"port": 80, "verdict": "filtered-timeout",
                                  "service": "http", "banner": "",
                                  "error": "timeout", "attempts": 1,
                                  "latency_ms": None}]}]}
    new = [{"host": "10.0.0.1", "confidence": "confirmed",
            "ports": [{"port": 22, "verdict": "confirmed-open",
                       "service": "ssh", "banner": "", "error": None,
                       "attempts": 2, "latency_ms": 1.0},
                      {"port": 80, "verdict": "closed",
                       "service": "http", "banner": "", "error": "refused",
                       "attempts": 1, "latency_ms": 0.5}]}]
    merged = scanner.merge_resurvey(prev, new)
    by_port = {p["port"]: p for p in merged[0]["ports"]}
    assert by_port[22]["passes"] == 2
    assert by_port[22]["detections"] == 2
    assert by_port[80]["passes"] == 2
    assert by_port[80]["detections"] == 0


def test_format_json_v2_shape():
    doc = json.loads(scanner.format_json(_sample_results(), 1.5))
    assert doc["report_version"] == 2
    assert doc["summary"]["hosts_scanned"] == 1
    assert doc["summary"]["open_ports"] == 1


def test_format_text_skim_and_attempts_language():
    results = [{"host": "10.0.0.9", "hostname": "", "open_ports": [],
                "ports": [], "verdict_counts": {"closed": 2},
                "confidence": "confirmed",
                "qc": {"passed": True}, "attempts": 2}]
    out = scanner.format_text(results, 0.2)
    assert "Port scan summary" in out
    assert "no open ports detected in 2 attempts" in out


def test_self_test_passes():
    assert scanner.run_self_test() == 0


def test_resurvey_targets_picks_indeterminate():
    doc = {"hosts": [
        {"host": "10.0.0.1", "confidence": "indeterminate",
         "ports": [{"port": 22}, {"port": 80}]},
        {"host": "10.0.0.2", "confidence": "confirmed",
         "ports": [{"port": 22}]},
    ]}
    assert scanner.resurvey_targets(doc) == [("10.0.0.1", [22, 80])]


def test_main_resurvey_without_target(tmp_path):
    prev = {"hosts": [{"host": "127.0.0.1", "confidence": "indeterminate",
                       "ports": [{"port": 59999, "verdict": "filtered-timeout",
                                  "service": "", "banner": "",
                                  "error": "timeout", "attempts": 1,
                                  "latency_ms": None}]}]}
    prev_path = str(tmp_path / "prev.json")
    with open(prev_path, "w") as f:
        json.dump(prev, f)
    rc = scanner.main(["--resurvey", prev_path, "--format", "json",
                       "--journal", str(tmp_path / "j.jsonl")])
    assert rc == 0
