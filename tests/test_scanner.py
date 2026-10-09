"""Tests for scanner.py — all local, no network beyond loopback."""
import json
import os
import socket
import socketserver
import sys
import threading
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
    assert lines[0] == "host,hostname,port,service,banner"
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
