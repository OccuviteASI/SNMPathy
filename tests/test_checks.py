import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from snmpathy.checks import probes
from snmpathy.checks.probes import ProbeResult, parse_ping_output, ping_command, status_matches
from snmpathy.checks.runner import record_result
from snmpathy.services import create_check


def test_status_matches():
    assert status_matches(200, "200-399")
    assert status_matches(204, "200,204")
    assert status_matches(302, "3xx")
    assert not status_matches(500, "200-399")
    assert status_matches(404, 404)


@pytest.mark.parametrize("output,code,ok,latency", [
    ("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.345 ms\n", 0, True, 0.345),        # Linux
    ("64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=12.5 ms\n", 0, True, 12.5),          # macOS
    ("Reply from 10.0.0.1: bytes=32 time<1ms TTL=128\r\n", 0, True, 1.0),                 # Windows
    ("Reply from 10.0.0.1: bytes=32 time=14ms TTL=57\r\n", 0, True, 14.0),
    ("Antwort von 10.0.0.1: Bytes=32 Zeit=3ms TTL=64\r\n", 0, True, 3.0),                  # German Windows
    ("Reply from 10.0.0.254: Destination host unreachable.\r\n", 0, False, None),         # Windows quirk
    ("Request timed out.\r\n", 1, False, None),
    ("1 packets transmitted, 0 received, 100% packet loss\n", 1, False, None),
])
def test_parse_ping_output(output, code, ok, latency):
    result = parse_ping_output(output, code)
    assert result.ok is ok
    if latency is not None:
        assert result.latency_ms == pytest.approx(latency)


def test_ping_command_per_platform():
    assert ping_command("1.2.3.4", 2, platform="win32")[-5:] == ["-n", "1", "-w", "2000", "1.2.3.4"]
    mac = ping_command("1.2.3.4", 2, platform="darwin")
    assert "-W" in mac and mac[mac.index("-W") + 1] == "2000"
    linux = ping_command("1.2.3.4", 2, platform="linux")
    assert linux[1:3] == ["-c", "1"] and linux[-1] == "1.2.3.4"


async def test_tcp_check_open_and_closed():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        ok = await probes.tcp_check("127.0.0.1", port, 2)
        assert ok.ok and ok.latency_ms is not None
    finally:
        server.close()
        await server.wait_closed()
    # Grab a free port and close it again: nothing is listening there now.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    free = s.getsockname()[1]
    s.close()
    closed = await probes.tcp_check("127.0.0.1", free, 2)
    assert not closed.ok


@pytest.fixture
def http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            code = 500 if self.path == "/fail" else 200
            body = b"<h1>Welcome to SNMPathy</h1>"
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


async def test_http_check(http_server):
    ok = await probes.http_check(http_server + "/", 5, {"keyword": "Welcome"})
    assert ok.ok, ok.message
    missing = await probes.http_check(http_server + "/", 5, {"keyword": "Goodbye"})
    assert not missing.ok and "missing" in missing.message
    fail = await probes.http_check(http_server + "/fail", 5, {})
    assert not fail.ok and "500" in fail.message
    absent = await probes.http_check(http_server + "/", 5, {"keyword": "Error", "keyword_absent": True})
    assert absent.ok


async def test_ping_localhost_works_in_any_mode():
    result = await probes.ping("127.0.0.1", timeout=2)
    # Whatever mode the platform supports (raw, dgram, ping command or TCP fallback)
    # localhost must be reachable, except for the TCP fallback with no open ports.
    if probes.detect_icmp_mode() != "tcp":
        assert result.ok, result.message


def test_state_machine_retries_and_backdated_outage(db):
    check = create_check(db, {"type": "icmp", "target": "10.0.0.1", "retries": 2})
    t = 1000.0
    check = record_result(db, check, ProbeResult(True, 1.0, "ok"), now=t)
    assert check["state"] == "up" and check["transition"] == "first-up"
    for i in range(1, 3):
        check = record_result(db, check, ProbeResult(False, None, "timeout"), now=t + 60 * i)
        assert check["state"] == "up"  # still within retry budget
    check = record_result(db, check, ProbeResult(False, None, "timeout"), now=t + 180)
    assert check["state"] == "down" and check["transition"] == "down"
    outage = db.one("SELECT * FROM outages")
    assert outage["started_at"] == t + 60  # backdated to the first failure
    assert outage["ended_at"] is None
    check = record_result(db, check, ProbeResult(True, 2.0, "ok"), now=t + 300)
    assert check["state"] == "up" and check["transition"] == "up"
    outage = db.one("SELECT * FROM outages")
    assert outage["ended_at"] == t + 300
    events = [r["type"] for r in db.query("SELECT type FROM events ORDER BY id")]
    assert events == ["check.down", "check.up"]
