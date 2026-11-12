import asyncio
import gzip
import json
import os
import socket
import time
import zlib
from datetime import datetime, timezone

import pytest

from snmpathy.syslog.structured import (
    MAX_STRUCTURED,
    GelfChunkBuffer,
    StructuredLogServer,
    decode_gelf_datagram,
    parse_json_event,
)

NOW = time.time()


def _free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _gelf(**extra):
    event = {
        "version": "1.1",
        "host": "app01.example.com",
        "short_message": "Payment failed",
        "full_message": "Payment failed\nTraceback: boom",
        "timestamp": NOW - 10.5,
        "level": 3,
        "_user_id": 42,
        "_request": {"path": "/pay", "method": "POST"},
        "_application_name": "billing",
    }
    event.update(extra)
    return event


def test_gelf_mapping_with_extra_fields():
    msg = parse_json_event(json.dumps(_gelf()).encode(), "10.1.1.1", NOW)
    assert msg.host == "app01.example.com"
    assert msg.message == "Payment failed\nTraceback: boom"
    assert msg.ts == pytest.approx(NOW - 10.5)
    assert msg.severity == 3 and msg.facility == 1
    assert msg.app == "billing"
    fields = json.loads(msg.structured)
    assert fields == {"user_id": 42, "request.path": "/pay", "request.method": "POST"}
    assert msg.sd["gelf"]["user_id"] == "42"


def test_gelf_facility_name_and_legacy_app_facility():
    msg = parse_json_event(json.dumps(_gelf(facility="local3", _application_name=None)), received_at=NOW)
    assert msg.facility == 19
    msg = parse_json_event(json.dumps(_gelf(facility="gelf-java", _application_name=None)), received_at=NOW)
    assert msg.facility == 1 and msg.app == "gelf-java"


def test_nxlog_windows_audit_failure():
    event_time = datetime.fromtimestamp(NOW - 60).strftime("%Y-%m-%d %H:%M:%S")
    event = {
        "EventTime": event_time,
        "Hostname": "DC01.corp.local",
        "Keywords": "9232379236109516800",
        "EventType": "AUDIT_FAILURE",
        "SeverityValue": 4,
        "Severity": "ERROR",
        "EventID": 4625,
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        "Version": 0,
        "Task": 12544,
        "OpcodeValue": 0,
        "RecordNumber": 123456,
        "ProcessID": 640,
        "ThreadID": 4316,
        "Channel": "Security",
        "Category": "Logon",
        "Message": "An account failed to log on.",
        "TargetUserName": "administrator",
        "IpAddress": "203.0.113.9",
        "EventReceivedTime": event_time,
        "SourceModuleName": "eventlog",
        "SourceModuleType": "im_msvistalog",
    }
    msg = parse_json_event(json.dumps(event), "10.0.0.5", NOW)
    assert msg.host == "DC01.corp.local"
    assert msg.app == "Microsoft-Windows-Security-Auditing"
    assert msg.msgid == "4625"
    assert msg.procid == "640"
    assert msg.severity == 5  # audit failure -> notice
    assert msg.facility == 1
    assert msg.message == "An account failed to log on."
    assert msg.ts == pytest.approx(int(NOW - 60), abs=1)
    fields = json.loads(msg.structured)
    assert fields["Channel"] == "Security"
    assert fields["EventType"] == "AUDIT_FAILURE"
    assert fields["TargetUserName"] == "administrator"
    for consumed in ("EventTime", "Hostname", "SourceName", "EventID", "Message", "Severity", "SeverityValue"):
        assert consumed not in fields


@pytest.mark.parametrize("extra,expected", [
    ({"Severity": "CRITICAL", "SeverityValue": 5}, 2),
    ({"Severity": "WARNING", "SeverityValue": 3}, 4),
    ({"SeverityValue": 1}, 7),
    ({"Severity": "INFO", "EventType": "AUDIT_SUCCESS"}, 6),
    ({"Severity": "INFO", "SyslogFacilityValue": 16}, 6),
])
def test_nxlog_severity_mapping(extra, expected):
    msg = parse_json_event(json.dumps({"EventTime": "2026-11-12T10:11:12Z", "Hostname": "h", "EventID": 1,
                                       "Message": "m", **extra}), received_at=NOW)
    assert msg.severity == expected
    if "SyslogFacilityValue" in extra:
        assert msg.facility == 16


def test_generic_filebeat_like():
    event = {
        "@timestamp": datetime.fromtimestamp(NOW - 5, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "message": "disk almost full",
        "host": {"name": "web-3", "ip": ["10.0.0.3"], "os": {"family": "debian"}},
        "log": {"level": "warn", "file": {"path": "/var/log/app.log"}},
        "service": {"name": "nginx"},
        "process": {"pid": 811},
        "agent": {"type": "filebeat", "version": "8.15.0"},
    }
    msg = parse_json_event(json.dumps(event), "10.0.0.3", NOW)
    assert msg.host == "web-3"
    assert msg.message == "disk almost full"
    assert msg.severity == 4
    assert msg.app == "nginx"
    assert msg.procid == "811"
    assert msg.ts == pytest.approx(NOW - 5, abs=0.01)
    fields = json.loads(msg.structured)
    assert fields == {
        "host.ip": '["10.0.0.3"]',
        "host.os.family": "debian",
        "log.file.path": "/var/log/app.log",
        "agent.type": "filebeat",
        "agent.version": "8.15.0",
    }


def test_generic_journald_and_names():
    event = {"MESSAGE": "Started foo", "_HOSTNAME": "srv", "PRIORITY": "3", "SYSLOG_IDENTIFIER": "systemd",
             "__REALTIME_TIMESTAMP": str(int((NOW - 2) * 1e6)), "_SYSTEMD_UNIT": "foo.service"}
    msg = parse_json_event(json.dumps(event), received_at=NOW)
    assert (msg.host, msg.severity, msg.app, msg.message) == ("srv", 3, "systemd", "Started foo")
    assert msg.ts == pytest.approx(NOW - 2, abs=0.01)
    assert json.loads(msg.structured) == {"_SYSTEMD_UNIT": "foo.service"}

    for level, sev in (("fatal", 2), ("ERROR", 3), ("err", 3), ("debug", 7), ("crit", 2), (7, 7), (50, 3)):
        assert parse_json_event(json.dumps({"msg": "x", "level": level}), received_at=NOW).severity == sev


def test_epoch_milliseconds_timestamp():
    msg = parse_json_event(json.dumps({"msg": "hi", "ts": int((NOW - 30) * 1000), "hostname": "h"}), received_at=NOW)
    assert msg.ts == pytest.approx(NOW - 30, abs=0.01)
    msg = parse_json_event(json.dumps({"msg": "hi", "time": NOW - 30}), "192.0.2.1", NOW)
    assert msg.ts == pytest.approx(NOW - 30)
    assert msg.host == "192.0.2.1"  # falls back to source IP
    assert msg.severity == 6 and msg.facility == 1  # defaults


def test_skewed_timestamps_fall_back_to_received_at():
    future = parse_json_event(json.dumps({"msg": "x", "time": NOW + 2 * 86400}), received_at=NOW)
    assert future.ts == NOW
    ancient = parse_json_event(json.dumps({"msg": "x", "time": NOW - 31 * 86400}), received_at=NOW)
    assert ancient.ts == NOW
    week_old = parse_json_event(json.dumps({"msg": "x", "time": NOW - 7 * 86400}), received_at=NOW)
    assert week_old.ts == pytest.approx(NOW - 7 * 86400)
    garbage = parse_json_event(json.dumps({"msg": "x", "time": "yesterday-ish"}), received_at=NOW)
    assert garbage.ts == NOW


@pytest.mark.parametrize("data", [b"not json", b"[1, 2]", b'"string"', b"{broken", b"", b"42"])
def test_invalid_json_raises(data):
    with pytest.raises(ValueError):
        parse_json_event(data)


def test_structured_limits_keep_valid_json():
    event = {"msg": "x", **{f"f{i}": "v" * 5000 for i in range(150)}}
    msg = parse_json_event(json.dumps(event), received_at=NOW)
    fields = json.loads(msg.structured)
    assert len(msg.structured) <= MAX_STRUCTURED
    assert all(len(v) <= 1000 for v in fields.values())
    many = parse_json_event(json.dumps({"msg": "x", **{f"k{i}": i for i in range(150)}}), received_at=NOW)
    assert len(json.loads(many.structured)) == 100


def test_gelf_zlib_and_gzip():
    raw = json.dumps(_gelf()).encode()
    buf = GelfChunkBuffer()
    assert decode_gelf_datagram(zlib.compress(raw), buf) == raw
    assert decode_gelf_datagram(gzip.compress(raw), buf) == raw
    assert decode_gelf_datagram(raw, buf) == raw
    with pytest.raises(ValueError):
        decode_gelf_datagram(b"\x78\x9cnot really zlib", buf)


def _chunks(payload: bytes, message_id: bytes, size: int) -> list[bytes]:
    parts = [payload[i:i + size] for i in range(0, len(payload), size)]
    return [b"\x1e\x0f" + message_id + bytes([i, len(parts)]) + p for i, p in enumerate(parts)]


def test_chunked_gelf_out_of_order():
    raw = json.dumps(_gelf(_blob=os.urandom(1500).hex())).encode()
    compressed = zlib.compress(raw)
    datagrams = _chunks(compressed, b"ABCDEFGH", 500)
    assert len(datagrams) >= 3
    buf = GelfChunkBuffer()
    order = list(reversed(datagrams))
    for d in order[:-1]:
        assert decode_gelf_datagram(d, buf, "10.0.0.1") is None
    assert decode_gelf_datagram(order[1], buf, "10.0.0.1") is None  # duplicate chunk ignored
    assert decode_gelf_datagram(order[-1], buf, "10.0.0.1") == raw
    assert len(buf) == 0


def test_incomplete_chunks_return_none_and_expire():
    raw = json.dumps(_gelf()).encode()
    datagrams = _chunks(raw, b"12345678", 100)
    buf = GelfChunkBuffer(timeout=5.0)
    for d in datagrams[:-1]:
        assert decode_gelf_datagram(d, buf) is None
    assert len(buf) == 1
    buf.expire(time.monotonic() + 6)
    assert len(buf) == 0 and buf.expired == 1
    # After expiry the last chunk alone cannot complete the message.
    assert decode_gelf_datagram(datagrams[-1], buf) is None
    with pytest.raises(ValueError):
        decode_gelf_datagram(b"\x1e\x0f12345678" + bytes([0, 129]) + b"x", buf)  # > 128 chunks
    with pytest.raises(ValueError):
        decode_gelf_datagram(b"\x1e\x0f1234", buf)  # truncated header


async def test_server_end_to_end(db, make_device):
    make_device("app01", "127.0.0.1")
    gelf_port = _free_port(socket.SOCK_DGRAM)
    tcp_port = _free_port()
    server = StructuredLogServer(db, "127.0.0.1", gelf_udp_port=gelf_port, json_tcp_port=tcp_port,
                                 json_udp_port=None, flush_interval=0.05)
    await server.start()
    try:
        assert server.listening == {"gelf_udp": f"127.0.0.1:{gelf_port}", "json_tcp": f"127.0.0.1:{tcp_port}"}
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(zlib.compress(json.dumps(_gelf()).encode()), ("127.0.0.1", gelf_port))
        udp.close()
        _, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
        line1 = {"message": "first line", "level": "error", "host": {"name": "web-1"}, "trace": {"id": "abc"}}
        line2 = {"msg": "second line", "service": "api", "region": "eu-west-1"}
        writer.write(json.dumps(line1).encode() + b"\n" + json.dumps(line2).encode()[:20])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(json.dumps(line2).encode()[20:] + b"\n")
        await writer.drain()
        writer.close()
        for _ in range(100):
            await asyncio.sleep(0.05)
            if db.scalar("SELECT COUNT(*) FROM syslog") >= 3:
                break
    finally:
        await server.stop()
    rows = {r["message"]: r for r in db.query("SELECT * FROM syslog")}
    assert set(rows) == {"Payment failed\nTraceback: boom", "first line", "second line"}
    gelf = rows["Payment failed\nTraceback: boom"]
    assert gelf["host"] == "app01.example.com" and gelf["app"] == "billing" and gelf["severity"] == 3
    assert gelf["device_id"] is not None  # mapped by source IP
    assert json.loads(gelf["structured"]) == {"user_id": 42, "request.path": "/pay", "request.method": "POST"}
    first = rows["first line"]
    assert first["host"] == "web-1" and first["severity"] == 3
    assert json.loads(first["structured"]) == {"trace.id": "abc"}
    second = rows["second line"]
    assert second["app"] == "api" and second["host"] == "127.0.0.1"
    assert json.loads(second["structured"]) == {"region": "eu-west-1"}
    assert server.stats.received == 3 and server.stats.stored == 3 and server.stats.errors == 0


async def test_server_json_udp_and_bad_input(db):
    port = _free_port(socket.SOCK_DGRAM)
    server = StructuredLogServer(db, "127.0.0.1", gelf_udp_port=0, json_tcp_port=0, json_udp_port=port,
                                 flush_interval=0.05)
    await server.start()
    try:
        assert server.listening == {"json_udp": f"127.0.0.1:{port}"}
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(json.dumps({"message": "via udp", "level": "info"}).encode(), ("127.0.0.1", port))
        udp.sendto(b"<13>plain syslog is rejected", ("127.0.0.1", port))
        udp.close()
        for _ in range(100):
            await asyncio.sleep(0.05)
            if server.stats.stored + server.stats.errors >= 2:
                break
    finally:
        await server.stop()
    assert [r["message"] for r in db.query("SELECT message FROM syslog")] == ["via udp"]
    assert server.stats.errors == 1


async def test_bind_failure_is_logged_not_raised(db, caplog):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    port = blocker.getsockname()[1]
    try:
        server = StructuredLogServer(db, "127.0.0.1", gelf_udp_port=None, json_tcp_port=port, json_udp_port=None)
        await server.start()
        await server.stop()
    finally:
        blocker.close()
    assert server.listening == {}
    assert "cannot bind json_tcp" in caplog.text


async def test_tcp_overlong_line_is_dropped(db):
    port = _free_port()
    server = StructuredLogServer(db, "127.0.0.1", gelf_udp_port=None, json_tcp_port=port, json_udp_port=None,
                                 flush_interval=0.05)
    await server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        huge = json.dumps({"message": "huge", "blob": "x" * (300 * 1024)}).encode()
        writer.write(huge + b"\x00" + json.dumps({"message": "after"}).encode() + b"\x00")
        await writer.drain()
        writer.close()
        for _ in range(100):
            await asyncio.sleep(0.05)
            if server.stats.stored >= 1:
                break
    finally:
        await server.stop()
    assert [r["message"] for r in db.query("SELECT message FROM syslog")] == ["after"]
    assert server.stats.dropped == 1
