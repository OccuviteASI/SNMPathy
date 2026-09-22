import pytest

from snmpathy.snmp import mibs
from snmpathy.snmp.client import FakeSnmpClient, convert_value, decode_octets, format_mac
from snmpathy.snmp.discovery import apply_discovery, discover
from snmpathy.snmp.poller import compute_value, counter_delta, poll_device

from .conftest import agent_data


def test_counter_delta_wraps_and_resets():
    assert counter_delta(100, 150, 32) == 50
    assert counter_delta(2**32 - 10, 5, 32) == 15
    assert counter_delta(2**64 - 1, 9, 64) == 10
    # A small counter going backwards cannot be a wrap (it would imply > 2**31 increments): a reset.
    assert counter_delta(1000, 5, 32) is None


def test_compute_value_kinds():
    gauge = {"kind": "gauge", "scale": 0.01}
    assert compute_value(gauge, 12345, None, 0, False)[0] == pytest.approx(123.45)
    ratio = {"kind": "ratio", "scale": 1}
    assert compute_value(ratio, 25, 100, 0, False)[0] == 25
    free = {"kind": "ratio_free", "scale": 1}
    assert compute_value(free, 25, 100, 0, False)[0] == 75
    counter = {"kind": "counter", "scale": 8, "last_raw": 1000, "last_raw_ts": 100, "counter_bits": 64}
    assert compute_value(counter, 2000, None, 110, False) == (800.0, 2000)
    assert compute_value(counter, 2000, None, 110, True) == (None, 2000)  # rebooted
    assert compute_value({"kind": "gauge", "scale": 1}, "0.42", None, 0, False)[0] == pytest.approx(0.42)
    # Unchanged counter 2 s after the last poll: agent cache, keep the baseline.
    assert compute_value(counter, 1000, None, 102, False) == (None, None)
    # Unchanged over a long window is a genuine zero rate.
    assert compute_value(counter, 1000, None, 400, False) == (0.0, 1000)


def test_value_decoding_helpers():
    assert decode_octets(b"hello\x00") == "hello"
    assert decode_octets(b"\x00\x1b\x54\x01\x02\x03") == b"\x00\x1b\x54\x01\x02\x03"
    assert format_mac(b"\x00\x1b\x54\x01\x02\x03") == "00:1b:54:01:02:03"

    class Counter64(int):
        pass

    assert convert_value(Counter64(5)) == 5


async def test_discovery_and_polling_computes_rates(db, make_device):
    device = make_device()
    client = FakeSnmpClient(agent_data())
    result = await discover(client)
    assert result.system["vendor"] == "Cisco"
    assert result.system["sys_uptime"] == 1000.0
    assert len(result.interfaces) == 2
    keys = {m.key for m in result.metrics}
    assert {"if.in_bps", "if.out_bps", "if.in_util", "cpu.load", "cpu.avg", "hr.mem.used_pct", "storage.used_pct"} <= keys
    in_metric = next(m for m in result.metrics if m.key == "if.in_bps" and m.instance == "1")
    assert in_metric.oid == f"{mibs.IF_HC_IN_OCTETS}.1" and in_metric.counter_bits == 64
    apply_discovery(db, device["id"], result, now=1000)
    # Without UCD-SNMP the hrStorage RAM entry becomes the device's memory metric.
    assert db.one("SELECT oid2 FROM metrics WHERE key = 'mem.used_pct'")["oid2"] == f"{mibs.HR_STORAGE_SIZE}.1"

    device = db.one("SELECT * FROM devices WHERE id = ?", (device["id"],))
    first = await poll_device(db, client, device, now=1000)
    assert first.ok
    # Second poll 10 s later with 1,250,000 more octets = 1 Mbps.
    client.data.update({k.lstrip("."): v for k, v in agent_data(in_octets=1000 + 1_250_000, uptime_ticks=101_000).items()})
    device = db.one("SELECT * FROM devices WHERE id = ?", (device["id"],))
    second = await poll_device(db, client, device, now=1010)
    assert second.ok and second.samples > 0

    bps = db.one("SELECT last_value FROM metrics WHERE key = 'if.in_bps' AND instance = '1'")["last_value"]
    assert bps == pytest.approx(1_000_000)
    util = db.one("SELECT last_value FROM metrics WHERE key = 'if.in_util' AND instance = '1'")["last_value"]
    assert util == pytest.approx(0.1)
    cpu = db.one("SELECT last_value FROM metrics WHERE key = 'cpu.avg'")["last_value"]
    assert cpu == 20
    assert db.one("SELECT last_value FROM metrics WHERE key = 'mem.used_pct'")["last_value"] == 25
    disk = db.one("SELECT last_value FROM metrics WHERE key = 'storage.used_pct'")["last_value"]
    assert disk == 95
    iface = db.one("SELECT * FROM interfaces WHERE if_index = 1")
    assert iface["in_bps"] == pytest.approx(1_000_000)
    assert db.one("SELECT status FROM devices")["status"] == "up"


async def test_reboot_and_interface_events(db, make_device):
    device = make_device()
    client = FakeSnmpClient(agent_data(uptime_ticks=10_000_000))
    apply_discovery(db, device["id"], await discover(client), now=0)
    device = db.one("SELECT * FROM devices")
    await poll_device(db, client, device, now=100)
    client.data.update({k.lstrip("."): v for k, v in agent_data(uptime_ticks=500, oper=2).items()})
    result = await poll_device(db, client, db.one("SELECT * FROM devices"), now=200)
    assert any("restarted" in e for e in result.events)
    assert any("Gi0/1" in e and "down" in e for e in result.events)
    # Counters must not produce a bogus rate across a reboot.
    assert db.one("SELECT COUNT(*) AS n FROM samples WHERE metric_id = (SELECT id FROM metrics WHERE key = 'if.in_bps' AND instance = '1') AND ts = 200")["n"] == 0


async def test_unreachable_device_marked_down(db, make_device):
    device = make_device()
    result = await poll_device(db, FakeSnmpClient(fail=True), device, now=50)
    assert not result.ok
    row = db.one("SELECT status, last_error FROM devices")
    assert row["status"] == "down"
    assert "timeout" in row["last_error"]
    assert db.one("SELECT type FROM events WHERE type = 'device.down'")


async def test_rediscovery_disables_vanished_series(db, make_device):
    device = make_device()
    data = agent_data()
    apply_discovery(db, device["id"], await discover(FakeSnmpClient(data)))
    for suffix in ("2",):
        for base in list(data):
            if base.endswith("." + suffix) and base.startswith("1.3.6.1.2.1.2.2.1"):
                del data[base]
            if base.endswith("." + suffix) and base.startswith("1.3.6.1.2.1.31.1.1.1"):
                del data[base]
    apply_discovery(db, device["id"], await discover(FakeSnmpClient(data)))
    assert db.scalar("SELECT COUNT(*) FROM interfaces") == 1
    assert db.scalar("SELECT enabled FROM metrics WHERE key = 'if.in_bps' AND instance = '2'") == 0
