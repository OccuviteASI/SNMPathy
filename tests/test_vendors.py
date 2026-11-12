"""Rajant and Tachyon private-MIB discovery, using agents shaped like real device walks."""

import pytest

from snmpathy.snmp import mibs
from snmpathy.snmp.client import FakeSnmpClient
from snmpathy.snmp.discovery import apply_discovery, discover
from snmpathy.snmp.neighbors import apply_neighbors, discover_neighbors
from snmpathy.snmp.poller import compute_value, poll_device
from snmpathy.snmp.vendors import vendor_of
from snmpathy.topology import build_graph

R = "1.3.6.1.4.1.34861"
T = "1.3.6.1.4.1.57344"


def rajant_agent(idle=10_000, uptime=20_000, rx=1000):
    # Like an ME4-2450R: private scalars are served WITHOUT ".0".
    return {
        mibs.SYS_DESCR: "bc-north 11.27.0 ME4-2450R-12345 Mine Mesh",
        mibs.SYS_OBJECT_ID: f"{R}.1.1",
        mibs.SYS_NAME: "bc-north",
        mibs.SYS_UPTIME: uptime,
        f"{R}.1.1": "ME4-2450R-12345",
        f"{R}.1.2": 2370,
        f"{R}.1.3": 177632,
        f"{R}.1.4": idle,
        f"{R}.1.5": uptime,
        f"{R}.2.6": 0, f"{R}.2.7": 5, f"{R}.2.9": rx, f"{R}.2.10": 2000,
        f"{R}.3.1.1": "wlan0", f"{R}.3.1.2": 5785, f"{R}.3.1.3": -109,
        f"{R}.3.2.1": "wlan1", f"{R}.3.2.2": 2462, f"{R}.3.2.3": -95,
    }


def tachyon_agent(rx_bytes=0):
    return {
        mibs.SYS_DESCR: "Linux tna-303x",
        mibs.SYS_OBJECT_ID: f"{T}.1",
        mibs.SYS_NAME: "tna-east",
        mibs.SYS_UPTIME: 100_000,
        f"{T}.1.3.1.0": "TNA-303X", f"{T}.1.3.2.0": "TN303X0001", f"{T}.1.3.3.0": 48,
        f"{T}.1.3.4.0": "1.12.0 rev 54574", f"{T}.1.3.6.0": 12, f"{T}.1.3.7.0": 41, f"{T}.1.2.5.0": 2,
        f"{T}.1.2.2.1.2.1": "wlan0", f"{T}.1.2.2.1.3.1": 54, f"{T}.1.2.2.1.5.1": 66960,
        f"{T}.1.2.2.1.6.1": 2160, f"{T}.1.2.2.1.10.1": 52, f"{T}.1.2.2.1.11.1": 50,
        # Peer table rows 1..2
        f"{T}.1.2.6.1.1.1": "78:5E:E8:00:00:01", f"{T}.1.2.6.1.1.2": "78:5E:E8:00:00:02",
        f"{T}.1.2.6.1.6.1": -61, f"{T}.1.2.6.1.6.2": -59,
        f"{T}.1.2.6.1.7.1": 2502, f"{T}.1.2.6.1.7.2": 2310,
        f"{T}.1.2.6.1.8.1": 8, f"{T}.1.2.6.1.8.2": 2,
        f"{T}.1.2.6.1.9.1": 2310, f"{T}.1.2.6.1.9.2": 2502,
        f"{T}.1.2.6.1.12.1": 3600, f"{T}.1.2.6.1.12.2": 120,
        f"{T}.1.2.6.1.13.1": 180, f"{T}.1.2.6.1.13.2": 950,
        f"{T}.1.2.6.1.14.1": rx_bytes, f"{T}.1.2.6.1.14.2": 0,
        f"{T}.1.2.6.1.15.1": 0, f"{T}.1.2.6.1.15.2": 0,
        f"{T}.1.2.6.1.18.1": "TNA-303X", f"{T}.1.2.6.1.18.2": "TNA-301",
        f"{T}.1.2.6.1.20.1": "tna-west", f"{T}.1.2.6.1.20.2": "tna-south",
        f"{T}.1.2.6.1.23.1": "10.40.0.2", f"{T}.1.2.6.1.23.2": "0.0.0.0",
    }


def test_vendor_detection():
    assert vendor_of(f"{R}.1.1") == "rajant"
    assert vendor_of(f".{T}.2") == "tachyon"
    assert vendor_of("1.3.6.1.4.1.9.1.1") == ""
    assert mibs.vendor_from_sysobjectid(f"{T}.1") == "Tachyon Networks"


async def test_rajant_discovery_and_polling(db, make_device):
    device = make_device("bc-north", "10.30.0.5")
    client = FakeSnmpClient(rajant_agent())
    result = await discover(client)
    assert result.system["vendor"] == "Rajant"
    assert result.system["hw_model"] == "ME4-2450R" and result.system["hw_serial"] == "ME4-2450R-12345"
    assert result.system["firmware"] == "11.27.0"
    by = {(m.key, m.instance): m for m in result.metrics}
    assert by[("hw.temperature", "system")].oid == f"{R}.1.2" and by[("hw.temperature", "system")].scale == 0.01
    assert by[("radio.noise", "wlan1")].oid == f"{R}.3.2.3"
    assert by[("cpu.load", "0")].kind == "idle_counter"   # no HOST-RESOURCES CPU on this fake agent
    assert ("rajant.mesh.rx_pps", "") in by and ("rajant.mesh.dropped_pps", "") in by
    apply_discovery(db, device["id"], result, now=1000)
    row = db.one("SELECT vendor, hw_model, hw_serial, firmware FROM devices")
    assert row == {"vendor": "Rajant", "hw_model": "ME4-2450R", "hw_serial": "ME4-2450R-12345", "firmware": "11.27.0"}

    await poll_device(db, client, db.one("SELECT * FROM devices"), now=1000)
    # 20 s later: idle grew by 1500 cs (= 75 % idle -> 25 % busy), 400 more mesh packets.
    client.data.update({k: v for k, v in rajant_agent(idle=11_500, uptime=22_000, rx=1400).items()})
    await poll_device(db, client, db.one("SELECT * FROM devices"), now=1020)
    value = lambda key, inst="": db.one("SELECT last_value FROM metrics WHERE key = ? AND instance = ?", (key, inst))["last_value"]  # noqa: E731
    assert value("hw.temperature", "system") == pytest.approx(23.7)
    assert value("mem.free_bytes") == 177632 * 1024
    assert value("cpu.load", "0") == pytest.approx(25.0)
    assert value("cpu.avg") == pytest.approx(25.0)
    assert value("rajant.mesh.rx_pps") == pytest.approx(20.0)
    assert value("radio.frequency", "wlan0") == 5785


def test_idle_counter_math():
    metric = {"kind": "idle_counter", "scale": 1, "last_raw": 1000, "last_raw_ts": 0, "counter_bits": 32}
    assert compute_value(metric, 1000 + 9000, None, 100, False)[0] == pytest.approx(10.0)  # 90 % idle
    assert compute_value(metric, 1000 + 20000, None, 100, False)[0] == 0.0  # clamped (multi-core idle)


async def test_tachyon_discovery_polling_and_map(db, make_device):
    east = make_device("tna-east", "10.40.0.1")
    west = make_device("tna-west", "10.40.0.2")
    client = FakeSnmpClient(tachyon_agent())
    result = await discover(client)
    assert result.system["vendor"] == "Tachyon Networks" and result.system["hw_model"] == "TNA-303X"
    assert result.system["firmware"] == "1.12.0 rev 54574"
    by = {(m.key, m.instance): m for m in result.metrics}
    peer = "78:5e:e8:00:00:01"
    assert by[("wireless.rssi", peer)].oid == f"{T}.1.2.6.1.6.1"
    assert by[("wireless.rssi", peer)].label == "tna-west (78:5E:E8:00:00:01)"
    assert by[("wireless.tx_rate", peer)].scale == 1e6
    assert by[("wireless.rx_bps", peer)].kind == "counter" and by[("wireless.rx_bps", peer)].counter_bits == 64
    assert by[("hw.temperature", "modem wlan0")].oid == f"{T}.1.2.2.1.10.1"
    assert by[("cpu.load", "0")].oid == f"{T}.1.3.6.0" and ("mem.used_pct", "") in by
    apply_discovery(db, east["id"], result, now=1000)

    await poll_device(db, client, db.one("SELECT * FROM devices WHERE id = ?", (east["id"],)), now=1000)
    client.data.update({k: v for k, v in tachyon_agent(rx_bytes=12_500_000).items()})
    await poll_device(db, client, db.one("SELECT * FROM devices WHERE id = ?", (east["id"],)), now=1020)
    value = lambda key, inst: db.one("SELECT last_value FROM metrics WHERE key = ? AND instance = ?", (key, inst))["last_value"]  # noqa: E731
    assert value("wireless.rssi", peer) == -61 and value("wireless.snr", peer) == 8
    assert value("wireless.tx_rate", peer) == 2502e6
    assert value("wireless.rx_bps", peer) == pytest.approx(5_000_000)  # 12.5 MB in 20 s = 5 Mbps
    assert value("wireless.distance", "78:5e:e8:00:00:02") == 950

    # Peers become wireless links on the map, matched by IP (and by name for the second).
    links = await discover_neighbors(client)
    assert {(n["protocol"], n["remote_name"], n["remote_ip"]) for n in links} == {
        ("wireless", "tna-west", "10.40.0.2"), ("wireless", "tna-south", "")}
    apply_neighbors(db, east["id"], links)
    graph = build_graph(db)
    edge = next(e for e in graph["edges"] if e["target"] == f"d{west['id']}" or e["source"] == f"d{west['id']}")
    assert edge["protocols"] == ["wireless"]
    assert next(n for n in graph["nodes"] if n["name"] == "tna-east")["kind"] == "wireless"


async def test_plain_devices_are_not_probed_as_vendors(db):
    from .conftest import agent_data

    client = FakeSnmpClient(agent_data())
    result = await discover(client)
    assert "hw_model" not in result.system and result.system["vendor"] == "Cisco"
    assert not any(m.key.startswith(("wireless.", "rajant.")) for m in result.metrics)


async def test_generic_sysobjectid_is_probed():
    agent = rajant_agent()
    agent[mibs.SYS_OBJECT_ID] = "1.3.6.1.4.1.8072.3.2.10"  # Net-SNMP
    result = await discover(FakeSnmpClient(agent))
    assert result.system["vendor"] == "Rajant" and result.system["hw_model"] == "ME4-2450R"
