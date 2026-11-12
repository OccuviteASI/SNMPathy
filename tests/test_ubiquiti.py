"""Ubiquiti discovery (airMAX, UniFi, airFiber, LTU, AF60 / Wave, EdgeMAX, EdgeSwitch) with agents
shaped like real device walks, including the places where devices disagree with the MIBs."""

import pytest

from snmpathy.snmp import mibs
from snmpathy.snmp.client import FakeSnmpClient
from snmpathy.snmp.discovery import apply_discovery, discover
from snmpathy.snmp.neighbors import discover_neighbors
from snmpathy.snmp.poller import compute_value, poll_device

U = "1.3.6.1.4.1.41112"
FROG = "1.3.6.1.4.1.10002.1"
MAC1 = "24.90.170.1.2.3"     # 18:5a:aa:01:02:03
MAC1_TEXT = "18:5a:aa:01:02:03"


def base(descr, oid=FROG, name="dev"):
    return {mibs.SYS_DESCR: descr, mibs.SYS_OBJECT_ID: oid, mibs.SYS_NAME: name, mibs.SYS_UPTIME: 100_000,
            f"{FROG}.1.1.1.1.0": 61_000, f"{FROG}.1.1.1.2.0": 30_500}   # Frogfoot memTotal / memFree (KiB)


def airmax_agent(temp=66, tx_bytes=0):
    d = base("Linux 2.6.32.68 #1 Mon Nov 18 mips", name="litebeam-north")
    d.update({
        "1.2.840.10036.3.1.2.1.3.5": "LiteBeam 5AC Gen2", "1.2.840.10036.3.1.2.1.4.5": "XC.qca955x.v8.5.1.37185.180110.1349",
        f"{U}.1.4.1.1.4.1": 5745, f"{U}.1.4.1.1.6.1": 27, f"{U}.1.4.1.1.7.1": 14400,
        f"{U}.1.4.5.1.2.1": "wisp-ap", f"{U}.1.4.5.1.5.1": -69, f"{U}.1.4.5.1.7.1": 94, f"{U}.1.4.5.1.8.1": -103,
        f"{U}.1.4.5.1.9.1": 59_999_000, f"{U}.1.4.5.1.10.1": 52_000_000, f"{U}.1.4.5.1.15.1": 1,
        f"{U}.1.4.6.1.3.1": 88, f"{U}.1.4.6.1.4.1": 71, f"{U}.1.4.6.1.7.1": 699,
        f"{U}.1.4.8.4.0": temp,
        # ubntStaTable: index = wlStatIndex(1) + station MAC as 6 decimal octets
        f"{U}.1.4.7.1.2.1.{MAC1}": "cpe-smith", f"{U}.1.4.7.1.3.1.{MAC1}": -62, f"{U}.1.4.7.1.5.1.{MAC1}": 2300,
        f"{U}.1.4.7.1.6.1.{MAC1}": 91, f"{U}.1.4.7.1.9.1.{MAC1}": 64, f"{U}.1.4.7.1.10.1.{MAC1}": "10.50.0.20",
        f"{U}.1.4.7.1.13.1.{MAC1}": tx_bytes, f"{U}.1.4.7.1.14.1.{MAC1}": 0,
        f"{U}.1.4.7.1.17.1.{MAC1}": 120_000, f"{U}.1.4.7.1.18.1.{MAC1}": 150_000, f"{U}.1.4.7.1.21.1.{MAC1}": 3,
    })
    return d


def by(result):
    return {(m.key, m.instance): m for m in result.metrics}


async def test_airmax(db, make_device):
    device = make_device("litebeam-north", "10.50.0.2")
    client = FakeSnmpClient(airmax_agent())
    result = await discover(client)
    assert result.system["vendor"] == "Ubiquiti" and result.system["hw_model"] == "LiteBeam 5AC Gen2"
    assert result.system["firmware"] == "8.5.1"
    m = by(result)
    assert m[("wireless.signal", "")].oid == f"{U}.1.4.5.1.5.1"
    assert m[("wireless.airtime", "")].scale == 0.1
    assert m[("hw.temperature", "system")].scale == 1.0
    assert m[("mem.used_pct", "")].kind == "ratio_free"
    assert m[("wireless.rssi", MAC1_TEXT)].label == f"cpe-smith ({MAC1_TEXT})"
    assert m[("wireless.tx_capacity", MAC1_TEXT)].scale == 1000.0
    apply_discovery(db, device["id"], result, now=1000)
    await poll_device(db, client, db.one("SELECT * FROM devices"), now=1000)
    client.data.update(airmax_agent(tx_bytes=2_500_000))
    await poll_device(db, client, db.one("SELECT * FROM devices"), now=1020)
    value = lambda k, i="": db.one("SELECT last_value FROM metrics WHERE key = ? AND instance = ?", (k, i))["last_value"]  # noqa: E731
    assert value("wireless.airtime") == pytest.approx(69.9)
    assert value("wireless.tx_capacity", MAC1_TEXT) == 120_000_000
    assert value("wireless.tx_bps", MAC1_TEXT) == pytest.approx(1_000_000)
    assert value("mem.used_pct") == pytest.approx(50.0)
    neighbours = await discover_neighbors(client)
    assert neighbours == [{"protocol": "wireless", "if_index": None, "local_port": "wireless", "remote_name": "cpe-smith",
                           "remote_port": "", "remote_ip": "10.50.0.20", "remote_chassis": MAC1_TEXT, "remote_platform": ""}]


async def test_airmax_temperature_quirk():
    result = await discover(FakeSnmpClient(airmax_agent(temp=660_000_000)))
    assert by(result)[("hw.temperature", "system")].scale == 1e-7


async def test_unifi_ap():
    d = base("UAP-nanoHD 5.43.36.12724", oid=U, name="ap-lobby")
    radio, vap = f"{U}.1.6.1.1.1", f"{U}.1.6.1.2.1"
    d.update({
        f"{U}.1.6.3.3.0": "UAP-nanoHD", f"{U}.1.6.3.6.0": "5.43.36.12724",
        f"{radio}.2.1": "wifi0", f"{radio}.3.1": "ng", f"{radio}.6.1": 34, f"{radio}.7.1": 5, f"{radio}.8.1": 9,
        f"{radio}.2.2": "wifi1", f"{radio}.3.2": "na", f"{radio}.6.2": 12,
        f"{vap}.3.1": 789, f"{vap}.4.1": 6, f"{vap}.6.1": "Office", f"{vap}.8.1": 14, f"{vap}.9.1": "ng",
        f"{vap}.10.1": 1000, f"{vap}.16.1": 2000, f"{vap}.21.1": 17,
        f"{vap}.3.2": 991, f"{vap}.4.2": 44, f"{vap}.6.2": "Office", f"{vap}.8.2": 31, f"{vap}.9.2": "na",
        f"{vap}.6.3": "vwire-abc", f"{vap}.8.3": 1, f"{vap}.9.3": "na",
    })
    result = await discover(FakeSnmpClient(d))
    assert result.system["hw_model"] == "UAP-nanoHD" and result.system["firmware"] == "5.43.36.12724"
    m = by(result)
    assert m[("wireless.clients", "Office 2.4 GHz")].oid == f"{vap}.8.1"
    assert m[("wireless.clients", "Office 5 GHz")].label == "Office (5 GHz)"
    assert not any("vwire" in i for _, i in m)                           # mesh uplink VAP skipped
    assert m[("wireless.ccq", "Office 2.4 GHz")].scale == 0.1            # per-mille
    assert m[("radio.channel_util", "wifi0")].label.startswith("2.4 GHz")
    assert m[("radio.tx_power", "2.4 GHz")].oid == f"{vap}.21.1"
    assert m[("wireless.rx_bps", "Office 2.4 GHz")].counter_bits == 32


async def test_airfiber_classic_khz_frequency():
    st, cfg = f"{U}.1.3.2.1", f"{U}.1.3.1.1"
    d = base("Linux 2.6.33 armv5tejl", name="af11-east")
    d.update({f"{cfg}.5.1": 11_485_000, f"{cfg}.6.1": 10_995_000, f"{cfg}.9.1": 58, f"{cfg}.14.1": "east-west",
              f"{st}.4.1": 8200, f"{st}.5.1": 686_400_640, f"{st}.6.1": 686_400_640, f"{st}.8.1": 41, f"{st}.10.1": 43,
              f"{st}.11.1": -48, f"{st}.14.1": -50, f"{st}.19.1": -49, f"{st}.22.1": -51, f"{st}.26.1": 1,
              f"{st}.40.1": "v4.0.3", f"{st}.44.1": 86400, f"{st}.45.1": "04:18:D6:AA:BB:CC", f"{st}.46.1": "10.60.0.2",
              f"{U}.1.3.3.1.64.1": 0, f"{U}.1.3.3.1.66.1": 0})
    result = await discover(FakeSnmpClient(d))
    assert result.system["firmware"] == "4.0.3" and result.system["hw_model"] == "airFiber"
    m = by(result)
    assert m[("radio.frequency", "tx")].scale == 0.001       # reported in kHz
    assert m[("wireless.remote_rssi", "chain1")].oid == f"{st}.22.1"
    assert m[("wireless.link_up", "link")].oid == f"{st}.26.1"
    assert result.metrics and (await discover_neighbors(FakeSnmpClient(d)))[0]["remote_ip"] == "10.60.0.2"


async def test_ltu_and_af60_stations():
    ltu, sta = f"{U}.1.10.1", f"{U}.1.10.1.4.1"
    d = base("Linux PRIVATE 3.14.77 armv7l", oid="1.3.6.1.4.1.8072.3.2.10", name="af5xhd")
    d.update({f"{ltu}.3.2.0": "airFiber 5XHD", f"{ltu}.3.4.0": "v1.4.0", f"{ltu}.3.5.0": 47, f"{ltu}.3.6.0": 12,
              f"{ltu}.2.2.0": 5800, f"{ltu}.5.5.0": 1, f"{ltu}.5.1.0": 0, f"{ltu}.5.3.0": 0,
              f"{sta}.3.{MAC1}": 450_000, f"{sta}.5.{MAC1}": -55, f"{sta}.13.{MAC1}": "af5xhd-b",
              f"{sta}.23.{MAC1}": 10955, f"{sta}.25.{MAC1}": "10.70.0.2"})
    result = await discover(FakeSnmpClient(d))
    assert result.system["hw_model"] == "airFiber 5XHD" and result.system["firmware"] == "1.4.0"
    m = by(result)
    assert m[("wireless.distance", MAC1_TEXT)].scale == 1.0          # metres despite the MIB
    assert m[("wireless.tx_capacity", MAC1_TEXT)].scale == 1000.0
    assert m[("cpu.load", "0")].oid == f"{ltu}.3.6.0"

    af, st = f"{U}.1.11.1", f"{U}.1.11.1.3.1"
    d = base("Linux 4.4.60 armv7l", oid=U, name="wave-lr")
    # Scalars end in .1 and station rows carry a trailing .1 after the MAC.
    d.update({f"{af}.2.2.1": "Wave Long-Range", f"{af}.2.4.1": "GMC.ipq5018.v3.4.0", f"{af}.2.6.1": 20,
              f"{af}.1.2.1": 69120, f"{st}.3.{MAC1}.1": -52, f"{st}.4.{MAC1}.1": 23, f"{st}.7.{MAC1}.1": 1_951_000,
              f"{st}.14.{MAC1}.1": "wave-cpe", f"{st}.20.{MAC1}.1": "10.80.0.2", f"{st}.2.{MAC1}.1": "main"})
    result = await discover(FakeSnmpClient(d))
    assert result.system["hw_model"] == "Wave Long-Range"
    m = by(result)
    assert m[("wireless.snr", MAC1_TEXT)].oid == f"{st}.4.{MAC1}.1"
    assert m[("wireless.tx_capacity", MAC1_TEXT)].label == f"wave-cpe ({MAC1_TEXT})"


async def test_edgemax_and_edgeswitch():
    em = f"{U}.1.5"
    d = base("UFiber OLT", oid=f"{U}.1.5", name="olt1")
    d.update({f"{em}.1.1.0": "UFiber OLT", f"{em}.1.2.0": "SN123", f"{em}.1.3.0": "v4.4.2",
              f"{em}.4.2.1.2.1": 3, f"{em}.4.2.1.3.1": 47250, f"{em}.5.2.1.3.0": 5200})
    result = await discover(FakeSnmpClient(d))
    m = by(result)
    assert result.system["hw_serial"] == "SN123"
    assert m[("hw.temperature", "cpu 1")].scale == 0.001            # milli-degrees
    assert m[("hw.fan_rpm", "fan 0")].oid == f"{em}.5.2.1.3.0"

    fp = "1.3.6.1.4.1.4413.1.1"
    d = base("EdgeSwitch 24-Port 250W", oid="1.3.6.1.4.1.4413", name="es24")
    d.update({f"{fp}.1.1.1.3.0": "ES-24-250W", f"{fp}.1.1.1.13.0": "1.9.1",
              f"{fp}.1.1.4.9.0": "    5 Secs ( 31.11%)   60 Secs ( 16.75%)  300 Secs ( 12.0%)",
              f"{fp}.1.1.4.1.0": 200_000, f"{fp}.1.1.4.2.0": 500_000,
              f"{fp}.43.1.8.1.4.1.0": 1, f"{fp}.43.1.8.1.5.1.0": 59,
              f"{fp}.43.1.6.1.3.1.0": 2, f"{fp}.43.1.6.1.4.1.0": 3900, f"{fp}.43.1.7.1.3.1.0": 2,
              "1.3.6.1.2.1.105.1.3.1.1.2.1": 250, "1.3.6.1.2.1.105.1.3.1.1.4.1": 87})
    result = await discover(FakeSnmpClient(d))
    m = by(result)
    assert result.system["hw_model"] == "ES-24-250W"
    assert m[("cpu.load", "0")].kind == "pct_text"
    assert m[("hw.temperature", "sensor 1.0")].oid == f"{fp}.43.1.8.1.5.1.0"
    assert ("hw.psu_state", "psu 1.0") in m and ("hw.fan_rpm", "fan 1.0") in m
    assert m[("poe.consumption_w", "1")].oid == "1.3.6.1.2.1.105.1.3.1.1.4.1"
    assert compute_value({"kind": "pct_text", "scale": 1}, d[f"{fp}.1.1.4.9.0"], None, 0, False)[0] == 31.11


async def test_other_devices_are_not_misdetected():
    from .conftest import agent_data

    result = await discover(FakeSnmpClient(agent_data()))
    assert result.system["vendor"] == "Cisco" and "hw_model" not in result.system
