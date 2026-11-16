import json

from snmpathy import brands
from snmpathy.config import Settings
from snmpathy.monitor import Monitor
from snmpathy.scanner import ScanManager
from snmpathy.snmp import arp
from snmpathy.snmp.client import FakeSnmpClient
from tests.test_scanner import Net

PHYS = arp.IP_NET_TO_PHYSICAL
MEDIA = arp.IP_NET_TO_MEDIA
UBNT = bytes.fromhex("f09fc2112233")

# A UniFi gateway (net-snmp): ipNetToPhysicalTable with length-prefixed IPv4 indexes.
ROUTER = {
    arp.IP_FORWARDING: 1,
    f"{PHYS}.12.1.4.192.168.20.15": UBNT,                              # Ubiquiti AP on VLAN 20
    f"{PHYS}.13.1.4.192.168.30.7": bytes.fromhex("240ac4000002"),     # Espressif plug on VLAN 30
    f"{PHYS}.13.1.4.192.168.30.8": b"",                               # incomplete entry
    f"{PHYS}.13.1.4.192.168.30.255": b"\xff" * 6,                     # broadcast
    f"{PHYS}.12.2.16." + ".".join(["254", "128"] + ["0"] * 13 + ["1"]): UBNT,  # IPv6: ignored
}


def test_parse_router_tables():
    table = arp.parse_physical({k: v for k, v in ROUTER.items() if k.startswith(PHYS)})
    assert table == {"192.168.20.15": "F0:9F:C2:11:22:33", "192.168.30.7": "24:0A:C4:00:00:02"}
    media = arp.parse_media({f"{MEDIA}.4.10.0.0.9": bytes.fromhex("0c ea 14 00 00 01".replace(" ", "")),
                             f"{MEDIA}.4.10.0.0.10": "aa:bb:cc:dd:ee:ff"[0:0]})
    assert media == {"10.0.0.9": "0C:EA:14:00:00:01"}
    # Agents that leave out the address length, and MACs that came back as text.
    assert arp.parse_physical({f"{PHYS}.3.1.10.1.2.3": "0c:ea:14:00:00:05"}) == {"10.1.2.3": "0C:EA:14:00:00:05"}
    assert arp.mac_text("\x0c\xea\x14\x00\x00\x06") == "0C:EA:14:00:00:06"
    assert arp.mac_text(b"\x01\x00\x5e\x00\x00\x01") == ""  # multicast


async def test_read_arp_falls_back_and_detects_routers():
    assert await arp.read_arp(FakeSnmpClient(ROUTER)) == {"192.168.20.15": "F0:9F:C2:11:22:33",
                                                         "192.168.30.7": "24:0A:C4:00:00:02"}
    old = FakeSnmpClient({f"{MEDIA}.2.10.0.0.9": UBNT})
    assert await arp.read_arp(old) == {"10.0.0.9": "F0:9F:C2:11:22:33"}
    assert await arp.is_router(FakeSnmpClient(ROUTER))
    assert not await arp.is_router(FakeSnmpClient({arp.IP_FORWARDING: 2}))
    assert not await arp.is_router(FakeSnmpClient(fail=True))


def _monitor(db, data_for):
    return Monitor(db, Settings(database=":memory:"), snmp_factory=lambda device, settings: FakeSnmpClient(data_for(device)))


async def test_monitor_reads_router_arp_and_devices_on_other_vlans_get_tagged(db, make_device):
    gw = make_device("gateway", "192.168.1.1")
    switch = make_device("switch", "192.168.1.2")
    db.execute("UPDATE devices SET snmp_status = 'up'")
    ap = make_device("ap", "192.168.20.15", snmp_enabled=0)
    plug = make_device("plug", "192.168.30.7", snmp_enabled=0)
    monitor = _monitor(db, lambda d: ROUTER if d["id"] == gw["id"] else {arp.IP_FORWARDING: 2})
    assert await monitor.refresh_router_arp() == 2
    assert db.scalar("SELECT COUNT(*) FROM arp_cache WHERE site = 0 AND router_id = ?", (gw["id"],)) == 2
    assert switch["id"] in monitor._router_flag and not monitor._router_flag[switch["id"]][0]
    result = brands.tag_all(db, arp={})  # this computer's own ARP table knows none of them
    assert result["brands"] == {"Ubiquiti": 1, "Espressif": 1}
    row = db.one("SELECT * FROM devices WHERE id = ?", (ap["id"],))
    assert row["mac"] == "F0:9F:C2:11:22:33" and row["mac_vendor"] == "Ubiquiti Inc" and row["mac_source"] == "gateway"
    assert json.loads(db.one("SELECT tags FROM devices WHERE id = ?", (plug["id"],))["tags"]) == ["Espressif"]


def test_router_entries_stay_within_their_site(db, make_device):
    router = make_device("site-b-router", "10.9.0.1")
    db.update("devices", router["id"], {"collector_id": None})
    local = make_device("local-printer", "192.168.20.15", snmp_enabled=0)
    brands.store_router_arp(db, {"id": router["id"], "collector_id": 7}, {"192.168.20.15": "F0:9F:C2:11:22:33"})
    assert brands.refresh_macs(db, arp={}) == 0  # same address, other site: not this device
    assert db.one("SELECT mac FROM devices WHERE id = ?", (local["id"],))["mac"] == ""
    # The computer's own ARP table wins for local devices.
    brands.store_router_arp(db, {"id": router["id"], "collector_id": None}, {"192.168.20.15": "F0:9F:C2:11:22:33"})
    brands.refresh_macs(db, arp={"192.168.20.15": "00:1B:A9:00:00:21"})
    row = db.one("SELECT mac, mac_source FROM devices WHERE id = ?", (local["id"],))
    assert row["mac"] == "00:1B:A9:00:00:21" and row["mac_source"] == ""


async def test_scan_of_another_vlan_gets_macs_from_the_router(db, make_device):
    net = Net()
    net.ping = {"10.0.0.1", "10.0.0.2"}
    net.snmp = {}
    gw = make_device("gateway", "192.168.1.1")
    calls = []

    async def hook():
        calls.append(1)
        return brands.store_router_arp(db, dict(gw), {"10.0.0.2": "F0:9F:C2:11:22:33"})
    manager = ScanManager(db, local_probe=net.probe, local_clients=net.client)
    manager.arp_hook = hook
    scan = manager.create({"name": "vlan", "targets": "10.0.0.1-3",
                           "options": {"resolve_dns": False, "auto_add": "alive", "tags": []}})
    await manager.run(scan["id"])
    assert calls == [1]
    rows = {r["ip"]: r for r in db.query("SELECT * FROM scan_results")}
    assert rows["10.0.0.2"]["mac"] == "F0:9F:C2:11:22:33" and rows["10.0.0.2"]["mac_vendor"] == "Ubiquiti Inc"
    assert rows["10.0.0.1"]["mac"] == ""
    dev = db.one("SELECT * FROM devices WHERE hostname = '10.0.0.2'")
    assert json.loads(dev["tags"]) == ["Ubiquiti"] and dev["mac_source"] == "gateway"


def test_settings_show_router_arp(tmp_path):
    from fastapi.testclient import TestClient

    from snmpathy.app import create_app
    from snmpathy.db import Database

    settings = Settings(database=str(tmp_path / "s.db"), enable_syslog=False)
    db = Database(settings.database)
    with TestClient(create_app(settings, db=db, start_monitor=False)) as client:
        assert "poll that router over SNMP" in client.get("/settings").text
        brands.store_router_arp(db, {"id": 1, "collector_id": None}, {"10.0.0.2": "F0:9F:C2:11:22:33"})
        assert "1 from 1 router" in client.get("/settings").text
