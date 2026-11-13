import json

import pytest

from snmpathy import brands, macvendor
from snmpathy.scanner import ScanManager, ScanOptions, scan_host
from tests.test_scanner import Net


@pytest.fixture
def arp(monkeypatch):
    """A fake ARP table for the scanner and the device refresh."""
    table: dict[str, str] = {}
    monkeypatch.setattr(macvendor, "_cache", macvendor.ArpCache(reader=lambda: dict(table), min_age=0))
    monkeypatch.setattr(macvendor, "read_arp_table", lambda: dict(table))
    return table


def test_normalize_and_vendor():
    assert macvendor.normalize_mac("f0-9f-c2-a-b-c") == "F0:9F:C2:0A:0B:0C"
    assert macvendor.normalize_mac("F09F.C2AA.BBCC") == "F0:9F:C2:AA:BB:CC"
    assert macvendor.normalize_mac("f09fc2aabbcc") == "F0:9F:C2:AA:BB:CC"
    assert macvendor.normalize_mac("nope") == "" and macvendor.normalize_mac("00:00:00:00:00:00") == ""
    assert macvendor.vendor_for("f0:9f:c2:11:22:33") == "Ubiquiti Inc"
    assert macvendor.is_random("da:a1:19:00:00:01") and macvendor.vendor_for("da:a1:19:00:00:01") == ""


def test_brand_for_vendor():
    b = macvendor.brand_for_vendor
    assert b("Ubiquiti Inc") == "Ubiquiti" and b("Routerboard.com") == "MikroTik"
    assert b("TP-LINK TECHNOLOGIES CO.,LTD.") == "TP-Link" and b("Cisco Meraki") == "Cisco Meraki"
    assert b("Cisco-Linksys, LLC") == "Linksys" and b("Cisco Systems, Inc") == "Cisco"
    assert b("Rajant Corporation") == "Rajant" and b("Tachyon, Inc") == "Tachyon"
    assert b("Aruba, a Hewlett Packard Enterprise Company") == "Aruba"
    # Chip / module makers are not the brand of the finished product.
    for org in ("Espressif Inc.", "Intel Corporate", "Realtek Semiconductor Corp.", "Harris Corporation", ""):
        assert b(org) == ""


def test_parse_arp_formats():
    text = """
Interface: 192.168.1.10 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.1           f0-9f-c2-aa-bb-cc     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
? (192.168.1.5) at f0:9f:c2:a:b:c on en0 ifscope [ethernet]
? (192.168.1.6) at (incomplete) on en0 ifscope [ethernet]
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.7      0x1         0x2         80:2a:a8:00:11:22     *        eth0
192.168.1.8      0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.9 dev eth0 lladdr 78:8a:20:01:02:03 REACHABLE
192.168.1.11 dev eth0  FAILED
"""
    assert macvendor.parse_arp(text) == {
        "192.168.1.1": "F0:9F:C2:AA:BB:CC", "192.168.1.5": "F0:9F:C2:0A:0B:0C",
        "192.168.1.7": "80:2A:A8:00:11:22", "192.168.1.9": "78:8A:20:01:02:03"}


def test_arp_cache_rereads_on_miss_only_after_min_age():
    reads = []

    def reader():
        reads.append(1)
        return {"10.0.0.1": "F0:9F:C2:00:00:01"}
    cache = macvendor.ArpCache(reader=reader, min_age=60)
    assert cache.get("10.0.0.1") == "F0:9F:C2:00:00:01"
    assert cache.get("10.0.0.1") and cache.get("10.0.0.2") == "" and len(reads) == 1


def test_brand_for_falls_back_to_mac_vendor():
    assert brands.brand_for("", "", "", "Ubiquiti Inc") == "Ubiquiti"
    assert brands.brand_for("Net-SNMP", "Linux nas 5.10", "", "Synology Incorporated") == "Synology"
    assert brands.brand_for("Cisco", "", "", "Ubiquiti Inc") == "Cisco"  # SNMP's answer wins
    assert brands.brand_for("", "", "", "Espressif Inc.") == ""


async def test_scan_tags_devices_without_snmp_by_mac(db, arp):
    """A home network: nothing answers SNMP, but the ARP table names the makers."""
    net = Net()
    net.snmp = {}
    arp.update({"10.0.0.1": "F0:9F:C2:11:22:33", "10.0.0.3": "DA:A1:19:00:00:01"})
    opts = ScanOptions.from_dict({"resolve_dns": False})
    r = await scan_host("10.0.0.1", opts, net.probe, net.client)
    assert r["mac"] == "F0:9F:C2:11:22:33" and r["mac_vendor"] == "Ubiquiti Inc" and not r["snmp"]

    manager = ScanManager(db, local_probe=net.probe, local_clients=net.client)
    scan = manager.create({"name": "home", "targets": "10.0.0.1-3",
                           "options": {"resolve_dns": False, "auto_add": "alive", "tags": []}})
    await manager.run(scan["id"])
    rows = {r["ip"]: r for r in db.query("SELECT * FROM scan_results")}
    assert rows["10.0.0.1"]["mac_vendor"] == "Ubiquiti Inc"
    assert rows["10.0.0.3"]["mac"] == "DA:A1:19:00:00:01" and rows["10.0.0.3"]["mac_vendor"] == ""  # randomised
    ap = db.one("SELECT * FROM devices WHERE hostname = '10.0.0.1'")
    assert ap["mac_vendor"] == "Ubiquiti Inc" and json.loads(ap["tags"]) == ["Ubiquiti"] and ap["brand_tag"] == "Ubiquiti"
    assert json.loads(db.one("SELECT tags FROM devices WHERE hostname = '10.0.0.3'")["tags"]) == []


def test_existing_devices_pick_up_macs(db, make_device, arp):
    make_device("ap", "192.168.1.20")
    make_device("far", "192.168.1.21", collector_id=None)
    make_device("named", "printer.lan")
    arp.update({"192.168.1.20": "F0:9F:C2:00:00:20", "192.168.1.21": "00:1B:A9:00:00:21"})
    result = brands.tag_all(db)
    assert result["brands"] == {"Ubiquiti": 1, "Brother": 1}
    ap = db.one("SELECT * FROM devices WHERE name = 'ap'")
    assert ap["mac"] == "F0:9F:C2:00:00:20" and json.loads(ap["tags"]) == ["Ubiquiti"]
    assert db.one("SELECT mac FROM devices WHERE name = 'named'")["mac"] == ""
    assert brands.refresh_macs(db) == 0  # nothing changed


async def test_public_community_is_always_tried_and_added(db):
    net = Net()  # 10.0.0.5 answers "public", 10.0.0.1 answers "secret"
    opts = ScanOptions.from_dict({"communities": ["secret"]})
    assert [c["snmp_community"] for c in opts.credentials()] == ["secret", "public"]
    assert [c["snmp_community"] for c in ScanOptions.from_dict({}).credentials()] == ["public"]
    assert ScanOptions.from_dict({"snmp": False}).credentials() == []

    manager = ScanManager(db, local_probe=net.probe, local_clients=net.client)
    # "No - I'll pick from the results", but public still works: those hosts are added anyway.
    scan = manager.create({"name": "lab", "targets": "10.0.0.1-6", "options": {
        "communities": ["secret"], "resolve_dns": False, "auto_add": "none", "tags": []}})
    final = await manager.run(scan["id"])
    rows = {r["ip"]: r for r in db.query("SELECT * FROM scan_results")}
    assert rows["10.0.0.5"]["status"] == "added" and final["added"] == 1
    assert rows["10.0.0.1"]["status"] == "new"  # answered "secret": left for you to pick
    dev = db.one("SELECT * FROM devices WHERE hostname = '10.0.0.5'")
    assert dev["snmp_enabled"] == 1 and dev["snmp_community"] == "public"

    # Switched off per scan.
    db.execute("DELETE FROM devices")
    manager.update(scan["id"], {"options": {"add_public": False}})
    final = await manager.run(scan["id"])
    assert final["added"] == 0 and db.scalar("SELECT COUNT(*) FROM devices") == 0
