import json

import pytest
from fastapi.testclient import TestClient

from snmpathy import brands
from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.db import Database
from snmpathy.snmp import mibs
from snmpathy.snmp.client import FakeSnmpClient
from snmpathy.snmp.discovery import apply_discovery, discover

from .conftest import agent_data


@pytest.mark.parametrize("vendor, descr, model, brand", [
    ("Cisco", "", "", "Cisco"),
    ("Cisco (Airespace)", "", "", "Cisco"),
    ("Ubiquiti", "", "", "Ubiquiti"),
    ("Rajant", "", "", "Rajant"),
    ("Tachyon Networks", "", "", "Tachyon"),
    ("Dell EMC Networking", "", "", "Dell"),
    ("pfSense/FreeBSD", "", "", "pfSense"),
    ("Microsoft", "Hardware: Intel64 Software: Windows Version 6.3", "", "Microsoft"),
    ("Net-SNMP", "Linux DiskStation 4.4.302+ #72806 SMP", "", "Synology"),
    ("Net-SNMP", "Linux U7PG2 4.4.153 #1 SMP", "UniFi AP-AC-Pro", "Ubiquiti"),
    ("Net-SNMP", "pfSense fw.local 2.7.2-RELEASE", "", "pfSense"),
    ("Net-SNMP", "Linux server 6.1.0-18-amd64 #1 SMP Debian", "", ""),
    ("Enterprise 99999", "", "", ""),
    ("", "RouterOS RB4011iGS+", "", "MikroTik"),
    ("", "", "", ""),
])
def test_brand_for(vendor, descr, model, brand):
    assert brands.brand_for(vendor, descr, model) == brand


def _tags(db, device_id):
    return json.loads(db.scalar("SELECT tags FROM devices WHERE id = ?", (device_id,)))


async def test_discovery_tags_the_brand_once(db, make_device):
    device = make_device(tags=["core"])
    apply_discovery(db, device["id"], await discover(FakeSnmpClient(agent_data())))
    assert _tags(db, device["id"]) == ["core", "Cisco"]
    # The user removes it: rediscovery does not put it back.
    db.update("devices", device["id"], {"tags": json.dumps(["core"])})
    apply_discovery(db, device["id"], await discover(FakeSnmpClient(agent_data())))
    assert _tags(db, device["id"]) == ["core"]


async def test_brand_change_swaps_the_tag_and_keeps_user_tags(db, make_device):
    device = make_device(tags=["site-a"])
    apply_discovery(db, device["id"], await discover(FakeSnmpClient(agent_data())))
    data = agent_data()
    data[mibs.SYS_OBJECT_ID] = "1.3.6.1.4.1.2636.1.1.1.2.29"  # replaced by a Juniper box at the same address
    apply_discovery(db, device["id"], await discover(FakeSnmpClient(data)))
    assert _tags(db, device["id"]) == ["site-a", "Juniper"]


def test_existing_tag_in_other_case_is_not_duplicated(db, make_device):
    device = make_device(tags=["cisco"])
    db.update("devices", device["id"], {"vendor": "Cisco"})
    assert brands.apply_brand_tag(db, device["id"]) == ""
    assert _tags(db, device["id"]) == ["cisco"]
    assert db.scalar("SELECT brand_tag FROM devices WHERE id = ?", (device["id"],)) == "Cisco"


def test_switched_off_and_backfill(db, make_device):
    a, b, c = make_device("a", "10.0.0.1"), make_device("b", "10.0.0.2"), make_device("c", "10.0.0.3")
    db.update("devices", a["id"], {"vendor": "Ubiquiti"})
    db.update("devices", b["id"], {"vendor": "Net-SNMP", "sys_descr": "Linux DiskStation"})
    brands.set_enabled(db, False)
    assert brands.apply_brand_tag(db, a["id"]) == "" and brands.tag_all(db)["tagged"] == 0
    assert brands.tag_all(db, force=True) == {"tagged": 2, "brands": {"Ubiquiti": 1, "Synology": 1}}
    assert _tags(db, c["id"]) == []
    assert brands.tag_all(db, force=True)["tagged"] == 0  # already done


def test_settings_api_and_page(tmp_path):
    settings = Settings(database=str(tmp_path / "api.db"), enable_syslog=False)
    db = Database(settings.database)
    with TestClient(create_app(settings, db=db, start_monitor=False)) as client:
        dev = client.post("/api/devices", json={"name": "ap1", "hostname": "10.0.0.9", "snmp_enabled": False}).json()
        db.update("devices", dev["id"], {"vendor": "Rajant"})
        assert client.get("/api/system/brand-tags").json() == {"enabled": True, "tagged": 0}
        assert client.put("/api/system/brand-tags", json={"enabled": False}).json()["enabled"] is False
        assert "Tag devices with their brand" in client.get("/settings").text
        r = client.put("/api/system/brand-tags", json={"enabled": True}).json()  # turning on tags right away
        assert r == {"enabled": True, "tagged": 1, "brands": {"Rajant": 1}}
        assert client.get(f"/api/devices/{dev['id']}").json()["tags"] == ["Rajant"]
        assert client.get("/api/devices", params={"tag": "Rajant"}).json()[0]["name"] == "ap1"
