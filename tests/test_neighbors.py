import time

from snmpathy.snmp import mibs
from snmpathy.snmp.client import FakeSnmpClient
from snmpathy.snmp.neighbors import apply_neighbors, discover_neighbors, resolve_links

from .conftest import agent_data

SW2_CHASSIS = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
SW3_CHASSIS = bytes([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01])
SW3_PORT_MAC = bytes([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x07])
IPV6 = bytes.fromhex("20010db8000000000000000000000003")


def neighbor_agent():
    """sw1 (ifIndex 1 = Gi0/1, 2 = Gi0/2) with LLDP and CDP neighbours."""
    data = agent_data()
    # lldpLocPortTable: localPortNum 101 is Gi0/1 (numbers differ from ifIndex).
    data[f"{mibs.LLDP_LOC_PORT_ID_SUBTYPE}.101"] = 5
    data[f"{mibs.LLDP_LOC_PORT_ID}.101"] = "Gi0/1"
    data[f"{mibs.LLDP_LOC_PORT_DESC}.101"] = "GigabitEthernet0/1"

    # Neighbour A on local port 101: sw2, MAC chassis, sysName, IPv4 management address.
    a = "0.101.1"
    data[f"{mibs.LLDP_REM_CHASSIS_ID_SUBTYPE}.{a}"] = 4
    data[f"{mibs.LLDP_REM_CHASSIS_ID}.{a}"] = SW2_CHASSIS
    data[f"{mibs.LLDP_REM_PORT_ID_SUBTYPE}.{a}"] = 5
    data[f"{mibs.LLDP_REM_PORT_ID}.{a}"] = "Gi1/0/24"
    data[f"{mibs.LLDP_REM_PORT_DESC}.{a}"] = "to sw1"
    data[f"{mibs.LLDP_REM_SYS_NAME}.{a}"] = "sw2.example.com"
    data[f"{mibs.LLDP_REM_MAN_ADDR_TABLE}.3.{a}.1.4.10.0.0.2"] = 2

    # Neighbour B on local port 2 (no lldpLocPortTable row -> ifIndex fallback):
    # no sysName, MAC port id, IPv6 management address.
    b = "0.2.3"
    data[f"{mibs.LLDP_REM_CHASSIS_ID_SUBTYPE}.{b}"] = 4
    data[f"{mibs.LLDP_REM_CHASSIS_ID}.{b}"] = SW3_CHASSIS
    data[f"{mibs.LLDP_REM_PORT_ID_SUBTYPE}.{b}"] = 3
    data[f"{mibs.LLDP_REM_PORT_ID}.{b}"] = SW3_PORT_MAC
    data[f"{mibs.LLDP_REM_SYS_DESC}.{b}"] = "Linux sw3 6.1.0\nsecond line"
    addr6 = ".".join(str(o) for o in IPV6)
    data[f"{mibs.LLDP_REM_MAN_ADDR_TABLE}.3.{b}.2.16.{addr6}"] = 2

    # CDP: sw2 again on ifIndex 1 (duplicate of LLDP A), and an AP on ifIndex 2.
    data[f"{mibs.CDP_CACHE_ADDRESS_TYPE}.1.7"] = 1
    data[f"{mibs.CDP_CACHE_ADDRESS}.1.7"] = bytes([10, 0, 0, 2])
    data[f"{mibs.CDP_CACHE_VERSION}.1.7"] = "Cisco IOS XE Software, Version 17.9"
    data[f"{mibs.CDP_CACHE_DEVICE_ID}.1.7"] = "sw2.example.com(FOC1234ABCD)"
    data[f"{mibs.CDP_CACHE_DEVICE_PORT}.1.7"] = "GigabitEthernet1/0/24"
    data[f"{mibs.CDP_CACHE_PLATFORM}.1.7"] = "cisco C9300-48P"
    data[f"{mibs.CDP_CACHE_ADDRESS_TYPE}.2.9"] = 1
    data[f"{mibs.CDP_CACHE_ADDRESS}.2.9"] = bytes([192, 168, 1, 50])
    data[f"{mibs.CDP_CACHE_DEVICE_ID}.2.9"] = "ap1"
    data[f"{mibs.CDP_CACHE_DEVICE_PORT}.2.9"] = "GigabitEthernet0"
    data[f"{mibs.CDP_CACHE_PLATFORM}.2.9"] = "cisco AIR-AP2802I"
    return data


async def test_discover_neighbors_lldp_and_cdp():
    neighbors = await discover_neighbors(FakeSnmpClient(neighbor_agent()))
    # Sorted by LLDP localPortNum (2 before 101), then CDP.
    assert [n["protocol"] for n in neighbors] == ["lldp", "lldp", "cdp"]
    b, a, ap = neighbors

    assert a == {
        "protocol": "lldp",
        "if_index": 1,
        "local_port": "Gi0/1",
        "remote_name": "sw2.example.com",
        "remote_port": "Gi1/0/24",
        "remote_ip": "10.0.0.2",
        "remote_chassis": "00:11:22:33:44:55",
        # LLDP sent no sysDesc: filled in from the duplicate CDP entry.
        "remote_platform": "cisco C9300-48P",
    }
    assert b["protocol"] == "lldp"
    assert b["if_index"] == 2 and b["local_port"] == "Gi0/2"
    assert b["remote_chassis"] == "00:aa:bb:cc:dd:01"
    assert b["remote_name"] == "00:aa:bb:cc:dd:01"  # no sysName -> chassis id
    assert b["remote_port"] == "00:aa:bb:cc:dd:07"
    assert b["remote_ip"] == "2001:db8::3"
    assert b["remote_platform"] == "Linux sw3 6.1.0"

    assert ap == {
        "protocol": "cdp",
        "if_index": 2,
        "local_port": "Gi0/2",
        "remote_name": "ap1",
        "remote_port": "GigabitEthernet0",
        "remote_ip": "192.168.1.50",
        "remote_chassis": "",
        "remote_platform": "cisco AIR-AP2802I",
    }


async def test_cdp_only_keeps_device_id_without_serial():
    data = agent_data()
    data[f"{mibs.CDP_CACHE_ADDRESS_TYPE}.1.1"] = 1
    data[f"{mibs.CDP_CACHE_ADDRESS}.1.1"] = "\n\x00\x00\x07"  # printable octets decoded as text
    data[f"{mibs.CDP_CACHE_DEVICE_ID}.1.1"] = "core-1.example.com(SSI123)"
    data[f"{mibs.CDP_CACHE_DEVICE_PORT}.1.1"] = "Te1/1"
    neighbors = await discover_neighbors(FakeSnmpClient(data))
    assert len(neighbors) == 1
    assert neighbors[0]["protocol"] == "cdp"
    assert neighbors[0]["remote_name"] == "core-1.example.com"
    assert neighbors[0]["remote_ip"] == "10.0.0.7"
    assert neighbors[0]["if_index"] == 1 and neighbors[0]["local_port"] == "Gi0/1"


async def test_lldp_chassis_id_formats():
    data = agent_data()
    # Printable MAC octets arrive as text from the SNMP client.
    data[f"{mibs.LLDP_REM_CHASSIS_ID_SUBTYPE}.0.1.1"] = 4
    data[f"{mibs.LLDP_REM_CHASSIS_ID}.0.1.1"] = "ABCDEF"
    data[f"{mibs.LLDP_REM_PORT_ID_SUBTYPE}.0.1.1"] = 7
    data[f"{mibs.LLDP_REM_PORT_ID}.0.1.1"] = "17"
    # Network-address chassis id (IANA family 1 = IPv4).
    data[f"{mibs.LLDP_REM_CHASSIS_ID_SUBTYPE}.0.2.1"] = 5
    data[f"{mibs.LLDP_REM_CHASSIS_ID}.0.2.1"] = bytes([1, 10, 0, 0, 9])
    data[f"{mibs.LLDP_REM_PORT_ID_SUBTYPE}.0.2.1"] = 5
    data[f"{mibs.LLDP_REM_PORT_ID}.0.2.1"] = "eth0"
    neighbors = await discover_neighbors(FakeSnmpClient(data))
    assert [n["remote_chassis"] for n in neighbors] == ["41:42:43:44:45:46", "10.0.0.9"]
    assert neighbors[1]["remote_ip"] == "10.0.0.9"
    assert neighbors[1]["remote_name"] == "10.0.0.9"
    # localPortNum is a valid ifIndex when lldpLocPortTable is missing.
    assert [n["if_index"] for n in neighbors] == [1, 2]
    assert [n["local_port"] for n in neighbors] == ["Gi0/1", "Gi0/2"]


async def test_missing_mibs_yield_no_neighbors():
    assert await discover_neighbors(FakeSnmpClient(agent_data())) == []
    assert await discover_neighbors(FakeSnmpClient({})) == []
    assert await discover_neighbors(FakeSnmpClient(neighbor_agent(), fail=True)) == []


def _add_iface(db, device_id, if_index, name, descr="", alias="", mac=""):
    db.insert("interfaces", {
        "device_id": device_id, "if_index": if_index, "name": name, "descr": descr,
        "alias": alias, "mac": mac, "updated_at": time.time(),
    })


def _links(db, device_id):
    return {
        (row["protocol"], row["remote_name"]): row
        for row in db.query("SELECT * FROM links WHERE device_id = ?", (device_id,))
    }


async def test_apply_neighbors_resolves_and_upserts(db, make_device):
    sw1 = make_device("sw1", "10.0.0.1")
    sw2 = make_device("switch-two", "192.0.2.2")
    db.update("devices", sw2["id"], {"sys_name": "sw2"})
    _add_iface(db, sw2["id"], 24, "Gi1/0/24", "GigabitEthernet1/0/24")
    sw3 = make_device("sw3", "192.0.2.3")
    _add_iface(db, sw3["id"], 1, "eth0", mac="00:aa:bb:cc:dd:01")
    _add_iface(db, sw3["id"], 7, "eth6", mac="00:aa:bb:cc:dd:07")

    neighbors = await discover_neighbors(FakeSnmpClient(neighbor_agent()))
    result = apply_neighbors(db, sw1["id"], neighbors, now=1000.0)
    assert result == {"links": 3, "resolved": 2}

    links = _links(db, sw1["id"])
    a = links[("lldp", "sw2.example.com")]
    assert a["remote_device_id"] == sw2["id"]  # sysName with the domain stripped
    assert a["remote_if_index"] == 24
    assert a["if_index"] == 1 and a["local_port"] == "Gi0/1"
    b = links[("lldp", "00:aa:bb:cc:dd:01")]
    assert b["remote_device_id"] == sw3["id"]  # chassis MAC matches an interface MAC
    assert b["remote_if_index"] == 7           # MAC port id matches an interface MAC
    ap = links[("cdp", "ap1")]
    assert ap["remote_device_id"] is None and ap["remote_if_index"] is None
    assert ap["remote_platform"] == "cisco AIR-AP2802I"
    assert all(row["first_seen"] == 1000.0 for row in links.values())

    # A manual link must survive later discovery runs.
    db.insert("links", {
        "device_id": sw1["id"], "local_port": "Gi0/9", "remote_name": "patch panel",
        "protocol": "manual", "first_seen": 500.0, "last_seen": 500.0,
    })

    # Second run: only neighbour A is still there.
    only_a = [n for n in neighbors if n["remote_name"] == "sw2.example.com"]
    result = apply_neighbors(db, sw1["id"], only_a, now=2000.0)
    assert result == {"links": 1, "resolved": 1}
    links = _links(db, sw1["id"])
    assert set(links) == {("lldp", "sw2.example.com"), ("manual", "patch panel")}
    a2 = links[("lldp", "sw2.example.com")]
    assert a2["id"] == a["id"]
    assert a2["first_seen"] == 1000.0 and a2["last_seen"] == 2000.0
    assert links[("manual", "patch panel")]["last_seen"] == 500.0

    # No neighbours at all: discovery links go, the manual one stays.
    assert apply_neighbors(db, sw1["id"], [], now=3000.0) == {"links": 0, "resolved": 0}
    assert set(_links(db, sw1["id"])) == {("manual", "patch panel")}


async def test_apply_neighbors_matches_ip_and_hostname(db, make_device):
    sw1 = make_device("sw1", "10.0.0.1")
    by_ip = make_device("core", "10.0.0.2")
    by_host = make_device("edge", "edge-1.example.net")
    neighbors = [
        {"protocol": "cdp", "if_index": 1, "local_port": "Gi0/1", "remote_name": "unknown-name",
         "remote_port": "Te1/1", "remote_ip": "10.0.0.2", "remote_chassis": "", "remote_platform": ""},
        {"protocol": "lldp", "if_index": 2, "local_port": "Gi0/2", "remote_name": "EDGE-1",
         "remote_port": "xe-0/0/0", "remote_ip": "", "remote_chassis": "", "remote_platform": ""},
        # A neighbour that looks like sw1 itself is never resolved to sw1.
        {"protocol": "lldp", "if_index": 3, "local_port": "Gi0/3", "remote_name": "sw1",
         "remote_port": "p1", "remote_ip": "", "remote_chassis": "", "remote_platform": ""},
    ]
    assert apply_neighbors(db, sw1["id"], neighbors) == {"links": 3, "resolved": 2}
    links = _links(db, sw1["id"])
    assert links[("cdp", "unknown-name")]["remote_device_id"] == by_ip["id"]
    assert links[("lldp", "EDGE-1")]["remote_device_id"] == by_host["id"]
    assert links[("lldp", "sw1")]["remote_device_id"] is None


async def test_resolve_links_after_device_added(db, make_device):
    sw1 = make_device("sw1", "10.0.0.1")
    neighbors = await discover_neighbors(FakeSnmpClient(neighbor_agent()))
    assert apply_neighbors(db, sw1["id"], neighbors)["resolved"] == 0
    assert resolve_links(db) == 0

    ap = make_device("ap1", "192.168.1.50")
    _add_iface(db, ap["id"], 1, "GigabitEthernet0")
    sw2 = make_device("sw2", "10.0.0.2")
    assert resolve_links(db) == 2

    links = _links(db, sw1["id"])
    assert links[("cdp", "ap1")]["remote_device_id"] == ap["id"]
    assert links[("cdp", "ap1")]["remote_if_index"] == 1
    assert links[("lldp", "sw2.example.com")]["remote_device_id"] == sw2["id"]
    assert links[("lldp", "00:aa:bb:cc:dd:01")]["remote_device_id"] is None
    assert resolve_links(db) == 0
