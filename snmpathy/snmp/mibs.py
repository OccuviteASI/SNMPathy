"""OIDs and metric definitions for the standard MIBs SNMPathy understands.

Only numeric OIDs are used so no MIB compilation is needed at runtime.
"""

from __future__ import annotations

# SNMPv2-MIB::system
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYSTEM_OIDS = [SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_CONTACT, SYS_NAME, SYS_LOCATION]

# IF-MIB::ifTable columns
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_MTU = "1.3.6.1.2.1.2.2.1.4"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_LAST_CHANGE = "1.3.6.1.2.1.2.2.1.9"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"

# IF-MIB::ifXTable columns
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# HOST-RESOURCES-MIB
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
HR_STORAGE_ALLOC = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"
HR_STORAGE_VIRTUAL = "1.3.6.1.2.1.25.2.1.3"

# UCD-SNMP-MIB (net-snmp agents)
UCD_LOAD_1 = "1.3.6.1.4.1.2021.10.1.3.1"
UCD_LOAD_5 = "1.3.6.1.4.1.2021.10.1.3.2"
UCD_LOAD_15 = "1.3.6.1.4.1.2021.10.1.3.3"
UCD_MEM_TOTAL_REAL = "1.3.6.1.4.1.2021.4.5.0"
UCD_MEM_AVAIL_REAL = "1.3.6.1.4.1.2021.4.6.0"
UCD_MEM_BUFFER = "1.3.6.1.4.1.2021.4.14.0"
UCD_MEM_CACHED = "1.3.6.1.4.1.2021.4.15.0"
UCD_SS_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"

IF_OPER_STATUS_NAMES = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}

# Common ifType values (IANAifType-MIB) worth naming in the UI.
IF_TYPE_NAMES = {
    1: "other",
    6: "ethernetCsmacd",
    24: "softwareLoopback",
    53: "propVirtual",
    71: "ieee80211",
    131: "tunnel",
    135: "l2vlan",
    136: "l3ipvlan",
    161: "ieee8023adLag",
}

# Interfaces of these types are not worth polling for traffic by default.
IF_TYPES_SKIP_METRICS: set[int] = set()

# IANA private enterprise numbers -> vendor name (first arc after 1.3.6.1.4.1).
ENTERPRISES = {
    9: "Cisco",
    11: "HPE",
    43: "3Com",
    171: "D-Link",
    311: "Microsoft",
    674: "Dell",
    1588: "Brocade",
    1916: "Extreme Networks",
    1991: "Brocade (Foundry)",
    2011: "Huawei",
    2021: "Net-SNMP (UCD)",
    2272: "Nortel/Avaya",
    2636: "Juniper",
    3375: "F5",
    4526: "Netgear",
    5951: "Citrix",
    6027: "Dell EMC Networking",
    6486: "Alcatel-Lucent",
    6876: "VMware",
    8072: "Net-SNMP",
    9148: "Acme Packet",
    10002: "Ubiquiti",
    11863: "TP-Link",
    12356: "Fortinet",
    12325: "pfSense/FreeBSD",
    14179: "Cisco (Airespace)",
    14988: "MikroTik",
    25461: "Palo Alto Networks",
    25506: "H3C",
    30065: "Arista",
    41112: "Ubiquiti",
    47196: "Cisco Meraki",
    6574: "Synology",
    24681: "QNAP",
    318: "APC",
    534: "Eaton",
    2620: "Check Point",
    8741: "SonicWall",
    890: "Zyxel",
    207: "Allied Telesis",
    3224: "Juniper (NetScreen)",
    5624: "Enterasys",
}


def vendor_from_sysobjectid(sys_object_id: str) -> str:
    prefix = "1.3.6.1.4.1."
    oid = (sys_object_id or "").lstrip(".")
    if not oid.startswith(prefix):
        return ""
    arcs = oid[len(prefix):].split(".")
    try:
        return ENTERPRISES.get(int(arcs[0]), f"Enterprise {arcs[0]}")
    except (ValueError, IndexError):
        return ""


# Well-known metric keys and their presentation metadata.
METRIC_INFO: dict[str, dict[str, str]] = {
    "sys.uptime": {"name": "System uptime", "unit": "s"},
    "cpu.load": {"name": "CPU load (per core)", "unit": "%"},
    "cpu.avg": {"name": "CPU load (average)", "unit": "%"},
    "load.1": {"name": "Load average (1m)", "unit": ""},
    "load.5": {"name": "Load average (5m)", "unit": ""},
    "load.15": {"name": "Load average (15m)", "unit": ""},
    "mem.used_pct": {"name": "Memory used", "unit": "%"},
    "storage.used_pct": {"name": "Storage used", "unit": "%"},
    "storage.used_bytes": {"name": "Storage used", "unit": "B"},
    "if.in_bps": {"name": "Inbound traffic", "unit": "bps"},
    "if.out_bps": {"name": "Outbound traffic", "unit": "bps"},
    "if.in_util": {"name": "Inbound utilisation", "unit": "%"},
    "if.out_util": {"name": "Outbound utilisation", "unit": "%"},
    "if.in_errors": {"name": "Inbound errors", "unit": "/s"},
    "if.out_errors": {"name": "Outbound errors", "unit": "/s"},
    "if.in_discards": {"name": "Inbound discards", "unit": "/s"},
    "if.out_discards": {"name": "Outbound discards", "unit": "/s"},
    "if.oper_status": {"name": "Operational status", "unit": ""},
    "snmp.response_ms": {"name": "SNMP response time", "unit": "ms"},
}
