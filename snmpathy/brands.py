"""Tag devices with their brand (Cisco, Ubiquiti, Rajant, ...) when discovery detects it.

The brand comes from the vendor that discovery found (the sysObjectID enterprise number,
or a vendor private MIB such as Ubiquiti's), cleaned up for use as a tag. Devices that
answer with a generic Net-SNMP identity (Synology, pfSense, UniFi, ...) are recognised from
their sysDescr instead. Devices without SNMP (common on home networks) are recognised from
the maker registered for their MAC address (snmpathy/macvendor.py).

The tag SNMPathy added is remembered in ``devices.brand_tag``:

* it is added once; if you delete it, rediscovery does not put it back,
* if the detected brand changes, the old brand tag is swapped for the new one,
* your own tags are never touched, and an existing tag that differs only in case
  (``cisco``) counts as already tagged.

Turned on by default; Settings > Device tagging switches it off (meta ``auto_tag_brand``).
"""

from __future__ import annotations

import json
import re
from typing import Any

from .db import Database, loads

META_KEY = "auto_tag_brand"

# Vendor names from discovery (snmp/mibs.ENTERPRISES and vendor modules) -> brand tag.
BRAND_NAMES = {
    "Cisco (Airespace)": "Cisco",
    "Brocade (Foundry)": "Brocade",
    "Juniper (NetScreen)": "Juniper",
    "Dell EMC Networking": "Dell",
    "Nortel/Avaya": "Avaya",
    "pfSense/FreeBSD": "pfSense",
    "Tachyon Networks": "Tachyon",
}
# Agents that say nothing about the hardware's maker.
GENERIC_VENDORS = {"net-snmp", "net-snmp (ucd)"}
# For generic agents: sysDescr / model hints (checked in order).
DESCR_HINTS: list[tuple[str, str]] = [
    (r"\bpfsense\b", "pfSense"),
    (r"\bopnsense\b", "OPNsense"),
    (r"\bsynology\b|\bdiskstation\b|\brackstation\b", "Synology"),
    (r"\bqnap\b|\bqts\b", "QNAP"),
    (r"\bmikrotik\b|\brouteros\b", "MikroTik"),
    (r"\bubiquiti\b|\bunifi\b|\bubnt\b|\bairos\b|\bedgeos\b|\bedgeswitch\b|\buisp\b", "Ubiquiti"),
    (r"\brajant\b|\bbreadcrumb\b", "Rajant"),
    (r"\btachyon\b", "Tachyon"),
    (r"\bcisco\b", "Cisco"),
    (r"\bjuniper\b|\bjunos\b", "Juniper"),
    (r"\bfortigate\b|\bfortinet\b", "Fortinet"),
    (r"\bpalo alto\b|\bpan-os\b", "Palo Alto Networks"),
    (r"\barista\b", "Arista"),
    (r"\bhuawei\b", "Huawei"),
    (r"\bnetgear\b", "Netgear"),
    (r"\btp-link\b|\btplink\b|\bomada\b", "TP-Link"),
    (r"\bproxmox\b", "Proxmox"),
    (r"\bvmware\b|\besxi\b", "VMware"),
    (r"\btruenas\b|\bfreenas\b", "TrueNAS"),
    (r"\bwindows\b", "Microsoft"),
]


def brand_for(vendor: str = "", sys_descr: str = "", hw_model: str = "", mac_vendor: str = "") -> str:
    """The brand tag for a device, or '' when the maker is unknown.

    SNMP's answer wins; without one (SNMP off, or a generic agent with no hints in sysDescr)
    the maker registered for the device's MAC address is used.
    """
    vendor = (vendor or "").strip()
    if vendor and vendor.lower() not in GENERIC_VENDORS and not vendor.startswith("Enterprise "):
        return BRAND_NAMES.get(vendor, re.sub(r"\s*\(.*\)$", "", vendor))
    text = f"{hw_model or ''} {sys_descr or ''}".lower()
    for pattern, brand in DESCR_HINTS:
        if re.search(pattern, text):
            return brand
    if mac_vendor:
        from .macvendor import brand_for_vendor

        return brand_for_vendor(mac_vendor)
    return ""


def enabled(db: Database) -> bool:
    return db.get_meta(META_KEY, "1") != "0"


def set_enabled(db: Database, on: bool) -> None:
    db.set_meta(META_KEY, "1" if on else "0")


def apply_brand_tag(db: Database, device_id: int, force: bool = False) -> str:
    """Tag one device with its detected brand. Returns the tag added ('' if nothing changed)."""
    if not force and not enabled(db):
        return ""
    row = db.one("SELECT tags, brand_tag, vendor, sys_descr, hw_model, mac_vendor FROM devices WHERE id = ?",
                 (device_id,))
    if not row:
        return ""
    brand = brand_for(row["vendor"], row["sys_descr"], row["hw_model"], row["mac_vendor"])
    previous = row["brand_tag"] or ""
    if not brand or brand == previous:
        return ""  # unknown, or already tagged once (respect the user removing it)
    tags: list[str] = list(loads(row["tags"], []))
    if previous and previous in tags:
        tags.remove(previous)  # the brand we tagged earlier was wrong: swap it
    added = ""
    if brand.lower() not in {t.lower() for t in tags}:
        tags.append(brand)
        added = brand
    db.update("devices", device_id, {"tags": json.dumps(tags), "brand_tag": brand})
    return added


def refresh_macs(db: Database, arp: dict[str, str] | None = None) -> int:
    """Record the MAC address (and its maker) of devices this server can see in its ARP table.

    Only devices polled from this server and addressed by IPv4 qualify: a remote collector's
    devices are on another network, and the ARP table only lists the local segment.
    Returns how many devices changed.
    """
    from . import macvendor

    table = macvendor.read_arp_table() if arp is None else arp
    if not table:
        return 0
    changed = 0
    for row in db.query("SELECT id, hostname, mac, mac_vendor FROM devices WHERE collector_id IS NULL"):
        mac = table.get((row["hostname"] or "").strip())
        if not mac:
            continue
        info = macvendor.describe(mac)
        if info["mac"] != row["mac"] or info["mac_vendor"] != row["mac_vendor"]:
            db.update("devices", row["id"], info)
            changed += 1
    return changed


def tag_all(db: Database, force: bool = False, arp: dict[str, str] | None = None) -> dict[str, Any]:
    """Tag every device whose brand is known and that SNMPathy has not tagged yet."""
    if not force and not enabled(db):
        return {"tagged": 0, "brands": {}}
    try:
        refresh_macs(db, arp)
    except Exception:  # the ARP table is a bonus: never block tagging on it
        pass
    brands: dict[str, int] = {}
    for row in db.query("SELECT id FROM devices WHERE brand_tag = ''"):
        added = apply_brand_tag(db, row["id"], force=True)
        if added:
            brands[added] = brands.get(added, 0) + 1
    return {"tagged": sum(brands.values()), "brands": brands}
