"""Tag devices with their brand (Cisco, Ubiquiti, Rajant, ...) when discovery detects it.

The brand comes from the vendor that discovery found (the sysObjectID enterprise number,
or a vendor private MIB such as Ubiquiti's), cleaned up for use as a tag. Devices that
answer with a generic Net-SNMP identity (Synology, pfSense, UniFi, ...) are recognised from
their sysDescr instead.

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


def brand_for(vendor: str = "", sys_descr: str = "", hw_model: str = "") -> str:
    """The brand tag for a device, or '' when the maker is unknown."""
    vendor = (vendor or "").strip()
    if vendor and vendor.lower() not in GENERIC_VENDORS and not vendor.startswith("Enterprise "):
        return BRAND_NAMES.get(vendor, re.sub(r"\s*\(.*\)$", "", vendor))
    text = f"{hw_model or ''} {sys_descr or ''}".lower()
    for pattern, brand in DESCR_HINTS:
        if re.search(pattern, text):
            return brand
    return ""


def enabled(db: Database) -> bool:
    return db.get_meta(META_KEY, "1") != "0"


def set_enabled(db: Database, on: bool) -> None:
    db.set_meta(META_KEY, "1" if on else "0")


def apply_brand_tag(db: Database, device_id: int, force: bool = False) -> str:
    """Tag one device with its detected brand. Returns the tag added ('' if nothing changed)."""
    if not force and not enabled(db):
        return ""
    row = db.one("SELECT tags, brand_tag, vendor, sys_descr, hw_model FROM devices WHERE id = ?", (device_id,))
    if not row:
        return ""
    brand = brand_for(row["vendor"], row["sys_descr"], row["hw_model"])
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


def tag_all(db: Database, force: bool = False) -> dict[str, Any]:
    """Tag every device whose brand is known and that SNMPathy has not tagged yet."""
    if not force and not enabled(db):
        return {"tagged": 0, "brands": {}}
    brands: dict[str, int] = {}
    for row in db.query("SELECT id FROM devices WHERE brand_tag = ''"):
        added = apply_brand_tag(db, row["id"], force=True)
        if added:
            brands[added] = brands.get(added, 0) + 1
    return {"tagged": sum(brands.values()), "brands": brands}
