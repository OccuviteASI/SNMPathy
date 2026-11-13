"""Who made a device, from its network card's MAC address.

Home and small-office gear (Ubiquiti access points, TP-Link switches, printers, cameras, ...)
often has SNMP switched off, so discovery cannot ask it who made it. Every device on the same
network segment still reveals its MAC address once it has answered a ping: the scanning machine
keeps it in its ARP (neighbour) table. The first half of a MAC (the OUI) is registered to the
maker with the IEEE; ``data/oui.tsv.gz`` holds that registry (built from the public MA-L list).

* ``mac_for(ip)`` reads the local ARP table (Linux /proc/net/arp or ``ip neigh``, Windows and
  macOS ``arp -a``). Devices behind a router never show up there, so nothing is guessed for them.
* ``vendor_for(mac)`` returns the registered organisation ("Ubiquiti Inc"); randomised
  (locally administered) MACs, as phones use for privacy, have no maker and return ''.
* ``brand_for_vendor(org)`` turns that into a brand tag ("Ubiquiti") for the makers people
  recognise. Chip and module makers (Espressif, Realtek, Hon Hai, ...) are not brands of the
  finished product, so they are shown but never used as a tag.
"""

from __future__ import annotations

import gzip
import logging
import re
import subprocess
import sys
import threading
import time
from importlib import resources
from pathlib import Path

log = logging.getLogger(__name__)

_MAC_RE = re.compile(r"([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Registered organisation name (regex, case-insensitive) -> brand tag. First match wins, so
# more specific names come first. Brands match the names SNMP discovery uses (snmp/mibs.py).
OUI_BRANDS: list[tuple[str, str]] = [
    (r"ubiquiti", "Ubiquiti"),
    (r"meraki", "Cisco Meraki"),
    (r"linksys", "Linksys"),
    (r"^cisco", "Cisco"),
    (r"routerboard|mikrotik", "MikroTik"),
    (r"rajant", "Rajant"),
    (r"^tachyon", "Tachyon"),
    (r"tp-?link", "TP-Link"),
    (r"netgear", "Netgear"),
    (r"d-link", "D-Link"),
    (r"asustek|^asus", "ASUS"),
    (r"^eero", "eero"),
    (r"^arris|^commscope", "Arris"),
    (r"ruckus", "Ruckus"),
    (r"cambium", "Cambium"),
    (r"aruba", "Aruba"),
    (r"hewlett packard enterprise", "HPE"),
    (r"hewlett[- ]packard|^hp inc", "HP"),
    (r"juniper networks", "Juniper"),
    (r"fortinet", "Fortinet"),
    (r"palo alto networks", "Palo Alto Networks"),
    (r"sonicwall", "SonicWall"),
    (r"watchguard", "WatchGuard"),
    (r"sophos", "Sophos"),
    (r"peplink|pepwave", "Peplink"),
    (r"arista", "Arista"),
    (r"extreme networks", "Extreme Networks"),
    (r"zyxel", "Zyxel"),
    (r"huawei", "Huawei"),
    (r"^zte\b", "ZTE"),
    (r"synology", "Synology"),
    (r"qnap", "QNAP"),
    (r"western digital", "Western Digital"),
    (r"^dell\b", "Dell"),
    (r"lenovo", "Lenovo"),
    (r"super ?micro", "Supermicro"),
    (r"raspberry pi", "Raspberry Pi"),
    (r"^apple\b", "Apple"),
    (r"^google|nest labs", "Google"),
    (r"amazon technologies|^amazon", "Amazon"),
    (r"^microsoft", "Microsoft"),
    (r"samsung", "Samsung"),
    (r"^sonos", "Sonos"),
    (r"^roku", "Roku"),
    (r"^lg electronics", "LG"),
    (r"^sony\b", "Sony"),
    (r"^vizio", "Vizio"),
    (r"nintendo", "Nintendo"),
    (r"xiaomi", "Xiaomi"),
    (r"signify|philips lighting", "Philips Hue"),
    (r"wyze", "Wyze"),
    (r"^ring llc", "Ring"),
    (r"ecobee", "ecobee"),
    (r"hikvision", "Hikvision"),
    (r"dahua", "Dahua"),
    (r"axis communications", "Axis"),
    (r"reolink", "Reolink"),
    (r"brother industries", "Brother"),
    (r"^canon\b", "Canon"),
    (r"seiko epson", "Epson"),
    (r"lexmark", "Lexmark"),
    (r"xerox", "Xerox"),
    (r"kyocera", "Kyocera"),
    (r"american power conversion", "APC"),
    (r"^eaton", "Eaton"),
    (r"cyber ?power", "CyberPower"),
    (r"^vmware", "VMware"),
    (r"yealink", "Yealink"),
    (r"grandstream", "Grandstream"),
    (r"polycom|^hp poly", "Poly"),
    (r"^mitel", "Mitel"),
]
_OUI_BRANDS = [(re.compile(p, re.I), b) for p, b in OUI_BRANDS]

_table: dict[str, str] | None = None
_table_lock = threading.Lock()


def _load_table() -> dict[str, str]:
    global _table
    with _table_lock:
        if _table is None:
            table: dict[str, str] = {}
            try:
                path = resources.files(__package__).joinpath("data/oui.tsv.gz")
                with path.open("rb") as raw, gzip.open(raw, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        prefix, _, org = line.rstrip("\n").partition("\t")
                        if org:
                            table[prefix] = org
            except (OSError, FileNotFoundError) as exc:  # a broken install: no vendors, nothing else breaks
                log.warning("MAC vendor table unavailable: %s", exc)
            _table = table
        return _table


def normalize_mac(mac: str) -> str:
    """'f0-9f-c2-a-b-c' / 'F09F.C2AA.BBCC' -> 'F0:9F:C2:0A:0B:0C'; '' if it is not a MAC."""
    text = (mac or "").strip()
    if re.fullmatch(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}", text):
        text = text.replace(".", "")
    if re.fullmatch(r"[0-9A-Fa-f]{12}", text):
        parts = [text[i:i + 2] for i in range(0, 12, 2)]
    else:
        parts = re.split(r"[:-]", text)
        if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
            return ""
    mac = ":".join(p.zfill(2).upper() for p in parts)
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return ""
    return mac


def is_random(mac: str) -> bool:
    """Locally administered (randomised / virtual) MAC: the OUI says nothing about the maker."""
    mac = normalize_mac(mac)
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)


def vendor_for(mac: str) -> str:
    """The organisation the MAC's OUI is registered to, or ''."""
    mac = normalize_mac(mac)
    if not mac or is_random(mac) or int(mac[:2], 16) & 0x01:  # randomised or multicast
        return ""
    return _load_table().get(mac.replace(":", "")[:6], "")


def brand_for_vendor(org: str) -> str:
    """Brand tag for a registered organisation name ('' for chip makers and unknown names)."""
    org = (org or "").strip()
    if not org:
        return ""
    for pattern, brand in _OUI_BRANDS:
        if pattern.search(org):
            return brand
    return ""


# --------------------------------------------------------------------------- ARP table
def parse_arp(text: str) -> dict[str, str]:
    """IPv4 -> MAC from `arp -a` (Windows, macOS, BSD), `ip neigh` or /proc/net/arp output."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "incomplete" in line.lower() or "FAILED" in line:
            continue
        ip_m, mac_m = _IPV4_RE.search(line), _MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        if " 0x0 " in f" {line} ":  # /proc/net/arp: flags 0x0 = no answer yet
            continue
        mac = normalize_mac(mac_m.group(1))
        if mac:
            out[ip_m.group(1)] = mac
    return out


def _run(cmd: list[str]) -> str:
    kwargs: dict = {"capture_output": True, "text": True, "timeout": 5}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(cmd, **kwargs).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def read_arp_table() -> dict[str, str]:
    """The machine's current IPv4 -> MAC neighbour table (empty if it cannot be read)."""
    proc = Path("/proc/net/arp")
    if sys.platform.startswith("linux"):
        try:
            table = parse_arp(proc.read_text())
            if table:
                return table
        except OSError:
            pass
        return parse_arp(_run(["ip", "-4", "neigh", "show"]))
    if sys.platform == "win32":
        return parse_arp(_run(["arp", "-a"]))
    return parse_arp(_run(["arp", "-an"]))


class ArpCache:
    """Reads the ARP table at most every ``min_age`` seconds, however many hosts ask at once."""

    def __init__(self, reader=read_arp_table, min_age: float = 0.5):
        self.reader = reader
        self.min_age = min_age
        self.table: dict[str, str] = {}
        self.read_at: float | None = None  # never read yet (monotonic time can be small after boot)
        self.lock = threading.Lock()

    def get(self, ip: str) -> str:
        with self.lock:
            if ip not in self.table and (self.read_at is None or time.monotonic() - self.read_at >= self.min_age):
                self.table = self.reader()
                self.read_at = time.monotonic()
            return self.table.get(ip, "")


_cache = ArpCache()


def mac_for(ip: str) -> str:
    """The MAC address of ``ip`` if it is on this machine's own network segment, else ''."""
    return _cache.get(ip)


def describe(mac: str) -> dict[str, str]:
    """{mac, mac_vendor} for a scan result or device."""
    mac = normalize_mac(mac)
    return {"mac": mac, "mac_vendor": vendor_for(mac) if mac else ""}
