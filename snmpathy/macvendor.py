"""Who made a device, from its network card's MAC address.

Home and small-office gear (Ubiquiti access points, TP-Link switches, printers, cameras, ...)
often has SNMP switched off, so discovery cannot ask it who made it. Every device on the same
network segment still reveals its MAC address once it has answered a ping: the scanning machine
keeps it in its ARP (neighbour) table. The first half of a MAC (the OUI) is registered to the
maker with the IEEE.

Two maker lists are used, most specific first:

* **Wireshark's** (``manuf``): the IEEE registries (MA-L, plus the MA-M / MA-S blocks that split
  one prefix between several makers) kept current by the Wireshark project. It is GPL-licensed,
  so SNMPathy does not ship it: ``refresh_wireshark()`` downloads it into the data folder
  (``manuf-wireshark.tsv.gz``, next to the database) and refreshes it weekly.
* the IEEE MA-L list bundled in ``data/oui.tsv.gz``, used until that download has happened.

* ``mac_for(ip)`` reads the local ARP table (Linux /proc/net/arp or ``ip neigh``, Windows and
  macOS ``arp -a``). Devices behind a router never show up there, so nothing is guessed for them.
* ``vendor_for(mac)`` returns the registered organisation ("Ubiquiti Inc"); randomised
  (locally administered) MACs, as phones use for privacy, have no maker and return ''.
* ``brand_for_vendor(org)`` turns that into a brand tag: the familiar name for well-known
  brands ("Ubiquiti", "TP-Link"), otherwise the maker's name without "Co., Ltd", "Technology",
  city names and the like ("Shenzhen Bilian Electronic Co.,Ltd" -> "Bilian").
"""

from __future__ import annotations

import gzip
import logging
import os
import re
import subprocess
import sys
import threading
import time
from importlib import resources
from pathlib import Path
from typing import Any, Callable

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
    (r"hon hai|foxconn", "Foxconn"),
    (r"^tuya", "Tuya"),
    (r"shelly|allterco", "Shelly"),
    (r"itead|sonoff", "Sonoff"),
    (r"^arlo", "Arlo"),
    (r"ezviz", "Ezviz"),
    (r"^bose\b", "Bose"),
    (r"^denon|sound united", "Denon"),
    (r"^intel\b", "Intel"),
    (r"realtek", "Realtek"),
    (r"espressif", "Espressif"),
    (r"texas instruments", "Texas Instruments"),
    (r"murata", "Murata"),
    (r"azurewave", "AzureWave"),
    (r"^nokia", "Nokia"),
    (r"motorola", "Motorola"),
    (r"oneplus", "OnePlus"),
    (r"^oppo\b|guangdong oppo", "OPPO"),
    (r"^vivo\b|vivo mobile", "vivo"),
    (r"panasonic", "Panasonic"),
    (r"^philips\b|koninklijke philips", "Philips"),
    (r"^tcl\b", "TCL"),
    (r"hisense", "Hisense"),
    (r"sagemcom", "Sagemcom"),
    (r"^avm\b", "AVM"),
    (r"technicolor", "Technicolor"),
    (r"actiontec", "Actiontec"),
    (r"^calix", "Calix"),
    (r"^sercomm", "Sercomm"),
    (r"^askey", "Askey"),
    (r"^wistron", "Wistron"),
    (r"^liteon|lite-on", "Lite-On"),
    (r"^gigabyte|giga-byte", "Gigabyte"),
    (r"micro-star|^msi\b", "MSI"),
    (r"^acer\b", "Acer"),
    (r"silicon lab", "Silicon Labs"),
    (r"^ieee registration authority|^private$", ""),
]
_OUI_BRANDS = [(re.compile(p, re.I), b) for p, b in OUI_BRANDS]

_table: dict[str, str] | None = None
_table_lock = threading.Lock()

# ---------------------------------------------------------------- Wireshark's list
WIRESHARK_URLS = (
    "https://www.wireshark.org/download/automated/data/manuf",
    "https://raw.githubusercontent.com/wireshark/wireshark/master/epan/manuf-data.c",
)
WIRESHARK_FILE = "manuf-wireshark.tsv.gz"
REFRESH_AGE = 7 * 86400  # seconds before the downloaded list is fetched again
MIN_ENTRIES = 20000  # fewer means a broken download: keep what we have
_data_dir: Path | None = None
# nibbles (6 = /24, 7 = /28, 9 = /36) -> prefix (upper-case hex) -> long name; short names by long name
_ws: dict[int, dict[str, str]] | None = None
_short: dict[str, str] = {}


def set_data_dir(path: Path | str | None) -> None:
    """Where the downloaded Wireshark list lives (the database's folder)."""
    global _data_dir, _ws
    with _table_lock:
        _data_dir = Path(path) if path else None
        _ws = None


def wireshark_path() -> Path | None:
    return _data_dir / WIRESHARK_FILE if _data_dir else None


def _bits_ok(bits: int) -> bool:
    return 24 <= bits <= 44 and bits % 4 == 0


def parse_manuf(text: str) -> list[tuple[int, str, str, str]]:
    """Wireshark's ``manuf`` text: ``00:1B:C5:00:00:00/36<TAB>Short<TAB>Long name``.

    Returns (nibbles, hex prefix, short, long) rows.
    """
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        addr, _, bits_text = parts[0].strip().partition("/")
        digits = re.sub(r"[^0-9A-Fa-f]", "", addr).upper()
        bits = int(bits_text) if bits_text.isdigit() else 24
        if not _bits_ok(bits) or len(digits) < bits // 4:
            continue
        short = parts[1].strip()
        long_name = (parts[2].strip() if len(parts) > 2 else "") or short
        rows.append((bits // 4, digits[:bits // 4], short, long_name))
    return rows


_C_ROW = re.compile(r'\{\s*\{\s*((?:0x[0-9A-Fa-f]{2}\s*,\s*){2,4}0x[0-9A-Fa-f]{2})\s*\}\s*,\s*'
                    r'"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}')


def parse_manuf_c(text: str) -> list[tuple[int, str, str, str]]:
    """Wireshark's generated ``epan/manuf-data.c`` (3, 4 and 5 byte rows = /24, /28, /36)."""
    nibbles_for = {3: 6, 4: 7, 5: 9}
    rows = []
    for match in _C_ROW.finditer(text):
        octets = [o.strip()[2:].upper() for o in match.group(1).split(",")]
        n = nibbles_for.get(len(octets))
        if n is None:
            continue
        short = match.group(2).replace('\\"', '"')
        long_name = match.group(3).replace('\\"', '"') or short
        rows.append((n, "".join(octets)[:n], short, long_name))
    return rows


def _write_rows(path: Path, rows: list[tuple[int, str, str, str]]) -> None:
    part = path.with_name(path.name + ".part")
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(part, "wt", encoding="utf-8", compresslevel=6) as fh:
        for n, prefix, short, long_name in rows:
            fh.write(f"{n}\t{prefix}\t{short.replace(chr(9), ' ')}\t{long_name.replace(chr(9), ' ')}\n")
    os.replace(part, path)


def _load_wireshark() -> dict[int, dict[str, str]]:
    global _ws, _short
    with _table_lock:
        if _ws is None:
            tables: dict[int, dict[str, str]] = {}
            short: dict[str, str] = {}
            path = _data_dir / WIRESHARK_FILE if _data_dir else None
            if path and path.exists():
                try:
                    with gzip.open(path, "rt", encoding="utf-8") as fh:
                        for line in fh:
                            n, prefix, sname, lname = line.rstrip("\n").split("\t")
                            tables.setdefault(int(n), {})[prefix] = lname
                            short.setdefault(lname, sname)
                except (OSError, ValueError, EOFError) as exc:
                    log.warning("ignoring a damaged %s: %s", path, exc)
                    tables, short = {}, {}
            _ws, _short = tables, short
        return _ws


def fetch_wireshark(fetch: Callable[[str], str] | None = None) -> list[tuple[int, str, str, str]]:
    """Download Wireshark's list (its web site, else the GitHub mirror of its source)."""
    if fetch is None:
        from .netfetch import open_url

        def fetch(url: str) -> str:
            with open_url(url, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
    errors = []
    for url in WIRESHARK_URLS:
        try:
            text = fetch(url)
        except Exception as exc:
            errors.append(f"{url}: {getattr(exc, 'reason', exc)}")
            continue
        rows = parse_manuf_c(text) if url.endswith(".c") else parse_manuf(text)
        if len(rows) >= MIN_ENTRIES:
            return rows
        errors.append(f"{url}: only {len(rows)} entries")
    raise OSError("could not download Wireshark's maker list (" + "; ".join(errors) + ")")


def refresh_wireshark(force: bool = False, fetch: Callable[[str], str] | None = None) -> dict[str, Any]:
    """Download Wireshark's list when there is none or it is a week old. Returns status()."""
    path = wireshark_path()
    if path is None:
        raise OSError("no data folder for the maker list")
    if not force and path.exists() and time.time() - path.stat().st_mtime < REFRESH_AGE:
        return status()
    rows = fetch_wireshark(fetch)
    _write_rows(path, rows)
    global _ws
    with _table_lock:
        _ws = None
    log.info("maker list: %d entries from Wireshark", len(rows))
    return status()


def status() -> dict[str, Any]:
    """Which maker list is in use, its size and when it was downloaded."""
    tables = _load_wireshark()
    path = wireshark_path()
    if tables and path and path.exists():
        return {"source": "Wireshark", "entries": sum(len(t) for t in tables.values()),
                "updated": path.stat().st_mtime}
    return {"source": "IEEE (bundled)", "entries": len(_load_table()), "updated": None}


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
    digits = mac.replace(":", "")
    tables = _load_wireshark()
    for n in (9, 7, 6):  # an MA-S / MA-M block names the actual maker, not the registry
        name = tables.get(n, {}).get(digits[:n])
        if name and not name.lower().startswith("ieee registration authority"):
            return name
    name = _load_table().get(digits[:6], "")
    return "" if name.lower().startswith("ieee registration authority") else name


LEGAL_WORDS = {
    "inc", "incorporated", "co", "company", "ltd", "limited", "llc", "lp", "llp", "corp", "corporation",
    "gmbh", "ag", "kg", "sa", "sas", "sarl", "srl", "spa", "bv", "nv", "oy", "ab", "as", "plc", "pty",
    "pte", "kk", "sdn", "bhd", "jsc", "ooo", "zao", "cv", "de", "mbh", "ug", "aps", "asa", "se",
}
GENERIC_WORDS = {
    "technology", "technologies", "tech", "electronics", "electronic", "electric", "electrical",
    "communication", "communications", "comm", "network", "networks", "networking", "digital",
    "industrial", "industries", "industry", "ind", "group", "international", "intl", "systems",
    "system", "holdings", "holding", "solutions", "solution", "products", "manufacturing",
    "manufacturer", "enterprise", "enterprises", "the", "of", "and", "science", "trading",
    "development", "information", "precision", "equipment", "devices", "device", "global",
    "worldwide", "america", "americas", "usa", "europe", "asia", "computer", "computers", "software",
}
PLACE_WORDS = {
    "shenzhen", "guangdong", "guangzhou", "hangzhou", "beijing", "shanghai", "dongguan", "zhejiang",
    "jiangsu", "xiamen", "fujian", "suzhou", "ningbo", "chengdu", "wuhan", "qingdao", "zhuhai",
    "foshan", "huizhou", "nanjing", "tianjin", "chongqing", "hefei", "jiangxi", "shandong", "sichuan",
    "hubei", "hunan", "anhui", "henan", "hebei", "liaoning", "taiwan", "taipei", "china", "chinese",
    "hongkong", "kunshan", "wuxi", "changzhou", "zhongshan", "jiaxing", "yantai", "dalian", "fuzhou",
}


def clean_maker(org: str) -> str:
    """'Shenzhen Bilian Electronic Co.,Ltd' -> 'Bilian', 'ESPRESSIF INC.' -> 'Espressif'."""
    text = re.sub(r"\([^)]*\)", " ", org or "")
    text = re.sub(r"\bhong kong\b", "hongkong", text, flags=re.I)
    text = re.sub(r"\bhui zhou\b", "huizhou", text, flags=re.I)
    words = [w for w in re.split(r"[\s,./;:&+]+", text) if w and w != "-"]
    kept = []
    for word in words:
        bare = re.sub(r"[^0-9A-Za-z]", "", word).lower()
        if not bare or bare in LEGAL_WORDS or bare in GENERIC_WORDS or bare in PLACE_WORDS:
            continue
        kept.append(word.strip("-'\""))
    out = []
    for word in kept[:2]:
        if word.isupper() and len(word) > 4:
            word = word.capitalize()  # SHENZHEN-style capitals, keeping acronyms (ZTE, TCL, AVM)
        out.append(word)
    name = " ".join(out)
    return name[:24].rstrip() if len(name) > 1 else ""


def brand_for_vendor(org: str) -> str:
    """Brand tag for a maker's registered name: the familiar name, else the cleaned-up one."""
    org = (org or "").strip()
    if not org:
        return ""
    for pattern, brand in _OUI_BRANDS:
        if pattern.search(org):
            return brand
    return clean_maker(org) or _short.get(org, "")


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

    def __init__(self, reader=read_arp_table, min_age: float = 2.0):
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


def warm_up() -> None:
    """Load the maker lists now (a background thread at startup), not on a scan's first result."""
    _load_table()
    _load_wireshark()


def mac_for(ip: str) -> str:
    """The MAC address of ``ip`` if it is on this machine's own network segment, else ''."""
    return _cache.get(ip)


def describe(mac: str) -> dict[str, str]:
    """{mac, mac_vendor} for a scan result or device."""
    mac = normalize_mac(mac)
    return {"mac": mac, "mac_vendor": vendor_for(mac) if mac else ""}
