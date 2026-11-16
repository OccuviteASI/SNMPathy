"""IP -> MAC from a router's ARP table, read over SNMP.

SNMPathy's own ARP table only lists devices on the computer's own subnet. The router between
subnets / VLANs knows them all, and publishes its table in the IP-MIB:

* ``ipNetToPhysicalPhysAddress`` (1.3.6.1.2.1.4.35.1.4, RFC 4293), indexed
  ``ifIndex.addressType.length.a.b.c.d`` - read first, and
* ``ipNetToMediaPhysAddress`` (1.3.6.1.2.1.4.22.1.2, the older RFC 1213 table), indexed
  ``ifIndex.a.b.c.d`` - used when the first is empty.

UniFi gateways (net-snmp), pfSense / OPNsense, MikroTik, EdgeRouters and Cisco routers answer
at least one of them. A device is treated as a router when ``ipForwarding.0`` is 1.
"""

from __future__ import annotations

import logging

from .client import SnmpClient, SnmpError, SnmpValue, index_of

log = logging.getLogger(__name__)

IP_FORWARDING = "1.3.6.1.2.1.4.1.0"
IP_NET_TO_PHYSICAL = "1.3.6.1.2.1.4.35.1.4"
IP_NET_TO_MEDIA = "1.3.6.1.2.1.4.22.1.2"


def mac_text(value: SnmpValue) -> str:
    """A PhysAddress value (6 raw bytes, sometimes decoded to text) as 'AA:BB:CC:DD:EE:FF', else ''."""
    from ..macvendor import normalize_mac

    raw: bytes | None = None
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str) and value:
        if len(value) == 6:
            raw = value.encode("latin-1", errors="ignore")
        else:
            return _usable(normalize_mac(value))  # some agents return "aa:bb:cc:dd:ee:ff" text
    if raw is None or len(raw) != 6:
        return ""
    return _usable(":".join(f"{b:02X}" for b in raw))


def _usable(mac: str) -> str:
    if not mac or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") or int(mac[:2], 16) & 0x01:
        return ""  # empty / broadcast / multicast entries
    return mac


def _ipv4(parts: list[str]) -> str:
    if len(parts) != 4 or not all(p.isdigit() and int(p) < 256 for p in parts):
        return ""
    return ".".join(str(int(p)) for p in parts)


def parse_physical(table: dict[str, SnmpValue]) -> dict[str, str]:
    """ipNetToPhysicalPhysAddress rows -> {ip: mac} (IPv4 only)."""
    out: dict[str, str] = {}
    for oid, value in table.items():
        parts = index_of(oid, IP_NET_TO_PHYSICAL).split(".")
        if len(parts) < 6 or parts[1] != "1":  # 1 = ipv4
            continue
        rest = parts[2:]
        if len(rest) == 5 and rest[0] == "4":  # length-prefixed address (the usual form)
            rest = rest[1:]
        ip, mac = _ipv4(rest), mac_text(value)
        if ip and mac:
            out[ip] = mac
    return out


def parse_media(table: dict[str, SnmpValue]) -> dict[str, str]:
    """ipNetToMediaPhysAddress rows -> {ip: mac}."""
    out: dict[str, str] = {}
    for oid, value in table.items():
        parts = index_of(oid, IP_NET_TO_MEDIA).split(".")
        ip, mac = _ipv4(parts[1:]) if len(parts) == 5 else "", mac_text(value)
        if ip and mac:
            out[ip] = mac
    return out


async def is_router(client: SnmpClient) -> bool:
    try:
        values = await client.get([IP_FORWARDING])
    except SnmpError:
        return False
    return values.get(IP_FORWARDING) == 1


async def read_arp(client: SnmpClient) -> dict[str, str]:
    """The device's IPv4 ARP table, {ip: mac}."""
    table: dict[str, str] = {}
    try:
        table = parse_physical(await client.walk(IP_NET_TO_PHYSICAL))
    except SnmpError as exc:
        log.debug("ipNetToPhysicalTable walk failed: %s", exc)
    if not table:
        table = parse_media(await client.walk(IP_NET_TO_MEDIA))
    return table
