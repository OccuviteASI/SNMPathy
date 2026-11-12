"""Layer-2 neighbour discovery (LLDP / CDP) for the topology map.

:func:`discover_neighbors` reads the LLDP-MIB and CISCO-CDP-MIB neighbour
tables of a device, :func:`apply_neighbors` stores them in ``links`` and
matches each neighbour against the devices SNMPathy already knows, and
:func:`resolve_links` retries that matching after new devices are added.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import defaultdict
from typing import Any

from ..db import Database
from . import mibs
from .client import SnmpClient, SnmpError, format_mac, index_of, oid_sort_key

log = logging.getLogger(__name__)

# Protocols written by discovery; anything else (e.g. 'manual') is never touched.
DISCOVERY_PROTOCOLS = ("lldp", "cdp")

# LLDP chassis-id / port-id subtypes (IEEE 802.1AB).
_CHASSIS_MAC = 4
_CHASSIS_NETWORK_ADDRESS = 5
_PORT_MAC = 3
_PORT_NETWORK_ADDRESS = 4

# lldpRemManAddrSubtype / IANA address families.
_AF_IPV4 = 1
_AF_IPV6 = 2

# CISCO-CDP-MIB CiscoNetworkProtocol values.
_CDP_ADDR_IP = 1
_CDP_ADDR_IPV6 = 20

_SERIAL_SUFFIX = re.compile(r"\s*\([^()]*\)\s*$")
_MAC_COLON = re.compile(r"^[0-9a-f]{2}([:\-]?)[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}$")
_MAC_DOTTED = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$")
_NULL_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

_FIELDS = ("local_port", "remote_name", "remote_port", "remote_ip", "remote_chassis", "remote_platform")


# -- value helpers ---------------------------------------------------------
async def _safe_walk(client: SnmpClient, oid: str) -> dict[str, Any]:
    try:
        return await client.walk(oid)
    except SnmpError as exc:
        log.debug("walk %s failed: %s", oid, exc)
        return {}


def _column(table: dict[str, Any], base: str) -> dict[str, Any]:
    return {index_of(oid, base): value for oid, value in table.items() if oid.startswith(base + ".")}


def _index_key(index: str) -> tuple[int, ...]:
    return oid_sort_key(index)


def _text(value: Any) -> str:
    """Printable text for a DisplayString-ish value; hex for binary octets."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            text = value.rstrip(b"\x00").decode("utf-8")
        except UnicodeDecodeError:
            return value.hex(":")
        if not all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return value.hex(":")
        value = text
    return str(value).replace("\x00", "").strip()


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        # decode_octets() turned printable octets into UTF-8 text; reverse it.
        return value.encode("utf-8")
    return b""


def _parse_ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return ""


def _ip_from_octets(raw: bytes) -> str:
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    return ""


def _parse_mac_text(text: str) -> str:
    """Normalise a textual MAC (aa:bb:.., aa-bb-.., aabb.ccdd.eeff, aabbcc..) or return ''."""
    s = (text or "").strip().lower()
    if not (_MAC_COLON.match(s) or _MAC_DOTTED.match(s)):
        return ""
    digits = re.sub(r"[^0-9a-f]", "", s)
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _mac(value: Any) -> str:
    """Format a MAC-address octet string as aa:bb:cc:dd:ee:ff."""
    if isinstance(value, str):
        parsed = _parse_mac_text(value)
        if parsed:
            return parsed
    raw = _to_bytes(value)
    if raw:
        return format_mac(raw)
    return _text(value)


def _network_address(value: Any) -> str:
    """Decode an LLDP networkAddress (IANA family octet + address) to an IP string."""
    if isinstance(value, str):
        ip = _parse_ip(value)
        if ip:
            return ip
    raw = _to_bytes(value)
    if len(raw) == 5 and raw[0] == _AF_IPV4:
        return _ip_from_octets(raw[1:])
    if len(raw) == 17 and raw[0] == _AF_IPV6:
        return _ip_from_octets(raw[1:])
    return _ip_from_octets(raw) or _text(value)


def _chassis_id(subtype: Any, value: Any) -> str:
    if subtype == _CHASSIS_MAC:
        return _mac(value)
    if subtype == _CHASSIS_NETWORK_ADDRESS:
        return _network_address(value)
    return _text(value)


def _port_id(subtype: Any, value: Any) -> str:
    if subtype == _PORT_MAC:
        return _mac(value)
    if subtype == _PORT_NETWORK_ADDRESS:
        return _network_address(value)
    return _text(value)


def _is_ip(text: str) -> bool:
    return bool(_parse_ip(text))


def _short_name(name: str) -> str:
    """Lower-cased host name with the domain part stripped (IP addresses kept whole)."""
    s = (name or "").strip().lower().rstrip(".")
    if not s or _is_ip(s):
        return s
    return s.split(".", 1)[0]


def _neighbor(protocol: str, if_index: int | None, local_port: str) -> dict[str, Any]:
    record: dict[str, Any] = {"protocol": protocol, "if_index": if_index}
    record.update({field: "" for field in _FIELDS})
    record["local_port"] = local_port
    return record


# -- discovery -------------------------------------------------------------
async def discover_neighbors(client: SnmpClient) -> list[dict[str, Any]]:
    """Return the LLDP and CDP neighbours a device reports.

    MIBs the agent does not implement (or walks that fail) simply contribute
    no records. A neighbour reported by both protocols on the same interface
    is returned once, as the LLDP record completed with CDP's fields.
    """
    if_names = _column(await _safe_walk(client, mibs.IF_NAME), mibs.IF_NAME)
    if_descrs = _column(await _safe_walk(client, mibs.IF_DESCR), mibs.IF_DESCR)
    iface_name: dict[int, str] = {}
    name_to_index: dict[str, int] = {}
    for column in (if_names, if_descrs):
        for idx, value in column.items():
            if not idx.isdigit():
                continue
            text = _text(value)
            if text:
                iface_name.setdefault(int(idx), text)
                name_to_index.setdefault(text.lower(), int(idx))
            else:
                iface_name.setdefault(int(idx), "")

    lldp = await _discover_lldp(client, iface_name, name_to_index)
    cdp = await _discover_cdp(client, iface_name)
    return _merge(lldp, cdp)


async def _discover_lldp(
    client: SnmpClient, iface_name: dict[int, str], name_to_index: dict[str, int]
) -> list[dict[str, Any]]:
    rem = await _safe_walk(client, mibs.LLDP_REM_TABLE)
    if not rem:
        return []
    loc = await _safe_walk(client, mibs.LLDP_LOC_PORT_TABLE)
    loc_subtypes = _column(loc, mibs.LLDP_LOC_PORT_ID_SUBTYPE)
    loc_ids = _column(loc, mibs.LLDP_LOC_PORT_ID)
    loc_descs = _column(loc, mibs.LLDP_LOC_PORT_DESC)

    def local_port(port_num: str) -> tuple[int | None, str]:
        port_id = _port_id(loc_subtypes.get(port_num), loc_ids.get(port_num))
        port_desc = _text(loc_descs.get(port_num))
        for candidate in (port_id, port_desc):
            if candidate and candidate.lower() in name_to_index:
                idx = name_to_index[candidate.lower()]
                return idx, iface_name.get(idx) or candidate
        if port_num.isdigit() and int(port_num) in iface_name:
            idx = int(port_num)
            return idx, iface_name[idx] or port_id or port_desc
        return None, port_id or port_desc or port_num

    columns = {
        base: _column(rem, base)
        for base in (
            mibs.LLDP_REM_CHASSIS_ID_SUBTYPE, mibs.LLDP_REM_CHASSIS_ID,
            mibs.LLDP_REM_PORT_ID_SUBTYPE, mibs.LLDP_REM_PORT_ID, mibs.LLDP_REM_PORT_DESC,
            mibs.LLDP_REM_SYS_NAME, mibs.LLDP_REM_SYS_DESC,
        )
    }
    man_addrs = _lldp_management_addresses(await _safe_walk(client, mibs.LLDP_REM_MAN_ADDR_TABLE))

    indexes = (
        set(columns[mibs.LLDP_REM_CHASSIS_ID])
        | set(columns[mibs.LLDP_REM_PORT_ID])
        | set(columns[mibs.LLDP_REM_SYS_NAME])
    )
    neighbors = []
    for idx in sorted(indexes, key=_index_key):
        parts = idx.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            continue
        _time_mark, port_num, rem_index = parts
        if_index, port_name = local_port(port_num)
        record = _neighbor("lldp", if_index, port_name)

        chassis = _chassis_id(
            columns[mibs.LLDP_REM_CHASSIS_ID_SUBTYPE].get(idx), columns[mibs.LLDP_REM_CHASSIS_ID].get(idx)
        )
        port_id = _port_id(columns[mibs.LLDP_REM_PORT_ID_SUBTYPE].get(idx), columns[mibs.LLDP_REM_PORT_ID].get(idx))
        sys_desc = _text(columns[mibs.LLDP_REM_SYS_DESC].get(idx))
        record.update(
            remote_chassis=chassis,
            remote_name=_text(columns[mibs.LLDP_REM_SYS_NAME].get(idx)) or chassis,
            remote_port=port_id or _text(columns[mibs.LLDP_REM_PORT_DESC].get(idx)),
            remote_platform=sys_desc.splitlines()[0].strip() if sys_desc else "",
        )
        ip = man_addrs.get((port_num, rem_index), "")
        if not ip and columns[mibs.LLDP_REM_CHASSIS_ID_SUBTYPE].get(idx) == _CHASSIS_NETWORK_ADDRESS:
            ip = _parse_ip(chassis)
        record["remote_ip"] = ip
        neighbors.append(record)
    return neighbors


def _lldp_management_addresses(table: dict[str, Any]) -> dict[tuple[str, str], str]:
    """Map (localPortNum, remIndex) -> management IP, preferring IPv4."""
    found: dict[tuple[str, str], dict[int, str]] = defaultdict(dict)
    base = mibs.LLDP_REM_MAN_ADDR_TABLE
    for oid in sorted(table, key=oid_sort_key):
        if not oid.startswith(base + "."):
            continue
        parts = index_of(oid, base).split(".")
        # column.timeMark.localPortNum.remIndex.addrSubtype.addrLen.addr...
        if len(parts) < 6 or not all(p.isdigit() for p in parts):
            continue
        key = (parts[2], parts[3])
        subtype = int(parts[4])
        rest = [int(p) for p in parts[5:]]
        octets = rest[1:] if rest[0] == len(rest) - 1 else rest
        if any(o > 255 for o in octets):
            continue
        if subtype == _AF_IPV4 and len(octets) == 4:
            found[key].setdefault(4, _ip_from_octets(bytes(octets)))
        elif subtype == _AF_IPV6 and len(octets) == 16:
            found[key].setdefault(6, _ip_from_octets(bytes(octets)))
    return {key: addrs.get(4) or addrs.get(6, "") for key, addrs in found.items()}


async def _discover_cdp(client: SnmpClient, iface_name: dict[int, str]) -> list[dict[str, Any]]:
    table = await _safe_walk(client, mibs.CDP_CACHE_TABLE)
    if not table:
        return []
    columns = {
        base: _column(table, base)
        for base in (
            mibs.CDP_CACHE_ADDRESS_TYPE, mibs.CDP_CACHE_ADDRESS, mibs.CDP_CACHE_DEVICE_ID,
            mibs.CDP_CACHE_DEVICE_PORT, mibs.CDP_CACHE_PLATFORM,
        )
    }
    indexes = set(columns[mibs.CDP_CACHE_DEVICE_ID]) | set(columns[mibs.CDP_CACHE_DEVICE_PORT])
    neighbors = []
    for idx in sorted(indexes, key=_index_key):
        parts = idx.split(".")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            continue
        if_index = int(parts[0])
        record = _neighbor("cdp", if_index, iface_name.get(if_index, ""))
        device_id = _SERIAL_SUFFIX.sub("", _text(columns[mibs.CDP_CACHE_DEVICE_ID].get(idx)))
        record.update(
            remote_name=device_id,
            remote_port=_text(columns[mibs.CDP_CACHE_DEVICE_PORT].get(idx)),
            remote_platform=_text(columns[mibs.CDP_CACHE_PLATFORM].get(idx)),
            remote_ip=_cdp_address(
                columns[mibs.CDP_CACHE_ADDRESS_TYPE].get(idx), columns[mibs.CDP_CACHE_ADDRESS].get(idx)
            ),
        )
        neighbors.append(record)
    return neighbors


def _cdp_address(addr_type: Any, value: Any) -> str:
    if value is None or addr_type not in (_CDP_ADDR_IP, _CDP_ADDR_IPV6, None):
        return ""
    if isinstance(value, str):
        ip = _parse_ip(value)
        if ip:
            return ip
    raw = _to_bytes(value)
    if addr_type == _CDP_ADDR_IPV6:
        return _ip_from_octets(raw) if len(raw) == 16 else ""
    return _ip_from_octets(raw) if len(raw) == 4 else ""


def _merge(lldp: list[dict[str, Any]], cdp: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop CDP records LLDP already reports, filling LLDP's empty fields from them."""
    by_key: dict[tuple[int | None, str], dict[str, Any]] = {}
    for record in lldp:
        if record["remote_name"]:
            by_key.setdefault((record["if_index"], _short_name(record["remote_name"])), record)
    result = list(lldp)
    for record in cdp:
        match = by_key.get((record["if_index"], _short_name(record["remote_name"]))) if record["remote_name"] else None
        if match is None:
            result.append(record)
            continue
        for key, value in record.items():
            if key != "protocol" and match.get(key) in ("", None) and value not in ("", None):
                match[key] = value
    return result


# -- persistence -----------------------------------------------------------
class _Resolver:
    """Matches neighbour records against the devices / interfaces in the database."""

    def __init__(self, db: Database):
        self.db = db
        self.by_host: dict[str, set[int]] = defaultdict(set)
        self.by_name: dict[str, set[int]] = defaultdict(set)
        self.by_short: dict[str, set[int]] = defaultdict(set)
        self.by_mac: dict[str, set[int]] = defaultdict(set)
        self._ifaces: dict[int, list[dict[str, Any]]] = {}
        for dev in db.query("SELECT id, name, hostname, sys_name FROM devices"):
            host = (dev.get("hostname") or "").strip().lower()
            if host:
                self.by_host[host].add(dev["id"])
                ip = _parse_ip(host)
                if ip:
                    self.by_host[ip].add(dev["id"])
            for field in ("sys_name", "name", "hostname"):
                value = (dev.get(field) or "").strip().lower().rstrip(".")
                if value:
                    self.by_name[value].add(dev["id"])
                    self.by_short[_short_name(value)].add(dev["id"])
        for row in db.query("SELECT device_id, mac FROM interfaces WHERE mac != ''"):
            mac = _parse_mac_text(row["mac"])
            if mac and mac not in _NULL_MACS:
                self.by_mac[mac].add(row["device_id"])

    @staticmethod
    def _pick(ids: set[int] | None, exclude: int | None) -> int | None:
        candidates = (ids or set()) - {exclude}
        return next(iter(candidates)) if len(candidates) == 1 else None

    def device_for(self, link: dict[str, Any], exclude: int | None = None) -> int | None:
        ip = (link.get("remote_ip") or "").strip().lower()
        if ip:
            found = self._pick(self.by_host.get(_parse_ip(ip) or ip), exclude)
            if found:
                return found
        name = (link.get("remote_name") or "").strip().lower().rstrip(".")
        if name:
            found = self._pick(self.by_name.get(name), exclude) or self._pick(
                self.by_short.get(_short_name(name)), exclude
            )
            if found:
                return found
        for value in (link.get("remote_chassis"), link.get("remote_name")):
            mac = _parse_mac_text(value or "")
            if mac:
                found = self._pick(self.by_mac.get(mac), exclude)
                if found:
                    return found
        return None

    def if_index_for(self, device_id: int | None, remote_port: str) -> int | None:
        port = (remote_port or "").strip().lower()
        if not device_id or not port:
            return None
        if device_id not in self._ifaces:
            self._ifaces[device_id] = self.db.query(
                "SELECT if_index, name, descr, alias, mac FROM interfaces WHERE device_id = ? ORDER BY if_index",
                (device_id,),
            )
        ifaces = self._ifaces[device_id]
        for field in ("name", "descr", "alias"):
            for iface in ifaces:
                if (iface.get(field) or "").strip().lower() == port:
                    return iface["if_index"]
        mac = _parse_mac_text(port)
        if mac:
            for iface in ifaces:
                if _parse_mac_text(iface.get("mac") or "") == mac:
                    return iface["if_index"]
        if port.isdigit():
            for iface in ifaces:
                if iface["if_index"] == int(port):
                    return iface["if_index"]
        return None


def _link_row(neighbor: dict[str, Any]) -> dict[str, Any] | None:
    protocol = str(neighbor.get("protocol") or "lldp").strip().lower()
    if protocol not in DISCOVERY_PROTOCOLS:
        return None
    row: dict[str, Any] = {"protocol": protocol}
    for field in _FIELDS:
        row[field] = str(neighbor.get(field) or "").strip()
    try:
        row["if_index"] = int(neighbor["if_index"]) if neighbor.get("if_index") is not None else None
    except (TypeError, ValueError):
        row["if_index"] = None
    if not (row["remote_name"] or row["remote_chassis"] or row["remote_ip"] or row["remote_port"]):
        return None
    return row


def apply_neighbors(
    db: Database, device_id: int, neighbors: list[dict[str, Any]], now: float | None = None
) -> dict[str, int]:
    """Store the neighbours discovered on ``device_id`` in ``links``.

    Existing links keep their ``first_seen``; LLDP/CDP links of this device
    that were not reported this time are removed (manual links are left
    alone). Returns ``{"links": n, "resolved": m}`` where ``m`` counts the
    links whose remote end is a known device.
    """
    now = now or time.time()
    resolver = _Resolver(db)
    seen: dict[int, int | None] = {}
    with db.transaction():
        for neighbor in neighbors:
            row = _link_row(neighbor)
            if row is None:
                continue
            remote_id = resolver.device_for(row, exclude=device_id)
            remote_if = resolver.if_index_for(remote_id, row["remote_port"]) if remote_id else None
            params = {
                **row, "device_id": device_id, "remote_device_id": remote_id,
                "remote_if_index": remote_if, "first_seen": now, "last_seen": now,
            }
            db.execute(
                """
                INSERT INTO links (device_id, if_index, local_port, remote_device_id, remote_if_index,
                                   remote_name, remote_port, remote_ip, remote_chassis, remote_platform,
                                   protocol, first_seen, last_seen)
                VALUES (:device_id, :if_index, :local_port, :remote_device_id, :remote_if_index,
                        :remote_name, :remote_port, :remote_ip, :remote_chassis, :remote_platform,
                        :protocol, :first_seen, :last_seen)
                ON CONFLICT(device_id, protocol, local_port, remote_name, remote_port) DO UPDATE SET
                    if_index = excluded.if_index, remote_device_id = excluded.remote_device_id,
                    remote_if_index = excluded.remote_if_index, remote_ip = excluded.remote_ip,
                    remote_chassis = excluded.remote_chassis, remote_platform = excluded.remote_platform,
                    last_seen = excluded.last_seen
                """,
                params,
            )
            link_id = db.scalar(
                "SELECT id FROM links WHERE device_id = ? AND protocol = ? AND local_port = ?"
                " AND remote_name = ? AND remote_port = ?",
                (device_id, row["protocol"], row["local_port"], row["remote_name"], row["remote_port"]),
            )
            seen[link_id] = remote_id

        protocols = ",".join("?" for _ in DISCOVERY_PROTOCOLS)
        sql = f"DELETE FROM links WHERE device_id = ? AND protocol IN ({protocols})"
        if seen:  # (``NOT IN (NULL)`` would match nothing, so omit the clause when empty)
            sql += f" AND id NOT IN ({','.join('?' for _ in seen)})"
        db.execute(sql, [device_id, *DISCOVERY_PROTOCOLS, *seen])
    return {"links": len(seen), "resolved": sum(1 for remote_id in seen.values() if remote_id)}


def resolve_links(db: Database) -> int:
    """Match links with an unknown remote end against the current devices.

    Call after devices are added. Returns how many links got a remote device.
    """
    rows = db.query(
        "SELECT id, device_id, remote_name, remote_port, remote_ip, remote_chassis"
        " FROM links WHERE remote_device_id IS NULL"
    )
    if not rows:
        return 0
    resolver = _Resolver(db)
    resolved = 0
    with db.transaction():
        for row in rows:
            remote_id = resolver.device_for(row, exclude=row["device_id"])
            if not remote_id:
                continue
            db.update("links", row["id"], {
                "remote_device_id": remote_id,
                "remote_if_index": resolver.if_index_for(remote_id, row["remote_port"]),
            })
            resolved += 1
    return resolved
