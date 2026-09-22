"""SNMP device discovery.

Discovery reads the system group, walks the interface / host-resources /
UCD tables and turns what it finds into rows in ``interfaces`` and
``metrics``. The poller then only issues GETs for the OIDs recorded there.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ..db import Database
from . import mibs
from .client import SnmpClient, SnmpError, as_text, format_mac, index_of

log = logging.getLogger(__name__)


@dataclass
class MetricSpec:
    key: str
    instance: str = ""
    label: str = ""
    kind: str = "gauge"       # gauge | counter | ratio | ratio_free | derived
    oid: str = ""
    oid2: str = ""
    unit: str = ""
    scale: float = 1.0
    counter_bits: int = 32


@dataclass
class DiscoveryResult:
    system: dict[str, Any] = field(default_factory=dict)
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    metrics: list[MetricSpec] = field(default_factory=list)


async def _safe_walk(client: SnmpClient, oid: str) -> dict[str, Any]:
    try:
        return await client.walk(oid)
    except SnmpError as exc:
        log.debug("walk %s failed: %s", oid, exc)
        return {}


def _column(table: dict[str, Any], base: str) -> dict[str, Any]:
    return {index_of(oid, base): value for oid, value in table.items() if oid.startswith(base + ".")}


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


async def discover(client: SnmpClient) -> DiscoveryResult:
    """Query a device and describe everything SNMPathy should poll on it.

    Raises :class:`SnmpError` if the device does not answer at all.
    """
    result = DiscoveryResult()
    system = await client.get(mibs.SYSTEM_OIDS)
    if all(v is None for v in system.values()):
        raise SnmpError("device returned no system information")
    sys_object_id = as_text(system.get(mibs.SYS_OBJECT_ID))
    uptime = system.get(mibs.SYS_UPTIME)
    result.system = {
        "sys_descr": as_text(system.get(mibs.SYS_DESCR)),
        "sys_object_id": sys_object_id,
        "sys_name": as_text(system.get(mibs.SYS_NAME)),
        "sys_location": as_text(system.get(mibs.SYS_LOCATION)),
        "sys_contact": as_text(system.get(mibs.SYS_CONTACT)),
        "sys_uptime": (uptime / 100.0) if isinstance(uptime, int) else None,
        "vendor": mibs.vendor_from_sysobjectid(sys_object_id),
    }
    metrics = result.metrics
    metrics.append(MetricSpec("sys.uptime", kind="gauge", oid=mibs.SYS_UPTIME, unit="s", scale=0.01))
    metrics.append(MetricSpec("snmp.response_ms", kind="derived", unit="ms"))

    await _discover_interfaces(client, result)
    await _discover_host_resources(client, result)
    await _discover_ucd(client, result)
    return result


async def _discover_interfaces(client: SnmpClient, result: DiscoveryResult) -> None:
    columns = {}
    for base in (
        mibs.IF_DESCR, mibs.IF_TYPE, mibs.IF_MTU, mibs.IF_SPEED, mibs.IF_PHYS_ADDRESS,
        mibs.IF_ADMIN_STATUS, mibs.IF_OPER_STATUS, mibs.IF_LAST_CHANGE,
        mibs.IF_NAME, mibs.IF_ALIAS, mibs.IF_HIGH_SPEED, mibs.IF_HC_IN_OCTETS,
    ):
        columns[base] = _column(await _safe_walk(client, base), base)

    indexes = sorted(
        set(columns[mibs.IF_DESCR]) | set(columns[mibs.IF_NAME]),
        key=lambda i: int(i) if i.isdigit() else 0,
    )
    for idx in indexes:
        if not idx.isdigit():
            continue
        descr = as_text(columns[mibs.IF_DESCR].get(idx))
        name = as_text(columns[mibs.IF_NAME].get(idx)) or descr or f"if{idx}"
        high_speed = columns[mibs.IF_HIGH_SPEED].get(idx)
        speed = columns[mibs.IF_SPEED].get(idx)
        speed_bps: float | None = None
        if isinstance(high_speed, int) and high_speed > 0:
            speed_bps = high_speed * 1_000_000.0
        elif isinstance(speed, int) and speed > 0:
            speed_bps = float(speed)
        last_change = columns[mibs.IF_LAST_CHANGE].get(idx)
        iface = {
            "if_index": int(idx),
            "name": name,
            "descr": descr,
            "alias": as_text(columns[mibs.IF_ALIAS].get(idx)),
            "if_type": columns[mibs.IF_TYPE].get(idx),
            "speed": speed_bps,
            "mtu": columns[mibs.IF_MTU].get(idx),
            "mac": format_mac(columns[mibs.IF_PHYS_ADDRESS].get(idx)),
            "admin_status": columns[mibs.IF_ADMIN_STATUS].get(idx),
            "oper_status": columns[mibs.IF_OPER_STATUS].get(idx),
            "last_change": (last_change / 100.0) if isinstance(last_change, int) else None,
        }
        result.interfaces.append(iface)
        if iface["if_type"] in mibs.IF_TYPES_SKIP_METRICS:
            continue
        label = name if not iface["alias"] else f"{name} ({iface['alias']})"
        hc = idx in columns[mibs.IF_HC_IN_OCTETS]
        in_oid = f"{mibs.IF_HC_IN_OCTETS if hc else mibs.IF_IN_OCTETS}.{idx}"
        out_oid = f"{mibs.IF_HC_OUT_OCTETS if hc else mibs.IF_OUT_OCTETS}.{idx}"
        bits = 64 if hc else 32
        m = result.metrics
        m.append(MetricSpec("if.in_bps", idx, label, "counter", in_oid, unit="bps", scale=8, counter_bits=bits))
        m.append(MetricSpec("if.out_bps", idx, label, "counter", out_oid, unit="bps", scale=8, counter_bits=bits))
        m.append(MetricSpec("if.in_errors", idx, label, "counter", f"{mibs.IF_IN_ERRORS}.{idx}", unit="/s"))
        m.append(MetricSpec("if.out_errors", idx, label, "counter", f"{mibs.IF_OUT_ERRORS}.{idx}", unit="/s"))
        m.append(MetricSpec("if.in_discards", idx, label, "counter", f"{mibs.IF_IN_DISCARDS}.{idx}", unit="/s"))
        m.append(MetricSpec("if.out_discards", idx, label, "counter", f"{mibs.IF_OUT_DISCARDS}.{idx}", unit="/s"))
        m.append(MetricSpec("if.oper_status", idx, label, "gauge", f"{mibs.IF_OPER_STATUS}.{idx}"))
        if speed_bps:
            m.append(MetricSpec("if.in_util", idx, label, "derived", unit="%"))
            m.append(MetricSpec("if.out_util", idx, label, "derived", unit="%"))


async def _discover_host_resources(client: SnmpClient, result: DiscoveryResult) -> None:
    cpus = _column(await _safe_walk(client, mibs.HR_PROCESSOR_LOAD), mibs.HR_PROCESSOR_LOAD)
    for n, idx in enumerate(sorted(cpus, key=lambda i: int(i) if i.isdigit() else 0)):
        if cpus[idx] is None:
            continue
        result.metrics.append(
            MetricSpec("cpu.load", idx, f"CPU {n}", "gauge", f"{mibs.HR_PROCESSOR_LOAD}.{idx}", unit="%")
        )
    if cpus:
        result.metrics.append(MetricSpec("cpu.avg", kind="derived", unit="%"))

    table = await _safe_walk(client, "1.3.6.1.2.1.25.2.3.1")
    types = _column(table, mibs.HR_STORAGE_TYPE)
    descrs = _column(table, mibs.HR_STORAGE_DESCR)
    allocs = _column(table, mibs.HR_STORAGE_ALLOC)
    sizes = _column(table, mibs.HR_STORAGE_SIZE)
    for idx, stype in types.items():
        size = sizes.get(idx)
        if not isinstance(size, int) or size <= 0:
            continue
        descr = as_text(descrs.get(idx)) or f"storage {idx}"
        alloc = allocs.get(idx) if isinstance(allocs.get(idx), int) else 1
        used_oid = f"{mibs.HR_STORAGE_USED}.{idx}"
        size_oid = f"{mibs.HR_STORAGE_SIZE}.{idx}"
        stype = as_text(stype)
        if stype == mibs.HR_STORAGE_RAM:
            result.metrics.append(MetricSpec("hr.mem.used_pct", idx, descr, "ratio", used_oid, size_oid, "%"))
        elif stype == mibs.HR_STORAGE_FIXED_DISK:
            result.metrics.append(MetricSpec("storage.used_pct", idx, descr, "ratio", used_oid, size_oid, "%"))
            result.metrics.append(
                MetricSpec("storage.used_bytes", idx, descr, "gauge", used_oid, unit="B", scale=float(alloc))
            )


async def _discover_ucd(client: SnmpClient, result: DiscoveryResult) -> None:
    try:
        values = await client.get([
            mibs.UCD_LOAD_1, mibs.UCD_LOAD_5, mibs.UCD_LOAD_15,
            mibs.UCD_MEM_TOTAL_REAL, mibs.UCD_MEM_AVAIL_REAL,
        ])
    except SnmpError:
        return
    for key, oid in (("load.1", mibs.UCD_LOAD_1), ("load.5", mibs.UCD_LOAD_5), ("load.15", mibs.UCD_LOAD_15)):
        if _float(values.get(oid)) is not None:
            result.metrics.append(MetricSpec(key, kind="gauge", oid=oid))
    if isinstance(values.get(mibs.UCD_MEM_TOTAL_REAL), int) and isinstance(values.get(mibs.UCD_MEM_AVAIL_REAL), int):
        result.metrics.append(
            MetricSpec("mem.used_pct", label="Real memory", kind="ratio_free",
                       oid=mibs.UCD_MEM_AVAIL_REAL, oid2=mibs.UCD_MEM_TOTAL_REAL, unit="%")
        )


def apply_discovery(db: Database, device_id: int, result: DiscoveryResult, now: float | None = None) -> dict[str, int]:
    """Persist a :class:`DiscoveryResult` for ``device_id``."""
    now = now or time.time()
    specs = list(result.metrics)
    # Prefer the UCD view of memory (excludes buffers/cache); fall back to hrStorage RAM.
    if not any(s.key == "mem.used_pct" for s in specs):
        for s in specs:
            if s.key == "hr.mem.used_pct":
                s.key = "mem.used_pct"
                break
    specs = [s for s in specs if s.key != "hr.mem.used_pct"]

    with db.transaction():
        values = dict(result.system)
        values.update(last_discovered=now, updated_at=now)
        db.update("devices", device_id, values)

        seen_ifaces = []
        for iface in result.interfaces:
            seen_ifaces.append(iface["if_index"])
            db.execute(
                """
                INSERT INTO interfaces (device_id, if_index, name, descr, alias, if_type, speed, mtu, mac,
                                        admin_status, oper_status, last_change, updated_at)
                VALUES (:device_id, :if_index, :name, :descr, :alias, :if_type, :speed, :mtu, :mac,
                        :admin_status, :oper_status, :last_change, :updated_at)
                ON CONFLICT(device_id, if_index) DO UPDATE SET
                    name = excluded.name, descr = excluded.descr, alias = excluded.alias,
                    if_type = excluded.if_type, speed = excluded.speed, mtu = excluded.mtu,
                    mac = excluded.mac, admin_status = excluded.admin_status,
                    oper_status = excluded.oper_status, last_change = excluded.last_change,
                    updated_at = excluded.updated_at
                """,
                {**iface, "device_id": device_id, "updated_at": now},
            )
        if seen_ifaces:
            marks = ",".join("?" for _ in seen_ifaces)
            db.execute(
                f"DELETE FROM interfaces WHERE device_id = ? AND if_index NOT IN ({marks})",
                [device_id, *seen_ifaces],
            )
        else:
            db.execute("DELETE FROM interfaces WHERE device_id = ?", (device_id,))

        seen_metrics: list[int] = []
        for spec in specs:
            existing = db.one(
                "SELECT id, oid FROM metrics WHERE device_id = ? AND key = ? AND instance = ?",
                (device_id, spec.key, spec.instance),
            )
            fields = {
                "label": spec.label, "kind": spec.kind, "oid": spec.oid, "oid2": spec.oid2,
                "unit": spec.unit, "scale": spec.scale, "counter_bits": spec.counter_bits, "enabled": 1,
            }
            if existing:
                if existing["oid"] != spec.oid:
                    fields.update(last_raw=None, last_raw_ts=None)
                db.update("metrics", existing["id"], fields)
                seen_metrics.append(existing["id"])
            else:
                seen_metrics.append(
                    db.insert("metrics", {"device_id": device_id, "key": spec.key, "instance": spec.instance, **fields})
                )
        # Series that vanished (e.g. a removed line card) stop being polled but keep their history.
        marks = ",".join("?" for _ in seen_metrics) or "NULL"
        db.execute(
            f"UPDATE metrics SET enabled = 0 WHERE device_id = ? AND custom = 0 AND id NOT IN ({marks})",
            [device_id, *seen_metrics],
        )
    return {"interfaces": len(result.interfaces), "metrics": len(specs)}
