"""SNMP metric polling: turns raw OID values into stored samples."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ..db import Database
from . import mibs
from .client import SnmpClient, SnmpError

log = logging.getLogger(__name__)

COUNTER32_MAX = 2**32
COUNTER64_MAX = 2**64
MIN_RATE_WINDOW = 15.0  # seconds


@dataclass
class PollResult:
    ok: bool
    samples: int = 0
    duration_ms: float = 0.0
    error: str = ""
    events: list[str] = field(default_factory=list)


def to_number(value: Any) -> float | None:
    """Coerce an SNMP value (int, numeric string such as laLoad "0.42") to float."""
    if value is None or isinstance(value, bytes):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def counter_delta(prev: float, cur: float, bits: int) -> float | None:
    """Difference between two counter readings, accounting for wraparound.

    Returns ``None`` when the counter appears to have been reset (device
    reboot, counter cleared) rather than wrapped.
    """
    if cur >= prev:
        return cur - prev
    if bits == 32 and prev < COUNTER32_MAX:
        wrapped = COUNTER32_MAX - prev + cur
        # A genuine wrap only moves the counter forward by less than half its range.
        if wrapped < COUNTER32_MAX / 2:
            return wrapped
    if bits == 64 and prev < COUNTER64_MAX:
        wrapped = COUNTER64_MAX - prev + cur
        if wrapped < COUNTER64_MAX / 2:
            return wrapped
    return None


def compute_value(metric: dict[str, Any], raw: Any, raw2: Any, now: float, rebooted: bool) -> tuple[float | None, float | None]:
    """Return ``(value, new_last_raw)`` for a metric given freshly polled raw values."""
    kind = metric["kind"]
    scale = metric["scale"] or 1.0
    num = to_number(raw)
    if kind == "gauge":
        return (None if num is None else num * scale), num
    if kind == "counter":
        if num is None:
            return None, None
        prev = metric.get("last_raw")
        prev_ts = metric.get("last_raw_ts")
        if prev is None or prev_ts is None or rebooted:
            return None, num
        dt = now - prev_ts
        if dt <= 0:
            return None, num
        delta = counter_delta(float(prev), num, int(metric.get("counter_bits") or 32))
        if delta is None:
            return None, num
        if delta == 0 and dt < MIN_RATE_WINDOW:
            # Agents cache counters for a few seconds (net-snmp: ~5 s). An unchanged
            # value right after the previous poll is not a real zero rate: keep the
            # old baseline so the next poll measures over a longer window.
            return None, None
        return delta / dt * scale, num
    if kind in {"ratio", "ratio_free"}:
        den = to_number(raw2)
        if num is None or not den:
            return None, num
        ratio = num / den
        if kind == "ratio_free":
            ratio = 1.0 - ratio
        return max(0.0, min(100.0, ratio * 100.0)), num
    return None, num


async def poll_device(db: Database, client: SnmpClient, device: dict[str, Any], now: float | None = None) -> PollResult:
    """Poll every enabled metric of ``device`` and persist the results."""
    now = now or time.time()
    metrics = db.query(
        "SELECT * FROM metrics WHERE device_id = ? AND enabled = 1", (device["id"],)
    )
    oids: set[str] = {mibs.SYS_UPTIME}
    for m in metrics:
        if m["oid"]:
            oids.add(m["oid"])
        if m["oid2"]:
            oids.add(m["oid2"])

    started = time.perf_counter()
    try:
        values = await client.get(sorted(oids))
    except SnmpError as exc:
        duration = (time.perf_counter() - started) * 1000
        _mark_failure(db, device, str(exc), now)
        return PollResult(ok=False, duration_ms=duration, error=str(exc))
    duration = (time.perf_counter() - started) * 1000
    if values.get(mibs.SYS_UPTIME) is None and all(v is None for v in values.values()):
        _mark_failure(db, device, "device returned no data", now)
        return PollResult(ok=False, duration_ms=duration, error="device returned no data")

    result = PollResult(ok=True, duration_ms=duration)
    uptime_ticks = values.get(mibs.SYS_UPTIME)
    uptime = uptime_ticks / 100.0 if isinstance(uptime_ticks, int) else None
    prev_uptime = device.get("sys_uptime")
    prev_polled = device.get("last_polled")
    rebooted = False
    if uptime is not None and prev_uptime is not None and prev_polled:
        # sysUpTime going backwards (allowing for the 497-day TimeTicks wrap) means a restart.
        if uptime + 60 < prev_uptime and prev_uptime < 42_900_000:
            rebooted = True
            result.events.append(f"{device['name']} restarted (uptime reset to {int(uptime)}s)")

    samples: list[tuple[int, int, float]] = []
    updates: list[tuple[Any, ...]] = []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    computed: dict[int, float] = {}
    ifaces = {
        str(i["if_index"]): i
        for i in db.query("SELECT * FROM interfaces WHERE device_id = ?", (device["id"],))
    }
    ts = int(now)

    for m in metrics:
        by_key[(m["key"], m["instance"])] = m
        if m["kind"] == "derived":
            continue
        raw = values.get(m["oid"]) if m["oid"] else None
        raw2 = values.get(m["oid2"]) if m["oid2"] else None
        value, new_raw = compute_value(m, raw, raw2, now, rebooted)
        if value is not None and m["key"] in {"if.in_bps", "if.out_bps"}:
            speed = (ifaces.get(m["instance"]) or {}).get("speed")
            # Discard impossible spikes (e.g. counter glitches) above twice line rate.
            if speed and value > speed * 2:
                value = None
        if value is not None:
            computed[m["id"]] = value
        text = raw if isinstance(raw, str) and to_number(raw) is None else None
        updates.append((
            new_raw if new_raw is not None else m["last_raw"],
            now if new_raw is not None else m["last_raw_ts"],
            value if value is not None else m["last_value"],
            text,
            now if value is not None else m["last_ts"],
            m["id"],
        ))

    # Derived series
    def find(key: str, instance: str = "") -> dict[str, Any] | None:
        return by_key.get((key, instance))

    derived: dict[int, float] = {}
    rt = find("snmp.response_ms")
    if rt:
        derived[rt["id"]] = duration
    cpu_avg = find("cpu.avg")
    if cpu_avg:
        loads = [computed[m["id"]] for m in metrics if m["key"] == "cpu.load" and m["id"] in computed]
        if loads:
            derived[cpu_avg["id"]] = sum(loads) / len(loads)
    for idx, iface in ifaces.items():
        speed = iface.get("speed")
        for direction in ("in", "out"):
            util = find(f"if.{direction}_util", idx)
            bps = find(f"if.{direction}_bps", idx)
            if util and bps and speed and bps["id"] in computed:
                derived[util["id"]] = min(100.0, computed[bps["id"]] / speed * 100.0)
    for metric_id, value in derived.items():
        computed[metric_id] = value
        updates.append((None, None, value, None, now, metric_id))

    for metric_id, value in computed.items():
        samples.append((metric_id, ts, value))

    # Interface status/traffic snapshot
    iface_updates = []
    for idx, iface in ifaces.items():
        status_m = find("if.oper_status", idx)
        oper = None
        if status_m and status_m["oid"]:
            raw = values.get(status_m["oid"])
            oper = int(raw) if isinstance(raw, int) else None
        in_m, out_m = find("if.in_bps", idx), find("if.out_bps", idx)
        in_bps = computed.get(in_m["id"]) if in_m else None
        out_bps = computed.get(out_m["id"]) if out_m else None
        if oper is not None and iface.get("oper_status") is not None and oper != iface["oper_status"]:
            old = mibs.IF_OPER_STATUS_NAMES.get(iface["oper_status"], str(iface["oper_status"]))
            new = mibs.IF_OPER_STATUS_NAMES.get(oper, str(oper))
            # Only report changes on admin-up ports, like most NMSes do.
            if iface.get("admin_status") in (None, 1):
                result.events.append(f"{device['name']}: interface {iface['name']} changed state {old} -> {new}")
        iface_updates.append((
            oper if oper is not None else iface.get("oper_status"),
            in_bps if in_bps is not None else iface.get("in_bps"),
            out_bps if out_bps is not None else iface.get("out_bps"),
            now,
            iface["id"],
        ))

    with db.transaction() as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO samples (metric_id, ts, value) VALUES (?, ?, ?)", samples
        )
        conn.executemany(
            "UPDATE metrics SET last_raw = COALESCE(?, last_raw), last_raw_ts = COALESCE(?, last_raw_ts), "
            "last_value = ?, last_text = ?, last_ts = ? WHERE id = ?",
            updates,
        )
        conn.executemany(
            "UPDATE interfaces SET oper_status = ?, in_bps = ?, out_bps = ?, updated_at = ? WHERE id = ?",
            iface_updates,
        )
        was_down = device.get("status") == "down"
        db.update("devices", device["id"], {
            "status": "up",
            "status_since": now if device.get("status") != "up" else device.get("status_since") or now,
            "last_polled": now,
            "last_poll_ms": duration,
            "last_error": "",
            "sys_uptime": uptime if uptime is not None else device.get("sys_uptime"),
        })
        if was_down:
            db.log_event("device.up", f"{device['name']} is responding to SNMP again", "info", device_id=device["id"], ts=now)
        for message in result.events:
            level = "warning" if (message.endswith(("down", "lowerLayerDown")) or "restarted" in message) else "info"
            db.log_event("device.change", message, level, device_id=device["id"], ts=now)

    result.samples = len(samples)
    return result


def _mark_failure(db: Database, device: dict[str, Any], error: str, now: float) -> None:
    changed = device.get("status") != "down"
    db.update("devices", device["id"], {
        "status": "down",
        "status_since": now if changed else device.get("status_since") or now,
        "last_polled": now,
        "last_error": error[:500],
    })
    if changed:
        db.log_event("device.down", f"{device['name']} is not responding to SNMP: {error}", "error",
                     device_id=device["id"], ts=now)
