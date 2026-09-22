"""Uptime / SLA reporting built from outage history and heartbeats."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timedelta
from typing import Any, Iterable

from .db import Database

Interval = tuple[float, float]


def merge(intervals: Iterable[Interval]) -> list[Interval]:
    out: list[list[float]] = []
    for s, e in sorted(i for i in intervals if i[1] > i[0]):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def clip(intervals: Iterable[Interval], start: float, end: float) -> list[Interval]:
    return [(max(s, start), min(e, end)) for s, e in intervals if e > start and s < end]


def total(intervals: Iterable[Interval]) -> float:
    return sum(e - s for s, e in intervals)


def subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    """Remove every interval in ``b`` from the (merged) intervals in ``a``."""
    result: list[Interval] = []
    b = merge(b)
    for s, e in merge(a):
        cur = s
        for bs, be in b:
            if be <= cur or bs >= e:
                continue
            if bs > cur:
                result.append((cur, bs))
            cur = max(cur, be)
            if cur >= e:
                break
        if cur < e:
            result.append((cur, e))
    return result


def maintenance_windows(db: Database, check: dict[str, Any], start: float, end: float) -> list[Interval]:
    rows = db.query(
        "SELECT starts_at, ends_at FROM maintenance WHERE ends_at > ? AND starts_at < ? AND "
        "((device_id IS NULL AND check_id IS NULL) OR check_id = ? OR (device_id IS NOT NULL AND device_id = ?))",
        (start, end, check["id"], check.get("device_id")),
    )
    return merge(clip([(r["starts_at"], r["ends_at"]) for r in rows], start, end))


def outage_intervals(db: Database, check_id: int, start: float, end: float, now: float) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT * FROM outages WHERE check_id = ? AND started_at < ? AND COALESCE(ended_at, ?) > ? ORDER BY started_at",
        (check_id, end, now, start),
    )
    for r in rows:
        r["effective_end"] = r["ended_at"] if r["ended_at"] is not None else now
        r["duration"] = r["effective_end"] - r["started_at"]
    return rows


def availability(db: Database, check: dict[str, Any], start: float, end: float, now: float | None = None) -> dict[str, Any]:
    """Availability of ``check`` over ``[start, end)``.

    Time before the first heartbeat is not counted (the check did not exist
    yet) and scheduled maintenance is excluded from both uptime and downtime.
    """
    now = now or time.time()
    end = min(end, now)
    first_seen = db.scalar("SELECT MIN(ts) FROM heartbeats WHERE check_id = ?", (check["id"],))
    earliest_outage = db.scalar("SELECT MIN(started_at) FROM outages WHERE check_id = ?", (check["id"],))
    candidates = [x for x in (first_seen, earliest_outage) if x is not None]
    if not candidates:
        return _empty(start, end)
    effective_start = max(start, min(candidates))
    if effective_start >= end:
        return _empty(start, end)

    maint = maintenance_windows(db, check, effective_start, end)
    outages = outage_intervals(db, check["id"], effective_start, end, now)
    down = subtract(clip([(o["started_at"], o["effective_end"]) for o in outages], effective_start, end), maint)
    monitored = (end - effective_start) - total(maint)
    downtime = total(down)
    uptime_pct = 100.0 if monitored <= 0 else max(0.0, 100.0 * (1 - downtime / monitored))

    closed = [o for o in outages if o["ended_at"] is not None]
    lat = db.one(
        "SELECT AVG(latency_ms) AS avg, MIN(latency_ms) AS min, MAX(latency_ms) AS max, COUNT(*) AS n, "
        "SUM(ok) AS ok FROM heartbeats WHERE check_id = ? AND ts >= ? AND ts < ?",
        (check["id"], effective_start, end),
    ) or {}
    n_outages = len(outages)
    return {
        "start": start,
        "end": end,
        "monitored_seconds": monitored,
        "downtime_seconds": downtime,
        "maintenance_seconds": total(maint),
        "uptime_pct": uptime_pct,
        "outages": n_outages,
        "longest_outage": max((o["duration"] for o in outages), default=0.0),
        "mttr": (sum(o["duration"] for o in closed) / len(closed)) if closed else None,
        "mtbf": ((monitored - downtime) / n_outages) if n_outages else None,
        "avg_latency_ms": lat.get("avg"),
        "min_latency_ms": lat.get("min"),
        "max_latency_ms": lat.get("max"),
        "checks_run": lat.get("n") or 0,
        "checks_ok": lat.get("ok") or 0,
    }


def _empty(start: float, end: float) -> dict[str, Any]:
    return {
        "start": start, "end": end, "monitored_seconds": 0, "downtime_seconds": 0, "maintenance_seconds": 0,
        "uptime_pct": None, "outages": 0, "longest_outage": 0, "mttr": None, "mtbf": None,
        "avg_latency_ms": None, "min_latency_ms": None, "max_latency_ms": None, "checks_run": 0, "checks_ok": 0,
    }


def daily_bars(db: Database, check: dict[str, Any], days: int = 90, now: float | None = None) -> list[dict[str, Any]]:
    """Per-day availability for the last ``days`` local calendar days (oldest first)."""
    now = now or time.time()
    today = datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0)
    out = []
    for i in range(days - 1, -1, -1):
        day = today - timedelta(days=i)
        s = day.timestamp()
        e = (day + timedelta(days=1)).timestamp()
        a = availability(db, check, s, e, now)
        out.append({
            "date": day.strftime("%Y-%m-%d"),
            "uptime_pct": a["uptime_pct"],
            "downtime_seconds": a["downtime_seconds"],
            "outages": a["outages"],
        })
    return out


WINDOWS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "365d": 365 * 86400}


def uptime_report(db: Database, start: float, end: float, check_ids: list[int] | None = None,
                  device_id: int | None = None, now: float | None = None) -> list[dict[str, Any]]:
    sql = "SELECT checks.*, devices.name AS device_name FROM checks LEFT JOIN devices ON devices.id = checks.device_id"
    clauses, params = [], []
    if check_ids:
        clauses.append(f"checks.id IN ({','.join('?' for _ in check_ids)})")
        params.extend(check_ids)
    if device_id:
        clauses.append("checks.device_id = ?")
        params.append(device_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY checks.name"
    rows = []
    for check in db.query(sql, params):
        a = availability(db, check, start, end, now)
        rows.append({"check": check, **a})
    return rows


def sla_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    measured = [r for r in rows if r["uptime_pct"] is not None]
    if not measured:
        return {"checks": len(rows), "avg_uptime_pct": None, "total_downtime": 0, "total_outages": 0}
    weight = sum(r["monitored_seconds"] for r in measured) or 1
    return {
        "checks": len(rows),
        "avg_uptime_pct": sum(r["uptime_pct"] * r["monitored_seconds"] for r in measured) / weight,
        "total_downtime": sum(r["downtime_seconds"] for r in measured),
        "total_outages": sum(r["outages"] for r in measured),
        "worst": min(measured, key=lambda r: r["uptime_pct"])["check"]["name"],
    }


def report_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([
        "check", "type", "target", "device", "uptime_pct", "downtime_seconds", "outages",
        "longest_outage_seconds", "mttr_seconds", "mtbf_seconds", "avg_latency_ms", "maintenance_seconds",
    ])
    for r in rows:
        c = r["check"]
        writer.writerow([
            c["name"], c["type"], c["target"], c.get("device_name") or "",
            "" if r["uptime_pct"] is None else f"{r['uptime_pct']:.4f}",
            f"{r['downtime_seconds']:.0f}", r["outages"], f"{r['longest_outage']:.0f}",
            "" if r["mttr"] is None else f"{r['mttr']:.0f}",
            "" if r["mtbf"] is None else f"{r['mtbf']:.0f}",
            "" if r["avg_latency_ms"] is None else f"{r['avg_latency_ms']:.1f}",
            f"{r['maintenance_seconds']:.0f}",
        ])
    return buf.getvalue()


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, s = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {s}s" if s else f"{minutes}m"
    hours, m = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {m}m" if m else f"{hours}h"
    days, h = divmod(hours, 24)
    return f"{days}d {h}h" if h else f"{days}d"
