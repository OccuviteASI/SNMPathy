"""Report builder.

Every report returns the same structure so the web UI, CSV export,
printable view and scheduled e-mail/webhook delivery can share one
renderer::

    {"id", "title", "subtitle", "start", "end",
     "summary": [{"label", "value", "fmt", "status"?}],
     "sections": [{"title", "columns": [{"key", "label", "fmt"}], "rows": [...], "chart"?}]}

Column formats: text, num, int, pct, bps, bytes, duration, ms, ts.
"""

from __future__ import annotations

import csv
import io
import re
import time
from datetime import datetime, timedelta
from typing import Any, Callable

from . import reports as uptime
from .db import Database, loads
from .syslog.parser import SEVERITIES
from .syslog.search import parse_duration

REPORT_TYPES: dict[str, dict[str, str]] = {
    "uptime": {"title": "Availability / SLA", "description": "Uptime %, downtime, outages, MTTR and MTBF per check."},
    "health": {"title": "Device health", "description": "CPU, memory, storage, reachability and reboots per device."},
    "bandwidth": {"title": "Bandwidth & 95th percentile",
                  "description": "Traffic per interface: average, peak, 95th percentile and volume transferred."},
    "syslog": {"title": "Syslog summary", "description": "Log volume by severity, host, application and message pattern."},
    "alerts": {"title": "Alert history", "description": "Alerts raised, time to acknowledge / resolve, noisiest rules."},
}


# ------------------------------------------------------------------ ranges
def resolve_range(range_: str, now: float | None = None) -> tuple[float, float, str]:
    """Supports durations (``24h``, ``7d``) and calendar periods.

    Calendar keywords: ``today``, ``yesterday``, ``this_week``, ``last_week``,
    ``this_month``, ``last_month``.
    """
    now = now or time.time()
    today = datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0)
    if range_ == "today":
        return today.timestamp(), now, "Today"
    if range_ == "yesterday":
        s = today - timedelta(days=1)
        return s.timestamp(), today.timestamp(), s.strftime("%A %d %B %Y")
    if range_ in ("this_week", "last_week"):
        monday = today - timedelta(days=today.weekday())
        if range_ == "this_week":
            return monday.timestamp(), now, f"Week of {monday:%d %b %Y}"
        s = monday - timedelta(days=7)
        return s.timestamp(), monday.timestamp(), f"Week of {s:%d %b %Y}"
    if range_ in ("this_month", "last_month"):
        first = today.replace(day=1)
        if range_ == "this_month":
            return first.timestamp(), now, f"{first:%B %Y}"
        prev = (first - timedelta(days=1)).replace(day=1)
        return prev.timestamp(), first.timestamp(), f"{prev:%B %Y}"
    span = parse_duration(range_)
    return now - span, now, f"Last {range_}"


# ------------------------------------------------------------------ helpers
def _metric_stats(db: Database, metric_ids: list[int], start: float, end: float) -> dict[int, dict[str, Any]]:
    """avg / max per metric, using raw samples where available and 1h rollups before that."""
    out: dict[int, dict[str, Any]] = {}
    if not metric_ids:
        return out
    # Uses the (metric_id, ts) primary key instead of scanning the whole table.
    oldest_raw = db.scalar("SELECT MIN(ts) FROM samples WHERE metric_id = ?", (metric_ids[0],)) or end
    for i in range(0, len(metric_ids), 500):
        chunk = metric_ids[i:i + 500]
        marks = ",".join("?" for _ in chunk)
        acc: dict[int, list[float]] = {}  # metric -> [sum, count, max]
        if start < oldest_raw:
            for r in db.query(
                f"SELECT metric_id, SUM(vavg * vcount) AS s, SUM(vcount) AS n, MAX(vmax) AS mx FROM rollups "
                f"WHERE period = 3600 AND metric_id IN ({marks}) AND bucket >= ? AND bucket < ? GROUP BY metric_id",
                [*chunk, int(start), int(oldest_raw)],
            ):
                acc[r["metric_id"]] = [r["s"] or 0, r["n"] or 0, r["mx"]]
        for r in db.query(
            f"SELECT metric_id, SUM(value) AS s, COUNT(*) AS n, MAX(value) AS mx FROM samples "
            f"WHERE metric_id IN ({marks}) AND ts >= ? AND ts <= ? GROUP BY metric_id",
            [*chunk, int(max(start, oldest_raw)), int(end)],
        ):
            a = acc.setdefault(r["metric_id"], [0, 0, None])
            a[0] += r["s"] or 0
            a[1] += r["n"] or 0
            a[2] = r["mx"] if a[2] is None else max(a[2], r["mx"] if r["mx"] is not None else a[2])
        for mid, (s, n, mx) in acc.items():
            out[mid] = {"avg": (s / n) if n else None, "max": mx, "count": n}
    return out


def percentile_95(db: Database, metric_id: int, start: float, end: float) -> tuple[float | None, str]:
    """95th percentile of 5-minute averages (the burstable-billing definition).

    Falls back to hourly averages when the window is older than the 5-minute
    rollup retention, and to raw samples for very recent data.
    """
    for period, label in ((300, "5 min"), (3600, "1 h")):
        n = db.scalar("SELECT COUNT(*) FROM rollups WHERE metric_id = ? AND period = ? AND bucket >= ? AND bucket < ?",
                      (metric_id, period, int(start), int(end))) or 0
        if n >= 12 or (period == 3600 and n):
            offset = max(0, int(math_ceil(n * 0.95)) - 1)
            v = db.scalar(
                "SELECT vavg FROM rollups WHERE metric_id = ? AND period = ? AND bucket >= ? AND bucket < ? "
                "ORDER BY vavg LIMIT 1 OFFSET ?", (metric_id, period, int(start), int(end), offset))
            return v, label
    n = db.scalar("SELECT COUNT(*) FROM samples WHERE metric_id = ? AND ts >= ? AND ts <= ?",
                  (metric_id, int(start), int(end))) or 0
    if not n:
        return None, ""
    offset = max(0, int(math_ceil(n * 0.95)) - 1)
    v = db.scalar("SELECT value FROM samples WHERE metric_id = ? AND ts >= ? AND ts <= ? ORDER BY value "
                  "LIMIT 1 OFFSET ?", (metric_id, int(start), int(end), offset))
    return v, "raw"


def math_ceil(x: float) -> int:
    i = int(x)
    return i if i == x else i + 1


def _volume_bytes(db: Database, metric_id: int, start: float, end: float) -> float:
    """Bytes transferred = integral of bits/s over time / 8.

    Uses 5-minute rollups where they exist, hourly rollups for older parts of
    the window and raw samples for the most recent, not yet rolled-up part.
    """
    start, end = int(start), int(end)
    total = 0.0
    five = db.one(
        "SELECT SUM(vavg) AS s, MIN(bucket) AS lo, MAX(bucket) AS hi FROM rollups "
        "WHERE metric_id = ? AND period = 300 AND bucket >= ? AND bucket + 300 <= ?", (metric_id, start, end))
    if five and five["s"] is not None:
        total += five["s"] * 300
        older_until, newer_from = five["lo"], five["hi"] + 300
    else:
        older_until, newer_from = end, None
    hour = db.one(
        "SELECT SUM(vavg) AS s, MAX(bucket) AS hi FROM rollups WHERE metric_id = ? AND period = 3600 "
        "AND bucket >= ? AND bucket + 3600 <= ?", (metric_id, start, older_until))
    if hour and hour["s"] is not None:
        total += hour["s"] * 3600
        if newer_from is None:
            newer_from = hour["hi"] + 3600
    if newer_from is None:
        newer_from = start
    rows = db.query("SELECT ts, value FROM samples WHERE metric_id = ? AND ts >= ? AND ts <= ? ORDER BY ts",
                    (metric_id, newer_from, end))
    for a, b in zip(rows, rows[1:]):
        total += a["value"] * (b["ts"] - a["ts"])
    return total / 8


def _device_where(device_id: int | None, tag: str | None, db: Database) -> list[dict[str, Any]]:
    devices = db.query("SELECT * FROM devices ORDER BY name COLLATE NOCASE")
    if device_id:
        devices = [d for d in devices if d["id"] == device_id]
    if tag:
        devices = [d for d in devices if tag in loads(d["tags"], [])]
    return devices


def _base(report: str, start: float, end: float, label: str) -> dict[str, Any]:
    info = REPORT_TYPES[report]
    return {
        "id": report, "title": info["title"], "subtitle": label, "start": start, "end": end,
        "generated_at": time.time(), "summary": [], "sections": [],
    }


# ----------------------------------------------------------------- reports
def uptime_report(db: Database, start: float, end: float, label: str, device_id: int | None = None,
                  tag: str | None = None, sla_target: float = 99.9, **_: Any) -> dict[str, Any]:
    rows = uptime.uptime_report(db, start, end, device_id=device_id)
    if tag:
        tagged = {d["id"] for d in _device_where(None, tag, db)}
        rows = [r for r in rows if r["check"]["device_id"] in tagged]
    summary = uptime.sla_summary(rows)
    rep = _base("uptime", start, end, label)
    breaches = [r for r in rows if r["uptime_pct"] is not None and r["uptime_pct"] < sla_target]
    rep["summary"] = [
        {"label": "Average availability", "value": summary["avg_uptime_pct"], "fmt": "pct",
         "status": "ok" if (summary["avg_uptime_pct"] or 100) >= sla_target else "bad"},
        {"label": "Checks", "value": summary["checks"], "fmt": "int"},
        {"label": f"Below {sla_target}% SLA", "value": len(breaches), "fmt": "int",
         "status": "bad" if breaches else "ok"},
        {"label": "Outages", "value": summary["total_outages"], "fmt": "int"},
        {"label": "Total downtime", "value": summary["total_downtime"], "fmt": "duration"},
    ]
    table = []
    for r in rows:
        c = r["check"]
        table.append({
            "name": c["name"], "type": c["type"].upper(), "target": c["target"], "device": c.get("device_name") or "",
            "uptime_pct": r["uptime_pct"], "downtime": r["downtime_seconds"], "outages": r["outages"],
            "longest": r["longest_outage"], "mttr": r["mttr"], "mtbf": r["mtbf"],
            "latency": r["avg_latency_ms"], "maintenance": r["maintenance_seconds"],
            "sla": None if r["uptime_pct"] is None else ("met" if r["uptime_pct"] >= sla_target else "breached"),
            "_link": f"/checks/{c['id']}",
        })
    table.sort(key=lambda x: (x["uptime_pct"] is None, x["uptime_pct"] if x["uptime_pct"] is not None else 0))
    rep["sections"].append({
        "title": "Availability by check",
        "columns": [
            {"key": "name", "label": "Check"}, {"key": "type", "label": "Type"},
            {"key": "device", "label": "Device"}, {"key": "uptime_pct", "label": "Uptime", "fmt": "pct3"},
            {"key": "sla", "label": f"SLA {sla_target}%", "fmt": "badge"},
            {"key": "downtime", "label": "Downtime", "fmt": "duration"},
            {"key": "outages", "label": "Outages", "fmt": "int"},
            {"key": "longest", "label": "Longest", "fmt": "duration"},
            {"key": "mttr", "label": "MTTR", "fmt": "duration"}, {"key": "mtbf", "label": "MTBF", "fmt": "duration"},
            {"key": "latency", "label": "Avg response", "fmt": "ms"},
        ],
        "rows": table,
    })
    outages = db.query(
        "SELECT outages.*, checks.name AS check_name FROM outages JOIN checks ON checks.id = outages.check_id "
        "WHERE outages.started_at < ? AND COALESCE(outages.ended_at, ?) > ? ORDER BY outages.started_at DESC LIMIT 500",
        (end, time.time(), start))
    rep["sections"].append({
        "title": "Outages",
        "columns": [
            {"key": "check_name", "label": "Check"}, {"key": "started_at", "label": "Started", "fmt": "ts"},
            {"key": "ended_at", "label": "Ended", "fmt": "ts"}, {"key": "duration", "label": "Duration", "fmt": "duration"},
            {"key": "reason", "label": "Reason"},
        ],
        "rows": [{**o, "duration": (o["ended_at"] or time.time()) - o["started_at"]} for o in outages],
    })
    return rep


def health_report(db: Database, start: float, end: float, label: str, device_id: int | None = None,
                  tag: str | None = None, **_: Any) -> dict[str, Any]:
    devices = _device_where(device_id, tag, db)
    rep = _base("health", start, end, label)
    if not devices:
        return rep
    ids = [d["id"] for d in devices]
    marks = ",".join("?" for _ in ids)
    metrics = db.query(
        f"SELECT id, device_id, key, instance, label FROM metrics WHERE device_id IN ({marks}) AND key IN "
        f"('cpu.avg', 'mem.used_pct', 'storage.used_pct', 'snmp.response_ms')", ids)
    stats = _metric_stats(db, [m["id"] for m in metrics], start, end)
    per: dict[int, dict[str, Any]] = {d["id"]: {} for d in devices}
    for m in metrics:
        s = stats.get(m["id"])
        if not s:
            continue
        slot = per[m["device_id"]]
        if m["key"] == "storage.used_pct":
            if s["max"] is not None and (slot.get("disk_max") is None or s["max"] > slot["disk_max"]):
                slot["disk_max"], slot["disk_name"] = s["max"], m["label"]
        else:
            slot[f"{m['key']}.avg"] = s["avg"]
            slot[f"{m['key']}.max"] = s["max"]
    reboots = {r["device_id"]: r["n"] for r in db.query(
        f"SELECT device_id, COUNT(*) AS n FROM events WHERE type = 'device.change' AND message LIKE '% restarted (uptime reset%' "
        f"AND ts >= ? AND ts <= ? AND device_id IN ({marks}) GROUP BY device_id", [start, end, *ids])}
    snmp_down = {r["device_id"]: r["n"] for r in db.query(
        f"SELECT device_id, COUNT(*) AS n FROM events WHERE type = 'device.down' AND ts >= ? AND ts <= ? "
        f"AND device_id IN ({marks}) GROUP BY device_id", [start, end, *ids])}
    ifdown = {r["device_id"]: r["n"] for r in db.query(
        f"SELECT device_id, COUNT(*) AS n FROM interfaces WHERE admin_status = 1 AND oper_status = 2 "
        f"AND device_id IN ({marks}) GROUP BY device_id", ids)}
    logs = {r["device_id"]: r for r in db.query(
        f"SELECT device_id, COUNT(*) AS n, SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END) AS errors FROM syslog "
        f"WHERE ts >= ? AND ts <= ? AND device_id IN ({marks}) GROUP BY device_id", [start, end, *ids])}
    ping = {}
    for c in db.query(f"SELECT * FROM checks WHERE type = 'icmp' AND device_id IN ({marks})", ids):
        ping[c["device_id"]] = uptime.availability(db, c, start, end)["uptime_pct"]

    rows = []
    for d in devices:
        p = per[d["id"]]
        issues = []
        if (p.get("cpu.avg.max") or 0) > 90:
            issues.append("CPU peaked above 90%")
        if (p.get("disk_max") or 0) > 90:
            issues.append(f"{p.get('disk_name')} above 90%")
        if (p.get("mem.used_pct.max") or 0) > 95:
            issues.append("memory above 95%")
        if reboots.get(d["id"]):
            issues.append(f"{reboots[d['id']]} reboot(s)")
        if ping.get(d["id"]) is not None and ping[d["id"]] < 99.9:
            issues.append("availability below 99.9%")
        rows.append({
            "name": d["name"], "vendor": d["vendor"], "status": d["status"], "location": d["location"],
            "availability": ping.get(d["id"]),
            "cpu_avg": p.get("cpu.avg.avg"), "cpu_max": p.get("cpu.avg.max"),
            "mem_avg": p.get("mem.used_pct.avg"), "mem_max": p.get("mem.used_pct.max"),
            "disk_max": p.get("disk_max"), "response": p.get("snmp.response_ms.avg"),
            "reboots": reboots.get(d["id"], 0), "snmp_outages": snmp_down.get(d["id"], 0),
            "if_down": ifdown.get(d["id"], 0),
            "log_errors": (logs.get(d["id"]) or {}).get("errors") or 0,
            "issues": "; ".join(issues) or "-",
            "_link": f"/devices/{d['id']}",
        })
    rows.sort(key=lambda r: (r["issues"] == "-", r["name"].lower()))
    with_issues = sum(1 for r in rows if r["issues"] != "-")
    cpu_vals = [r["cpu_avg"] for r in rows if r["cpu_avg"] is not None]
    rep["summary"] = [
        {"label": "Devices", "value": len(rows), "fmt": "int"},
        {"label": "Devices with issues", "value": with_issues, "fmt": "int", "status": "bad" if with_issues else "ok"},
        {"label": "Currently down", "value": sum(1 for r in rows if r["status"] == "down"), "fmt": "int"},
        {"label": "Average CPU", "value": (sum(cpu_vals) / len(cpu_vals)) if cpu_vals else None, "fmt": "pct1"},
        {"label": "Reboots", "value": sum(r["reboots"] for r in rows), "fmt": "int"},
    ]
    rep["sections"].append({
        "title": "Devices",
        "columns": [
            {"key": "name", "label": "Device"}, {"key": "status", "label": "Status", "fmt": "badge"},
            {"key": "availability", "label": "Ping uptime", "fmt": "pct3"},
            {"key": "cpu_avg", "label": "CPU avg", "fmt": "pct1"}, {"key": "cpu_max", "label": "CPU max", "fmt": "pct1"},
            {"key": "mem_avg", "label": "Mem avg", "fmt": "pct1"}, {"key": "mem_max", "label": "Mem max", "fmt": "pct1"},
            {"key": "disk_max", "label": "Fullest disk", "fmt": "pct1"},
            {"key": "response", "label": "SNMP resp.", "fmt": "ms"},
            {"key": "reboots", "label": "Reboots", "fmt": "int"},
            {"key": "if_down", "label": "Ports down", "fmt": "int"},
            {"key": "log_errors", "label": "Log errors", "fmt": "int"},
            {"key": "issues", "label": "Issues"},
        ],
        "rows": rows,
    })
    return rep


def bandwidth_report(db: Database, start: float, end: float, label: str, device_id: int | None = None,
                     tag: str | None = None, limit: int = 100, **_: Any) -> dict[str, Any]:
    devices = {d["id"]: d for d in _device_where(device_id, tag, db)}
    rep = _base("bandwidth", start, end, label)
    if not devices:
        return rep
    marks = ",".join("?" for _ in devices)
    metrics = db.query(
        f"SELECT * FROM metrics WHERE key IN ('if.in_bps', 'if.out_bps') AND device_id IN ({marks})", list(devices))
    ifaces = {(r["device_id"], str(r["if_index"])): r for r in db.query(
        f"SELECT * FROM interfaces WHERE device_id IN ({marks})", list(devices))}
    stats = _metric_stats(db, [m["id"] for m in metrics], start, end)
    pairs: dict[tuple[int, str], dict[str, Any]] = {}
    for m in metrics:
        pairs.setdefault((m["device_id"], m["instance"]), {})[m["key"]] = m
    rows = []
    for (dev_id, inst), ms in pairs.items():
        in_m, out_m = ms.get("if.in_bps"), ms.get("if.out_bps")
        s_in = stats.get(in_m["id"]) if in_m else None
        s_out = stats.get(out_m["id"]) if out_m else None
        if not (s_in or s_out):
            continue
        iface = ifaces.get((dev_id, inst)) or {}
        rows.append({
            "device": devices[dev_id]["name"], "interface": iface.get("name") or (in_m or out_m)["label"],
            "alias": iface.get("alias") or "", "speed": iface.get("speed"),
            "in_avg": (s_in or {}).get("avg"), "out_avg": (s_out or {}).get("avg"),
            "in_max": (s_in or {}).get("max"), "out_max": (s_out or {}).get("max"),
            "_in_id": in_m["id"] if in_m else None, "_out_id": out_m["id"] if out_m else None,
            "_link": f"/devices/{dev_id}?tab=interfaces",
        })
    # Rank by average traffic, then compute the expensive figures for the top N only.
    rows.sort(key=lambda r: -((r["in_avg"] or 0) + (r["out_avg"] or 0)))
    rows = rows[:limit]
    basis = set()
    for r in rows:
        r["in_p95"], b1 = percentile_95(db, r["_in_id"], start, end) if r["_in_id"] else (None, "")
        r["out_p95"], b2 = percentile_95(db, r["_out_id"], start, end) if r["_out_id"] else (None, "")
        basis.update(x for x in (b1, b2) if x)
        r["p95"] = max(r["in_p95"] or 0, r["out_p95"] or 0)
        r["in_bytes"] = _volume_bytes(db, r["_in_id"], start, end) if r["_in_id"] else None
        r["out_bytes"] = _volume_bytes(db, r["_out_id"], start, end) if r["_out_id"] else None
        speed = r["speed"]
        r["util_avg"] = (max(r["in_avg"] or 0, r["out_avg"] or 0) / speed * 100) if speed else None
        r["util_p95"] = (r["p95"] / speed * 100) if speed else None
    total_in = sum(r["in_bytes"] or 0 for r in rows)
    total_out = sum(r["out_bytes"] or 0 for r in rows)
    rep["summary"] = [
        {"label": "Interfaces", "value": len(rows), "fmt": "int"},
        {"label": "Received", "value": total_in, "fmt": "bytes"},
        {"label": "Sent", "value": total_out, "fmt": "bytes"},
        {"label": "Highest 95th pct", "value": max((r["p95"] for r in rows), default=None), "fmt": "bps"},
        {"label": "Busiest (95th pct util.)", "value": max((r["util_p95"] or 0 for r in rows), default=None),
         "fmt": "pct1"},
    ]
    rep["sections"].append({
        "title": "Interfaces by traffic",
        "note": ("95th percentile is calculated from " + " / ".join(sorted(basis)) + " averages.") if basis else "",
        "columns": [
            {"key": "device", "label": "Device"}, {"key": "interface", "label": "Interface"},
            {"key": "alias", "label": "Description"}, {"key": "speed", "label": "Speed", "fmt": "bps"},
            {"key": "in_avg", "label": "In avg", "fmt": "bps"}, {"key": "out_avg", "label": "Out avg", "fmt": "bps"},
            {"key": "in_max", "label": "In peak", "fmt": "bps"}, {"key": "out_max", "label": "Out peak", "fmt": "bps"},
            {"key": "in_p95", "label": "In 95th", "fmt": "bps"}, {"key": "out_p95", "label": "Out 95th", "fmt": "bps"},
            {"key": "util_p95", "label": "95th util.", "fmt": "pct1"},
            {"key": "in_bytes", "label": "Received", "fmt": "bytes"}, {"key": "out_bytes", "label": "Sent", "fmt": "bytes"},
        ],
        "rows": rows,
    })
    return rep


_PATTERN_SUBS = [
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I), "<mac>"),
    (re.compile(r"\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b", re.I), "<mac>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\d+"), "<n>"),
]


def message_pattern(message: str) -> str:
    """Collapse variable parts (IPs, numbers, MACs) so similar messages group together."""
    text = message[:200]
    for rx, repl in _PATTERN_SUBS:
        text = rx.sub(repl, text)
    return text


def syslog_report(db: Database, start: float, end: float, label: str, device_id: int | None = None,
                  tag: str | None = None, **_: Any) -> dict[str, Any]:
    rep = _base("syslog", start, end, label)
    where = "WHERE ts >= ? AND ts <= ?"
    params: list[Any] = [start, end]
    if device_id:
        where += " AND device_id = ?"
        params.append(device_id)
    elif tag:
        ids = [d["id"] for d in _device_where(None, tag, db)] or [-1]
        where += f" AND device_id IN ({','.join('?' for _ in ids)})"
        params.extend(ids)
    total = db.scalar(f"SELECT COUNT(*) FROM syslog {where}", params) or 0
    by_sev = db.query(f"SELECT severity, COUNT(*) AS n FROM syslog {where} GROUP BY severity ORDER BY severity", params)
    errors = sum(r["n"] for r in by_sev if r["severity"] is not None and r["severity"] <= 3)
    hosts = db.query(
        f"SELECT host, COUNT(*) AS n, SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END) AS errors, "
        f"SUM(CASE WHEN severity = 4 THEN 1 ELSE 0 END) AS warnings FROM syslog {where} "
        f"GROUP BY host ORDER BY n DESC LIMIT 25", params)
    apps = db.query(f"SELECT app, COUNT(*) AS n FROM syslog {where} GROUP BY app ORDER BY n DESC LIMIT 25", params)
    patterns: dict[str, dict[str, Any]] = {}
    for r in db.query(f"SELECT host, app, severity, message FROM syslog {where} AND severity <= 4 "
                      f"ORDER BY id DESC LIMIT 20000", params):
        key = f"{r['app']}|{message_pattern(r['message'])}"
        p = patterns.setdefault(key, {"app": r["app"], "pattern": message_pattern(r["message"]),
                                      "example": r["message"][:200], "severity": r["severity"], "count": 0,
                                      "hosts": set()})
        p["count"] += 1
        p["hosts"].add(r["host"])
        p["severity"] = min(p["severity"], r["severity"])
    top_patterns = sorted(patterns.values(), key=lambda p: -p["count"])[:25]
    for p in top_patterns:
        p["hosts"] = len(p["hosts"])
        p["severity"] = SEVERITIES[p["severity"]] if p["severity"] is not None else ""
    days = db.query(
        f"SELECT date(ts, 'unixepoch', 'localtime') AS day, COUNT(*) AS n, "
        f"SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END) AS errors FROM syslog {where} GROUP BY day ORDER BY day", params)
    rep["summary"] = [
        {"label": "Messages", "value": total, "fmt": "int"},
        {"label": "Errors (err+)", "value": errors, "fmt": "int", "status": "bad" if errors else "ok"},
        {"label": "Hosts", "value": db.scalar(f"SELECT COUNT(DISTINCT host) FROM syslog {where}", params), "fmt": "int"},
        {"label": "Per hour", "value": total / max(1.0, (end - start) / 3600), "fmt": "num"},
    ]
    rep["sections"] = [
        {"title": "By severity", "columns": [{"key": "severity", "label": "Severity"},
                                              {"key": "n", "label": "Messages", "fmt": "int"},
                                              {"key": "share", "label": "Share", "fmt": "pct1"}],
         "rows": [{"severity": SEVERITIES[r["severity"]] if r["severity"] is not None else "-", "n": r["n"],
                   "share": r["n"] / total * 100 if total else 0} for r in by_sev]},
        {"title": "Top hosts", "columns": [{"key": "host", "label": "Host"}, {"key": "n", "label": "Messages", "fmt": "int"},
                                            {"key": "errors", "label": "Errors", "fmt": "int"},
                                            {"key": "warnings", "label": "Warnings", "fmt": "int"}],
         "rows": [{**h, "_link": f"/syslog?host={h['host']}"} for h in hosts]},
        {"title": "Top applications", "columns": [{"key": "app", "label": "Application"},
                                                   {"key": "n", "label": "Messages", "fmt": "int"}],
         "rows": [{**a, "_link": f"/syslog?app={a['app']}"} for a in apps]},
        {"title": "Most frequent warnings and errors",
         "columns": [{"key": "count", "label": "Count", "fmt": "int"}, {"key": "severity", "label": "Worst"},
                     {"key": "app", "label": "App"}, {"key": "hosts", "label": "Hosts", "fmt": "int"},
                     {"key": "example", "label": "Example message"}],
         "rows": top_patterns},
        {"title": "Per day", "columns": [{"key": "day", "label": "Day"}, {"key": "n", "label": "Messages", "fmt": "int"},
                                          {"key": "errors", "label": "Errors", "fmt": "int"}],
         "rows": days},
    ]
    return rep


def alerts_report(db: Database, start: float, end: float, label: str, device_id: int | None = None,
                  **_: Any) -> dict[str, Any]:
    rep = _base("alerts", start, end, label)
    where = "WHERE alerts.fired_at IS NOT NULL AND alerts.fired_at >= ? AND alerts.fired_at <= ?"
    params: list[Any] = [start, end]
    if device_id:
        where += " AND alerts.device_id = ?"
        params.append(device_id)
    rows = db.query(
        f"SELECT alerts.*, alert_rules.name AS rule_name FROM alerts LEFT JOIN alert_rules "
        f"ON alert_rules.id = alerts.rule_id {where} ORDER BY alerts.fired_at DESC", params)
    now = time.time()
    resolved = [r for r in rows if r["resolved_at"]]
    acked = [r for r in rows if r["ack_at"]]
    mttr = sum(r["resolved_at"] - r["fired_at"] for r in resolved) / len(resolved) if resolved else None
    mtta = sum(r["ack_at"] - r["fired_at"] for r in acked) / len(acked) if acked else None
    by_rule: dict[str, dict[str, Any]] = {}
    for r in rows:
        b = by_rule.setdefault(r["rule_name"] or "(deleted rule)", {"rule": r["rule_name"] or "(deleted rule)",
                                                                    "severity": r["severity"], "count": 0,
                                                                    "duration": 0.0, "subjects": set()})
        b["count"] += 1
        b["duration"] += (r["resolved_at"] or now) - r["fired_at"]
        b["subjects"].add(r["subject"])
    rule_rows = sorted(by_rule.values(), key=lambda b: -b["count"])
    for b in rule_rows:
        b["subjects"] = len(b["subjects"])
    by_subject: dict[str, int] = {}
    for r in rows:
        by_subject[r["subject"]] = by_subject.get(r["subject"], 0) + 1
    rep["summary"] = [
        {"label": "Alerts fired", "value": len(rows), "fmt": "int"},
        {"label": "Critical", "value": sum(1 for r in rows if r["severity"] == "critical"), "fmt": "int",
         "status": "bad" if any(r["severity"] == "critical" for r in rows) else "ok"},
        {"label": "Still firing", "value": sum(1 for r in rows if r["state"] == "firing"), "fmt": "int"},
        {"label": "Mean time to resolve", "value": mttr, "fmt": "duration"},
        {"label": "Mean time to acknowledge", "value": mtta, "fmt": "duration"},
    ]
    rep["sections"] = [
        {"title": "By rule", "columns": [{"key": "rule", "label": "Rule"}, {"key": "severity", "label": "Severity", "fmt": "badge"},
                                          {"key": "count", "label": "Alerts", "fmt": "int"},
                                          {"key": "subjects", "label": "Distinct subjects", "fmt": "int"},
                                          {"key": "duration", "label": "Total time firing", "fmt": "duration"}],
         "rows": rule_rows},
        {"title": "Noisiest subjects", "columns": [{"key": "subject", "label": "Subject"},
                                                    {"key": "count", "label": "Alerts", "fmt": "int"}],
         "rows": [{"subject": k, "count": v} for k, v in sorted(by_subject.items(), key=lambda kv: -kv[1])[:25]]},
        {"title": "All alerts", "columns": [
            {"key": "fired_at", "label": "Fired", "fmt": "ts"}, {"key": "severity", "label": "Severity", "fmt": "badge"},
            {"key": "subject", "label": "Subject"}, {"key": "message", "label": "Message"},
            {"key": "duration", "label": "Duration", "fmt": "duration"}, {"key": "state", "label": "State", "fmt": "badge"},
            {"key": "ack_by", "label": "Acknowledged by"}],
         "rows": [{**r, "duration": (r["resolved_at"] or now) - r["fired_at"]} for r in rows[:1000]]},
    ]
    return rep


BUILDERS: dict[str, Callable[..., dict[str, Any]]] = {
    "uptime": uptime_report,
    "health": health_report,
    "bandwidth": bandwidth_report,
    "syslog": syslog_report,
    "alerts": alerts_report,
}


def build(db: Database, report: str, range_: str = "7d", start: float | None = None, end: float | None = None,
          **options: Any) -> dict[str, Any]:
    if report not in BUILDERS:
        raise KeyError(report)
    if start is not None and end is not None:
        label = f"{datetime.fromtimestamp(start):%Y-%m-%d %H:%M} - {datetime.fromtimestamp(end):%Y-%m-%d %H:%M}"
    else:
        start, end, label = resolve_range(range_ or "7d")
    options = {k: v for k, v in options.items() if v not in (None, "")}
    return BUILDERS[report](db, start, end, label, **options)


# ----------------------------------------------------------------- output
def format_cell(value: Any, fmt: str = "text") -> str:
    from .fmt import fmt_bps, fmt_bytes

    if value is None or value == "":
        return "-"
    if fmt in ("pct", "pct3"):
        return f"{float(value):.3f}%" if fmt == "pct3" else f"{float(value):.2f}%"
    if fmt == "pct1":
        return f"{float(value):.1f}%"
    if fmt == "bps":
        return fmt_bps(value)
    if fmt == "bytes":
        return fmt_bytes(value)
    if fmt == "duration":
        return uptime.format_duration(value)
    if fmt == "ms":
        return f"{float(value):.1f} ms"
    if fmt == "int":
        return f"{int(value):,}"
    if fmt == "num":
        return f"{float(value):,.1f}"
    if fmt == "ts":
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M")
    return str(value)


def to_csv(report: dict[str, Any], section: int | None = None) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    sections = report["sections"] if section is None else [report["sections"][section]]
    for i, sec in enumerate(sections):
        if len(sections) > 1:
            if i:
                writer.writerow([])
            writer.writerow([f"# {sec['title']}"])
        cols = sec["columns"]
        writer.writerow([c["label"] for c in cols])
        for row in sec["rows"]:
            out = []
            for c in cols:
                v = row.get(c["key"])
                fmt = c.get("fmt", "text")
                if v is None:
                    out.append("")
                elif fmt == "ts":
                    out.append(datetime.fromtimestamp(float(v)).isoformat(timespec="seconds"))
                elif fmt in ("pct", "pct1", "pct3", "num", "ms", "bps", "bytes", "duration"):
                    out.append(f"{float(v):.4f}".rstrip("0").rstrip("."))
                else:
                    out.append(str(v))
            writer.writerow(out)
    return buf.getvalue()


def to_text(report: dict[str, Any]) -> str:
    lines = [f"{report['title']} - {report['subtitle']}"]
    for s in report["summary"]:
        lines.append(f"  {s['label']}: {format_cell(s['value'], s.get('fmt', 'text'))}")
    return "\n".join(lines)
