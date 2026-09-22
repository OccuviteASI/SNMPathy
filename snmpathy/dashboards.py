"""Grafana-style dashboards: query targets, panel data and default dashboards.

A *target* selects time series. The same target format is used by the
built-in dashboards and by the Grafana JSON data source (``/grafana``)::

    {"source": "metric", "key": "if.in_bps", "device": "core-sw01" | 12 | "*",
     "tag": "hq", "instance": "Gi1/0/*", "agg": "each|sum|avg|max|min", "limit": 10}
    {"source": "check", "check": 3 | "*", "field": "latency|up"}
    {"source": "syslog", "q": "failed", "severity": 3, "host": "fw*"}
"""

from __future__ import annotations

import fnmatch
import json
import math
import re
import time
from typing import Any

from . import reports, services
from .db import Database, loads
from .snmp.mibs import METRIC_INFO
from .syslog import search as syslog_search

NICE_STEPS = [30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]
TARGET_POINTS = 300
MAX_SERIES = 50

PANEL_TYPES = {
    "timeseries": "Time series graph",
    "stat": "Single stat",
    "gauge": "Gauge",
    "table": "Top-N table",
    "status": "Status grid (devices or checks)",
    "uptime": "Uptime bars",
    "syslog_histogram": "Syslog volume",
    "syslog_stream": "Syslog stream",
    "syslog_top": "Syslog top hosts/apps",
    "alerts": "Firing alerts",
    "summary": "Overview counters",
    "events": "Event log",
    "text": "Text / notes",
}


# ------------------------------------------------------------------ helpers
def nice_step(span: float, min_step: int = 30, points: int = TARGET_POINTS) -> int:
    want = max(min_step, span / max(1, points))
    for step in NICE_STEPS:
        if step >= want:
            return step
    return int(math.ceil(want / 86400) * 86400)


def _device_filter(db: Database, target: dict[str, Any]) -> dict[int, dict[str, Any]]:
    devices = {d["id"]: d for d in db.query("SELECT * FROM devices WHERE enabled = 1")}
    sel = target.get("device")
    if sel not in (None, "", "*", "all", "$__all"):
        wanted: set[int] = set()
        values = sel if isinstance(sel, list) else [sel]
        for v in values:
            v = str(v).strip()
            if v in ("*", "all", "$__all"):
                wanted = set(devices)
                break
            if v.isdigit() and int(v) in devices:
                wanted.add(int(v))
                continue
            for d in devices.values():
                if fnmatch.fnmatch(d["name"].lower(), v.lower()) or d["hostname"].lower() == v.lower():
                    wanted.add(d["id"])
        devices = {k: v for k, v in devices.items() if k in wanted}
    tag = (target.get("tag") or "").strip()
    if tag:
        devices = {k: v for k, v in devices.items() if tag in loads(v["tags"], [])}
    return devices


def resolve_metrics(db: Database, target: dict[str, Any]) -> list[dict[str, Any]]:
    key = (target.get("key") or "").strip()
    if not key:
        return []
    devices = _device_filter(db, target)
    if not devices:
        return []
    marks = ",".join("?" for _ in devices)
    if any(ch in key for ch in "*?["):
        rows = db.query(f"SELECT * FROM metrics WHERE enabled = 1 AND device_id IN ({marks})", list(devices))
        rows = [r for r in rows if fnmatch.fnmatchcase(r["key"], key)]
    else:
        rows = db.query(f"SELECT * FROM metrics WHERE enabled = 1 AND key = ? AND device_id IN ({marks})",
                        [key, *devices])
    inst = str(target.get("instance") or "").strip()
    if inst and inst != "*":
        rows = [r for r in rows if fnmatch.fnmatch(r["instance"], inst)
                or fnmatch.fnmatch(r["label"].lower(), inst.lower())]
    for r in rows:
        d = devices[r["device_id"]]
        r["device_name"] = d["name"]
        r["poll_interval"] = d["poll_interval"]
    return rows


def _series_name(m: dict[str, Any], multi_key: bool, alias: str = "") -> str:
    if alias:
        return (alias.replace("{device}", m["device_name"]).replace("{label}", m["label"] or m["key"])
                .replace("{instance}", m["instance"]).replace("{key}", m["key"]))
    name = m["device_name"]
    if m["label"] and m["label"] not in (m["key"],):
        name += f" {m['label']}"
    if multi_key:
        name += f" {m['key']}"
    return name


def _bucketed(db: Database, metric_ids: list[int], start: float, end: float, step: int) -> dict[int, dict[int, float]]:
    """Per-metric averages in ``step``-second buckets, from raw samples or rollups."""
    out: dict[int, dict[int, float]] = {mid: {} for mid in metric_ids}
    if not metric_ids:
        return out
    start, end = int(start), int(end)
    raw_start = start
    if step >= 300 and end - start > 2 * 86400:
        period = 3600 if step >= 3600 else 300
        watermark = int(db.get_meta(f"rollup_watermark_{period}") or 0)
        roll_end = min(end, watermark) if watermark else start
        for chunk in _chunks(metric_ids):
            marks = ",".join("?" for _ in chunk)
            for r in db.query(
                f"SELECT metric_id, (bucket / ?) * ? AS b, AVG(vavg) AS v FROM rollups "
                f"WHERE period = ? AND metric_id IN ({marks}) AND bucket >= ? AND bucket < ? GROUP BY metric_id, b",
                [step, step, period, *chunk, start, roll_end],
            ):
                out[r["metric_id"]][r["b"]] = r["v"]
        raw_start = max(start, roll_end)
    for chunk in _chunks(metric_ids):
        marks = ",".join("?" for _ in chunk)
        for r in db.query(
            f"SELECT metric_id, (ts / ?) * ? AS b, AVG(value) AS v FROM samples "
            f"WHERE metric_id IN ({marks}) AND ts >= ? AND ts <= ? GROUP BY metric_id, b",
            [step, step, *chunk, raw_start, end],
        ):
            out[r["metric_id"]][r["b"]] = r["v"]
    return out


def _chunks(items: list[int], size: int = 500):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def target_unit(db: Database, target: dict[str, Any]) -> str:
    source = target.get("source") or "metric"
    if source == "check":
        return "%" if target.get("field") == "up" else "ms"
    if source == "syslog":
        return "msgs"
    key = target.get("key") or ""
    if key in METRIC_INFO:
        return METRIC_INFO[key]["unit"]
    row = db.one("SELECT unit FROM metrics WHERE key = ? LIMIT 1", (key,)) if key else None
    return row["unit"] if row else ""


def query_target(db: Database, target: dict[str, Any], start: float, end: float,
                 step: int | None = None) -> list[dict[str, Any]]:
    """Resolve a target into ``[{"name", "unit", "points": [[ts, value], ...]}]``."""
    source = target.get("source") or "metric"
    span = max(60, end - start)
    if source == "check":
        return _check_series(db, target, start, end, step or nice_step(span, 60))
    if source == "syslog":
        return _syslog_series(db, target, start, end, step or nice_step(span, 60))

    metrics = resolve_metrics(db, target)
    if not metrics:
        return []
    min_step = max(30, max(int(m["poll_interval"] or 300) for m in metrics))
    step = step or nice_step(span, min_step if span > 6 * 3600 else min(min_step, 60))
    agg = (target.get("agg") or "each").lower()
    limit = max(1, min(int(target.get("limit") or 8), MAX_SERIES))
    unit = metrics[0]["unit"] or target_unit(db, target)
    scale = float(target.get("scale") or 1)

    if agg == "each":
        metrics.sort(key=lambda m: (m["last_value"] is None, -(m["last_value"] or 0)))
        metrics = metrics[:limit]
    data = _bucketed(db, [m["id"] for m in metrics], start, end, step)
    multi_key = len({m["key"] for m in metrics}) > 1
    if agg == "each":
        series = []
        for m in metrics:
            pts = sorted(data[m["id"]].items())
            series.append({
                "name": _series_name(m, multi_key, target.get("alias") or ""),
                "unit": m["unit"] or unit, "metric_id": m["id"], "device_id": m["device_id"],
                "points": [[ts, v * scale] for ts, v in pts],
            })
        return series
    buckets: dict[int, list[float]] = {}
    for per_metric in data.values():
        for ts, v in per_metric.items():
            buckets.setdefault(ts, []).append(v)
    fn = {"sum": sum, "avg": lambda xs: sum(xs) / len(xs), "max": max, "min": min}.get(agg, sum)
    label = target.get("alias") or f"{agg}({target.get('key')})"
    return [{"name": label, "unit": unit,
             "points": [[ts, fn(vs) * scale] for ts, vs in sorted(buckets.items())]}]


def _check_series(db: Database, target: dict[str, Any], start: float, end: float, step: int) -> list[dict[str, Any]]:
    sel = target.get("check")
    checks = db.query("SELECT * FROM checks WHERE enabled = 1 ORDER BY name")
    if sel not in (None, "", "*", "all", "$__all"):
        values = [str(v) for v in (sel if isinstance(sel, list) else [sel])]
        checks = [c for c in checks if str(c["id"]) in values or any(fnmatch.fnmatch(c["name"], v) for v in values)]
    if target.get("device"):
        devices = _device_filter(db, target)
        checks = [c for c in checks if c["device_id"] in devices]
    field = target.get("field") or "latency"
    limit = max(1, min(int(target.get("limit") or 20), MAX_SERIES))
    out = []
    for c in checks[:limit]:
        expr = "AVG(latency_ms)" if field == "latency" else "AVG(ok) * 100.0"
        rows = db.query(
            f"SELECT CAST(ts / ? AS INTEGER) * ? AS b, {expr} AS v FROM heartbeats "
            f"WHERE check_id = ? AND ts >= ? AND ts <= ? GROUP BY b ORDER BY b",
            (step, step, c["id"], start, end),
        )
        out.append({"name": c["name"], "unit": "ms" if field == "latency" else "%", "check_id": c["id"],
                    "points": [[r["b"], r["v"]] for r in rows if r["v"] is not None]})
    return out


def _syslog_series(db: Database, target: dict[str, Any], start: float, end: float, step: int) -> list[dict[str, Any]]:
    f = syslog_search.SyslogFilter.from_params({**target, "start": start, "end": end})
    buckets = max(1, int((end - start) / step))
    hist = syslog_search.histogram(db, f, buckets)
    split = target.get("split", True)
    if split:
        return [
            {"name": name, "unit": "msgs", "color": color,
             "points": [[b["ts"], b[field]] for b in hist["buckets"]]}
            for field, name, color in (("error", "error+", "red"), ("warning", "warning", "orange"),
                                       ("info", "notice/info", "blue"))
        ]
    return [{"name": target.get("alias") or "messages", "unit": "msgs",
             "points": [[b["ts"], b["error"] + b["warning"] + b["info"]] for b in hist["buckets"]]}]


def reduce_series(series: list[dict[str, Any]], how: str = "last") -> float | None:
    values = [p[1] for s in series for p in s["points"] if p[1] is not None]
    if not values:
        return None
    if how == "last":
        lasts = [s["points"][-1][1] for s in series if s["points"]]
        return sum(lasts) if len(lasts) > 1 else (lasts[0] if lasts else None)
    if how == "avg":
        return sum(values) / len(values)
    if how == "max":
        return max(values)
    if how == "min":
        return min(values)
    if how == "sum":
        return sum(values)
    return values[-1]


# ---------------------------------------------------------------- panel data
def panel_data(db: Database, panel: dict[str, Any], start: float, end: float) -> dict[str, Any]:
    ptype = panel.get("type")
    opts = panel.get("options") or {}
    targets = panel.get("targets") or []
    if ptype == "timeseries":
        series = []
        for t in targets:
            series.extend(query_target(db, t, start, end))
        return {"series": series[:MAX_SERIES]}
    if ptype in ("stat", "gauge"):
        series = []
        for t in targets:
            series.extend(query_target(db, t, start, end))
        reducer = opts.get("reduce", "last")
        if reducer == "last" and targets and (targets[0].get("source") or "metric") == "metric" \
                and (targets[0].get("agg") or "each") != "each":
            value = series[0]["points"][-1][1] if series and series[0]["points"] else None
        else:
            value = reduce_series(series, reducer)
        unit = opts.get("unit") or (series[0]["unit"] if series else (target_unit(db, targets[0]) if targets else ""))
        spark = []
        if series:
            merged: dict[int, float] = {}
            for s in series:
                for ts, v in s["points"]:
                    merged[ts] = merged.get(ts, 0) + v
            spark = sorted(merged.items())
        return {"value": value, "unit": unit, "sparkline": spark[-120:]}
    if ptype == "table":
        t = targets[0] if targets else {}
        metrics = resolve_metrics(db, t)
        order = opts.get("order", "desc")
        metrics = [m for m in metrics if m["last_value"] is not None]
        metrics.sort(key=lambda m: m["last_value"], reverse=(order != "asc"))
        limit = int(opts.get("limit") or t.get("limit") or 10)
        speeds = {}
        if t.get("key", "").startswith("if."):
            speeds = {(r["device_id"], str(r["if_index"])): r["speed"]
                      for r in db.query("SELECT device_id, if_index, speed FROM interfaces")}
        rows = []
        for m in metrics[:limit]:
            speed = speeds.get((m["device_id"], m["instance"]))
            rows.append({
                "device": m["device_name"], "device_id": m["device_id"], "label": m["label"] or m["key"],
                "key": m["key"], "value": m["last_value"], "unit": m["unit"], "ts": m["last_ts"],
                "util": (m["last_value"] / speed * 100) if speed and m["unit"] == "bps" else None,
                "metric_id": m["id"],
            })
        return {"rows": rows}
    if ptype == "status":
        what = opts.get("of", "devices")
        tag = opts.get("tag") or ""
        if what == "checks":
            now = time.time()
            items = []
            for c in db.query("SELECT * FROM checks WHERE enabled = 1 ORDER BY name COLLATE NOCASE"):
                items.append({"id": c["id"], "name": c["name"], "state": c["state"], "since": c["state_since"],
                              "latency": c["last_latency_ms"], "link": f"/checks/{c['id']}",
                              "uptime": reports.availability(db, c, now - 86400, now, now)["uptime_pct"]})
        else:
            rows = db.query("SELECT * FROM devices WHERE enabled = 1 ORDER BY name COLLATE NOCASE")
            if tag:
                rows = [d for d in rows if tag in loads(d["tags"], [])]
            items = [{"id": d["id"], "name": d["name"], "state": d["status"], "since": d["status_since"],
                      "detail": d["hostname"], "link": f"/devices/{d['id']}"} for d in rows]
        return {"items": items, "of": what}
    if ptype == "uptime":
        now = time.time()
        days = int(opts.get("days") or 30)
        checks = db.query("SELECT * FROM checks WHERE enabled = 1 ORDER BY name COLLATE NOCASE")
        if opts.get("public_only"):
            checks = [c for c in checks if c["public"]]
        ids = opts.get("checks")
        if ids:
            checks = [c for c in checks if c["id"] in ids]
        items = []
        for c in checks[: int(opts.get("limit") or 50)]:
            items.append({
                "id": c["id"], "name": c["name"], "state": c["state"],
                "uptime": reports.availability(db, c, start, end, now)["uptime_pct"],
                "daily": reports.daily_bars(db, c, days, now),
            })
        return {"items": items}
    if ptype == "syslog_histogram":
        t = targets[0] if targets else {}
        f = syslog_search.SyslogFilter.from_params({**t, "start": start, "end": end})
        return syslog_search.histogram(db, f, int(opts.get("buckets") or 80))
    if ptype == "syslog_stream":
        t = targets[0] if targets else {}
        f = syslog_search.SyslogFilter.from_params({**t, "start": start, "end": end})
        return {"rows": syslog_search.search(db, f, int(opts.get("limit") or 25))}
    if ptype == "syslog_top":
        t = targets[0] if targets else {}
        f = syslog_search.SyslogFilter.from_params({**t, "start": start, "end": end})
        return {"rows": syslog_search.top(db, f, opts.get("field", "host"), int(opts.get("limit") or 10)),
                "field": opts.get("field", "host")}
    if ptype == "alerts":
        rows = db.query(
            "SELECT * FROM alerts WHERE state = 'firing' ORDER BY CASE severity WHEN 'critical' THEN 0 "
            "WHEN 'warning' THEN 1 ELSE 2 END, fired_at DESC LIMIT ?", (int(opts.get("limit") or 20),))
        return {"rows": rows}
    if ptype == "events":
        rows = db.query("SELECT * FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC, id DESC LIMIT ?",
                        (start, end, int(opts.get("limit") or 20)))
        return {"rows": rows}
    if ptype == "summary":
        return services.overview(db)
    if ptype == "text":
        return {"text": opts.get("text", "")}
    return {"error": f"unknown panel type {ptype!r}"}


# ---------------------------------------------------------------- storage
def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "dashboard"


def public_dashboard(row: dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["config"] = loads(d.get("config"), {})
    return d


def normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    config = dict(config or {})
    config.setdefault("time", "24h")
    config.setdefault("refresh", 60)
    panels = []
    for i, p in enumerate(config.get("panels") or []):
        if p.get("type") not in PANEL_TYPES:
            raise ValueError(f"unknown panel type {p.get('type')!r}")
        panels.append({
            "id": p.get("id") or f"p{i + 1}",
            "type": p["type"],
            "title": p.get("title") or PANEL_TYPES[p["type"]],
            "w": max(1, min(12, int(p.get("w") or 6))),
            "h": max(1, min(4, int(p.get("h") or 2))),
            "options": p.get("options") or {},
            "targets": p.get("targets") or [],
        })
    config["panels"] = panels
    return config


def save_dashboard(db: Database, values: dict[str, Any], dashboard_id: int | None = None) -> dict[str, Any]:
    now = time.time()
    name = (values.get("name") or "").strip()
    config = normalize_config(values.get("config") or {})
    if dashboard_id is None:
        if not name:
            raise ValueError("name is required")
        slug = base = slugify(values.get("slug") or name)
        n = 2
        while db.one("SELECT 1 FROM dashboards WHERE slug = ?", (slug,)):
            slug = f"{base}-{n}"
            n += 1
        position = (db.scalar("SELECT MAX(position) FROM dashboards") or 0) + 1
        dashboard_id = db.insert("dashboards", {
            "name": name, "slug": slug, "description": values.get("description") or "",
            "config": json.dumps(config), "position": values.get("position", position),
            "created_at": now, "updated_at": now,
        })
    else:
        current = db.one("SELECT * FROM dashboards WHERE id = ?", (dashboard_id,))
        if not current:
            raise KeyError(dashboard_id)
        changes: dict[str, Any] = {"updated_at": now}
        if name:
            changes["name"] = name
        if "description" in values:
            changes["description"] = values["description"] or ""
        if "config" in values:
            changes["config"] = json.dumps(config)
        if "position" in values:
            changes["position"] = int(values["position"])
        db.update("dashboards", dashboard_id, changes)
    return public_dashboard(db.one("SELECT * FROM dashboards WHERE id = ?", (dashboard_id,)))


def _p(type_: str, title: str, w: int, h: int, targets: list | None = None, **options: Any) -> dict[str, Any]:
    return {"type": type_, "title": title, "w": w, "h": h, "targets": targets or [], "options": options}


DEFAULT_DASHBOARDS: list[dict[str, Any]] = [
    {
        "name": "Network Overview",
        "description": "Everything at a glance: health, traffic, availability and logs.",
        "config": {"time": "24h", "refresh": 60, "panels": [
            _p("summary", "Overview", 12, 1),
            _p("timeseries", "Total traffic (all interfaces)", 8, 2, [
                {"key": "if.in_bps", "agg": "sum", "alias": "Inbound"},
                {"key": "if.out_bps", "agg": "sum", "alias": "Outbound"}], chart="area"),
            _p("alerts", "Firing alerts", 4, 2, limit=10),
            _p("status", "Devices", 6, 2, of="devices"),
            _p("status", "Availability checks", 6, 2, of="checks"),
            _p("table", "Busiest interfaces (inbound)", 6, 2, [{"key": "if.in_bps"}], limit=8),
            _p("table", "Highest CPU", 6, 2, [{"key": "cpu.avg"}], limit=8),
            _p("syslog_histogram", "Syslog volume", 8, 2, [{}]),
            _p("events", "Recent events", 4, 2, limit=12),
        ]},
    },
    {
        "name": "Traffic & Interfaces",
        "description": "Per-interface bandwidth, utilisation, errors and discards.",
        "config": {"time": "24h", "refresh": 60, "panels": [
            _p("timeseries", "Busiest interfaces - inbound", 6, 2, [{"key": "if.in_bps", "limit": 8}], chart="line"),
            _p("timeseries", "Busiest interfaces - outbound", 6, 2, [{"key": "if.out_bps", "limit": 8}], chart="line"),
            _p("table", "Highest utilisation (in)", 4, 2, [{"key": "if.in_util"}], limit=10),
            _p("table", "Highest utilisation (out)", 4, 2, [{"key": "if.out_util"}], limit=10),
            _p("table", "Most input errors", 4, 2, [{"key": "if.in_errors"}], limit=10),
            _p("timeseries", "Interface errors", 6, 2, [{"key": "if.*_errors", "limit": 8}], chart="bar"),
            _p("timeseries", "Interface discards", 6, 2, [{"key": "if.*_discards", "limit": 8}], chart="bar"),
        ]},
    },
    {
        "name": "Server & Device Health",
        "description": "CPU, memory, storage and SNMP responsiveness.",
        "config": {"time": "24h", "refresh": 60, "panels": [
            _p("gauge", "Average CPU (all devices)", 3, 1, [{"key": "cpu.avg", "agg": "avg"}], max=100, unit="%",
               thresholds=[70, 90]),
            _p("gauge", "Average memory used", 3, 1, [{"key": "mem.used_pct", "agg": "avg"}], max=100, unit="%",
               thresholds=[80, 95]),
            _p("stat", "Fullest disk", 3, 1, [{"key": "storage.used_pct", "agg": "max"}], unit="%", thresholds=[80, 90]),
            _p("stat", "Slowest SNMP response", 3, 1, [{"key": "snmp.response_ms", "agg": "max"}], unit="ms",
               thresholds=[500, 1500]),
            _p("timeseries", "CPU by device", 6, 2, [{"key": "cpu.avg", "limit": 8}], chart="line", y_max=100),
            _p("timeseries", "Memory used by device", 6, 2, [{"key": "mem.used_pct", "limit": 8}], chart="line",
               y_max=100),
            _p("table", "Storage used", 6, 2, [{"key": "storage.used_pct"}], limit=15),
            _p("timeseries", "SNMP response time", 6, 2, [{"key": "snmp.response_ms", "limit": 8}], chart="line"),
        ]},
    },
    {
        "name": "Availability",
        "description": "Uptime Robot style view of every check.",
        "config": {"time": "30d", "refresh": 60, "panels": [
            _p("uptime", "Uptime (last 30 days)", 12, 3, days=30),
            _p("timeseries", "Response time", 8, 2, [{"source": "check", "check": "*", "field": "latency", "limit": 8}],
               chart="line"),
            _p("status", "Current state", 4, 2, of="checks"),
        ]},
    },
    {
        "name": "Syslog",
        "description": "Log volume, noisy hosts and recent errors.",
        "config": {"time": "24h", "refresh": 30, "panels": [
            _p("timeseries", "Messages by severity", 8, 2, [{"source": "syslog"}], chart="stacked"),
            _p("stat", "Errors (err and worse)", 4, 1, [{"source": "syslog", "severity": 3, "split": False}],
               reduce="sum", unit="msgs", thresholds=[50, 200]),
            _p("stat", "Messages", 4, 1, [{"source": "syslog", "split": False}], reduce="sum", unit="msgs"),
            _p("syslog_top", "Top hosts", 4, 2, [{}], field="host"),
            _p("syslog_top", "Top applications", 4, 2, [{}], field="app"),
            _p("syslog_top", "By severity", 4, 2, [{}], field="severity"),
            _p("syslog_stream", "Latest errors", 12, 2, [{"severity": 3}], limit=20),
        ]},
    },
]


def seed_dashboards(db: Database) -> int:
    if db.get_meta("dashboards_seeded"):
        return 0
    n = 0
    for i, d in enumerate(DEFAULT_DASHBOARDS):
        if not db.one("SELECT 1 FROM dashboards WHERE slug = ?", (slugify(d["name"]),)):
            save_dashboard(db, {**d, "position": i})
            n += 1
    db.set_meta("dashboards_seeded", str(time.time()))
    return n
