"""Grafana integration.

SNMPathy speaks the protocol of the Grafana *JSON* data source plugin
(``simpod-json-datasource``) under ``/grafana``, and ships ready-made
Grafana dashboards that use it. Point the data source at
``http://<snmpathy>:8080/grafana`` (add an ``X-API-Key`` header when an
API token is configured) or use the bundled docker-compose stack, which
provisions everything automatically.

Query targets
-------------
``metric``        SNMP metric time series (payload: key, device, tag, instance, agg, limit)
``check``         check response time / availability (payload: check, device, field)
``syslog``        syslog message counts (payload: q, severity, host, app, split)
``devices``       table of devices and their status
``checks``        table of checks with uptime
``interfaces``    table of interfaces with current traffic
``alerts``        table of firing alerts
``syslog_events`` table of syslog messages
``events``        table of SNMPathy events (state changes, reboots, ...)
``top``           table of devices/instances ranked by a metric's latest value
``count``         single value: devices_down, checks_down, alerts_firing, ...
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request

from . import dashboards, reports
from .db import Database
from .snmp.mibs import METRIC_INFO
from .syslog import search as syslog_search
from .syslog.parser import SEVERITIES

router = APIRouter(prefix="/grafana", tags=["grafana"])

DATASOURCE_TYPE = "simpod-json-datasource"
DATASOURCE_UID = "snmpathy"

GRAFANA_UNITS = {"bps": "bps", "%": "percent", "ms": "ms", "B": "bytes", "s": "s", "/s": "pps", "msgs": "short"}


def _db(request: Request) -> Database:
    return request.app.state.db


def _ts(value: Any, default: float) -> float:
    if not value:
        return default
    if isinstance(value, (int, float)):
        return float(value) / (1000 if value > 1e11 else 1)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return default


def grafana_value(value: Any) -> Any:
    """Undo Grafana's regex formatting of template variables.

    ``core\\-sw01`` -> ``core-sw01``; ``(a|b)`` -> ``["a", "b"]``; "All" -> ``"*"``.
    """
    if isinstance(value, list):
        out: list[Any] = []
        for v in value:
            parsed = grafana_value(v)
            out.extend(parsed if isinstance(parsed, list) else [parsed])
        return out
    if value is None:
        return None
    text = str(value).strip()
    if text in ("$__all", "All", "all", ".*", "*"):
        return "*"
    if text.startswith("(") and text.endswith(")") and "|" in text:
        return [re.sub(r"\\(.)", r"\1", part) for part in text[1:-1].split("|")]
    if text.startswith("{") and text.endswith("}") and "," in text:
        return [part.strip() for part in text[1:-1].split(",")]
    return re.sub(r"\\(.)", r"\1", text)


def _payload(target: dict[str, Any]) -> dict[str, Any]:
    payload = target.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload) if payload.strip() else {}
        except ValueError:
            payload = {}
    return {k: grafana_value(v) for k, v in payload.items() if v not in (None, "")}


# ------------------------------------------------------------------ endpoints
@router.get("")
@router.get("/")
def health():
    return {"status": "ok", "service": "snmpathy"}


@router.post("/metrics")
async def metrics(request: Request):
    db = _db(request)
    keys = sorted({r["key"] for r in db.query("SELECT DISTINCT key FROM metrics")} | set(METRIC_INFO))
    devices = [{"label": "All devices", "value": "*"}] + [
        {"label": d["name"], "value": d["name"]} for d in db.query("SELECT name FROM devices ORDER BY name COLLATE NOCASE")]
    checks = [{"label": "All checks", "value": "*"}] + [
        {"label": c["name"], "value": str(c["id"])} for c in db.query("SELECT id, name FROM checks ORDER BY name")]
    agg = [{"label": x, "value": x} for x in ("each", "sum", "avg", "max", "min")]
    sev = [{"label": f"{s} and worse", "value": str(i)} for i, s in enumerate(SEVERITIES)]
    key_opts = [{"label": f"{k} - {METRIC_INFO[k]['name']}" if k in METRIC_INFO else k, "value": k} for k in keys]
    return [
        {"label": "SNMP metric (time series)", "value": "metric", "payloads": [
            {"name": "key", "label": "Metric", "type": "select", "options": key_opts, "width": 40},
            {"name": "device", "label": "Device", "type": "multi-select", "options": devices},
            {"name": "tag", "label": "Tag", "type": "input"},
            {"name": "instance", "label": "Instance / label (glob)", "type": "input"},
            {"name": "agg", "label": "Aggregate", "type": "select", "options": agg},
            {"name": "limit", "label": "Max series", "type": "input", "placeholder": "10"},
        ]},
        {"label": "Check response time / availability", "value": "check", "payloads": [
            {"name": "check", "label": "Check", "type": "multi-select", "options": checks},
            {"name": "field", "label": "Field", "type": "select",
             "options": [{"label": "Response time (ms)", "value": "latency"}, {"label": "Availability (%)", "value": "up"}]},
        ]},
        {"label": "Syslog message count", "value": "syslog", "payloads": [
            {"name": "q", "label": "Search", "type": "input"},
            {"name": "severity", "label": "Severity", "type": "select", "options": sev},
            {"name": "host", "label": "Host", "type": "input"},
            {"name": "split", "label": "Split by severity", "type": "select",
             "options": [{"label": "yes", "value": "true"}, {"label": "no", "value": "false"}]},
        ]},
        {"label": "Counter (single value)", "value": "count", "payloads": [
            {"name": "what", "type": "select", "options": [{"label": k, "value": k} for k in COUNTERS]}]},
        {"label": "Table: devices", "value": "devices", "payloads": [{"name": "tag", "type": "input"}]},
        {"label": "Table: checks & uptime", "value": "checks", "payloads": []},
        {"label": "Table: interfaces", "value": "interfaces", "payloads": [
            {"name": "device", "label": "Device", "type": "multi-select", "options": devices}]},
        {"label": "Table: firing alerts", "value": "alerts", "payloads": []},
        {"label": "Table: syslog messages", "value": "syslog_events", "payloads": [
            {"name": "q", "type": "input"}, {"name": "severity", "type": "select", "options": sev},
            {"name": "host", "type": "input"}, {"name": "limit", "type": "input"}]},
        {"label": "Table: events", "value": "events", "payloads": [{"name": "device", "type": "multi-select", "options": devices}]},
        {"label": "Table: top N by metric", "value": "top", "payloads": [
            {"name": "key", "label": "Metric", "type": "select", "options": key_opts},
            {"name": "device", "type": "multi-select", "options": devices}, {"name": "limit", "type": "input"}]},
    ]


@router.post("/metric-payload-options")
async def metric_payload_options(request: Request):
    body = await request.json()
    db = _db(request)
    name = body.get("name")
    if name == "device":
        return [{"label": "All devices", "value": "*"}] + [
            {"label": d["name"], "value": d["name"]} for d in db.query("SELECT name FROM devices ORDER BY name")]
    if name == "key":
        return [{"label": k, "value": k} for k in sorted({r["key"] for r in db.query("SELECT DISTINCT key FROM metrics")})]
    return []


@router.post("/variable")
async def variable(request: Request):
    """Template variables: ``devices``, ``tags``, ``checks``, ``keys``, ``interfaces``, ``hosts``."""
    body = await request.json()
    db = _db(request)
    payload = body.get("payload") or {}
    if isinstance(payload, str):
        payload = {"target": payload}
    target = str(payload.get("target") or "").strip()
    name, _, arg = target.partition(" ")
    if name in ("devices", "device"):
        rows = db.query("SELECT name, tags FROM devices WHERE enabled = 1 ORDER BY name COLLATE NOCASE")
        tag = grafana_value(arg) if arg else None
        return [{"__text": r["name"], "__value": r["name"]} for r in rows
                if not tag or tag == "*" or tag in json.loads(r["tags"] or "[]")]
    if name == "tags":
        tags = sorted({t for r in db.query("SELECT tags FROM devices") for t in json.loads(r["tags"] or "[]")})
        return [{"__text": t, "__value": t} for t in tags]
    if name == "checks":
        return [{"__text": r["name"], "__value": str(r["id"])} for r in db.query("SELECT id, name FROM checks ORDER BY name")]
    if name == "keys":
        return [{"__text": r["key"], "__value": r["key"]} for r in db.query("SELECT DISTINCT key FROM metrics ORDER BY key")]
    if name == "interfaces":
        dev = grafana_value(arg) if arg else "*"
        sel = dashboards._device_filter(db, {"device": dev})
        if not sel:
            return []
        marks = ",".join("?" for _ in sel)
        rows = db.query(f"SELECT DISTINCT name FROM interfaces WHERE device_id IN ({marks}) ORDER BY name", list(sel))
        return [{"__text": r["name"], "__value": r["name"]} for r in rows]
    if name == "hosts":
        rows = db.query("SELECT host, COUNT(*) AS n FROM syslog WHERE ts > ? GROUP BY host ORDER BY n DESC LIMIT 200",
                        (time.time() - 7 * 86400,))
        return [{"__text": r["host"], "__value": r["host"]} for r in rows if r["host"]]
    return []


@router.post("/tag-keys")
async def tag_keys():
    return [{"type": "string", "text": "device"}, {"type": "string", "text": "tag"}]


@router.post("/tag-values")
async def tag_values(request: Request):
    body = await request.json()
    db = _db(request)
    if body.get("key") == "tag":
        tags = sorted({t for r in db.query("SELECT tags FROM devices") for t in json.loads(r["tags"] or "[]")})
        return [{"text": t} for t in tags]
    return [{"text": d["name"]} for d in db.query("SELECT name FROM devices ORDER BY name")]


@router.post("/query")
async def query(request: Request):
    body = await request.json()
    db = _db(request)
    now = time.time()
    rng = body.get("range") or {}
    start = _ts(rng.get("from"), now - 6 * 3600)
    end = _ts(rng.get("to"), now)
    max_points = int(body.get("maxDataPoints") or dashboards.TARGET_POINTS)
    interval_ms = body.get("intervalMs")
    filters = {f.get("key"): f.get("value") for f in (body.get("adhocFilters") or body.get("filters") or [])
               if f.get("operator", "=") == "="}
    out: list[dict[str, Any]] = []
    for t in body.get("targets") or []:
        if t.get("hide"):
            continue
        kind = t.get("target") or "metric"
        payload = _payload(t)
        for k, v in filters.items():
            payload.setdefault(k, v)
        out.extend(run_target(db, kind, payload, start, end, max_points, interval_ms, t.get("refId")))
    return out


COUNTERS = {
    "devices_total": "SELECT COUNT(*) FROM devices WHERE enabled = 1",
    "devices_up": "SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'up'",
    "devices_down": "SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'down'",
    "checks_up": "SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'up'",
    "checks_down": "SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'down'",
    "alerts_firing": "SELECT COUNT(*) FROM alerts WHERE state = 'firing'",
    "alerts_critical": "SELECT COUNT(*) FROM alerts WHERE state = 'firing' AND severity = 'critical'",
    "interfaces_down": "SELECT COUNT(*) FROM interfaces WHERE admin_status = 1 AND oper_status = 2",
}


def run_target(db: Database, kind: str, payload: dict[str, Any], start: float, end: float,
               max_points: int = 300, interval_ms: float | None = None, ref_id: str | None = None) -> list[dict[str, Any]]:
    span = max(60.0, end - start)
    step = None
    if interval_ms:
        step = dashboards.nice_step(max(float(interval_ms) / 1000, span / max(1, max_points)), 30)
    if kind in ("metric", "check", "syslog"):
        target = {**payload, "source": kind}
        if kind == "syslog":
            target["split"] = str(payload.get("split", "true")).lower() not in ("false", "0", "no")
        series = dashboards.query_target(db, target, start, end, step)
        return [{"target": s["name"], "refId": ref_id,
                 "datapoints": [[v, int(ts * 1000)] for ts, v in s["points"]]} for s in series]
    if kind == "count":
        what = str(payload.get("what") or "devices_down")
        if what not in COUNTERS:
            return []
        value = db.scalar(COUNTERS[what]) or 0
        return [{"target": what, "refId": ref_id, "datapoints": [[value, int(end * 1000)]]}]
    if kind == "devices":
        rows = dashboards._device_filter(db, payload).values()
        return [_table(
            [("Device", "string"), ("Hostname", "string"), ("Status", "string"), ("Vendor", "string"),
             ("Location", "string"), ("Uptime (s)", "number"), ("Last polled", "time")],
            [[d["name"], d["hostname"], d["status"], d["vendor"], d["location"], d["sys_uptime"],
              int((d["last_polled"] or 0) * 1000) or None] for d in rows])]
    if kind == "checks":
        now = time.time()
        rows = []
        for c in db.query("SELECT * FROM checks WHERE enabled = 1 ORDER BY name COLLATE NOCASE"):
            a = reports.availability(db, c, start, end, now)
            rows.append([c["name"], c["type"], c["target"], c["state"], c["last_latency_ms"],
                         a["uptime_pct"], a["outages"], a["downtime_seconds"]])
        return [_table([("Check", "string"), ("Type", "string"), ("Target", "string"), ("State", "string"),
                        ("Response (ms)", "number"), ("Uptime %", "number"), ("Outages", "number"),
                        ("Downtime (s)", "number")], rows)]
    if kind == "interfaces":
        devices = dashboards._device_filter(db, payload)
        if not devices:
            return [_table([("Device", "string")], [])]
        marks = ",".join("?" for _ in devices)
        rows = db.query(f"SELECT * FROM interfaces WHERE device_id IN ({marks}) ORDER BY device_id, if_index", list(devices))
        from .snmp.mibs import IF_OPER_STATUS_NAMES

        return [_table(
            [("Device", "string"), ("Interface", "string"), ("Description", "string"), ("Status", "string"),
             ("Speed (bps)", "number"), ("In (bps)", "number"), ("Out (bps)", "number"), ("In util %", "number"),
             ("Out util %", "number")],
            [[devices[r["device_id"]]["name"], r["name"], r["alias"], IF_OPER_STATUS_NAMES.get(r["oper_status"], "?"),
              r["speed"], r["in_bps"], r["out_bps"],
              (r["in_bps"] / r["speed"] * 100) if r["speed"] and r["in_bps"] is not None else None,
              (r["out_bps"] / r["speed"] * 100) if r["speed"] and r["out_bps"] is not None else None] for r in rows])]
    if kind == "alerts":
        rows = db.query("SELECT * FROM alerts WHERE state = 'firing' ORDER BY fired_at DESC")
        return [_table([("Fired", "time"), ("Severity", "string"), ("Subject", "string"), ("Message", "string"),
                        ("Acknowledged", "string")],
                       [[int(r["fired_at"] * 1000), r["severity"], r["subject"], r["message"],
                         "yes" if r["acknowledged"] else "no"] for r in rows])]
    if kind == "syslog_events":
        f = syslog_search.SyslogFilter.from_params({**payload, "start": start, "end": end})
        rows = syslog_search.search(db, f, int(payload.get("limit") or 200))
        return [_table([("Time", "time"), ("Host", "string"), ("Severity", "string"), ("App", "string"),
                        ("Message", "string")],
                       [[int(r["ts"] * 1000), r["host"], r["severity_name"], r["app"], r["message"]] for r in rows])]
    if kind == "events":
        devices = dashboards._device_filter(db, payload) if payload.get("device") else None
        rows = db.query("SELECT * FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT 500", (start, end))
        if devices is not None:
            rows = [r for r in rows if r["device_id"] in devices]
        return [_table([("Time", "time"), ("Level", "string"), ("Type", "string"), ("Message", "string")],
                       [[int(r["ts"] * 1000), r["level"], r["type"], r["message"]] for r in rows])]
    if kind == "top":
        data = dashboards.panel_data(db, {"type": "table", "targets": [payload],
                                          "options": {"limit": int(payload.get("limit") or 10)}}, start, end)
        return [_table([("Device", "string"), ("Instance", "string"), ("Value", "number"), ("Unit", "string")],
                       [[r["device"], r["label"], r["value"], r["unit"]] for r in data["rows"]])]
    return []


def _table(columns: list[tuple[str, str]], rows: list[list[Any]]) -> dict[str, Any]:
    return {"type": "table", "columns": [{"text": c, "type": t} for c, t in columns], "rows": rows}


# ----------------------------------------------------------- dashboard JSON
class _Builder:
    def __init__(self, uid: str, title: str, description: str, tags: list[str], time_from: str = "now-24h"):
        self.uid, self.title, self.description, self.tags = uid, title, description, tags
        self.time_from = time_from
        self.panels: list[dict[str, Any]] = []
        self.variables: list[dict[str, Any]] = []
        self._x = 0
        self._y = 0
        self._row_h = 0

    def _pos(self, w: int, h: int) -> dict[str, int]:
        if self._x + w > 24:
            self._x = 0
            self._y += self._row_h
            self._row_h = 0
        pos = {"x": self._x, "y": self._y, "w": w, "h": h}
        self._x += w
        self._row_h = max(self._row_h, h)
        return pos

    def variable(self, name: str, query: str, label: str, multi: bool = True, include_all: bool = True) -> "_Builder":
        self.variables.append({
            "name": name, "label": label, "type": "query",
            "datasource": {"type": DATASOURCE_TYPE, "uid": DATASOURCE_UID},
            "query": {"query": query, "format": "string", "refId": f"var-{name}"},
            "definition": query, "refresh": 1, "multi": multi, "includeAll": include_all,
            "allValue": "*", "current": {"selected": True, "text": ["All"], "value": ["$__all"]} if include_all else {},
            "sort": 1,
        })
        return self

    def panel(self, ptype: str, title: str, w: int, h: int, targets: list[tuple[str, dict[str, Any]]],
              unit: str = "", **extra: Any) -> "_Builder":
        panel: dict[str, Any] = {
            "id": len(self.panels) + 1, "type": ptype, "title": title, "gridPos": self._pos(w, h),
            "datasource": {"type": DATASOURCE_TYPE, "uid": DATASOURCE_UID},
            "targets": [{"refId": chr(65 + i), "datasource": {"type": DATASOURCE_TYPE, "uid": DATASOURCE_UID},
                         "target": kind, "payload": payload, "editorMode": "builder"}
                        for i, (kind, payload) in enumerate(targets)],
            "fieldConfig": {"defaults": {}, "overrides": []},
            "options": {},
        }
        defaults = panel["fieldConfig"]["defaults"]
        if unit:
            defaults["unit"] = GRAFANA_UNITS.get(unit, unit)
        if ptype == "timeseries":
            defaults["custom"] = {"drawStyle": extra.pop("draw", "line"), "fillOpacity": extra.pop("fill", 10),
                                  "lineWidth": 1, "showPoints": "never", "spanNulls": 600000,
                                  "stacking": {"mode": extra.pop("stack", "none")}}
            panel["options"] = {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max", "lastNotNull"]},
                                "tooltip": {"mode": "multi", "sort": "desc"}}
        elif ptype in ("stat", "gauge"):
            panel["options"] = {"reduceOptions": {"calcs": [extra.pop("calc", "lastNotNull")], "fields": "", "values": False},
                                "colorMode": "background" if ptype == "stat" else "value", "graphMode": "area"}
            steps = [{"color": "green", "value": None}]
            for value, color in zip(extra.pop("thresholds", []), ("orange", "red")):
                steps.append({"color": color, "value": value})
            defaults["thresholds"] = {"mode": "absolute", "steps": steps}
            if "max" in extra:
                defaults["max"] = extra.pop("max")
                defaults["min"] = 0
        elif ptype == "table":
            panel["options"] = {"showHeader": True, "cellHeight": "sm"}
        defaults.update(extra.pop("defaults", {}))
        panel.update(extra)
        self.panels.append(panel)
        return self

    def build(self) -> dict[str, Any]:
        return {
            "uid": self.uid, "title": self.title, "description": self.description, "tags": ["snmpathy", *self.tags],
            "timezone": "browser", "schemaVersion": 39, "version": 1, "editable": True, "refresh": "1m",
            "time": {"from": self.time_from, "to": "now"},
            "templating": {"list": self.variables},
            "annotations": {"list": []},
            "links": [{"title": "SNMPathy dashboards", "type": "dashboards", "tags": ["snmpathy"], "asDropdown": True}],
            "panels": self.panels,
        }


def grafana_dashboards() -> dict[str, dict[str, Any]]:
    """The Grafana dashboards shipped with SNMPathy, keyed by file name."""
    D = "$device"
    overview = (
        _Builder("snmpathy-overview", "SNMPathy - Network Overview", "Health, traffic, availability and logs.", ["overview"])
        .variable("device", "devices", "Device")
        .panel("stat", "Devices down", 4, 4, [("count", {"what": "devices_down"})], thresholds=[1, 1])
        .panel("stat", "Firing alerts", 4, 4, [("count", {"what": "alerts_firing"})], thresholds=[1, 5])
        .panel("stat", "Total inbound", 4, 4, [("metric", {"key": "if.in_bps", "device": D, "agg": "sum"})], unit="bps")
        .panel("stat", "Total outbound", 4, 4, [("metric", {"key": "if.out_bps", "device": D, "agg": "sum"})], unit="bps")
        .panel("stat", "Avg CPU", 4, 4, [("metric", {"key": "cpu.avg", "device": D, "agg": "avg"})], unit="%",
               thresholds=[70, 90])
        .panel("stat", "Syslog errors", 4, 4, [("syslog", {"severity": "3", "split": "false"})], calc="sum",
               thresholds=[50, 200])
        .panel("timeseries", "Total traffic", 16, 8, [
            ("metric", {"key": "if.in_bps", "device": D, "agg": "sum", "alias": "Inbound"}),
            ("metric", {"key": "if.out_bps", "device": D, "agg": "sum", "alias": "Outbound"})], unit="bps", fill=25)
        .panel("table", "Firing alerts", 8, 8, [("alerts", {})])
        .panel("table", "Devices", 12, 9, [("devices", {})])
        .panel("table", "Availability", 12, 9, [("checks", {})],
               defaults={"custom": {"align": "auto"}})
        .panel("timeseries", "Syslog volume by severity", 24, 7, [("syslog", {"split": "true"})], unit="msgs",
               draw="bars", stack="normal", fill=80)
        .build()
    )
    device = (
        _Builder("snmpathy-device", "SNMPathy - Device", "Per-device drill down.", ["device"])
        .variable("device", "devices", "Device", multi=False, include_all=False)
        .panel("timeseries", "CPU", 12, 8, [("metric", {"key": "cpu.load", "device": D, "limit": "32"}),
                                             ("metric", {"key": "cpu.avg", "device": D})], unit="%",
               defaults={"max": 100, "min": 0})
        .panel("timeseries", "Memory & storage", 12, 8, [("metric", {"key": "mem.used_pct", "device": D}),
                                                          ("metric", {"key": "storage.used_pct", "device": D})],
               unit="%", defaults={"max": 100, "min": 0})
        .panel("timeseries", "Inbound traffic by interface", 12, 9,
               [("metric", {"key": "if.in_bps", "device": D, "limit": "15"})], unit="bps")
        .panel("timeseries", "Outbound traffic by interface", 12, 9,
               [("metric", {"key": "if.out_bps", "device": D, "limit": "15"})], unit="bps")
        .panel("timeseries", "Errors & discards", 12, 7,
               [("metric", {"key": "if.*_errors", "device": D, "limit": "10"}),
                ("metric", {"key": "if.*_discards", "device": D, "limit": "10"})], unit="/s", draw="bars")
        .panel("timeseries", "SNMP response time", 12, 7, [("metric", {"key": "snmp.response_ms", "device": D})], unit="ms")
        .panel("table", "Interfaces", 24, 10, [("interfaces", {"device": D})])
        .panel("table", "Events", 24, 8, [("events", {"device": D})])
        .build()
    )
    interfaces = (
        _Builder("snmpathy-interfaces", "SNMPathy - Traffic & Interfaces", "Bandwidth, utilisation and errors.", ["traffic"])
        .variable("device", "devices", "Device")
        .panel("timeseries", "Top inbound", 12, 9, [("metric", {"key": "if.in_bps", "device": D, "limit": "10"})], unit="bps")
        .panel("timeseries", "Top outbound", 12, 9, [("metric", {"key": "if.out_bps", "device": D, "limit": "10"})], unit="bps")
        .panel("timeseries", "Utilisation", 24, 8, [("metric", {"key": "if.*_util", "device": D, "limit": "15"})],
               unit="%", defaults={"max": 100, "min": 0})
        .panel("table", "Busiest interfaces", 12, 9, [("top", {"key": "if.in_bps", "device": D, "limit": "15"})])
        .panel("table", "Most errors", 12, 9, [("top", {"key": "if.in_errors", "device": D, "limit": "15"})])
        .build()
    )
    uptime = (
        _Builder("snmpathy-uptime", "SNMPathy - Availability", "Uptime, SLA and response times.", ["uptime"],
                 time_from="now-7d")
        .variable("check", "checks", "Check")
        .panel("table", "Uptime for the selected range", 24, 9, [("checks", {})])
        .panel("timeseries", "Response time", 24, 9, [("check", {"check": "$check", "field": "latency"})], unit="ms")
        .panel("timeseries", "Availability", 24, 7, [("check", {"check": "$check", "field": "up"})], unit="%",
               draw="bars", defaults={"max": 100, "min": 0})
        .build()
    )
    syslog = (
        _Builder("snmpathy-syslog", "SNMPathy - Syslog", "Log volume and messages.", ["syslog"])
        .variable("host", "hosts", "Host")
        .panel("timeseries", "Messages by severity", 24, 8, [("syslog", {"host": "$host", "split": "true"})], unit="msgs",
               draw="bars", stack="normal", fill=80)
        .panel("table", "Latest errors (err and worse)", 24, 10,
               [("syslog_events", {"severity": "3", "host": "$host", "limit": "200"})])
        .panel("table", "Latest messages", 24, 12, [("syslog_events", {"host": "$host", "limit": "500"})])
        .build()
    )
    return {
        "snmpathy-overview.json": overview,
        "snmpathy-device.json": device,
        "snmpathy-interfaces.json": interfaces,
        "snmpathy-uptime.json": uptime,
        "snmpathy-syslog.json": syslog,
    }


@router.get("/dashboards")
def list_grafana_dashboards():
    return [{"file": name, "uid": d["uid"], "title": d["title"]} for name, d in grafana_dashboards().items()]


@router.get("/dashboards/{name}")
def get_grafana_dashboard(name: str):
    boards = grafana_dashboards()
    if not name.endswith(".json"):
        name += ".json"
    if name not in boards:
        from fastapi import HTTPException

        raise HTTPException(404, "unknown dashboard")
    return boards[name]


def datasource_provisioning(url: str = "http://snmpathy:8080/grafana", token: str = "") -> str:
    lines = [
        "apiVersion: 1",
        "datasources:",
        "  - name: SNMPathy",
        f"    type: {DATASOURCE_TYPE}",
        f"    uid: {DATASOURCE_UID}",
        "    access: proxy",
        f"    url: {url}",
        "    isDefault: true",
        "    editable: true",
    ]
    if token:
        lines += ["    jsonData:", "      httpHeaderName1: X-API-Key", "    secureJsonData:",
                  f"      httpHeaderValue1: {token}"]
    return "\n".join(lines) + "\n"


def write_provisioning(directory: str, url: str = "http://snmpathy:8080/grafana", token: str = "${SNMPATHY_API_TOKEN}") -> list[str]:
    """Write Grafana provisioning files (datasource + dashboards) into ``directory``."""
    from pathlib import Path

    root = Path(directory)
    (root / "datasources").mkdir(parents=True, exist_ok=True)
    (root / "dashboards").mkdir(parents=True, exist_ok=True)
    (root / "dashboards" / "json").mkdir(parents=True, exist_ok=True)
    written = []
    ds = root / "datasources" / "snmpathy.yaml"
    ds.write_text(datasource_provisioning(url, token), encoding="utf-8")
    written.append(str(ds))
    provider = root / "dashboards" / "snmpathy.yaml"
    provider.write_text(
        "apiVersion: 1\nproviders:\n  - name: SNMPathy\n    folder: SNMPathy\n    type: file\n"
        "    disableDeletion: false\n    allowUiUpdates: true\n    options:\n"
        "      path: /etc/grafana/provisioning/dashboards/json\n", encoding="utf-8")
    written.append(str(provider))
    for name, board in grafana_dashboards().items():
        path = root / "dashboards" / "json" / name
        path.write_text(json.dumps(board, indent=2) + "\n", encoding="utf-8")
        written.append(str(path))
    return written
