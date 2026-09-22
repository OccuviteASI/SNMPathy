"""Server-rendered web UI."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import reports, services
from ..db import Database, loads
from ..snmp import mibs
from ..syslog.parser import FACILITIES, SEVERITIES, SEVERITY_LABELS

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
router = APIRouter(include_in_schema=False)


# ------------------------------------------------------------------ filters
from ..fmt import ago, fmt_bps, fmt_bytes, fmt_pct, fmt_speed, fmt_value  # noqa: E402


def ts_html(ts: Any, fmt: str = "datetime") -> str:
    """Emit a <time> element that app.js localises into the viewer's timezone."""
    if not ts:
        return "-"
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(ts)))
    return f'<time datetime="{iso}" data-ts="{float(ts):.3f}" data-fmt="{fmt}">{iso}</time>'


templates.env.filters.update(
    bps=fmt_bps, bytes=fmt_bytes, speed=fmt_speed, pct=fmt_pct, value=fmt_value, ago=ago,
    duration=reports.format_duration, ts=ts_html, loads=lambda v: loads(v, None),
)
templates.env.globals.update(
    SEVERITIES=SEVERITIES, SEVERITY_LABELS=SEVERITY_LABELS, FACILITIES=FACILITIES,
    IF_OPER=mibs.IF_OPER_STATUS_NAMES, METRIC_INFO=mibs.METRIC_INFO, now=time.time,
)


def db_of(request: Request) -> Database:
    return request.app.state.db


def render(request: Request, name: str, **context: Any) -> HTMLResponse:
    db = db_of(request)
    context.setdefault("nav", name.split(".")[0])
    context["problems"] = {
        "devices": db.scalar("SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'down'"),
        "checks": db.scalar("SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'down'"),
        "alerts": db.scalar("SELECT COUNT(*) FROM alerts WHERE state = 'firing'"),
    }
    context["auth_enabled"] = bool(request.app.state.settings.api_token)
    from .. import __version__

    context.setdefault("version", __version__)
    return templates.TemplateResponse(request, name, context)


# --------------------------------------------------------------------- pages
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    db = db_of(request)
    now = time.time()
    down_devices = db.query("SELECT * FROM devices WHERE enabled = 1 AND status = 'down' ORDER BY status_since")
    down_checks = db.query(
        "SELECT checks.*, devices.name AS device_name FROM checks LEFT JOIN devices ON devices.id = checks.device_id "
        "WHERE checks.enabled = 1 AND checks.state = 'down' ORDER BY checks.state_since")
    firing = db.query(
        "SELECT * FROM alerts WHERE state = 'firing' ORDER BY CASE severity WHEN 'critical' THEN 0 "
        "WHEN 'warning' THEN 1 ELSE 2 END, fired_at DESC LIMIT 50")
    top_ifaces = db.query(
        "SELECT interfaces.*, devices.name AS device_name, "
        "COALESCE(in_bps, 0) + COALESCE(out_bps, 0) AS total_bps FROM interfaces "
        "JOIN devices ON devices.id = interfaces.device_id WHERE devices.enabled = 1 "
        "ORDER BY total_bps DESC LIMIT 8")
    top_cpu = db.query(
        "SELECT metrics.*, devices.name AS device_name FROM metrics JOIN devices ON devices.id = metrics.device_id "
        "WHERE metrics.key = 'cpu.avg' AND metrics.last_value IS NOT NULL ORDER BY metrics.last_value DESC LIMIT 8")
    events = db.query("SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT 15")
    checks = db.query("SELECT * FROM checks WHERE enabled = 1")
    avail = [reports.availability(db, c, now - 86400, now, now)["uptime_pct"] for c in checks]
    avail = [a for a in avail if a is not None]
    return render(
        request, "dashboard.html",
        overview=services.overview(db),
        down_devices=down_devices, down_checks=down_checks, firing=firing,
        top_ifaces=top_ifaces, top_cpu=top_cpu, events=events,
        avg_availability=(sum(avail) / len(avail)) if avail else None,
    )


@router.get("/devices", response_class=HTMLResponse)
def devices(request: Request, tag: str = "", q: str = ""):
    db = db_of(request)
    rows = [services.public_device(d) for d in db.query("SELECT * FROM devices ORDER BY name COLLATE NOCASE")]
    all_tags = sorted({t for d in rows for t in d["tags"]})
    if tag:
        rows = [d for d in rows if tag in d["tags"]]
    counts = {r["device_id"]: r for r in db.query(
        "SELECT device_id, COUNT(*) AS ifaces, SUM(CASE WHEN admin_status = 1 AND oper_status = 2 THEN 1 ELSE 0 END) "
        "AS down FROM interfaces GROUP BY device_id")}
    cpu = {r["device_id"]: r["last_value"] for r in db.query(
        "SELECT device_id, last_value FROM metrics WHERE key = 'cpu.avg'")}
    mem = {r["device_id"]: r["last_value"] for r in db.query(
        "SELECT device_id, last_value FROM metrics WHERE key = 'mem.used_pct'")}
    return render(request, "devices.html", devices=rows, tags=all_tags, tag=tag, q=q,
                  counts=counts, cpu=cpu, mem=mem)


@router.get("/devices/new", response_class=HTMLResponse)
def device_new(request: Request):
    return render(request, "device_form.html", device=None, nav="devices")


@router.get("/devices/{device_id}/edit", response_class=HTMLResponse)
def device_edit(request: Request, device_id: int):
    device = db_of(request).one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not device:
        raise HTTPException(404)
    return render(request, "device_form.html", device=services.public_device(device), nav="devices")


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: int, tab: str = "overview"):
    db = db_of(request)
    device = db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not device:
        raise HTTPException(404)
    metrics = db.query("SELECT * FROM metrics WHERE device_id = ? ORDER BY key, CAST(instance AS INTEGER), instance",
                       (device_id,))
    by_key: dict[str, list[dict[str, Any]]] = {}
    for m in metrics:
        by_key.setdefault(m["key"], []).append(m)
    interfaces = db.query("SELECT * FROM interfaces WHERE device_id = ? ORDER BY if_index", (device_id,))
    iface_metrics: dict[str, dict[str, int]] = {}
    for m in metrics:
        if m["key"].startswith("if."):
            iface_metrics.setdefault(m["instance"], {})[m["key"]] = m["id"]
    checks = db.query("SELECT * FROM checks WHERE device_id = ? ORDER BY name", (device_id,))
    now = time.time()
    for c in checks:
        c["uptime_30d"] = reports.availability(db, c, now - 30 * 86400, now, now)["uptime_pct"]
    events = db.query("SELECT * FROM events WHERE device_id = ? ORDER BY ts DESC, id DESC LIMIT 50", (device_id,))
    alerts = db.query("SELECT * FROM alerts WHERE device_id = ? AND state = 'firing' ORDER BY fired_at DESC",
                      (device_id,))
    return render(
        request, "device.html", nav="devices", tab=tab,
        device=services.public_device(device), metrics=metrics, by_key=by_key,
        interfaces=interfaces, iface_metrics=iface_metrics, checks=checks, events=events, alerts=alerts,
    )


@router.get("/checks", response_class=HTMLResponse)
def checks(request: Request):
    db = db_of(request)
    now = time.time()
    rows = db.query(
        "SELECT checks.*, devices.name AS device_name FROM checks LEFT JOIN devices ON devices.id = checks.device_id "
        "ORDER BY CASE checks.state WHEN 'down' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, checks.name COLLATE NOCASE")
    for c in rows:
        c["options"] = loads(c["options"], {})
        c["uptime_24h"] = reports.availability(db, c, now - 86400, now, now)["uptime_pct"]
        c["uptime_30d"] = reports.availability(db, c, now - 30 * 86400, now, now)["uptime_pct"]
    devices = db.query("SELECT id, name, hostname FROM devices ORDER BY name COLLATE NOCASE")
    return render(request, "checks.html", checks=rows, devices=devices)


@router.get("/checks/{check_id}", response_class=HTMLResponse)
def check_detail(request: Request, check_id: int):
    db = db_of(request)
    check = db.one(
        "SELECT checks.*, devices.name AS device_name FROM checks LEFT JOIN devices ON devices.id = checks.device_id "
        "WHERE checks.id = ?", (check_id,))
    if not check:
        raise HTTPException(404)
    check["options"] = loads(check["options"], {})
    now = time.time()
    windows = {name: reports.availability(db, check, now - secs, now, now) for name, secs in reports.WINDOWS.items()}
    outages = db.query("SELECT * FROM outages WHERE check_id = ? ORDER BY started_at DESC LIMIT 50", (check_id,))
    devices = db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")
    return render(request, "check.html", nav="checks", check=check, windows=windows, outages=outages,
                  devices=devices)


@router.get("/syslog", response_class=HTMLResponse)
def syslog(request: Request):
    db = db_of(request)
    devices = db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")
    return render(request, "syslog.html", params=dict(request.query_params), devices=devices,
                  listening=(request.app.state.monitor.syslog.listening
                             if request.app.state.monitor and request.app.state.monitor.syslog else {}))


@router.get("/alerts", response_class=HTMLResponse)
def alerts(request: Request, tab: str = "active"):
    db = db_of(request)
    active = db.query(
        "SELECT alerts.*, alert_rules.name AS rule_name FROM alerts LEFT JOIN alert_rules ON alert_rules.id = alerts.rule_id "
        "WHERE alerts.state IN ('firing', 'pending') ORDER BY CASE alerts.state WHEN 'firing' THEN 0 ELSE 1 END, "
        "CASE alerts.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, alerts.started_at DESC")
    history = db.query(
        "SELECT alerts.*, alert_rules.name AS rule_name FROM alerts LEFT JOIN alert_rules ON alert_rules.id = alerts.rule_id "
        "WHERE alerts.state = 'resolved' ORDER BY alerts.resolved_at DESC LIMIT 200")
    rules = [services.public_rule(r) for r in db.query("SELECT * FROM alert_rules ORDER BY name COLLATE NOCASE")]
    channels = [services.public_channel(c) for c in db.query("SELECT * FROM channels ORDER BY name")]
    notifications = db.query(
        "SELECT notifications.*, channels.name AS channel_name, alerts.subject FROM notifications "
        "LEFT JOIN channels ON channels.id = notifications.channel_id "
        "LEFT JOIN alerts ON alerts.id = notifications.alert_id ORDER BY notifications.ts DESC LIMIT 100")
    devices = db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")
    metric_keys = [r["key"] for r in db.query("SELECT DISTINCT key FROM metrics ORDER BY key")]
    from ..alerting.notify import CHANNEL_TYPES

    return render(request, "alerts.html", tab=tab, active=active, history=history, rules=rules,
                  channels=channels, notifications=notifications, devices=devices,
                  metric_keys=sorted(set(metric_keys) | set(mibs.METRIC_INFO)), channel_types=CHANNEL_TYPES)


@router.get("/reports", response_class=HTMLResponse)
def reports_index(request: Request):
    from ..reporting import REPORT_TYPES

    db = db_of(request)
    schedules = db.query("SELECT * FROM report_schedules ORDER BY name")
    for s in schedules:
        s["channels"] = loads(s["channels"], [])
        s["options"] = loads(s["options"], {})
    channels = db.query("SELECT id, name, type FROM channels WHERE enabled = 1 ORDER BY name")
    devices = db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")
    return render(request, "reports.html", report_types=REPORT_TYPES, schedules=schedules, channels=channels,
                  devices=devices)


REPORT_RANGES = [("24h", "Last 24 hours"), ("7d", "Last 7 days"), ("30d", "Last 30 days"), ("90d", "Last 90 days"),
                 ("365d", "Last 12 months"), ("today", "Today"), ("yesterday", "Yesterday"),
                 ("this_week", "This week"), ("last_week", "Last week"), ("this_month", "This month"),
                 ("last_month", "Last month")]


@router.get("/reports/{report}", response_class=HTMLResponse)
def report_view(request: Request, report: str, range: str = "7d", device_id: str = "", tag: str = "",
                sla: str = ""):
    from .. import reporting

    if report not in reporting.REPORT_TYPES:
        raise HTTPException(404)
    db = db_of(request)
    dev = int(device_id) if device_id.isdigit() else None
    options: dict[str, Any] = {"device_id": dev, "tag": tag or None}
    if report == "uptime" and sla:
        try:
            options["sla_target"] = float(sla)
        except ValueError:
            pass
    data = reporting.build(db, report, range, **options)
    devices = db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")
    tags = sorted({t for r in db.query("SELECT tags FROM devices") for t in loads(r["tags"], [])})
    from urllib.parse import urlencode

    qs = urlencode({k: v for k, v in {"range": range, "device_id": dev, "tag": tag}.items() if v})
    return render(request, "report.html", nav="reports", report=data, report_id=report, range=range, qs=qs,
                  ranges=REPORT_RANGES, device_id=dev, tag=tag, devices=devices, tags=tags, sla=sla,
                  fmt=reporting.format_cell, report_types=reporting.REPORT_TYPES)


@router.get("/dashboards", response_class=HTMLResponse)
def dashboards_index(request: Request):
    from .. import dashboards as dash

    db = db_of(request)
    rows = [dash.public_dashboard(d) for d in db.query("SELECT * FROM dashboards ORDER BY position, name")]
    return render(request, "dashboards.html", dashboards=rows)


@router.get("/dashboards/{slug}", response_class=HTMLResponse)
def dashboard_view(request: Request, slug: str):
    from .. import dashboards as dash

    db = db_of(request)
    row = db.one("SELECT * FROM dashboards WHERE slug = ? OR id = ?", (slug, int(slug) if slug.isdigit() else -1))
    if not row:
        raise HTTPException(404)
    others = db.query("SELECT name, slug FROM dashboards ORDER BY position, name")
    return render(request, "dashboard_view.html", nav="dashboards", dash=dash.public_dashboard(row), others=others)


@router.get("/maintenance", response_class=HTMLResponse)
def maintenance(request: Request):
    db = db_of(request)
    windows = db.query(
        "SELECT maintenance.*, devices.name AS device_name, checks.name AS check_name FROM maintenance "
        "LEFT JOIN devices ON devices.id = maintenance.device_id LEFT JOIN checks ON checks.id = maintenance.check_id "
        "ORDER BY ends_at DESC LIMIT 200")
    devices = db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")
    checks = db.query("SELECT id, name FROM checks ORDER BY name COLLATE NOCASE")
    return render(request, "maintenance.html", windows=windows, devices=devices, checks=checks)


@router.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    from .. import __version__, storage
    from ..checks.probes import detect_icmp_mode
    import platform
    import sys

    db = db_of(request)
    s = request.app.state.settings
    monitor = request.app.state.monitor
    from ..grafana import grafana_dashboards

    return render(
        request, "settings.html", settings=s, version=__version__, stats=storage.database_stats(db),
        grafana_boards=[{"file": k, "title": v["title"]} for k, v in grafana_dashboards().items()],
        base_url=str(request.base_url).rstrip("/"),
        python=sys.version.split()[0], platform=platform.platform(), icmp_mode=detect_icmp_mode(),
        fts=db.has_fts, monitor=monitor.status() if monitor else None,
    )


@router.get("/status", response_class=HTMLResponse)
def public_status(request: Request):
    db = db_of(request)
    now = time.time()
    rows = []
    for c in db.query("SELECT * FROM checks WHERE public = 1 AND enabled = 1 ORDER BY name COLLATE NOCASE"):
        rows.append({
            "check": c,
            "uptime_30d": reports.availability(db, c, now - 30 * 86400, now, now)["uptime_pct"],
            "daily": reports.daily_bars(db, c, 90, now),
        })
    all_up = all(r["check"]["state"] != "down" for r in rows)
    return templates.TemplateResponse(request, "status.html", {"rows": rows, "all_up": all_up})


@router.get("/login", response_class=HTMLResponse)
def login(request: Request, next: str = "/", error: str = ""):
    return templates.TemplateResponse(request, "login.html", {"next": next, "error": error})


@router.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("snmpathy_token")
    return resp
