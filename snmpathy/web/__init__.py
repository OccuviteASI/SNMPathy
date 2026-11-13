"""Server-rendered web UI."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import reports, services
from ..availability import AVAIL_MODES, device_report
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
    IF_OPER=mibs.IF_OPER_STATUS_NAMES, METRIC_INFO=mibs.METRIC_INFO, now=time.time, AVAIL_MODES=AVAIL_MODES,
)


def db_of(request: Request) -> Database:
    return request.app.state.db


def render(request: Request, name: str, **context: Any) -> HTMLResponse:
    db = db_of(request)
    context.setdefault("nav", name.split(".")[0])
    context["problems"] = {
        "devices": db.scalar("SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'down'"),
        "collectors": db.scalar("SELECT COUNT(*) FROM collectors WHERE enabled = 1 AND status = 'offline'"),
        "checks": db.scalar("SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'down'"),
        "alerts": db.scalar("SELECT COUNT(*) FROM alerts WHERE state = 'firing'"),
    }
    context["auth_enabled"] = bool(request.app.state.settings.api_token)
    context.setdefault("collectors", db.query("SELECT id, name, site, status FROM collectors ORDER BY name COLLATE NOCASE"))
    from .. import version_string

    context.setdefault("version", version_string())
    return templates.TemplateResponse(request, name, context)


# --------------------------------------------------------------------- pages
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, classic: bool = False):
    db = db_of(request)
    hud_row = None if classic else db.one("SELECT * FROM dashboards WHERE slug = 'main-hud'")
    if hud_row:  # the Overview is the Main HUD dashboard (Nagios-style); ?classic=1 shows the old page
        return _render_dashboard(request, db, hud_row, overview=True)
    now = time.time()
    down_devices = db.query("SELECT * FROM devices WHERE enabled = 1 AND status IN ('down', 'unreachable') "
                            "ORDER BY status = 'unreachable', status_since")
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
def devices(request: Request, tag: str = "", q: str = "", state: str = ""):
    from ..hud import LABEL, device_state

    db = db_of(request)
    rows = [services.public_device(d) for d in db.query("SELECT * FROM devices ORDER BY name COLLATE NOCASE")]
    all_tags = sorted({t for d in rows for t in d["tags"]})
    if tag:
        rows = [d for d in rows if tag in d["tags"]]
    if state in LABEL:  # from a dashboard donut: e.g. ?state=critical lists the devices that are down
        rows = [d for d in rows if d["enabled"] and device_state(d) == state]
    counts = {r["device_id"]: r for r in db.query(
        "SELECT device_id, COUNT(*) AS ifaces, SUM(CASE WHEN admin_status = 1 AND oper_status = 2 THEN 1 ELSE 0 END) "
        "AS down FROM interfaces GROUP BY device_id")}
    cpu = {r["device_id"]: r["last_value"] for r in db.query(
        "SELECT device_id, last_value FROM metrics WHERE key = 'cpu.avg'")}
    mem = {r["device_id"]: r["last_value"] for r in db.query(
        "SELECT device_id, last_value FROM metrics WHERE key = 'mem.used_pct'")}
    return render(request, "devices.html", devices=rows, tags=all_tags, tag=tag, q=q,
                  counts=counts, cpu=cpu, mem=mem, state=state if state in LABEL else "",
                  state_label={"ok": "up", "warning": "degraded", "serious": "unreachable", "critical": "down",
                               "unknown": "unknown"}.get(state, ""))


def _device_names(db: Database) -> list[dict[str, Any]]:
    return db.query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE")


@router.get("/devices/new", response_class=HTMLResponse)
def device_new(request: Request):
    return render(request, "device_form.html", device=None, nav="devices", all_devices=_device_names(db_of(request)))


@router.get("/devices/{device_id}/edit", response_class=HTMLResponse)
def device_edit(request: Request, device_id: int):
    device = db_of(request).one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not device:
        raise HTTPException(404)
    return render(request, "device_form.html", device=services.public_device(device), nav="devices",
                  all_devices=_device_names(db_of(request)))


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
    collector = db.one("SELECT * FROM collectors WHERE id = ?", (device["collector_id"],)) if device["collector_id"] else None
    parent = db.one("SELECT id, name, status FROM devices WHERE id = ?", (device["parent_id"],)) if device["parent_id"] else None
    return render(
        request, "device.html", nav="devices", tab=tab, avail=device_report(db, device),
        uptime_30d=reports.device_availability(db, device, now - 30 * 86400, now, now)["uptime_pct"],
        collector=collector, parent=parent,
        device=services.public_device(device), metrics=metrics, by_key=by_key,
        interfaces=interfaces, iface_metrics=iface_metrics, checks=checks, events=events, alerts=alerts,
    )


@router.get("/checks", response_class=HTMLResponse)
def checks(request: Request, state: str = ""):
    from ..hud import LABEL, check_state

    db = db_of(request)
    now = time.time()
    rows = db.query(
        "SELECT checks.*, devices.name AS device_name FROM checks LEFT JOIN devices ON devices.id = checks.device_id "
        "ORDER BY CASE checks.state WHEN 'down' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, checks.name COLLATE NOCASE")
    if state in LABEL:  # from a dashboard donut
        rows = [c for c in rows if c["enabled"] and check_state(c) == state]
    for c in rows:
        c["options"] = loads(c["options"], {})
        c["uptime_24h"] = reports.availability(db, c, now - 86400, now, now)["uptime_pct"]
        c["uptime_30d"] = reports.availability(db, c, now - 30 * 86400, now, now)["uptime_pct"]
    devices = db.query("SELECT id, name, hostname FROM devices ORDER BY name COLLATE NOCASE")
    return render(request, "checks.html", checks=rows, devices=devices, state=state if state in LABEL else "")


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
    from ..topology import site_of

    rows = [dash.public_dashboard(d) for d in db.query("SELECT * FROM dashboards ORDER BY position, name")]
    devices = db.query("SELECT * FROM devices ORDER BY name COLLATE NOCASE")
    collectors = {c["id"]: c for c in db.query("SELECT id, name, site FROM collectors")}
    return render(request, "dashboards.html", dashboards=rows,
                  all_tags=sorted({t for x in devices for t in loads(x["tags"], [])}),
                  all_sites=sorted({s for x in devices if (s := site_of(x, collectors))}),
                  device_names=[x["name"] for x in devices])


@router.get("/dashboards/{slug}", response_class=HTMLResponse)
def dashboard_view(request: Request, slug: str):
    db = db_of(request)
    row = db.one("SELECT * FROM dashboards WHERE slug = ? OR id = ?", (slug, int(slug) if slug.isdigit() else -1))
    if not row:
        raise HTTPException(404)
    return _render_dashboard(request, db, row)


def _render_dashboard(request: Request, db: Any, row: dict[str, Any], overview: bool = False):
    from .. import dashboards as dash
    from ..hud import describe_scope, scope_device_ids
    from ..topology import site_of

    d = dash.public_dashboard(row)
    scope = d["config"].get("scope") or {}
    ids = scope_device_ids(db, scope)
    others = db.query("SELECT name, slug FROM dashboards ORDER BY position, name")
    devices = db.query("SELECT * FROM devices ORDER BY name COLLATE NOCASE")
    collectors = {c["id"]: c for c in db.query("SELECT id, name, site FROM collectors")}
    return render(request, "dashboard_view.html", nav="dashboard" if overview else "dashboards", dash=d, others=others,
                  is_overview=overview, scope=scope, scope_text=describe_scope(scope),
                  scope_count=len(ids) if ids is not None else None,
                  all_tags=sorted({t for x in devices for t in loads(x["tags"], [])}),
                  all_sites=sorted({s for x in devices if (s := site_of(x, collectors))}),
                  device_names=[x["name"] for x in devices])


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
    from .. import storage, version_string
    from ..checks.probes import detect_icmp_mode
    import platform
    import sys

    db = db_of(request)
    s = request.app.state.settings
    monitor = request.app.state.monitor
    from ..grafana import grafana_dashboards

    return render(
        request, "settings.html", settings=s, version=version_string(), stats=storage.database_stats(db),
        grafana_boards=[{"file": k, "title": v["title"]} for k, v in grafana_dashboards().items()],
        base_url=str(request.base_url).rstrip("/"),
        python=sys.version.split()[0], platform=platform.platform(), icmp_mode=detect_icmp_mode(),
        fts=db.has_fts, monitor=monitor.status() if monitor else None,
        autostart=_autostart_status(s), firewall=_firewall_status(s), brand_tags=_brand_tags_status(db),
    )


def _firewall_status(settings: Any) -> dict[str, Any]:
    from ..firewall import GROUPS, status

    try:
        return status(settings)
    except Exception as exc:  # never break the settings page
        return {"backend": "unknown", "admin": False, "note": str(exc), "rules": [], "groups": GROUPS,
                "default_groups": ["syslog"], "can_apply": False}


def _brand_tags_status(db: Any) -> dict[str, Any]:
    from ..brands import enabled

    return {"enabled": enabled(db), "tagged": db.scalar("SELECT COUNT(*) FROM devices WHERE brand_tag != ''") or 0}


def _autostart_status(settings: Any) -> dict[str, Any]:
    from ..autostart import status

    try:
        return status(settings)
    except Exception as exc:  # never break the settings page
        return {"supported": False, "enabled": False, "note": str(exc), "command": [], "location": ""}


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


# ------------------------------------------------------------ scans & collectors
@router.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request):
    db = db_of(request)
    rows = db.query("SELECT scans.*, collectors.name AS collector_name FROM scans "
                    "LEFT JOIN collectors ON collectors.id = scans.collector_id ORDER BY scans.created_at DESC")
    return render(request, "scans.html", nav="devices", scans=rows)


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, scan_id: int):
    from ..scanner import public_options

    db = db_of(request)
    scan = db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise HTTPException(404)
    scan["options"] = public_options(loads(scan["options"], {}))
    collector = db.one("SELECT * FROM collectors WHERE id = ?", (scan["collector_id"],)) if scan["collector_id"] else None
    return render(request, "scan.html", nav="devices", scan=scan, collector=collector)


def _download_context(request: Request) -> dict[str, Any]:
    from ..collector_api import available_downloads, downloads_dir

    return {"downloads": available_downloads(request), "downloads_dir": str(downloads_dir(request))}


@router.get("/collectors", response_class=HTMLResponse)
def collectors_page(request: Request):
    db = db_of(request)
    rows = db.query("SELECT * FROM collectors ORDER BY name COLLATE NOCASE")
    devs = {r["collector_id"]: r["n"] for r in db.query(
        "SELECT collector_id, COUNT(*) AS n FROM devices WHERE collector_id IS NOT NULL GROUP BY collector_id")}
    chks = {r["collector_id"]: r["n"] for r in db.query(
        "SELECT collector_id, COUNT(*) AS n FROM checks WHERE collector_id IS NOT NULL GROUP BY collector_id")}
    for r in rows:
        r["devices"], r["checks"] = devs.get(r["id"], 0), chks.get(r["id"], 0)
    return render(request, "collectors.html", nav="collectors", rows=rows, **_download_context(request))


@router.get("/collectors/{collector_id}", response_class=HTMLResponse)
def collector_page(request: Request, collector_id: int):
    db = db_of(request)
    col = db.one("SELECT * FROM collectors WHERE id = ?", (collector_id,))
    if not col:
        raise HTTPException(404)
    devices = db.query("SELECT * FROM devices WHERE collector_id = ? ORDER BY name COLLATE NOCASE", (collector_id,))
    checks = db.query("SELECT * FROM checks WHERE collector_id = ? ORDER BY name COLLATE NOCASE", (collector_id,))
    return render(request, "collector.html", nav="collectors", col=col, devices=devices, checks=checks,
                  **_download_context(request))
