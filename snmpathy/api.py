"""REST API (mounted at ``/api``). Interactive docs are served at ``/docs``."""

from __future__ import annotations

import time
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import dashboards, reporting, reports, scheduled, services, storage
from .db import Database
from .services import ValidationError
from .snmp.client import PySnmpClient, SnmpCredentials, SnmpError
from .snmp.discovery import discover
from .syslog import search as syslog_search

router = APIRouter(prefix="/api")


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_monitor(request: Request):
    monitor = request.app.state.monitor
    if monitor is None:
        raise HTTPException(503, "monitoring engine is not running")
    return monitor


def _not_found(what: str):
    return HTTPException(404, f"{what} not found")


def _time_range(range_: str | None, start: float | None, end: float | None, default: str = "24h") -> tuple[float, float]:
    end = end or time.time()
    if start is None:
        start = end - syslog_search.parse_duration(range_ or default)
    return float(start), float(end)


# ======================================================================= models
class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    snmp_enabled: bool = True
    snmp_version: Literal["1", "2c", "3"] = "2c"
    snmp_port: int = Field(161, ge=1, le=65535)
    snmp_community: str = "public"
    v3_user: str = ""
    v3_auth_proto: str = "sha"
    v3_auth_key: str = ""
    v3_priv_proto: str = "aes"
    v3_priv_key: str = ""
    v3_context: str = ""
    poll_interval: int = Field(300, ge=10, le=86400)
    location: str = ""
    tags: list[str] = []
    notes: str = ""
    add_ping_check: bool = True


class DevicePatch(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    enabled: Optional[bool] = None
    snmp_enabled: Optional[bool] = None
    snmp_version: Optional[Literal["1", "2c", "3"]] = None
    snmp_port: Optional[int] = Field(None, ge=1, le=65535)
    snmp_community: Optional[str] = None
    v3_user: Optional[str] = None
    v3_auth_proto: Optional[str] = None
    v3_auth_key: Optional[str] = None
    v3_priv_proto: Optional[str] = None
    v3_priv_key: Optional[str] = None
    v3_context: Optional[str] = None
    poll_interval: Optional[int] = Field(None, ge=10, le=86400)
    location: Optional[str] = None
    tags: Optional[list[str]] = None
    notes: Optional[str] = None


class SnmpTestIn(BaseModel):
    hostname: str
    snmp_version: Literal["1", "2c", "3"] = "2c"
    snmp_port: int = 161
    snmp_community: str = "public"
    v3_user: str = ""
    v3_auth_proto: str = "sha"
    v3_auth_key: str = ""
    v3_priv_proto: str = "aes"
    v3_priv_key: str = ""
    v3_context: str = ""


class MetricIn(BaseModel):
    key: str
    oid: str
    oid2: str = ""
    kind: Literal["gauge", "counter", "ratio", "ratio_free"] = "gauge"
    label: str = ""
    instance: str = ""
    unit: str = ""
    scale: float = 1.0
    counter_bits: int = 64


class CheckIn(BaseModel):
    name: Optional[str] = None
    type: Literal["icmp", "tcp", "http", "snmp", "dns"]
    target: str = Field(min_length=1)
    port: Optional[int] = Field(None, ge=1, le=65535)
    interval: int = Field(60, ge=5, le=86400)
    timeout: float = Field(5, gt=0, le=120)
    retries: int = Field(2, ge=0, le=20)
    options: dict[str, Any] = {}
    enabled: bool = True
    public: bool = False
    device_id: Optional[int] = None


class CheckPatch(BaseModel):
    name: Optional[str] = None
    type: Optional[Literal["icmp", "tcp", "http", "snmp", "dns"]] = None
    target: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    interval: Optional[int] = Field(None, ge=5, le=86400)
    timeout: Optional[float] = Field(None, gt=0, le=120)
    retries: Optional[int] = Field(None, ge=0, le=20)
    options: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None
    public: Optional[bool] = None
    device_id: Optional[int] = None


class RuleIn(BaseModel):
    name: str
    kind: Literal["metric", "check", "device", "syslog"]
    enabled: bool = True
    severity: Literal["critical", "warning", "info"] = "warning"
    device_id: Optional[int] = None
    device_tag: str = ""
    metric_key: str = ""
    instance: str = ""
    operator: Literal[">", ">=", "<", "<=", "==", "!="] = ">"
    threshold: Optional[float] = None
    for_seconds: int = Field(0, ge=0)
    syslog_query: str = ""
    syslog_severity: Optional[int] = Field(None, ge=0, le=7)
    window_seconds: int = Field(300, ge=10)
    count_threshold: int = Field(1, ge=1)
    channels: list[int] = []
    description: str = ""


class RulePatch(BaseModel):
    name: Optional[str] = None
    kind: Optional[Literal["metric", "check", "device", "syslog"]] = None
    enabled: Optional[bool] = None
    severity: Optional[Literal["critical", "warning", "info"]] = None
    device_id: Optional[int] = None
    device_tag: Optional[str] = None
    metric_key: Optional[str] = None
    instance: Optional[str] = None
    operator: Optional[Literal[">", ">=", "<", "<=", "==", "!="]] = None
    threshold: Optional[float] = None
    for_seconds: Optional[int] = Field(None, ge=0)
    syslog_query: Optional[str] = None
    syslog_severity: Optional[int] = Field(None, ge=0, le=7)
    window_seconds: Optional[int] = Field(None, ge=10)
    count_threshold: Optional[int] = Field(None, ge=1)
    channels: Optional[list[int]] = None
    description: Optional[str] = None


class ChannelIn(BaseModel):
    name: str
    type: Literal["webhook", "slack", "teams", "discord", "pagerduty", "email", "log"]
    config: dict[str, Any] = {}
    enabled: bool = True


class ChannelPatch(BaseModel):
    name: Optional[str] = None
    config: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None


class MaintenanceIn(BaseModel):
    name: str
    device_id: Optional[int] = None
    check_id: Optional[int] = None
    starts_at: Optional[float] = None
    ends_at: Optional[float] = None
    duration_minutes: Optional[float] = Field(None, gt=0)


class AckIn(BaseModel):
    by: str = ""


def _patch(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(exclude_unset=True)


def _guard(fn, *args):
    try:
        return fn(*args)
    except ValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    except KeyError as exc:
        raise _not_found("object") from exc


# ======================================================================= status
@router.get("/status", tags=["system"])
def status(db: Database = Depends(get_db)):
    return services.overview(db)


@router.get("/system", tags=["system"])
def system(request: Request, db: Database = Depends(get_db)):
    from . import __version__
    from .checks.probes import detect_icmp_mode
    import platform
    import sys

    monitor = request.app.state.monitor
    return {
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "icmp_mode": detect_icmp_mode(),
        "fts": db.has_fts,
        "database": db.path,
        "db": storage.database_stats(db),
        "monitor": monitor.status() if monitor else None,
    }


@router.get("/events", tags=["system"])
def events(db: Database = Depends(get_db), device_id: Optional[int] = None, check_id: Optional[int] = None,
           level: Optional[str] = None, limit: int = Query(100, le=1000)):
    clauses, params = [], []
    if device_id:
        clauses.append("device_id = ?"); params.append(device_id)
    if check_id:
        clauses.append("check_id = ?"); params.append(check_id)
    if level:
        clauses.append("level = ?"); params.append(level)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return db.query(f"SELECT * FROM events {where} ORDER BY ts DESC, id DESC LIMIT ?", [*params, limit])


# ====================================================================== devices
@router.get("/devices", tags=["devices"])
def list_devices(db: Database = Depends(get_db), tag: Optional[str] = None, status: Optional[str] = None,
                 q: Optional[str] = None):
    rows = [services.public_device(d) for d in db.query("SELECT * FROM devices ORDER BY name COLLATE NOCASE")]
    if tag:
        rows = [d for d in rows if tag in d["tags"]]
    if status:
        rows = [d for d in rows if d["status"] == status]
    if q:
        ql = q.lower()
        rows = [d for d in rows if ql in d["name"].lower() or ql in d["hostname"].lower()
                or ql in (d["sys_descr"] or "").lower() or ql in (d["location"] or "").lower()]
    return rows


@router.post("/devices", status_code=201, tags=["devices"])
async def create_device(body: DeviceIn, request: Request, db: Database = Depends(get_db)):
    values = body.model_dump()
    add_ping = values.pop("add_ping_check")
    device = _guard(services.create_device, db, values, add_ping)
    monitor = request.app.state.monitor
    if monitor and device["snmp_enabled"]:
        monitor.reschedule_device(device["id"])
    return services.public_device(device)


@router.post("/devices/test", tags=["devices"])
async def test_snmp(body: SnmpTestIn):
    """Try SNMP credentials without saving anything and report what was found."""
    creds = SnmpCredentials.from_device(body.model_dump())
    client = PySnmpClient(body.hostname, creds, timeout=2, retries=1)
    try:
        result = await discover(client)
    except SnmpError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        client.close()
    return {
        "ok": True,
        "system": result.system,
        "interfaces": len(result.interfaces),
        "metrics": len(result.metrics),
    }


@router.get("/devices/{device_id}", tags=["devices"])
def get_device(device_id: int, db: Database = Depends(get_db)):
    device = db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not device:
        raise _not_found("device")
    return services.public_device(device)


@router.patch("/devices/{device_id}", tags=["devices"])
def patch_device(device_id: int, body: DevicePatch, request: Request, db: Database = Depends(get_db)):
    device = _guard(services.update_device, db, device_id, _patch(body))
    monitor = request.app.state.monitor
    if monitor:
        monitor.reschedule_device(device_id)
    return services.public_device(device)


@router.delete("/devices/{device_id}", status_code=204, tags=["devices"])
def delete_device(device_id: int, request: Request, db: Database = Depends(get_db)):
    _guard(services.delete_device, db, device_id)
    monitor = request.app.state.monitor
    if monitor:
        monitor.forget_device(device_id)


@router.post("/devices/{device_id}/discover", tags=["devices"])
async def rediscover(device_id: int, monitor=Depends(get_monitor)):
    try:
        return await monitor.discover_device(device_id)
    except KeyError:
        raise _not_found("device")
    except SnmpError as exc:
        raise HTTPException(502, f"SNMP discovery failed: {exc}")


@router.post("/devices/{device_id}/poll", tags=["devices"])
async def poll_now(device_id: int, monitor=Depends(get_monitor)):
    try:
        return await monitor.poll_now(device_id)
    except KeyError:
        raise _not_found("device")


@router.get("/devices/{device_id}/interfaces", tags=["devices"])
def device_interfaces(device_id: int, db: Database = Depends(get_db)):
    return db.query("SELECT * FROM interfaces WHERE device_id = ? ORDER BY if_index", (device_id,))


@router.get("/devices/{device_id}/metrics", tags=["devices"])
def device_metrics(device_id: int, db: Database = Depends(get_db), key: Optional[str] = None):
    if key:
        return db.query("SELECT * FROM metrics WHERE device_id = ? AND key = ? ORDER BY instance",
                        (device_id, key))
    return db.query("SELECT * FROM metrics WHERE device_id = ? ORDER BY key, instance", (device_id,))


@router.post("/devices/{device_id}/metrics", status_code=201, tags=["devices"])
def add_metric(device_id: int, body: MetricIn, db: Database = Depends(get_db)):
    return _guard(services.add_custom_metric, db, device_id, body.model_dump())


@router.delete("/metrics/{metric_id}", status_code=204, tags=["metrics"])
def delete_metric(metric_id: int, db: Database = Depends(get_db)):
    with db.transaction():
        db.execute("DELETE FROM samples WHERE metric_id = ?", (metric_id,))
        db.execute("DELETE FROM rollups WHERE metric_id = ?", (metric_id,))
        db.execute("DELETE FROM metrics WHERE id = ?", (metric_id,))


@router.patch("/metrics/{metric_id}", tags=["metrics"])
def toggle_metric(metric_id: int, enabled: bool, db: Database = Depends(get_db)):
    db.execute("UPDATE metrics SET enabled = ? WHERE id = ?", (int(enabled), metric_id))
    return db.one("SELECT * FROM metrics WHERE id = ?", (metric_id,))


@router.get("/metrics/{metric_id}/series", tags=["metrics"])
def metric_series(metric_id: int, db: Database = Depends(get_db), range: str = "24h",
                  start: Optional[float] = None, end: Optional[float] = None, resolution: str = "auto"):
    metric = db.one("SELECT * FROM metrics WHERE id = ?", (metric_id,))
    if not metric:
        raise _not_found("metric")
    s, e = _time_range(range, start, end)
    data = storage.series(db, metric_id, s, e, resolution)
    return {"metric": metric, "start": s, "end": e, **data}


@router.get("/metrics/{metric_id}/summary", tags=["metrics"])
def metric_summary(metric_id: int, db: Database = Depends(get_db), range: str = "24h"):
    s, e = _time_range(range, None, None)
    return storage.metric_summary(db, metric_id, s, e)


# ======================================================================= checks
@router.get("/checks", tags=["checks"])
def list_checks(db: Database = Depends(get_db), device_id: Optional[int] = None, state: Optional[str] = None):
    sql = "SELECT checks.*, devices.name AS device_name FROM checks LEFT JOIN devices ON devices.id = checks.device_id"
    clauses, params = [], []
    if device_id:
        clauses.append("checks.device_id = ?"); params.append(device_id)
    if state:
        clauses.append("checks.state = ?"); params.append(state)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return [services.public_check(c) for c in db.query(sql + " ORDER BY checks.name COLLATE NOCASE", params)]


@router.post("/checks", status_code=201, tags=["checks"])
def create_check(body: CheckIn, request: Request, db: Database = Depends(get_db)):
    values = body.model_dump()
    if values.get("name") is None:
        values.pop("name")
    check = _guard(services.create_check, db, values)
    if request.app.state.monitor:
        request.app.state.monitor.reschedule_check(check["id"])
    return services.public_check(check)


@router.get("/checks/{check_id}", tags=["checks"])
def get_check(check_id: int, db: Database = Depends(get_db)):
    check = db.one("SELECT * FROM checks WHERE id = ?", (check_id,))
    if not check:
        raise _not_found("check")
    return services.public_check(check)


@router.patch("/checks/{check_id}", tags=["checks"])
def patch_check(check_id: int, body: CheckPatch, request: Request, db: Database = Depends(get_db)):
    check = _guard(services.update_check, db, check_id, _patch(body))
    if request.app.state.monitor:
        request.app.state.monitor.reschedule_check(check_id)
    return services.public_check(check)


@router.delete("/checks/{check_id}", status_code=204, tags=["checks"])
def delete_check(check_id: int, db: Database = Depends(get_db)):
    services.delete_check(db, check_id)


@router.post("/checks/{check_id}/run", tags=["checks"])
async def run_check(check_id: int, monitor=Depends(get_monitor)):
    try:
        return services.public_check(await monitor.run_check_now(check_id))
    except KeyError:
        raise _not_found("check")


@router.get("/checks/{check_id}/heartbeats", tags=["checks"])
def heartbeats(check_id: int, db: Database = Depends(get_db), range: str = "24h",
               start: Optional[float] = None, end: Optional[float] = None, limit: int = Query(5000, le=50000)):
    s, e = _time_range(range, start, end)
    return db.query(
        "SELECT ts, ok, latency_ms, message FROM heartbeats WHERE check_id = ? AND ts >= ? AND ts <= ? "
        "ORDER BY ts DESC LIMIT ?",
        (check_id, s, e, limit),
    )[::-1]


@router.get("/checks/{check_id}/outages", tags=["checks"])
def outages(check_id: int, db: Database = Depends(get_db), limit: int = Query(100, le=1000)):
    return db.query("SELECT * FROM outages WHERE check_id = ? ORDER BY started_at DESC LIMIT ?", (check_id, limit))


@router.get("/checks/{check_id}/uptime", tags=["checks"])
def check_uptime(check_id: int, db: Database = Depends(get_db), days: int = Query(90, ge=1, le=366)):
    check = db.one("SELECT * FROM checks WHERE id = ?", (check_id,))
    if not check:
        raise _not_found("check")
    now = time.time()
    return {
        "windows": {name: reports.availability(db, check, now - secs, now, now)
                    for name, secs in reports.WINDOWS.items()},
        "daily": reports.daily_bars(db, check, days, now),
    }


# ======================================================================= syslog
def _syslog_filter(request: Request) -> syslog_search.SyslogFilter:
    params = dict(request.query_params)
    params.setdefault("since", params.get("range") or "")
    if not params["since"]:
        params.pop("since")
    return syslog_search.SyslogFilter.from_params(params)


@router.get("/syslog", tags=["syslog"])
def syslog(request: Request, db: Database = Depends(get_db), limit: int = Query(200, le=5000),
           before_id: Optional[int] = None):
    f = _syslog_filter(request)
    return syslog_search.search(db, f, limit, before_id)


@router.get("/syslog/count", tags=["syslog"])
def syslog_count(request: Request, db: Database = Depends(get_db)):
    return {"count": syslog_search.count(db, _syslog_filter(request))}


@router.get("/syslog/histogram", tags=["syslog"])
def syslog_histogram(request: Request, db: Database = Depends(get_db), buckets: int = Query(60, ge=5, le=500)):
    f = _syslog_filter(request)
    if f.start is None:
        f.start = time.time() - 86400
    return syslog_search.histogram(db, f, buckets)


@router.get("/syslog/top", tags=["syslog"])
def syslog_top(request: Request, field: str = "host", db: Database = Depends(get_db),
               limit: int = Query(10, le=100)):
    try:
        return syslog_search.top(db, _syslog_filter(request), field, limit)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


# ======================================================================= alerts
@router.get("/alerts", tags=["alerts"])
def list_alerts(db: Database = Depends(get_db), state: Optional[str] = None, limit: int = Query(200, le=5000)):
    sql = ("SELECT alerts.*, alert_rules.name AS rule_name FROM alerts "
           "LEFT JOIN alert_rules ON alert_rules.id = alerts.rule_id")
    params: list[Any] = []
    if state:
        sql += " WHERE alerts.state = ?"
        params.append(state)
    else:
        sql += " WHERE alerts.state != 'pending'"
    sql += " ORDER BY CASE alerts.state WHEN 'firing' THEN 0 ELSE 1 END, alerts.started_at DESC LIMIT ?"
    return db.query(sql, [*params, limit])


@router.post("/alerts/{alert_id}/ack", tags=["alerts"])
def ack_alert(alert_id: int, body: AckIn, db: Database = Depends(get_db)):
    if not db.one("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)):
        raise _not_found("alert")
    db.update("alerts", alert_id, {"acknowledged": 1, "ack_by": body.by, "ack_at": time.time()})
    return db.one("SELECT * FROM alerts WHERE id = ?", (alert_id,))


@router.post("/alerts/evaluate", tags=["alerts"])
async def evaluate(monitor=Depends(get_monitor)):
    return await monitor.evaluate_alerts()


@router.get("/rules", tags=["alerts"])
def list_rules(db: Database = Depends(get_db)):
    return [services.public_rule(r) for r in db.query("SELECT * FROM alert_rules ORDER BY name COLLATE NOCASE")]


@router.post("/rules", status_code=201, tags=["alerts"])
def create_rule(body: RuleIn, db: Database = Depends(get_db)):
    return services.public_rule(_guard(services.create_rule, db, body.model_dump()))


@router.get("/rules/{rule_id}", tags=["alerts"])
def get_rule(rule_id: int, db: Database = Depends(get_db)):
    rule = db.one("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))
    if not rule:
        raise _not_found("rule")
    return services.public_rule(rule)


@router.patch("/rules/{rule_id}", tags=["alerts"])
def patch_rule(rule_id: int, body: RulePatch, db: Database = Depends(get_db)):
    return services.public_rule(_guard(services.update_rule, db, rule_id, _patch(body)))


@router.delete("/rules/{rule_id}", status_code=204, tags=["alerts"])
def delete_rule(rule_id: int, db: Database = Depends(get_db)):
    db.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))


@router.get("/channels", tags=["alerts"])
def list_channels(db: Database = Depends(get_db)):
    return [services.public_channel(c) for c in db.query("SELECT * FROM channels ORDER BY name")]


@router.post("/channels", status_code=201, tags=["alerts"])
def create_channel(body: ChannelIn, db: Database = Depends(get_db)):
    return services.public_channel(_guard(services.create_channel, db, body.model_dump()))


@router.patch("/channels/{channel_id}", tags=["alerts"])
def patch_channel(channel_id: int, body: ChannelPatch, db: Database = Depends(get_db)):
    return services.public_channel(_guard(services.update_channel, db, channel_id, _patch(body)))


@router.delete("/channels/{channel_id}", status_code=204, tags=["alerts"])
def delete_channel(channel_id: int, db: Database = Depends(get_db)):
    db.execute("DELETE FROM channels WHERE id = ?", (channel_id,))


@router.post("/channels/{channel_id}/test", tags=["alerts"])
async def test_channel(channel_id: int, request: Request, db: Database = Depends(get_db)):
    from .alerting.notify import send

    channel = db.one("SELECT * FROM channels WHERE id = ?", (channel_id,))
    if not channel:
        raise _not_found("channel")
    alert = {"id": 0, "fingerprint": "test", "subject": "SNMPathy test notification", "severity": "info",
             "state": "firing", "message": "If you can read this, the channel works.", "started_at": time.time()}
    try:
        await send(channel, "firing", alert, {"name": "Test"}, request.app.state.settings)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True}


# ================================================================== maintenance
@router.get("/maintenance", tags=["maintenance"])
def list_maintenance(db: Database = Depends(get_db), active: bool = False):
    sql = ("SELECT maintenance.*, devices.name AS device_name, checks.name AS check_name FROM maintenance "
           "LEFT JOIN devices ON devices.id = maintenance.device_id "
           "LEFT JOIN checks ON checks.id = maintenance.check_id")
    params: list[Any] = []
    if active:
        now = time.time()
        sql += " WHERE starts_at <= ? AND ends_at > ?"
        params = [now, now]
    return db.query(sql + " ORDER BY starts_at DESC", params)


@router.post("/maintenance", status_code=201, tags=["maintenance"])
def create_maintenance(body: MaintenanceIn, db: Database = Depends(get_db)):
    now = time.time()
    starts = body.starts_at or now
    ends = body.ends_at or (starts + (body.duration_minutes or 60) * 60)
    if ends <= starts:
        raise HTTPException(422, "ends_at must be after starts_at")
    mid = db.insert("maintenance", {"name": body.name, "device_id": body.device_id, "check_id": body.check_id,
                                    "starts_at": starts, "ends_at": ends, "created_at": now})
    return db.one("SELECT * FROM maintenance WHERE id = ?", (mid,))


@router.delete("/maintenance/{mid}", status_code=204, tags=["maintenance"])
def delete_maintenance(mid: int, db: Database = Depends(get_db)):
    db.execute("DELETE FROM maintenance WHERE id = ?", (mid,))


# ====================================================================== reports
@router.get("/reports/uptime.csv", tags=["reports"], response_class=PlainTextResponse)
def uptime_csv(db: Database = Depends(get_db), range: str = "30d", start: Optional[float] = None,
               end: Optional[float] = None, device_id: Optional[int] = None):
    s, e = _time_range(range, start, end, "30d")
    rows = reports.uptime_report(db, s, e, device_id=device_id)
    return PlainTextResponse(
        reports.report_csv(rows), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="uptime-{time.strftime("%Y%m%d")}.csv"'},
    )


@router.get("/reports/top", tags=["reports"])
def top_metrics(db: Database = Depends(get_db), key: str = "cpu.avg", limit: int = Query(10, le=100)):
    """Devices/instances with the highest current value of a metric (e.g. busiest interfaces)."""
    return db.query(
        "SELECT metrics.*, devices.name AS device_name FROM metrics JOIN devices ON devices.id = metrics.device_id "
        "WHERE metrics.key = ? AND metrics.last_value IS NOT NULL AND metrics.enabled = 1 "
        "ORDER BY metrics.last_value DESC LIMIT ?",
        (key, limit),
    )


# ========================================================================= misc
@router.get("/status-page", tags=["public"])
def status_page(db: Database = Depends(get_db)):
    """Public status summary of checks flagged ``public`` (no authentication required)."""
    now = time.time()
    out = []
    for check in db.query("SELECT * FROM checks WHERE public = 1 AND enabled = 1 ORDER BY name"):
        out.append({
            "name": check["name"],
            "state": check["state"],
            "uptime_30d": reports.availability(db, check, now - 30 * 86400, now, now)["uptime_pct"],
            "daily": reports.daily_bars(db, check, 90, now),
        })
    return {"generated_at": now, "checks": out}


@router.get("/export", tags=["system"])
def export(db: Database = Depends(get_db)):
    return services.export_config(db)


@router.post("/import", tags=["system"])
def import_(data: dict[str, Any], db: Database = Depends(get_db)):
    try:
        return services.import_config(db, data)
    except (ValidationError, KeyError, TypeError) as exc:
        raise HTTPException(422, f"invalid import: {exc}")


# =================================================================== dashboards
class DashboardIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    config: dict[str, Any] = {}
    position: Optional[int] = None


class DashboardPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    config: Optional[dict[str, Any]] = None
    position: Optional[int] = None


class PanelQuery(BaseModel):
    panel: dict[str, Any]
    range: str = "24h"
    start: Optional[float] = None
    end: Optional[float] = None


@router.get("/dashboards", tags=["dashboards"])
def list_dashboards(db: Database = Depends(get_db)):
    return [dashboards.public_dashboard(d) for d in db.query("SELECT * FROM dashboards ORDER BY position, name")]


@router.post("/dashboards", status_code=201, tags=["dashboards"])
def create_dashboard(body: DashboardIn, db: Database = Depends(get_db)):
    values = body.model_dump(exclude_none=True)
    try:
        return dashboards.save_dashboard(db, values)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/dashboards/{ref}", tags=["dashboards"])
def get_dashboard(ref: str, db: Database = Depends(get_db)):
    row = db.one("SELECT * FROM dashboards WHERE id = ? OR slug = ?", (int(ref) if ref.isdigit() else -1, ref))
    if not row:
        raise _not_found("dashboard")
    return dashboards.public_dashboard(row)


@router.patch("/dashboards/{dashboard_id}", tags=["dashboards"])
def patch_dashboard(dashboard_id: int, body: DashboardPatch, db: Database = Depends(get_db)):
    try:
        return dashboards.save_dashboard(db, body.model_dump(exclude_unset=True), dashboard_id)
    except KeyError:
        raise _not_found("dashboard")
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.delete("/dashboards/{dashboard_id}", status_code=204, tags=["dashboards"])
def delete_dashboard(dashboard_id: int, db: Database = Depends(get_db)):
    db.execute("DELETE FROM dashboards WHERE id = ?", (dashboard_id,))


@router.post("/dashboards/{dashboard_id}/duplicate", status_code=201, tags=["dashboards"])
def duplicate_dashboard(dashboard_id: int, db: Database = Depends(get_db)):
    row = db.one("SELECT * FROM dashboards WHERE id = ?", (dashboard_id,))
    if not row:
        raise _not_found("dashboard")
    d = dashboards.public_dashboard(row)
    return dashboards.save_dashboard(db, {"name": f"{d['name']} (copy)", "description": d["description"],
                                          "config": d["config"]})


@router.post("/dashboards/reset", tags=["dashboards"])
def reset_dashboards(db: Database = Depends(get_db)):
    """Re-create any built-in dashboard that was deleted."""
    db.execute("DELETE FROM meta WHERE key = 'dashboards_seeded'")
    return {"created": dashboards.seed_dashboards(db)}


@router.get("/metric-keys", tags=["metrics"])
def metric_keys(db: Database = Depends(get_db)):
    from .snmp.mibs import METRIC_INFO

    keys = {r["key"]: r["n"] for r in db.query("SELECT key, COUNT(*) AS n FROM metrics GROUP BY key")}
    out = [{"key": k, "name": METRIC_INFO.get(k, {}).get("name", k), "unit": METRIC_INFO.get(k, {}).get("unit", ""),
            "series": keys.get(k, 0)} for k in sorted(set(keys) | set(METRIC_INFO))]
    return out


@router.get("/panel-types", tags=["dashboards"])
def panel_types():
    return dashboards.PANEL_TYPES


@router.post("/panel-data", tags=["dashboards"])
def panel_data(body: PanelQuery, db: Database = Depends(get_db)):
    """Data for one dashboard panel (used by the built-in dashboards)."""
    s, e = _time_range(body.range, body.start, body.end)
    return dashboards.panel_data(db, body.panel, s, e)


@router.post("/query", tags=["dashboards"])
def query_series(target: dict[str, Any], db: Database = Depends(get_db), range: str = "24h",
                 start: Optional[float] = None, end: Optional[float] = None):
    """Resolve a dashboard target (see ``snmpathy.dashboards``) into time series."""
    s, e = _time_range(range, start, end)
    return {"start": s, "end": e, "series": dashboards.query_target(db, target, s, e)}


# ===================================================================== reporting
class ScheduleIn(BaseModel):
    name: str
    report: Literal["uptime", "health", "bandwidth", "syslog", "alerts"]
    range: str = ""
    frequency: Literal["daily", "weekly", "monthly"] = "weekly"
    hour: int = Field(7, ge=0, le=23)
    weekday: int = Field(0, ge=0, le=6)
    monthday: int = Field(1, ge=1, le=28)
    options: dict[str, Any] = {}
    channels: list[int] = []
    enabled: bool = True


@router.get("/report-types", tags=["reports"])
def report_types():
    return reporting.REPORT_TYPES


@router.get("/reports/{report}", tags=["reports"])
def build_report(report: str, db: Database = Depends(get_db), range: str = "7d", start: Optional[float] = None,
                 end: Optional[float] = None, device_id: Optional[int] = None, tag: Optional[str] = None,
                 format: Literal["json", "csv"] = "json", section: Optional[int] = None):
    if report not in reporting.REPORT_TYPES:
        raise _not_found("report")
    data = reporting.build(db, report, range, start, end, device_id=device_id, tag=tag)
    if format == "csv":
        return PlainTextResponse(
            reporting.to_csv(data, section), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{report}-{time.strftime("%Y%m%d")}.csv"'})
    return data


@router.get("/report-schedules", tags=["reports"])
def list_schedules(db: Database = Depends(get_db)):
    from .db import loads

    return [{**r, "options": loads(r["options"], {}), "channels": loads(r["channels"], [])}
            for r in db.query("SELECT * FROM report_schedules ORDER BY name")]


@router.post("/report-schedules", status_code=201, tags=["reports"])
def create_schedule(body: ScheduleIn, db: Database = Depends(get_db)):
    import json as _json

    values = body.model_dump()
    values["range"] = values["range"] or scheduled.default_range(values["frequency"])
    values["options"] = _json.dumps(values["options"])
    values["channels"] = _json.dumps(values["channels"])
    values["enabled"] = int(values["enabled"])
    values["created_at"] = time.time()
    sid = db.insert("report_schedules", values)
    return db.one("SELECT * FROM report_schedules WHERE id = ?", (sid,))


@router.patch("/report-schedules/{sid}", tags=["reports"])
def patch_schedule(sid: int, body: dict[str, Any], db: Database = Depends(get_db)):
    import json as _json

    allowed = {"name", "report", "range", "frequency", "hour", "weekday", "monthday", "options", "channels", "enabled"}
    values = {k: (_json.dumps(v) if isinstance(v, (dict, list)) else (int(v) if isinstance(v, bool) else v))
              for k, v in body.items() if k in allowed}
    db.update("report_schedules", sid, values)
    return db.one("SELECT * FROM report_schedules WHERE id = ?", (sid,))


@router.delete("/report-schedules/{sid}", status_code=204, tags=["reports"])
def delete_schedule(sid: int, db: Database = Depends(get_db)):
    db.execute("DELETE FROM report_schedules WHERE id = ?", (sid,))


@router.post("/report-schedules/{sid}/send", tags=["reports"])
async def send_schedule_now(sid: int, request: Request, db: Database = Depends(get_db)):
    schedule = db.one("SELECT * FROM report_schedules WHERE id = ?", (sid,))
    if not schedule:
        raise _not_found("schedule")
    return await scheduled.deliver(db, schedule, request.app.state.settings)
