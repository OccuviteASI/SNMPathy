"""Network Analyzer: JSON API and pages over the flow tables (NetFlow / IPFIX / sFlow).

Mount with ``app.include_router(router)``. JSON endpoints live under ``/api/flows`` and accept a
shared set of filters (see :func:`flow_filter`); the HTML pages are ``/traffic``,
``/traffic/sources`` and ``/traffic/host/{ip}``.
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ..db import Database
from ..syslog.search import parse_duration
from . import query as fq
from .query import PROTO_NAMES, SERVICE_NAMES, FlowFilter

router = APIRouter()

MAX_RANGE = 400 * 86400
ACTIVE_AFTER = 300.0        # a source that exported within 5 minutes is "receiving"
IDLE_AFTER = 3600.0         # within an hour it is "idle", after that "silent"
RATE_WINDOW = 300           # seconds used for the records/s and bps estimates
OVERRIDE_KEY = "flows.sampling_override."
TS_GROUPS = ("total", "src", "dst", "dport", "proto", "source", "app")

_RANGE_RE = re.compile(r"\s*\d+(?:\.\d+)?\s*[smhdw]?\s*")
_PROTO_LOOKUP = {name.lower(): num for num, name in PROTO_NAMES.items()}
_SERVICE_LOOKUP: dict[str, int] = {}
for _port, _name in sorted(SERVICE_NAMES.items()):
    _SERVICE_LOOKUP.setdefault(_name, _port)


# ------------------------------------------------------------------ helpers
def _db(request: Request) -> Database:
    return request.app.state.db


def flow_collector(request: Request) -> Any:
    """The running :class:`~snmpathy.flows.FlowCollector`, or ``None``."""
    monitor = getattr(request.app.state, "monitor", None)
    return getattr(monitor, "flows", None) if monitor is not None else None


def _invalidate(request: Request) -> None:
    collector = flow_collector(request)
    if collector is not None:
        collector.invalidate_sources()


def _bad(msg: str) -> HTTPException:
    return HTTPException(status_code=400, detail=msg)


def parse_proto(value: Any) -> int | None:
    """``6``, ``"6"``, ``"tcp"``, ``"ICMPv6"`` -> protocol number; ``None`` for empty; ValueError if unknown."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.isdigit():
        num = int(text)
        if not 0 <= num <= 255:
            raise ValueError(f"invalid protocol {value!r}")
        return num
    num = _PROTO_LOOKUP.get(text.lower())
    if num is None:
        raise ValueError(f"unknown protocol {value!r}")
    return num


def parse_port(value: Any) -> int | None:
    """``443``, ``"443"`` or a service name (``"https"``) -> port; ``None`` for empty; ValueError if unknown."""
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if text.isdigit():
        num = int(text)
        if not 0 <= num <= 65535:
            raise ValueError(f"invalid port {value!r}")
        return num
    num = _SERVICE_LOOKUP.get(text)
    if num is None:
        raise ValueError(f"unknown port or service {value!r}")
    return num


def _check_ip(value: str, what: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"invalid {what} address {value!r}") from exc


def build_filter(params: Mapping[str, Any], now: float | None = None) -> FlowFilter:
    """Validate query-style parameters and build a :class:`FlowFilter`.

    Accepts ``range`` (``15m``, ``1h``, ``7d``...) or ``start``/``end`` (epoch seconds), plus
    ``source_id``, ``ip`` (a CIDR here becomes a ``cidr`` filter), ``src``, ``dst``, ``port`` (number
    or service name), ``proto`` (number or name) and ``cidr``. Raises ValueError on bad input.
    """
    p = {k: v for k, v in params.items() if v not in (None, "")}
    now = time.time() if now is None else now

    def num(name: str) -> float | None:
        if name not in p:
            return None
        try:
            return float(p[name])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid {name} {p[name]!r}") from exc

    start, end = num("start"), num("end")
    if end is None:
        end = now
    if start is None:
        rng = str(p.get("range") or p.get("since") or "1h")
        if not _RANGE_RE.fullmatch(rng):
            raise ValueError(f"invalid range {rng!r} (use e.g. 15m, 1h, 24h, 7d)")
        start = end - parse_duration(rng)
    if start >= end:
        raise ValueError("start must be before end")
    if end - start > MAX_RANGE:
        start = end - MAX_RANGE

    ip = str(p.get("ip") or "").strip()
    cidr = str(p.get("cidr") or "").strip()
    if "/" in ip:
        cidr, ip = cidr or ip, ""
    if ip:
        ip = _check_ip(ip, "IP")
    if cidr:
        try:
            cidr = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid CIDR {cidr!r}") from exc
    src = _check_ip(str(p["src"]).strip(), "source") if p.get("src") else ""
    dst = _check_ip(str(p["dst"]).strip(), "destination") if p.get("dst") else ""
    source_id = p.get("source_id")
    if source_id is not None:
        try:
            source_id = int(source_id)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid source_id {source_id!r}") from exc
    return FlowFilter.from_params({
        "start": start, "end": end, "source_id": source_id, "ip": ip, "src": src, "dst": dst,
        "port": parse_port(p.get("port")), "proto": parse_proto(p.get("proto")), "cidr": cidr,
    })


def flow_filter(
    range: Optional[str] = Query(None, description="Relative range ending now: 15m, 1h, 6h, 24h, 7d (default 1h)"),
    start: Optional[float] = Query(None, description="Range start (epoch seconds); overrides range"),
    end: Optional[float] = Query(None, description="Range end (epoch seconds), default now"),
    source_id: Optional[int] = Query(None, description="Only flows from this exporter"),
    ip: Optional[str] = Query(None, description="Source or destination IP (a CIDR is treated as cidr)"),
    src: Optional[str] = Query(None, description="Source IP"),
    dst: Optional[str] = Query(None, description="Destination IP"),
    port: Optional[str] = Query(None, description="Source or destination port, or a service name (https)"),
    proto: Optional[str] = Query(None, description="IP protocol number or name (tcp, udp, icmp...)"),
    cidr: Optional[str] = Query(None, description="Source or destination inside this network"),
) -> FlowFilter:
    """FastAPI dependency: the shared flow filter of every ``/api/flows`` endpoint."""
    try:
        return build_filter({
            "range": range, "start": start, "end": end, "source_id": source_id, "ip": ip, "src": src,
            "dst": dst, "port": port, "proto": proto, "cidr": cidr,
        })
    except ValueError as exc:
        raise _bad(str(exc)) from exc


def filter_dict(f: FlowFilter) -> dict[str, Any]:
    """The active filter as JSON (only non-empty fields, plus the resolved bounds)."""
    start, end = f.bounds()
    out: dict[str, Any] = {"start": start, "end": end}
    for key in ("source_id", "ip", "src", "dst", "port", "proto", "cidr"):
        value = getattr(f, key)
        if value not in (None, ""):
            out[key] = value
    if f.proto is not None:
        out["proto_name"] = fq.proto_name(f.proto)
    return out


def _guarded(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ValueError as exc:
        raise _bad(str(exc)) from exc


def app_timeseries(db: Database, f: FlowFilter, step: int | None = None, limit: int = 6) -> dict[str, Any]:
    """Like :func:`query.timeseries` but grouped by application (service name, e.g. ``https``)."""
    start, end = f.bounds()
    step = int(step) if step else fq.auto_step(end - start)
    step = max(60, step // 60 * 60)
    while (end - start) / step > 2000:
        step *= 2
    first = int(start) // step * step
    stamps = list(range(first, int(end) + 1, step))
    index = set(stamps)
    rows = fq._grouped(db, f, (("t", f"(bucket / {step}) * {step}"), ("proto", "proto"), ("port", fq._APP_PORT_SQL)))
    per_app: dict[str, dict[int, int]] = {}
    totals: dict[str, int] = {}
    for r in rows:
        name = fq.service_name(r["proto"], r["port"])
        b = int(r["bytes"] or 0)
        totals[name] = totals.get(name, 0) + b
        if r["t"] in index:
            slot = per_app.setdefault(name, {})
            slot[r["t"]] = slot.get(r["t"], 0) + b
    ranked = sorted(totals, key=lambda n: (-totals[n], n))
    chosen = ranked[:max(0, limit)]
    other: dict[int, int] = {}
    for name in ranked[len(chosen):]:
        for t, b in per_app.get(name, {}).items():
            other[t] = other.get(t, 0) + b

    def points(values: dict[int, int]) -> list[list[float]]:
        return [[t, values.get(t, 0) * 8 / step] for t in stamps]

    series = [{"name": n, "key": n, "points": points(per_app.get(n, {}))} for n in chosen]
    if any(other.values()):
        series.append({"name": "Other", "key": None, "points": points(other)})
    return {"step": step, "series": series}


def flow_timeseries(db: Database, f: FlowFilter, group: str | None = None, limit: int = 6,
                    step: int | None = None) -> dict[str, Any]:
    group = None if group in (None, "", "total") else group
    if group == "app":
        return app_timeseries(db, f, step=step, limit=limit)
    return fq.timeseries(db, f, step=step, group=group, limit=limit)


def flow_summary(db: Database, f: FlowFilter) -> dict[str, Any]:
    """Totals plus peak rate (highest per-step average; 1 min steps up to 6 h ranges)."""
    tot = fq.totals(db, f)
    series = fq.timeseries(db, f)
    points = series["series"][0]["points"] if series["series"] else []
    peak_ts, peak = None, 0.0
    for ts, bps in points:
        if bps > peak:
            peak_ts, peak = ts, bps
    start, end = f.bounds()
    return {
        **tot,
        "bps_peak": peak,
        "peak_ts": peak_ts,
        "peak_step": series["step"],
        "pps_avg": tot["packets"] / max(1.0, end - start),
        "sources": int(_scalar(db, "SELECT COUNT(*) FROM flow_sources") or 0),
        "filter": filter_dict(f),
    }


def _scalar(db: Database, sql: str, params: Any = ()) -> Any:
    return db.scalar(sql, params)


def _overrides(db: Database) -> dict[int, int]:
    out: dict[int, int] = {}
    for r in db.query("SELECT key, value FROM meta WHERE key LIKE ?", (OVERRIDE_KEY + "%",)):
        try:
            out[int(r["key"][len(OVERRIDE_KEY):])] = int(r["value"])
        except (TypeError, ValueError):
            continue
    return out


def source_status(src: dict[str, Any], now: float) -> tuple[str, str]:
    """(css status class, label) for an exporter from ``enabled`` and ``last_seen``."""
    if not src.get("enabled"):
        return "paused", "disabled"
    age = now - float(src.get("last_seen") or 0)
    if age <= ACTIVE_AFTER:
        return "up", "receiving"
    if age <= IDLE_AFTER:
        return "warning", "idle"
    return "down", "silent"


def list_sources(db: Database, now: float | None = None) -> list[dict[str, Any]]:
    """Exporters with linked device name, status, recent records/s and bps estimates."""
    now = time.time() if now is None else now
    rows = db.query(
        "SELECT flow_sources.*, devices.name AS device_name FROM flow_sources "
        "LEFT JOIN devices ON devices.id = flow_sources.device_id "
        "ORDER BY flow_sources.name = '', flow_sources.name COLLATE NOCASE, flow_sources.address")
    since = int(now) // 60 * 60 - RATE_WINDOW
    recent = {r["source_id"]: r for r in db.query(
        "SELECT source_id, SUM(flows) AS records, SUM(bytes) AS bytes FROM flows WHERE bucket >= ? GROUP BY source_id",
        (since,))}
    window = max(60.0, now - since)
    overrides = _overrides(db)
    out = []
    for r in rows:
        r = dict(r)
        rec = recent.get(r["id"]) or {}
        lifetime = max(1.0, float(r["last_seen"] or now) - float(r["first_seen"] or now))
        status, label = source_status(r, now)
        r.update(
            display_name=r["name"] or r["address"],
            status=status,
            status_label=label,
            age=max(0.0, now - float(r["last_seen"] or 0)),
            records_per_sec=(rec.get("records") or 0) / window if rec else (
                r["records"] / lifetime if label == "receiving" else 0.0),
            records_per_sec_avg=r["records"] / lifetime,
            bps_recent=(rec.get("bytes") or 0) * 8 / window if rec else 0.0,
            sampling_override=overrides.get(r["id"]),
            enabled=bool(r["enabled"]),
        )
        out.append(r)
    return out


def _source_or_404(db: Database, source_id: int) -> dict[str, Any]:
    row = db.one("SELECT * FROM flow_sources WHERE id = ?", (source_id,))
    if not row:
        raise HTTPException(status_code=404, detail="flow source not found")
    return row


def _iface_names(db: Database, rows: list[dict[str, Any]], col: str) -> None:
    """Annotate in_if/out_if rows with the SNMP interface name of the exporter's linked device."""
    devices = {r["id"]: r["device_id"] for r in db.query("SELECT id, device_id FROM flow_sources")}
    wanted = {devices.get(r["source_id"]) for r in rows} - {None}
    names: dict[tuple[int, int], dict[str, Any]] = {}
    if wanted:
        marks = ",".join("?" for _ in wanted)
        for i in db.query(f"SELECT device_id, if_index, name, alias FROM interfaces WHERE device_id IN ({marks})",
                          list(wanted)):
            names[(i["device_id"], i["if_index"])] = i
    for r in rows:
        dev = devices.get(r["source_id"])
        iface = names.get((dev, r[col])) if dev else None
        r["device_id"] = dev
        r["if_name"] = (iface or {}).get("name") or (f"ifIndex {r[col]}" if r[col] else "-")
        r["if_alias"] = (iface or {}).get("alias") or ""


def flow_top(db: Database, f: FlowFilter, by: str, limit: int = 10) -> list[dict[str, Any]]:
    rows = _guarded(fq.top, db, f, by, limit)
    if by in ("in_if", "out_if"):
        _iface_names(db, rows, by)
    start, end = f.bounds()
    span = max(1.0, end - start)
    for r in rows:
        r["bps"] = r["bytes"] * 8 / span
    return rows


def host_detail(db: Database, f: FlowFilter, ip: str, peers: int = 15) -> dict[str, Any]:
    """Traffic for one IP: in/out totals and series, plus top peers with per-direction bytes."""
    base = dict(start=f.start, end=f.end, source_id=f.source_id, port=f.port, proto=f.proto)
    f_in = FlowFilter(dst=ip, **base)
    f_out = FlowFilter(src=ip, **base)
    tot_in, tot_out = fq.totals(db, f_in), fq.totals(db, f_out)
    s_in, s_out = fq.timeseries(db, f_in), fq.timeseries(db, f_out)
    peer: dict[str, dict[str, Any]] = {}
    for r in fq.top(db, FlowFilter(ip=ip, **base), "conversation", limit=1000):
        if r["src"] == ip and r["dst"] == ip:
            continue
        other, direction = (r["dst"], "out_bytes") if r["src"] == ip else (r["src"], "in_bytes")
        p = peer.setdefault(other, {"peer": other, "in_bytes": 0, "out_bytes": 0, "bytes": 0, "packets": 0,
                                    "flows": 0})
        p[direction] += r["bytes"]
        p["bytes"] += r["bytes"]
        p["packets"] += r["packets"]
        p["flows"] += r["flows"]
    total = sum(p["bytes"] for p in peer.values())
    ranked = sorted(peer.values(), key=lambda p: (-p["bytes"], p["peer"]))[:peers]
    for p in ranked:
        p["pct"] = p["bytes"] * 100.0 / total if total else 0.0
    device = db.one("SELECT id, name, status FROM devices WHERE hostname = ? ORDER BY id LIMIT 1", (ip,))
    source = db.one("SELECT id, name, address FROM flow_sources WHERE address = ?", (ip,))
    start, end = f.bounds()
    span = max(1.0, end - start)
    return {
        "ip": ip,
        "device": device,
        "exporter": source,
        "in": {**tot_in, "bps_avg": tot_in["bytes"] * 8 / span},
        "out": {**tot_out, "bps_avg": tot_out["bytes"] * 8 / span},
        "bytes": tot_in["bytes"] + tot_out["bytes"],
        "packets": tot_in["packets"] + tot_out["packets"],
        "flows": tot_in["flows"] + tot_out["flows"],
        "step": s_in["step"],
        "series": [
            {"name": "In (to host)", "points": s_in["series"][0]["points"]},
            {"name": "Out (from host)", "points": s_out["series"][0]["points"]},
        ],
        "peers": ranked,
        "filter": filter_dict(f),
    }


def busiest_interfaces(db: Database, limit: int = 10) -> list[dict[str, Any]]:
    """Busiest SNMP-polled interfaces right now (from the ``interfaces`` table)."""
    rows = db.query(
        "SELECT interfaces.id, interfaces.device_id, interfaces.if_index, interfaces.name, interfaces.alias, "
        "interfaces.speed, interfaces.in_bps, interfaces.out_bps, interfaces.oper_status, interfaces.updated_at, "
        "devices.name AS device_name, COALESCE(interfaces.in_bps, 0) + COALESCE(interfaces.out_bps, 0) AS total_bps "
        "FROM interfaces JOIN devices ON devices.id = interfaces.device_id "
        "WHERE devices.enabled = 1 AND COALESCE(interfaces.in_bps, 0) + COALESCE(interfaces.out_bps, 0) > 0 "
        "ORDER BY total_bps DESC LIMIT ?", (max(1, min(int(limit), 100)),))
    for r in rows:
        speed = r["speed"]
        r["util"] = (max(r["in_bps"] or 0, r["out_bps"] or 0) / speed * 100) if speed else None
        r["link"] = f"/devices/{r['device_id']}?tab=interfaces#if{r['if_index']}"
    return rows


def collector_status(request: Request) -> dict[str, Any]:
    settings = request.app.state.settings
    configured = {
        "netflow": getattr(settings, "netflow_port", 2055),
        "ipfix": getattr(settings, "ipfix_port", 4739),
        "sflow": getattr(settings, "sflow_port", 6343),
    }
    collector = flow_collector(request)
    if collector is None:
        return {"enabled": False, "listening": {}, "ports": configured, "stats": None,
                "retention_days": getattr(settings, "retention_flow_days", None)}
    return {
        "enabled": True,
        "listening": dict(collector.listening),
        "ports": dict(collector.ports),
        "stats": collector.stats.as_dict(),
        "flush_interval": collector.flush_interval,
        "retention_days": getattr(settings, "retention_flow_days", None),
    }


# ------------------------------------------------------------------ JSON API
class SourcePatch(BaseModel):
    name: Optional[str] = Field(None, max_length=200)
    enabled: Optional[bool] = None
    sampling: Optional[int] = Field(None, ge=0, le=1_000_000,
                                    description="Sampling override (1 in N); 0 or null clears the override")
    device_id: Optional[int] = Field(None, description="Linked device; null or 0 unlinks")


@router.get("/api/flows/sources", tags=["flows"])
def api_sources(request: Request):
    return list_sources(_db(request))


@router.get("/api/flows/sources/{source_id}", tags=["flows"])
def api_source(source_id: int, request: Request):
    db = _db(request)
    _source_or_404(db, source_id)
    return next(s for s in list_sources(db) if s["id"] == source_id)


@router.patch("/api/flows/sources/{source_id}", tags=["flows"])
def api_patch_source(source_id: int, body: SourcePatch, request: Request):
    db = _db(request)
    _source_or_404(db, source_id)
    fields = body.model_fields_set
    values: dict[str, Any] = {}
    if "name" in fields:
        values["name"] = (body.name or "").strip()
    if "enabled" in fields and body.enabled is not None:
        values["enabled"] = int(body.enabled)
    if "device_id" in fields:
        if body.device_id:
            if not db.one("SELECT id FROM devices WHERE id = ?", (body.device_id,)):
                raise _bad(f"device {body.device_id} does not exist")
            values["device_id"] = body.device_id
        else:
            values["device_id"] = None
    if "sampling" in fields:
        key = f"{OVERRIDE_KEY}{source_id}"
        if body.sampling and body.sampling > 1:
            db.set_meta(key, str(int(body.sampling)))
            values["sampling"] = int(body.sampling)
        else:
            db.execute("DELETE FROM meta WHERE key = ?", (key,))
    db.update("flow_sources", source_id, values)
    _invalidate(request)
    return next(s for s in list_sources(db) if s["id"] == source_id)


@router.delete("/api/flows/sources/{source_id}", status_code=204, tags=["flows"])
def api_delete_source(source_id: int, request: Request):
    db = _db(request)
    _source_or_404(db, source_id)
    with db.transaction():
        db.execute("DELETE FROM flows WHERE source_id = ?", (source_id,))
        db.execute("DELETE FROM flow_sources WHERE id = ?", (source_id,))
        db.execute("DELETE FROM meta WHERE key = ?", (f"{OVERRIDE_KEY}{source_id}",))
    _invalidate(request)
    return Response(status_code=204)


@router.get("/api/flows/summary", tags=["flows"])
def api_summary(request: Request, f: FlowFilter = Depends(flow_filter)):
    return _guarded(flow_summary, _db(request), f)


@router.get("/api/flows/timeseries", tags=["flows"])
def api_timeseries(
    request: Request,
    f: FlowFilter = Depends(flow_filter),
    group: str = Query("total", description="total, src, dst, dport, proto, source or app"),
    limit: int = Query(6, ge=1, le=20, description="Series to keep before folding the rest into Other"),
    step: Optional[int] = Query(None, ge=60, description="Bucket size in seconds (default: automatic)"),
):
    if group not in TS_GROUPS:
        raise _bad(f"unknown group {group!r}; use one of {', '.join(TS_GROUPS)}")
    data = _guarded(flow_timeseries, _db(request), f, group, limit, step)
    start, end = f.bounds()
    return {"start": start, "end": end, "group": group, "unit": "bps", **data, "filter": filter_dict(f)}


@router.get("/api/flows/top", tags=["flows"])
def api_top(
    request: Request,
    f: FlowFilter = Depends(flow_filter),
    by: str = Query("src", description="src, dst, conversation, app, dport, proto, source, in_if or out_if"),
    limit: int = Query(10, ge=1, le=1000),
):
    if by not in fq.TOP_BY:
        raise _bad(f"unknown dimension {by!r}; use one of {', '.join(fq.TOP_BY)}")
    return {"by": by, "rows": flow_top(_db(request), f, by, limit), "filter": filter_dict(f)}


@router.get("/api/flows/host/{address}", tags=["flows"])
def api_host(address: str, request: Request, f: FlowFilter = Depends(flow_filter),
             peers: int = Query(15, ge=1, le=200)):
    """Traffic for one IP: in/out totals and series, top peers (``ip``/``src``/``dst``/``cidr`` are ignored)."""
    try:
        ip = _check_ip(address, "host")
    except ValueError as exc:
        raise _bad(str(exc)) from exc
    return _guarded(host_detail, _db(request), f, ip, peers)


@router.get("/api/flows/interfaces", tags=["flows"])
def api_interfaces(request: Request, limit: int = Query(10, ge=1, le=100)):
    """Busiest SNMP interfaces, to show polled bandwidth next to flow data."""
    return busiest_interfaces(_db(request), limit)


@router.get("/api/flows/status", tags=["flows"])
def api_status(request: Request):
    db = _db(request)
    now = time.time()
    sources = list_sources(db, now)
    return {
        **collector_status(request),
        "sources": len(sources),
        "sources_receiving": sum(1 for s in sources if s["status_label"] == "receiving"),
        "oldest_bucket": db.scalar("SELECT MIN(bucket) FROM flows"),
        "newest_bucket": db.scalar("SELECT MAX(bucket) FROM flows"),
    }


# ------------------------------------------------------------------ pages
def _server_host(request: Request) -> str:
    host = request.url.hostname or ""
    if host in ("", "localhost", "127.0.0.1", "::1", "testserver"):
        return "SNMPATHY-IP"
    return host


def _page_context(request: Request) -> dict[str, Any]:
    status = collector_status(request)
    configured = {k: int(v) for k, v in status["ports"].items() if v}
    # Every listener sniffs the export format, so a disabled listener's exporters can use any other port.
    fallback = next(iter(configured.values()), 2055)
    ports = {k: configured.get(k, fallback) for k in ("netflow", "ipfix", "sflow")}
    return {"collector": status, "ports": ports, "configured_ports": configured,
            "server_host": _server_host(request)}


@router.get("/traffic", response_class=HTMLResponse, include_in_schema=False)
def traffic_page(request: Request):
    from ..web import render

    from .. import reporting

    db = _db(request)
    sources = list_sources(db)
    return render(request, "traffic.html", nav="traffic", sources=sources,
                  source_names={s["id"]: s["display_name"] for s in sources}, proto_names=PROTO_NAMES,
                  has_data=bool(sources) or bool(db.scalar("SELECT 1 FROM flows LIMIT 1")),
                  report_available="traffic" in reporting.REPORT_TYPES, **_page_context(request))


@router.get("/traffic/sources", response_class=HTMLResponse, include_in_schema=False)
def traffic_sources_page(request: Request):
    from ..web import render

    db = _db(request)
    devices = db.query("SELECT id, name, hostname FROM devices ORDER BY name COLLATE NOCASE")
    return render(request, "traffic_sources.html", nav="traffic", sources=list_sources(db), devices=devices,
                  **_page_context(request))


@router.get("/traffic/host/{ip}", response_class=HTMLResponse, include_in_schema=False)
def traffic_host_page(request: Request, ip: str):
    from ..web import render

    try:
        ip = _check_ip(ip, "host")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db = _db(request)
    device = db.one("SELECT id, name, status FROM devices WHERE hostname = ? ORDER BY id LIMIT 1", (ip,))
    exporter = db.one("SELECT id, name, address FROM flow_sources WHERE address = ?", (ip,))
    params = {k: v for k, v in request.query_params.items() if v}
    return render(request, "traffic_host.html", nav="traffic", ip=ip, device=device, exporter=exporter,
                  sources=list_sources(db), params=params)
