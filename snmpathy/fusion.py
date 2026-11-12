"""Fusion: combine several independent SNMPathy servers into one tactical view.

Modelled on Nagios Fusion. Every SNMPathy server exposes a compact snapshot of
its state at ``GET /api/fusion/summary`` (normal API authentication applies).
A server acting as the Fusion master keeps a list of remote servers in the
``fusion_servers`` table, polls their summaries in the background
(:class:`FusionPoller`) and caches the JSON in ``fusion_servers.data``.
``GET /api/fusion/combined`` merges the live local summary with every enabled
remote's cached summary into aggregate totals, one problem list, one list of
firing alerts and cross-server "top N" metric lists. ``GET /fusion`` renders
the dashboard.

Data from remote servers is treated as untrusted input: numbers are coerced,
links must be site-relative paths and base URLs must be http(s), and the UI
escapes every value.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import __version__, reports, version_string
from .db import Database, loads
from .services import overview

log = logging.getLogger(__name__)

SCHEMA = 1
STALE_AFTER = 300.0          # seconds: cached remote data older than this is stale
DEFAULT_INTERVAL = 60.0      # seconds between background fetches
MAX_RESPONSE_BYTES = 2_000_000
TOP_N = 10
MAX_PROBLEMS = 100           # per server summary
MAX_ALERTS = 50              # per server summary
MAX_TEXT = 300

# Ordering for merged problems: lower is more severe.
PROBLEM_RANK = {"down": 0, "critical": 0, "error": 0, "unreachable": 1, "warning": 2, "stale": 2, "unknown": 3}
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


# ======================================================================= helpers
def _txt(value: Any, limit: int = MAX_TEXT) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _num(value: Any) -> float | None:
    try:
        if value is None or isinstance(value, bool):
            return None
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def normalize_url(url: str) -> str:
    """Validate an http(s) base URL and strip trailing slashes. Raises ValueError."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
        raise ValueError("URL must be an absolute http:// or https:// URL, e.g. https://snmpathy-eu.example.com")
    if parsed.query or parsed.fragment:
        raise ValueError("URL must not contain a query string or fragment")
    return url.rstrip("/")


def _safe_base(url: Any) -> str:
    try:
        return normalize_url(str(url or ""))
    except ValueError:
        return ""


def _abs_link(base: str, link: Any) -> str:
    """Join a server's base URL and a site-relative link; anything else is dropped."""
    link = str(link or "")
    if not link.startswith("/") or link.startswith("//"):
        link = "/"
    return (base or "") + link


def server_name(settings: Any) -> str:
    extra = getattr(settings, "extra", None) or {}
    return str(extra.get("server_name") or extra.get("fusion_name") or socket.gethostname() or "SNMPathy")


def base_url_of(request: Request) -> str:
    settings = request.app.state.settings
    return (getattr(settings, "public_url", "") or str(request.base_url)).rstrip("/")


# ======================================================================= summary
def summary(db: Database, name: str | None = None) -> dict[str, Any]:
    """Compact snapshot of this server for a Fusion master (well under 100 KB)."""
    now = time.time()
    q = db.scalar
    dev = {r["k"]: r["n"] for r in db.query(
        "SELECT CASE WHEN enabled = 0 THEN 'disabled' WHEN status = 'up' AND degraded = 1 THEN 'degraded' "
        "ELSE status END AS k, COUNT(*) AS n FROM devices GROUP BY k")}
    devices = {k: int(dev.get(k, 0)) for k in ("up", "degraded", "down", "unreachable", "unknown", "disabled")}
    devices["total"] = sum(int(v) for v in dev.values())
    chk = {r["k"]: r["n"] for r in db.query(
        "SELECT CASE WHEN enabled = 0 THEN 'paused' WHEN state = 'up' AND warning = 1 THEN 'warning' "
        "ELSE state END AS k, COUNT(*) AS n FROM checks GROUP BY k")}
    checks = {k: int(chk.get(k, 0)) for k in ("up", "warning", "down", "unknown", "paused")}
    checks["total"] = sum(int(v) for v in chk.values())

    problems: list[dict[str, Any]] = []
    for d in db.query(
            "SELECT id, name, hostname, status, status_since, status_reason, last_error FROM devices "
            "WHERE enabled = 1 AND status IN ('down', 'unreachable') ORDER BY status = 'unreachable', status_since"):
        problems.append({
            "kind": "device", "id": d["id"], "name": d["name"], "status": d["status"], "since": d["status_since"],
            "detail": _txt(d["status_reason"] or d["last_error"]), "host": d["hostname"],
            "link": f"/devices/{d['id']}",
        })
    for c in db.query(
            "SELECT checks.id, checks.name, checks.type, checks.target, checks.state, checks.warning, "
            "checks.state_since, checks.last_message, devices.name AS device_name FROM checks "
            "LEFT JOIN devices ON devices.id = checks.device_id "
            "WHERE checks.enabled = 1 AND (checks.state = 'down' OR (checks.state = 'up' AND checks.warning = 1)) "
            "ORDER BY checks.state = 'up', checks.state_since"):
        problems.append({
            "kind": "check", "id": c["id"], "name": c["name"], "status": "down" if c["state"] == "down" else "warning",
            "since": c["state_since"], "device": c["device_name"] or "",
            "detail": _txt(f"{(c['type'] or '').upper()} {c['target']}: {c['last_message'] or ''}".strip(" :")),
            "link": f"/checks/{c['id']}",
        })
    problems.sort(key=lambda p: (PROBLEM_RANK.get(p["status"], 9), p["since"] or now))

    firing = []
    for a in db.query(
            "SELECT id, subject, severity, message, started_at, fired_at, acknowledged, ack_by, device_id, check_id "
            "FROM alerts WHERE state = 'firing' ORDER BY CASE severity WHEN 'critical' THEN 0 "
            "WHEN 'warning' THEN 1 ELSE 2 END, fired_at DESC LIMIT ?", (MAX_ALERTS,)):
        link = (f"/checks/{a['check_id']}" if a["check_id"] else
                f"/devices/{a['device_id']}" if a["device_id"] else "/alerts")
        firing.append({
            "id": a["id"], "subject": _txt(a["subject"], 200), "severity": a["severity"],
            "message": _txt(a["message"]), "started_at": a["started_at"], "fired_at": a["fired_at"],
            "acknowledged": bool(a["acknowledged"]), "ack_by": a["ack_by"] or "", "link": link,
        })

    def metric_top(key: str) -> list[dict[str, Any]]:
        return [{"device_id": r["device_id"], "device": r["device_name"], "value": r["last_value"],
                 "instance": r["instance"], "link": f"/devices/{r['device_id']}"}
                for r in db.query(
                    "SELECT metrics.device_id, metrics.instance, metrics.last_value, devices.name AS device_name "
                    "FROM metrics JOIN devices ON devices.id = metrics.device_id "
                    "WHERE metrics.key = ? AND metrics.last_value IS NOT NULL AND devices.enabled = 1 "
                    "ORDER BY metrics.last_value DESC LIMIT ?", (key, TOP_N))]

    interfaces = []
    for i in db.query(
            "SELECT interfaces.device_id, interfaces.if_index, interfaces.name, interfaces.alias, interfaces.speed, "
            "interfaces.in_bps, interfaces.out_bps, devices.name AS device_name, "
            "COALESCE(in_bps, 0) + COALESCE(out_bps, 0) AS total_bps FROM interfaces "
            "JOIN devices ON devices.id = interfaces.device_id WHERE devices.enabled = 1 "
            "AND COALESCE(in_bps, 0) + COALESCE(out_bps, 0) > 0 ORDER BY total_bps DESC LIMIT ?", (TOP_N,)):
        speed = i["speed"] or 0
        util = (max(i["in_bps"] or 0, i["out_bps"] or 0) / speed * 100) if speed else None
        interfaces.append({
            "device_id": i["device_id"], "device": i["device_name"], "name": i["name"], "alias": _txt(i["alias"], 80),
            "in_bps": i["in_bps"], "out_bps": i["out_bps"], "total_bps": i["total_bps"], "speed": i["speed"],
            "util_pct": util, "value": i["total_bps"],
            "link": f"/devices/{i['device_id']}?tab=interfaces#if{i['if_index']}",
        })

    collectors = {r["status"]: r["n"] for r in db.query(
        "SELECT status, COUNT(*) AS n FROM collectors WHERE enabled = 1 GROUP BY status")}
    ov = overview(db)
    return {
        "schema": SCHEMA,
        "server": {"name": name or "SNMPathy", "version": version_string(), "time": now},
        "overview": ov,
        "devices": devices,
        "checks": checks,
        "alerts": {"firing": ov["alerts"]["firing"], "critical": ov["alerts"]["critical"],
                   "warning": q("SELECT COUNT(*) FROM alerts WHERE state = 'firing' AND severity = 'warning'"),
                   "unacknowledged": ov["alerts"]["unacknowledged"]},
        "problems": problems[:MAX_PROBLEMS],
        "problems_total": len(problems),
        "firing": firing,
        "top": {
            "cpu": metric_top("cpu.avg"),
            "memory": metric_top("mem.used_pct"),
            "interfaces": interfaces,
            "availability": worst_availability(db, now),
        },
        "syslog": {"last_hour": ov["syslog"]["last_hour"], "errors_last_hour": ov["syslog"]["errors_last_hour"]},
        "collectors": {"total": sum(collectors.values()), "online": int(collectors.get("online", 0)),
                       "offline": int(collectors.get("offline", 0))},
    }


def worst_availability(db: Database, now: float | None = None, days: int = 30, limit: int = TOP_N) -> list[dict[str, Any]]:
    """The ``limit`` enabled devices with the lowest availability over ``days`` days.

    Only devices with an outage in the window can be below 100%, so those are
    evaluated first; the rest only fill the list up to ``limit``.
    """
    now = now or time.time()
    start = now - days * 86400
    with_outages = {r["device_id"] for r in db.query(
        "SELECT DISTINCT device_id FROM device_outages WHERE started_at < ? AND COALESCE(ended_at, ?) > ?",
        (now, now, start))}
    devices = db.query("SELECT * FROM devices WHERE enabled = 1 ORDER BY name COLLATE NOCASE")
    ordered = [d for d in devices if d["id"] in with_outages] + [d for d in devices if d["id"] not in with_outages]
    rows: list[dict[str, Any]] = []
    for d in ordered:
        if d["id"] not in with_outages and len(rows) >= limit:
            break
        a = reports.device_availability(db, d, start, now, now)
        if a["uptime_pct"] is None:
            continue
        rows.append({"device_id": d["id"], "device": d["name"], "value": a["uptime_pct"], "status": d["status"],
                     "outages": a["outages"], "downtime_seconds": a["downtime_seconds"],
                     "link": f"/devices/{d['id']}"})
    rows.sort(key=lambda r: (r["value"], r["device"]))
    return rows[:limit]


# ================================================================ remote fetch
def public_server(row: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """A fusion_servers row without its token or cached data."""
    now = now or time.time()
    out = {k: row.get(k) for k in ("id", "name", "url", "status", "error", "last_fetch", "last_ok", "created_at")}
    out["verify_tls"] = bool(row.get("verify_tls"))
    out["enabled"] = bool(row.get("enabled"))
    out["has_token"] = bool(row.get("api_token"))
    out["stale"] = _is_stale(row, now)
    return out


def _is_stale(row: dict[str, Any], now: float) -> bool:
    return not row.get("last_ok") or now - float(row["last_ok"]) > STALE_AFTER


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        hint = {401: "authentication failed - check the API token",
                403: "access denied - check the API token",
                404: "not found - is this an SNMPathy server with Fusion support?"}.get(code, exc.response.reason_phrase)
        return f"HTTP {code}: {hint}"
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.RequestError):
        return f"connection failed: {exc}" if str(exc) else f"connection failed ({type(exc).__name__})"
    return str(exc) or type(exc).__name__


async def fetch_server(db: Database, server_row: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
    """Fetch one remote's summary, cache it and record the outcome. Never raises for remote errors.

    Returns the updated public row (without token or data).
    """
    started = time.time()
    url = f"{str(server_row['url']).rstrip('/')}/api/fusion/summary"
    headers = {"Accept": "application/json", "User-Agent": f"SNMPathy-Fusion/{__version__}"}
    if server_row.get("api_token"):
        headers["Authorization"] = f"Bearer {server_row['api_token']}"
    changes: dict[str, Any]
    try:
        async with httpx.AsyncClient(verify=bool(server_row.get("verify_tls", 1)), timeout=timeout,
                                     follow_redirects=False) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise ValueError(f"response too large ({len(resp.content)} bytes)")
            try:
                data = resp.json()
            except ValueError as exc:
                raise ValueError("response is not JSON - is this an SNMPathy server?") from exc
            if not isinstance(data, dict) or not isinstance(data.get("server"), dict):
                raise ValueError("response is not an SNMPathy Fusion summary")
        changes = {"status": "ok", "error": "", "last_fetch": started, "last_ok": time.time(),
                   "data": json.dumps(data, separators=(",", ":"))}
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - every failure is recorded on the row
        if isinstance(exc, httpx.HTTPStatusError) and exc.response.is_redirect:
            msg = f"HTTP {exc.response.status_code}: redirected to {exc.response.headers.get('location', '?')}"
        else:
            msg = _error_text(exc)
        log.info("fusion fetch of %s failed: %s", server_row.get("name"), msg)
        changes = {"status": "error", "error": _txt(msg, 500), "last_fetch": started}
    if db.one("SELECT 1 FROM fusion_servers WHERE id = ?", (server_row["id"],)):
        db.update("fusion_servers", server_row["id"], changes)
    row = db.one("SELECT * FROM fusion_servers WHERE id = ?", (server_row["id"],)) or {**server_row, **changes}
    return public_server(row)


async def fetch_all(db: Database, timeout: float = 10.0, concurrency: int = 8) -> list[dict[str, Any]]:
    """Fetch every enabled remote server concurrently."""
    rows = db.query("SELECT * FROM fusion_servers WHERE enabled = 1 ORDER BY name COLLATE NOCASE")
    if not rows:
        return []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(row: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            return await fetch_server(db, row, timeout=timeout)

    results = await asyncio.gather(*(one(r) for r in rows), return_exceptions=True)
    out = []
    for row, res in zip(rows, results):
        if isinstance(res, BaseException):
            log.error("fusion fetch of %s crashed: %r", row["name"], res)
            continue
        out.append(res)
    return out


class FusionPoller:
    """Background task that refreshes every enabled remote's summary every ``interval`` seconds."""

    def __init__(self, db: Database, interval: float = DEFAULT_INTERVAL, timeout: float = 10.0):
        self.db = db
        self.interval = max(5.0, float(interval or DEFAULT_INTERVAL))
        self.timeout = float(timeout)
        self._task: asyncio.Task | None = None
        self.last_run: float | None = None

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._task = asyncio.create_task(self._run(), name="fusion-poller")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def run_once(self) -> list[dict[str, Any]]:
        self.last_run = time.time()
        return await fetch_all(self.db, timeout=self.timeout)

    async def _run(self) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("fusion poll failed")
            await asyncio.sleep(self.interval)


# ================================================================ combined view
def _counts(src: Any, keys: tuple[str, ...]) -> dict[str, int]:
    src = src if isinstance(src, dict) else {}
    return {k: _int(src.get(k)) for k in keys}


DEVICE_KEYS = ("up", "degraded", "down", "unreachable", "unknown", "disabled", "total")
CHECK_KEYS = ("up", "warning", "down", "unknown", "paused", "total")
ALERT_KEYS = ("firing", "critical", "warning", "unacknowledged")


def combined(db: Database, local: dict[str, Any], local_base: str = "", now: float | None = None,
             top_n: int = TOP_N) -> dict[str, Any]:
    """Merge the local summary with every enabled remote's cached summary."""
    now = now or time.time()
    entries: list[tuple[dict[str, Any], dict[str, Any]]] = []
    local_info = {
        "id": None, "name": "This server", "hostname": (local.get("server") or {}).get("name", ""),
        "local": True, "url": local_base or "", "status": "ok", "error": "", "stale": False,
        "last_fetch": now, "last_ok": now, "age": 0.0, "enabled": True,
    }
    entries.append((local_info, local))
    for row in db.query("SELECT * FROM fusion_servers WHERE enabled = 1 ORDER BY name COLLATE NOCASE"):
        data = loads(row["data"], {})
        data = data if isinstance(data, dict) else {}
        has_data = bool(data.get("server"))
        stale = _is_stale(row, now)
        status = row["status"] or "unknown"
        if status == "ok" and stale:
            status = "stale"
        elif status == "unknown" and not row["last_fetch"]:
            status = "pending"
        info = public_server(row, now)
        info.update({
            "local": False, "status": status, "stale": stale and has_data,
            "hostname": _txt((data.get("server") or {}).get("name", ""), 120) if has_data else "",
            "age": (now - row["last_ok"]) if row["last_ok"] else None,
            "url": _safe_base(data.get("base_url")) or row["url"],
        })
        entries.append((info, data if has_data else {}))

    totals = {
        "servers": {"total": len(entries), "ok": 0, "stale": 0, "error": 0, "pending": 0},
        "devices": dict.fromkeys(DEVICE_KEYS, 0), "checks": dict.fromkeys(CHECK_KEYS, 0),
        "alerts": dict.fromkeys(ALERT_KEYS, 0), "syslog": {"last_hour": 0, "errors_last_hour": 0},
        "collectors": {"total": 0, "online": 0, "offline": 0}, "problems": 0,
    }
    servers, problems, firing = [], [], []
    top: dict[str, list[dict[str, Any]]] = {"cpu": [], "memory": [], "interfaces": [], "availability": []}
    for info, data in entries:
        status = info["status"]
        totals["servers"][status if status in ("ok", "stale", "error") else "pending"] += 1
        tag = {"server": info["name"], "server_id": info["id"], "server_local": info["local"],
               "server_stale": bool(info.get("stale")) or status == "error"}
        base = info["url"]
        if status in ("error", "stale") and not info["local"]:
            problems.append({**tag, "server_stale": False, "kind": "server", "name": info["name"],
                             "status": "down" if status == "error" else "warning",
                             "since": info.get("last_ok") or info.get("created_at"),
                             "detail": info.get("error") or f"no fresh data for {int(info['age'] or 0)}s",
                             "url": base})
        devices = _counts(data.get("devices"), DEVICE_KEYS)
        checks = _counts(data.get("checks"), CHECK_KEYS)
        alerts = _counts(data.get("alerts"), ALERT_KEYS)
        for key, group in (("devices", devices), ("checks", checks), ("alerts", alerts),
                           ("syslog", _counts(data.get("syslog"), ("last_hour", "errors_last_hour"))),
                           ("collectors", _counts(data.get("collectors"), ("total", "online", "offline")))):
            for k, v in group.items():
                totals[key][k] += v
        n_problems = _int(data.get("problems_total")) or len(data.get("problems") or [])
        totals["problems"] += n_problems
        version = (data.get("server") or {}).get("version") if data else None
        servers.append({**info, "version": _txt(version, 40) if version else "", "devices": devices,
                        "checks": checks, "alerts": alerts, "problems": n_problems,
                        "problems_shown": len(data.get("problems") or [])})
        for p in data.get("problems") or []:
            if not isinstance(p, dict):
                continue
            problems.append({**tag, "kind": _txt(p.get("kind"), 20), "name": _txt(p.get("name"), 200),
                             "status": _txt(p.get("status"), 20), "since": _num(p.get("since")),
                             "detail": _txt(p.get("detail")), "device": _txt(p.get("device"), 200),
                             "url": _abs_link(base, p.get("link"))})
        for a in data.get("firing") or []:
            if not isinstance(a, dict):
                continue
            firing.append({**tag, "subject": _txt(a.get("subject"), 200), "severity": _txt(a.get("severity"), 20),
                           "message": _txt(a.get("message")), "started_at": _num(a.get("started_at")),
                           "fired_at": _num(a.get("fired_at")), "acknowledged": bool(a.get("acknowledged")),
                           "ack_by": _txt(a.get("ack_by"), 80), "url": _abs_link(base, a.get("link"))})
        remote_top = data.get("top") if isinstance(data.get("top"), dict) else {}
        for key in top:
            for item in remote_top.get(key) or []:
                if not isinstance(item, dict) or _num(item.get("value")) is None:
                    continue
                entry = {**tag, "device": _txt(item.get("device"), 200), "value": _num(item.get("value")),
                         "url": _abs_link(base, item.get("link"))}
                if key == "interfaces":
                    entry.update(name=_txt(item.get("name"), 120), alias=_txt(item.get("alias"), 80),
                                 in_bps=_num(item.get("in_bps")), out_bps=_num(item.get("out_bps")),
                                 speed=_num(item.get("speed")), util_pct=_num(item.get("util_pct")))
                elif key == "availability":
                    entry.update(outages=_int(item.get("outages")),
                                 downtime_seconds=_num(item.get("downtime_seconds")))
                top[key].append(entry)

    problems.sort(key=lambda p: (PROBLEM_RANK.get(p["status"], 9), 0 if p["kind"] == "server" else 1,
                                 p["since"] or now, p["server"].lower(), p["name"].lower()))
    firing.sort(key=lambda a: (SEVERITY_RANK.get(a["severity"], 3), -(a["fired_at"] or a["started_at"] or 0)))
    for key in ("cpu", "memory", "interfaces"):
        top[key].sort(key=lambda r: -r["value"])
    top["availability"].sort(key=lambda r: r["value"])
    return {
        "generated_at": now,
        "stale_after": STALE_AFTER,
        "servers": servers,
        "totals": totals,
        "problems": problems[:500],
        "firing": firing[:200],
        "top": {k: v[:top_n] for k, v in top.items()},
    }


# ======================================================================= routes
router = APIRouter()


def get_db(request: Request) -> Database:
    return request.app.state.db


class ServerIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=500)
    api_token: str = Field("", max_length=500)
    verify_tls: bool = True
    enabled: bool = True


class ServerPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    url: Optional[str] = Field(None, min_length=1, max_length=500)
    api_token: Optional[str] = Field(None, max_length=500)
    verify_tls: Optional[bool] = None
    enabled: Optional[bool] = None


def _row(db: Database, server_id: int) -> dict[str, Any]:
    row = db.one("SELECT * FROM fusion_servers WHERE id = ?", (server_id,))
    if not row:
        raise HTTPException(404, "fusion server not found")
    return row


def _check_url(url: str) -> str:
    try:
        return normalize_url(url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _check_name(db: Database, name: str, server_id: int | None = None) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(422, "name is required")
    if db.one("SELECT 1 FROM fusion_servers WHERE name = ? AND id IS NOT ?", (name, server_id)):
        raise HTTPException(422, f"a server named {name!r} already exists")
    return name


@router.get("/api/fusion/summary", tags=["fusion"])
def api_summary(request: Request, db: Database = Depends(get_db)):
    """Snapshot of this server for a Fusion master."""
    data = summary(db, server_name(request.app.state.settings))
    data["base_url"] = base_url_of(request)
    return data


@router.get("/api/fusion/combined", tags=["fusion"])
def api_combined(request: Request, db: Database = Depends(get_db)):
    """This server plus every enabled remote's cached summary, merged."""
    local = summary(db, server_name(request.app.state.settings))
    return combined(db, local, base_url_of(request))


@router.get("/api/fusion/servers", tags=["fusion"])
def list_servers(db: Database = Depends(get_db)):
    now = time.time()
    return [public_server(r, now) for r in db.query("SELECT * FROM fusion_servers ORDER BY name COLLATE NOCASE")]


@router.post("/api/fusion/servers", status_code=201, tags=["fusion"])
def create_server(body: ServerIn, db: Database = Depends(get_db)):
    values = {
        "name": _check_name(db, body.name), "url": _check_url(body.url), "api_token": body.api_token.strip(),
        "verify_tls": int(body.verify_tls), "enabled": int(body.enabled), "created_at": time.time(),
    }
    server_id = db.insert("fusion_servers", values)
    db.log_event("fusion.added", f"Fusion server {values['name']} ({values['url']}) added")
    return public_server(_row(db, server_id))


@router.get("/api/fusion/servers/{server_id}", tags=["fusion"])
def get_server(server_id: int, db: Database = Depends(get_db)):
    return public_server(_row(db, server_id))


@router.patch("/api/fusion/servers/{server_id}", tags=["fusion"])
def patch_server(server_id: int, body: ServerPatch, db: Database = Depends(get_db)):
    current = _row(db, server_id)
    data = body.model_dump(exclude_unset=True)
    changes: dict[str, Any] = {}
    if data.get("name") is not None:
        changes["name"] = _check_name(db, data["name"], server_id)
    if data.get("url") is not None:
        changes["url"] = _check_url(data["url"])
    if data.get("api_token"):
        # Write-only secret: an empty value keeps the stored token.
        changes["api_token"] = data["api_token"].strip()
    for key in ("verify_tls", "enabled"):
        if data.get(key) is not None:
            changes[key] = int(data[key])
    if any(k in changes and changes[k] != current[k] for k in ("url", "api_token", "verify_tls")):
        # Connection details changed: the cached data no longer proves anything.
        changes.update(status="unknown", error="")
    db.update("fusion_servers", server_id, changes)
    return public_server(_row(db, server_id))


@router.delete("/api/fusion/servers/{server_id}", status_code=204, tags=["fusion"])
def delete_server(server_id: int, db: Database = Depends(get_db)):
    row = _row(db, server_id)
    db.execute("DELETE FROM fusion_servers WHERE id = ?", (server_id,))
    db.log_event("fusion.deleted", f"Fusion server {row['name']} removed")


@router.post("/api/fusion/servers/{server_id}/refresh", tags=["fusion"])
async def refresh_server(server_id: int, db: Database = Depends(get_db)):
    """Fetch this server's summary now."""
    return await fetch_server(db, _row(db, server_id))


@router.post("/api/fusion/refresh", tags=["fusion"])
async def refresh_all(db: Database = Depends(get_db)):
    """Fetch every enabled server's summary now."""
    return await fetch_all(db)


@router.get("/fusion", response_class=HTMLResponse, include_in_schema=False)
def fusion_page(request: Request):
    from .web import render

    db = get_db(request)
    local = summary(db, server_name(request.app.state.settings))
    return render(request, "fusion.html", nav="fusion", fusion=combined(db, local, base_url_of(request)))
