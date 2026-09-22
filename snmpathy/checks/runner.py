"""Runs availability checks and maintains their up/down state and outage history."""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any, Awaitable, Callable

from ..db import Database, loads
from ..snmp.client import SnmpCredentials
from . import probes
from .probes import ProbeResult

CHECK_TYPES = ("icmp", "tcp", "http", "snmp", "dns")

ProbeFunc = Callable[[dict[str, Any], dict[str, Any] | None], Awaitable[ProbeResult]]


async def run_probe(check: dict[str, Any], device: dict[str, Any] | None = None) -> ProbeResult:
    ctype = check["type"]
    target = check["target"]
    timeout = float(check.get("timeout") or 5)
    options = loads(check.get("options"), {}) if isinstance(check.get("options"), str) else (check.get("options") or {})
    try:
        if ctype == "icmp":
            return await probes.ping(target, timeout=timeout, count=int(options.get("count", 1)))
        if ctype == "tcp":
            return await probes.tcp_check(target, int(check.get("port") or 0), timeout)
        if ctype == "http":
            url = target if "://" in target else f"http://{target}"
            return await probes.http_check(url, timeout, options)
        if ctype == "snmp":
            creds = SnmpCredentials.from_device(device) if device else SnmpCredentials(
                community=options.get("community", "public"), port=int(check.get("port") or 161)
            )
            return await probes.snmp_check(target, creds, timeout)
        if ctype == "dns":
            start = time.perf_counter()
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(loop.getaddrinfo(target, None, type=socket.SOCK_STREAM), timeout)
            addrs = sorted({i[4][0] for i in infos})
            expected = options.get("expected")
            if expected and expected not in addrs:
                return ProbeResult(False, None, f"resolved to {', '.join(addrs)} (expected {expected})")
            return ProbeResult(True, (time.perf_counter() - start) * 1000, ", ".join(addrs[:4]))
    except asyncio.TimeoutError:
        return ProbeResult(False, None, f"timeout after {timeout:.1f}s")
    except (OSError, ValueError) as exc:
        return ProbeResult(False, None, str(exc))
    return ProbeResult(False, None, f"unknown check type {ctype!r}")


def in_maintenance(db: Database, check: dict[str, Any], now: float) -> bool:
    row = db.one(
        "SELECT 1 FROM maintenance WHERE starts_at <= ? AND ends_at > ? AND "
        "((device_id IS NULL AND check_id IS NULL) OR check_id = ? OR (device_id IS NOT NULL AND device_id = ?))",
        (now, now, check["id"], check.get("device_id")),
    )
    return row is not None


def record_result(db: Database, check: dict[str, Any], result: ProbeResult, now: float | None = None) -> dict[str, Any]:
    """Store a probe result and advance the check's state machine.

    A check goes ``down`` only after ``retries + 1`` consecutive failures and
    ``up`` again on the first success. Outages are backdated to the first
    failed probe so downtime figures are accurate.
    """
    now = now or time.time()
    retries = int(check.get("retries") or 0)
    state = check.get("state") or "unknown"
    fail_count = int(check.get("fail_count") or 0)
    changes: dict[str, Any] = {
        "last_checked": now,
        "last_latency_ms": result.latency_ms,
        "last_message": (result.message or "")[:500],
        "updated_at": now,
    }
    transition = None
    with db.transaction():
        db.execute(
            "INSERT OR REPLACE INTO heartbeats (check_id, ts, ok, latency_ms, message) VALUES (?, ?, ?, ?, ?)",
            (check["id"], now, 1 if result.ok else 0, result.latency_ms, (result.message or "")[:200]),
        )
        if result.ok:
            changes["fail_count"] = 0
            if state != "up":
                changes.update(state="up", state_since=now)
                open_outage = db.one(
                    "SELECT id FROM outages WHERE check_id = ? AND ended_at IS NULL", (check["id"],)
                )
                if open_outage:
                    db.update("outages", open_outage["id"], {"ended_at": now})
                transition = "up" if state == "down" else "first-up"
        else:
            fail_count += 1
            changes["fail_count"] = fail_count
            if fail_count > retries and state != "down":
                first_fail = db.scalar(
                    "SELECT MIN(ts) FROM heartbeats WHERE check_id = ? AND ok = 0 AND ts > "
                    "COALESCE((SELECT MAX(ts) FROM heartbeats WHERE check_id = ? AND ok = 1), 0)",
                    (check["id"], check["id"]),
                ) or now
                changes.update(state="down", state_since=first_fail)
                db.insert("outages", {
                    "check_id": check["id"], "started_at": first_fail, "reason": (result.message or "")[:500],
                })
                transition = "down"
        db.update("checks", check["id"], changes)
        if transition == "down":
            db.log_event("check.down", f"{check['name']} is DOWN: {result.message}", "error",
                         device_id=check.get("device_id"), check_id=check["id"], ts=now)
        elif transition == "up":
            db.log_event("check.up", f"{check['name']} is UP again ({result.message})", "info",
                         device_id=check.get("device_id"), check_id=check["id"], ts=now)
    check = dict(check)
    check.update(changes)
    check["transition"] = transition
    return check


async def execute_check(db: Database, check: dict[str, Any], probe: ProbeFunc | None = None) -> dict[str, Any]:
    device = None
    if check.get("device_id"):
        device = db.one("SELECT * FROM devices WHERE id = ?", (check["device_id"],))
    result = await (probe or run_probe)(check, device)
    return record_result(db, check, result)
