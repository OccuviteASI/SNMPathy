"""Device availability: decides whether a device is online from several sources.

A device can have more than one way of telling whether it is alive: SNMP
polling, a ping check, a TCP/HTTP check and so on. One failing method does
not have to mean the device is offline (ICMP may be filtered while SNMP
works, or the SNMP agent may hang while the box still forwards traffic), so
each device has an *availability rule* that combines its sources:

``any``     online while at least one source answers (default)
``all``     offline as soon as any source fails
``quorum``  online while at least ``avail_min`` sources answer
``snmp``    only SNMP polling decides
``checks``  only the device's availability checks decide (e.g. ping)

Like Nagios, a failing device whose *parent* device is down, or whose remote
collector is offline, is ``unreachable`` instead of ``down``.

Checks can be left out of the decision individually (``checks.affects_device``).
A device that is online while some of its sources fail is flagged
``degraded`` so the UI can show the partial failure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .db import Database

AVAIL_MODES: dict[str, str] = {
    "any": "Online if any method responds",
    "all": "Online only if every method responds",
    "quorum": "Online if at least N methods respond",
    "snmp": "SNMP polling only",
    "checks": "Availability checks only (ping, TCP, HTTP…)",
}


@dataclass
class Source:
    kind: str  # "snmp" or the check type
    name: str
    state: str  # up / down / unknown
    since: float | None = None
    message: str = ""
    check_id: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "state": self.state, "since": self.since,
                "message": self.message, "check_id": self.check_id}


@dataclass
class Verdict:
    state: str  # up / down / unknown
    since: float | None
    degraded: bool
    reason: str
    required: int
    sources: list[Source]


def device_sources(db: Database, device: dict[str, Any]) -> list[Source]:
    """The sources that count towards ``device``'s availability under its rule."""
    mode = device.get("avail_mode") or "any"
    sources: list[Source] = []
    if mode != "checks" and device.get("snmp_enabled"):
        sources.append(Source(
            kind="snmp", name="SNMP", state=device.get("snmp_status") or "unknown",
            since=device.get("snmp_since"),
            message=(device.get("last_error") or "") if device.get("snmp_status") == "down" else "",
        ))
    if mode != "snmp":
        for c in db.query(
            "SELECT id, name, type, state, state_since, last_message FROM checks "
            "WHERE device_id = ? AND enabled = 1 AND affects_device = 1 ORDER BY id", (device["id"],)
        ):
            sources.append(Source(kind=c["type"], name=c["name"], state=c["state"] or "unknown",
                                  since=c["state_since"], message=c["last_message"] or "", check_id=c["id"]))
    return sources


def _label(source: Source) -> str:
    return "SNMP" if source.kind == "snmp" else source.name


def combine(sources: list[Source], mode: str = "any", min_up: int = 2) -> Verdict:
    """Combine source states into a device verdict."""
    known = [s for s in sources if s.state in ("up", "down")]
    if not sources:
        return Verdict("unknown", None, False, "no availability sources (enable SNMP or add a check)", 0, sources)
    if not known:
        return Verdict("unknown", None, False, "waiting for the first result", 0, sources)
    up = [s for s in known if s.state == "up"]
    down = [s for s in known if s.state == "down"]
    if mode == "all":
        required = len(known)
    elif mode == "quorum":
        required = max(1, min(int(min_up or 1), len(known)))
    else:
        required = 1
    online = len(up) >= required
    since = None
    if not online:
        # The device went down when the k-th source failed, k being the number of
        # failures it takes to drop below the required count.
        failures_needed = len(known) - required + 1
        times = sorted(s.since for s in down if s.since is not None)
        if len(times) >= failures_needed:
            since = times[failures_needed - 1]
        elif times:
            since = times[-1]
    failing = ", ".join(_label(s) + (f" ({s.message})" if s.message else "") for s in down)
    if online and down:
        reason = f"{len(up)} of {len(known)} methods responding; failing: {failing}"
    elif online:
        reason = "responding to " + ", ".join(_label(s) for s in up)
    else:
        reason = f"{len(up)} of {len(known)} methods responding (needs {required}); failing: {failing}"
    return Verdict("up" if online else "down", since, online and bool(down), reason[:500], required, sources)


def describe_rule(device: dict[str, Any]) -> str:
    mode = device.get("avail_mode") or "any"
    if mode == "quorum":
        return f"Online if at least {int(device.get('avail_min') or 2)} methods respond"
    return AVAIL_MODES.get(mode, mode)


def _blocker(db: Database, device: dict[str, Any]) -> str:
    """Why a failing device cannot be reached at all (Nagios' UNREACHABLE), or ''."""
    if device.get("collector_id"):
        col = db.one("SELECT name, status FROM collectors WHERE id = ?", (device["collector_id"],))
        if col and col["status"] == "offline":
            return f"collector {col['name']} is offline"
    if device.get("parent_id"):
        parent = db.one("SELECT name, status FROM devices WHERE id = ?", (device["parent_id"],))
        if parent and parent["status"] in ("down", "unreachable"):
            return f"parent {parent['name']} is {parent['status']}"
    return ""


def evaluate_device(db: Database, device_id: int, now: float | None = None, _seen: set[int] | None = None) -> str | None:
    """Recompute a device's status from its sources and record any transition.

    Returns the new status (``up``, ``down``, ``unreachable`` or ``unknown``)
    when it changed, otherwise ``None``. A failing device whose parent is down,
    or whose collector is offline, is ``unreachable`` rather than ``down`` (as
    in Nagios), so only the device at the root of a failure raises alerts.
    Device outages are written to ``device_outages`` and backdated to the
    moment the deciding source failed. Children are re-evaluated on change.
    """
    now = now or time.time()
    seen = _seen if _seen is not None else set()
    if device_id in seen:
        return None
    seen.add(device_id)
    device = db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if not device:
        return None
    verdict = combine(device_sources(db, device), device.get("avail_mode") or "any", device.get("avail_min") or 2)
    state, reason = verdict.state, verdict.reason
    blocker = _blocker(db, device)
    if blocker and (state == "down" or (device.get("collector_id") and "collector" in blocker)):
        # With the collector offline nothing is known about the device; with the
        # parent down a failure is explained by the parent.
        state, reason = "unreachable", f"{blocker}; {reason}"[:500]
    old = device.get("status") or "unknown"
    changes: dict[str, Any] = {}
    if reason != device.get("status_reason"):
        changes["status_reason"] = reason
    degraded = verdict.degraded and state == "up"
    if int(degraded) != int(device.get("degraded") or 0):
        changes["degraded"] = int(degraded)
    if state != "unknown" and not device.get("avail_started"):
        changes["avail_started"] = now
    transition = None
    with db.transaction():
        if state != old:
            transition = state
            since = verdict.since if (state in ("down", "unreachable") and verdict.since) else now
            since = min(since, now)
            changes.update(status=state, status_since=since)
            open_outage = db.one(
                "SELECT id FROM device_outages WHERE device_id = ? AND ended_at IS NULL", (device_id,))
            if state in ("down", "unreachable"):
                if not open_outage:
                    db.insert("device_outages", {"device_id": device_id, "started_at": since, "reason": reason})
                if state == "down":
                    db.log_event("device.down", f"{device['name']} is OFFLINE: {reason}", "error",
                                 device_id=device_id, ts=now)
                else:
                    db.log_event("device.unreachable", f"{device['name']} is UNREACHABLE: {reason}", "warning",
                                 device_id=device_id, ts=now)
            else:
                if open_outage:
                    db.update("device_outages", open_outage["id"], {"ended_at": now})
                if old in ("down", "unreachable") and state == "up":
                    db.log_event("device.up", f"{device['name']} is back ONLINE ({reason})", "info",
                                 device_id=device_id, ts=now)
        if changes:
            db.update("devices", device_id, changes)
    if transition:
        for child in db.query("SELECT id FROM devices WHERE parent_id = ?", (device_id,)):
            evaluate_device(db, child["id"], now, seen)
    return transition


def evaluate_collector_devices(db: Database, collector_id: int, now: float | None = None) -> int:
    changed = 0
    for row in db.query("SELECT id FROM devices WHERE collector_id = ?", (collector_id,)):
        if evaluate_device(db, row["id"], now):
            changed += 1
    return changed


def evaluate_all(db: Database, now: float | None = None) -> int:
    """Re-evaluate every device (used at start-up and after imports)."""
    changed = 0
    for row in db.query("SELECT id FROM devices"):
        if evaluate_device(db, row["id"], now):
            changed += 1
    return changed


def device_report(db: Database, device: dict[str, Any]) -> dict[str, Any]:
    """Current verdict plus per-source detail, for the UI and API."""
    verdict = combine(device_sources(db, device), device.get("avail_mode") or "any", device.get("avail_min") or 2)
    return {
        "state": verdict.state, "degraded": verdict.degraded, "reason": verdict.reason,
        "required": verdict.required, "rule": describe_rule(device), "mode": device.get("avail_mode") or "any",
        "sources": [s.as_dict() for s in verdict.sources],
    }
