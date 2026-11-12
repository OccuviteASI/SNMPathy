"""Central side of remote collectors (distributed monitoring, Nagios style).

A *collector* is SNMPathy running in ``collector`` mode at a remote site. It
connects out to the central server over HTTP(S), so sites need no inbound
firewall rules, and then:

* pulls its configuration: the devices (with SNMP credentials and the OIDs
  to poll) and checks assigned to it,
* polls and checks them on its own schedule, so monitoring continues while
  the WAN is down, and pushes the results back (like Nagios passive check
  results). Results are buffered on the collector and replayed with their
  original timestamps after an outage,
* runs on-demand jobs the server queues for it: SNMP get/walk (discovery,
  "test SNMP"), "check now", and network-scan host probes.

The server feeds the pushed results through the same code paths as local
polling (:func:`poll_device`, :func:`record_result`), so graphs, outages,
availability rules and alerts behave identically. A collector that stops
calling in is marked offline and the devices it monitors become
``unreachable`` (Nagios' freshness checking) instead of ``down``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from typing import Any

from .availability import evaluate_collector_devices
from .checks.probes import ProbeResult
from .checks.runner import record_result
from .db import Database, loads
from .snmp import mibs
from .snmp.client import SnmpCredentials, SnmpError, SnmpValue

log = logging.getLogger(__name__)

OFFLINE_AFTER = 90.0  # seconds without contact before a collector is offline
PROTOCOL_VERSION = 1


class CollectorOffline(SnmpError):
    """Raised for jobs sent to a collector that is not connected."""


class RemoteError(Exception):
    pass


# ----------------------------------------------------------------- tokens
def new_token() -> str:
    return "col_" + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_collector(db: Database, name: str, site: str = "", description: str = "") -> tuple[dict[str, Any], str]:
    name = (name or "").strip()
    if not name:
        raise ValueError("name is required")
    if db.one("SELECT 1 FROM collectors WHERE name = ?", (name,)):
        raise ValueError(f"a collector named {name!r} already exists")
    token = new_token()
    cid = db.insert("collectors", {"name": name[:100], "site": site[:100], "description": description[:500],
                                   "token_hash": hash_token(token), "created_at": time.time()})
    db.log_event("collector.added", f"Collector {name} added")
    return db.one("SELECT * FROM collectors WHERE id = ?", (cid,)), token


def rotate_token(db: Database, collector_id: int) -> str:
    if not db.one("SELECT 1 FROM collectors WHERE id = ?", (collector_id,)):
        raise KeyError(collector_id)
    token = new_token()
    db.update("collectors", collector_id, {"token_hash": hash_token(token)})
    return token


def authenticate(db: Database, token: str) -> dict[str, Any] | None:
    if not token or not token.startswith("col_"):
        return None
    row = db.one("SELECT * FROM collectors WHERE token_hash = ?", (hash_token(token),))
    if row and hmac.compare_digest(row["token_hash"], hash_token(token)) and row["enabled"]:
        return row
    return None


def public_collector(row: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in row.items() if k != "token_hash"}
    out["online"] = row.get("status") == "online"
    return out


def delete_collector(db: Database, collector_id: int) -> None:
    with db.transaction():
        db.execute("UPDATE devices SET collector_id = NULL WHERE collector_id = ?", (collector_id,))
        db.execute("UPDATE checks SET collector_id = NULL WHERE collector_id = ?", (collector_id,))
        db.execute("UPDATE scans SET collector_id = NULL WHERE collector_id = ?", (collector_id,))
        db.execute("DELETE FROM collectors WHERE id = ?", (collector_id,))


# ------------------------------------------------------------ value codec
def encode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"b64": base64.b64encode(value).decode()}
    return value


def decode_value(value: Any) -> SnmpValue:
    if isinstance(value, dict) and "b64" in value:
        return base64.b64decode(value["b64"])
    return value


def encode_values(values: dict[str, Any]) -> dict[str, Any]:
    return {k: encode_value(v) for k, v in values.items()}


def decode_values(values: dict[str, Any] | None) -> dict[str, SnmpValue]:
    return {k: decode_value(v) for k, v in (values or {}).items()}


def creds_dict(device: dict[str, Any]) -> dict[str, Any]:
    keys = ("snmp_version", "snmp_port", "snmp_community", "v3_user", "v3_auth_proto", "v3_auth_key",
            "v3_priv_proto", "v3_priv_key", "v3_context")
    return {k: device.get(k) for k in keys}


# ------------------------------------------------------------ SNMP clients
class PrefetchedClient:
    """SnmpClient that replays values a collector already fetched."""

    def __init__(self, values: dict[str, SnmpValue] | None, error: str = ""):
        self.values = values or {}
        self.error = error

    async def get(self, oids: list[str]) -> dict[str, SnmpValue]:
        if self.error:
            raise SnmpError(self.error)
        return {o: self.values.get(o) for o in oids}

    async def walk(self, oid: str) -> dict[str, SnmpValue]:
        raise SnmpError("walk is not available from pushed results")

    def close(self) -> None:
        pass


class RemoteSnmpClient:
    """SnmpClient that runs each request on a collector (used for discovery)."""

    def __init__(self, hub: "CollectorHub", collector_id: int, host: str, device: dict[str, Any],
                 timeout: float = 2.0, retries: int = 1):
        self.hub, self.collector_id, self.host = hub, collector_id, host
        self.creds, self.timeout, self.retries = creds_dict(device), timeout, retries

    def _params(self, **extra: Any) -> dict[str, Any]:
        return {"host": self.host, "creds": self.creds, "timeout": self.timeout, "retries": self.retries, **extra}

    async def get(self, oids: list[str]) -> dict[str, SnmpValue]:
        result = await self.hub.call(self.collector_id, "snmp_get", self._params(oids=list(oids)),
                                     timeout=self.timeout * (self.retries + 1) * (len(oids) // 24 + 1) + 30)
        return decode_values(result)

    async def walk(self, oid: str) -> dict[str, SnmpValue]:
        result = await self.hub.call(self.collector_id, "snmp_walk", self._params(oid=oid), timeout=300)
        return decode_values(result)

    def close(self) -> None:
        pass


# ------------------------------------------------------------------- hub
class CollectorHub:
    """Job relay, configuration source and result sink for all collectors."""

    def __init__(self, db: Database, offline_after: float = OFFLINE_AFTER, on_change: Any = None):
        self.db = db
        self.offline_after = offline_after
        self.on_change = on_change  # callable() poked when device/check states may have changed
        self._queues: dict[int, asyncio.Queue] = {}
        self._pending: dict[str, tuple[int, asyncio.Future]] = {}
        self._config_cache: dict[int, tuple[float, str, dict[str, Any]]] = {}

    # ------------------------------------------------------------- status
    def is_online(self, collector_id: int) -> bool:
        return self.db.scalar("SELECT status FROM collectors WHERE id = ?", (collector_id,)) == "online"

    def touch(self, collector: dict[str, Any], info: dict[str, Any], now: float | None = None) -> None:
        now = now or time.time()
        changes = {"last_seen": now, **{k: str(v)[:200] for k, v in info.items()
                                        if k in ("last_ip", "hostname", "platform", "version") and v}}
        if "backlog" in info:
            try:
                changes["backlog"] = int(info["backlog"])
            except (TypeError, ValueError):
                pass
        came_online = collector.get("status") != "online"
        if came_online:
            changes["status"] = "online"
        self.db.update("collectors", collector["id"], changes)
        if came_online:
            self.db.log_event("collector.online", f"Collector {collector['name']} connected"
                              + (f" from {info.get('last_ip')}" if info.get("last_ip") else ""), "info")
            evaluate_collector_devices(self.db, collector["id"], now)
            self._poke()

    def sweep(self, now: float | None = None) -> list[int]:
        """Mark collectors that stopped calling in as offline. Returns their ids."""
        now = now or time.time()
        gone = []
        for c in self.db.query("SELECT * FROM collectors WHERE status = 'online' AND COALESCE(last_seen, 0) < ?",
                               (now - self.offline_after,)):
            self.db.update("collectors", c["id"], {"status": "offline"})
            self.db.log_event("collector.offline",
                              f"Collector {c['name']} stopped reporting (last contact {int(now - (c['last_seen'] or now))}s ago); "
                              "its devices are now unreachable", "error")
            evaluate_collector_devices(self.db, c["id"], now)
            self._fail_pending(c["id"], f"collector {c['name']} is offline")
            gone.append(c["id"])
        if gone:
            self._poke()
        return gone

    def _poke(self) -> None:
        if self.on_change:
            try:
                self.on_change()
            except Exception:  # pragma: no cover - notification only
                log.exception("collector change callback failed")

    # --------------------------------------------------------------- jobs
    def _queue(self, collector_id: int) -> asyncio.Queue:
        q = self._queues.get(collector_id)
        if q is None:
            q = self._queues[collector_id] = asyncio.Queue()
        return q

    async def call(self, collector_id: int, op: str, params: dict[str, Any], timeout: float = 60.0) -> Any:
        """Run ``op`` on a collector and wait for its answer."""
        row = self.db.one("SELECT name, status FROM collectors WHERE id = ?", (collector_id,))
        if not row:
            raise CollectorOffline(f"collector {collector_id} does not exist")
        if row["status"] != "online":
            raise CollectorOffline(f"collector {row['name']} is offline")
        job_id = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self._pending[job_id] = (collector_id, future)
        await self._queue(collector_id).put({"id": job_id, "op": op, "params": params, "queued": time.time()})
        try:
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError as exc:
            raise CollectorOffline(f"collector {row['name']} did not answer within {timeout:.0f}s") from exc
        finally:
            self._pending.pop(job_id, None)

    async def next_jobs(self, collector_id: int, wait: float = 25.0, limit: int = 200,
                        until: Any = None) -> list[dict[str, Any]]:
        """Jobs for a collector, waiting up to ``wait`` seconds for the first one.

        ``until`` is checked every few seconds and ends the wait early (used to
        return promptly when the collector's configuration changes).
        """
        q = self._queue(collector_id)
        jobs: list[dict[str, Any]] = []
        deadline = time.monotonic() + wait
        while True:
            remaining = deadline - time.monotonic()
            try:
                jobs.append(await asyncio.wait_for(q.get(), max(0.0, min(remaining, 3.0)) if until else max(0.0, remaining)))
                break
            except asyncio.TimeoutError:
                if remaining <= 3.0 or (until and until()):
                    return jobs
        while not q.empty() and len(jobs) < limit:
            jobs.append(q.get_nowait())
        # Drop jobs nobody waits for any more (timed out while queued).
        return [j for j in jobs if j["id"] in self._pending]

    def resolve(self, collector_id: int, answers: list[dict[str, Any]]) -> int:
        n = 0
        for a in answers:
            entry = self._pending.get(str(a.get("id")))
            if not entry or entry[0] != collector_id or entry[1].done():
                continue
            if a.get("ok"):
                entry[1].set_result(a.get("result"))
            elif a.get("error_type") == "snmp":
                entry[1].set_exception(SnmpError(a.get("error") or "SNMP error on collector"))
            else:
                entry[1].set_exception(RemoteError(a.get("error") or "job failed on collector"))
            n += 1
        return n

    def _fail_pending(self, collector_id: int, message: str) -> None:
        for cid, fut in list(self._pending.values()):
            if cid == collector_id and not fut.done():
                fut.set_exception(CollectorOffline(message))

    # ------------------------------------------------------------- config
    def config(self, collector_id: int) -> dict[str, Any]:
        """Everything the collector schedules itself: devices to poll and checks to run."""
        cached = self._config_cache.get(collector_id)
        if cached and time.time() - cached[0] < 3:
            return cached[2]
        devices = []
        rows = self.db.query("SELECT * FROM devices WHERE collector_id = ? AND enabled = 1", (collector_id,))
        for d in rows:
            oids: set[str] = {mibs.SYS_UPTIME}
            if d["snmp_enabled"] and d["last_discovered"]:
                for m in self.db.query("SELECT oid, oid2 FROM metrics WHERE device_id = ? AND enabled = 1", (d["id"],)):
                    if m["oid"]:
                        oids.add(m["oid"])
                    if m["oid2"]:
                        oids.add(m["oid2"])
            devices.append({
                "id": d["id"], "name": d["name"], "hostname": d["hostname"],
                # Undiscovered devices are not polled until discovery (run through this collector) finishes.
                "snmp": bool(d["snmp_enabled"] and d["last_discovered"]),
                "poll_interval": int(d["poll_interval"] or 300), "creds": creds_dict(d), "oids": sorted(oids),
            })
        device_by_id = {d["id"]: d for d in rows}
        checks = []
        for c in self.db.query("SELECT * FROM checks WHERE collector_id = ? AND enabled = 1 AND type != 'passive'",
                               (collector_id,)):
            dev = device_by_id.get(c["device_id"]) or (
                self.db.one("SELECT * FROM devices WHERE id = ?", (c["device_id"],)) if c["device_id"] else None)
            checks.append({
                "id": c["id"], "name": c["name"], "type": c["type"], "target": c["target"], "port": c["port"],
                "interval": int(c["interval"] or 60), "timeout": float(c["timeout"] or 5),
                "retries": int(c["retries"] or 0), "options": loads(c["options"], {}),
                "device": ({"name": dev["name"], **creds_dict(dev)} if dev else None),
            })
        body = {"devices": devices, "checks": checks}
        version = hashlib.sha1(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:16]
        config = {"version": version, "protocol": PROTOCOL_VERSION, **body}
        self._config_cache[collector_id] = (time.time(), version, config)
        return config

    def config_version(self, collector_id: int) -> str:
        return self.config(collector_id)["version"]

    def invalidate(self, collector_id: int | None = None) -> None:
        if collector_id is None:
            self._config_cache.clear()
        else:
            self._config_cache.pop(collector_id, None)

    # ------------------------------------------------------------ results
    async def ingest(self, collector: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, int]:
        """Apply results a collector pushed (oldest first)."""
        from .snmp.poller import poll_device

        counts = {"accepted": 0, "ignored": 0}
        cid = collector["id"]
        changed = False
        for item in sorted(results, key=lambda r: float(r.get("ts") or 0)):
            ts = float(item.get("ts") or time.time())
            ts = min(ts, time.time())
            kind = item.get("type")
            if kind == "check":
                check = self.db.one("SELECT * FROM checks WHERE id = ? AND collector_id = ?", (item.get("check_id"), cid))
                if not check or (check["last_checked"] and ts <= check["last_checked"]):
                    counts["ignored"] += 1
                    continue
                updated = record_result(self.db, check, ProbeResult.from_dict(item), now=ts)
                changed = changed or bool(updated.get("transition"))
            elif kind == "snmp":
                device = self.db.one("SELECT * FROM devices WHERE id = ? AND collector_id = ?",
                                     (item.get("device_id"), cid))
                if not device or not device["snmp_enabled"] or (device["last_polled"] and ts <= device["last_polled"]):
                    counts["ignored"] += 1
                    continue
                client = PrefetchedClient(decode_values(item.get("values")), item.get("error") or "")
                result = await poll_device(self.db, client, device, now=ts, duration_ms=item.get("duration_ms"))
                changed = changed or (not result.ok) or bool(result.events)
            else:
                counts["ignored"] += 1
                continue
            counts["accepted"] += 1
        if counts["accepted"]:
            self.db.execute("UPDATE collectors SET results = results + ? WHERE id = ?", (counts["accepted"], cid))
        if changed:
            self._poke()
        return counts

    # --------------------------------------------------------------- misc
    async def run_check(self, collector_id: int, check: dict[str, Any], device: dict[str, Any] | None) -> ProbeResult:
        """Run a check on a collector right now ("check now" button)."""
        payload = {k: check.get(k) for k in ("id", "name", "type", "target", "port", "interval", "timeout", "retries")}
        payload["options"] = loads(check["options"], {}) if isinstance(check.get("options"), str) else check.get("options") or {}
        payload["device"] = {"name": device["name"], **creds_dict(device)} if device else None
        timeout = float(check.get("timeout") or 5) + 30
        try:
            result = await self.call(collector_id, "check", {"check": payload}, timeout=timeout)
        except (CollectorOffline, RemoteError) as exc:
            return ProbeResult(False, None, f"collector: {exc}")
        return ProbeResult.from_dict(result or {})

    def credentials(self, device: dict[str, Any]) -> SnmpCredentials:
        return SnmpCredentials.from_device(device)
