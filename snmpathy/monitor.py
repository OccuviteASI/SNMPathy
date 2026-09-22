"""The monitoring engine: schedules SNMP polls, availability checks,
alert evaluation, rollups and retention on a single asyncio loop."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
from typing import Any, Callable

from .alerting.engine import AlertEngine
from .alerting.notify import dispatch
from .checks.runner import ProbeFunc, execute_check
from .config import Settings
from .db import Database
from .snmp.client import PySnmpClient, SnmpClient, SnmpCredentials, SnmpError
from .snmp.discovery import apply_discovery, discover
from .snmp.poller import poll_device
from .scheduled import run_due as run_due_reports
from .storage import apply_retention, rollup
from .syslog.server import SyslogServer

log = logging.getLogger(__name__)

REDISCOVER_INTERVAL = 6 * 3600
ROLLUP_INTERVAL = 60
RETENTION_INTERVAL = 3600

SnmpFactory = Callable[[dict[str, Any], Settings], SnmpClient]


def default_snmp_factory(device: dict[str, Any], settings: Settings) -> SnmpClient:
    return PySnmpClient(
        device["hostname"], SnmpCredentials.from_device(device),
        timeout=settings.snmp_timeout, retries=settings.snmp_retries,
    )


def _creds_fingerprint(device: dict[str, Any]) -> str:
    keys = ("hostname", "snmp_version", "snmp_port", "snmp_community", "v3_user", "v3_auth_proto",
            "v3_auth_key", "v3_priv_proto", "v3_priv_key", "v3_context")
    return hashlib.sha1(json.dumps([device.get(k) for k in keys]).encode()).hexdigest()


class Monitor:
    def __init__(self, db: Database, settings: Settings, snmp_factory: SnmpFactory | None = None,
                 probe: ProbeFunc | None = None):
        self.db = db
        self.settings = settings
        self.snmp_factory = snmp_factory or default_snmp_factory
        self.probe = probe
        self.alerts = AlertEngine(db, notifier=self._notify)
        self.syslog: SyslogServer | None = None
        self._tasks: list[asyncio.Task] = []
        self._sem = asyncio.Semaphore(max(1, settings.poller_concurrency))
        self._clients: dict[int, tuple[str, SnmpClient]] = {}
        self._next_poll: dict[int, float] = {}
        self._next_check: dict[int, float] = {}
        self._inflight: set[str] = set()
        self._jobs: set[asyncio.Task] = set()
        self._alert_wakeup = asyncio.Event()
        self.started_at = time.time()
        self.counters = {"polls": 0, "poll_failures": 0, "checks": 0, "alert_evals": 0}

    # ----------------------------------------------------------- lifecycle
    async def start(self) -> None:
        s = self.settings
        if s.enable_syslog and (s.syslog_udp_port or s.syslog_tcp_port):
            self.syslog = SyslogServer(self.db, s.syslog_host, s.syslog_udp_port, s.syslog_tcp_port,
                                       s.syslog_batch_size, s.syslog_flush_interval)
            await self.syslog.start()
        if s.enable_poller:
            self._spawn(self._poll_loop(), "snmp-poller")
            self._spawn(self._check_loop(), "check-runner")
        if s.enable_alerting:
            self._spawn(self._alert_loop(), "alert-engine")
        self._spawn(self._housekeeping_loop(), "housekeeping")
        log.info("monitor started (poller=%s syslog=%s alerting=%s)", s.enable_poller, s.enable_syslog,
                 s.enable_alerting)

    def _job(self, coro) -> None:
        # Hold a reference so fire-and-forget jobs are not garbage collected mid-flight.
        task = asyncio.create_task(coro)
        self._jobs.add(task)
        task.add_done_callback(self._jobs.discard)

    def _spawn(self, coro, name: str) -> None:
        task = asyncio.create_task(coro, name=name)
        self._tasks.append(task)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks.clear()
        for job in list(self._jobs):
            job.cancel()
        if self._jobs:
            await asyncio.gather(*self._jobs, return_exceptions=True)
        if self.syslog:
            await self.syslog.stop()
        for _, client in self._clients.values():
            client.close()
        self._clients.clear()

    # ----------------------------------------------------------- SNMP
    def _client(self, device: dict[str, Any]) -> SnmpClient:
        fp = _creds_fingerprint(device)
        cached = self._clients.get(device["id"])
        if cached and cached[0] == fp:
            return cached[1]
        if cached:
            cached[1].close()
        client = self.snmp_factory(device, self.settings)
        self._clients[device["id"]] = (fp, client)
        return client

    def forget_device(self, device_id: int) -> None:
        cached = self._clients.pop(device_id, None)
        if cached:
            cached[1].close()
        self._next_poll.pop(device_id, None)
        if self.syslog:
            self.syslog.invalidate_devices()

    async def discover_device(self, device_id: int) -> dict[str, Any]:
        device = self.db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
        if not device:
            raise KeyError(device_id)
        client = self._client(device)
        try:
            result = await discover(client)
        except SnmpError as exc:
            # last_discovered stays unset so the next poll retries discovery.
            self.db.update("devices", device_id, {"last_error": str(exc)[:500]})
            raise
        summary = apply_discovery(self.db, device_id, result)
        self.db.log_event("device.discovered",
                          f"Discovered {summary['interfaces']} interfaces and {summary['metrics']} metrics on {device['name']}",
                          device_id=device_id)
        return summary

    async def poll_now(self, device_id: int) -> dict[str, Any]:
        device = self.db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
        if not device:
            raise KeyError(device_id)
        return await self._poll_job(device)

    async def _poll_job(self, device: dict[str, Any]) -> dict[str, Any]:
        key = f"d{device['id']}"
        self._inflight.add(key)
        try:
            async with self._sem:
                client = self._client(device)
                needs_discovery = not device.get("last_discovered") or (
                    time.time() - device["last_discovered"] > REDISCOVER_INTERVAL
                )
                if needs_discovery:
                    try:
                        await self.discover_device(device["id"])
                    except SnmpError as exc:
                        log.info("discovery of %s failed: %s", device["name"], exc)
                    device = self.db.one("SELECT * FROM devices WHERE id = ?", (device["id"],)) or device
                result = await poll_device(self.db, client, device)
                self.counters["polls"] += 1
                if not result.ok:
                    self.counters["poll_failures"] += 1
                    self._alert_wakeup.set()
                elif result.events:
                    self._alert_wakeup.set()
                return {"ok": result.ok, "samples": result.samples, "duration_ms": result.duration_ms,
                        "error": result.error, "events": result.events}
        except Exception as exc:
            log.exception("poll of %s crashed", device.get("name"))
            return {"ok": False, "error": str(exc)}
        finally:
            self._inflight.discard(key)

    async def _poll_loop(self) -> None:
        while True:
            now = time.time()
            devices = self.db.query("SELECT * FROM devices WHERE enabled = 1 AND snmp_enabled = 1")
            live = set()
            for device in devices:
                live.add(device["id"])
                interval = max(10, int(device["poll_interval"] or self.settings.default_poll_interval))
                due = self._next_poll.get(device["id"])
                if due is None:
                    if device["last_polled"]:
                        due = min(device["last_polled"] + interval, now + random.uniform(0, 10))
                    else:
                        due = now + random.uniform(0, 3)
                    self._next_poll[device["id"]] = due
                if now >= due and f"d{device['id']}" not in self._inflight:
                    self._next_poll[device["id"]] = now + interval
                    self._job(self._poll_job(device))
            for stale in set(self._next_poll) - live:
                self.forget_device(stale)
            await asyncio.sleep(1)

    # ----------------------------------------------------------- checks
    async def run_check_now(self, check_id: int) -> dict[str, Any]:
        check = self.db.one("SELECT * FROM checks WHERE id = ?", (check_id,))
        if not check:
            raise KeyError(check_id)
        return await self._check_job(check)

    async def _check_job(self, check: dict[str, Any]) -> dict[str, Any]:
        key = f"c{check['id']}"
        self._inflight.add(key)
        try:
            async with self._sem:
                updated = await execute_check(self.db, check, self.probe)
                self.counters["checks"] += 1
                if updated.get("transition") in {"up", "down"}:
                    self._alert_wakeup.set()
                return updated
        except Exception as exc:
            log.exception("check %s crashed", check.get("name"))
            return {**check, "error": str(exc)}
        finally:
            self._inflight.discard(key)

    async def _check_loop(self) -> None:
        while True:
            now = time.time()
            live = set()
            for check in self.db.query("SELECT * FROM checks WHERE enabled = 1"):
                live.add(check["id"])
                interval = max(5, int(check["interval"] or self.settings.default_check_interval))
                due = self._next_check.get(check["id"])
                if due is None:
                    due = (check["last_checked"] + interval) if check["last_checked"] else now + random.uniform(0, 2)
                    due = min(due, now + random.uniform(0, 5))
                    self._next_check[check["id"]] = due
                if now >= due and f"c{check['id']}" not in self._inflight:
                    # Re-probe faster while a check is failing but not yet declared down.
                    fast = check["fail_count"] and check["state"] != "down"
                    self._next_check[check["id"]] = now + (min(interval, 20) if fast else interval)
                    self._job(self._check_job(check))
            for stale in set(self._next_check) - live:
                self._next_check.pop(stale, None)
            await asyncio.sleep(0.5)

    def reschedule_check(self, check_id: int) -> None:
        self._next_check.pop(check_id, None)

    def reschedule_device(self, device_id: int) -> None:
        self._next_poll.pop(device_id, None)

    # ----------------------------------------------------------- alerting
    async def _notify(self, event: str, alert: dict[str, Any], rule: dict[str, Any]) -> None:
        await dispatch(self.db, event, alert, rule, self.settings)

    async def evaluate_alerts(self) -> dict[str, int]:
        stats = await self.alerts.evaluate()
        self.counters["alert_evals"] += 1
        return stats

    async def _alert_loop(self) -> None:
        interval = max(5, int(self.settings.alert_eval_interval))
        while True:
            try:
                await self.evaluate_alerts()
            except Exception:
                log.exception("alert evaluation failed")
            self._alert_wakeup.clear()
            try:
                await asyncio.wait_for(self._alert_wakeup.wait(), interval)
                await asyncio.sleep(0.5)  # let bursts of state changes settle
            except asyncio.TimeoutError:
                pass

    # ----------------------------------------------------------- housekeeping
    async def _housekeeping_loop(self) -> None:
        last_retention = 0.0
        while True:
            try:
                await asyncio.to_thread(rollup, self.db)
                await run_due_reports(self.db, self.settings)
                if time.time() - last_retention > RETENTION_INTERVAL:
                    removed = await asyncio.to_thread(apply_retention, self.db, self.settings)
                    last_retention = time.time()
                    log.info("retention: %s", removed)
            except Exception:
                log.exception("housekeeping failed")
            await asyncio.sleep(ROLLUP_INTERVAL)

    # ----------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "uptime": time.time() - self.started_at,
            "counters": dict(self.counters),
            "inflight": len(self._inflight),
            "syslog": ({**self.syslog.stats.as_dict(), "listening": self.syslog.listening}
                       if self.syslog else None),
            "tasks": {t.get_name(): (not t.done()) for t in self._tasks},
        }
