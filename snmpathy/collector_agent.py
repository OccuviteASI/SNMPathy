"""Remote collector: the process installed at a site (``snmpathy collector``).

It keeps three loops running:

* **sync** - long-polls the central server for on-demand jobs and notices
  configuration changes (devices and checks assigned to this collector),
* **scheduler** - polls SNMP and runs checks on their intervals, locally,
* **uploader** - pushes results to the server in batches. While the server is
  unreachable results are kept (and spooled to disk), then replayed in order
  with their original timestamps, so no history is lost during WAN outages.

Only outbound HTTP(S) to the server is needed.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import platform
import random
import socket
import time
from pathlib import Path
from typing import Any

from . import __version__, version_string
from .checks.probes import ProbeResult
from .checks.runner import run_probe
from .collectors import encode_values
from .scanner import ScanOptions, default_client_factory, scan_host
from .snmp.client import PySnmpClient, SnmpCredentials, SnmpError

log = logging.getLogger("snmpathy.collector")

MAX_OUTBOX = 200_000
UPLOAD_BATCH = 1000


class CollectorAgent:
    def __init__(self, server: str, token: str, verify: bool | str = True, state_dir: str | os.PathLike = ".",
                 concurrency: int = 32, name: str = ""):
        self.server = server.rstrip("/")
        self.token = token
        self.verify = verify
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.spool = self.state_dir / "collector-outbox.jsonl"
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self.name = name or socket.gethostname()
        self.config: dict[str, Any] = {"version": "", "devices": [], "checks": []}
        self.outbox: collections.deque[dict[str, Any]] = collections.deque(maxlen=MAX_OUTBOX)
        self.answers: list[dict[str, Any]] = []
        self._due: dict[str, float] = {}
        self._fails: dict[str, int] = {}
        self._running: set[str] = set()
        self._clients: dict[int, tuple[str, PySnmpClient]] = {}
        self._tasks: set[asyncio.Task] = set()
        self.connected = False
        self.stats = {"polls": 0, "checks": 0, "jobs": 0, "uploaded": 0, "errors": 0}
        self._client = None
        self._load_spool()

    # -------------------------------------------------------------- http
    def _http(self):
        import httpx

        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.server, verify=self.verify, timeout=httpx.Timeout(40.0, connect=10.0),
                headers={"Authorization": f"Bearer {self.token}", "User-Agent": f"snmpathy-collector/{__version__}"},
            )
        return self._client

    def _info_headers(self) -> dict[str, str]:
        return {"X-Collector-Version": version_string(), "X-Collector-Hostname": self.name,
                "X-Collector-Platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
                "X-Collector-Backlog": str(len(self.outbox)),
                "X-Collector-Config": str(self.config.get("version") or "")}

    # -------------------------------------------------------------- spool
    def _load_spool(self) -> None:
        if not self.spool.exists():
            return
        try:
            with self.spool.open() as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self.outbox.append(json.loads(line))
            self.spool.unlink()
            log.info("replaying %d buffered results from %s", len(self.outbox), self.spool)
        except (OSError, ValueError) as exc:
            log.warning("could not read %s: %s", self.spool, exc)

    def _save_spool(self) -> None:
        try:
            if not self.outbox:
                if self.spool.exists():
                    self.spool.unlink()
                return
            tmp = self.spool.with_suffix(".tmp")
            with tmp.open("w") as fh:
                for item in self.outbox:
                    fh.write(json.dumps(item) + "\n")
            os.replace(tmp, self.spool)
        except OSError as exc:
            log.warning("could not write %s: %s", self.spool, exc)

    # -------------------------------------------------------------- main
    async def run(self) -> None:
        log.info("collector %s connecting to %s", self.name, self.server)
        loops = [self._sync_loop(), self._scheduler_loop(), self._upload_loop(), self._spool_loop()]
        try:
            await asyncio.gather(*loops)
        finally:
            self._save_spool()
            for _, c in self._clients.values():
                c.close()
            if self._client is not None:
                await self._client.aclose()

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _sync_loop(self) -> None:
        backoff = 2.0
        while True:
            try:
                r = await self._http().get("/api/collector/v1/poll", params={"wait": 25}, headers=self._info_headers())
                if r.status_code == 401:
                    log.error("the server rejected this collector's token; create a new one in Settings > Collectors")
                    await asyncio.sleep(60)
                    continue
                r.raise_for_status()
                body = r.json()
                if not self.connected:
                    log.info("connected to %s", self.server)
                self.connected, backoff = True, 2.0
                if body.get("config_version") != self.config.get("version"):
                    await self._fetch_config()
                for job in body.get("jobs") or []:
                    self._spawn(self._run_job(job))
            except Exception as exc:  # network errors, server restarts
                if self.connected:
                    log.warning("lost connection to %s: %s (results are buffered)", self.server, exc)
                self.connected = False
                await asyncio.sleep(backoff + random.uniform(0, 1))
                backoff = min(backoff * 2, 60.0)

    async def _fetch_config(self) -> None:
        r = await self._http().get("/api/collector/v1/config")
        r.raise_for_status()
        self.config = r.json()
        live = {f"d{d['id']}" for d in self.config["devices"] if d.get("snmp")} | {f"c{c['id']}" for c in self.config["checks"]}
        for key in list(self._due):
            if key not in live:
                self._due.pop(key, None)
        log.info("configuration %s: %d devices, %d checks", self.config.get("version"),
                 len(self.config["devices"]), len(self.config["checks"]))

    # --------------------------------------------------------- scheduling
    async def _scheduler_loop(self) -> None:
        while True:
            now = time.time()
            for d in self.config.get("devices", []):
                if not d.get("snmp"):
                    continue
                key = f"d{d['id']}"
                due = self._due.setdefault(key, now + random.uniform(0, 5))
                if now >= due and key not in self._running:
                    self._due[key] = now + max(10, int(d.get("poll_interval") or 300))
                    self._spawn(self._poll(d, key))
            for c in self.config.get("checks", []):
                key = f"c{c['id']}"
                due = self._due.setdefault(key, now + random.uniform(0, 3))
                if now >= due and key not in self._running:
                    interval = max(5, int(c.get("interval") or 60))
                    # Re-check faster while failing, like the central scheduler does.
                    self._due[key] = now + (min(interval, 20) if self._fails.get(key) else interval)
                    self._spawn(self._check(c, key))
            await asyncio.sleep(0.5)

    def _snmp_client(self, device: dict[str, Any]) -> PySnmpClient:
        fp = json.dumps([device["hostname"], device["creds"]], sort_keys=True)
        cached = self._clients.get(device["id"])
        if cached and cached[0] == fp:
            return cached[1]
        if cached:
            cached[1].close()
        client = PySnmpClient(device["hostname"], SnmpCredentials.from_device(device["creds"]), timeout=2.0, retries=1)
        self._clients[device["id"]] = (fp, client)
        return client

    async def _poll(self, device: dict[str, Any], key: str) -> None:
        self._running.add(key)
        try:
            async with self.sem:
                ts = time.time()
                started = time.perf_counter()
                item: dict[str, Any] = {"type": "snmp", "device_id": device["id"], "ts": ts}
                try:
                    values = await self._snmp_client(device).get(device["oids"])
                    item["values"] = encode_values(values)
                except SnmpError as exc:
                    item["error"] = str(exc)
                item["duration_ms"] = (time.perf_counter() - started) * 1000
                self.outbox.append(item)
                self.stats["polls"] += 1
        except Exception:
            log.exception("poll of %s failed", device.get("name"))
            self.stats["errors"] += 1
        finally:
            self._running.discard(key)

    async def _check(self, check: dict[str, Any], key: str) -> None:
        self._running.add(key)
        try:
            async with self.sem:
                ts = time.time()
                result = await run_probe(check, check.get("device"))
                self._fails[key] = 0 if result.ok else self._fails.get(key, 0) + 1
                self.outbox.append({"type": "check", "check_id": check["id"], "ts": ts, **result.as_dict()})
                self.stats["checks"] += 1
        except Exception:
            log.exception("check %s failed", check.get("name"))
            self.stats["errors"] += 1
        finally:
            self._running.discard(key)

    # --------------------------------------------------------------- jobs
    async def _run_job(self, job: dict[str, Any]) -> None:
        answer: dict[str, Any] = {"id": job["id"]}
        try:
            async with self.sem:
                answer["result"] = await execute_job(job["op"], job.get("params") or {})
            answer["ok"] = True
        except SnmpError as exc:
            answer.update(ok=False, error=str(exc), error_type="snmp")
        except Exception as exc:
            answer.update(ok=False, error=f"{type(exc).__name__}: {exc}")
        self.stats["jobs"] += 1
        self.answers.append(answer)
        await self._flush()

    # ------------------------------------------------------------- upload
    async def _upload_loop(self) -> None:
        while True:
            await asyncio.sleep(2.0)
            await self._flush()

    async def _flush(self) -> None:
        if not self.outbox and not self.answers:
            return
        batch = [self.outbox[i] for i in range(min(UPLOAD_BATCH, len(self.outbox)))]
        answers, self.answers = self.answers, []
        try:
            r = await self._http().post("/api/collector/v1/results", json={"results": batch, "jobs": answers},
                                        headers=self._info_headers())
            r.raise_for_status()
        except Exception as exc:
            self.answers = answers + self.answers if answers else self.answers
            log.debug("upload failed: %s", exc)
            return
        for _ in batch:
            self.outbox.popleft()
        self.stats["uploaded"] += len(batch)

    async def _spool_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            if not self.connected and self.outbox:
                self._save_spool()


async def execute_job(op: str, params: dict[str, Any]) -> Any:
    """Run one on-demand job sent by the server."""
    if op in ("snmp_get", "snmp_walk"):
        client = PySnmpClient(params["host"], SnmpCredentials.from_device(params.get("creds") or {}),
                              timeout=float(params.get("timeout") or 2), retries=int(params.get("retries") or 1))
        try:
            if op == "snmp_get":
                return encode_values(await client.get(list(params.get("oids") or [])))
            return encode_values(await client.walk(params["oid"]))
        finally:
            client.close()
    if op == "check":
        check = params["check"]
        result: ProbeResult = await run_probe(check, check.get("device"))
        return result.as_dict()
    if op == "scan_host":
        opts = ScanOptions.from_dict(params.get("options") or {})
        return await scan_host(params["target"], opts, run_probe, default_client_factory)
    if op == "ping":
        return {"pong": time.time(), "version": __version__}
    raise ValueError(f"unknown job {op!r}")


def load_collector_config(path: str | os.PathLike | None) -> dict[str, Any]:
    """Read ``collector.yaml`` (server, token, verify_tls, ca_file, state_dir, concurrency, name)."""
    from .config import app_dir, is_frozen

    candidates = [Path(path)] if path else []
    if not path:
        candidates += [app_dir() / "collector.yaml"] if is_frozen() else []
        candidates += [Path("collector.yaml")]
    for candidate in candidates:
        if candidate.exists():
            import yaml

            with candidate.open() as fh:
                data = yaml.safe_load(fh) or {}
            data["_path"] = str(candidate)
            return data
    if path:
        raise FileNotFoundError(path)
    return {}
