"""Network scanning: sweep IP ranges for devices and add them automatically.

A scan expands its targets (CIDR blocks, ranges, single addresses or host
names), probes each host with ICMP, optional TCP ports and SNMP (trying every
configured community / v3 user in turn) and records the hosts that answer.
Responding hosts can be added as devices automatically, with the SNMP
credentials that worked, a ping check and the scan's tags.

:func:`scan_host` has no database access so a remote probe can run it on the
far side of a WAN link; :class:`ScanManager` runs scans in the background on
the server, either locally or through a probe, and re-runs recurring scans.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Awaitable, Callable

from .db import Database, loads
from .snmp import mibs
from .snmp.client import SnmpClient, SnmpError

log = logging.getLogger(__name__)

MAX_HOSTS = 65536
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$")
AUTO_ADD = ("none", "snmp", "alive")
SECRET_KEYS = ("auth_key", "priv_key")


class TargetError(ValueError):
    pass


def _count_range(a: ipaddress._BaseAddress, b: ipaddress._BaseAddress) -> int:
    return int(b) - int(a) + 1


def expand_targets(spec: str, exclude: str = "", limit: int = MAX_HOSTS) -> list[str]:
    """Turn a target specification into a list of addresses / host names.

    Accepts, separated by commas, semicolons or whitespace:
    ``10.0.0.0/24``, ``10.0.0.1-50``, ``10.0.0.1-10.0.1.20``, ``10.0.0.7``,
    ``2001:db8::/120`` and host names. Network and broadcast addresses of
    IPv4 blocks larger than /31 are skipped. ``exclude`` uses the same syntax.
    """
    out: list[str] = []
    seen: set[str] = set()
    excluded = set(expand_targets(exclude, limit=limit)) if exclude and exclude.strip() else set()

    def add(item: str) -> None:
        if item not in seen and item not in excluded:
            seen.add(item)
            out.append(item)
            if len(out) > limit:
                raise TargetError(f"too many hosts (more than {limit}); split the scan into smaller ranges")

    for token in re.split(r"[\s,;]+", spec or ""):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise TargetError(f"invalid network {token!r}: {exc}") from exc
            if net.num_addresses > limit + 2:
                raise TargetError(f"{token} has {net.num_addresses} addresses (limit {limit})")
            hosts = net.hosts() if net.num_addresses > 2 else iter(net)
            for ip in hosts:
                add(str(ip))
            continue
        if "-" in token and not HOSTNAME_RE.match(token) or (token.count("-") == 1 and _looks_like_ip(token.split("-")[0])):
            first, _, last = token.partition("-")
            try:
                start = ipaddress.ip_address(first)
            except ValueError as exc:
                raise TargetError(f"invalid range {token!r}") from exc
            try:
                if "." in last or ":" in last:
                    end = ipaddress.ip_address(last)
                elif start.version == 4:
                    octets = str(start).split(".")
                    end = ipaddress.ip_address(".".join(octets[:3] + [last]))
                else:
                    raise ValueError
            except ValueError as exc:
                raise TargetError(f"invalid range {token!r}") from exc
            if end.version != start.version or end < start:
                raise TargetError(f"invalid range {token!r}: end before start")
            if _count_range(start, end) > limit:
                raise TargetError(f"{token} has {_count_range(start, end)} addresses (limit {limit})")
            for n in range(int(start), int(end) + 1):
                add(str(ipaddress.ip_address(n)))
            continue
        if _looks_like_ip(token):
            add(str(ipaddress.ip_address(token)))
        elif re.fullmatch(r"[\d.]+", token):
            raise TargetError(f"invalid address {token!r}")
        elif HOSTNAME_RE.match(token):
            add(token.rstrip(".").lower())
        else:
            raise TargetError(f"not an address, range or host name: {token!r}")
    return out


def _looks_like_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


@dataclass
class ScanOptions:
    """How to probe each host, and what to do with the ones that answer."""
    communities: list[str] = field(default_factory=lambda: ["public"])
    # SNMPv3 users to try: {user, auth_proto, auth_key, priv_proto, priv_key, context}
    v3: list[dict[str, Any]] = field(default_factory=list)
    snmp: bool = True
    snmp_port: int = 161
    ping: bool = True
    tcp_ports: list[int] = field(default_factory=list)
    timeout: float = 1.5
    concurrency: int = 64
    resolve_dns: bool = True
    snmp_only_if_alive: bool = False
    exclude: str = ""
    # What to add automatically: none, snmp (hosts that answered SNMP) or alive (any answer)
    auto_add: str = "none"
    add_ping_check: bool = True
    tags: list[str] = field(default_factory=lambda: ["discovered"])
    location: str = ""
    poll_interval: int = 300
    avail_mode: str = "any"

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScanOptions":
        data = dict(data or {})
        known = {f.name for f in fields(cls)}
        opts = cls(**{k: v for k, v in data.items() if k in known})
        opts.communities = [c for c in (str(x).strip() for x in opts.communities or []) if c]
        opts.tcp_ports = sorted({int(p) for p in opts.tcp_ports or [] if 0 < int(p) < 65536})
        opts.timeout = max(0.2, min(float(opts.timeout), 30.0))
        opts.concurrency = max(1, min(int(opts.concurrency), 512))
        if opts.auto_add not in AUTO_ADD:
            raise ValueError(f"auto_add must be one of {', '.join(AUTO_ADD)}")
        if isinstance(opts.tags, str):
            opts.tags = [t.strip() for t in opts.tags.split(",") if t.strip()]
        return opts

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def credentials(self) -> list[dict[str, Any]]:
        """Device-style SNMP credential sets, in the order they are tried."""
        creds: list[dict[str, Any]] = []
        if not self.snmp:
            return creds
        for community in self.communities:
            creds.append({"snmp_version": "2c", "snmp_community": community, "snmp_port": self.snmp_port})
        for user in self.v3:
            if not user.get("user"):
                continue
            creds.append({
                "snmp_version": "3", "snmp_port": self.snmp_port, "v3_user": user["user"],
                "v3_auth_proto": user.get("auth_proto") or "sha", "v3_auth_key": user.get("auth_key") or "",
                "v3_priv_proto": user.get("priv_proto") or "aes", "v3_priv_key": user.get("priv_key") or "",
                "v3_context": user.get("context") or "",
            })
        return creds


def public_options(options: dict[str, Any]) -> dict[str, Any]:
    """Scan options with SNMPv3 passphrases blanked (they are write-only)."""
    out = dict(options)
    out["v3"] = [{**u, **{k: "" for k in SECRET_KEYS}, **{f"has_{k}": bool(u.get(k)) for k in SECRET_KEYS}}
                 for u in options.get("v3") or []]
    return out


# A check-shaped probe function (checks.runner.run_probe, a demo probe or a remote probe).
ProbeFunc = Callable[[dict[str, Any], dict[str, Any] | None], Awaitable[Any]]
# (address, device-style credential dict, timeout) -> SnmpClient
ClientFactory = Callable[[str, dict[str, Any], float], SnmpClient]


async def _reverse_dns(ip: str, timeout: float) -> str:
    loop = asyncio.get_running_loop()
    try:
        name, _ = await asyncio.wait_for(loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout)
        return "" if name == ip else name
    except (OSError, asyncio.TimeoutError, UnicodeError):
        return ""


async def scan_host(target: str, opts: ScanOptions, probe: ProbeFunc, client_factory: ClientFactory) -> dict[str, Any] | None:
    """Probe one host. Returns a result dict if anything answered, else ``None``."""
    result: dict[str, Any] = {
        "ip": target, "dns_name": "", "ping_ms": None, "open_ports": [], "snmp": 0, "snmp_cred": None,
        "snmp_version": "", "sys_name": "", "sys_descr": "", "sys_object_id": "", "vendor": "",
    }
    is_ip = _looks_like_ip(target)
    if not is_ip:
        result["dns_name"] = target
    tasks: list[Awaitable[Any]] = []
    if opts.ping:
        tasks.append(probe({"type": "icmp", "target": target, "timeout": opts.timeout,
                            "options": {"count": 1}}, None))
    for port in opts.tcp_ports:
        tasks.append(probe({"type": "tcp", "target": target, "port": port, "timeout": opts.timeout,
                            "options": {}}, None))
    answers = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
    idx = 0
    if opts.ping:
        ping = answers[0]
        idx = 1
        if not isinstance(ping, BaseException) and getattr(ping, "ok", False):
            result["ping_ms"] = ping.latency_ms if ping.latency_ms is not None else 0.0
    for port, ans in zip(opts.tcp_ports, answers[idx:]):
        if not isinstance(ans, BaseException) and getattr(ans, "ok", False):
            result["open_ports"].append(port)
    alive = result["ping_ms"] is not None or bool(result["open_ports"])

    if not opts.snmp_only_if_alive or alive:
        for n, cred in enumerate(opts.credentials()):
            client = client_factory(target, cred, opts.timeout)
            try:
                values = await client.get([mibs.SYS_DESCR, mibs.SYS_OBJECT_ID, mibs.SYS_NAME])
            except SnmpError:
                continue
            except Exception as exc:  # a broken agent must not abort the sweep
                log.debug("SNMP probe of %s failed: %s", target, exc)
                continue
            finally:
                client.close()
            if all(v is None for v in values.values()):
                continue
            from .snmp.discovery import as_text

            result.update(
                snmp=1, snmp_cred=n, snmp_version=cred["snmp_version"],
                sys_descr=as_text(values.get(mibs.SYS_DESCR))[:1000],
                sys_object_id=as_text(values.get(mibs.SYS_OBJECT_ID)),
                sys_name=as_text(values.get(mibs.SYS_NAME))[:255],
            )
            result["vendor"] = mibs.vendor_from_sysobjectid(result["sys_object_id"])
            break
    if not alive and not result["snmp"]:
        return None
    if is_ip and opts.resolve_dns:
        result["dns_name"] = await _reverse_dns(target, max(1.0, opts.timeout))
    return result


# --------------------------------------------------------------------------- server side
def suggest_name(result: dict[str, Any]) -> str:
    name = (result.get("sys_name") or "").strip()
    if not name or name.lower() in {"localhost", "localhost.localdomain", "(none)"}:
        name = (result.get("dns_name") or "").strip().rstrip(".")
    return (name or result["ip"])[:128]


def _unique_name(db: Database, name: str, ip: str) -> str:
    if not db.one("SELECT 1 FROM devices WHERE name = ?", (name,)):
        return name
    candidate = f"{name} ({ip})"[:128]
    n = 2
    while db.one("SELECT 1 FROM devices WHERE name = ?", (candidate,)):
        candidate = f"{name} ({ip}) #{n}"[:128]
        n += 1
    return candidate


def add_result(db: Database, scan: dict[str, Any], result: dict[str, Any]) -> int:
    """Create a device (plus availability checks) from a scan result. Returns the device id."""
    from .services import create_check, create_device

    opts = ScanOptions.from_dict(loads(scan["options"], {}) if isinstance(scan["options"], str) else scan["options"])
    creds = opts.credentials()
    cred = creds[result["snmp_cred"]] if result.get("snmp") and result.get("snmp_cred") is not None \
        and result["snmp_cred"] < len(creds) else {}
    values: dict[str, Any] = {
        "name": _unique_name(db, suggest_name(result), result["ip"]),
        "hostname": result["ip"],
        "snmp_enabled": 1 if result.get("snmp") else 0,
        "poll_interval": opts.poll_interval,
        "location": opts.location,
        "tags": list(opts.tags),
        "avail_mode": opts.avail_mode,
        "collector_id": scan.get("collector_id"),
        "notes": f"Found by network scan '{scan['name']}'",
        **cred,
    }
    extra = {k: result.get(k) or "" for k in ("sys_name", "sys_descr", "sys_object_id", "vendor")}
    pinged = result.get("ping_ms") is not None
    device = create_device(db, values, add_ping_check=bool(opts.add_ping_check and pinged), extra=extra)
    if not pinged and not result.get("snmp") and result.get("open_ports"):
        # Only a TCP port answered: watch that port so the device has an availability source.
        port = loads(result["open_ports"], []) if isinstance(result["open_ports"], str) else result["open_ports"]
        if port:
            create_check(db, {"device_id": device["id"], "name": f"{device['name']} TCP {port[0]}", "type": "tcp",
                              "target": result["ip"], "port": port[0], "interval": 60, "timeout": 3, "retries": 2,
                              "collector_id": scan.get("collector_id")})
    return device["id"]


class ScanManager:
    """Runs scans in the background and re-runs recurring ones when due."""

    def __init__(self, db: Database, local_probe: ProbeFunc | None = None,
                 local_clients: ClientFactory | None = None, hub: Any = None):
        self.db = db
        self.local_probe = local_probe
        self.local_clients = local_clients
        self.hub = hub
        self._tasks: dict[int, asyncio.Task] = {}
        # Scans that were running when the process stopped will never finish.
        db.execute("UPDATE scans SET state = 'interrupted', finished_at = ? WHERE state = 'running'", (time.time(),))

    # ---------------------------------------------------------------- CRUD
    def create(self, values: dict[str, Any]) -> dict[str, Any]:
        targets = (values.get("targets") or "").strip()
        opts = ScanOptions.from_dict(values.get("options") or {})
        hosts = expand_targets(targets, opts.exclude)
        if not hosts:
            raise TargetError("no targets to scan")
        now = time.time()
        interval = int(values.get("interval") or 0)
        scan_id = self.db.insert("scans", {
            "name": (values.get("name") or targets)[:200], "targets": targets, "options": _dumps(opts.to_dict()),
            "interval": interval, "collector_id": values.get("collector_id") or None, "total": len(hosts),
            "next_run": now + interval if interval else None, "created_at": now,
        })
        return self.get(scan_id)

    def update(self, scan_id: int, values: dict[str, Any]) -> dict[str, Any]:
        scan = self.get(scan_id)
        changes: dict[str, Any] = {}
        if "name" in values and values["name"]:
            changes["name"] = values["name"][:200]
        if "collector_id" in values:
            changes["collector_id"] = values["collector_id"] or None
        old_opts = loads(scan["options"], {})
        if "options" in values and values["options"] is not None:
            merged = {**old_opts, **values["options"]}
            # Keep stored v3 passphrases when the form sends blanks.
            old_v3 = {u.get("user"): u for u in old_opts.get("v3") or []}
            for user in merged.get("v3") or []:
                for key in SECRET_KEYS:
                    if not user.get(key) and user.get("user") in old_v3:
                        user[key] = old_v3[user["user"]].get(key, "")
            opts = ScanOptions.from_dict(merged)
            changes["options"] = _dumps(opts.to_dict())
            old_opts = opts.to_dict()
        if "targets" in values and values["targets"]:
            hosts = expand_targets(values["targets"], old_opts.get("exclude", ""))
            changes.update(targets=values["targets"].strip(), total=len(hosts))
        if "interval" in values and values["interval"] is not None:
            interval = int(values["interval"])
            changes["interval"] = interval
            changes["next_run"] = (scan["finished_at"] or time.time()) + interval if interval else None
        if changes:
            self.db.update("scans", scan_id, changes)
        return self.get(scan_id)

    def get(self, scan_id: int) -> dict[str, Any]:
        scan = self.db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        if not scan:
            raise KeyError(scan_id)
        return scan

    def delete(self, scan_id: int) -> None:
        self.cancel(scan_id)
        with self.db.transaction():
            self.db.execute("DELETE FROM scan_results WHERE scan_id = ?", (scan_id,))
            self.db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    # ---------------------------------------------------------------- running
    def is_running(self, scan_id: int) -> bool:
        task = self._tasks.get(scan_id)
        return bool(task and not task.done())

    def start(self, scan_id: int) -> dict[str, Any]:
        scan = self.get(scan_id)
        if self.is_running(scan_id):
            return scan
        self.db.update("scans", scan_id, {"state": "queued", "error": ""})
        task = asyncio.get_running_loop().create_task(self.run(scan_id), name=f"scan-{scan_id}")
        self._tasks[scan_id] = task
        task.add_done_callback(lambda _t, sid=scan_id: self._tasks.pop(sid, None) if self._tasks.get(sid) is _t else None)
        return self.get(scan_id)

    def cancel(self, scan_id: int) -> bool:
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    async def stop(self) -> None:
        tasks = [t for t in self._tasks.values() if not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def run_due(self, now: float | None = None) -> int:
        now = now or time.time()
        started = 0
        for scan in self.db.query("SELECT id FROM scans WHERE interval > 0 AND next_run IS NOT NULL AND next_run <= ?",
                                  (now,)):
            if not self.is_running(scan["id"]):
                self.start(scan["id"])
                started += 1
        return started

    def _executor(self, scan: dict[str, Any]) -> Callable[[str, ScanOptions], Awaitable[dict[str, Any] | None]]:
        if scan.get("collector_id"):
            if self.hub is None:
                raise RuntimeError("remote probes are not available")
            collector_id = scan["collector_id"]

            async def remote(target: str, opts: ScanOptions) -> dict[str, Any] | None:
                return await self.hub.call(collector_id, "scan_host", {"target": target, "options": opts.to_dict()},
                                           timeout=opts.timeout * (2 + len(opts.credentials())) + 30)
            return remote
        from .checks.runner import run_probe

        probe = self.local_probe or run_probe
        clients = self.local_clients or default_client_factory

        async def local(target: str, opts: ScanOptions) -> dict[str, Any] | None:
            return await scan_host(target, opts, probe, clients)
        return local

    async def run(self, scan_id: int) -> dict[str, Any]:
        scan = self.get(scan_id)
        opts = ScanOptions.from_dict(loads(scan["options"], {}))
        started = time.time()
        hosts = expand_targets(scan["targets"], opts.exclude)
        self.db.update("scans", scan_id, {"state": "running", "started_at": started, "finished_at": None,
                                          "total": len(hosts), "scanned": 0, "found": 0, "added": 0, "error": ""})
        self.db.execute("DELETE FROM scan_results WHERE scan_id = ?", (scan_id,))
        state, error = "done", ""
        progress = {"scanned": 0, "found": 0}
        last_flush = 0.0
        try:
            execute = self._executor(scan)
            sem = asyncio.Semaphore(opts.concurrency)

            async def one(target: str) -> None:
                nonlocal last_flush
                async with sem:
                    try:
                        found = await execute(target, opts)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        log.debug("scan of %s failed: %s", target, exc)
                        found = None
                        if "offline" in str(exc).lower():
                            raise
                progress["scanned"] += 1
                if found:
                    progress["found"] += 1
                    self._store(scan_id, found)
                if time.time() - last_flush > 0.5:
                    last_flush = time.time()
                    self.db.update("scans", scan_id, dict(progress))

            await asyncio.gather(*(one(h) for h in hosts))
            self.db.update("scans", scan_id, dict(progress))
            await self._match_existing(scan_id)
            if opts.auto_add != "none":
                added = self.add(scan_id, mode=opts.auto_add)
                self.db.update("scans", scan_id, {"added": len(added)})
        except asyncio.CancelledError:
            state = "cancelled"
            raise
        except Exception as exc:
            state, error = "failed", str(exc)[:500]
            log.warning("scan %s failed: %s", scan_id, exc)
        finally:
            finished = time.time()
            changes = {"state": state, "error": error, "finished_at": finished, **progress}
            if scan["interval"]:
                changes["next_run"] = finished + scan["interval"]
            self.db.update("scans", scan_id, changes)
            final = self.get(scan_id)
            if state == "done":
                self.db.log_event(
                    "scan.done", f"Scan '{scan['name']}' found {final['found']} hosts in {len(hosts)} addresses"
                    + (f", added {final['added']} devices" if final["added"] else ""), "info")
        return final

    def _store(self, scan_id: int, r: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO scan_results (scan_id, ip, dns_name, ping_ms, open_ports, snmp, snmp_cred, "
            "snmp_version, sys_name, sys_descr, sys_object_id, vendor, status, seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)",
            (scan_id, r["ip"], r.get("dns_name") or "", r.get("ping_ms"), _dumps(r.get("open_ports") or []),
             int(bool(r.get("snmp"))), r.get("snmp_cred"), r.get("snmp_version") or "", r.get("sys_name") or "",
             r.get("sys_descr") or "", r.get("sys_object_id") or "", r.get("vendor") or "", time.time()),
        )

    async def _match_existing(self, scan_id: int) -> None:
        """Mark results that are already monitored (by address or name)."""
        known: dict[str, int] = {}
        unresolved = []
        for d in self.db.query("SELECT id, hostname FROM devices"):
            host = d["hostname"].strip().lower()
            known[host] = d["id"]
            if not _looks_like_ip(host):
                unresolved.append((host, d["id"]))
        loop = asyncio.get_running_loop()

        async def resolve(host: str, device_id: int) -> None:
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), 3)
            except (OSError, asyncio.TimeoutError, UnicodeError):
                return
            for info in infos:
                known.setdefault(info[4][0], device_id)

        await asyncio.gather(*(resolve(h, i) for h, i in unresolved[:500]))
        for r in self.db.query("SELECT id, ip, dns_name FROM scan_results WHERE scan_id = ?", (scan_id,)):
            device_id = known.get(r["ip"].lower()) or (known.get(r["dns_name"].lower()) if r["dns_name"] else None)
            if device_id:
                self.db.update("scan_results", r["id"], {"status": "existing", "device_id": device_id})

    def add(self, scan_id: int, ips: list[str] | None = None, mode: str = "alive") -> list[dict[str, Any]]:
        """Add scan results as devices: the given ``ips``, or every new result matching ``mode``."""
        scan = self.get(scan_id)
        rows = self.db.query("SELECT * FROM scan_results WHERE scan_id = ? AND status IN ('new', 'error') ORDER BY id",
                             (scan_id,))
        if ips is not None:
            wanted = set(ips)
            rows = [r for r in rows if r["ip"] in wanted]
        elif mode == "snmp":
            rows = [r for r in rows if r["snmp"]]
        added = []
        for r in rows:
            try:
                device_id = add_result(self.db, scan, r)
            except Exception as exc:  # e.g. validation error: keep going with the rest
                self.db.update("scan_results", r["id"], {"status": "error", "message": str(exc)[:300]})
                continue
            self.db.update("scan_results", r["id"], {"status": "added", "device_id": device_id, "message": ""})
            added.append({"ip": r["ip"], "device_id": device_id})
        if added:
            self.db.execute("UPDATE scans SET added = added + ? WHERE id = ?", (len(added), scan_id))
            self.db.log_event("scan.added", f"Added {len(added)} devices from scan '{scan['name']}'", "info")
        return added


def default_client_factory(target: str, cred: dict[str, Any], timeout: float) -> SnmpClient:
    from .snmp.client import PySnmpClient, SnmpCredentials

    return PySnmpClient(target, SnmpCredentials.from_device(cred), timeout=timeout, retries=0)


def _dumps(value: Any) -> str:
    import json

    return json.dumps(value)
