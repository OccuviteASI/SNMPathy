"""Command line interface: ``snmpathy serve``, ``snmpathy walk`` and friends."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import socket
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__

EXAMPLE_CONFIG = """\
# SNMPathy configuration. Every key can also be set with an environment
# variable: SNMPATHY_<KEY> (e.g. SNMPATHY_HTTP_PORT=9000).

database: snmpathy.db          # SQLite file (created on first start)

http_host: 0.0.0.0
http_port: 8080
api_token: ""                   # set to require a token for the UI and API

# Syslog listeners. 514 is the standard port but needs root/Administrator
# on most systems; point devices at 5514 or forward 514 -> 5514.
syslog_host: 0.0.0.0
syslog_udp_port: 5514
syslog_tcp_port: 5514

default_poll_interval: 300      # seconds between SNMP polls
default_check_interval: 60      # seconds between availability checks
poller_concurrency: 64
snmp_timeout: 2.0
snmp_retries: 1

retention_raw_days: 7
retention_rollup_days: 400
retention_syslog_days: 30
retention_heartbeat_days: 90

alert_eval_interval: 30
smtp_host: ""
smtp_port: 25
smtp_user: ""
smtp_password: ""
smtp_from: snmpathy@localhost
smtp_starttls: false
"""


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    logging.getLogger("pysnmp").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def _settings(args: argparse.Namespace):
    from .config import Settings

    settings = Settings.load(getattr(args, "config", None))
    for name in ("database", "http_host", "http_port", "syslog_udp_port", "syslog_tcp_port", "api_token"):
        value = getattr(args, name, None)
        if value is not None:
            setattr(settings, name, value)
    if getattr(args, "no_syslog", False):
        settings.enable_syslog = False
    if getattr(args, "no_poller", False):
        settings.enable_poller = False
    return settings


async def _open_browser_when_ready(server, url: str) -> None:
    import webbrowser

    for _ in range(300):
        if getattr(server, "started", False):
            try:
                webbrowser.open(url)
            except Exception:  # no browser available (headless server): not fatal
                pass
            return
        await asyncio.sleep(0.1)


async def _serve(settings, snmp_factory=None, probe=None, setup=None, open_browser: bool = False,
                 on_app=None) -> None:
    import uvicorn

    from .app import create_app
    from .db import Database

    db = Database(settings.database)
    if setup:
        result = setup(db)
        if asyncio.iscoroutine(result):
            await result
    app = create_app(settings, db=db, snmp_factory=snmp_factory, probe=probe)
    if on_app:
        on_app(app)
    config = uvicorn.Config(app, host=settings.http_host, port=settings.http_port, log_level="info",
                            access_log=False, lifespan="on")
    server = uvicorn.Server(config)
    shown = "localhost" if settings.http_host in ("0.0.0.0", "::") else settings.http_host
    url = f"http://{shown}:{settings.http_port}/"
    logging.getLogger("snmpathy").info("web UI: %s (database: %s)", url, settings.database)
    opener = asyncio.create_task(_open_browser_when_ready(server, url)) if open_browser else None
    try:
        await server.serve()
    finally:
        if opener:
            opener.cancel()


def _run(coro) -> Any:
    # asyncio.run() uses the Proactor loop on Windows, which supports UDP and
    # subprocesses (needed for ping.exe); uvloop is used automatically elsewhere
    # only when uvicorn manages the loop, so the default loop is fine everywhere.
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        return None


# ------------------------------------------------------------------ commands
def cmd_serve(args: argparse.Namespace) -> int:
    settings = _settings(args)
    _run(_serve(settings, open_browser=getattr(args, "open", False)))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import demo_flow_sender, demo_probe, demo_snmp_factory, demo_syslog_sender, populate_demo

    settings = _settings(args)
    if args.database is None:
        # Keep demo data apart from real data, in the same directory (e.g. /data in Docker).
        settings.database = str(Path(settings.database).with_name("snmpathy-demo.db"))
    async def run() -> None:
        sender = asyncio.create_task(demo_syslog_sender(settings))
        flows: list[asyncio.Task] = []

        def start_flows(app) -> None:
            monitor = lambda: app.state.monitor.flows if app.state.monitor else None  # noqa: E731
            flows.append(asyncio.create_task(demo_flow_sender(monitor)))
        try:
            await _serve(settings, snmp_factory=demo_snmp_factory, probe=demo_probe,
                         setup=lambda db: populate_demo(db, settings, days=args.days),
                         open_browser=getattr(args, "open", False), on_app=start_flows)
        finally:
            sender.cancel()
            for task in flows:
                task.cancel()

    _run(run())
    return 0


def cmd_init_config(args: argparse.Namespace) -> int:
    path = Path(args.output)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    print(f"wrote {path}")
    return 0


def _creds(args: argparse.Namespace):
    from .snmp.client import SnmpCredentials

    return SnmpCredentials(
        version=args.version, community=args.community, port=args.port,
        v3_user=args.user or "", v3_auth_proto=args.auth_proto, v3_auth_key=args.auth_key or "",
        v3_priv_proto=args.priv_proto, v3_priv_key=args.priv_key or "",
    )


def _print_value(oid: str, value: Any) -> None:
    if isinstance(value, bytes):
        value = "0x" + value.hex()
    print(f"{oid} = {value}")


def cmd_get(args: argparse.Namespace) -> int:
    from .snmp.client import PySnmpClient, SnmpError

    async def go():
        client = PySnmpClient(args.host, _creds(args), timeout=args.timeout, retries=1)
        try:
            for oid, value in (await client.get(args.oids)).items():
                _print_value(oid, value)
        finally:
            client.close()

    try:
        _run(go())
    except SnmpError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_walk(args: argparse.Namespace) -> int:
    from .snmp.client import PySnmpClient, SnmpError

    async def go():
        client = PySnmpClient(args.host, _creds(args), timeout=args.timeout, retries=1)
        try:
            rows = await client.walk(args.oid)
            for oid, value in rows.items():
                _print_value(oid, value)
            print(f"-- {len(rows)} objects", file=sys.stderr)
        finally:
            client.close()

    try:
        _run(go())
    except SnmpError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    from .snmp.client import PySnmpClient, SnmpError
    from .snmp.discovery import discover

    async def go():
        client = PySnmpClient(args.host, _creds(args), timeout=args.timeout, retries=1)
        try:
            return await discover(client)
        finally:
            client.close()

    try:
        result = _run(go())
    except SnmpError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.system, indent=2))
    print(f"\n{len(result.interfaces)} interfaces:")
    for iface in result.interfaces:
        speed = f"{iface['speed'] / 1e6:.0f}M" if iface["speed"] else "-"
        print(f"  {iface['if_index']:>5}  {iface['name']:<24} {speed:>7}  oper={iface['oper_status']}  {iface['alias']}")
    keys: dict[str, int] = {}
    for m in result.metrics:
        keys[m.key] = keys.get(m.key, 0) + 1
    print(f"\n{len(result.metrics)} metrics:")
    for key, n in sorted(keys.items()):
        print(f"  {key:<22} x{n}")
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    from .checks.probes import detect_icmp_mode, ping

    print(f"ICMP mode: {detect_icmp_mode()}")
    failures = 0
    for _ in range(args.count):
        result = _run(ping(args.host, timeout=args.timeout))
        if result.ok:
            print(f"reply from {args.host}: time={result.latency_ms:.2f} ms")
        else:
            failures += 1
            print(f"{args.host}: {result.message}")
        time.sleep(0.5)
    return 1 if failures == args.count else 0


def cmd_send_syslog(args: argparse.Namespace) -> int:
    pri = args.facility * 8 + args.severity
    t = time.localtime()
    month = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()[t.tm_mon - 1]
    stamp = f"{month} {t.tm_mday:>2} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
    host = socket.gethostname().split(".")[0]
    data = f"<{pri}>{stamp} {host} {args.app}: {args.message}".encode()
    if args.tcp:
        with socket.create_connection((args.server, args.port), timeout=5) as sock:
            sock.sendall(data + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (args.server, args.port))
    print(f"sent to {args.server}:{args.port}/{'tcp' if args.tcp else 'udp'}: {data.decode()}")
    return 0


def cmd_add_device(args: argparse.Namespace) -> int:
    from .db import Database
    from .services import ValidationError, create_device

    settings = _settings(args)
    db = Database(settings.database)
    try:
        device = create_device(db, {
            "name": args.name, "hostname": args.hostname, "snmp_version": args.version,
            "snmp_community": args.community, "snmp_port": args.port, "v3_user": args.user or "",
            "v3_auth_proto": args.auth_proto, "v3_auth_key": args.auth_key or "",
            "v3_priv_proto": args.priv_proto, "v3_priv_key": args.priv_key or "",
            "poll_interval": args.interval, "tags": args.tag or [],
            "snmp_enabled": 0 if args.no_snmp else 1,
        }, add_ping_check=not args.no_ping)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"added device #{device['id']} {device['name']}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .db import Database
    from .services import export_config

    db = Database(_settings(args).database)
    text = json.dumps(export_config(db), indent=2)
    if args.output == "-":
        print(text)
    else:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from .db import Database
    from .services import import_config

    db = Database(_settings(args).database)
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    print(json.dumps(import_config(db, data)))
    return 0


def cmd_grafana_export(args: argparse.Namespace) -> int:
    from .grafana import write_provisioning

    token = args.token if args.token is not None else "${SNMPATHY_API_TOKEN}"
    for path in write_provisioning(args.output, url=args.url, token=token):
        print(f"wrote {path}")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"snmpathy {__version__} (Python {sys.version.split()[0]}, {sys.platform})")
    return 0


# -------------------------------------------------------------------- parser
def _snmp_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-v", "--version", default="2c", choices=["1", "2c", "3"], help="SNMP version")
    p.add_argument("-c", "--community", default="public")
    p.add_argument("-p", "--port", type=int, default=161)
    p.add_argument("-u", "--user", help="SNMPv3 user")
    p.add_argument("-a", "--auth-proto", default="sha", help="md5|sha|sha224|sha256|sha384|sha512")
    p.add_argument("-A", "--auth-key")
    p.add_argument("-x", "--priv-proto", default="aes", help="des|3des|aes|aes192|aes256")
    p.add_argument("-X", "--priv-key")
    p.add_argument("-t", "--timeout", type=float, default=2.0)


def _server_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="YAML config file")
    p.add_argument("--db", dest="database", help="SQLite database path")
    p.add_argument("--host", dest="http_host")
    p.add_argument("--port", dest="http_port", type=int)
    p.add_argument("--syslog-udp", dest="syslog_udp_port", type=int)
    p.add_argument("--syslog-tcp", dest="syslog_tcp_port", type=int)
    p.add_argument("--token", dest="api_token", help="require this API/UI token")
    p.add_argument("--no-syslog", action="store_true")
    p.add_argument("--no-poller", action="store_true")
    p.add_argument("--open", action="store_true", help="open the web UI in a browser once started")


def cmd_collector(args: argparse.Namespace) -> int:
    """Run as a remote collector for a central SNMPathy server."""
    import os

    from .collector_agent import CollectorAgent, load_collector_config

    try:
        conf = load_collector_config(args.config)
    except FileNotFoundError:
        print(f"error: config file {args.config} not found", file=sys.stderr)
        return 2
    server = args.server or os.environ.get("SNMPATHY_COLLECTOR_SERVER") or conf.get("server")
    token = args.token or os.environ.get("SNMPATHY_COLLECTOR_TOKEN") or conf.get("token")
    if not server or not token:
        print("error: --server and --token are required (or a collector.yaml with server: and token:).\n"
              "Create a collector in the SNMPathy web UI (Collectors) to get a token and install command.",
              file=sys.stderr)
        return 2
    verify: bool | str = True
    if args.insecure or str(conf.get("verify_tls", "true")).lower() in ("false", "0", "no"):
        verify = False
    if args.ca_file or conf.get("ca_file"):
        verify = args.ca_file or conf["ca_file"]
    state_dir = args.state_dir or conf.get("state_dir") or "."
    agent = CollectorAgent(server, token, verify=verify, state_dir=state_dir,
                           concurrency=int(args.concurrency or conf.get("concurrency") or 32),
                           name=conf.get("name") or "")
    _run(agent.run())
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Sweep IP ranges for devices and optionally add them to the database."""
    from .checks.runner import run_probe
    from .scanner import ScanOptions, TargetError, default_client_factory, expand_targets, scan_host

    opts = ScanOptions.from_dict({
        "communities": args.community or ["public"], "snmp_port": args.port, "ping": not args.no_ping,
        "tcp_ports": [int(p) for p in (args.tcp or "").split(",") if p.strip()], "timeout": args.timeout,
        "concurrency": args.concurrency, "resolve_dns": not args.no_dns, "exclude": args.exclude or "",
        "v3": ([{"user": args.user, "auth_proto": args.auth_proto, "auth_key": args.auth_key or "",
                 "priv_proto": args.priv_proto, "priv_key": args.priv_key or ""}] if args.user else []),
        "auto_add": args.add, "tags": args.tag or ["discovered"],
    })
    try:
        hosts = expand_targets(" ".join(args.targets), opts.exclude)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Scanning {len(hosts)} addresses ...", file=sys.stderr)

    async def go():
        sem = asyncio.Semaphore(opts.concurrency)
        found = []

        async def one(h):
            async with sem:
                r = await scan_host(h, opts, run_probe, default_client_factory)
                if r:
                    found.append(r)
                    if not args.json:
                        ports = ",".join(map(str, r["open_ports"])) or "-"
                        ping = f"{r['ping_ms']:.1f}ms" if r["ping_ms"] is not None else "-"
                        snmp = f"v{r['snmp_version']}" if r["snmp"] else "-"
                        print(f"{r['ip']:<16} {ping:>8}  snmp={snmp:<4} ports={ports:<12} "
                              f"{r['sys_name'] or r['dns_name']}  {r['vendor']}")
        await asyncio.gather(*(one(h) for h in hosts))
        return found

    found = _run(go()) or []
    if args.json:
        print(json.dumps(found, indent=2))
    print(f"{len(found)} hosts responded", file=sys.stderr)
    if args.add != "none" and found:
        from .db import Database
        from .scanner import ScanManager

        db = Database(_settings(args).database)
        manager = ScanManager(db)
        scan = manager.create({"name": "CLI scan " + " ".join(args.targets)[:150], "targets": " ".join(args.targets),
                               "options": opts.to_dict()})
        for r in found:
            manager._store(scan["id"], r)
        added = manager.add(scan["id"], mode=args.add)
        db.update("scans", scan["id"], {"state": "done", "found": len(found), "scanned": len(hosts),
                                        "finished_at": time.time(), "started_at": time.time()})
        print(f"added {len(added)} devices to {db.path}", file=sys.stderr)
    return 0


def cmd_autostart(args: argparse.Namespace) -> int:
    """Turn starting SNMPathy at login on or off for the current user."""
    from . import autostart

    settings = _settings(args)
    try:
        if args.action == "on":
            info = autostart.enable(settings)
        elif args.action == "off":
            info = autostart.disable(settings)
        else:
            info = autostart.status(settings)
    except (autostart.AutostartError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not info["supported"]:
        print(f"autostart not supported: {info['note']}")
        return 1
    print(f"autostart is {'ON' if info['enabled'] else 'OFF'} ({info['platform']})")
    if info["enabled"]:
        print(f"  entry:   {info['location']}")
        print(f"  command: {' '.join(info['command'])}")
    if info["note"]:
        print(f"  {info['note']}")
    return 0


def cmd_firewall(args: argparse.Namespace) -> int:
    """Open (or close) the host firewall for SNMPathy's listeners."""
    from . import firewall

    settings = _settings(args)
    groups = [g.strip() for g in (args.include or "syslog").split(",") if g.strip()]
    if args.action == "status":
        info = firewall.status(settings)
        print(f"firewall backend: {info['backend']}  (running as admin/root: {'yes' if info['admin'] else 'no'})")
        for r in info["rules"]:
            state = {True: "open", False: "not open", None: "unknown"}[r["present"]]
            print(f"  {r['name']:<34} {state}")
        print(info["note"])
        return 0
    try:
        result = firewall.apply(settings, groups, remove=args.action == "remove")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(result["output"])
    if result["manual"]:
        print("\n" + result["manual"])
    return 0 if result["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="snmpathy", description="SNMP polling, syslog ingest and uptime monitoring")
    parser.add_argument("--log-level", default="info")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("serve", help="run the web UI, poller and syslog server")
    _server_args(p)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("demo", help="run with simulated devices, checks and syslog traffic")
    _server_args(p)
    p.add_argument("--days", type=int, default=7, help="days of history to generate")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("init-config", help="write an example configuration file")
    p.add_argument("output", nargs="?", default="snmpathy.yaml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init_config)

    p = sub.add_parser("get", help="SNMP GET (like snmpget)")
    p.add_argument("host")
    p.add_argument("oids", nargs="+")
    _snmp_args(p)
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("walk", help="SNMP walk (like snmpwalk)")
    p.add_argument("host")
    p.add_argument("oid", nargs="?", default="1.3.6.1.2.1.1")
    _snmp_args(p)
    p.set_defaults(func=cmd_walk)

    p = sub.add_parser("discover", help="show what SNMPathy would monitor on a device")
    p.add_argument("host")
    _snmp_args(p)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("ping", help="ICMP ping using SNMPathy's probe")
    p.add_argument("host")
    p.add_argument("-n", "--count", type=int, default=4)
    p.add_argument("-t", "--timeout", type=float, default=2.0)
    p.set_defaults(func=cmd_ping)

    p = sub.add_parser("send-syslog", help="send a test syslog message")
    p.add_argument("message")
    p.add_argument("--server", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5514)
    p.add_argument("--tcp", action="store_true")
    p.add_argument("--facility", type=int, default=1)
    p.add_argument("--severity", type=int, default=6)
    p.add_argument("--app", default="snmpathy-test")
    p.set_defaults(func=cmd_send_syslog)

    p = sub.add_parser("add-device", help="add a device from the command line")
    p.add_argument("name")
    p.add_argument("hostname")
    _snmp_args(p)
    p.add_argument("--interval", type=int, default=300)
    p.add_argument("--tag", action="append")
    p.add_argument("--no-ping", action="store_true", help="do not create a ping check")
    p.add_argument("--no-snmp", action="store_true", help="availability checks only")
    p.add_argument("--config")
    p.add_argument("--db", dest="database")
    p.set_defaults(func=cmd_add_device)

    p = sub.add_parser("export", help="export configuration (devices, checks, rules, channels) as JSON")
    p.add_argument("output", nargs="?", default="-")
    p.add_argument("--config")
    p.add_argument("--db", dest="database")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("import", help="import a configuration exported with 'export'")
    p.add_argument("input")
    p.add_argument("--config")
    p.add_argument("--db", dest="database")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("grafana-export", help="write Grafana provisioning files (data source + dashboards)")
    p.add_argument("output", nargs="?", default="grafana-provisioning")
    p.add_argument("--url", default="http://snmpathy:8080/grafana", help="SNMPathy /grafana URL as seen from Grafana")
    p.add_argument("--token", help="API token to put in the data source (default: ${SNMPATHY_API_TOKEN})")
    p.set_defaults(func=cmd_grafana_export)

    p = sub.add_parser("scan", help="scan IP ranges for devices (ping, TCP, SNMP) and optionally add them")
    p.add_argument("targets", nargs="+", help="10.0.0.0/24, 10.0.1.1-50, 192.168.1.10, host names")
    p.add_argument("-c", "--community", action="append", help="community to try (repeatable; default public)")
    p.add_argument("-p", "--port", type=int, default=161, help="SNMP port")
    p.add_argument("-u", "--user", help="SNMPv3 user to try as well")
    p.add_argument("-a", "--auth-proto", default="sha")
    p.add_argument("-A", "--auth-key")
    p.add_argument("-x", "--priv-proto", default="aes")
    p.add_argument("-X", "--priv-key")
    p.add_argument("--tcp", help="TCP ports to probe, e.g. 22,80,443,3389")
    p.add_argument("--exclude", help="addresses/ranges to skip")
    p.add_argument("--no-ping", action="store_true")
    p.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")
    p.add_argument("-t", "--timeout", type=float, default=1.5)
    p.add_argument("--concurrency", type=int, default=64)
    p.add_argument("--add", choices=["none", "snmp", "alive"], default="none",
                   help="add hosts to the database: those answering SNMP, or any that answered")
    p.add_argument("--tag", action="append")
    p.add_argument("--json", action="store_true", help="print results as JSON")
    p.add_argument("--config")
    p.add_argument("--db", dest="database")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("collector", help="run as a remote collector (probe) for a central SNMPathy server")
    p.add_argument("--server", help="central server URL, e.g. https://nms.example.com")
    p.add_argument("--token", help="collector token (created in the web UI under Collectors)")
    p.add_argument("--config", help="collector.yaml with server/token/verify_tls/ca_file/state_dir")
    p.add_argument("--insecure", action="store_true", help="do not verify the server's TLS certificate")
    p.add_argument("--ca-file", help="CA bundle for a server with a private certificate")
    p.add_argument("--state-dir", help="where buffered results are kept while the server is unreachable")
    p.add_argument("--concurrency", type=int)
    p.set_defaults(func=cmd_collector)

    p = sub.add_parser("autostart", help="start SNMPathy automatically when you log in (on / off / status)")
    p.add_argument("action", nargs="?", choices=["on", "off", "status"], default="status")
    p.add_argument("--config", help="config file the autostarted server should use")
    p.add_argument("--db", dest="database", help="database the autostarted server should use")
    p.set_defaults(func=cmd_autostart)

    p = sub.add_parser("firewall", help="open the host firewall for syslog (and other listeners)")
    p.add_argument("action", nargs="?", choices=["add", "remove", "status"], default="status")
    p.add_argument("--include", help="comma-separated groups: syslog (default), web, logs, flows")
    p.add_argument("--config")
    p.set_defaults(func=cmd_firewall)

    p = sub.add_parser("version", help="print version information")
    p.set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.log_level)
    if not getattr(args, "func", None):
        # No sub-command: run the server. A double-clicked executable also opens the browser.
        from .config import app_dir, is_frozen

        if is_frozen() and (app_dir() / "collector.yaml").exists() and not (app_dir() / "snmpathy.yaml").exists():
            # A collector install: the executable sits next to its collector.yaml.
            return int(cmd_collector(build_parser().parse_args(["collector"])) or 0)
        extra = ["--open"] if is_frozen() else []
        # Only top-level options (e.g. --log-level) can be present here, so they go first.
        args = parser.parse_args([*(argv if argv is not None else sys.argv[1:]), "serve", *extra])
    return int(args.func(args) or 0)
