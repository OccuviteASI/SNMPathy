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


async def _serve(settings, snmp_factory=None, probe=None, setup=None, open_browser: bool = False) -> None:
    import uvicorn

    from .app import create_app
    from .db import Database

    db = Database(settings.database)
    if setup:
        result = setup(db)
        if asyncio.iscoroutine(result):
            await result
    app = create_app(settings, db=db, snmp_factory=snmp_factory, probe=probe)
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
    from .demo import demo_probe, demo_snmp_factory, demo_syslog_sender, populate_demo

    settings = _settings(args)
    if args.database is None:
        # Keep demo data apart from real data, in the same directory (e.g. /data in Docker).
        settings.database = str(Path(settings.database).with_name("snmpathy-demo.db"))
    async def run() -> None:
        sender = asyncio.create_task(demo_syslog_sender(settings))
        try:
            await _serve(settings, snmp_factory=demo_snmp_factory, probe=demo_probe,
                         setup=lambda db: populate_demo(db, settings, days=args.days),
                         open_browser=getattr(args, "open", False))
        finally:
            sender.cancel()

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

    p = sub.add_parser("version", help="print version information")
    p.set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.log_level)
    if not getattr(args, "func", None):
        # No sub-command: run the server. A double-clicked executable also opens the browser.
        from .config import is_frozen

        extra = ["--open"] if is_frozen() else []
        # Only top-level options (e.g. --log-level) can be present here, so they go first.
        args = parser.parse_args([*(argv if argv is not None else sys.argv[1:]), "serve", *extra])
    return int(args.func(args) or 0)
