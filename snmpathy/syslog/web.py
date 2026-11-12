"""Log explorer API (fields, multi-query histograms, CSV export, saved searches)
and the "Log sources" setup page.

Mounted by the application factory with ``app.include_router(router)``.
"""

from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from markupsafe import Markup
from pydantic import BaseModel, Field

from ..db import Database, loads
from . import search as logsearch

router = APIRouter()

EXPORT_MAX = 100_000
EXPORT_CHUNK = 5000


def _db(request: Request) -> Database:
    return request.app.state.db


def log_filter(request: Request) -> logsearch.SyslogFilter:
    """The same parameters as ``/api/syslog`` (q, host, app, severity, device_id,
    facility, range/since, start, end) plus ``must`` / ``must_not`` pills (JSON)."""
    params: dict[str, Any] = dict(request.query_params)
    since = params.get("since") or params.get("range")
    if since:
        params["since"] = since
    return logsearch.SyslogFilter.from_params(params)


# ===================================================================== search API
@router.get("/api/logs/fields", tags=["logs"])
def log_fields(request: Request, sample: int = Query(2000, ge=1, le=20000)):
    """Fields present in the most recent ``sample`` matching messages, with counts."""
    f = log_filter(request)
    return {"sample": sample, "fields": logsearch.fields(_db(request), f, sample)}


@router.get("/api/logs/field-top", tags=["logs"])
def log_field_top(request: Request, field: str = Query(..., min_length=1, max_length=256),
                  limit: int = Query(10, ge=1, le=100)):
    """Most common values of a column (host, app, severity...) or a structured key."""
    f = log_filter(request)
    try:
        values = logsearch.field_top(_db(request), f, field, limit)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return {"field": field, "canonical": logsearch.canonical_field(field), "values": values}


@router.get("/api/logs/histogram-multi", tags=["logs"])
def log_histogram_multi(request: Request, buckets: int = Query(60, ge=5, le=500)):
    """One series per ``q`` parameter (repeatable), sharing the other filters."""
    f = log_filter(request)
    if f.start is None:
        f.start = time.time() - 86400
    queries = request.query_params.getlist("q") or [""]
    return logsearch.histogram_multi(_db(request), f, queries, buckets)


def _csv_cell(value: Any) -> Any:
    # Keep spreadsheets from evaluating log content as formulas.
    if isinstance(value, str) and value[:1] in ("=", "+", "@", "\t", "\r"):
        return "'" + value
    return value


def _iso(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


EXPORT_COLUMNS = ["time", "host", "source_ip", "severity", "facility", "app", "procid", "msgid", "message",
                  "structured"]


def export_rows(db: Database, f: logsearch.SyslogFilter, limit: int = EXPORT_MAX) -> Iterator[str]:
    """CSV text chunks for the newest ``limit`` messages matching ``f``."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(EXPORT_COLUMNS)
    yield buf.getvalue()
    remaining = max(0, min(int(limit), EXPORT_MAX))
    before: int | None = None
    while remaining > 0:
        chunk = min(EXPORT_CHUNK, remaining)
        rows = logsearch.search(db, f, chunk, before)
        if not rows:
            break
        buf.seek(0)
        buf.truncate()
        for r in rows:
            writer.writerow([_csv_cell(v) for v in (
                _iso(r["ts"]), r["host"], r["source_ip"], r["severity_name"], r["facility_name"], r["app"],
                r["procid"], r["msgid"], r["message"], r["structured"])])
        yield buf.getvalue()
        remaining -= len(rows)
        before = rows[-1]["id"]
        if len(rows) < chunk:
            break


@router.get("/api/logs/export.csv", tags=["logs"])
def log_export(request: Request, limit: int = Query(EXPORT_MAX, ge=1, le=EXPORT_MAX)):
    """The current query as CSV (newest first, up to 100 000 rows), streamed."""
    f = log_filter(request)
    name = time.strftime("logs-%Y%m%d-%H%M%S.csv")
    return StreamingResponse(export_rows(_db(request), f, limit), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ================================================================ saved searches
class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    query: str = Field("", max_length=8192)
    filters: dict[str, Any] = {}


def _public_saved(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "filters": loads(row.get("filters"), {})}


@router.get("/api/logs/saved", tags=["logs"])
def saved_list(request: Request):
    rows = _db(request).query("SELECT * FROM saved_searches ORDER BY name COLLATE NOCASE, id")
    return [_public_saved(r) for r in rows]


@router.post("/api/logs/saved", tags=["logs"], status_code=201)
def saved_create(body: SavedSearchIn, request: Request, response: Response):
    """Save a search. Saving again under an existing name replaces it."""
    db = _db(request)
    name = body.name.strip()
    if not name:
        raise HTTPException(422, "name required")
    filters = json.dumps(body.filters, separators=(",", ":"), default=str)
    if len(filters) > 65536:
        raise HTTPException(422, "filters too large")
    existing = db.one("SELECT id FROM saved_searches WHERE name = ? COLLATE NOCASE", (name,))
    if existing:
        db.update("saved_searches", existing["id"], {"name": name, "query": body.query, "filters": filters})
        sid = existing["id"]
        response.status_code = 200
    else:
        sid = db.insert("saved_searches", {"name": name, "query": body.query, "filters": filters,
                                           "created_at": time.time()})
    return _public_saved(db.one("SELECT * FROM saved_searches WHERE id = ?", (sid,)))


@router.delete("/api/logs/saved/{search_id}", tags=["logs"], status_code=204)
def saved_delete(search_id: int, request: Request):
    db = _db(request)
    if not db.one("SELECT id FROM saved_searches WHERE id = ?", (search_id,)):
        raise HTTPException(404, "saved search not found")
    db.execute("DELETE FROM saved_searches WHERE id = ?", (search_id,))
    return Response(status_code=204)


# ================================================================== sources page
INPUTS = [
    # key in listening dicts, label, transport, settings attribute, accepted formats
    ("udp", "Syslog", "UDP", "syslog_udp_port", "RFC 3164 (BSD) and RFC 5424, Cisco / Juniper / Fortinet variants"),
    ("tcp", "Syslog", "TCP", "syslog_tcp_port", "RFC 5424 / 3164, octet-counted (RFC 6587) or newline framed"),
    ("gelf_udp", "GELF", "UDP", "gelf_udp_port", "GELF 1.1, chunked, zlib / gzip compressed (Docker, Graylog libraries, NXLog xm_gelf)"),
    ("json_tcp", "JSON lines", "TCP", "json_tcp_port", "One JSON object per line: NXLog to_json(), Fluent Bit, Vector, journald, NUL-framed GELF"),
    ("json_udp", "JSON", "UDP", "json_udp_port", "One JSON object per datagram"),
]


def _port_of(addr: str | None) -> int | None:
    if not addr or ":" not in addr:
        return None
    try:
        return int(addr.rsplit(":", 1)[1])
    except ValueError:
        return None


def _server_host(request: Request) -> str:
    settings = request.app.state.settings
    public = getattr(settings, "public_url", "") or ""
    if public:
        parsed = urlparse(public if "//" in public else "//" + public)
        if parsed.hostname:
            return parsed.hostname
    return request.base_url.hostname or "snmpathy.example.com"


def _guide(id_: str, title: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"id": id_, "title": title, "items": items}


def _item(title: str, code: str, note: str | Markup = "", lang: str = "") -> dict[str, Any]:
    return {"title": title, "code": code.strip("\n"), "note": note, "lang": lang}


def setup_guides(host: str, ports: dict[str, int]) -> list[dict[str, Any]]:
    """Copy-paste configuration snippets for common log senders."""
    sys_udp = ports.get("udp") or 5514
    sys_tcp = ports.get("tcp") or sys_udp
    gelf = ports.get("gelf_udp") or 12201
    jtcp = ports.get("json_tcp") or 5544
    h = host

    def note(text: str, **kw: Any) -> Markup:
        return Markup(text).format(**kw)

    linux = _guide("linux", "Linux", [
        _item("rsyslog: forward everything (UDP or TCP)", f"""
# /etc/rsyslog.d/90-snmpathy.conf
# UDP (one @):
*.* @{h}:{sys_udp}
# ...or TCP (two @@), recommended:
# *.* @@{h}:{sys_tcp}
""", note("Then <code>sudo systemctl restart rsyslog</code>. Test with "
          "<code>logger -n {h} -P {p} -T \"hello from $(hostname)\"</code>.", h=h, p=sys_tcp)),
        _item("rsyslog: RFC 5424 over TCP with a disk-assisted queue", f"""
# /etc/rsyslog.d/90-snmpathy.conf
template(name="SnmpathyRFC5424" type="string"
         string="<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% %STRUCTURED-DATA% %msg%\\n")

*.* action(type="omfwd" target="{h}" port="{sys_tcp}" protocol="tcp"
           template="SnmpathyRFC5424"
           queue.type="LinkedList" queue.filename="snmpathy_fwd" queue.saveOnShutdown="on"
           action.resumeRetryCount="-1")
""", note("RFC 5424 keeps the year, sub-second precision, the time zone and structured data. "
          "The built-in <code>RSYSLOG_SyslogProtocol23Format</code> template works too.")),
        _item("syslog-ng", f"""
# /etc/syslog-ng/conf.d/snmpathy.conf
destination d_snmpathy {{
    syslog("{h}" transport("tcp") port({sys_tcp}));   # RFC 5424 over TCP
    # network("{h}" transport("udp") port({sys_udp})); # BSD syslog over UDP
}};
log {{ source(s_src); destination(d_snmpathy); }};
""", note("The default source is <code>s_src</code> on Debian / Ubuntu and <code>s_sys</code> on RHEL / SUSE. "
          "Reload with <code>sudo systemctl reload syslog-ng</code>.")),
        _item("systemd-journald (via rsyslog)", f"""
# /etc/systemd/journald.conf
[Journal]
ForwardToSyslog=yes

# /etc/rsyslog.conf (RHEL / Fedora read the journal directly instead):
# module(load="imjournal" StateFile="imjournal.state")

# then forward with rsyslog as above:
*.* @@{h}:{sys_tcp}
""", note("Run <code>sudo systemctl restart systemd-journald rsyslog</code>. Without rsyslog, "
          "<code>journalctl -o json -f | nc {h} {p}</code> streams the journal as JSON lines (fields such as "
          "<code>_SYSTEMD_UNIT</code> become searchable).", h=h, p=jtcp)),
    ])

    nxlog_json = f"""
## nxlog.conf - NXLog Community Edition: Windows Event Log -> SNMPathy (JSON over TCP)
define ROOT     C:\\Program Files\\nxlog
define CERTDIR  %ROOT%\\cert
define CONFDIR  %ROOT%\\conf\\nxlog.d
define LOGDIR   %ROOT%\\data

Moduledir %ROOT%\\modules
CacheDir  %ROOT%\\data
Pidfile   %ROOT%\\data\\nxlog.pid
SpoolDir  %ROOT%\\data
LogFile   %LOGDIR%\\nxlog.log
LogLevel  INFO

<Extension _json>
    Module      xm_json
</Extension>

<Input eventlog>
    Module      im_msvistalog
    # Without a query every channel is collected; keep the useful ones.
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Application">*</Select>
                <Select Path="System">*</Select>
                <Select Path="Security">*</Select>
                <!-- <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select> -->
                <!-- <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select> -->
            </Query>
        </QueryList>
    </QueryXML>
    Exec        to_json();
</Input>

<Output snmpathy>
    Module      om_tcp
    Host        {h}
    Port        {jtcp}
    # NXLog Enterprise 5+/6: use "Host {h}:{jtcp}" instead of Host + Port.
</Output>

<Route eventlog_to_snmpathy>
    Path        eventlog => snmpathy
</Route>
"""
    nxlog_gelf = f"""
## GELF variant: replace the _json extension and the output above with
<Extension _gelf>
    Module      xm_gelf
</Extension>

<Input eventlog>
    Module      im_msvistalog
</Input>

<Output snmpathy_gelf>
    Module      om_udp
    Host        {h}
    Port        {gelf}
    OutputType  GELF_UDP
</Output>

<Route eventlog_to_snmpathy>
    Path        eventlog => snmpathy_gelf
</Route>
"""
    windows = _guide("windows", "Windows", [
        _item("Windows Event Logs with NXLog Community Edition (JSON over TCP)", nxlog_json, note(
            "Install NXLog CE, replace <code>C:\\Program Files\\nxlog\\conf\\nxlog.conf</code> with this file and "
            "restart the service (<code>Restart-Service nxlog</code>). Event fields are searchable, e.g. "
            "<code>EventID:4625</code>, <code>app:Microsoft-Windows-Security-Auditing</code>, "
            "<code>TargetUserName:administrator</code>. Allow outbound TCP {p} in the Windows firewall.", p=jtcp)),
        _item("NXLog with GELF over UDP", nxlog_gelf, note(
            "GELF keeps the same fields; UDP is fire-and-forget, so prefer the TCP output above for Security logs.")),
        _item("Fluent Bit on Windows (winevtlog)", f"""
[INPUT]
    Name         winevtlog
    Channels     Setup,Windows PowerShell,System,Application,Security
    Interval_Sec 1
    DB           C:\\fluent-bit\\winevtlog.sqlite

[OUTPUT]
    Name         tcp
    Match        *
    Host         {h}
    Port         {jtcp}
    Format       json_lines
""", note("An alternative to NXLog with the same JSON lines input.")),
        _item("Winlogbeat (optional, via Logstash)", f"""
# winlogbeat.yml
winlogbeat.event_logs:
  - name: Application
  - name: System
  - name: Security
output.logstash:
  hosts: ["logstash.example.com:5044"]

# logstash pipeline: beats in, JSON lines out to SNMPathy
input  {{ beats {{ port => 5044 }} }}
output {{ tcp {{ host => "{h}" port => {jtcp} codec => json_lines }} }}
""", note("Winlogbeat has no plain TCP output, so it needs Logstash (or use NXLog / Fluent Bit instead).")),
    ])

    network = _guide("network", "Network devices", [
        _item("Cisco IOS / IOS-XE", f"""
configure terminal
 logging host {h} transport udp port {sys_udp}
 logging trap informational
 logging source-interface Loopback0
 logging origin-id hostname
 service timestamps log datetime msec localtime show-timezone
 service sequence-numbers
end
write memory
""", note("NX-OS: <code>logging server {h} 6 port {p} use-vrf management</code>. "
          "ASA: <code>logging enable</code>, <code>logging trap informational</code>, "
          "<code>logging host inside {h} udp/{p}</code>.", h=h, p=sys_udp)),
        _item("Juniper Junos", f"""
set system syslog host {h} any info
set system syslog host {h} port {sys_udp}
set system syslog host {h} structured-data
set system syslog time-format millisecond year
commit
"""),
        _item("Fortinet FortiGate", f"""
config log syslogd setting
    set status enable
    set server "{h}"
    set port {sys_udp}
    set mode udp
    set facility local7
    set format default
end
config log syslogd filter
    set severity information
end
"""),
        _item("Palo Alto Networks PAN-OS", f"""
# GUI: Device > Server Profiles > Syslog > Add
#   Name: snmpathy   Server: {h}   Transport: UDP   Port: {sys_udp}   Format: BSD   Facility: LOG_USER
# Then: Objects > Log Forwarding (attach to security rules) and Device > Log Settings (System, Config).
# CLI (configure mode):
set shared log-settings syslog snmpathy server snmpathy server {h} transport UDP port {sys_udp} format BSD facility LOG_USER
commit
"""),
        _item("MikroTik RouterOS", f"""
/system logging action add name=snmpathy target=remote remote={h} remote-port={sys_udp} bsd-syslog=yes syslog-facility=local0
/system logging add topics=info action=snmpathy
/system logging add topics=warning action=snmpathy
/system logging add topics=error action=snmpathy
/system logging add topics=critical action=snmpathy
""", note("RouterOS v6 needs an IP address for <code>remote</code>.")),
        _item("Ubiquiti (UniFi / EdgeOS)", f"""
# UniFi Network: Settings > System > Advanced > Remote Logging (newer releases: Settings > Control Plane
#   > Integrations > Activity Logging / SIEM Server)  ->  Server: {h}  Port: {sys_udp}
# EdgeRouter (EdgeOS):
configure
set system syslog host {h}:{sys_udp} facility all level info
commit ; save
"""),
    ])

    shippers = _guide("containers", "Containers & shippers", [
        _item("Docker: one container", f"""
docker run -d \\
  --log-driver gelf \\
  --log-opt gelf-address=udp://{h}:{gelf} \\
  --log-opt tag="{{{{.Name}}}}" \\
  nginx
"""),
        _item("Docker: all containers (/etc/docker/daemon.json)", json.dumps(
            {"log-driver": "gelf", "log-opts": {"gelf-address": f"udp://{h}:{gelf}", "tag": "{{.Name}}"}}, indent=2),
            note("Restart the Docker daemon; existing containers keep their old driver until re-created.")),
        _item("Docker Compose", f"""
services:
  web:
    image: nginx
    logging:
      driver: gelf
      options:
        gelf-address: "udp://{h}:{gelf}"
        tag: "{{{{.Name}}}}"
"""),
        _item("Fluent Bit (JSON lines over TCP)", f"""
[OUTPUT]
    Name             tcp
    Match            *
    Host             {h}
    Port             {jtcp}
    Format           json_lines
    json_date_key    timestamp
    json_date_format iso8601
"""),
        _item("Vector (JSON lines over TCP)", f"""
[sinks.snmpathy]
type = "socket"
inputs = ["my_source"]
address = "{h}:{jtcp}"
mode = "tcp"
encoding.codec = "json"
framing.method = "newline_delimited"
"""),
        _item("Kubernetes (Fluent Bit DaemonSet values)", f"""
config:
  outputs: |
    [OUTPUT]
        Name   tcp
        Match  kube.*
        Host   {h}
        Port   {jtcp}
        Format json_lines
"""),
    ])

    test = _guide("test", "Test", [
        _item("Send test messages", f"""
# Syslog over UDP / TCP
echo '<14>1 2024-01-01T12:00:00Z myhost myapp 123 ID47 - hello over UDP' | nc -u -w1 {h} {sys_udp}
echo '<14>1 2024-01-01T12:00:00Z myhost myapp 123 ID47 - hello over TCP' | nc -w1 {h} {sys_tcp}
logger -n {h} -P {sys_udp} -d "hello from logger"

# JSON lines over TCP
echo '{{"host":"myhost","app":"demo","level":"warning","message":"hello JSON","user":{{"name":"bob"}}}}' | nc -w1 {h} {jtcp}

# GELF over UDP
echo -n '{{"version":"1.1","host":"myhost","short_message":"hello GELF","level":3,"_EventID":4625}}' | nc -u -w1 {h} {gelf}

# From the SNMPathy host itself
snmpathy send-syslog "hello"
""", note("Then search for <code>host:myhost</code>, <code>user.name:bob</code> or <code>EventID:4625</code>.")),
    ])
    return [linux, windows, network, shippers, test]


@router.get("/logs/sources", response_class=HTMLResponse, include_in_schema=False)
def log_sources(request: Request):
    from ..web import render

    db = _db(request)
    settings = request.app.state.settings
    monitor = request.app.state.monitor
    syslog_server = getattr(monitor, "syslog", None) if monitor is not None else None
    log_server = getattr(monitor, "logs", None) if monitor is not None else None
    listening: dict[str, str] = {}
    for server in (syslog_server, log_server):
        if server is not None:
            listening.update(getattr(server, "listening", {}) or {})

    inputs, ports = [], {}
    for key, label, transport, attr, formats in INPUTS:
        configured = int(getattr(settings, attr, 0) or 0)
        addr = listening.get(key)
        port = _port_of(addr) or configured
        if addr:
            state = "listening"
        elif not configured or (key in ("udp", "tcp") and not settings.enable_syslog):
            state = "disabled"
        elif monitor is None:
            state = "not running"
        else:
            state = "not listening"
        if state != "disabled":
            ports[key] = port
        inputs.append({"key": key, "label": label, "transport": transport, "port": port, "address": addr,
                       "state": state, "formats": formats, "setting": attr})

    since = time.time() - 86400
    sources = db.query(
        "SELECT host, source_ip, MAX(device_id) AS device_id, COUNT(*) AS n, "
        "SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END) AS errors, "
        "SUM(CASE WHEN severity = 4 THEN 1 ELSE 0 END) AS warnings, "
        "SUM(CASE WHEN structured LIKE '{%' THEN 1 ELSE 0 END) AS structured_n, "
        "MAX(ts) AS last_ts FROM syslog WHERE ts >= ? GROUP BY host, source_ip ORDER BY n DESC LIMIT 500",
        (since,))
    device_names = {d["id"]: d["name"] for d in db.query("SELECT id, name FROM devices")}
    for s in sources:
        s["device_name"] = device_names.get(s["device_id"])
        s["kind"] = "JSON / GELF" if s["structured_n"] and s["structured_n"] >= s["n"] / 2 else "Syslog"
    total = sum(s["n"] for s in sources)
    stats = {}
    for name, server in (("syslog", syslog_server), ("structured", log_server)):
        if server is not None and getattr(server, "stats", None) is not None:
            stats[name] = server.stats.as_dict()
    host = _server_host(request)
    return render(request, "logsources.html", nav="logsources", inputs=inputs, sources=sources, total=total,
                  stats=stats, server_host=host, guides=setup_guides(host, ports),
                  monitor_running=monitor is not None)
