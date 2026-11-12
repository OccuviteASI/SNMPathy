"""Log explorer: query language, filter pills, field discovery, multi-query
histograms and the /api/logs + /logs/sources endpoints."""

import csv
import io
import json
import time

import pytest
from fastapi.testclient import TestClient

from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.db import Database
from snmpathy.syslog import search as S
from snmpathy.syslog.parser import parse
from snmpathy.syslog.search import SyslogFilter
from snmpathy.syslog.server import message_row, store_messages
from snmpathy.syslog.structured import parse_json_event
from snmpathy.syslog.web import router, setup_guides

NOW = time.time()


def _nxlog(event_id=4625, user="bob", host="WIN-DC01"):
    return {
        "EventTime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NOW - 30)),
        "Hostname": host,
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "EventID": event_id,
        "EventType": "AUDIT_FAILURE",
        "Channel": "Security",
        "Message": f"An account failed to log on. Account Name: {user}",
        "TargetUserName": user,
        "LogonType": 3,
    }


def _gelf():
    return {"version": "1.1", "host": "app01", "short_message": "login failed for bob", "level": 4,
            "timestamp": NOW - 20, "_EventID": 4771, "_user": {"name": "bob", "id": 7}, "_bytes": 1500,
            "_application_name": "auth-api"}


def seed(db):
    rows = []
    syslog = [
        ("10.0.0.1", f"<187>1 - core-sw1 LINK - - - Interface Gi0/1, changed state to down"),   # local7.err
        ("10.0.0.1", f"<190>1 - core-sw1 LINK - - - Interface Gi0/1, changed state to up"),     # local7.info
        ("10.0.5.9", f"<86>1 - web1 sshd 1234 - - Failed password for root from 192.0.2.1"),    # authpriv.info
        ("172.16.0.4", f"<34>1 - fw1 kernel - - - kernel panic imminent"),                     # auth.crit
        ("192.168.1.10", f"<14>1 - web2 cron - - [meta@1 job=\"backup\"] job finished"),       # user.info + SD
    ]
    for i, (ip, text) in enumerate(syslog):
        rows.append(message_row(parse(text, ip, NOW - 300 + i)))
    rows.append(message_row(parse_json_event(json.dumps(_nxlog()), "10.9.9.9", NOW)))
    rows.append(message_row(parse_json_event(json.dumps(_nxlog(4624, "alice")), "10.9.9.9", NOW)))
    rows.append(message_row(parse_json_event(json.dumps(_gelf()), "10.9.9.10", NOW)))
    store_messages(db, rows)


def hosts(db, **kw):
    kw.setdefault("start", NOW - 3600)
    return sorted(r["host"] for r in S.search(db, SyslogFilter(**kw)))


# ======================================================================= search
def test_field_qualified_terms(db):
    seed(db)
    assert hosts(db, q="host:core-sw1") == ["core-sw1", "core-sw1"]
    assert hosts(db, q="host:CORE-*") == ["core-sw1", "core-sw1"]
    assert hosts(db, q="host:10.0.5.9") == ["web1"]           # host matches the source IP too
    assert hosts(db, q="app:sshd") == ["web1"]
    assert hosts(db, q="severity:<=3") == ["core-sw1", "fw1"]
    assert hosts(db, q="severity:err") == ["core-sw1"]
    assert hosts(db, q="severity:<=crit") == ["fw1"]
    assert hosts(db, q="facility:local7") == ["core-sw1", "core-sw1"]
    assert hosts(db, q="facility:local7 -severity:err") == ["core-sw1"]
    assert hosts(db, q="source_ip:10.0.0.0/8") == ["WIN-DC01", "WIN-DC01", "app01", "core-sw1", "core-sw1", "web1"]
    assert hosts(db, q="source_ip:10.0.*") == ["core-sw1", "core-sw1", "web1"]
    assert hosts(db, q="NOT source_ip:10.0.0.0/8") == ["fw1", "web2"]
    assert hosts(db, q="host:172.16.0.0/12") == ["fw1"]
    assert hosts(db, q='"changed state" host:core-sw1') == ["core-sw1", "core-sw1"]
    assert hosts(db, q="changed -up") == ["core-sw1"]
    assert hosts(db, q="panic OR sshd") == ["fw1", "web1"]
    assert hosts(db, q="(app:sshd OR app:kernel) -panic") == ["web1"]
    assert hosts(db, q="fail*") == ["WIN-DC01", "WIN-DC01", "app01", "web1"]
    assert hosts(db, q="*imminent") == ["fw1"]
    assert hosts(db, q='message:"changed state to"') == ["core-sw1", "core-sw1"]
    assert hosts(db, q="device_id:*") == []
    # A MAC address is text, not a field query; odd input never errors.
    assert hosts(db, q="aa:bb:cc:dd:ee:ff") == []
    for odd in ['foo-bar "unterminated', "((", ")", "NOT", "a OR", "host:", "-", 'severity:<=bogus', "*"]:
        S.search(db, SyslogFilter(q=odd))


def test_structured_fields_from_gelf_and_nxlog(db):
    seed(db)
    assert hosts(db, q="EventID:4625") == ["WIN-DC01"]                 # NXLog: EventID -> msgid
    assert hosts(db, q="eventid:4771") == ["app01"]                    # GELF: kept in structured
    assert hosts(db, q="msgid:4624") == ["WIN-DC01"]
    assert hosts(db, q="user.name:bob") == ["app01"]
    assert hosts(db, q="user.name:BO*") == ["app01"]
    assert hosts(db, q="TargetUserName:alice") == ["WIN-DC01"]
    assert hosts(db, q="bytes:>1000") == ["app01"]
    assert hosts(db, q="bytes:<1000") == []
    assert hosts(db, q="LogonType:3 -TargetUserName:bob") == ["WIN-DC01"]
    assert hosts(db, q="Channel:*") == ["WIN-DC01", "WIN-DC01"]
    assert hosts(db, q="job:backup") == ["web2"]                       # RFC 5424 structured data
    assert hosts(db, q="SourceName:Microsoft-Windows-Security-Auditing") == ["WIN-DC01", "WIN-DC01"]


def test_text_search_without_fts(db, monkeypatch):
    seed(db)
    monkeypatch.setattr(db, "has_fts", False)
    assert hosts(db, q='"changed state" -up') == ["core-sw1"]
    assert hosts(db, q="panic OR (sshd host:web1)") == ["fw1", "web1"]
    assert hosts(db, q="fail* app:sshd") == ["web1"]
    assert hosts(db, q="-panic -changed -EventID:*") == ["web1", "web2"]  # app01 has a GELF _EventID


def test_structured_fields_without_json1(db, monkeypatch):
    seed(db)
    monkeypatch.setattr(db, "_snmpathy_search_caps", {"json": False, "cidr": True}, raising=False)
    assert hosts(db, q="EventID:4771") == ["app01"]
    assert hosts(db, q="TargetUserName:alice") == ["WIN-DC01"]
    assert hosts(db, q="user.name:bob") == ["app01"]
    assert {r["value"] for r in S.field_top(db, SyslogFilter(), "TargetUserName")} == {"bob", "alice"}


def test_must_and_must_not(db):
    seed(db)
    assert hosts(db, must=[("host", "core-sw1")]) == ["core-sw1", "core-sw1"]
    assert hosts(db, must=[("host", "core-sw1")], must_not=[("severity", "3")]) == ["core-sw1"]
    assert hosts(db, must=[("EventID", "4625")]) == ["WIN-DC01"]
    assert hosts(db, must_not=[("app", "Microsoft-Windows-Security-Auditing"), ("app", "LINK")]) == [
        "app01", "fw1", "web1", "web2"]
    # Pill values are literal: no wildcards or operators.
    assert hosts(db, must=[("host", "core-*")]) == []
    assert hosts(db, must=[("severity", "err")], q="changed") == ["core-sw1"]
    # None = field missing.
    assert hosts(db, must=[("TargetUserName", None)], q="host:WIN-DC01 OR host:app01") == ["app01"]
    # From request parameters (JSON pills) and combined with the legacy filters.
    f = SyslogFilter.from_params({"must": json.dumps([["app", "LINK"]]), "must_not": '["severity:6"]',
                                  "severity": "err", "since": "1h"})
    assert f.must == [("app", "LINK")] and f.must_not == [("severity", "6")]
    assert [r["message"] for r in S.search(db, f)] == ["Interface Gi0/1, changed state to down"]
    assert S.count(db, f) == 1
    assert SyslogFilter.from_params({"must": "host:sw1"}).must == [("host", "sw1")]
    assert SyslogFilter.from_params({"must": "not json ["}).must == []


def test_fields_and_field_top(db):
    seed(db)
    found = {f["name"]: f for f in S.fields(db, SyslogFilter())}
    assert found["host"]["kind"] == "column" and found["host"]["count"] == 8
    assert found["severity"]["pct"] == 100.0
    assert found["TargetUserName"]["kind"] == "structured" and found["TargetUserName"]["count"] == 2
    assert {"user.name", "bytes", "EventID", "LogonType", "Channel"} <= set(found)
    assert "device_id" not in found  # never set
    only_gelf = {f["name"] for f in S.fields(db, SyslogFilter(q="host:app01"))}
    assert "user.name" in only_gelf and "TargetUserName" not in only_gelf
    assert S.fields(db, SyslogFilter(q="nothing-matches-this")) == []

    top_hosts = S.field_top(db, SyslogFilter(), "host", 3)
    assert top_hosts[0]["count"] == 2 and len(top_hosts) == 3
    sev = {r["label"]: r["count"] for r in S.field_top(db, SyslogFilter(), "severity")}
    assert sev["err"] == 1 and sev["crit"] == 1
    users = S.field_top(db, SyslogFilter(), "TargetUserName")
    assert {(r["value"], r["count"]) for r in users} == {("bob", 1), ("alice", 1)}
    assert S.field_top(db, SyslogFilter(), "user.name") == [{"value": "bob", "count": 1}]
    assert S.field_top(db, SyslogFilter(), "LogonType") == [{"value": "3", "count": 2}]
    event_ids = {r["value"] for r in S.field_top(db, SyslogFilter(), "EventID")}
    assert event_ids == {"4625", "4624", "4771"}
    with pytest.raises(ValueError):
        S.field_top(db, SyslogFilter(), "")


def test_histogram_multi(db):
    seed(db)
    base = SyslogFilter(start=NOW - 600, end=NOW + 1, must_not=[("host", "fw1")])
    h = S.histogram_multi(db, base, ["host:core-sw1", "EventID:4625 OR EventID:4624", "", "panic"], buckets=10)
    counts = [s["count"] for s in h["series"]]
    assert counts == [2, 2, 7, 0]  # the base filter (no fw1) applies to every query
    assert all(len(s["points"]) == len(h["series"][0]["points"]) for s in h["series"])
    assert sum(p[1] for p in h["series"][0]["points"]) == 2
    assert h["series"][1]["q"] == "EventID:4625 OR EventID:4624"
    assert len(S.histogram_multi(db, base, [str(i) for i in range(20)])["series"]) == S.MAX_QUERIES
    # The legacy histogram still works with the new query language.
    legacy = S.histogram(db, SyslogFilter(q="severity:<=3", start=NOW - 600))
    assert sum(b["error"] for b in legacy["buckets"]) == 2


def test_query_parser_shapes():
    tree = S.parse_query('host:a "b c" -d OR e')
    assert isinstance(tree, S.Or)
    assert S.parse_query("") is None
    field = S.parse_query("severity:<=3")
    assert (field.name, field.op, field.value) == ("severity", "<=", "3")
    assert isinstance(S.parse_query("-host:x"), S.Not)
    assert isinstance(S.parse_query("aa:bb:cc"), S.Text)


# ===================================================================== HTTP API
@pytest.fixture
def client(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    app = create_app(Settings(database=str(tmp_path / "t.db"), public_url="https://logs.example.net:8443/"),
                     db=db, start_monitor=False)
    app.include_router(router)
    with TestClient(app) as c:
        seed(db)
        yield c
    db.close()


def test_saved_search_crud(client):
    assert client.get("/api/logs/saved").json() == []
    body = {"name": "SSH failures", "query": "app:sshd failed",
            "filters": {"queries": ["app:sshd failed", "EventID:4625"], "pills": [{"field": "host", "value": "web1"}]}}
    r = client.post("/api/logs/saved", json=body)
    assert r.status_code == 201, r.text
    saved = r.json()
    assert saved["name"] == "SSH failures" and saved["filters"]["queries"][1] == "EventID:4625"
    # Saving under the same name replaces it.
    r = client.post("/api/logs/saved", json={**body, "query": "app:sshd"})
    assert r.status_code == 200 and r.json()["id"] == saved["id"]
    client.post("/api/logs/saved", json={"name": "Errors", "query": "severity:<=3"})
    listed = client.get("/api/logs/saved").json()
    assert [s["name"] for s in listed] == ["Errors", "SSH failures"]
    assert listed[1]["query"] == "app:sshd"
    assert client.post("/api/logs/saved", json={"name": ""}).status_code == 422
    assert client.delete(f"/api/logs/saved/{saved['id']}").status_code == 204
    assert client.delete(f"/api/logs/saved/{saved['id']}").status_code == 404
    assert [s["name"] for s in client.get("/api/logs/saved").json()] == ["Errors"]


def test_csv_export(client):
    r = client.get("/api/logs/export.csv", params={"q": "source_ip:10.0.0.0/8", "range": "1h",
                                                   "must_not": json.dumps([["host", "app01"]])})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert sorted(x["host"] for x in rows) == ["WIN-DC01", "WIN-DC01", "core-sw1", "core-sw1", "web1"]
    win = next(x for x in rows if x["msgid"] == "4625")
    assert json.loads(win["structured"])["TargetUserName"] == "bob"
    assert win["time"].endswith("Z") and win["severity"]
    assert len(list(csv.DictReader(io.StringIO(client.get("/api/logs/export.csv?limit=2").text)))) == 2


def test_csv_export_streams_in_chunks(db, monkeypatch):
    from snmpathy.syslog import web

    monkeypatch.setattr(web, "EXPORT_CHUNK", 3)
    seed(db)
    chunks = list(web.export_rows(db, SyslogFilter(), limit=7))
    assert len(chunks) == 1 + 3  # header + 3 + 3 + 1
    text = "".join(chunks)
    assert len(list(csv.DictReader(io.StringIO(text)))) == 7
    # Spreadsheet formula injection is neutralised.
    store_messages(db, [message_row(parse("<14>1 - h app - - - =HYPERLINK(\"x\")", "1.2.3.4", NOW))])
    out = "".join(web.export_rows(db, SyslogFilter(q="host:h")))
    assert "'=HYPERLINK" in out


def test_fields_top_and_histogram_endpoints(client):
    fields = client.get("/api/logs/fields", params={"range": "1h"}).json()
    names = {f["name"] for f in fields["fields"]}
    assert {"host", "app", "TargetUserName", "user.name"} <= names
    top = client.get("/api/logs/field-top", params={"field": "TargetUserName", "range": "1h"}).json()
    assert {v["value"] for v in top["values"]} == {"bob", "alice"}
    top = client.get("/api/logs/field-top", params={"field": "Hostname", "range": "1h", "limit": 1}).json()
    assert top["canonical"] == "host" and len(top["values"]) == 1
    assert client.get("/api/logs/field-top", params={"field": "id"}).status_code == 422
    h = client.get("/api/logs/histogram-multi",
                   params=[("q", "host:core-sw1"), ("q", "EventID:4625"), ("range", "1h"), ("buckets", "12")]).json()
    assert [s["count"] for s in h["series"]] == [2, 1]
    assert client.get("/api/logs/histogram-multi?range=1h").json()["series"][0]["count"] == 8
    # Pills reach the existing /api/syslog endpoints too.
    must = json.dumps([["EventID", "4625"]])
    assert client.get("/api/syslog/count", params={"must": must}).json()["count"] == 1
    assert len(client.get("/api/syslog", params={"q": "severity:<=3"}).json()) == 2


def test_pages_render(client):
    r = client.get("/syslog?q=host:core-sw1&severity=3")
    assert r.status_code == 200
    assert 'id="log-body"' in r.text and "Create alert" in r.text
    r = client.get("/logs/sources")
    assert r.status_code == 200
    html = r.text
    assert "logs.example.net" in html                      # public_url host in the snippets
    assert "im_msvistalog" in html and "to_json()" in html and "xm_gelf" in html
    assert "logging host logs.example.net" in html
    assert "--log-driver gelf" in html and "{{.Name}}" in html
    assert "&lt;Input eventlog&gt;" in html                # config is escaped, not parsed as HTML
    assert "WIN-DC01" in html                              # sources seen in the last 24 h
    assert "not running" in html                           # monitor not started


def test_setup_guides_use_ports():
    guides = setup_guides("10.1.2.3", {"udp": 1514, "tcp": 1515, "gelf_udp": 12202, "json_tcp": 5600})
    text = "\n".join(item["code"] for g in guides for item in g["items"])
    assert "@@10.1.2.3:1515" in text and "Port        5600" in text and "udp://10.1.2.3:12202" in text
    assert {g["id"] for g in guides} == {"linux", "windows", "network", "containers", "test"}
