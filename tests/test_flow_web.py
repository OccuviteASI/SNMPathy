import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from snmpathy import reporting
from snmpathy.app import create_app
from snmpathy.config import Settings
from snmpathy.flows import query as fq
from snmpathy.flows.alerts import evaluate_flow_rule, parse_expression, traffic_report
from snmpathy.flows.collector import FlowCollector
from snmpathy.flows.web import build_filter, router
from tests.test_flows import v5_packet

EXP1, EXP2 = "192.0.2.1", "192.0.2.2"
HTTPS_OUT = {"src": "10.0.0.1", "dst": "93.184.216.34", "sport": 51000, "dport": 443, "proto": 6,
             "packets": 50, "bytes": 50_000}
HTTPS_BACK = {"src": "93.184.216.34", "dst": "10.0.0.1", "sport": 443, "dport": 51000, "proto": 6,
              "packets": 20, "bytes": 20_000}
DNS = {"src": "10.0.0.2", "dst": "8.8.8.8", "sport": 40000, "dport": 53, "proto": 17, "packets": 2, "bytes": 1_000}
SSH = {"src": "192.168.1.5", "dst": "10.0.0.9", "sport": 22, "dport": 50123, "proto": 6, "packets": 5,
       "bytes": 3_000, "in_if": 7, "out_if": 8}
TOTAL = 74_000


class FakeMonitor:
    """Stands in for Monitor: only ``flows`` is used by the analyzer, ``stop`` by the app lifespan."""

    def __init__(self, flows):
        self.flows = flows

    async def stop(self):
        pass


@pytest.fixture
def env(tmp_path, db, make_device):
    device = make_device("edge1", EXP1)
    db.insert("interfaces", {"device_id": device["id"], "if_index": 1, "name": "Gi0/1", "alias": "uplink",
                             "speed": 1e9, "in_bps": 5e6, "out_bps": 1e6, "oper_status": 1, "admin_status": 1,
                             "updated_at": time.time()})
    now = time.time()
    collector = FlowCollector(db, ports={})
    assert collector.ingest(v5_packet([HTTPS_OUT, HTTPS_BACK, DNS], secs=now), EXP1, now=now) == 3
    assert collector.ingest(v5_packet([SSH], secs=now), EXP2, now=now) == 1
    collector.flush_now()
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    app.include_router(router)
    sources = {r["address"]: r["id"] for r in db.query("SELECT id, address FROM flow_sources")}
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, app=app, db=db, collector=collector, device=device, now=now,
                              s1=sources[EXP1], s2=sources[EXP2])


def get(env, url, status=200):
    r = env.client.get(url)
    assert r.status_code == status, r.text
    return r.json()


# ----------------------------------------------------------------------------- JSON API
def test_sources(env):
    rows = {s["address"]: s for s in get(env, "/api/flows/sources")}
    one = rows[EXP1]
    assert one["device_name"] == "edge1" and one["device_id"] == env.device["id"]
    assert one["kind"] == "netflow5" and one["status"] == "up" and one["status_label"] == "receiving"
    assert one["records"] == 3 and one["records_per_sec"] > 0 and one["bps_recent"] > 0
    assert one["display_name"] == EXP1 and one["sampling_override"] is None and one["enabled"] is True
    assert rows[EXP2]["device_name"] is None
    assert get(env, f"/api/flows/sources/{env.s2}")["address"] == EXP2
    get(env, "/api/flows/sources/9999", 404)


def test_summary(env):
    s = get(env, "/api/flows/summary?range=1h")
    assert s["bytes"] == TOTAL and s["flows"] == 4 and s["packets"] == 77
    assert s["bps_avg"] == pytest.approx(TOTAL * 8 / 3600, rel=0.01)
    assert s["bps_peak"] == pytest.approx(TOTAL * 8 / 60) and s["peak_step"] == 60 and s["peak_ts"]
    assert s["sources"] == 2 and s["filter"]["end"] - s["filter"]["start"] == pytest.approx(3600)
    custom = get(env, f"/api/flows/summary?start={env.now - 600}&end={env.now + 60}")
    assert custom["bytes"] == TOTAL
    assert get(env, f"/api/flows/summary?start={env.now - 7200}&end={env.now - 3600}")["bytes"] == 0


@pytest.mark.parametrize("query, expected", [
    ("ip=10.0.0.1", 70_000),
    ("src=10.0.0.1", 50_000),
    ("dst=10.0.0.1", 20_000),
    ("port=443", 70_000),
    ("port=https", 70_000),
    ("proto=udp", 1_000),
    ("proto=17", 1_000),
    ("proto=TCP", 73_000),
    ("cidr=10.0.0.0/8", TOTAL),
    ("ip=8.8.0.0/16", 1_000),           # a CIDR in ip= becomes a network filter
    ("cidr=192.168.0.0/16&port=22", 3_000),
    ("source_id={s2}", 3_000),
    ("source_id={s1}&proto=tcp", 70_000),
])
def test_filters(env, query, expected):
    q = query.format(s1=env.s1, s2=env.s2)
    assert get(env, f"/api/flows/summary?{q}")["bytes"] == expected
    rows = get(env, f"/api/flows/top?by=src&limit=50&{q}")["rows"]
    assert sum(r["bytes"] for r in rows) == expected


@pytest.mark.parametrize("query", ["proto=bogus", "cidr=10.0.0.0/99", "ip=not-an-ip", "range=forever",
                                   "port=70000", "port=nosuchservice", "src=1.2.3", "start=10&end=5"])
def test_bad_filters(env, query):
    assert "detail" in get(env, f"/api/flows/summary?{query}", 400)


def test_filter_echo_and_build_filter():
    f = build_filter({"range": "6h", "ip": "10.0.0.0/8", "proto": "icmp", "port": "dns"}, now=10_000_000)
    assert (f.cidr, f.ip, f.proto, f.port) == ("10.0.0.0/8", "", 1, 53)
    assert f.end - f.start == 6 * 3600


def test_timeseries(env):
    total = get(env, "/api/flows/timeseries?range=1h")
    assert total["unit"] == "bps" and total["step"] == 60 and [s["name"] for s in total["series"]] == ["Total"]
    assert sum(v for _, v in total["series"][0]["points"]) * 60 / 8 == pytest.approx(TOTAL)

    by_src = get(env, "/api/flows/timeseries?range=1h&group=src&limit=1")
    assert [s["name"] for s in by_src["series"]] == ["10.0.0.1", "Other"]

    apps = get(env, "/api/flows/timeseries?range=1h&group=app")
    names = [s["name"] for s in apps["series"]]
    assert names[0] == "https" and {"dns", "ssh"} <= set(names)
    assert sum(sum(v for _, v in s["points"]) for s in apps["series"]) * 60 / 8 == pytest.approx(TOTAL)

    for group in ("dst", "dport", "proto", "source"):
        assert get(env, f"/api/flows/timeseries?range=6h&group={group}")["series"]
    src_names = {s["name"] for s in get(env, "/api/flows/timeseries?range=1h&group=source")["series"]}
    assert src_names == {EXP1, EXP2}
    week = get(env, "/api/flows/timeseries?range=7d&proto=udp")
    assert week["step"] == 3600 and week["filter"]["proto"] == 17
    get(env, "/api/flows/timeseries?group=nope", 400)


def test_top_dimensions(env):
    for by in fq.TOP_BY:
        rows = get(env, f"/api/flows/top?by={by}&range=1h")["rows"]
        assert rows and sum(r["bytes"] for r in rows) == TOTAL, by
        assert sum(r["pct"] for r in rows) == pytest.approx(100)
    apps = get(env, "/api/flows/top?by=app")["rows"]
    assert (apps[0]["service"], apps[0]["port"], apps[0]["bytes"]) == ("https", 443, 70_000)
    conv = get(env, "/api/flows/top?by=conversation&limit=1")["rows"][0]
    assert (conv["src"], conv["dst"]) == ("10.0.0.1", "93.184.216.34")
    assert conv["bps"] == pytest.approx(50_000 * 8 / 3600, rel=0.01)
    in_if = {r["source_id"]: r for r in get(env, "/api/flows/top?by=in_if")["rows"]}
    assert in_if[env.s1]["if_name"] == "Gi0/1" and in_if[env.s1]["if_alias"] == "uplink"
    assert in_if[env.s2]["if_name"] == "ifIndex 7"
    assert get(env, "/api/flows/top?by=proto")["rows"][0]["proto_name"] == "TCP"
    get(env, "/api/flows/top?by=bogus", 400)
    get(env, "/api/flows/top?by=src&limit=0", 422)


def test_host_detail(env):
    h = get(env, "/api/flows/host/10.0.0.1?range=1h")
    assert h["ip"] == "10.0.0.1" and h["in"]["bytes"] == 20_000 and h["out"]["bytes"] == 50_000
    assert h["bytes"] == 70_000 and [s["name"] for s in h["series"]] == ["In (to host)", "Out (from host)"]
    (peer,) = h["peers"]
    assert peer["peer"] == "93.184.216.34" and (peer["in_bytes"], peer["out_bytes"]) == (20_000, 50_000)
    assert peer["pct"] == pytest.approx(100)
    exporter = get(env, f"/api/flows/host/{EXP1}")
    assert exporter["device"]["name"] == "edge1" and exporter["exporter"]["id"] == env.s1
    assert get(env, f"/api/flows/host/10.0.0.1?source_id={env.s2}")["bytes"] == 0
    get(env, "/api/flows/host/nonsense", 400)


def test_interfaces_and_status(env):
    (iface,) = get(env, "/api/flows/interfaces")
    assert iface["device_name"] == "edge1" and iface["util"] == pytest.approx(0.5)
    assert iface["link"] == f"/devices/{env.device['id']}?tab=interfaces#if1"

    status = get(env, "/api/flows/status")
    assert status["enabled"] is False and status["stats"] is None
    assert status["ports"] == {"netflow": 2055, "ipfix": 4739, "sflow": 6343}
    assert status["sources"] == 2 and status["sources_receiving"] == 2 and status["newest_bucket"]

    env.app.state.monitor = FakeMonitor(env.collector)
    status = get(env, "/api/flows/status")
    assert status["enabled"] is True and status["stats"]["records"] == 4 and status["listening"] == {}


def test_patch_and_delete_source(env):
    env.app.state.monitor = FakeMonitor(env.collector)
    c = env.client
    r = c.patch(f"/api/flows/sources/{env.s2}", json={"name": "branch fw", "sampling": 100,
                                                      "device_id": env.device["id"]})
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["name"] == "branch fw" and s["display_name"] == "branch fw"
    assert s["sampling_override"] == 100 and s["sampling"] == 100 and s["device_name"] == "edge1"

    s = c.patch(f"/api/flows/sources/{env.s2}", json={"sampling": 0, "device_id": None}).json()
    assert s["sampling_override"] is None and s["device_id"] is None and s["name"] == "branch fw"
    assert c.patch(f"/api/flows/sources/{env.s2}", json={"device_id": 9999}).status_code == 400
    assert c.patch("/api/flows/sources/9999", json={"name": "x"}).status_code == 404
    assert c.patch(f"/api/flows/sources/{env.s2}", json={"sampling": -1}).status_code == 422

    # Disabling reaches the running collector immediately.
    assert c.patch(f"/api/flows/sources/{env.s2}", json={"enabled": False}).json()["status"] == "paused"
    assert env.collector.ingest(v5_packet([SSH], secs=time.time()), EXP2) == 0
    assert env.collector.ingest(v5_packet([SSH], secs=time.time()), EXP1) == 1
    env.collector.flush_now()

    assert c.delete(f"/api/flows/sources/{env.s1}").status_code == 204
    assert env.db.scalar("SELECT COUNT(*) FROM flows WHERE source_id = ?", (env.s1,)) == 0
    assert [s["address"] for s in get(env, "/api/flows/sources")] == [EXP2]
    assert get(env, "/api/flows/summary")["bytes"] == 3_000
    assert c.delete(f"/api/flows/sources/{env.s1}").status_code == 404


# ----------------------------------------------------------------------------- pages
def test_pages_render(env):
    page = env.client.get("/traffic")
    assert page.status_code == 200
    for text in ("Network analyzer", "Top talkers", "Top conversations", "Interface bandwidth (SNMP)",
                 "Exporter setup guide", "UDP 2055", "ip flow-export", "/ip traffic-flow", "softflowd",
                 "inline-jflow", "sflow collector", "SP.chart"):
        assert text in page.text, text
    assert "No flow data yet" not in page.text

    page = env.client.get("/traffic/sources")
    assert page.status_code == 200
    assert EXP1 in page.text and EXP2 in page.text and "edge1" in page.text and "receiving" in page.text

    page = env.client.get("/traffic/host/10.0.0.1?range=6h")
    assert page.status_code == 200 and "10.0.0.1" in page.text and "Top peers" in page.text
    assert "edge1" in env.client.get(f"/traffic/host/{EXP1}").text
    assert env.client.get("/traffic/host/not-an-ip").status_code == 404


def test_empty_state(tmp_path, db):
    app = create_app(Settings(database=str(tmp_path / "e.db")), db=db, start_monitor=False)
    app.include_router(router)
    with TestClient(app) as client:
        page = client.get("/traffic")
        assert page.status_code == 200
        for text in ("No flow data yet", "UDP <b>2055</b>", "UDP <b>4739</b>", "UDP <b>6343</b>", "flow exporter SNMPATHY",
                     "set forwarding-options sampling", "version=9", "OPNsense", "pmacct", "sflow 1 destination"):
            assert text in page.text, text
        sources = client.get("/traffic/sources")
        assert sources.status_code == 200 and "No exporters have sent flows yet" in sources.text
        assert client.get("/api/flows/sources").json() == []
        assert client.get("/api/flows/summary").json()["bytes"] == 0


# ----------------------------------------------------------------------------- alerting
def rule(expr, threshold, op=">", window=300, **extra):
    return {"id": 7, "kind": "flow", "metric_key": expr, "window_seconds": window, "operator": op,
            "threshold": threshold, "device_id": None, "device_tag": "", **extra}


def test_flow_rule_fires_and_clears(env):
    now = env.now + 1
    bps_443 = 70_000 * 8 / 300
    (m,) = evaluate_flow_rule(env.db, rule("dport=443", 1000), now)
    assert m["fingerprint"] == "r7:flow" and m["value"] == pytest.approx(bps_443)
    assert "443" in m["subject"] and "kbps" in m["message"] and m["device_id"] is None
    assert evaluate_flow_rule(env.db, rule("dport=443", 5000), now) == []
    assert len(evaluate_flow_rule(env.db, rule("dport=443", 5000, op="<"), now)) == 1

    (m,) = evaluate_flow_rule(env.db, rule("", 1000), now)
    assert m["value"] == pytest.approx(TOTAL * 8 / 300) and m["subject"] == "Total traffic"
    (m,) = evaluate_flow_rule(env.db, rule("cidr=10.0.0.0/8 proto=udp", 10), now)
    assert m["value"] == pytest.approx(1000 * 8 / 300)
    assert evaluate_flow_rule(env.db, rule("ip=10.0.0.5", 0), now) == []
    assert len(evaluate_flow_rule(env.db, rule("ip=10.0.0.1", 0), now)) == 1
    # Traffic outside the window does not count.
    assert evaluate_flow_rule(env.db, rule("", 0), now + 3600) == []


def test_flow_rule_grouping_and_scope(env, make_device):
    now = env.now + 1
    matches = evaluate_flow_rule(env.db, rule("by=src", 50), now)
    assert {m["fingerprint"] for m in matches} == {"r7:flow:src:10.0.0.1", "r7:flow:src:93.184.216.34",
                                                   "r7:flow:src:192.168.1.5"}
    apps = evaluate_flow_rule(env.db, rule("proto=tcp, by=app", 0), now)
    assert {m["subject"] for m in apps} == {"https traffic", "ssh traffic"}

    scoped = evaluate_flow_rule(env.db, rule("", 0, device_id=env.device["id"]), now)
    assert scoped[0]["value"] == pytest.approx(71_000 * 8 / 300) and scoped[0]["device_id"] == env.device["id"]
    no_exporter = make_device("other", "198.51.100.1")["id"]
    assert evaluate_flow_rule(env.db, rule("", 0, device_id=no_exporter), now) == []
    (m,) = evaluate_flow_rule(env.db, rule(f"source={env.s2}", 0), now)
    assert m["value"] == pytest.approx(3000 * 8 / 300)

    assert evaluate_flow_rule(env.db, rule("", None), now) == []
    with pytest.raises(ValueError):
        evaluate_flow_rule(env.db, rule("colour=blue", 1), now)
    assert parse_expression("10.0.0.5 udp https 10.1.0.0/16") == {
        "ip": "10.0.0.5", "proto": 17, "port": 443, "cidr": "10.1.0.0/16"}


# ----------------------------------------------------------------------------- report
def test_traffic_report_shape(env):
    start, end = env.now - 3600, env.now + 60
    rep = traffic_report(env.db, start, end, "Last 1h")
    assert {"id", "title", "subtitle", "start", "end", "generated_at", "summary", "sections"} <= set(rep)
    assert rep["id"] == "traffic" and rep["subtitle"] == "Last 1h"
    summary = {s["label"]: s for s in rep["summary"]}
    assert summary["Total traffic"]["value"] == TOTAL and summary["Total traffic"]["fmt"] == "bytes"
    assert summary["Exporters"]["value"] == 2 and summary["Peak rate"]["value"] > 0
    titles = [s["title"] for s in rep["sections"]]
    assert titles == ["Top talkers (sources)", "Top destinations", "Top applications", "Top conversations",
                      "Protocols", "Traffic per exporter"]
    for sec in rep["sections"]:
        assert sec["rows"], sec["title"]
        for col in sec["columns"]:
            assert {"key", "label"} <= set(col)
            for row in sec["rows"]:
                assert col["key"] in row, (sec["title"], col["key"])
                reporting.format_cell(row[col["key"]], col.get("fmt", "text"))
    assert rep["sections"][0]["rows"][0]["_link"] == "/traffic/host/10.0.0.1"
    assert rep["sections"][2]["rows"][0]["service"] == "https"
    assert reporting.to_csv(rep).startswith("# Top talkers")
    assert "Total traffic" in reporting.to_text(rep)

    scoped = traffic_report(env.db, start, end, "x", device_id=env.device["id"], limit=1)
    assert scoped["summary"][0]["value"] == 71_000 and len(scoped["sections"][0]["rows"]) == 1
    assert "exporter" in scoped["sections"][0]["note"]
    filtered = traffic_report(env.db, start, end, "x", proto="udp")
    assert filtered["summary"][0]["value"] == 1_000
