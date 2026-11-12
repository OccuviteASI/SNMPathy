import asyncio
import random
import socket
import struct
import time

import pytest

from snmpathy.flows import FlowCollector, FlowDecodeError, FlowFilter, TemplateCache, decode
from snmpathy.flows import query as fq
from snmpathy.flows.parser import parse_ethernet

NOW = 1_700_000_030.0
EXPORTER = "192.0.2.1"


def ip4(addr):
    return socket.inet_pton(socket.AF_INET, addr)


def ip6(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


# ----------------------------------------------------------------------------- packet builders
def v5_packet(records, secs=NOW, uptime=100_000, sampling=0):
    header = struct.pack("!HHIIIIBBH", 5, len(records), uptime, int(secs), 0, 1, 0, 0, sampling)
    body = b""
    for r in records:
        body += struct.pack(
            "!4s4s4sHHIIIIHHxBBBHHBBxx",
            ip4(r["src"]), ip4(r["dst"]), ip4("0.0.0.0"), r.get("in_if", 1), r.get("out_if", 2),
            r["packets"], r["bytes"], r.get("first", 98_000), r.get("last", 99_000),
            r["sport"], r["dport"], 0x18, r["proto"], 0, 0, 0, 24, 24,
        )
    return header + body


V5_RECORDS = [
    {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 51000, "dport": 443, "proto": 6, "packets": 10, "bytes": 5000},
    {"src": "10.0.0.3", "dst": "8.8.8.8", "sport": 40000, "dport": 53, "proto": 17, "packets": 1, "bytes": 80,
     "in_if": 3, "out_if": 4},
]

V9_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (10, 2), (14, 2), (22, 4), (21, 4)]


def _pad4(b):
    return b + b"\x00" * (-len(b) % 4)


def flowset(set_id, body):
    body = _pad4(body)
    return struct.pack("!HH", set_id, len(body) + 4) + body


def v9_packet(flowsets, secs=NOW, uptime=100_000, source_id=7):
    return struct.pack("!HHIIII", 9, len(flowsets), uptime, int(secs), 1, source_id) + b"".join(flowsets)


def v9_template(template_id=256, fields=V9_FIELDS):
    body = struct.pack("!HH", template_id, len(fields))
    for fid, length in fields:
        body += struct.pack("!HH", fid, length)
    return flowset(0, body)


def v9_record(src, dst, sport, dport, proto, nbytes, pkts, in_if=1, out_if=2, first=98_000, last=99_000):
    return struct.pack("!4s4sHHBIIHHII", ip4(src), ip4(dst), sport, dport, proto, nbytes, pkts, in_if, out_if,
                       first, last)


def ipfix_message(sets, export_time=NOW, domain=1):
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, 16 + len(body), int(export_time), 1, domain) + body


def ipfix_set(set_id, body):
    return struct.pack("!HH", set_id, len(body) + 4) + body


IPFIX_TEMPLATE_FIELDS = (
    struct.pack("!HH", 27, 16) + struct.pack("!HH", 28, 16)        # IPv6 src / dst
    + struct.pack("!HH", 7, 2) + struct.pack("!HH", 11, 2)         # ports
    + struct.pack("!HH", 4, 1)                                     # protocol
    + struct.pack("!HHI", 0x8000 | 100, 4, 9)                      # enterprise field (Cisco), skipped
    + struct.pack("!HH", 1, 8) + struct.pack("!HH", 2, 8)          # octet/packet delta (64-bit)
    + struct.pack("!HH", 82, 65535)                                # interfaceName, variable length
    + struct.pack("!HH", 10, 4) + struct.pack("!HH", 14, 4)        # ingress/egress interface
    + struct.pack("!HH", 152, 8) + struct.pack("!HH", 153, 8)      # flowStart/EndMilliseconds
)


def ipfix_record(src, dst, sport, dport, nbytes, pkts, ifname, start_ms, end_ms):
    name = ifname.encode()
    var = (bytes([len(name)]) if len(name) < 255 else b"\xff" + struct.pack("!H", len(name))) + name
    return (ip6(src) + ip6(dst) + struct.pack("!HHB", sport, dport, 6) + b"\xde\xad\xbe\xef"
            + struct.pack("!QQ", nbytes, pkts) + var + struct.pack("!IIQQ", 5, 6, start_ms, end_ms))


def ethernet_ipv4_tcp(src, dst, sport, dport, vlan=100):
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
    if vlan is not None:
        eth += struct.pack("!HH", 0x8100, vlan)
    eth += struct.pack("!H", 0x0800)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0x4000, 64, 6, 0, ip4(src), ip4(dst))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x10, 1024, 0, 0)
    return eth + iph + tcp


def sflow_datagram(agent="192.0.2.50", rate=512, frame_length=1514, header=None, expanded=False):
    header = header if header is not None else ethernet_ipv4_tcp("10.1.1.1", "10.2.2.2", 443, 50000)
    raw = struct.pack("!IIII", 1, frame_length, 4, len(header)) + _pad4(header)
    record = struct.pack("!II", 1, len(raw)) + raw
    if expanded:
        sample = struct.pack("!IIIIIIIIIII", 1, 0, 3, rate, 1000, 0, 0, 3, 0, 4, 1)
        fmt = 3
    else:
        sample = struct.pack("!IIIIIIII", 1, 3, rate, 1000, 0, 3, 4, 1)
        fmt = 1
    sample += record
    counter = struct.pack("!II", 2, 8) + struct.pack("!II", 1, 0)   # counters sample: ignored
    samples = struct.pack("!II", fmt, len(sample)) + sample + counter
    return struct.pack("!II", 5, 1) + ip4(agent) + struct.pack("!IIII", 0, 1, 1000, 2) + samples


# ----------------------------------------------------------------------------- decoder tests
def test_netflow_v5():
    res = decode(v5_packet(V5_RECORDS, sampling=0x4000 | 10), EXPORTER, TemplateCache())
    assert res.kind == "netflow5" and res.sampling == 10 and res.skipped == 0
    a, b = res.records
    assert (a["src"], a["dst"], a["sport"], a["dport"], a["proto"]) == ("10.0.0.1", "10.0.0.2", 51000, 443, 6)
    assert a["bytes"] == 50_000 and a["packets"] == 100
    assert (b["in_if"], b["out_if"]) == (3, 4)
    assert a["end"] == pytest.approx(NOW - 1) and a["start"] == pytest.approx(NOW - 2)


def test_netflow_v9_template_then_data_only():
    cache = TemplateCache()
    first = v9_packet([
        v9_template(),
        flowset(256, v9_record("10.0.0.1", "10.0.0.2", 51000, 443, 6, 1000, 5)
                + v9_record("10.0.0.2", "10.0.0.1", 443, 51000, 6, 9000, 7, in_if=2, out_if=1)),
    ])
    res = decode(first, EXPORTER, cache)
    assert res.kind == "netflow9" and len(res.records) == 2 and res.skipped == 0
    assert res.records[0]["bytes"] == 1000 and res.records[1]["in_if"] == 2
    assert res.records[0]["end"] == pytest.approx(NOW - 1)
    assert len(cache) == 1

    second = v9_packet([flowset(256, v9_record("10.9.9.9", "10.0.0.2", 1234, 22, 6, 300, 3))])
    res = decode(second, EXPORTER, cache)
    assert [r["dport"] for r in res.records] == [22]

    # Same template id from another exporter is unknown: skipped, not misparsed.
    res = decode(second, "192.0.2.99", cache)
    assert res.records == [] and res.skipped == 1


def test_netflow_v9_options_sampling():
    cache = TemplateCache()
    options = flowset(1, struct.pack("!HHH", 257, 4, 8) + struct.pack("!HH", 1, 4)
                      + struct.pack("!HH", 34, 4) + struct.pack("!HH", 35, 1))
    options_data = flowset(257, struct.pack("!IIB", 0, 100, 2))
    data = flowset(256, v9_record("10.0.0.1", "10.0.0.2", 51000, 443, 6, 1000, 5))
    # Data is listed before the options data: sampling must still apply.
    res = decode(v9_packet([v9_template(), options, data, options_data]), EXPORTER, cache)
    assert res.sampling == 100
    assert res.records[0]["bytes"] == 100_000 and res.records[0]["packets"] == 500
    assert cache.sampling_for(EXPORTER) == 100


def test_ipfix_variable_length_and_enterprise_fields():
    cache = TemplateCache()
    template = ipfix_set(2, struct.pack("!HH", 300, 13) + IPFIX_TEMPLATE_FIELDS)
    start_ms, end_ms = int((NOW - 5) * 1000), int((NOW - 2) * 1000)
    long_name = "x" * 300  # forces the 3-byte (255 + uint16) length encoding
    data = ipfix_set(300, ipfix_record("2001:db8::1", "2001:db8::2", 40000, 443, 2**33, 4, "Gi0/1", start_ms, end_ms)
                     + ipfix_record("2001:db8::3", "2001:db8::4", 53, 40001, 120, 1, long_name, start_ms, end_ms))
    res = decode(ipfix_message([template, data]), EXPORTER, cache)
    assert res.kind == "ipfix" and res.skipped == 0
    a, b = res.records
    assert (a["src"], a["dst"], a["sport"], a["dport"], a["proto"]) == ("2001:db8::1", "2001:db8::2", 40000, 443, 6)
    assert a["bytes"] == 2**33 and a["packets"] == 4 and (a["in_if"], a["out_if"]) == (5, 6)
    assert a["start"] == pytest.approx(NOW - 5) and a["end"] == pytest.approx(NOW - 2)
    assert b["src"] == "2001:db8::3" and b["bytes"] == 120

    # Data-only message reuses the cached template.
    res = decode(ipfix_message([data]), EXPORTER, cache)
    assert len(res.records) == 2


def test_ipfix_options_template_sampling_and_withdrawal():
    cache = TemplateCache()
    template = ipfix_set(2, struct.pack("!HH", 300, 13) + IPFIX_TEMPLATE_FIELDS)
    options = ipfix_set(3, struct.pack("!HHH", 301, 2, 1) + struct.pack("!HH", 149, 4) + struct.pack("!HH", 34, 4))
    options_data = ipfix_set(301, struct.pack("!II", 1, 1000))
    data = ipfix_set(300, ipfix_record("2001:db8::1", "2001:db8::2", 1, 2, 10, 1, "a", 0, 0))
    res = decode(ipfix_message([template, options, options_data, data]), EXPORTER, cache)
    assert res.sampling == 1000 and res.records[0]["bytes"] == 10_000
    assert "end" not in res.records[0]  # zero timestamps are treated as absent

    withdraw = ipfix_set(2, struct.pack("!HH", 300, 0))
    decode(ipfix_message([withdraw]), EXPORTER, cache)
    res = decode(ipfix_message([data]), EXPORTER, cache)
    assert res.records == [] and res.skipped == 1


@pytest.mark.parametrize("expanded", [False, True])
def test_sflow_flow_sample(expanded):
    res = decode(sflow_datagram(expanded=expanded), "198.51.100.7", TemplateCache())
    assert res.kind == "sflow" and res.agent == "192.0.2.50" and res.sampling == 512
    (rec,) = res.records
    assert (rec["src"], rec["dst"], rec["sport"], rec["dport"], rec["proto"]) == ("10.1.1.1", "10.2.2.2", 443, 50000, 6)
    assert rec["bytes"] == 1514 * 512 and rec["packets"] == 512
    assert (rec["in_if"], rec["out_if"]) == (3, 4)


def test_sflow_non_ip_sample_is_skipped():
    arp = b"\xff" * 6 + b"\x00" * 6 + struct.pack("!H", 0x0806) + b"\x00" * 28
    res = decode(sflow_datagram(header=arp), "198.51.100.7", TemplateCache())
    assert res.records == [] and res.skipped == 1


def test_parse_ethernet_ipv6_udp():
    eth = b"\x00" * 12 + struct.pack("!H", 0x86DD)
    ip = struct.pack("!IHBB", 6 << 28, 8, 17, 64) + ip6("2001:db8::a") + ip6("2001:db8::b")
    udp = struct.pack("!HHHH", 5353, 53, 8, 0)
    assert parse_ethernet(eth + ip + udp) == {
        "src": "2001:db8::a", "dst": "2001:db8::b", "proto": 17, "sport": 5353, "dport": 53}


@pytest.mark.parametrize("data", [
    b"",
    b"\x00\x05",
    b"\x00\x07" + b"\x00" * 30,                        # unsupported version
    v5_packet(V5_RECORDS)[:-10],                       # truncated record
    v9_packet([v9_template()])[:-3],                   # FlowSet length beyond datagram
    ipfix_message([ipfix_set(2, struct.pack("!HH", 300, 13) + IPFIX_TEMPLATE_FIELDS)])[:-6],
    sflow_datagram()[:-20],                            # truncated sample
])
def test_malformed_raises(data):
    with pytest.raises(FlowDecodeError):
        decode(data, EXPORTER, TemplateCache())


def test_fuzz_only_flowdecodeerror():
    rng = random.Random(1234)
    template = ipfix_set(2, struct.pack("!HH", 300, 13) + IPFIX_TEMPLATE_FIELDS)
    samples = [
        v5_packet(V5_RECORDS),
        v9_packet([v9_template(), flowset(256, v9_record("10.0.0.1", "10.0.0.2", 1, 2, 6, 3, 4))]),
        ipfix_message([template, ipfix_set(300, ipfix_record("::1", "::2", 1, 2, 3, 4, "eth0", 0, 0))]),
        sflow_datagram(),
        sflow_datagram(expanded=True),
    ]
    for sample in samples:
        for cut in range(len(sample)):
            try:
                decode(sample[:cut], EXPORTER, TemplateCache())
            except FlowDecodeError:
                pass
        for _ in range(300):
            mutated = bytearray(sample)
            for _ in range(rng.randint(1, 6)):
                mutated[rng.randrange(4, len(mutated))] = rng.randrange(256)
            try:
                decode(bytes(mutated), EXPORTER, TemplateCache())
            except FlowDecodeError:
                pass


# ----------------------------------------------------------------------------- collector
def test_collector_ingest_flush_and_sources(db, make_device):
    device_id = make_device("edge1", EXPORTER)["id"]
    collector = FlowCollector(db, ports={})
    packet = v5_packet(V5_RECORDS)
    assert collector.ingest(packet, EXPORTER, now=NOW) == 2
    assert collector.ingest(packet, "::ffff:" + EXPORTER, now=NOW) == 2
    assert collector.ingest(b"garbage!", EXPORTER, now=NOW) == 0
    assert collector.stats.datagrams == 3 and collector.stats.records == 4 and collector.stats.errors == 1
    assert collector.flush_now() == 2

    rows = db.query("SELECT * FROM flows ORDER BY bytes DESC")
    assert len(rows) == 2
    bucket = int(NOW - 1) // 60 * 60
    assert rows[0]["bucket"] == bucket and rows[0]["bytes"] == 10_000 and rows[0]["packets"] == 20
    assert rows[0]["flows"] == 2 and rows[0]["dport"] == 443

    src = db.one("SELECT * FROM flow_sources")
    assert src["address"] == EXPORTER and src["kind"] == "netflow5" and src["device_id"] == device_id
    assert src["packets"] == 2 and src["records"] == 4 and src["last_seen"] == NOW
    assert rows[0]["source_id"] == src["id"]

    # A second flush adds new rows; queries sum over them.
    collector.ingest(packet, EXPORTER, now=NOW + 5)
    collector.flush_now()
    assert db.scalar("SELECT COUNT(*) FROM flows") == 4
    assert db.scalar("SELECT packets FROM flow_sources") == 3

    # Disabled sources are ignored once the collector notices.
    db.execute("UPDATE flow_sources SET enabled = 0")
    collector.invalidate_sources()
    assert collector.ingest(packet, EXPORTER, now=NOW) == 0
    assert collector.stats.ignored == 1
    assert collector.flush_now() == 0


def test_collector_bucketing_cap_and_sflow_agent(db):
    collector = FlowCollector(db, ports={}, max_keys=2)
    now = time.time()
    # Record end times a day old fall back to the receive time.
    collector.ingest(v5_packet(V5_RECORDS, secs=now - 86400), EXPORTER, now=now)
    assert collector.ingest(sflow_datagram(), "198.51.100.7", now=now) == 0
    assert collector.stats.dropped == 1
    collector.flush_now()
    assert {r["bucket"] for r in db.query("SELECT bucket FROM flows")} == {int(now) // 60 * 60}
    collector.ingest(sflow_datagram(), "198.51.100.7", now=now)
    collector.flush_now()
    sources = {r["address"]: r for r in db.query("SELECT * FROM flow_sources")}
    assert set(sources) == {EXPORTER, "192.0.2.50"}  # sFlow uses the agent address
    assert sources["192.0.2.50"]["kind"] == "sflow" and sources["192.0.2.50"]["sampling"] == 512


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def test_collector_udp_end_to_end(db):
    port = _free_udp_port()
    collector = FlowCollector(db, "127.0.0.1", ports={"netflow": port, "ipfix": 0, "sflow": None},
                              flush_interval=60)
    await collector.start()
    clash = FlowCollector(db, "127.0.0.1", ports={"netflow": port})
    await clash.start()  # port already bound: logged and skipped, not fatal
    try:
        assert collector.listening == {"netflow": f"127.0.0.1:{port}"}
        assert clash.listening == {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(v5_packet(V5_RECORDS, secs=time.time()), ("127.0.0.1", port))
        sock.close()
        for _ in range(100):
            await asyncio.sleep(0.02)
            if collector.stats.datagrams:
                break
    finally:
        await clash.stop()
        await collector.stop()
    assert collector.stats.records == 2
    assert db.scalar("SELECT SUM(bytes) FROM flows") == 5080
    assert db.scalar("SELECT address FROM flow_sources") == "127.0.0.1"


# ----------------------------------------------------------------------------- queries
@pytest.fixture
def flow_rows(db):
    sid = db.insert("flow_sources", {"address": EXPORTER, "name": "edge", "first_seen": NOW, "last_seen": NOW})
    base = int(NOW) // 60 * 60 - 600
    rows = [
        # bucket, src, dst, sport, dport, proto, bytes
        (base, "10.0.0.1", "93.184.216.34", 51000, 443, 6, 6000),
        (base + 60, "10.0.0.1", "93.184.216.34", 51001, 443, 6, 4000),
        (base, "10.0.0.2", "8.8.8.8", 40000, 53, 17, 3000),
        (base + 120, "192.168.1.5", "10.0.0.9", 22, 50123, 6, 2000),   # reply from an ssh server
        (base + 120, "172.16.0.1", "172.16.0.2", 40000, 50000, 6, 500),
    ]
    db.executemany(
        "INSERT INTO flows (bucket, source_id, src, dst, sport, dport, proto, in_if, out_if, bytes, packets, flows) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 2, ?, 1, 1)",
        [(b, sid, s, d, sp, dp, p, by) for b, s, d, sp, dp, p, by in rows],
    )
    return {"sid": sid, "base": base, "filter": FlowFilter(start=base - 60, end=base + 600)}


def test_totals_and_top_talkers(db, flow_rows):
    f = flow_rows["filter"]
    tot = fq.totals(db, f)
    assert tot["bytes"] == 15_500 and tot["flows"] == 5
    assert tot["bps_avg"] == pytest.approx(15_500 * 8 / 660)

    talkers = fq.top(db, f, "src", limit=3)
    assert [r["src"] for r in talkers] == ["10.0.0.1", "10.0.0.2", "192.168.1.5"]
    assert talkers[0]["bytes"] == 10_000 and talkers[0]["pct"] == pytest.approx(10_000 / 15_500 * 100)

    conv = fq.top(db, f, "conversation", limit=1)[0]
    assert (conv["src"], conv["dst"]) == ("10.0.0.1", "93.184.216.34")

    (source,) = fq.top(db, f, "source")
    assert source["source_name"] == "edge" and source["bytes"] == 15_500
    assert fq.top(db, f, "proto")[0]["proto_name"] == "TCP"
    assert fq.top(db, f, "in_if")[0]["in_if"] == 1


def test_app_naming(db, flow_rows):
    apps = {r["service"]: r for r in fq.top(db, flow_rows["filter"], "app")}
    assert apps["https"]["bytes"] == 10_000 and apps["https"]["port"] == 443
    assert apps["dns"]["bytes"] == 3000
    assert apps["ssh"]["port"] == 22            # well-known source port wins over an ephemeral dport
    assert "tcp/50000" in apps
    assert fq.app_name(6, 51000, 443) == "https"
    assert fq.app_name(17, 53, 40000) == "dns"
    assert fq.app_name(1, 0, 2048) == "ICMP"
    assert fq.SERVICE_NAMES[443] == "https" and fq.PROTO_NAMES[58] == "ICMPv6"


def test_timeseries_grouping_with_other(db, flow_rows):
    f, base = flow_rows["filter"], flow_rows["base"]
    total = fq.timeseries(db, f)
    assert total["step"] == 60 and [s["name"] for s in total["series"]] == ["Total"]
    pts = dict((t, v) for t, v in total["series"][0]["points"])
    assert pts[base] == pytest.approx(9000 * 8 / 60) and pts[base + 180] == 0

    grouped = fq.timeseries(db, f, group="src", limit=2)
    names = [s["name"] for s in grouped["series"]]
    assert names == ["10.0.0.1", "10.0.0.2", "Other"]
    other = dict((t, v) for t, v in grouped["series"][-1]["points"])
    assert other[base + 120] == pytest.approx(2500 * 8 / 60)

    by_proto = fq.timeseries(db, f, group="proto")
    assert {s["name"] for s in by_proto["series"]} == {"TCP", "UDP"}
    assert fq.timeseries(db, FlowFilter(start=NOW - 7 * 86400, end=NOW))["step"] == 3600
    assert fq.timeseries(db, FlowFilter(start=NOW - 86400, end=NOW))["step"] == 300


def test_port_ip_and_cidr_filters(db, flow_rows):
    f = flow_rows["filter"]
    port = FlowFilter(start=f.start, end=f.end, port=443)
    assert fq.totals(db, port)["bytes"] == 10_000
    ip = FlowFilter(start=f.start, end=f.end, ip="8.8.8.8")
    assert fq.totals(db, ip)["bytes"] == 3000

    cidr = FlowFilter(start=f.start, end=f.end, cidr="10.0.0.0/8")
    assert fq.totals(db, cidr)["bytes"] == 15_000
    assert [r["src"] for r in fq.top(db, cidr, "src")] == ["10.0.0.1", "10.0.0.2", "192.168.1.5"]
    series = fq.timeseries(db, FlowFilter(start=f.start, end=f.end, cidr="172.16.0.0/12"), group="dst")
    assert [s["name"] for s in series["series"]] == ["172.16.0.2"]
    assert fq.totals(db, FlowFilter(start=f.start, end=f.end, cidr="2001:db8::/32"))["bytes"] == 0

    params = FlowFilter.from_params({"since": "1h", "proto": "udp", "port": "53"})
    assert params.proto == 17 and params.port == 53 and params.start is not None


def test_prune(db, flow_rows):
    assert fq.prune(db, flow_rows["base"] + 60) == 2
    assert db.scalar("SELECT COUNT(*) FROM flows") == 3
