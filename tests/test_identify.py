import asyncio
import gzip
import json
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from snmpathy import brands, identify, macvendor
from snmpathy.identify import Identity
from snmpathy.scanner import ScanManager, ScanOptions, scan_host
from tests.test_scanner import Net


def ubnt_reply(fields, version=1):
    body = b"".join(bytes([kind]) + struct.pack(">H", len(value)) + value for kind, value in fields)
    return bytes([version, 0]) + struct.pack(">H", len(body)) + body


SAMPLE = ubnt_reply([(0x02, bytes.fromhex("f09fc2112233") + bytes([192, 168, 1, 20])),
                     (0x0B, b"Office-AP"), (0x0C, b"UAL6"), (0x03, b"UAL6.qca956x.v6.5.62.14789.230606.1504"),
                     (0x14, b"U6-Lite"), (0x0A, struct.pack(">I", 1234))])

DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Living room router</friendlyName><manufacturer>NETGEAR, Inc.</manufacturer>
<modelName>Nighthawk</modelName><modelNumber>R7000</modelNumber>
<deviceList><device><manufacturer>Other</manufacturer><modelName>Inner</modelName></device></deviceList>
</device></root>"""


# ------------------------------------------------------------------ parsing
def test_parse_ubnt():
    found = identify.parse_ubnt(SAMPLE)
    assert found == Identity(vendor="Ubiquiti", model="U6-Lite", firmware="UAL6.qca956x.v6.5.62.14789.230606.1504",
                             name="Office-AP", source="ubiquiti")
    assert identify.parse_ubnt(ubnt_reply([(0x0C, b"ER-X")], version=2)).model == "ER-X"
    for junk in (b"", b"\x05\x00\x00\x00", b"\x01\x00\x00\x00", b"\x01\x00\x00\x09\x0c\x00\xffX"):
        assert identify.parse_ubnt(junk) is None


def test_parse_upnp_description_and_location():
    found = identify.parse_description(DESCRIPTION)
    assert found == Identity(vendor="NETGEAR, Inc.", model="Nighthawk R7000", name="Living room router", source="upnp")
    assert identify.parse_description(b"<not xml") is None and identify.parse_description(b"<root/>") is None
    reply = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n"
    assert identify.ssdp_location(reply) == "http://192.168.1.1:5000/rootDesc.xml"
    assert identify.location_allowed("http://192.168.1.1:5000/x.xml", "192.168.1.1")
    assert not identify.location_allowed("http://10.9.9.9/x.xml", "192.168.1.1")  # only the device itself
    assert not identify.location_allowed("file:///etc/passwd", "192.168.1.1")
    assert not identify.location_allowed("http://evil.example/x.xml", "192.168.1.1")


# ------------------------------------------------------------------ real sockets (localhost)
class _Reply(asyncio.DatagramProtocol):
    def __init__(self, answers):
        self.answers = answers

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        for answer in self.answers(data):
            self.transport.sendto(answer, addr)


async def _udp_server(answers):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _Reply(answers), local_addr=("127.0.0.1", 0))
    return transport, transport.get_extra_info("sockname")[1]


@pytest.mark.network_ok
async def test_ubiquiti_probe_over_udp():
    transport, port = await _udp_server(lambda data: [SAMPLE] if data == identify.UBNT_REQUEST else [])
    try:
        found = await identify.ubiquiti("127.0.0.1", 1.0, port=port)
    finally:
        transport.close()
    assert found.model == "U6-Lite" and found.vendor == "Ubiquiti"


@pytest.mark.network_ok
async def test_upnp_probe_fetches_the_description():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(DESCRIPTION)

        def log_message(self, *a):
            pass
    http = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    location = f"http://127.0.0.1:{http.server_address[1]}/rootDesc.xml".encode()

    def answers(data):
        assert data.startswith(b"M-SEARCH * HTTP/1.1") and b"ssdp:discover" in data
        return [b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: " + location + b"\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nLOCATION: http://10.1.2.3/elsewhere.xml\r\n\r\n"]
    transport, port = await _udp_server(answers)
    try:
        found = await identify.upnp("127.0.0.1", 0.5, port=port)
    finally:
        transport.close()
        http.shutdown()
    assert found.vendor == "NETGEAR, Inc." and found.model == "Nighthawk R7000"


@pytest.mark.network_ok
async def test_identify_merges_and_ignores_names():
    assert await identify.identify("printer.lan") == Identity()


# ------------------------------------------------------------------ scans and devices
async def test_scan_takes_model_from_probes_but_snmp_wins(monkeypatch):
    async def found(host, timeout=1.5):
        return Identity(vendor="NETGEAR, Inc.", model="Nighthawk R7000", firmware="1.0.11", name="router",
                        source="upnp")
    monkeypatch.setattr(identify, "identify", found)
    net = Net()
    opts = ScanOptions.from_dict({"communities": ["secret"], "resolve_dns": False})
    r = await scan_host("10.0.0.2", opts, net.probe, net.client)  # no SNMP
    assert (r["vendor"], r["hw_model"], r["firmware"], r["sys_name"]) == ("Netgear", "Nighthawk R7000", "1.0.11", "router")
    r = await scan_host("10.0.0.1", opts, net.probe, net.client)  # SNMP answered: its vendor / name stay
    assert r["vendor"] == "Cisco" and r["sys_name"] == "sw-1" and r["hw_model"] == "Nighthawk R7000"
    off = ScanOptions.from_dict({"resolve_dns": False, "identify": False})
    assert (await scan_host("10.0.0.2", off, net.probe, net.client))["hw_model"] == ""


async def test_scan_adds_devices_with_model_and_brand(db, monkeypatch):
    async def found(host, timeout=1.5):
        return Identity(vendor="Ubiquiti", model="U6-Lite", firmware="6.5.62", source="ubiquiti") \
            if host == "10.0.0.2" else Identity()
    monkeypatch.setattr(identify, "identify", found)
    manager = ScanManager(db, local_probe=Net().probe, local_clients=Net().client)
    scan = manager.create({"name": "home", "targets": "10.0.0.2-3",
                           "options": {"resolve_dns": False, "auto_add": "alive", "tags": []}})
    await manager.run(scan["id"])
    row = db.one("SELECT * FROM scan_results WHERE ip = '10.0.0.2'")
    assert row["hw_model"] == "U6-Lite" and row["firmware"] == "6.5.62" and row["vendor"] == "Ubiquiti"
    dev = db.one("SELECT * FROM devices WHERE hostname = '10.0.0.2'")
    assert dev["hw_model"] == "U6-Lite" and json.loads(dev["tags"]) == ["Ubiquiti"]


async def test_identify_existing_devices(db, make_device, monkeypatch):
    async def found(host, timeout=1.5):
        return Identity(vendor="Sonos, Inc.", model="Sonos One", source="upnp")
    monkeypatch.setattr(identify, "identify", found)
    make_device("speaker", "192.168.1.30", snmp_enabled=0)
    make_device("named", "speaker.lan", snmp_enabled=0)
    make_device("polled", "192.168.1.31")  # SNMP decides for this one
    assert await brands.identify_existing(db) == 1
    dev = db.one("SELECT * FROM devices WHERE name = 'speaker'")
    assert dev["vendor"] == "Sonos" and dev["hw_model"] == "Sonos One"
    assert brands.tag_all(db)["brands"] == {"Sonos": 1}
    assert await brands.identify_existing(db) == 0  # has a model now: not asked again


# ------------------------------------------------------------------ Wireshark's maker list
MANUF_TEXT = """# Wireshark manuf
00:00:0C\tCisco\tCisco Systems, Inc
F0:9F:C2\tUbiquiti\tUbiquiti Inc
00:55:DA\tIEEERegist\tIEEE Registration Authority
00:55:DA:10:00:00/28\tKoolPOS\tKoolPOS Inc.
00:1B:C5:00:00:00/36\tConvergi\tConverging Systems Inc.
00:1B:C5\tIEEERegist\tIEEE Registration Authority
0C:EA:14\tUbiquiti\tUbiquiti Inc
"""
MANUF_C = """static const manuf_registry_t ieee_registry_table[] = {
    { { 0x00, 0x1B, 0xC5 }, MA_S },
};
static const manuf_oui24_t global_manuf_oui24_table[] = {
    { { 0x0C, 0xEA, 0x14 }, "Ubiquiti",     "Ubiquiti Inc" },
    { { 0x00, 0x00, 0x0C }, "Cisco",        "Cisco Systems, Inc" },
    { { 0x00, 0x00, 0x99 }, "Quote",        "Say \\"hi\\" Ltd" },
};
static const manuf_oui28_t global_manuf_oui28_table[] = {
    { { 0x00, 0x55, 0xDA, 0x10 }, "KoolPOS",      "KoolPOS Inc." },
};
static const manuf_oui36_t global_manuf_oui36_table[] = {
    { { 0x00, 0x1B, 0xC5, 0x00, 0x00 }, "Convergi",     "Converging Systems Inc." },
};
"""


def test_parse_wireshark_formats():
    rows = macvendor.parse_manuf(MANUF_TEXT)
    assert (6, "0CEA14", "Ubiquiti", "Ubiquiti Inc") in rows
    assert (7, "0055DA1", "KoolPOS", "KoolPOS Inc.") in rows and (9, "001BC5000", "Convergi", "Converging Systems Inc.") in rows
    crows = macvendor.parse_manuf_c(MANUF_C)
    assert len(crows) == 5 and (6, "000099", "Quote", 'Say "hi" Ltd') in crows
    assert {r[1] for r in crows} >= {"0CEA14", "0055DA1", "001BC5000"}


@pytest.mark.network_ok
def test_wireshark_list_download_and_longest_match(tmp_path, monkeypatch):
    monkeypatch.setattr(macvendor, "MIN_ENTRIES", 3)
    macvendor.set_data_dir(tmp_path)
    try:
        assert macvendor.status()["source"] == "IEEE (bundled)"
        assert macvendor.vendor_for("0C:EA:14:00:00:01") == ""  # not in the old bundled list
        fetched = []

        def fetch(url):
            fetched.append(url)
            if "wireshark.org" in url:
                raise OSError("403 from a proxy")
            return MANUF_C
        status = macvendor.refresh_wireshark(fetch=fetch)
        assert status["source"] == "Wireshark" and status["entries"] == 5 and len(fetched) == 2
        assert macvendor.vendor_for("0C:EA:14:00:00:01") == "Ubiquiti Inc"
        assert macvendor.vendor_for("00:55:DA:1F:FF:FF") == "KoolPOS Inc."  # /28 block
        assert macvendor.vendor_for("00:1B:C5:00:00:0A") == "Converging Systems Inc."  # /36 block
        assert macvendor.vendor_for("00:1B:C5:00:10:00") == ""  # another /36 in that block: unknown
        assert macvendor.vendor_for("F0:9F:C2:00:00:01") == "Ubiquiti Inc"  # bundled list still used
        # Fresh: not downloaded again for a week; forced: it is.
        assert macvendor.refresh_wireshark(fetch=fetch) == status and len(fetched) == 2
        macvendor.refresh_wireshark(force=True, fetch=lambda url: MANUF_TEXT)
        assert macvendor.vendor_for("00:55:DA:10:00:00") == "KoolPOS Inc."
        # A broken download keeps the list we have.
        with pytest.raises(OSError):
            macvendor.refresh_wireshark(force=True, fetch=lambda url: "garbage")
        assert macvendor.vendor_for("0C:EA:14:00:00:01") == "Ubiquiti Inc"
        with gzip.open(tmp_path / macvendor.WIRESHARK_FILE, "rt") as fh:
            assert fh.readline().count("\t") == 3
    finally:
        macvendor.set_data_dir(None)


@pytest.mark.network_ok
def test_refresh_endpoint_reresolves_and_tags(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from snmpathy.app import create_app
    from snmpathy.config import Settings
    from snmpathy.db import Database

    monkeypatch.setattr(macvendor, "MIN_ENTRIES", 3)
    monkeypatch.setattr(macvendor, "fetch_wireshark", lambda fetch=None: macvendor.parse_manuf(MANUF_TEXT))
    settings = Settings(database=str(tmp_path / "api.db"), enable_syslog=False)
    db = Database(settings.database)
    macvendor.set_data_dir(tmp_path)
    try:
        with TestClient(create_app(settings, db=db, start_monitor=False)) as client:
            dev = client.post("/api/devices", json={"name": "ap", "hostname": "10.0.0.9", "snmp_enabled": False}).json()
            db.update("devices", dev["id"], {"mac": "0C:EA:14:00:00:01"})
            r = client.post("/api/system/maker-list/refresh").json()
            assert r["maker_list"]["source"] == "Wireshark" and r["changed"] == 1 and r["brands"] == {"Ubiquiti": 1}
            assert "Maker list: Wireshark" in client.get("/settings").text
    finally:
        macvendor.set_data_dir(None)
