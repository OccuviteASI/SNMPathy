import time

import pytest
from fastapi.testclient import TestClient

from snmpathy.app import create_app
from snmpathy.checks.probes import ProbeResult
from snmpathy.config import Settings
from snmpathy.scanner import ScanManager, ScanOptions, TargetError, expand_targets, scan_host, suggest_name
from snmpathy.snmp import mibs
from snmpathy.snmp.client import FakeSnmpClient, SnmpError


def test_expand_targets():
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    assert expand_targets("10.0.0.254-10.0.1.1") == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]
    assert expand_targets("10.0.0.1, 10.0.0.1;sw1.example.com\nSW2") == ["10.0.0.1", "sw1.example.com", "sw2"]
    assert expand_targets("10.0.0.0/29", exclude="10.0.0.2-4") == ["10.0.0.1", "10.0.0.5", "10.0.0.6"]
    assert expand_targets("192.168.1.7/32") == ["192.168.1.7"]
    assert len(expand_targets("2001:db8::/126")) == 3
    for bad in ("10.0.0.0/8", "10.0.0.9-3", "10.0.0.300", "not a host!", "10.0.0.1-x"):
        with pytest.raises(TargetError):
            expand_targets(bad)
    with pytest.raises(TargetError):
        expand_targets("10.0.0.0/24", limit=100)


class Net:
    """A fake network: which hosts answer ping / TCP / SNMP (and with which community)."""

    def __init__(self):
        self.ping = {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
        self.tcp = {("10.0.0.4", 22)}
        self.snmp = {"10.0.0.1": "secret", "10.0.0.5": "public"}  # .5 drops ICMP but answers SNMP

    async def probe(self, check, device=None):
        if check["type"] == "icmp":
            return ProbeResult(check["target"] in self.ping, 1.5, "echo")
        if check["type"] == "tcp":
            return ProbeResult((check["target"], check["port"]) in self.tcp, 2.0, "connect")
        raise AssertionError(check)

    def client(self, target, cred, timeout):
        net = self

        class Client(FakeSnmpClient):
            async def get(self, oids):
                if net.snmp.get(target) != cred.get("snmp_community"):
                    raise SnmpError("timeout")
                return {mibs.SYS_DESCR: "Cisco IOS Software", mibs.SYS_OBJECT_ID: "1.3.6.1.4.1.9.1.1",
                        mibs.SYS_NAME: f"sw-{target.split('.')[-1]}"}
        return Client()


async def test_scan_host_variants():
    net = Net()
    opts = ScanOptions.from_dict({"communities": ["public", "secret"], "tcp_ports": [22], "resolve_dns": False})
    r = await scan_host("10.0.0.1", opts, net.probe, net.client)
    assert r["ping_ms"] == 1.5 and r["snmp"] == 1 and r["snmp_cred"] == 1 and r["vendor"] == "Cisco"
    assert r["sys_name"] == "sw-1"
    r = await scan_host("10.0.0.4", opts, net.probe, net.client)
    assert r["ping_ms"] is None and r["open_ports"] == [22] and not r["snmp"]
    r = await scan_host("10.0.0.5", opts, net.probe, net.client)
    assert r["snmp"] and r["snmp_cred"] == 0 and r["ping_ms"] is None
    assert await scan_host("10.0.0.9", opts, net.probe, net.client) is None
    # snmp_only_if_alive skips SNMP on silent hosts.
    quiet = ScanOptions.from_dict({"communities": ["public"], "snmp_only_if_alive": True, "resolve_dns": False})
    assert await scan_host("10.0.0.5", quiet, net.probe, net.client) is None


def test_suggest_name():
    assert suggest_name({"ip": "10.0.0.1", "sys_name": "core", "dns_name": "x"}) == "core"
    assert suggest_name({"ip": "10.0.0.1", "sys_name": "localhost", "dns_name": "web1.lan"}) == "web1.lan"
    assert suggest_name({"ip": "10.0.0.1", "sys_name": "", "dns_name": ""}) == "10.0.0.1"


async def test_scan_manager_auto_add(db, make_device):
    net = Net()
    make_device("existing", "10.0.0.2")
    manager = ScanManager(db, local_probe=net.probe, local_clients=net.client)
    scan = manager.create({"name": "lab", "targets": "10.0.0.1-6", "options": {
        "communities": ["public", "secret"], "tcp_ports": [22], "resolve_dns": False, "auto_add": "snmp",
        "tags": ["lab"], "avail_mode": "all"}})
    final = await manager.run(scan["id"])
    assert final["state"] == "done" and final["scanned"] == 6 and final["found"] == 5 and final["added"] == 2
    rows = {r["ip"]: r for r in db.query("SELECT * FROM scan_results")}
    assert rows["10.0.0.2"]["status"] == "existing"
    assert rows["10.0.0.1"]["status"] == "added" and rows["10.0.0.3"]["status"] == "new"
    dev = db.one("SELECT * FROM devices WHERE hostname = '10.0.0.1'")
    assert dev["name"] == "sw-1" and dev["snmp_community"] == "secret" and dev["vendor"] == "Cisco"
    assert dev["avail_mode"] == "all" and '"lab"' in dev["tags"]
    assert __import__("json").loads(dev["tags"]) == ["lab", "Cisco"]  # brand tagged as soon as it is added
    assert db.scalar("SELECT COUNT(*) FROM checks WHERE device_id = ?", (dev["id"],)) == 1  # it answered ping
    silent = db.one("SELECT * FROM devices WHERE hostname = '10.0.0.5'")
    assert db.scalar("SELECT COUNT(*) FROM checks WHERE device_id = ?", (silent["id"],)) == 0
    # Add one more by hand: a TCP-only host gets a TCP check so it has an availability source.
    added = manager.add(scan["id"], ips=["10.0.0.4"])
    tcp_dev = db.one("SELECT * FROM devices WHERE id = ?", (added[0]["device_id"],))
    assert not tcp_dev["snmp_enabled"]
    assert db.one("SELECT type, port FROM checks WHERE device_id = ?", (tcp_dev["id"],)) == {"type": "tcp", "port": 22}
    # Name clashes get the address appended.
    net.snmp["10.0.0.3"] = "public"
    db.execute("UPDATE scan_results SET sys_name = 'sw-1', snmp = 1, snmp_cred = 0 WHERE ip = '10.0.0.3'")
    assert manager.add(scan["id"], ips=["10.0.0.3"])
    assert db.one("SELECT name FROM devices WHERE hostname = '10.0.0.3'")["name"] == "sw-1 (10.0.0.3)"


async def test_recurring_scans_are_due(db):
    net = Net()
    manager = ScanManager(db, local_probe=net.probe, local_clients=net.client)
    scan = manager.create({"targets": "10.0.0.1", "interval": 3600, "options": {"resolve_dns": False}})
    assert scan["next_run"] > time.time()
    db.update("scans", scan["id"], {"next_run": time.time() - 1})
    assert await manager.run_due() == 1
    await manager.stop()


def test_scan_api(tmp_path, db):
    net = Net()
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False,
                     probe=net.probe, snmp_factory=lambda dev, s: net.client(dev["hostname"], dev, 1))
    with TestClient(app) as c:
        assert c.post("/api/scans/preview", json={"targets": "10.0.0.0/29"}).json()["count"] == 6
        assert c.post("/api/scans/preview", json={"targets": "10.0.0.0/8"}).status_code == 422
        r = c.post("/api/scans", json={"targets": "10.0.0.1-5", "options": {
            "communities": ["secret", "public"], "v3": [{"user": "mon", "auth_key": "authpass1"}], "resolve_dns": False}})
        assert r.status_code == 201, r.text
        scan_id = r.json()["id"]
        assert r.json()["options"]["v3"][0]["auth_key"] == "" and r.json()["options"]["v3"][0]["has_auth_key"]
        for _ in range(100):
            body = c.get(f"/api/scans/{scan_id}").json()
            if body["state"] == "done":
                break
            time.sleep(0.05)
        assert body["found"] == 5 and [r["ip"] for r in body["results"]][:2] == ["10.0.0.1", "10.0.0.2"]
        r = c.post(f"/api/scans/{scan_id}/add", json={"ips": ["10.0.0.1"]})
        assert r.json()["added"] == 1
        assert c.get("/api/devices").json()[0]["snmp_community"] == "secret"
        # Blank v3 passphrases on update keep the stored ones.
        c.patch(f"/api/scans/{scan_id}", json={"options": {"v3": [{"user": "mon", "auth_key": ""}]}})
        stored = db.one("SELECT options FROM scans WHERE id = ?", (scan_id,))["options"]
        assert "authpass1" in stored
        assert c.get("/scans").status_code == 200 and c.get(f"/scans/{scan_id}").status_code == 200
        assert c.delete(f"/api/scans/{scan_id}").status_code == 204


def test_edit_scan(tmp_path, db):
    net = Net()
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False,
                     probe=net.probe, snmp_factory=lambda dev, s: net.client(dev["hostname"], dev, 1))
    with TestClient(app) as c:
        scan = c.post("/api/scans", json={"name": "Home", "targets": "10.0.0.1-2", "start": False, "options": {
            "communities": ["public"], "tcp_ports": [22], "v3": [{"user": "mon", "auth_key": "authpass1"}],
            "resolve_dns": False}}).json()
        # the scan page carries a pre-filled edit form (passphrases blank, marked as kept)
        page = c.get(f"/scans/{scan['id']}").text
        assert "Edit scan" in page and 'value="Home"' in page and ">10.0.0.1-2</textarea>" in page
        assert 'value="22"' in page and "unchanged - leave blank to keep" in page and "authpass1" not in page
        assert f'href="/scans/{scan["id"]}?edit=1"' in c.get("/scans").text
        # save without running: settings change, nothing starts
        r = c.patch(f"/api/scans/{scan['id']}", json={
            "name": "Home LAN", "targets": "10.0.0.1-6", "interval": 86400, "start": False,
            "options": {"communities": ["home", "public"], "exclude": "10.0.0.6", "tcp_ports": [22, 443],
                        "v3": [{"user": "mon", "auth_key": ""}], "auto_add": "alive"}})
        assert r.status_code == 200, r.text
        body = r.json()
        assert (body["name"], body["total"], body["interval"], body["state"]) == ("Home LAN", 5, 86400, "idle")
        assert body["options"]["communities"] == ["home", "public"] and body["options"]["auto_add"] == "alive"
        assert "authpass1" in db.one("SELECT options FROM scans WHERE id = ?", (scan["id"],))["options"]
        # save & run now
        assert c.patch(f"/api/scans/{scan['id']}", json={"start": True}).json()["state"] in ("queued", "running", "done")
        for _ in range(100):
            if c.get(f"/api/scans/{scan['id']}").json()["state"] == "done":
                break
            time.sleep(0.05)
        assert c.get(f"/api/scans/{scan['id']}").json()["found"] >= 1
        assert c.patch(f"/api/scans/{scan['id']}", json={"targets": "10.0.0.0/8"}).status_code == 422
