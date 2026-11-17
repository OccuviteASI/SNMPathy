"""SNMPathy Collector: setup codes, the Full-server choice (download + Fusion), downloads."""

import pytest
from fastapi.testclient import TestClient

from snmpathy import collector_app, collectors
from snmpathy.app import create_app
from snmpathy.config import Settings

ADMIN = {"Authorization": "Bearer admintoken"}


@pytest.fixture(autouse=True)
def _keep_full_app_profile(monkeypatch):
    """collector_app.main() switches autostart and self-update to the Collector: undo it after each test."""
    from snmpathy import autostart, selfupdate

    for name in ("APP_ID", "MAC_LABEL", "LINUX_UNIT", "VBS_NAME", "DESKTOP_NAME", "APP_TITLE", "LAUNCH"):
        monkeypatch.setattr(autostart, name, getattr(autostart, name))
    monkeypatch.setattr(selfupdate, "PRODUCT", selfupdate.PRODUCT)


@pytest.fixture
def server(tmp_path, db):
    app = create_app(Settings(database=str(tmp_path / "t.db"), api_token="admintoken"), db=db, start_monitor=False)
    with TestClient(app) as c:
        yield c


def test_setup_code_roundtrip_and_errors():
    code = collector_app.encode_setup_code("https://nms.example:8443/", "col_abc123")
    assert code.startswith("SNMPATHY-SETUP-1:")
    assert collector_app.decode_setup_code(code) == {"server": "https://nms.example:8443", "token": "col_abc123",
                                                     "insecure": False}
    # Pasted with line breaks or spaces: still fine.
    assert collector_app.decode_setup_code(" " + code[:20] + "\n" + code[20:] + " ")["token"] == "col_abc123"
    assert collector_app.decode_setup_code(collector_app.encode_setup_code("http://a", "t", True))["insecure"]
    for bad in ("", "col_abc", "SNMPATHY-SETUP-1:", "SNMPATHY-SETUP-1:bm9wZQ", code[:-6]):
        with pytest.raises(ValueError):
            collector_app.decode_setup_code(bad)


def test_config_written_by_setup_runs_the_agent(tmp_path):
    path = collector_app.save_config("http://nms:8080", "col_x", insecure=True, path=tmp_path / "collector.yaml")
    conf = collector_app.load_config(str(path))
    agent = collector_app.make_agent(conf, state_dir=str(tmp_path / "state"))
    assert agent.server == "http://nms:8080" and agent.token == "col_x" and agent.verify is False
    with pytest.raises(RuntimeError):
        collector_app.make_agent({})


def test_console_mode_without_server_says_how(capsys, tmp_path, monkeypatch):
    monkeypatch.delenv("SNMPATHY_COLLECTOR_SERVER", raising=False)
    monkeypatch.delenv("SNMPATHY_COLLECTOR_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    assert collector_app.main(["collector"]) == 2
    assert "setup" in capsys.readouterr().err
    assert collector_app.main(["version"]) == 0
    assert "snmpathy-collector" in capsys.readouterr().out
    from snmpathy import autostart, selfupdate

    assert selfupdate.asset_name("win32") == "SNMPathy-Collector-windows.exe"
    assert autostart.APP_ID == "SNMPathy Collector" and autostart.launch_command()[-1] == "snmpathy.collector_app"


def test_setup_code_offered_when_a_collector_is_added(server):
    created = server.post("/api/collectors", json={"name": "Branch C"}, headers=ADMIN).json()
    info = collector_app.decode_setup_code(created["install"]["app"])
    assert info == {"server": "http://testserver", "token": created["token"], "insecure": False}
    rotated = server.post(f"/api/collectors/{created['id']}/token", headers=ADMIN).json()
    assert collector_app.decode_setup_code(rotated["install"]["app"])["token"] == rotated["token"]
    page = server.get("/collectors", headers=ADMIN).text
    assert "tok-setup" in page and "SNMPathy-Collector-windows.exe" in page


def test_check_server_rejects_a_bad_token(server, monkeypatch):
    monkeypatch.setattr(collector_app, "_client", lambda url, insecure, token="": _as_client(server, token))
    with pytest.raises(RuntimeError, match="token"):
        collector_app.check_server("http://testserver", "col_nope")
    _, token = collectors.create_collector(server.app.state.db, "Site")
    collector_app.check_server("http://testserver", token)


def _as_client(server, token=""):
    """The collector setup's HTTP client, pointed at the test server."""
    server.headers.pop("Authorization", None)
    if token:
        server.headers["Authorization"] = f"Bearer {token}"
    return _NoClose(server)


class _NoClose:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *exc):
        return False


def test_enroll_replaces_the_collector_with_a_fusion_server(server, db, make_device):
    col, token = collectors.create_collector(db, "Branch D")
    device = make_device("sw-d", "10.4.0.1", collector_id=col["id"])
    auth = {"Authorization": f"Bearer {token}"}
    assert server.post("/api/collector/v1/enroll", json={"port": 8081}).status_code == 401
    db.insert("fusion_servers", {"name": "branch-pc", "url": "http://10.9.9.9:8080", "created_at": 1})
    r = server.post("/api/collector/v1/enroll", json={"name": "branch-pc", "port": 8081}, headers=auth)
    assert r.status_code == 200
    row = db.one("SELECT * FROM fusion_servers WHERE id = ?", (r.json()["id"],))
    assert row["name"] == "branch-pc (2)" and row["url"] == "http://testclient:8081" and row["enabled"] == 1
    # The collector is gone (its token with it) and its devices are monitored from here again.
    assert db.one("SELECT 1 FROM collectors WHERE id = ?", (col["id"],)) is None
    assert db.one("SELECT collector_id FROM devices WHERE id = ?", (device["id"],))["collector_id"] is None
    assert server.post("/api/collector/v1/enroll", json={"port": 8081}, headers=auth).status_code == 401
    assert db.scalar("SELECT COUNT(*) FROM events WHERE type = 'fusion.added'") == 1


def test_downloads_prefer_the_collector_app(server, tmp_path):
    items = server.get("/collector/downloads").json()
    assert [i["kind"] for i in items][:2] == ["collector", "collector"]
    assert {i["name"] for i in items if i["kind"] == "collector"} == {"SNMPathy-Collector-windows.exe",
                                                                      "SNMPathy-Collector-linux"}
    # Not fetched (no network in tests) and nothing else for Windows: 404 / 502.
    assert server.get("/collector/download/auto?os_=Windows").status_code == 404
    assert server.get("/collector/download/SNMPathy-Collector-windows.exe").status_code == 502
    assert server.get("/collector/download/server?os_=Windows").status_code == 404
    folder = tmp_path / "downloads"
    folder.mkdir()
    (folder / "SNMPathy-windows.exe").write_bytes(b"full")
    (folder / "SNMPathy-Collector-windows.exe").write_bytes(b"small")
    assert server.get("/collector/download/auto?os_=Windows").content == b"small"
    assert server.get("/collector/download/server?os_=Windows_NT").content == b"full"
    names = [i["name"] for i in server.get("/collector/downloads").json()]
    assert names.index("SNMPathy-Collector-windows.exe") < names.index("SNMPathy-windows.exe")


def test_fetched_release_files_are_kept(server, tmp_path, monkeypatch):
    from snmpathy import collector_api

    fetched = []

    def fake_fetch(name, folder):
        fetched.append(name)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(b"from github")
        return folder / name

    monkeypatch.setattr(collector_api, "fetch_release_asset", fake_fetch)
    assert server.get("/collector/download/auto?os_=Linux").content == b"from github"
    assert server.get("/collector/download/auto?os_=Linux").content == b"from github"
    assert fetched == ["SNMPathy-Collector-linux"]  # the second one came from the downloads folder


def test_full_server_setup_downloads_starts_and_joins_fusion(server, db, tmp_path, monkeypatch):
    import subprocess

    col, token = collectors.create_collector(db, "Branch E")
    folder = tmp_path / "downloads"
    folder.mkdir()
    exe_name = collector_app.full_exe_name()
    plat = "windows.exe" if exe_name.endswith(".exe") else "linux"
    (folder / f"SNMPathy-{plat}").write_bytes(b"the full snmpathy")
    monkeypatch.setattr(collector_app, "_client", lambda url, insecure, token="": _as_client(server, token))
    monkeypatch.setattr("snmpathy.webport.pick_port", lambda host, preferred, tries=20: 8090)
    started, ran, walls = [], [], []
    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kw: started.append(argv))
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: ran.append(argv))
    monkeypatch.setattr("snmpathy.firewall.apply", lambda settings, groups: walls.append((settings.http_port, groups)))
    site = tmp_path / "site"
    (site).mkdir()
    (site / "snmpathy.yaml").write_text("http_port: 8080\nsite_name: x\n")
    said = []
    done = collector_app.install_full_server("http://testserver", token, folder=site, say=said.append)
    exe = site / exe_name
    assert exe.read_bytes() == b"the full snmpathy" and done["port"] == 8090
    assert (site / "snmpathy.yaml").read_text() == "http_port: 8090\nsite_name: x\n"
    assert walls == [(8090, ["web"])]
    assert ran == [[str(exe), "autostart", "on"]] and started == [[str(exe)]]
    row = db.one("SELECT * FROM fusion_servers")
    assert row["url"] == "http://testclient:8090" and done["fusion"]["id"] == row["id"]
    assert db.one("SELECT 1 FROM collectors WHERE id = ?", (col["id"],)) is None
    assert any("Fusion" in s for s in said)


def test_collector_app_imports_no_web_stack():
    import subprocess
    import sys

    code = ("import sys, snmpathy.collector_app, snmpathy.collector_agent, snmpathy.tray, snmpathy.selfupdate, "
            "snmpathy.identify, snmpathy.snmp.arp, snmpathy.macvendor, snmpathy.brands, snmpathy.scanner, "
            "snmpathy.services, snmpathy.snmp.discovery, snmpathy.firewall, snmpathy.autostart\n"
            "bad = sorted({m.split('.')[0] for m in sys.modules} & {'fastapi', 'uvicorn', 'starlette', 'jinja2', "
            "'pydantic'})\nprint(bad)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip() == "[]", out.stderr
