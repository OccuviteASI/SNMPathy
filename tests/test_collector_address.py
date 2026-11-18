"""Collector setup codes carry an address the site can reach, not localhost."""

import pytest
from fastapi.testclient import TestClient

from snmpathy import collector_api, collector_app
from snmpathy.app import create_app
from snmpathy.config import Settings


@pytest.fixture
def make_client(tmp_path, db, monkeypatch):
    monkeypatch.setattr(collector_api, "lan_address", lambda: "192.168.1.10")
    clients = []

    def make(base_url="http://testserver", **settings):
        app = create_app(Settings(database=str(tmp_path / "t.db"), **settings), db=db, start_monitor=False)
        client = TestClient(app, base_url=base_url)
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for c in clients:
        c.__exit__(None, None, None)


def _created(client):
    return client.post("/api/collectors", json={"name": f"site {len(client.get('/api/collectors').json())}"}).json()


def test_localhost_becomes_the_servers_network_address(make_client):
    r = _created(make_client("http://localhost:8080"))
    assert r["server"] == "http://192.168.1.10:8080" and r["opened_on_server"] is True
    assert collector_app.decode_setup_code(r["install"]["app"])["server"] == "http://192.168.1.10:8080"
    assert "http://192.168.1.10:8080/collector/install.ps1" in r["install"]["windows"]
    assert "localhost" not in " ".join(r["install"].values())
    assert r["servers"][0] == "http://192.168.1.10:8080" and len(r["servers"]) == len(set(r["servers"]))
    assert all("localhost" not in s and "127.0.0.1" not in s for s in r["servers"])
    # A new token for an existing collector: the same.
    again = make_client("http://127.0.0.1:8080").post(f"/api/collectors/{r['id']}/token").json()
    assert collector_app.decode_setup_code(again["install"]["app"])["server"] == "http://192.168.1.10:8080"


def test_other_addresses_and_public_url_are_kept(make_client):
    r = _created(make_client("http://nms.lan:8080"))
    assert r["server"] == "http://nms.lan:8080" and r["opened_on_server"] is False
    assert "http://nms.lan:8080" in r["servers"]
    r = _created(make_client("http://localhost:8080", public_url="https://nms.example.com/"))
    assert collector_app.decode_setup_code(r["install"]["app"])["server"] == "https://nms.example.com"


def test_dialog_has_the_address_field(make_client):
    page = make_client("http://localhost:8080").get("/collectors").text
    assert 'id="tok-server"' in page and "SP.setupCode" in page


def test_collector_setup_can_correct_the_address():
    code = collector_app.encode_setup_code("http://localhost:8080", "col_abc")
    assert collector_app.resolve_setup(code)["server"] == "http://localhost:8080"
    assert collector_app.resolve_setup(code, "192.168.1.10:8080") == {
        "server": "http://192.168.1.10:8080", "token": "col_abc", "insecure": False}
    assert collector_app.resolve_setup(code, " https://nms.example.com/ ")["server"] == "https://nms.example.com"
    with pytest.raises(ValueError):
        collector_app.resolve_setup(code, "http://")
    hint = str(collector_app.unreachable("http://localhost:8080", OSError("refused")))
    assert "points at localhost" in hint and "Server address" in hint
    assert "points at" not in str(collector_app.unreachable("http://10.0.0.5:8080", OSError("refused")))


def test_check_server_explains_a_localhost_code(monkeypatch):
    import httpx

    def refuse(*a, **kw):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(collector_app, "_client", lambda *a, **kw: _Refusing())

    class _Refusing:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        get = staticmethod(refuse)

    with pytest.raises(RuntimeError, match="points at localhost"):
        collector_app.check_server("http://localhost:8080", "col_x")
