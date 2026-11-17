"""Collectors update themselves to their server's version."""

import asyncio
import contextlib
import sys

import pytest
from fastapi.testclient import TestClient

from snmpathy import __version__, collector_api, collector_update, collectors, selfupdate
from snmpathy.app import create_app
from snmpathy.collector_agent import CollectorAgent
from snmpathy.config import Settings

POSIX = not sys.platform.startswith("win")


@pytest.fixture
def server(tmp_path, db):
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _full_app_product(monkeypatch):
    monkeypatch.setattr(selfupdate, "PRODUCT", selfupdate.PRODUCT)


class _Agent:
    def __init__(self, server_version="", server="http://testserver"):
        self.server_version, self.server, self.verify = server_version, server, True
        self.handed = 0

    def hand_over(self):
        self.handed += 1


def test_only_a_newer_server_version_counts():
    assert collector_update.newer_server_version(_Agent("0.7.14"), "0.7.13") == "0.7.14"
    assert collector_update.newer_server_version(_Agent("0.8.0"), "0.7.13") == "0.8.0"
    for same_or_older in ("0.7.13", "0.7.9", "", "dev"):
        assert collector_update.newer_server_version(_Agent(same_or_older), "0.7.13") == ""


def test_it_is_on_for_executables_unless_turned_off(monkeypatch):
    assert not collector_update.enabled({})  # running from Python: pip updates it
    monkeypatch.setattr("snmpathy.config.is_frozen", lambda: True)
    assert collector_update.enabled({}) and collector_update.enabled({"auto_update": True})
    assert not collector_update.enabled({"auto_update": False}) and not collector_update.enabled({"auto_update": "no"})


def test_each_program_downloads_its_own_build(monkeypatch):
    monkeypatch.setattr(collector_update, "IS_WINDOWS", True)
    assert collector_update.download_path() == ("/collector/download/server", {"os_": "Windows"})
    monkeypatch.setattr(selfupdate, "PRODUCT", "SNMPathy-Collector")
    monkeypatch.setattr(sys, "platform", "win32")
    assert collector_update.download_path() == ("/collector/download/SNMPathy-Collector-windows.exe", {})


def _through(server, monkeypatch):
    """collector_update's HTTP client, pointed at the test server."""
    import httpx

    @contextlib.contextmanager
    def client(**kw):
        yield server

    monkeypatch.setattr(httpx, "Client", client)


@pytest.mark.skipif(not POSIX, reason="uses shell scripts as executables")
def test_update_downloads_from_the_server_checks_and_swaps(server, tmp_path, monkeypatch):
    monkeypatch.setattr(selfupdate, "PRODUCT", "SNMPathy-Collector")
    monkeypatch.setattr(sys, "platform", "linux")
    folder = tmp_path / "downloads"
    folder.mkdir()
    build = folder / "SNMPathy-Collector-linux"
    exe = tmp_path / "site" / "SNMPathy-Collector"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\necho 'snmpathy-collector 0.0.1'\n")
    exe.chmod(0o755)
    _through(server, monkeypatch)

    # The server's build is not newer: nothing changes.
    build.write_text("#!/bin/sh\necho 'snmpathy-collector 0.0.1'\n")
    with pytest.raises(RuntimeError, match="not newer"):
        collector_update.update(_Agent("99.0.0"), "99.0.0", exe=exe)
    assert "0.0.1" in exe.read_text() and not exe.with_name(exe.name + ".new").exists()

    build.write_text("#!/bin/sh\necho 'snmpathy-collector 99.0.0 (build abc)'\n")
    assert collector_update.update(_Agent("99.0.0"), "99.0.0", exe=exe) == exe
    assert "99.0.0" in exe.read_text() and selfupdate.old_path(exe).exists()

    # Nothing to download: a clear error.
    build.unlink()
    monkeypatch.setattr(collector_api, "fetch_release_asset", lambda name, folder: (_ for _ in ()).throw(OSError("x")))
    with pytest.raises(RuntimeError, match="no build"):
        collector_update.update(_Agent("100.0.0"), "100.0.0", exe=exe)


async def test_loop_updates_once_and_hands_over():
    agent, restarted, updates = _Agent("99.0.0"), [], []

    def fake_update(a, version):
        updates.append(version)
        return "exe"

    await asyncio.wait_for(collector_update.auto_update_loop(
        agent, {}, on_restart=lambda: restarted.append(1), first=0, every=0.01, do_update=fake_update,
        do_relaunch=lambda exe: True), 2)
    assert updates == ["99.0.0"] and agent.handed == 1 and restarted == [1]


async def test_failed_update_is_not_retried_at_once():
    agent, calls = _Agent("99.0.0"), []

    def broken(a, version):
        calls.append(version)
        raise RuntimeError("server unreachable")

    task = asyncio.create_task(collector_update.auto_update_loop(
        agent, {}, on_restart=lambda: None, first=0, every=0.01, do_update=broken, do_relaunch=lambda exe: True))
    await asyncio.sleep(0.2)
    task.cancel()
    assert calls == ["99.0.0"] and agent.handed == 0  # next try after RETRY_AFTER
    # Not newer: never tried.
    calls.clear()
    agent.server_version = __version__
    task = asyncio.create_task(collector_update.auto_update_loop(
        agent, {}, first=0, every=0.01, do_update=broken, do_relaunch=lambda exe: True))
    await asyncio.sleep(0.1)
    task.cancel()
    assert calls == []


def test_agent_hands_over_its_buffer(tmp_path):
    agent = CollectorAgent("http://x", "col_x", state_dir=tmp_path)
    agent.outbox.extend([{"kind": "poll", "n": 1}, {"kind": "poll", "n": 2}])
    agent.hand_over()
    assert len(agent.outbox) == 0 and len(agent.spool.read_text().splitlines()) == 2
    agent._save_spool()  # stopping afterwards must not touch the new copy's buffer
    assert len(agent.spool.read_text().splitlines()) == 2
    assert CollectorAgent("http://x", "col_x", state_dir=tmp_path).outbox  # the new copy replays it


def test_server_keeps_release_builds_per_version(tmp_path, monkeypatch):
    import httpx

    fetched = []

    @contextlib.contextmanager
    def fake_stream(method, url, **kw):
        fetched.append(url)

        class R:
            status_code = 200

            def iter_bytes(self, n):
                yield b"build of " + url.encode()
        yield R()

    monkeypatch.setattr(httpx, "stream", fake_stream)
    stale = tmp_path / "releases" / "v0.0.1"
    stale.mkdir(parents=True)
    (stale / "SNMPathy-Collector-linux").write_text("old")
    path = collector_api._fetch_release_asset("SNMPathy-Collector-linux", tmp_path)
    assert path.parent.name == f"v{__version__}" and f"v{__version__}" in fetched[0]
    assert not stale.exists()  # the old version's files are removed
    assert collector_api._fetch_release_asset("SNMPathy-Collector-linux", tmp_path) == path and len(fetched) == 1


def test_collectors_page_flags_older_collectors(server, db):
    old, _ = collectors.create_collector(db, "Old site")
    new, _ = collectors.create_collector(db, "New site")
    db.update("collectors", old["id"], {"version": "0.7.10 (build abc, 2026-11-01)"})
    db.update("collectors", new["id"], {"version": f"{__version__} (build def)"})
    page = server.get("/collectors").text
    assert page.count("older than this server") == 1
