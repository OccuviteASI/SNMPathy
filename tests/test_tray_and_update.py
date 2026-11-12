import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from snmpathy import autostart, tray
from snmpathy.checks.probes import ProbeResult
from snmpathy.checks.runner import record_result
from snmpathy.services import create_check

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------- tray
def test_status_summary(db, make_device):
    assert tray.status_summary(db) == ("ok", "No devices yet")
    make_device("a", "10.0.0.1", snmp_enabled=0)
    dev = make_device("b", "10.0.0.2", snmp_enabled=0)
    assert tray.status_summary(db) == ("ok", "All 2 devices OK")
    check = create_check(db, {"device_id": dev["id"], "type": "icmp", "target": "10.0.0.2", "retries": 0})
    record_result(db, check, ProbeResult(False, None, "timeout"), now=10)
    state, text = tray.status_summary(db)
    assert state == "down" and text == "1 device down, 1 check down"


def test_icon_and_fallback(monkeypatch):
    pytest.importorskip("PIL.ImageDraw")
    assert tray.make_icon("ok").size == (64, 64)
    assert tray.make_icon("down", 32).getpixel((26, 5))[0] > 150  # red status dot in the corner
    monkeypatch.setattr(tray, "available", lambda: False)
    assert tray.run_tray(None) == 2  # caller falls back to the console server


def test_tray_command_falls_back_to_console(monkeypatch):
    from snmpathy import cli

    served = []
    monkeypatch.setattr(tray, "run_tray", lambda settings, open_browser=True: 2)
    monkeypatch.setattr(cli, "_run", lambda coro: served.append(coro) or coro.close())
    assert cli.main(["tray", "--db", ":memory:"]) == 0 and served


def test_autostart_prefers_tray_on_desktop_platforms(monkeypatch):
    monkeypatch.setattr(autostart, "_tray_available", lambda: True)
    assert autostart.launch_command()[-3:] == ["snmpathy", "tray", "--no-browser"]
    monkeypatch.setattr(autostart, "_tray_available", lambda: False)
    assert autostart.launch_command()[-1] == "serve"


# ------------------------------------------------------------------- update
@pytest.fixture
def update():
    spec = importlib.util.spec_from_file_location("update", ROOT / "scripts" / "update.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_needs_build(update):
    assert update.needs_build("", "abc1234")
    assert not update.needs_build("abc1234", "abc1234")
    assert not update.needs_build("abc1234+local changes".split("+")[0], "abc1234")
    assert update.needs_build("abc1234", "def5678")
    assert update.needs_build("abc1234", "abc1234", force=True)


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": __import__("os").environ["PATH"],
                        "HOME": str(cwd)})


@pytest.mark.skipif(not __import__("shutil").which("git"), reason="git not installed")
def test_pull_latest_fast_forwards(update, tmp_path, monkeypatch):
    origin, clone = tmp_path / "origin", tmp_path / "clone"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "a.txt").write_text("1")
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "one")
    _git(tmp_path, "clone", "-q", str(origin), str(clone))
    _git(clone, "checkout", "-qb", "work")       # not on main: the updater switches back
    (origin / "a.txt").write_text("2")
    _git(origin, "commit", "-qam", "two")
    monkeypatch.setattr(update, "ROOT", clone)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "none"))
    old, new = update.pull_latest()
    assert old != new and (clone / "a.txt").read_text() == "2"
    assert update.pull_latest()[0] == new          # second run: nothing new
    (clone / "a.txt").write_text("local edit")
    with pytest.raises(update.UpdateError, match="local changes"):
        update.pull_latest()


def test_up_to_date_install_is_left_alone(update, monkeypatch, tmp_path):
    build = type("B", (), {"resolve_destination": staticmethod(lambda d: tmp_path),
                           "main": staticmethod(lambda argv: pytest.fail("must not rebuild"))})
    monkeypatch.setattr(update, "pull_latest", lambda: ("abc1234", "abc1234"))
    monkeypatch.setattr(update, "load_build_module", lambda: build)
    monkeypatch.setattr(update, "installed_build", lambda exe: "abc1234")
    assert update.main([]) == 0


def test_update_stops_rebuilds_and_restarts(update, monkeypatch, tmp_path):
    calls = []
    build = type("B", (), {"resolve_destination": staticmethod(lambda d: tmp_path),
                           "main": staticmethod(lambda argv: calls.append(("build", argv)) or 0)})
    monkeypatch.setattr(update, "pull_latest", lambda: ("abc1234", "def5678"))
    monkeypatch.setattr(update, "load_build_module", lambda: build)
    monkeypatch.setattr(update, "installed_build", lambda exe: "abc1234")
    monkeypatch.setattr(update, "stop", lambda exe: calls.append("stop") or True)
    monkeypatch.setattr(update, "start", lambda exe: calls.append("start"))
    assert update.main([]) == 0
    assert calls == ["stop", ("build", ["--dest", str(tmp_path)]), "start"]


def test_schedule_commands(update, monkeypatch):
    runs = []
    monkeypatch.setattr(update.subprocess, "run",
                        lambda argv, **kw: runs.append((argv, kw.get("input"))) or subprocess.CompletedProcess(argv, 0, "", ""))
    monkeypatch.setattr(update, "IS_WINDOWS", True)
    update.schedule(True)
    argv = runs[-1][0]
    assert argv[:2] == ["schtasks", "/Create"] and "-WindowStyle Hidden" in argv[argv.index("/TR") + 1]
    monkeypatch.setattr(update, "IS_WINDOWS", False)
    update.schedule(True)
    assert "# SNMPathy update" in runs[-1][1] and "update.sh" in runs[-1][1]


def test_update_launcher_written_next_to_exe(tmp_path):
    spec = importlib.util.spec_from_file_location("build_executable", ROOT / "scripts" / "build_executable.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    path = build.write_update_launcher(tmp_path)
    text = path.read_text()
    assert ("update.cmd" if sys.platform.startswith("win") else "update.sh") in text
    assert str(ROOT) in text
