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
    info = __import__("json").loads((tmp_path / "updater.json").read_text())
    assert info["gui"].endswith("update_gui.py") and Path(info["python"]).exists()


# ------------------------------------------------------------- progress window
@pytest.fixture
def gui():
    spec = importlib.util.spec_from_file_location("update_gui", ROOT / "scripts" / "update_gui.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TRANSCRIPT = """\
[update] checking https://github.com/OccuviteASI/SNMPathy.git for updates
[update] updated 96eed7e -> a5081a1 (2 new commit(s))
[update] installed build: 96eed7e; building a5081a1
[update] closing the running SNMPathy (pid 4120, 4188) so it can be replaced
[build] executable will be stored in C:\\Users\\me\\Claude\\SNMPathy
[build] using Python 3.12.4 (C:\\Python312\\python.exe)
[build] step 1/4: reusing build environment in C:\\src\\SNMPathy\\build\\venv
[build] build stamp: a5081a1, 2026-11-12
[build] step 2/4: installing SNMPathy and PyInstaller into the build environment (first run downloads ~60 MB)
[build] step 3/4: running PyInstaller (this takes a minute or two)
123 INFO: PyInstaller: 6.11.1
456 INFO: Building EXE from EXE-00.toc completed successfully.
[build] step 4/4: checking the executable starts
[build] smoke test ok: snmpathy 0.6.0 (build a5081a1, 2026-11-12)
[build] BUILD OK: C:\\Users\\me\\Claude\\SNMPathy\\SNMPathy.exe (31 MB)
[update] starting C:\\Users\\me\\Claude\\SNMPathy\\SNMPathy.exe
[update] UPDATE OK: SNMPathy is now build a5081a1
"""


def test_progress_follows_the_update_output(gui):
    percent, seen, outcome = 0, [], None
    for line in TRANSCRIPT.splitlines():
        new, status, result = gui.parse_line(line, percent)
        assert new >= percent  # never goes backwards
        percent, outcome = new, result or outcome
        if status:
            seen.append(status)
    assert percent == 100 and outcome == "ok"
    assert seen[0] == "Checking for updates…" and "Closing SNMPathy…" in seen
    assert "Building SNMPathy (a minute or two)…" in seen
    assert seen[-1] == "SNMPathy is up to date (build a5081a1)."


def test_progress_reports_failures_and_no_op(gui):
    assert gui.parse_line("[update] UPDATE FAILED: the source folder has local changes; commit them", 10) == (
        10, "Update failed: the source folder has local changes; commit them", "failed")
    assert gui.parse_line("[build] BUILD FAILED while running: pip install ... (exit code 1)", 30)[2] == "failed"
    pct, status, outcome = gui.parse_line(
        "[update] SNMPathy in C:\\x is already build a5081a1: nothing to do", 10)
    assert (pct, outcome) == (100, "current") and "a5081a1" in status
    # PyInstaller chatter creeps forward inside its stage but never past it
    pct = 50
    for _ in range(100):
        pct = gui.parse_line("INFO: Analyzing hidden import", pct)[0]
    assert pct == 85


def test_update_runs_without_a_console(gui, monkeypatch):
    cmd = gui.update_command(["--dest", "X"])
    assert cmd[1:3] == ["-u", str(ROOT / "scripts" / "update.py")] and "--from-tray" in cmd and cmd[-2:] == ["--dest", "X"]
    monkeypatch.setattr(gui.sys, "executable", str(ROOT / "pythonw.exe"))
    assert gui.console_python().endswith("pythonw.exe")  # no python.exe next to it: keep what we have


def test_only_one_update_at_a_time(update, tmp_path, monkeypatch):
    monkeypatch.setattr(update, "LOCK_FILE", tmp_path / "update.lock")
    assert update.acquire_lock() and not update.acquire_lock()
    update.release_lock()
    assert update.acquire_lock()
    old = __import__("time").time() - update.LOCK_STALE - 10
    __import__("os").utime(tmp_path / "update.lock", (old, old))  # left behind by a crash
    assert update.acquire_lock()
    monkeypatch.setattr(update, "acquire_lock", lambda: False)
    monkeypatch.setattr(update, "pull_latest", lambda: pytest.fail("must not run"))
    assert update.main([]) == 3


def test_restarted_app_does_not_inherit_the_progress_pipe(update, monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(update.subprocess, "Popen", lambda argv, **kw: seen.update(kw))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    update.start(tmp_path / "SNMPathy")
    assert seen["stdout"] is subprocess.DEVNULL and seen["stderr"] is subprocess.DEVNULL


def test_tray_opens_the_progress_window(monkeypatch, tmp_path):
    monkeypatch.setattr(tray, "app_dir", lambda: tmp_path)
    assert tray.updater_command() is None and not tray.update_available()
    gui_script = tmp_path / "src" / "scripts" / "update_gui.py"
    gui_script.parent.mkdir(parents=True)
    gui_script.write_text("")
    (tmp_path / "updater.json").write_text(__import__("json").dumps(
        {"python": sys.executable, "gui": str(gui_script), "source": str(tmp_path / "src")}))
    cmd = tray.updater_command()
    assert cmd == [sys.executable, str(gui_script), "--dest", str(tmp_path)] and tray.update_available()
    launched = []
    monkeypatch.setattr(tray.subprocess, "Popen", lambda argv, **kw: launched.append((argv, kw)))
    tray.TrayApp.__new__(tray.TrayApp).run_update()
    argv, kw = launched[0]
    assert argv == cmd and kw["stdout"] is subprocess.DEVNULL and kw["cwd"] == tmp_path / "src"


def test_error_lines_are_recognised(gui):
    assert gui.error_line("ERROR: Could not install packages due to an OSError: [WinError 5] Access is denied")
    assert gui.error_line("fatal: unable to access 'https://github.com/': Could not resolve host")
    assert gui.error_line("PermissionError: [Errno 13] Permission denied: 'SNMPathy.exe'")
    assert not gui.error_line("[build] BUILD FAILED while running: pip install")
    assert not gui.error_line("123 INFO: Building EXE")
