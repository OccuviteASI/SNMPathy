import importlib.util
import json
import os
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
    (gui_script.parent / "update.py").write_text("")
    (tmp_path / "updater.json").write_text(__import__("json").dumps(
        {"python": sys.executable, "gui": str(gui_script), "source": str(tmp_path / "src")}))
    cmd = tray.updater_command()
    assert cmd == [sys.executable, str(gui_script), "--dest", str(tmp_path)] and tray.update_available()
    launched = []
    monkeypatch.setattr(tray.subprocess, "Popen", lambda argv, **kw: launched.append((argv, kw)))
    tray.TrayApp.__new__(tray.TrayApp).run_update()
    argv, kw = launched[0]
    assert argv == cmd and kw["stdout"] is subprocess.DEVNULL and kw["cwd"] == tmp_path / "src"


def _fake_source(path):
    (path / "scripts").mkdir(parents=True)
    for name in ("update_gui.py", "update.py", "update.cmd"):
        (path / "scripts" / name).write_text("")
    return path


def test_copy_from_another_computer_finds_or_downloads_the_source(monkeypatch, tmp_path):
    """updater.json and the .cmd name paths from the computer that built this copy (a synced Desktop)."""
    app = tmp_path / "Desktop" / "SNMPathy"
    app.mkdir(parents=True)
    other = "C:/Users/someone-else/Claude/SNMPathy-src"
    (app / "updater.json").write_text(json.dumps({"python": other + "/python.exe", "gui": other + "/scripts/update_gui.py",
                                                  "source": other, "remote": "https://example.invalid/SNMPathy.git"}))
    (app / "Update SNMPathy.cmd").write_text(f'@echo off\r\ncall "{other}/scripts/update.cmd" %*\r\n')
    home = tmp_path / "local" / "source"
    monkeypatch.setattr(tray, "app_dir", lambda: app)
    monkeypatch.setattr(tray, "source_home", lambda: home)
    monkeypatch.setattr(tray.shutil, "which", lambda name: sys.executable if name.startswith("python") else
                        ("/usr/bin/git" if name == "git" else None))
    # Recorded paths do not exist here: no broken console script, Python found on PATH instead.
    assert tray.update_launcher() is None and tray.updater_command() is None
    python = tray.find_python()
    assert Path(python[0]).parent == Path(sys.executable).parent and tray.missing_for_update() == []

    clones, launched = [], []
    monkeypatch.setattr(tray, "clone_source", lambda remote, dest: (clones.append((remote, dest)), _fake_source(dest))
                        and (True, ""))
    monkeypatch.setattr(tray.subprocess, "Popen", lambda argv, **kw: launched.append((argv, kw)))
    app_obj = tray.TrayApp.__new__(tray.TrayApp)
    app_obj.notify = lambda msg: None
    app_obj._fetch_source_then_update()
    assert clones == [("https://example.invalid/SNMPathy.git", home)]
    argv, kw = launched[0]
    assert argv == [*python, str(home / "scripts" / "update_gui.py"), "--dest", str(app)] and kw["cwd"] == home


def test_update_explains_what_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(tray, "app_dir", lambda: tmp_path)
    monkeypatch.setattr(tray, "source_home", lambda: tmp_path / "nowhere")
    monkeypatch.setattr(tray.shutil, "which", lambda name: None)
    monkeypatch.setattr(tray, "find_python", lambda info=None: None)
    shown, launched = [], []
    monkeypatch.setattr(tray, "show_message", lambda text, title="": shown.append(text))
    monkeypatch.setattr(tray.subprocess, "Popen", lambda argv, **kw: launched.append(argv))
    assert tray.missing_for_update() == ['Python 3 (python.org - tick "Add python.exe to PATH")', "Git (git-scm.com)"]
    tray.TrayApp.__new__(tray.TrayApp).run_update()
    assert not launched and "Python 3" in shown[0] and "Git" in shown[0]


def test_found_source_next_to_the_executable(monkeypatch, tmp_path):
    src = _fake_source(tmp_path / "SNMPathy-src")
    (src / "dist").mkdir()
    monkeypatch.setattr(tray, "app_dir", lambda: src / "dist")
    monkeypatch.setattr(tray, "source_home", lambda: tmp_path / "nowhere")
    assert tray.find_source() == src


def test_error_lines_are_recognised(gui):
    assert gui.error_line("ERROR: Could not install packages due to an OSError: [WinError 5] Access is denied")
    assert gui.error_line("fatal: unable to access 'https://github.com/': Could not resolve host")
    assert gui.error_line("PermissionError: [Errno 13] Permission denied: 'SNMPathy.exe'")
    assert not gui.error_line("[build] BUILD FAILED while running: pip install")
    assert not gui.error_line("123 INFO: Building EXE")


class _FakeRoot:
    """Just enough of a Tk root to drive UpdateWindow.finish() without a display."""
    def __init__(self):
        self.timers, self.destroyed, self.title_text, self._state = {}, False, "", "normal"

    def after(self, ms, fn):
        key = len(self.timers) + 1
        self.timers[key] = fn
        return key

    def after_cancel(self, key):
        self.timers.pop(key, None)

    def destroy(self):
        self.destroyed = True

    def state(self):
        return self._state

    def title(self, text):
        self.title_text = text

    def tick(self):  # run the pending timer, like one second passing
        key = max(self.timers)
        self.timers.pop(key)()


def _window(gui, outcome):
    w = gui.UpdateWindow.__new__(gui.UpdateWindow)
    w.root, w.close_timer, w.details_shown, w.outcome = _FakeRoot(), None, False, outcome
    w.running, w.last_error, w.lines = True, "", []
    w.close_btn, w.title, w.status, w.bar = {}, {}, {}, {}
    w.add_log = lambda line: w.lines.append(line)
    w.toggle_details = lambda: (w.cancel_countdown(), setattr(w, "details_shown", not w.details_shown))
    return w


def test_update_window_closes_itself_after_success(gui):
    w = _window(gui, "ok")
    w.finish(0)
    assert w.close_btn["text"] == f"Close ({gui.AUTO_CLOSE_SECONDS})" and not w.root.destroyed
    for _ in range(gui.AUTO_CLOSE_SECONDS):
        w.root.tick()
    assert w.root.destroyed


def test_update_window_stays_open_on_failure_or_when_reading(gui):
    failed = _window(gui, None)
    failed.finish(1)
    assert failed.outcome == "failed" and not failed.root.timers and not failed.root.destroyed
    reading = _window(gui, "current")
    reading.finish(0)
    reading.root.tick()
    assert reading.close_btn["text"] == f"Close ({gui.AUTO_CLOSE_SECONDS - 1})"
    reading.toggle_details()  # opened the log: the countdown stops
    assert reading.close_btn["text"] == "Close" and not reading.root.timers and not reading.root.destroyed


def test_double_clicked_exe_restarts_without_its_console(monkeypatch):
    launched = []
    monkeypatch.setattr(tray.subprocess, "Popen", lambda argv, **kw: launched.append((argv, kw)))
    monkeypatch.delenv(tray.DETACHED_ENV, raising=False)
    monkeypatch.setattr(tray, "own_console", lambda: True)
    monkeypatch.setattr(tray, "is_frozen", lambda: False)
    assert not tray.relaunch_detached() and not launched  # running from Python: leave it
    monkeypatch.setattr(tray, "is_frozen", lambda: True)
    monkeypatch.setattr(tray.sys, "argv", ["SNMPathy.exe"])
    assert tray.relaunch_detached()
    argv, kw = launched[0]
    assert argv == [sys.executable] and kw["env"][tray.DETACHED_ENV] == "1" and kw["stdout"] is subprocess.DEVNULL
    # The relaunched copy, or one started from a terminal / without a window, stays put.
    monkeypatch.setenv(tray.DETACHED_ENV, "1")
    assert not tray.relaunch_detached()
    monkeypatch.delenv(tray.DETACHED_ENV)
    monkeypatch.setattr(tray, "own_console", lambda: False)
    assert not tray.relaunch_detached() and len(launched) == 1


def test_own_console_is_windows_only():
    if not sys.platform.startswith("win"):
        assert tray.own_console() is False


def test_self_env_gives_a_restarted_executable_its_own_files(tmp_path):
    from snmpathy.procutil import RESET, self_env

    mei = str(tmp_path / "_MEI1234")
    base = {"PATH": os.pathsep.join([mei, "/usr/bin"]), "_PYI_APPLICATION_HOME_DIR": mei,
            "_PYI_ARCHIVE_FILE": "/opt/SNMPathy", "_PYI_PARENT_PROCESS_LEVEL": "1", "_MEIPASS2": mei,
            "TCL_LIBRARY": os.path.join(mei, "_tcl_data"), "TK_LIBRARY": os.path.join(mei, "_tk_data"),
            "LD_LIBRARY_PATH": mei, "LD_LIBRARY_PATH_ORIG": "/usr/local/lib", "HOME": "/home/me",
            "LOCALAPPDATA": "C:/Users/me/AppData/Local"}
    env = self_env({"SNMPATHY_DETACHED": "1"}, base=base, meipass=mei, frozen=True)
    assert env[RESET] == "1" and env["SNMPATHY_DETACHED"] == "1"
    assert not [k for k in env if k.startswith("_PYI_") or k == "_MEIPASS2"]
    assert "TCL_LIBRARY" not in env and "TK_LIBRARY" not in env
    assert env["PATH"] == "/usr/bin" and env["LD_LIBRARY_PATH"] == "/usr/local/lib"
    assert "LD_LIBRARY_PATH_ORIG" not in env and env["HOME"] == "/home/me"
    # Without a saved original, only this copy's folder is dropped from LD_LIBRARY_PATH.
    env = self_env(base={"LD_LIBRARY_PATH": mei}, meipass=mei, frozen=True)
    assert "LD_LIBRARY_PATH" not in env
    # Running from Python: untouched.
    assert self_env({"A": "1"}, base={"TCL_LIBRARY": "/x"}, frozen=False) == {"TCL_LIBRARY": "/x", "A": "1"}


def test_self_launches_use_the_clean_environment(monkeypatch):
    from snmpathy import procutil, selfupdate

    monkeypatch.setattr(procutil, "self_env", lambda extra=None, **kw: {"CLEAN": "1", **(extra or {})})
    launched = []
    monkeypatch.setattr(tray.subprocess, "Popen", lambda argv, **kw: launched.append((argv, kw)))
    monkeypatch.delenv(tray.DETACHED_ENV, raising=False)
    monkeypatch.setattr(tray, "own_console", lambda: True)
    monkeypatch.setattr(tray, "is_frozen", lambda: True)
    assert tray.relaunch_detached()
    assert launched[-1][1]["env"] == {"CLEAN": "1", tray.DETACHED_ENV: "1"}
    tray.TrayApp.__new__(tray.TrayApp).run_update()
    assert launched[-1][0][1:] == ["self-update", "--gui"] and launched[-1][1]["env"] == {"CLEAN": "1"}
    monkeypatch.setattr(selfupdate.subprocess, "Popen", lambda argv, **kw: launched.append((argv, kw)))
    selfupdate.start(Path("/opt/snmpathy/SNMPathy"))
    assert launched[-1][1]["env"] == {"CLEAN": "1"}


class _FakePystray:
    """Enough of pystray to build the menu without a desktop."""

    class MenuItem:
        def __init__(self, text, action=None, **kw):
            self.text, self.action, self.kw = text, action, kw
            self.submenu = action if isinstance(action, _FakePystray.Menu) else None

        def __str__(self):
            return self.text if isinstance(self.text, str) else self.text(self)

    class Menu:
        SEPARATOR = None

        def __init__(self, *items):
            self.items = [i for i in items if i is not None]


def test_tray_server_admin_submenu(monkeypatch):
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "pystray", _FakePystray)
    pystray = _FakePystray
    app = tray.TrayApp.__new__(tray.TrayApp)
    app.available, app.status, app.url = "", "All up", "http://localhost:8080/"
    from snmpathy.config import Settings

    app.settings = Settings(http_port=8081)
    top = [str(i) for i in app.menu().items]
    assert "Server admin" in top and "Start at login" not in top and "View log" not in top
    admin = next(i for i in app.menu().items if str(i) == "Server admin").submenu
    names = [str(i) for i in admin.items]
    for wanted in ("Server admin config…", "Start at login", "Firewall", "Open data folder", "View log"):
        assert wanted in names, wanted
    assert "Web port: 8081 (change in Server admin config)" in names
    fw = [str(i) for i in next(i for i in admin.items if str(i) == "Firewall").submenu.items]
    assert "Open ports: Syslog (UDP and TCP)" in fw and "Open all SNMPathy ports" in fw
    assert "Remove SNMPathy's firewall rules" in fw
    assert pystray


def test_tray_firewall_action_reports(monkeypatch):
    from snmpathy import firewall

    calls, notes, boxes = [], [], []
    monkeypatch.setattr(firewall, "apply", lambda settings, groups, remove=False: calls.append((groups, remove)) or
                        {"ok": True, "rules": ["SNMPathy Syslog UDP 514"], "output": "", "manual": ""})
    monkeypatch.setattr(tray, "show_message", lambda text, title="": boxes.append(text))
    app = tray.TrayApp.__new__(tray.TrayApp)
    app.settings = None
    app.notify = notes.append
    app._firewall(["syslog"], False)
    assert calls == [(["syslog"], False)] and notes == ["Firewall opened for Syslog (UDP and TCP)"]
    monkeypatch.setattr(firewall, "apply", lambda settings, groups, remove=False:
                        {"ok": False, "rules": ["x"], "output": "sudo needs a password", "manual": "ufw allow 514/udp"})
    app._firewall(["syslog"], False)
    assert "ufw allow 514/udp" in boxes[-1] and "sudo needs a password" in boxes[-1]



def test_busy_port_moves_to_the_next_free_one(tmp_path):
    import socket

    from snmpathy import webport
    from snmpathy.config import Settings

    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen()
    busy = holder.getsockname()[1]
    try:
        cfg = tmp_path / "snmpathy.yaml"
        cfg.write_text("# my settings\nhttp_port: %d\nsyslog_udp_port: 5514\n" % busy)
        settings = Settings.load(str(cfg))
        settings.http_host = "127.0.0.1"
        assert not webport.port_free("127.0.0.1", busy)
        notice = webport.ensure_free_port(settings)
        assert settings.http_port != busy and f"Port {busy} is in use" in notice and "saved" in notice
        text = cfg.read_text()
        assert f"http_port: {settings.http_port}" in text and "# my settings" in text and "syslog_udp_port: 5514" in text
        assert webport.ensure_free_port(settings) == ""  # the new one is free: nothing to say
    finally:
        holder.close()


def test_web_port_api_and_restart(tmp_path):
    from fastapi.testclient import TestClient

    from snmpathy.app import create_app
    from snmpathy.config import Settings
    from snmpathy.db import Database

    cfg = tmp_path / "snmpathy.yaml"
    cfg.write_text(f"database: {tmp_path / 'p.db'}\n")
    settings = Settings.load(str(cfg))
    app = create_app(settings, db=Database(settings.database), start_monitor=False)
    with TestClient(app) as client:
        r = client.put("/api/system/web-port", json={"port": 18555})
        assert r.status_code == 200 and r.json()["can_restart"] is False and "http_port: 18555" in cfg.read_text()
        assert client.post("/api/system/restart").status_code == 409  # not the tray app
        restarted = []
        app.state.restart = lambda: restarted.append(1)
        assert client.post("/api/system/restart").json() == {"restarting": True} and restarted == [1]
        assert client.put("/api/system/web-port", json={"port": 0}).status_code == 422
        assert "Web port" in client.get("/admin").text
    with TestClient(app, client=("203.0.113.9", 1)) as remote:  # Server admin needs the passcode
        assert remote.put("/api/system/web-port", json={"port": 18556}).status_code == 403


def test_tray_mute_alerts(monkeypatch, db):
    import sys as _sys
    import types

    from snmpathy import services

    monkeypatch.setitem(_sys.modules, "pystray", _FakePystray)
    app = tray.TrayApp.__new__(tray.TrayApp)
    app.available, app.status, app.url, app.icon = "", "All up", "http://localhost:8080/", None
    app.app = types.SimpleNamespace(state=types.SimpleNamespace(db=db))
    notes = []
    app.notify = notes.append
    from snmpathy.config import Settings

    app.settings = Settings()
    top = app.menu().items
    assert [str(i) for i in top][:4] == ["Open SNMPathy", "All up", "Mute alerts", "Server admin"]
    sub = next(i for i in top if str(i) == "Mute alerts").submenu
    names = [str(i) for i in sub.items]
    assert names[1:5] == ["15 minutes", "1 hour", "8 hours", "Until I unmute"] and names[-1] == "Unmute"
    unmute = sub.items[-1]
    assert unmute.kw["enabled"](unmute) is False

    next(i for i in sub.items if str(i) == "1 hour").action()
    assert 59 * 60 < services.server_mute_until(db) - __import__("time").time() <= 3600
    assert str(next(i for i in app.menu().items if str(i).startswith("Alerts muted"))) == "Alerts muted (1 h 0 min left)"
    assert unmute.kw["enabled"](unmute) is True and "for 1 hour" in notes[-1]
    app.mute(-1)
    assert services.server_mute_until(db) == -1 and app.mute_label() == "Alerts muted (until unmuted)"
    unmute.action()
    assert services.server_mute_until(db) == 0 and app.mute_label() == "Mute alerts" and "unmuted" in notes[-1]


def test_only_browsers_on_the_server_obey_the_tray_mute(tmp_path, db):
    from fastapi.testclient import TestClient

    from snmpathy import services
    from snmpathy.app import create_app
    from snmpathy.config import Settings

    services.set_server_mute(db, 60)
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as local, TestClient(app, client=("203.0.113.9", 5000)) as remote:
        assert local.get("/api/ui/status").json()["server_muted_until"] > 0
        assert remote.get("/api/ui/status").json()["server_muted_until"] == 0
        assert remote.delete("/api/ui/mute").status_code == 403  # only on the server itself
        assert local.delete("/api/ui/mute").json() == {"server_muted_until": 0}
        assert services.server_mute_until(db) == 0
        page = local.get("/devices").text
        assert 'id="mute-btn"' in page and 'data-mute="-1"' in page


class _Release:
    def __init__(self, version, newer=True):
        self.version, self._newer = version, newer

    def is_newer(self):
        return self._newer


def _launch_app(db, monkeypatch, tmp_path):
    import types

    monkeypatch.setattr(tray, "is_frozen", lambda: True)
    monkeypatch.setattr(tray, "_attempt_file", lambda: tmp_path / "update-attempt.json")
    app = tray.TrayApp.__new__(tray.TrayApp)
    app.app = types.SimpleNamespace(state=types.SimpleNamespace(db=db))
    app.available, app.icon = "", None
    app.notes, app.updates = [], []
    app.notify = app.notes.append
    app.run_update = lambda *_: app.updates.append(1)
    return app


def test_update_at_launch_installs_a_newer_release(db, monkeypatch, tmp_path):
    from snmpathy import services

    app = _launch_app(db, monkeypatch, tmp_path)
    assert app.update_at_launch(_Release("9.9.9")) is True
    assert app.updates == [1] and "Updating SNMPathy to 9.9.9" in app.notes[-1]
    # Still here after starting it (the update did not happen): not again at the next start for a while.
    assert app.update_at_launch(_Release("9.9.9")) is False and app.updates == [1]
    assert app.update_at_launch(_Release("9.9.10")) is True  # a newer one is tried
    # Not newer, turned off, or running from Python: nothing.
    assert app.update_at_launch(_Release("0.0.1", newer=False)) is False
    assert app.update_at_launch(None) is False
    services.set_auto_update(db, False)
    assert app.update_at_launch(_Release("9.9.11")) is False
    services.set_auto_update(db, True)
    monkeypatch.setattr(tray, "is_frozen", lambda: False)
    assert app.update_at_launch(_Release("9.9.12")) is False
    assert app.updates == [1, 1]


def test_only_the_check_at_launch_updates(db, monkeypatch, tmp_path):
    import threading

    from snmpathy import selfupdate

    app = _launch_app(db, monkeypatch, tmp_path)
    monkeypatch.setattr(tray, "LAUNCH_CHECK_DELAY", 0)
    monkeypatch.setattr(tray, "UPDATE_CHECK_INTERVAL", 0.05)
    app._stop = threading.Event()
    calls = []

    def latest():
        calls.append(1)
        if len(calls) >= 3:
            app._stop.set()
        return _Release("9.9.9")

    monkeypatch.setattr(selfupdate, "latest_release", latest)
    from snmpathy import services

    services.set_auto_update(db, False)  # off: every check only says a release is available
    app._update_check_loop()
    assert len(calls) == 3 and app.updates == [] and app.available == "9.9.9"
    services.set_auto_update(db, True)
    calls.clear()
    app._stop.clear()
    app._update_check_loop()
    assert app.updates == [1] and len(calls) == 1  # updated at the first check; the updater takes over


def test_auto_update_setting(tmp_path, db, monkeypatch):
    import sys as _sys

    from fastapi.testclient import TestClient

    from snmpathy import selfupdate
    from snmpathy.app import create_app
    from snmpathy.config import Settings

    monkeypatch.setattr(selfupdate, "latest_release", lambda: None)
    app = create_app(Settings(database=str(tmp_path / "t.db")), db=db, start_monitor=False)
    with TestClient(app) as local, TestClient(app, client=("203.0.113.9", 5000)) as remote:
        assert local.get("/api/system/update").json()["auto"] is True
        assert remote.put("/api/system/auto-update", json={"enabled": False}).status_code == 403  # Server admin
        assert local.put("/api/system/auto-update", json={"enabled": False}).json() == {"auto": False}
        assert local.get("/api/system/update").json()["auto"] is False
    # The tray's Server admin menu has the switch.
    monkeypatch.setitem(_sys.modules, "pystray", _FakePystray)
    monkeypatch.setattr(tray, "is_frozen", lambda: True)
    t = tray.TrayApp.__new__(tray.TrayApp)
    t.available, t.status, t.url = "", "All up", "http://localhost:8080/"
    t.settings = Settings()
    admin = next(i for i in t.menu().items if str(i) == "Server admin").submenu
    assert "Update automatically at start" in [str(i) for i in admin.items]
