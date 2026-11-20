"""System-tray mode: SNMPathy runs in the background with an icon instead of a console window.

``snmpathy tray`` (and double-clicking the Windows / macOS executable) starts the web
server in a background thread and shows a tray icon with:

* **Open SNMPathy** (also double-click / left-click on Windows)
* a live status line (devices down / unreachable, checks down), and a red marker on the
  icon when something is down
* **Server admin** (expands): **Server admin config** (the web UI's Server admin page, unlocked
  in this computer's browser: startup, firewall, updates, backup, and the passcode other
  computers need for it), **Start at login**, **Firewall** (open SNMPathy's ports, or remove
  its rules), **Update SNMPathy**, **Open data folder**, **View log**
* **Update SNMPathy** - downloads the latest release from GitHub and restarts, showing a
  progress window (``snmpathy/selfupdate.py``; nothing else needs to be installed). Checked
  every few hours; the menu says when a new version is available. Running from source, it
  pulls and rebuilds instead (``scripts/update_gui.py``, recorded in ``updater.json``).
* (the log goes to ``snmpathy.log`` in tray mode)
* **Quit SNMPathy**

Needs the optional ``pystray`` and ``Pillow`` packages (``pip install snmpathy[tray]``;
always bundled in the executables). Without them, or without a desktop session,
SNMPathy falls back to the normal console server.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
import sys
import threading
import webbrowser
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from .config import Settings, app_dir, is_frozen

log = logging.getLogger(__name__)

BLUE = (42, 120, 214, 255)
RED = (217, 45, 32, 255)
AMBER = (232, 160, 0, 255)


def available() -> bool:
    try:
        import PIL  # noqa: F401
        import pystray  # noqa: F401
    except Exception:  # ImportError, or a missing display backend on Linux
        return False
    return True


def make_icon(state: str = "ok", size: int = 64):
    """The SNMPathy logo (pulse line on a blue tile) with a status dot when something is wrong."""
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    s = size / 32
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=int(8 * s), fill=BLUE)
    points = [(6 * s, 18 * s), (11 * s, 18 * s), (14 * s, 10 * s), (18 * s, 23 * s), (21 * s, 16 * s), (26 * s, 16 * s)]
    draw.line(points, fill=(255, 255, 255, 255), width=max(2, int(2.6 * s)), joint="curve")
    if state in ("down", "warning"):
        r = 7 * s
        cx, cy = size - r - 1, r + 1
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=RED if state == "down" else AMBER,
                     outline=(255, 255, 255, 255), width=max(1, int(1.5 * s)))
    return img


def status_summary(db: Any) -> tuple[str, str]:
    """(icon state, one-line text) from the database."""
    q = db.scalar
    down = q("SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'down'") or 0
    unreachable = q("SELECT COUNT(*) FROM devices WHERE enabled = 1 AND status = 'unreachable'") or 0
    checks = q("SELECT COUNT(*) FROM checks WHERE enabled = 1 AND state = 'down'") or 0
    total = q("SELECT COUNT(*) FROM devices WHERE enabled = 1") or 0
    alerts = q("SELECT COUNT(*) FROM alerts WHERE state = 'firing'") or 0
    parts = []
    if down:
        parts.append(f"{down} device{'s' if down != 1 else ''} down")
    if unreachable:
        parts.append(f"{unreachable} unreachable")
    if checks:
        parts.append(f"{checks} check{'s' if checks != 1 else ''} down")
    if parts:
        return "down", ", ".join(parts)
    if alerts:
        return "warning", f"{alerts} alert{'s' if alerts != 1 else ''} firing"
    return "ok", f"All {total} device{'s' if total != 1 else ''} OK" if total else "No devices yet"


def hide_own_console() -> None:
    """Hide the console window Windows opened for a double-clicked executable.

    A console shared with a terminal the user started is left alone.
    """
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            return
        pids = (ctypes.c_uint * 16)()
        attached = kernel32.GetConsoleProcessList(pids, 16)
        # A one-file executable is two processes (bootloader + app); a terminal adds the shell.
        if attached <= (2 if is_frozen() else 1):
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # type: ignore[attr-defined]
    except Exception:
        pass


DETACHED_ENV = "SNMPATHY_DETACHED"


def own_console() -> bool:
    """A console window Windows opened just for this (double-clicked) executable.

    Not a terminal the user started it from: there the shell is attached to the console too.
    A one-file executable is two processes (launcher + app), so up to two is "ours".
    """
    if not sys.platform.startswith("win"):
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        if not kernel32.GetConsoleWindow():
            return False  # started without a window (autostart, the updater): nothing to close
        pids = (ctypes.c_uint * 16)()
        return 0 < kernel32.GetConsoleProcessList(pids, 16) <= (2 if is_frozen() else 1)
    except Exception:
        return False


def relaunch_detached() -> bool:
    """Start this executable again without a console and return True (the caller then exits).

    Hiding the console window does not work when Windows Terminal hosts it (Windows 11): the
    tab stays open. Exiting closes it, so a copy carries on in the background instead.
    """
    if not is_frozen() or os.environ.get(DETACHED_ENV) or not own_console():
        return False
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        from .procutil import self_env

        # A fresh environment: inheriting this copy's would make the new one use (and lose) this
        # copy's unpacked files when this copy exits ("No module named _sqlite3").
        subprocess.Popen([sys.executable, *sys.argv[1:]], env=self_env({DETACHED_ENV: "1"}),
                         cwd=os.getcwd(), creationflags=flags, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        log.warning("could not restart without a console (%s); hiding it instead", exc)
        return False
    return True


def log_file(settings: Settings) -> Path:
    base = app_dir() if is_frozen() else Path(settings.database).resolve().parent
    return base / "snmpathy.log"


def setup_file_logging(path: Path) -> None:
    handler = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).addHandler(handler)


def open_path(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


# ------------------------------------------------------------------ updating
# Updating rebuilds SNMPathy from a git checkout of its source with Python. The build records
# both in updater.json next to the executable, but a copy can end up on another computer
# (a synced Desktop / OneDrive folder, a USB stick) where those paths do not exist. Then the
# source is looked for elsewhere, or downloaded once with git into SOURCE_HOME.
DEFAULT_REMOTE = "https://github.com/OccuviteASI/SNMPathy.git"
UPDATE_CHECK_INTERVAL = 6 * 3600  # seconds between looks for a new release
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def updater_info() -> dict[str, Any]:
    try:
        info = json.loads((app_dir() / "updater.json").read_text(encoding="utf-8"))
        return info if isinstance(info, dict) else {}
    except (OSError, ValueError):
        return {}


def source_home() -> Path:
    """Where a source checkout is downloaded to when this computer has none."""
    if sys.platform.startswith("win"):
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "SNMPathy" / "source"
    return Path.home() / ".local" / "share" / "snmpathy" / "source"


def is_source(path: Path) -> bool:
    return (path / "scripts" / "update_gui.py").is_file() and (path / "scripts" / "update.py").is_file()


def find_source(info: dict[str, Any] | None = None) -> Path | None:
    """The SNMPathy source checkout to update from, if this computer has one."""
    info = updater_info() if info is None else info
    candidates: list[Path] = []
    for value in (os.environ.get("SNMPATHY_SOURCE"), info.get("source"),
                  str(Path(info["gui"]).parent.parent) if info.get("gui") else None):
        if value:
            candidates.append(Path(value))
    here = app_dir()
    candidates += [here, *list(here.parents)[:3], source_home()]
    for path in candidates:
        try:
            if is_source(path):
                return path
        except OSError:
            continue
    return None


def _real_program(path: str | None) -> bool:
    # The Microsoft Store "python.exe" in WindowsApps only opens the Store.
    return bool(path) and "windowsapps" not in path.lower() and Path(path).exists()


def find_python(info: dict[str, Any] | None = None) -> list[str] | None:
    """A Python to run the updater with (windowless on Windows), as a command prefix."""
    info = updater_info() if info is None else info
    recorded = info.get("python")
    if recorded and _real_program(recorded):
        return [recorded]
    if sys.platform.startswith("win"):
        for name in ("pythonw", "python"):
            found = shutil.which(name)
            if _real_program(found):
                windowless = Path(found).with_name("pythonw.exe")
                return [str(windowless if windowless.exists() else found)]
        found = shutil.which("pyw") or shutil.which("py")
        if _real_program(found):
            return [found, "-3"]
        return None
    found = shutil.which("python3") or shutil.which("python")
    return [found] if _real_program(found) else None


def updater_command() -> list[str] | None:
    """Command for the progress-window updater (scripts/update_gui.py), or None if it cannot run here."""
    info = updater_info()
    source, python = find_source(info), find_python(info)
    if source is None or python is None:
        return None
    return [*python, str(source / "scripts" / "update_gui.py"), "--dest", str(app_dir())]


def missing_for_update() -> list[str]:
    """What this computer lacks to update SNMPathy ([] when it can, perhaps after downloading the source)."""
    info = updater_info()
    missing = []
    if find_python(info) is None:
        missing.append("Python 3 (python.org - tick \"Add python.exe to PATH\")")
    if find_source(info) is None and not shutil.which("git"):
        missing.append("Git (git-scm.com)")
    return missing


def update_launcher() -> Path | None:
    """The old "Update SNMPathy.cmd" / update-snmpathy.sh, if the script it calls exists here."""
    folder = app_dir()
    for name in ("Update SNMPathy.cmd", "update-snmpathy.sh"):
        path = folder / name
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        target = re.search(r'(?:call|exec)\s+"([^"]+)"', text)
        if target is None or Path(target.group(1)).exists():
            return path
    return None


def update_available() -> bool:
    """Show "Update SNMPathy" in the tray menu: always for the executable (it explains what is missing)."""
    return is_frozen() or updater_command() is not None or update_launcher() is not None


def clone_source(remote: str, dest: Path) -> tuple[bool, str]:
    """Download the SNMPathy source with git (credentials come from Git's own helper)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        done = subprocess.run(["git", "clone", "--quiet", remote, str(dest)], capture_output=True, text=True,
                              timeout=900, env=env, creationflags=NO_WINDOW, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return done.returncode == 0, (done.stderr or done.stdout or "").strip()


def show_message(text: str, title: str = "SNMPathy update") -> None:
    """A plain message box (Windows); elsewhere the log."""
    log.warning("%s: %s", title, text)
    if sys.platform.startswith("win"):
        try:
            import ctypes

            threading.Thread(target=ctypes.windll.user32.MessageBoxW,  # type: ignore[attr-defined]
                             args=(0, text, title, 0x40 | 0x10000), daemon=True).start()
        except Exception:
            pass


class TrayApp:
    def __init__(self, settings: Settings, open_browser: bool = True):
        self.settings = settings
        self.open_browser = open_browser
        host = "localhost" if settings.http_host in ("0.0.0.0", "::", "") else settings.http_host
        self.url = f"http://{host}:{settings.http_port}/"
        self.server: Any = None
        self.app: Any = None
        self.thread: threading.Thread | None = None
        self.icon: Any = None
        self.state, self.status = "ok", "Starting…"
        self.error = ""
        self.available = ""  # a newer release, when the update check found one
        self.notice = ""  # shown once the icon is up
        self._stop = threading.Event()

    # ------------------------------------------------------------ server
    def _run_server(self) -> None:
        from .cli import _serve

        def on_app(app: Any) -> None:
            self.app = app
            app.state.restart = self.restart  # Server admin > Web port > Save and restart

        try:
            asyncio.run(_serve(self.settings, open_browser=self.open_browser,
                               on_app=on_app,
                               on_server=lambda server: setattr(self, "server", server)))
        except BaseException as exc:  # e.g. port already in use
            self.error = str(exc) or type(exc).__name__
            log.exception("SNMPathy server stopped")
        finally:
            if not self._stop.is_set():
                self.error = self.error or "the server stopped unexpectedly (see the log)"
                self.state, self.status = "down", f"Not running: {self.error}"
                self._refresh_icon()

    def _status_loop(self) -> None:
        while not self._stop.wait(5 if self.status == "Starting…" else 30):
            if self.app is None or self.error:
                continue
            try:
                self.state, self.status = status_summary(self.app.state.db)
            except Exception as exc:  # never let the tray die on a status query
                log.debug("tray status failed: %s", exc)
                continue
            self._refresh_icon()

    def _refresh_icon(self) -> None:
        if self.icon is None:
            return
        try:
            self.icon.icon = make_icon(self.state)
            self.icon.title = f"SNMPathy - {self.status}"[:120]
            self.icon.update_menu()
        except Exception:
            pass

    # ------------------------------------------------------------ actions
    def open_ui(self, *_: Any) -> None:
        webbrowser.open(self.url)

    def toggle_autostart(self, *_: Any) -> None:
        from . import autostart

        try:
            autostart.set_enabled(not self.autostart_enabled(), self.settings)
        except Exception as exc:
            self.notify(f"Could not change autostart: {exc}")
        self._refresh_icon()

    def autostart_enabled(self, *_: Any) -> bool:
        from . import autostart

        try:
            return bool(autostart.status(self.settings)["enabled"])
        except Exception:
            return False

    def run_update(self, *_: Any) -> None:
        if is_frozen():
            # The executable updates itself from the latest GitHub release: no Python or Git needed.
            self._launch([sys.executable, "self-update", "--gui"], cwd=Path(sys.executable).parent)
            return
        command = updater_command()
        if command is None and find_source() is None and not missing_for_update():
            # A copy built on another computer: download the source here once, then update.
            threading.Thread(target=self._fetch_source_then_update, daemon=True).start()
            return
        if command is not None:
            # A progress window in its own process: it outlives this one, which the update closes.
            flags = 0
            if sys.platform.startswith("win"):
                flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            try:
                subprocess.Popen(command, cwd=Path(command[-3]).parent.parent, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
                                 start_new_session=not sys.platform.startswith("win"))
                return
            except OSError as exc:
                log.warning("could not open the update window (%s); using the update script", exc)
        launcher = update_launcher()
        if launcher is None:
            missing = missing_for_update()
            show_message(
                "SNMPathy can't update itself on this computer yet. Updating rebuilds it from its source, "
                "which needs:\n\n  - " + "\n  - ".join(missing or ["the SNMPathy source folder"])
                + "\n\nInstall " + ("them" if len(missing) > 1 else "it")
                + ", then choose Update SNMPathy again: the source is downloaded automatically.")
            return
        if sys.platform.startswith("win"):
            # Older builds without updater.json: the update script in a console window.
            subprocess.Popen(["cmd", "/c", "start", "SNMPathy update", str(launcher), "--from-tray"])
        else:
            subprocess.Popen([str(launcher)], start_new_session=True)

    def _launch(self, command: list[str], cwd: Path) -> None:
        flags = 0
        if sys.platform.startswith("win"):
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        from .procutil import self_env

        try:
            subprocess.Popen(command, cwd=cwd, env=self_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, creationflags=flags,
                             start_new_session=not sys.platform.startswith("win"))
        except OSError as exc:
            show_message(f"Could not start the updater: {exc}")

    def _update_check_loop(self) -> None:
        """Look for a new release now and then, so the menu can say one is available."""
        from . import selfupdate

        if self._stop.wait(60):
            return
        while not self._stop.is_set():
            try:
                release = selfupdate.latest_release()
                if release is not None and release.is_newer():
                    if release.version != self.available:
                        self.available = release.version
                        self.notify(f"SNMPathy {release.version} is available: choose Update SNMPathy in this menu.")
                        try:
                            self.icon.update_menu()
                        except Exception:
                            pass
            except Exception as exc:  # offline, rate-limited, ...: try again later
                log.debug("update check failed: %s", exc)
            if self._stop.wait(UPDATE_CHECK_INTERVAL):
                return

    def update_label(self, *_: Any) -> str:
        return f"Update SNMPathy ({self.available} available)" if self.available else "Update SNMPathy"

    def _fetch_source_then_update(self) -> None:
        dest = source_home()
        remote = updater_info().get("remote") or DEFAULT_REMOTE
        self.notify("Downloading the SNMPathy source for updates (first time on this computer)...")
        if dest.exists() and not is_source(dest):
            shutil.rmtree(dest, ignore_errors=True)  # a half-finished earlier download
        ok, detail = clone_source(remote, dest)
        if not ok or not is_source(dest):
            show_message(f"Could not download the SNMPathy source from {remote}:\n\n{detail[-600:]}\n\n"
                         "Check that this computer can reach GitHub and that you are signed in to Git "
                         "with an account that can read the repository.")
            return
        if updater_command() is None:
            show_message("The source was downloaded, but no Python was found to run the update.")
            return
        self.run_update()

    def open_folder(self, *_: Any) -> None:
        open_path(log_file(self.settings).parent)

    def view_log(self, *_: Any) -> None:
        path = log_file(self.settings)
        if path.exists():
            open_path(path)

    def notify(self, message: str) -> None:
        try:
            self.icon.notify(message, "SNMPathy")
        except Exception:
            log.warning(message)

    def restart(self) -> None:
        """Start a fresh copy of SNMPathy (e.g. on a new web port), then quit this one."""
        from .procutil import self_env

        argv = [sys.executable, *sys.argv[1:]] if is_frozen() else [sys.executable, "-m", "snmpathy", "tray"]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        def later() -> None:
            time.sleep(1.0)  # let the web request that asked for this get its answer
            try:
                subprocess.Popen(argv, env=self_env({DETACHED_ENV: "1"}), cwd=os.getcwd(), creationflags=flags,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=not sys.platform.startswith("win"))
            except OSError as exc:
                show_message(f"Could not restart SNMPathy: {exc}", "SNMPathy")
                return
            self.quit()
        threading.Thread(target=later, name="snmpathy-restart", daemon=True).start()

    def quit(self, *_: Any) -> None:
        self._stop.set()
        if self.server is not None:
            self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout=15)
        if self.icon is not None:
            self.icon.stop()

    # ------------------------------------------------------------ firewall
    def firewall(self, groups: list[str], remove: bool = False) -> None:
        """Open (or close) SNMPathy's ports in this computer's firewall, in the background."""
        threading.Thread(target=self._firewall, args=(groups, remove), name="snmpathy-firewall", daemon=True).start()

    def _firewall(self, groups: list[str], remove: bool) -> None:
        from . import firewall

        try:
            result = firewall.apply(self.settings, groups, remove=remove)
        except Exception as exc:
            show_message(f"Could not change the firewall: {exc}", "SNMPathy firewall")
            return
        what = ", ".join(firewall.GROUPS[g] for g in groups)
        if result.get("ok"):
            self.notify(("Removed SNMPathy's firewall rules" if remove else f"Firewall opened for {what}")
                        if result.get("rules") else result.get("output") or "Nothing to change")
        elif result.get("manual"):
            show_message(f"{result.get('output') or 'The rules were not changed automatically.'}\n\n"
                         f"Run these commands as administrator:\n\n{result['manual']}", "SNMPathy firewall")
        else:
            show_message(result.get("output") or "The firewall was not changed.", "SNMPathy firewall")

    def open_admin(self, *_: Any) -> None:
        """Server admin config: the web page, unlocked in this computer's browser by a one-time link."""
        from .adminauth import new_ticket

        webbrowser.open(self.url.rstrip("/") + "/admin/open?ticket=" + new_ticket())

    # ------------------------------------------------------------ menu
    def firewall_menu(self):
        import pystray

        from .firewall import GROUPS

        item = pystray.MenuItem
        opens = [item(f"Open ports: {label}", (lambda key: lambda *_: self.firewall([key]))(key))
                 for key, label in GROUPS.items()]
        return pystray.Menu(
            *opens,
            item("Open all SNMPathy ports", lambda *_: self.firewall(list(GROUPS))),
            pystray.Menu.SEPARATOR,
            item("Remove SNMPathy's firewall rules", lambda *_: self.firewall(list(GROUPS), remove=True)),
        )

    def admin_menu(self):
        import pystray

        item = pystray.MenuItem
        return pystray.Menu(
            item("Server admin config…", self.open_admin),
            item(lambda _i: f"Web port: {self.settings.http_port} (change in Server admin config)", self.open_admin),
            pystray.Menu.SEPARATOR,
            item("Start at login", self.toggle_autostart, checked=self.autostart_enabled),
            item("Firewall", self.firewall_menu()),
            item(self.update_label, self.run_update, visible=lambda _i: update_available()),
            pystray.Menu.SEPARATOR,
            item("Open data folder", self.open_folder),
            item("View log", self.view_log),
        )

    # ------------------------------------------------------------ mute
    MUTE_CHOICES = ((15, "15 minutes"), (60, "1 hour"), (480, "8 hours"), (-1, "Until I unmute"))

    def muted_until(self) -> float:
        from .services import server_mute_until

        db = getattr(getattr(getattr(self, "app", None), "state", None), "db", None)
        return server_mute_until(db) if db is not None else 0.0

    def mute_label(self, *_: Any) -> str:
        until = self.muted_until()
        if not until:
            return "Mute alerts"
        if until == -1:
            return "Alerts muted (until unmuted)"
        left = max(1, round((until - time.time()) / 60))
        return f"Alerts muted ({left // 60} h {left % 60} min left)" if left >= 60 else f"Alerts muted ({left} min left)"

    def mute(self, minutes: int | None) -> None:
        from .services import set_server_mute

        db = getattr(getattr(getattr(self, "app", None), "state", None), "db", None)
        if db is None:
            self.notify("SNMPathy is still starting: try again in a moment")
            return
        set_server_mute(db, minutes)
        if not minutes:
            self.notify("Alerts unmuted: browsers on this computer announce new alerts again")
        else:
            span = dict(self.MUTE_CHOICES)[minutes].lower()
            self.notify(f"Alerts muted {'until you unmute' if minutes == -1 else 'for ' + span}: browsers on this "
                        "computer stop the pop-ups, notifications and sound (emails still go out)")
        icon = getattr(self, "icon", None)
        if icon is not None:
            try:
                icon.update_menu()
            except Exception:
                pass

    def mute_menu(self):
        import pystray

        item = pystray.MenuItem
        return pystray.Menu(
            item("Quiets new-alert pop-ups and sound in browsers on this computer", None, enabled=False),
            *[item(label, (lambda m: lambda *_: self.mute(m))(minutes)) for minutes, label in self.MUTE_CHOICES],
            pystray.Menu.SEPARATOR,
            item("Unmute", lambda *_: self.mute(None), enabled=lambda _i: bool(self.muted_until())),
        )

    def menu(self):
        import pystray

        item = pystray.MenuItem
        return pystray.Menu(
            item("Open SNMPathy", self.open_ui, default=True),
            item(lambda _i: self.status, None, enabled=False),
            pystray.Menu.SEPARATOR,
            item(self.mute_label, self.mute_menu()),
            item("Server admin", self.admin_menu()),
            pystray.Menu.SEPARATOR,
            item("Quit SNMPathy", self.quit),
        )

    def run(self) -> None:
        import pystray

        self.thread = threading.Thread(target=self._run_server, name="snmpathy-server", daemon=True)
        self.thread.start()
        threading.Thread(target=self._status_loop, name="snmpathy-tray-status", daemon=True).start()
        if is_frozen():
            from .selfupdate import cleanup_old

            cleanup_old(Path(sys.executable).resolve())  # the previous version, kept until now
            threading.Thread(target=self._update_check_loop, name="snmpathy-update-check", daemon=True).start()
        self.icon = pystray.Icon("SNMPathy", make_icon("ok"), "SNMPathy - starting", self.menu())
        if self.notice:  # e.g. "port 8080 is in use, the web UI is on 8081"
            threading.Timer(3.0, lambda: self.notify(self.notice)).start()
        self.icon.run()
        self._stop.set()
        if self.server is not None:
            self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout=15)


def run_tray(settings: Settings, open_browser: bool = True) -> int:
    """Run in the tray; returns 2 when no tray is possible (the caller then serves normally)."""
    if not available():
        return 2
    if relaunch_detached():
        return 0  # the console-less copy runs the tray; exiting closes this console window
    hide_own_console()
    setup_file_logging(log_file(settings))
    log.info("SNMPathy starting in the system tray")
    from .webport import ensure_free_port

    notice = ensure_free_port(settings)  # 8080 taken by another program: use the next free port
    if notice:
        log.warning(notice)
    try:
        app = TrayApp(settings, open_browser=open_browser)
        app.notice = notice
        app.run()
    except Exception as exc:  # e.g. no display / tray on this Linux desktop
        log.error("tray unavailable (%s); running without it", exc)
        return 2
    return 0

