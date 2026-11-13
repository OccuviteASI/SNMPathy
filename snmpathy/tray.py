"""System-tray mode: SNMPathy runs in the background with an icon instead of a console window.

``snmpathy tray`` (and double-clicking the Windows / macOS executable) starts the web
server in a background thread and shows a tray icon with:

* **Open SNMPathy** (also double-click / left-click on Windows)
* a live status line (devices down / unreachable, checks down), and a red marker on the
  icon when something is down
* **Start at login** - the same switch as Settings > Startup
* **Update SNMPathy** - pulls, rebuilds and restarts, showing a progress window
  (``scripts/update_gui.py``, recorded in ``updater.json`` next to the executable)
* **Open data folder**, **View log** (the log goes to ``snmpathy.log`` in tray mode)
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
        self._stop = threading.Event()

    # ------------------------------------------------------------ server
    def _run_server(self) -> None:
        from .cli import _serve

        try:
            asyncio.run(_serve(self.settings, open_browser=self.open_browser,
                               on_app=lambda app: setattr(self, "app", app),
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

    def quit(self, *_: Any) -> None:
        self._stop.set()
        if self.server is not None:
            self.server.should_exit = True
        if self.thread is not None:
            self.thread.join(timeout=15)
        if self.icon is not None:
            self.icon.stop()

    # ------------------------------------------------------------ menu
    def menu(self):
        import pystray

        item = pystray.MenuItem
        return pystray.Menu(
            item("Open SNMPathy", self.open_ui, default=True),
            item(lambda _i: self.status, None, enabled=False),
            pystray.Menu.SEPARATOR,
            item("Start at login", self.toggle_autostart, checked=self.autostart_enabled),
            item("Update SNMPathy", self.run_update, visible=lambda _i: update_available()),
            item("Open data folder", self.open_folder),
            item("View log", self.view_log),
            pystray.Menu.SEPARATOR,
            item("Quit SNMPathy", self.quit),
        )

    def run(self) -> None:
        import pystray

        self.thread = threading.Thread(target=self._run_server, name="snmpathy-server", daemon=True)
        self.thread.start()
        threading.Thread(target=self._status_loop, name="snmpathy-tray-status", daemon=True).start()
        self.icon = pystray.Icon("SNMPathy", make_icon("ok"), "SNMPathy - starting", self.menu())
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
    hide_own_console()
    setup_file_logging(log_file(settings))
    log.info("SNMPathy starting in the system tray")
    try:
        TrayApp(settings, open_browser=open_browser).run()
    except Exception as exc:  # e.g. no display / tray on this Linux desktop
        log.error("tray unavailable (%s); running without it", exc)
        return 2
    return 0

