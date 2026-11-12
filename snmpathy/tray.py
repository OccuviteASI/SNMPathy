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
import logging
import os
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


def update_launcher() -> Path | None:
    folder = app_dir()
    for name in ("Update SNMPathy.cmd", "update-snmpathy.sh"):
        if (folder / name).exists():
            return folder / name
    return None


def updater_command() -> list[str] | None:
    """The progress-window updater recorded by the build (updater.json next to the executable)."""
    import json

    try:
        info = json.loads((app_dir() / "updater.json").read_text(encoding="utf-8"))
        python, gui = Path(info["python"]), Path(info["gui"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not python.exists() or not gui.exists():
        return None  # Python or the source folder was moved: rebuild once to refresh updater.json
    return [str(python), str(gui), "--dest", str(app_dir())]


def update_available() -> bool:
    return updater_command() is not None or update_launcher() is not None


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
        if command is not None:
            # A progress window in its own process: it outlives this one, which the update closes.
            flags = 0
            if sys.platform.startswith("win"):
                flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            try:
                subprocess.Popen(command, cwd=Path(command[1]).parent.parent, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
                                 start_new_session=not sys.platform.startswith("win"))
                return
            except OSError as exc:
                log.warning("could not open the update window (%s); using the update script", exc)
        launcher = update_launcher()
        if launcher is None:
            self.notify("No updater found next to SNMPathy. Rebuild once with scripts/build_executable.")
            return
        if sys.platform.startswith("win"):
            # Older builds without updater.json: the update script in a console window.
            subprocess.Popen(["cmd", "/c", "start", "SNMPathy update", str(launcher), "--from-tray"])
        else:
            subprocess.Popen([str(launcher)], start_new_session=True)

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

