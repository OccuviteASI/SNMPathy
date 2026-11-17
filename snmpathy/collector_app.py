"""SNMPathy Collector: the small app for remote sites (no web UI, database or dashboards).

Downloaded from the server's **Collectors** page (``SNMPathy-Collector-windows.exe`` /
``-linux``). Double-clicked the first time, it opens a setup window:

* paste the **setup code** shown on the Collectors page (server address + collector token),
* choose what to install on this computer:

  - **Collector** - this app runs in the tray, polls and checks the site's devices for the
    server and forwards the results (buffering them while the link is down);
  - **Full SNMPathy server** - downloads the full SNMPathy from the server, starts it with its
    own web UI and database, and adds it to the server's **Fusion** dashboard.

After setup it runs in the tray (status icon, Start at login, Update, Change setup, View log,
Quit). ``SNMPathy-Collector collector --config FILE`` (or ``run``) runs it without a window,
which is what the install scripts and services use.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import __version__, version_string
from .config import app_dir, is_frozen

log = logging.getLogger("snmpathy.collector_app")

SETUP_PREFIX = "SNMPATHY-SETUP-1:"
CONFIG_NAME = "collector.yaml"
LOG_NAME = "collector.log"
PRODUCT = "SNMPathy-Collector"


# --------------------------------------------------------------------------- setup code
def encode_setup_code(server: str, token: str, insecure: bool = False) -> str:
    """What the Collectors page shows: the server address and token in one string to paste."""
    data = {"s": server.rstrip("/"), "t": token}
    if insecure:
        data["k"] = 1
    raw = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
    return SETUP_PREFIX + raw


def decode_setup_code(code: str) -> dict[str, Any]:
    """{server, token, insecure} from a setup code (raises ValueError if it is not one)."""
    code = "".join((code or "").split())
    if not code.startswith(SETUP_PREFIX):
        raise ValueError("that is not an SNMPathy setup code (it starts with SNMPATHY-SETUP-1:)")
    raw = code[len(SETUP_PREFIX):]
    try:
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        server, token = str(data["s"]), str(data["t"])
    except (ValueError, KeyError, TypeError):
        raise ValueError("the setup code is incomplete: copy all of it from the Collectors page")
    if not server.startswith(("http://", "https://")) or not token:
        raise ValueError("the setup code is damaged: copy it again from the Collectors page")
    return {"server": server.rstrip("/"), "token": token, "insecure": bool(data.get("k"))}


# --------------------------------------------------------------------------- config
def config_path() -> Path:
    return app_dir() / CONFIG_NAME


def save_config(server: str, token: str, insecure: bool = False, path: Path | None = None) -> Path:
    path = path or config_path()
    path.write_text(f"# SNMPathy Collector (written by its setup)\nserver: {server}\ntoken: {token}\n"
                    f"verify_tls: {'false' if insecure else 'true'}\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def load_config(path: str | os.PathLike | None = None) -> dict[str, Any]:
    from .collector_agent import load_collector_config

    return load_collector_config(path) if path else (load_collector_config(str(config_path()))
                                                    if config_path().exists() else {})


def _client(server: str, insecure: bool, token: str = ""):
    import httpx

    headers = {"User-Agent": f"snmpathy-collector-setup/{__version__}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=server, verify=not insecure, timeout=httpx.Timeout(60.0, connect=10.0),
                        headers=headers, follow_redirects=True)


def check_server(server: str, token: str, insecure: bool = False) -> None:
    """Make sure the server answers and accepts the token (raises RuntimeError with the reason)."""
    import httpx

    try:
        with _client(server, insecure, token) as http:
            r = http.get("/api/collector/v1/config")
    except httpx.HTTPError as exc:
        raise RuntimeError(f"could not reach {server}: {exc}")
    if r.status_code == 401:
        raise RuntimeError("the server did not accept the collector token: create a new setup code "
                           "on its Collectors page")
    if r.status_code >= 400:
        raise RuntimeError(f"the server answered {r.status_code}")


# --------------------------------------------------------------------------- full server
def write_port(conf: Path, port: int) -> None:
    """Set http_port in the full SNMPathy's snmpathy.yaml (keeping anything else in it)."""
    import re

    text = conf.read_text(encoding="utf-8") if conf.exists() else "# SNMPathy (written by the Collector setup)\n"
    line = f"http_port: {int(port)}"
    if re.search(r"^http_port\s*:.*$", text, flags=re.M):
        text = re.sub(r"^http_port\s*:.*$", line, text, count=1, flags=re.M)
    else:
        text = text.rstrip("\n") + "\n" + line + "\n"
    conf.write_text(text, encoding="utf-8")


def full_exe_name() -> str:
    return "SNMPathy.exe" if sys.platform.startswith("win") else "SNMPathy"


def install_full_server(server: str, token: str, insecure: bool = False, folder: Path | None = None,
                        open_firewall: bool = True, start_at_login: bool = True,
                        say: Callable[[str], None] = lambda msg: None) -> dict[str, Any]:
    """Download the full SNMPathy, start it on a free port and add it to the server's Fusion."""
    import httpx

    from .procutil import self_env
    from .webport import pick_port

    folder = Path(folder or app_dir())
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / full_exe_name()
    plat = "Windows" if sys.platform.startswith("win") else "Linux"
    say(f"Downloading SNMPathy from {server}…")
    part = exe.with_name(exe.name + ".part")
    try:
        with _client(server, insecure) as http, http.stream("GET", "/collector/download/server",
                                                            params={"os_": plat}) as r:
            if r.status_code != 200:
                raise RuntimeError(f"the server has no SNMPathy download for {plat} ({r.status_code})")
            with part.open("wb") as fh:
                for chunk in r.iter_bytes(256 * 1024):
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"download failed: {exc}")
    if not sys.platform.startswith("win"):
        part.chmod(0o755)
    try:
        os.replace(part, exe)
    except OSError:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"{exe} is in use: quit the SNMPathy running from {folder} and try again")

    port = pick_port("0.0.0.0", 8080) or 8080
    say(f"Setting it up on port {port}…")
    write_port(folder / "snmpathy.yaml", port)
    if open_firewall:
        say("Opening the firewall for its web UI (approve the prompt if Windows asks)…")
        try:
            from . import firewall
            from .config import Settings

            firewall.apply(Settings(http_port=port), ["web"])
        except Exception as exc:  # the server can still be added; the rule can be added later
            log.warning("firewall not changed: %s", exc)
    say("Adding it to the server's Fusion dashboard…")
    try:
        with _client(server, insecure, token) as http:
            r = http.post("/api/collector/v1/enroll", json={"name": socket.gethostname(), "port": port})
    except httpx.HTTPError as exc:
        raise RuntimeError(f"could not add it to Fusion: {exc}")
    if r.status_code >= 400:
        detail = r.json().get("detail") if r.headers.get("content-type", "").startswith("application/json") else ""
        raise RuntimeError(f"the server did not add it to Fusion: {detail or r.status_code}")
    enrolled = r.json()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    if start_at_login:
        try:
            subprocess.run([str(exe), "autostart", "on"], cwd=folder, env=self_env(), creationflags=flags,
                           capture_output=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("autostart not set: %s", exc)
    say("Starting SNMPathy…")
    subprocess.Popen([str(exe)], cwd=folder, env=self_env(), creationflags=flags, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=not sys.platform.startswith("win"))
    return {"exe": str(exe), "port": port, "fusion": enrolled}


# --------------------------------------------------------------------------- setup window
class SetupWindow:
    """First run (or Change setup): setup code, Collector or Full server, options."""

    def __init__(self, existing: dict[str, Any] | None = None):
        import tkinter as tk
        from tkinter import ttk

        from .selfupdate import _dpi_aware, _set_icon

        self.tk = tk
        self.result: dict[str, Any] | None = None
        self.busy = False
        _dpi_aware()
        root = self.root = tk.Tk()
        root.title("SNMPathy Collector setup")
        root.resizable(False, False)
        _set_icon(root)
        frame = ttk.Frame(root, padding=(18, 16, 18, 14))
        frame.pack(fill="both", expand=True)
        bold = ("Segoe UI", 12, "bold") if sys.platform.startswith("win") else ("TkDefaultFont", 12, "bold")
        ttk.Label(frame, text="Set up SNMPathy on this computer", font=bold).pack(anchor="w")
        ttk.Label(frame, wraplength=520, justify="left", text=(
            "On your SNMPathy server, open Collectors, add a collector for this site and copy its setup code. "
            "Paste it here.")).pack(anchor="w", pady=(6, 8))
        ttk.Label(frame, text="Setup code").pack(anchor="w")
        self.code = ttk.Entry(frame, width=72)
        self.code.pack(fill="x", pady=(2, 10))
        if existing and existing.get("server") and existing.get("token"):
            self.code.insert(0, encode_setup_code(existing["server"], existing["token"],
                                                  str(existing.get("verify_tls", "true")).lower() == "false"))
        ttk.Label(frame, text="Install").pack(anchor="w")
        self.mode = tk.StringVar(value="collector")
        ttk.Radiobutton(frame, variable=self.mode, value="collector",
                        text="Collector: monitor this site for the server (small; no web UI here)").pack(anchor="w")
        ttk.Radiobutton(frame, variable=self.mode, value="server",
                        text="Full SNMPathy server: its own web UI and database, added to the server's Fusion"
                        ).pack(anchor="w", pady=(2, 8))
        self.login = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, variable=self.login, text="Start when I log in").pack(anchor="w")
        self.firewall = tk.BooleanVar(value=True)
        self.fw_box = ttk.Checkbutton(frame, variable=self.firewall,
                                      text="Open the firewall for the web UI (so the server's Fusion can reach it)")
        self.fw_box.pack(anchor="w")
        self.mode.trace_add("write", lambda *_: self._sync())
        self.status = ttk.Label(frame, text="", wraplength=520, justify="left")
        self.status.pack(anchor="w", pady=(10, 0), fill="x")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        self.install_btn = ttk.Button(buttons, text="Install", command=self.install)
        self.install_btn.pack(side="right")
        ttk.Button(buttons, text="Cancel", command=self.cancel).pack(side="right", padx=(0, 8))
        root.protocol("WM_DELETE_WINDOW", self.cancel)
        self._sync()
        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_width()) // 2
        y = (root.winfo_screenheight() - root.winfo_height()) // 3
        root.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        root.lift()
        root.attributes("-topmost", True)
        root.after(800, lambda: root.attributes("-topmost", False))

    def _sync(self) -> None:
        self.fw_box.state(["!disabled"] if self.mode.get() == "server" else ["disabled"])

    def say(self, text: str) -> None:
        self.root.after(0, lambda: self.status.configure(text=text))

    def cancel(self) -> None:
        if not self.busy:
            self.root.destroy()

    def install(self) -> None:
        try:
            info = decode_setup_code(self.code.get())
        except ValueError as exc:
            self.status.configure(text=str(exc))
            return
        self.busy = True
        self.install_btn.state(["disabled"])
        mode, login, fw = self.mode.get(), self.login.get(), self.firewall.get()
        threading.Thread(target=self._work, args=(info, mode, login, fw), daemon=True).start()

    def _work(self, info: dict[str, Any], mode: str, login: bool, fw: bool) -> None:
        try:
            if mode == "collector":
                self.say(f"Connecting to {info['server']}…")
                check_server(info["server"], info["token"], info["insecure"])
                save_config(info["server"], info["token"], info["insecure"])
                if login:
                    set_autostart(True)
                result = {"mode": "collector", **info}
                message = "Done: the collector is starting in the tray."
            else:
                done = install_full_server(info["server"], info["token"], info["insecure"], open_firewall=fw,
                                           start_at_login=login, say=self.say)
                result = {"mode": "server", **info, **done}
                message = (f"Done: SNMPathy is starting on port {done['port']} and was added to the server's "
                           f"Fusion as {done['fusion'].get('name', socket.gethostname())}.")
        except Exception as exc:
            log.warning("setup failed: %s", exc)
            self.say(f"Setup failed: {exc}")
            self.root.after(0, lambda: self.install_btn.state(["!disabled"]))
            self.busy = False
            return
        self.result = result
        self.say(message)
        self.busy = False
        self.root.after(2500, self.root.destroy)

    def run(self) -> dict[str, Any] | None:
        self.root.mainloop()
        return self.result


# --------------------------------------------------------------------------- autostart
def set_autostart(on: bool) -> None:
    from . import autostart

    autostart.use_collector_profile()
    autostart.set_enabled(on)


def autostart_enabled() -> bool:
    from . import autostart

    autostart.use_collector_profile()
    try:
        return bool(autostart.status()["enabled"])
    except Exception:
        return False


# --------------------------------------------------------------------------- the agent
def make_agent(conf: dict[str, Any], server: str = "", token: str = "", insecure: bool = False,
               ca_file: str = "", state_dir: str = "", concurrency: int = 0):
    from .collector_agent import CollectorAgent

    server = server or os.environ.get("SNMPATHY_COLLECTOR_SERVER") or conf.get("server") or ""
    token = token or os.environ.get("SNMPATHY_COLLECTOR_TOKEN") or conf.get("token") or ""
    if not server or not token:
        raise RuntimeError("no server and token: run the setup (double-click SNMPathy-Collector) or pass "
                           "--server and --token")
    verify: bool | str = True
    if insecure or str(conf.get("verify_tls", "true")).lower() in ("false", "0", "no"):
        verify = False
    if ca_file or conf.get("ca_file"):
        verify = ca_file or conf["ca_file"]
    state = state_dir or conf.get("state_dir") or str(app_dir())
    return CollectorAgent(server, token, verify=verify, state_dir=state,
                          concurrency=int(concurrency or conf.get("concurrency") or 32), name=conf.get("name") or "")


class CollectorTray:
    """The collector running in the tray: status icon and a short menu."""

    def __init__(self, agent: Any, conf: dict[str, Any] | None = None):
        self.agent = agent
        self.conf = conf or {}
        self.icon: Any = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.task: Any = None
        self.restart_setup = False

    def status(self) -> str:
        if self.agent.connected:
            return f"Connected to {self.agent.server}"
        return f"Not connected to {self.agent.server} (retrying; results are kept)"

    def _run_agent(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        # Updated to the server's version: the new copy is running, so this one quits.
        self.task = self.loop.create_task(run_with_updates(self.agent, self.conf, on_restart=self.quit))
        try:
            self.loop.run_until_complete(self.task)
        except BaseException:  # cancelled on quit
            pass

    def _status_loop(self) -> None:
        from .tray import make_icon

        last = None
        while self.icon is not None:
            state = "ok" if self.agent.connected else "down"
            if state != last:
                last = state
                try:
                    self.icon.icon = make_icon(state)
                    self.icon.title = f"SNMPathy Collector - {self.status()}"[:120]
                    self.icon.update_menu()
                except Exception:
                    pass
            time.sleep(3)

    def update(self, *_: Any) -> None:
        from .procutil import self_env

        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen([sys.executable, "self-update", "--gui"], env=self_env(), creationflags=flags,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def toggle_autostart(self, *_: Any) -> None:
        try:
            set_autostart(not autostart_enabled())
        except Exception as exc:
            log.warning("autostart: %s", exc)

    def view_log(self, *_: Any) -> None:
        from .tray import open_path

        path = app_dir() / LOG_NAME
        if path.exists():
            open_path(path)

    def change_setup(self, *_: Any) -> None:
        self.restart_setup = True
        self.quit()

    def quit(self, *_: Any) -> None:
        if self.loop is not None and self.task is not None:
            self.loop.call_soon_threadsafe(self.task.cancel)
        if self.icon is not None:
            icon, self.icon = self.icon, None
            icon.stop()

    def run(self) -> bool:
        """Run until Quit; True when the user asked to change the setup."""
        import pystray

        from .tray import make_icon

        threading.Thread(target=self._run_agent, name="collector-agent", daemon=True).start()
        item = pystray.MenuItem
        menu = pystray.Menu(
            item(lambda _i: self.status(), None, enabled=False),
            pystray.Menu.SEPARATOR,
            item("Start at login", self.toggle_autostart, checked=lambda _i: autostart_enabled()),
            item("Update SNMPathy Collector", self.update, visible=lambda _i: is_frozen()),
            item("Change setup…", self.change_setup),
            item("View log", self.view_log),
            pystray.Menu.SEPARATOR,
            item("Quit SNMPathy Collector", self.quit),
        )
        self.icon = pystray.Icon("SNMPathy Collector", make_icon("down"), "SNMPathy Collector - starting", menu)
        threading.Thread(target=self._status_loop, name="collector-status", daemon=True).start()
        self.icon.run()
        return self.restart_setup


# --------------------------------------------------------------------------- main
def _logging(to_file: bool) -> None:
    from logging.handlers import RotatingFileHandler

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if to_file:
        handler: logging.Handler = RotatingFileHandler(app_dir() / LOG_NAME, maxBytes=2_000_000, backupCount=2,
                                                       encoding="utf-8")
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    root.addHandler(handler)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="SNMPathy-Collector", description="SNMPathy Collector for remote sites")
    sub = p.add_subparsers(dest="command")
    for name in ("collector", "run"):
        r = sub.add_parser(name, help="run the collector without a window (services, install scripts)")
        r.add_argument("--config")
        r.add_argument("--server")
        r.add_argument("--token")
        r.add_argument("--insecure", action="store_true")
        r.add_argument("--ca-file")
        r.add_argument("--state-dir")
        r.add_argument("--concurrency", type=int)
    sub.add_parser("setup", help="open the setup window")
    sub.add_parser("tray", help="run in the tray (the default when double-clicked)")
    sub.add_parser("version", help="print the version")
    u = sub.add_parser("self-update", help="update to the latest release")
    u.add_argument("--gui", action="store_true")
    u.add_argument("--check", action="store_true")
    u.add_argument("--force", action="store_true")
    s = sub.add_parser("setup-code", help="decode / check a setup code")
    s.add_argument("code")
    return p


def run_console(args: argparse.Namespace) -> int:
    _logging(to_file=False)
    if is_frozen():
        from .selfupdate import cleanup_old

        cleanup_old(Path(sys.executable).resolve())  # left by an update
    try:
        conf = load_config(args.config)
        agent = make_agent(conf, args.server or "", args.token or "", args.insecure, args.ca_file or "",
                           args.state_dir or "", args.concurrency or 0)
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        asyncio.run(run_with_updates(agent, conf))
    except KeyboardInterrupt:
        pass
    return 0


async def run_with_updates(agent: Any, conf: dict[str, Any], on_restart: Callable[[], None] | None = None) -> None:
    """The agent plus automatic updates to the server's version (see collector_update)."""
    from .collector_update import auto_update_loop

    kwargs = {"on_restart": on_restart} if on_restart else {}
    await asyncio.gather(agent.run(), auto_update_loop(agent, conf, **kwargs))


def run_gui(force_setup: bool = False) -> int:
    from . import tray

    if tray.relaunch_detached():
        return 0  # a console-less copy carries on (see tray.relaunch_detached)
    tray.hide_own_console()
    _logging(to_file=True)
    if is_frozen():
        from .selfupdate import cleanup_old

        cleanup_old(Path(sys.executable).resolve())
    while True:
        conf = load_config()
        if force_setup or not (conf.get("server") and conf.get("token")):
            try:
                result = SetupWindow(conf).run()
            except Exception as exc:  # no display / no Tk
                log.error("setup window unavailable: %s", exc)
                print("Run: SNMPathy-Collector collector --server URL --token TOKEN", file=sys.stderr)
                return 2
            if not result or result["mode"] == "server":
                return 0  # cancelled, or the full SNMPathy now runs instead
            conf = load_config()
        force_setup = False
        agent = make_agent(conf)
        if not tray.available():
            asyncio.run(run_with_updates(agent, conf))
            return 0
        if not CollectorTray(agent, conf).run():
            return 0
        force_setup = True  # Change setup…


def main(argv: list[str] | None = None) -> int:
    from . import autostart, selfupdate

    selfupdate.PRODUCT = PRODUCT  # update from SNMPathy-Collector-windows.exe / -linux
    autostart.use_collector_profile()  # its own startup entry, separate from the full SNMPathy's
    args = build_parser().parse_args(argv)
    if args.command in ("collector", "run"):
        return run_console(args)
    if args.command == "version":
        print(f"snmpathy-collector {version_string()} (Python {sys.version.split()[0]}, {sys.platform})")
        return 0
    if args.command == "self-update":
        return selfupdate.main(gui=args.gui, check=args.check, force=args.force)
    if args.command == "setup-code":
        try:
            info = decode_setup_code(args.code)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"server: {info['server']}\ntoken: {info['token'][:6]}…")
        return 0
    return run_gui(force_setup=args.command == "setup")


if __name__ == "__main__":
    raise SystemExit(main())
