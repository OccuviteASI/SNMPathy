"""Start SNMPathy automatically when the user logs in (no admin rights needed).

* **Windows** - a value under ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run``
  that starts SNMPathy through a tiny VBScript, so no console window appears.
* **macOS**   - a LaunchAgent in ``~/Library/LaunchAgents`` (RunAtLoad, restarted if it exits).
* **Linux**   - a systemd *user* service when systemd is available, otherwise an XDG
  autostart entry in ``~/.config/autostart`` for desktop sessions.

For a machine that must run SNMPathy without anyone logging in, install it as a system
service instead (``deploy/``); this is the per-user, one-click option.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import Settings, app_dir, is_frozen

APP_ID = "SNMPathy"
MAC_LABEL = "com.snmpathy.autostart"
LINUX_UNIT = "snmpathy.service"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


class AutostartError(RuntimeError):
    pass


# ------------------------------------------------------------------ command
def launch_command(settings: Settings | None = None) -> list[str]:
    """The command line that starts this SNMPathy installation's server."""
    if is_frozen():
        argv = [sys.executable, "serve"]
    else:
        python = sys.executable
        if sys.platform.startswith("win"):
            # pythonw.exe runs without a console window.
            windowless = Path(python).with_name("pythonw.exe")
            if windowless.exists():
                python = str(windowless)
        argv = [python, "-m", "snmpathy", "serve"]
    if settings is not None:
        config = getattr(settings, "config_path", "") or ""
        if config:
            argv += ["--config", str(Path(config).resolve())]
        # Pin the database so the login session's working directory does not matter.
        argv += ["--db", str(Path(settings.database).resolve())]
    return argv


def working_dir(settings: Settings | None = None) -> str:
    if is_frozen():
        return str(app_dir())
    if settings is not None:
        return str(Path(settings.database).resolve().parent)
    return os.getcwd()


def _in_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("container") is not None


# ------------------------------------------------------------------ Windows
def _vbs_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "SNMPathy"
    return base / "autostart.vbs"


def _vbs_quote(arg: str) -> str:
    return '""' + arg.replace('"', '""') + '""' if (" " in arg or not arg) else arg.replace('"', '""')


def _windows_enable(argv: list[str], cwd: str) -> str:
    import winreg  # type: ignore[import-not-found]

    script = _vbs_path()
    script.parent.mkdir(parents=True, exist_ok=True)
    command = " ".join(_vbs_quote(a) for a in argv)
    script.write_text(
        "' Starts SNMPathy at logon without a console window (created by SNMPathy).\r\n"
        'Set shell = CreateObject("WScript.Shell")\r\n'
        f'shell.CurrentDirectory = "{cwd}"\r\n'
        f'shell.Run "{command}", 0, False\r\n',
        encoding="utf-8",
    )
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, APP_ID, 0, winreg.REG_SZ, f'wscript.exe //B //nologo "{script}"')
    return f"HKCU\\{RUN_KEY}\\{APP_ID}"


def _windows_disable() -> None:
    import winreg  # type: ignore[import-not-found]

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, APP_ID)
    except FileNotFoundError:
        pass
    _vbs_path().unlink(missing_ok=True)


def _windows_enabled() -> bool:
    import winreg  # type: ignore[import-not-found]

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, APP_ID)
        return True
    except FileNotFoundError:
        return False


# -------------------------------------------------------------------- macOS
def _mac_plist() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{MAC_LABEL}.plist"


def _mac_enable(argv: list[str], cwd: str) -> str:
    import plistlib

    logs = Path.home() / "Library" / "Logs" / "SNMPathy.log"
    plist = _mac_plist()
    plist.parent.mkdir(parents=True, exist_ok=True)
    logs.parent.mkdir(parents=True, exist_ok=True)
    with plist.open("wb") as fh:
        plistlib.dump({
            "Label": MAC_LABEL, "ProgramArguments": argv, "WorkingDirectory": cwd, "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False}, "StandardOutPath": str(logs), "StandardErrorPath": str(logs),
        }, fh)
    # Takes effect at the next login; loading now is not needed (SNMPathy is already running).
    return str(plist)


def _mac_disable() -> None:
    plist = _mac_plist()
    if plist.exists():
        subprocess.run(["launchctl", "unload", str(plist)], capture_output=True, timeout=10)
        plist.unlink()


# -------------------------------------------------------------------- Linux
def _systemd_user_available() -> bool:
    if not shutil.which("systemctl"):
        return False
    try:
        r = subprocess.run(["systemctl", "--user", "show-environment"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _linux_unit() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "systemd" / "user" / LINUX_UNIT


def _linux_desktop() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "autostart" / "snmpathy.desktop"


def _linux_enable(argv: list[str], cwd: str) -> str:
    if _systemd_user_available():
        unit = _linux_unit()
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(
            "[Unit]\nDescription=SNMPathy network monitoring (autostart)\nAfter=network-online.target\n\n"
            f"[Service]\nWorkingDirectory={cwd}\nExecStart={shlex.join(argv)}\nRestart=on-failure\nRestartSec=10\n\n"
            "[Install]\nWantedBy=default.target\n",
            encoding="utf-8",
        )
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=10)
        r = subprocess.run(["systemctl", "--user", "enable", LINUX_UNIT], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise AutostartError(f"systemctl --user enable failed: {r.stderr.strip()}")
        return str(unit)
    desktop = _linux_desktop()
    desktop.parent.mkdir(parents=True, exist_ok=True)
    desktop.write_text(
        "[Desktop Entry]\nType=Application\nName=SNMPathy\nComment=Network monitoring\n"
        f"Exec={shlex.join(argv)}\nPath={cwd}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        encoding="utf-8",
    )
    return str(desktop)


def _linux_disable() -> None:
    unit = _linux_unit()
    if unit.exists():
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "--user", "disable", LINUX_UNIT], capture_output=True, timeout=10)
        unit.unlink()
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=10)
    _linux_desktop().unlink(missing_ok=True)


# ---------------------------------------------------------------- public API
def platform_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def status(settings: Settings | None = None) -> dict[str, Any]:
    """Whether autostart is supported and enabled for the current user, and how."""
    plat = platform_name()
    info: dict[str, Any] = {"platform": plat, "supported": True, "enabled": False, "location": "",
                            "command": launch_command(settings), "note": ""}
    if _in_container():
        info.update(supported=False,
                    note="Running in a container: use the container's restart policy (restart: unless-stopped).")
        return info
    try:
        if plat == "windows":
            info["enabled"] = _windows_enabled()
            info["location"] = f"HKCU\\{RUN_KEY}\\{APP_ID}"
            info["note"] = "Starts when you sign in to Windows (hidden, no console window)."
        elif plat == "macos":
            info["enabled"] = _mac_plist().exists()
            info["location"] = str(_mac_plist())
            info["note"] = "Starts when you log in to macOS; logs go to ~/Library/Logs/SNMPathy.log."
        else:
            unit, desktop = _linux_unit(), _linux_desktop()
            info["enabled"] = unit.exists() or desktop.exists()
            systemd = unit.exists() or (not desktop.exists() and _systemd_user_available())
            info["location"] = str(unit if systemd else desktop)
            info["note"] = ("Starts with your user session (systemd user service). To start at boot before anyone "
                            "logs in, run 'sudo loginctl enable-linger $USER' or install the system service."
                            if systemd else "Starts when you log in to your desktop session.")
    except Exception as exc:  # e.g. registry access denied
        info.update(supported=False, note=f"Autostart is not available here: {exc}")
    return info


def enable(settings: Settings | None = None) -> dict[str, Any]:
    argv, cwd = launch_command(settings), working_dir(settings)
    if _in_container():
        raise AutostartError("not supported inside a container; use the container restart policy")
    plat = platform_name()
    if plat == "windows":
        _windows_enable(argv, cwd)
    elif plat == "macos":
        _mac_enable(argv, cwd)
    else:
        _linux_enable(argv, cwd)
    return status(settings)


def disable(settings: Settings | None = None) -> dict[str, Any]:
    plat = platform_name()
    if plat == "windows":
        _windows_disable()
    elif plat == "macos":
        _mac_disable()
    else:
        _linux_disable()
    return status(settings)


def set_enabled(on: bool, settings: Settings | None = None) -> dict[str, Any]:
    return enable(settings) if on else disable(settings)
