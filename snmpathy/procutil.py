"""Starting programs from the packaged (PyInstaller one-file) SNMPathy.

The one-file executable unpacks itself into a temporary ``_MEI…`` folder that its launcher
deletes when it exits, and tells its Python process where that folder is through environment
variables. A program started with that environment - SNMPathy.exe itself above all - takes over
the folder of the copy that started it, and loses its files as soon as that copy exits
("No module named _sqlite3"). ``self_env()`` is the environment to start programs with
instead: the started SNMPathy unpacks itself afresh.
"""

from __future__ import annotations

import os
import sys

RESET = "PYINSTALLER_RESET_ENVIRONMENT"  # PyInstaller >= 6.9: start as a fresh, separate copy


def _inside(value: str, folder: str) -> bool:
    folder = os.path.normcase(os.path.abspath(folder))
    for part in value.split(os.pathsep):
        if part:
            path = os.path.normcase(os.path.abspath(part))
            if path == folder or path.startswith(folder.rstrip(os.sep) + os.sep):
                return True
    return False


def self_env(extra: dict[str, str] | None = None, base: dict[str, str] | None = None,
             meipass: str | None = None, frozen: bool | None = None) -> dict[str, str]:
    """Environment for starting a program (above all SNMPathy itself) from this process."""
    env = dict(os.environ if base is None else base)
    frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    meipass = getattr(sys, "_MEIPASS", "") if meipass is None else meipass
    if frozen:
        env[RESET] = "1"
        for key in list(env):
            if key.startswith("_PYI_") or key in ("_MEIPASS2", "_MEIPASS"):
                del env[key]
        if meipass:
            for key in list(env):
                if key == "PATH":
                    kept = [p for p in env[key].split(os.pathsep) if p and not _inside(p, meipass)]
                    env[key] = os.pathsep.join(kept)
                elif key not in ("LD_LIBRARY_PATH", "LD_LIBRARY_PATH_ORIG") and _inside(env[key], meipass):
                    del env[key]  # TCL_LIBRARY, TK_LIBRARY, SSL_CERT_FILE, ... set for this copy only
        # Linux: the launcher prepends its folder to LD_LIBRARY_PATH and keeps the original.
        if "LD_LIBRARY_PATH_ORIG" in env:
            env["LD_LIBRARY_PATH"] = env.pop("LD_LIBRARY_PATH_ORIG")
        elif meipass and "LD_LIBRARY_PATH" in env and _inside(env["LD_LIBRARY_PATH"], meipass):
            kept = [p for p in env["LD_LIBRARY_PATH"].split(os.pathsep) if p and not _inside(p, meipass)]
            if kept:
                env["LD_LIBRARY_PATH"] = os.pathsep.join(kept)
            else:
                del env["LD_LIBRARY_PATH"]
    env.update(extra or {})
    return env
