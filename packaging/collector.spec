# PyInstaller spec for SNMPathy Collector: the collector agent, its setup window and tray icon,
# without the web UI (no FastAPI, Uvicorn, Jinja2 or templates).
# Build with:  python scripts/build_executable.py --collector
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - SPECPATH is provided by PyInstaller
PKG = ROOT / "snmpathy"

# Server-only modules (web UI and APIs): never imported by the collector.
SERVER_ONLY = ("snmpathy.web", "snmpathy.api", "snmpathy.app", "snmpathy.adminauth", "snmpathy.collector_api",
               "snmpathy.fusion", "snmpathy.grafana", "snmpathy.topology", "snmpathy.flows.web",
               "snmpathy.syslog.web", "snmpathy.cli")


def collector_module(name: str) -> bool:
    return not any(name == m or name.startswith(m + ".") for m in SERVER_ONLY)


datas = [(str(PKG / "data"), "snmpathy/data")]  # MAC vendor (OUI) table for device identification
binaries = []
hiddenimports = collect_submodules("snmpathy", filter=collector_module) + ["httpx", "yaml"]

# pysnmp loads its MIB modules from .py files on disk at runtime, so ship the sources too.
for package in ("pysnmp", "pyasn1"):
    pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden
datas += collect_data_files("pysnmp", include_py_files=True)

try:
    import pystray  # noqa: F401

    hiddenimports += collect_submodules("pystray") + ["PIL.Image", "PIL.ImageDraw"]
except Exception:  # not installed, or (Linux) no display on the build machine
    pass

a = Analysis(
    [str(ROOT / "packaging" / "collector_entry.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    # tkinter stays: the setup and update windows use it
    excludes=["pytest", "pytest_asyncio", "fastapi", "uvicorn", "starlette", "jinja2", "multipart",
              "python_multipart", "pydantic", "pydantic_core"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SNMPathy-Collector",
    console=True,  # double-clicked it hides its console (like SNMPathy); services read the log from it
    upx=False,
    strip=False,
    debug=False,
)
