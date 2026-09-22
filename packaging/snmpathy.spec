# PyInstaller spec for a single-file SNMPathy executable.
# Build with:  python scripts/build_executable.py   (recommended)
#        or:   pyinstaller packaging/snmpathy.spec
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - SPECPATH is provided by PyInstaller
PKG = ROOT / "snmpathy"

datas = [
    (str(PKG / "web" / "templates"), "snmpathy/web/templates"),
    (str(PKG / "web" / "static"), "snmpathy/web/static"),
]
binaries = []
hiddenimports = collect_submodules("snmpathy") + collect_submodules("uvicorn")

# pysnmp loads its MIB modules from .py files on disk at runtime, so ship the sources too.
for package in ("pysnmp", "pyasn1"):
    pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden
datas += collect_data_files("pysnmp", include_py_files=True)

a = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "pytest_asyncio"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SNMPathy",
    console=True,  # keep the console: it shows the log and the URL, and Ctrl+C stops the server
    upx=False,
    strip=False,
    debug=False,
)
