"""HTTP endpoints for remote collectors.

* ``/api/collector/v1/*`` - used by collectors themselves, authenticated with
  the collector's own token (``Authorization: Bearer col_...``).
* ``/api/collectors/*``   - management API for administrators (normal auth).
* ``/collector/*``        - public downloads and one-line install scripts, so
  a site machine can fetch the collector straight from this server.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from . import __version__, collectors
from .config import app_dir, is_frozen
from .db import Database

router = APIRouter()


def _db(request: Request) -> Database:
    return request.app.state.db


def _hub(request: Request) -> collectors.CollectorHub:
    return request.app.state.hub


# ======================================================= collector-facing API
def _collector(request: Request) -> dict[str, Any]:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-collector-token", "")
    row = collectors.authenticate(_db(request), token)
    if not row:
        raise HTTPException(401, "invalid collector token")
    info = {
        "last_ip": request.client.host if request.client else "",
        "hostname": request.headers.get("x-collector-hostname", ""),
        "platform": request.headers.get("x-collector-platform", ""),
        "version": request.headers.get("x-collector-version", ""),
    }
    if request.headers.get("x-collector-backlog") is not None:
        info["backlog"] = request.headers.get("x-collector-backlog")
    _hub(request).touch(row, info)
    return row


@router.get("/api/collector/v1/poll", include_in_schema=False)
async def collector_poll(request: Request, wait: float = 25.0):
    collector = _collector(request)
    hub = _hub(request)
    version = hub.config_version(collector["id"])
    if version == request.headers.get("x-collector-config"):
        # Nothing new yet: wait for jobs (or a config change) before answering.
        jobs = await hub.next_jobs(collector["id"], wait=max(0.0, min(wait, 30.0)),
                                   until=lambda: hub.config_version(collector["id"]) != version)
        version = hub.config_version(collector["id"])
    else:
        jobs = await hub.next_jobs(collector["id"], wait=0)
    if jobs:
        # Answering takes a while for long polls: refresh last_seen.
        hub.touch({**collector, "status": "online"}, {})
    return {"config_version": version, "jobs": jobs, "server_time": time.time(), "server_version": __version__}


@router.get("/api/collector/v1/config", include_in_schema=False)
async def collector_config(request: Request):
    collector = _collector(request)
    return _hub(request).config(collector["id"])


class ResultsIn(BaseModel):
    results: list[dict[str, Any]] = []
    jobs: list[dict[str, Any]] = []


@router.post("/api/collector/v1/results", include_in_schema=False)
async def collector_results(body: ResultsIn, request: Request):
    collector = _collector(request)
    hub = _hub(request)
    answered = hub.resolve(collector["id"], body.jobs)
    counts = await hub.ingest(collector, body.results[:5000])
    return {**counts, "jobs": answered}


# ========================================================== management API
class CollectorIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    site: str = ""
    description: str = ""


class CollectorPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    site: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None


def _base_url(request: Request) -> str:
    public = request.app.state.settings.public_url
    return (public or str(request.base_url)).rstrip("/")


def install_commands(request: Request, token: str) -> dict[str, str]:
    base = _base_url(request)
    return {
        "linux": f"curl -fsSL {base}/collector/install.sh | sudo bash -s -- --token {token}",
        "macos": f"curl -fsSL {base}/collector/install.sh | sudo bash -s -- --token {token}",
        "windows": (f"powershell -ExecutionPolicy Bypass -Command \"& ([scriptblock]::Create((iwr -UseBasicParsing "
                    f"'{base}/collector/install.ps1').Content)) -Token '{token}'\""),
        "docker": (f"docker run -d --name snmpathy-collector --restart unless-stopped --network host "
                   f"-v snmpathy-collector:/data -e SNMPATHY_COLLECTOR_SERVER={base} "
                   f"-e SNMPATHY_COLLECTOR_TOKEN={token} snmpathy collector --state-dir /data"),
        "manual": f"snmpathy collector --server {base} --token {token}",
    }


@router.get("/api/collectors", tags=["collectors"])
def list_collectors(db: Database = Depends(_db)):
    rows = db.query("SELECT * FROM collectors ORDER BY name COLLATE NOCASE")
    counts = {r["collector_id"]: r["n"] for r in db.query(
        "SELECT collector_id, COUNT(*) AS n FROM devices WHERE collector_id IS NOT NULL GROUP BY collector_id")}
    return [{**collectors.public_collector(r), "devices": counts.get(r["id"], 0)} for r in rows]


@router.post("/api/collectors", status_code=201, tags=["collectors"])
def create_collector(body: CollectorIn, request: Request, db: Database = Depends(_db)):
    try:
        row, token = collectors.create_collector(db, body.name, body.site, body.description)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {**collectors.public_collector(row), "token": token, "install": install_commands(request, token)}


@router.get("/api/collectors/{collector_id}", tags=["collectors"])
def get_collector(collector_id: int, db: Database = Depends(_db)):
    row = db.one("SELECT * FROM collectors WHERE id = ?", (collector_id,))
    if not row:
        raise HTTPException(404, "collector not found")
    return collectors.public_collector(row)


@router.patch("/api/collectors/{collector_id}", tags=["collectors"])
def patch_collector(collector_id: int, body: CollectorPatch, db: Database = Depends(_db)):
    if not db.one("SELECT 1 FROM collectors WHERE id = ?", (collector_id,)):
        raise HTTPException(404, "collector not found")
    values = body.model_dump(exclude_unset=True)
    if "enabled" in values:
        values["enabled"] = int(values["enabled"])
    if values.get("name") and db.one("SELECT 1 FROM collectors WHERE name = ? AND id != ?", (values["name"], collector_id)):
        raise HTTPException(422, "a collector with that name already exists")
    db.update("collectors", collector_id, values)
    return collectors.public_collector(db.one("SELECT * FROM collectors WHERE id = ?", (collector_id,)))


@router.post("/api/collectors/{collector_id}/token", tags=["collectors"])
def rotate_collector_token(collector_id: int, request: Request, db: Database = Depends(_db)):
    """Issue a new token (the old one stops working immediately)."""
    try:
        token = collectors.rotate_token(db, collector_id)
    except KeyError as exc:
        raise HTTPException(404, "collector not found") from exc
    return {"token": token, "install": install_commands(request, token)}


@router.delete("/api/collectors/{collector_id}", status_code=204, tags=["collectors"])
def delete_collector(collector_id: int, request: Request, db: Database = Depends(_db)):
    collectors.delete_collector(db, collector_id)
    _hub(request).invalidate(collector_id)


@router.post("/api/collectors/{collector_id}/ping", tags=["collectors"])
async def ping_collector(collector_id: int, request: Request):
    """Round-trip a no-op job through the collector."""
    started = time.perf_counter()
    try:
        result = await _hub(request).call(collector_id, "ping", {}, timeout=40)
    except collectors.CollectorOffline as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "rtt_ms": round((time.perf_counter() - started) * 1000, 1), **(result or {})}


# ================================================================ downloads
PLATFORM_HINTS = {
    "windows": ("windows", "win", ".exe"),
    "linux": ("linux",),
    "macos": ("macos", "darwin", "mac"),
}


def downloads_dir(request: Request) -> Path:
    configured = request.app.state.settings.downloads_dir
    if configured:
        return Path(configured)
    db_path = Path(request.app.state.settings.database)
    return (app_dir() if is_frozen() else db_path.resolve().parent) / "downloads"


def _platform_of(name: str) -> str:
    low = name.lower()
    if low.endswith(".exe") or "windows" in low or "-win" in low:
        return "windows"
    if "mac" in low or "darwin" in low:
        return "macos"
    if "linux" in low:
        return "linux"
    return ""


def _self_platform() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def available_downloads(request: Request) -> list[dict[str, Any]]:
    """Executables this server can hand to collectors."""
    items: list[dict[str, Any]] = []
    folder = downloads_dir(request)
    if folder.is_dir():
        for f in sorted(folder.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                items.append({"name": f.name, "platform": _platform_of(f.name), "size": f.stat().st_size,
                              "source": "downloads folder"})
    if is_frozen() and not any(i["platform"] == _self_platform() for i in items):
        exe = Path(sys.executable)
        items.append({"name": f"SNMPathy-{_self_platform()}{exe.suffix}", "platform": _self_platform(),
                      "size": exe.stat().st_size, "source": "this server's executable", "self": True})
    if not is_frozen():
        items.append({"name": f"snmpathy-{__version__}.tar.gz", "platform": "python", "size": None,
                      "source": "Python package (pip install, any OS with Python 3.10+)", "sdist": True})
    return items


def _find_download(request: Request, name: str) -> dict[str, Any] | None:
    return next((i for i in available_downloads(request) if i["name"] == name), None)


def build_sdist() -> bytes:
    """A pip-installable source archive of the running SNMPathy package."""
    from importlib import metadata

    pkg = Path(__file__).resolve().parent
    try:
        requires = [r for r in (metadata.requires("snmpathy") or []) if "extra ==" not in r]
    except metadata.PackageNotFoundError:
        requires = ["fastapi>=0.110", "uvicorn[standard]>=0.27", "jinja2>=3.1", "pysnmp>=7.1", "httpx>=0.27",
                    "pyyaml>=6.0", "python-multipart>=0.0.9", "cryptography>=42"]
    deps = ",\n    ".join(f'"{r}"' for r in requires)
    pyproject = f"""[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "snmpathy"
version = "{__version__}"
requires-python = ">=3.10"
dependencies = [
    {deps}
]

[project.scripts]
snmpathy = "snmpathy.cli:main"

[tool.setuptools.packages.find]
include = ["snmpathy*"]

[tool.setuptools.package-data]
snmpathy = ["web/templates/*.html", "web/static/*"]
"""
    root = f"snmpathy-{__version__}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = pyproject.encode()
        info = tarfile.TarInfo(f"{root}/pyproject.toml")
        info.size, info.mtime = len(data), int(time.time())
        tar.addfile(info, io.BytesIO(data))
        for path in pkg.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo"):
                tar.add(path, arcname=f"{root}/snmpathy/{path.relative_to(pkg).as_posix()}")
    return buf.getvalue()


@router.get("/collector/downloads", include_in_schema=False)
def list_downloads(request: Request):
    return available_downloads(request)


@router.get("/collector/download/{name}", include_in_schema=False)
def download(name: str, request: Request, os_: str = "", arch: str = ""):
    if name == "auto":
        wanted = {"windows_nt": "windows", "windows": "windows", "darwin": "macos", "macos": "macos",
                  "linux": "linux"}.get(os_.lower(), "")
        candidates = [i for i in available_downloads(request) if i["platform"] == wanted]
        if arch:
            preferred = [i for i in candidates if arch.lower() in i["name"].lower()
                         or (arch.lower() in ("x86_64", "amd64") and ("x64" in i["name"].lower() or "amd64" in i["name"].lower()))]
            candidates = preferred or candidates
        if not candidates:
            raise HTTPException(404, f"no collector executable for {os_ or 'this OS'} on this server")
        item = candidates[0]
    else:
        item = _find_download(request, name)
        if not item:
            raise HTTPException(404, "no such download")
    if item.get("sdist"):
        return Response(build_sdist(), media_type="application/gzip",
                        headers={"Content-Disposition": f'attachment; filename="{item["name"]}"'})
    path = Path(sys.executable) if item.get("self") else downloads_dir(request) / item["name"]
    return FileResponse(path, filename=item["name"], media_type="application/octet-stream")


@router.get("/collector/install.sh", include_in_schema=False, response_class=PlainTextResponse)
def install_sh(request: Request):
    return PlainTextResponse(INSTALL_SH.replace("@@SERVER@@", _base_url(request)).replace("@@VERSION@@", __version__),
                             media_type="text/x-shellscript")


@router.get("/collector/install.ps1", include_in_schema=False, response_class=PlainTextResponse)
def install_ps1(request: Request):
    return PlainTextResponse(INSTALL_PS1.replace("@@SERVER@@", _base_url(request)).replace("@@VERSION@@", __version__),
                             media_type="text/plain")


INSTALL_SH = r"""#!/usr/bin/env bash
# SNMPathy collector installer for Linux and macOS (generated by @@SERVER@@).
#   curl -fsSL @@SERVER@@/collector/install.sh | sudo bash -s -- --token col_xxx
# Options: --token TOKEN (required)  --server URL  --insecure  --uninstall
set -euo pipefail
SERVER="@@SERVER@@"; TOKEN=""; INSECURE=0; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2;;
    --server) SERVER="$2"; shift 2;;
    --insecure) INSECURE=1; shift;;
    --uninstall) UNINSTALL=1; shift;;
    *) echo "unknown option $1" >&2; exit 2;;
  esac
done
[ "$(id -u)" = "0" ] || { echo "please run as root (sudo)" >&2; exit 1; }
OS="$(uname -s)"; ARCH="$(uname -m)"
DIR=/opt/snmpathy-collector; CONF=/etc/snmpathy/collector.yaml; STATE=/var/lib/snmpathy-collector
CURL="curl -fsSL"; [ "$INSECURE" = 1 ] && CURL="$CURL -k"

if [ "$UNINSTALL" = 1 ]; then
  if [ "$OS" = "Darwin" ]; then launchctl unload /Library/LaunchDaemons/com.snmpathy.collector.plist 2>/dev/null || true; rm -f /Library/LaunchDaemons/com.snmpathy.collector.plist
  else systemctl disable --now snmpathy-collector 2>/dev/null || true; rm -f /etc/systemd/system/snmpathy-collector.service; systemctl daemon-reload || true; fi
  rm -rf "$DIR"; echo "SNMPathy collector removed (config $CONF and buffer $STATE kept)."; exit 0
fi
[ -n "$TOKEN" ] || { echo "--token is required (create a collector in SNMPathy > Collectors)" >&2; exit 2; }

mkdir -p "$DIR" "$(dirname "$CONF")" "$STATE"
BIN="$DIR/snmpathy"
echo "Downloading the collector for $OS/$ARCH from $SERVER ..."
if $CURL "$SERVER/collector/download/auto?os_=$OS&arch=$ARCH" -o "$BIN.new" 2>/dev/null; then
  mv "$BIN.new" "$BIN"; chmod 755 "$BIN"
else
  rm -f "$BIN.new"
  echo "No prebuilt executable on the server; installing the Python package instead."
  PY="$(command -v python3 || true)"
  [ -n "$PY" ] || { echo "python3 (3.10+) is required" >&2; exit 1; }
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo "python 3.10+ is required" >&2; exit 1; }
  "$PY" -m venv "$DIR/venv"
  PKG="$($CURL "$SERVER/collector/downloads" | "$PY" -c 'import json,sys; print(next(i["name"] for i in json.load(sys.stdin) if i["platform"]=="python"))')"
  $CURL "$SERVER/collector/download/$PKG" -o "$DIR/$PKG"
  "$DIR/venv/bin/pip" install --quiet --upgrade pip
  "$DIR/venv/bin/pip" install --quiet "$DIR/$PKG"
  ln -sf "$DIR/venv/bin/snmpathy" "$BIN"
fi

umask 077
cat > "$CONF" <<EOF
server: $SERVER
token: $TOKEN
verify_tls: $([ "$INSECURE" = 1 ] && echo false || echo true)
state_dir: $STATE
EOF
echo "Wrote $CONF"

if [ "$OS" = "Darwin" ]; then
  cat > /Library/LaunchDaemons/com.snmpathy.collector.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.snmpathy.collector</string>
  <key>ProgramArguments</key><array><string>$BIN</string><string>collector</string><string>--config</string><string>$CONF</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/snmpathy-collector.log</string>
  <key>StandardErrorPath</key><string>/var/log/snmpathy-collector.log</string>
</dict></plist>
EOF
  launchctl unload /Library/LaunchDaemons/com.snmpathy.collector.plist 2>/dev/null || true
  launchctl load -w /Library/LaunchDaemons/com.snmpathy.collector.plist
else
  cat > /etc/systemd/system/snmpathy-collector.service <<EOF
[Unit]
Description=SNMPathy remote collector
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN collector --config $CONF
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_RAW
StateDirectory=snmpathy-collector

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now snmpathy-collector
  systemctl restart snmpathy-collector
fi
echo "SNMPathy collector installed and running. It should show as online in SNMPathy within a few seconds."
"""


INSTALL_PS1 = r"""# SNMPathy collector installer for Windows (generated by @@SERVER@@).
# Run in an elevated PowerShell:
#   & ([scriptblock]::Create((iwr -UseBasicParsing '@@SERVER@@/collector/install.ps1').Content)) -Token 'col_xxx'
param(
    [string]$Token = "",
    [string]$Server = "@@SERVER@@",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "SNMPathy Collector"),
    [string]$TaskName = "SNMPathy Collector",
    [switch]$Insecure,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run this from an elevated (Administrator) PowerShell."
}
$stateDir = Join-Path $env:ProgramData "SNMPathy Collector"
if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host "SNMPathy collector removed (buffer and config in $stateDir kept)."
    return
}
if (-not $Token) { throw "-Token is required (create a collector in SNMPathy > Collectors)." }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($Insecure) {
    add-type "using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint a, X509Certificate b, WebRequest c, int d) { return true; } }"
    [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
}
New-Item -ItemType Directory -Force -Path $InstallDir, $stateDir | Out-Null
$exe = Join-Path $InstallDir "snmpathy-collector.exe"
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
Write-Host "Downloading the collector from $Server ..."
$command = $null
try {
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/collector/download/auto?os_=Windows&arch=$env:PROCESSOR_ARCHITECTURE" -OutFile $exe
    $command = $exe; $prefix = @()
} catch {
    Write-Host "No prebuilt Windows executable on the server; installing the Python package instead."
    $py = (Get-Command py -ErrorAction SilentlyContinue)
    if (-not $py) { $py = (Get-Command python -ErrorAction SilentlyContinue) }
    if (-not $py) { throw "Python 3.10+ is required (or copy SNMPathy.exe into the server's downloads folder)." }
    $venv = Join-Path $InstallDir "venv"
    & $py.Source -m venv $venv
    $list = Invoke-RestMethod -UseBasicParsing "$Server/collector/downloads"
    $pkg = ($list | Where-Object { $_.platform -eq "python" } | Select-Object -First 1).name
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/collector/download/$pkg" -OutFile (Join-Path $InstallDir $pkg)
    & (Join-Path $venv "Scripts\pip.exe") install --quiet (Join-Path $InstallDir $pkg)
    $command = Join-Path $venv "Scripts\snmpathy.exe"
}
$conf = Join-Path $stateDir "collector.yaml"
@"
server: $Server
token: $Token
verify_tls: $(if ($Insecure) { 'false' } else { 'true' })
state_dir: $($stateDir -replace '\\','/')
"@ | Set-Content -Encoding UTF8 $conf
icacls $conf /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
$action = New-ScheduledTaskAction -Execute $command -Argument "collector --config `"$conf`"" -WorkingDirectory $stateDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "SNMPathy collector installed and running (scheduled task '$TaskName'). It should show as online in SNMPathy within a few seconds."
"""
