"""Open the host firewall for SNMPathy's listeners (syslog first and foremost).

Backends:

* **Windows**   - Windows Defender Firewall rules via ``netsh advfirewall`` (one inbound
  rule per port, named ``SNMPathy …``). Needs Administrator: when SNMPathy is not
  elevated, a UAC prompt is raised on the SNMPathy computer.
* **firewalld** - ``firewall-cmd --permanent --add-port`` + reload (RHEL, Fedora, SUSE).
* **ufw**       - ``ufw allow <port>/<proto>`` (Ubuntu, Debian).
* **macOS**     - the application firewall is per application, not per port: SNMPathy's
  executable (or Python) is added and unblocked with ``socketfilterfw``.

Linux and macOS commands run directly as root, else through ``sudo -n`` (no password
prompt); when neither works the exact commands are returned for the user to run.
Only integers from the settings go into the commands - nothing user-typed.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import Settings

GROUPS: dict[str, str] = {
    "syslog": "Syslog (UDP and TCP)",
    "web": "Web UI and API",
    "logs": "GELF / JSON log inputs",
    "flows": "NetFlow / IPFIX / sFlow",
}
DEFAULT_GROUPS = ("syslog",)
MAC_FW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


@dataclass
class Rule:
    group: str
    label: str
    proto: str  # udp / tcp
    port: int

    @property
    def name(self) -> str:
        return f"SNMPathy {self.label} {self.proto.upper()} {self.port}"


def wanted_rules(settings: Settings, groups: list[str] | tuple[str, ...] = DEFAULT_GROUPS) -> list[Rule]:
    rules: list[Rule] = []

    def add(group: str, label: str, proto: str, port: Any) -> None:
        if group in groups and port and int(port) > 0:
            rules.append(Rule(group, label, proto, int(port)))

    if settings.enable_syslog:
        add("syslog", "Syslog", "udp", settings.syslog_udp_port)
        add("syslog", "Syslog", "tcp", settings.syslog_tcp_port)
    add("web", "Web", "tcp", settings.http_port)
    if settings.enable_syslog:
        add("logs", "GELF", "udp", getattr(settings, "gelf_udp_port", 0))
        add("logs", "JSON logs", "tcp", getattr(settings, "json_tcp_port", 0))
        add("logs", "JSON logs", "udp", getattr(settings, "json_udp_port", 0))
    add("flows", "NetFlow", "udp", getattr(settings, "netflow_port", 0))
    add("flows", "IPFIX", "udp", getattr(settings, "ipfix_port", 0))
    add("flows", "sFlow", "udp", getattr(settings, "sflow_port", 0))
    # The same port can serve several protocols (e.g. one flow port); keep one rule per port/proto.
    seen, unique = set(), []
    for r in rules:
        if (r.proto, r.port) not in seen:
            seen.add((r.proto, r.port))
            unique.append(r)
    return unique


# ----------------------------------------------------------------- helpers
def _run(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def _quiet(argv: list[str]) -> int:
    try:
        return _run(argv, timeout=15).returncode
    except (OSError, subprocess.SubprocessError):
        return 1


def _in_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("container") is not None


def is_admin() -> bool:
    if sys.platform.startswith("win"):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def detect_backend() -> str:
    if _in_container():
        return "container"
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if shutil.which("firewall-cmd") and _quiet(["firewall-cmd", "--state"]) == 0:
        return "firewalld"
    if shutil.which("ufw"):
        return "ufw"
    return "none"


def _app_binary() -> str:
    return sys.executable


# --------------------------------------------------------------- commands
def commands(backend: str, rules: list[Rule], remove: bool = False) -> list[list[str]]:
    """The commands that add (or remove) ``rules`` with ``backend``."""
    out: list[list[str]] = []
    if backend == "windows":
        for r in rules:
            if remove:
                out.append(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r.name}"])
            else:
                out.append(["netsh", "advfirewall", "firewall", "add", "rule", f"name={r.name}", "dir=in",
                            "action=allow", f"protocol={r.proto.upper()}", f"localport={r.port}", "profile=any"])
    elif backend == "firewalld":
        for r in rules:
            out.append(["firewall-cmd", "--permanent", f"--{'remove' if remove else 'add'}-port={r.port}/{r.proto}"])
        if rules:
            out.append(["firewall-cmd", "--reload"])
    elif backend == "ufw":
        for r in rules:
            if remove:
                out.append(["ufw", "--force", "delete", "allow", f"{r.port}/{r.proto}"])
            else:
                out.append(["ufw", "allow", f"{r.port}/{r.proto}", "comment", r.name])
    elif backend == "macos":
        app = _app_binary()
        out = [[MAC_FW, "--remove", app]] if remove else [[MAC_FW, "--add", app], [MAC_FW, "--unblockapp", app]]
    elif backend == "none":
        for r in rules:
            flag = "-D" if remove else "-I"
            out.append(["iptables", flag, "INPUT", "-p", r.proto, "--dport", str(r.port), "-j", "ACCEPT"])
    return out


def shell_text(backend: str, cmds: list[list[str]]) -> str:
    """Commands as text the user can paste (PowerShell / cmd on Windows, a shell elsewhere)."""
    import shlex

    if backend == "windows":
        return "\n".join(" ".join(f'"{a}"' if " " in a else a for a in c) for c in cmds)
    prefix = "" if is_admin() else "sudo "
    return "\n".join(prefix + shlex.join(c) for c in cmds)


# ----------------------------------------------------------------- status
def rule_present(backend: str, rule: Rule) -> bool | None:
    """True / False when it can be checked without extra privileges, else None."""
    try:
        if backend == "windows":
            return _quiet(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule.name}"]) == 0
        if backend == "firewalld":
            return _quiet(["firewall-cmd", f"--query-port={rule.port}/{rule.proto}"]) == 0
        if backend == "ufw" and is_admin():
            out = _run(["ufw", "status"]).stdout
            return any(line.split()[0] in (f"{rule.port}/{rule.proto}", f"{rule.port}")
                       for line in out.splitlines() if line.strip() and "ALLOW" in line)
    except (OSError, subprocess.SubprocessError, IndexError):
        return None
    return None


def macos_state() -> dict[str, Any]:
    try:
        on = "enabled" in _run([MAC_FW, "--getglobalstate"]).stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return {"enabled": None, "app_allowed": None}
    allowed = None
    try:
        out = _run([MAC_FW, "--getappblocked", _app_binary()]).stdout.lower()
        allowed = "permitted" in out or "not blocked" in out
    except (OSError, subprocess.SubprocessError):
        pass
    return {"enabled": on, "app_allowed": allowed}


NOTES = {
    "windows": "Adds inbound allow rules to Windows Defender Firewall (all profiles). Needs Administrator; "
               "if SNMPathy is not running elevated you will get a UAC prompt on this computer.",
    "firewalld": "Adds permanent firewalld ports to the default zone and reloads.",
    "ufw": "Adds ufw allow rules.",
    "macos": "The macOS firewall works per application: SNMPathy is allowed to accept incoming connections "
             "on all of its ports.",
    "none": "No managed firewall (firewalld or ufw) was found, so nothing is changed automatically. "
            "If you use nftables / iptables directly, the commands below open the ports (make them persistent "
            "with your distribution's tooling).",
    "container": "Running in a container: publish the ports instead (docker-compose.yml maps syslog 514 to 5514).",
}


def status(settings: Settings, groups: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
    backend = detect_backend()
    rules = wanted_rules(settings, groups or tuple(GROUPS))
    info: dict[str, Any] = {
        "backend": backend, "admin": is_admin(), "note": NOTES.get(backend, ""),
        "groups": GROUPS, "default_groups": list(DEFAULT_GROUPS),
        "rules": [{**asdict(r), "name": r.name, "present": rule_present(backend, r) if backend != "macos" else None}
                  for r in rules],
        "can_apply": backend in ("windows", "firewalld", "ufw", "macos"),
    }
    if backend == "macos":
        info["macos"] = macos_state()
        if info["macos"]["enabled"] is False:
            info["note"] = "The macOS firewall is off, so nothing blocks SNMPathy's ports."
    if 0 < settings.syslog_udp_port < 1024 or 0 < settings.syslog_tcp_port < 1024:
        info["note"] += " Ports below 1024 also need SNMPathy to run with elevated rights."
    return info


# ------------------------------------------------------------------ apply
def apply(settings: Settings, groups: list[str] | tuple[str, ...] = DEFAULT_GROUPS, remove: bool = False) -> dict[str, Any]:
    """Add (or remove) the rules. Returns what ran, its output, or the commands to run by hand."""
    unknown = [g for g in groups if g not in GROUPS]
    if unknown:
        raise ValueError(f"unknown group(s): {', '.join(unknown)}")
    backend = detect_backend()
    rules = wanted_rules(settings, groups)
    cmds = commands(backend, rules, remove)
    result: dict[str, Any] = {"backend": backend, "ok": False, "applied": False, "manual": "",
                              "output": "", "rules": [r.name for r in rules]}
    if not rules and backend != "macos":
        result.update(ok=True, output="No enabled listeners in the selected groups.")
        return result
    if backend in ("container", "none"):
        result["manual"] = shell_text(backend, cmds) if backend == "none" else ""
        result["output"] = NOTES[backend]
        return result
    if backend == "windows" and not is_admin():
        return _windows_elevated(cmds, result)
    prefix: list[str] = []
    if backend != "windows" and not is_admin():
        if shutil.which("sudo") and _quiet(["sudo", "-n", "true"]) == 0:
            prefix = ["sudo", "-n"]
        else:
            result["manual"] = shell_text(backend, cmds)
            result["output"] = ("SNMPathy is not running as root and sudo needs a password, so the rules were not "
                                "added. Run these commands in a terminal:")
            return result
    outputs, ok = [], True
    for c in cmds:
        try:
            r = _run(prefix + c, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            outputs.append(f"$ {' '.join(c)}\n{exc}")
            ok = False
            continue
        outputs.append(f"$ {' '.join(c)}\n{(r.stdout + r.stderr).strip()}")
        # Removing a rule that is not there is fine.
        if r.returncode != 0 and not remove:
            ok = False
    result.update(ok=ok, applied=ok, output="\n".join(outputs))
    if not ok:
        result["manual"] = shell_text(backend, cmds)
    return result


def _windows_elevated(cmds: list[list[str]], result: dict[str, Any]) -> dict[str, Any]:
    """Run the netsh commands through a UAC prompt on this computer."""
    script = Path(tempfile.gettempdir()) / "snmpathy-firewall.cmd"
    lines = ["@echo off"] + [" ".join(f'"{a}"' if " " in a else a for a in c) for c in cmds]
    script.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    ps = (f"$p = Start-Process -FilePath cmd.exe -ArgumentList '/c', '\"{script}\"' -Verb RunAs "
          f"-WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode")
    result["manual"] = shell_text("windows", cmds)
    try:
        r = _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        result["output"] = f"Could not request elevation: {exc}. Run these in an Administrator command prompt:"
        return result
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if r.returncode == 0:
        result.update(ok=True, applied=True, manual="",
                      output="Approved in the Windows UAC prompt; the firewall rules were updated.")
    else:
        result["output"] = ("The UAC prompt was declined or failed (it appears on the SNMPathy computer's screen). "
                            "Run these in an Administrator command prompt instead:\n" + (r.stderr or "").strip())
    return result
