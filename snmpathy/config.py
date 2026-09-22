"""Runtime configuration.

Settings are resolved in this order (later wins):
  1. built-in defaults
  2. a YAML file (``--config`` flag or ``SNMPATHY_CONFIG``)
  3. environment variables prefixed with ``SNMPATHY_`` (e.g. ``SNMPATHY_HTTP_PORT=8080``)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


@dataclass
class Settings:
    # Storage
    database: str = "snmpathy.db"

    # Web / API
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    # When set, every API/UI request must present this token (header
    # ``Authorization: Bearer <token>``, ``X-API-Key``, or the login cookie).
    api_token: str = ""
    # External URL of this server, used for links in notifications and reports.
    public_url: str = ""

    # Syslog listeners (set a port to 0 to disable that listener)
    syslog_host: str = "0.0.0.0"
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5514
    syslog_batch_size: int = 500
    syslog_flush_interval: float = 1.0

    # Poller
    default_poll_interval: int = 300
    default_check_interval: int = 60
    poller_concurrency: int = 64
    snmp_timeout: float = 2.0
    snmp_retries: int = 1

    # Retention (days)
    retention_raw_days: int = 7
    retention_rollup_days: int = 400
    retention_syslog_days: int = 30
    retention_heartbeat_days: int = 90

    # Alerting
    alert_eval_interval: int = 30
    smtp_host: str = ""
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "snmpathy@localhost"
    smtp_starttls: bool = False

    # Background services can be disabled (handy for tests / API-only nodes)
    enable_poller: bool = True
    enable_syslog: bool = True
    enable_alerting: bool = True

    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | os.PathLike | None = None, env: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if env is None else env)
        data: dict[str, Any] = {}
        path = path or env.get("SNMPATHY_CONFIG")
        if path:
            data.update(_load_yaml(Path(path)))
        known = {f.name: f for f in fields(cls) if f.name != "extra"}
        for name in known:
            key = f"SNMPATHY_{name.upper()}"
            if key in env:
                data[name] = env[key]
        kwargs: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for key, value in data.items():
            if key in known:
                kwargs[key] = _coerce(value, known[key].type)
            else:
                extra[key] = value
        settings = cls(**kwargs)
        settings.extra = extra
        return settings


def _load_yaml(path: Path) -> dict[str, Any]:
    import yaml

    with path.open() as fh:
        loaded = yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"config file {path} must contain a mapping")
    return loaded


def _coerce(value: Any, type_name: Any) -> Any:
    type_name = str(type_name)
    if type_name == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
    if type_name == "int":
        return int(value)
    if type_name == "float":
        return float(value)
    if type_name == "str":
        return str(value)
    return value
