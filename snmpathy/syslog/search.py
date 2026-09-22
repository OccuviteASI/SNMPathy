"""Syslog search, histograms and top-N aggregations."""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from ..db import Database
from .parser import FACILITIES, SEVERITIES


@dataclass
class SyslogFilter:
    q: str = ""
    host: str = ""
    app: str = ""
    device_id: int | None = None
    severity: int | None = None       # show this severity and anything more severe
    facility: int | None = None
    start: float | None = None
    end: float | None = None

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> "SyslogFilter":
        def num(name: str, conv=float):
            value = params.get(name)
            if value in (None, ""):
                return None
            try:
                return conv(value)
            except (TypeError, ValueError):
                return None

        severity = params.get("severity")
        if isinstance(severity, str) and severity in SEVERITIES:
            severity = SEVERITIES.index(severity)
        else:
            severity = num("severity", int)
        facility = params.get("facility")
        if isinstance(facility, str) and facility in FACILITIES:
            facility = FACILITIES.index(facility)
        else:
            facility = num("facility", int)
        start = num("start")
        end = num("end")
        since = params.get("since")
        if since and start is None:
            start = time.time() - parse_duration(str(since))
        return cls(
            q=str(params.get("q") or "").strip(),
            host=str(params.get("host") or "").strip(),
            app=str(params.get("app") or "").strip(),
            device_id=num("device_id", int),
            severity=severity,
            facility=facility,
            start=start,
            end=end,
        )


def parse_duration(text: str) -> float:
    """``"15m"`` -> 900, ``"24h"`` -> 86400, ``"7d"`` -> 604800, plain numbers are seconds."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*", text or "")
    if not match:
        return 3600.0
    value = float(match.group(1))
    return value * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2)]


def _fts_query(q: str) -> str:
    """Turn free text into a safe FTS5 query (each token as a phrase / prefix)."""
    tokens = re.findall(r'"[^"]+"|\S+', q)
    parts = []
    for tok in tokens:
        upper = tok.upper()
        if upper in {"AND", "OR", "NOT"}:
            parts.append(upper)
            continue
        negate = tok.startswith("-") and len(tok) > 1
        if negate:
            tok = tok[1:]
        prefix = tok.endswith("*") and not tok.startswith('"')
        tok = tok.strip('"').rstrip("*").replace('"', '""')
        if not tok:
            continue
        phrase = f'"{tok}"' + ("*" if prefix else "")
        parts.append(f"NOT {phrase}" if negate else phrase)
    # FTS5 does not allow a leading NOT.
    while parts and parts[0].startswith("NOT"):
        parts.pop(0)
    return " ".join(parts)


def _where(db: Database, f: SyslogFilter, use_fts: bool = True) -> tuple[str, str, list[Any]]:
    join = ""
    clauses: list[str] = []
    params: list[Any] = []
    if f.q:
        fts = _fts_query(f.q) if (db.has_fts and use_fts) else ""
        if fts:
            join = "JOIN syslog_fts ON syslog_fts.rowid = syslog.id"
            clauses.append("syslog_fts MATCH ?")
            params.append(fts)
        else:
            for word in re.findall(r'"[^"]+"|\S+', f.q):
                word = word.strip('"')
                if word.startswith("-") and len(word) > 1:
                    clauses.append("syslog.message NOT LIKE ?")
                    params.append(f"%{word[1:]}%")
                else:
                    clauses.append("(syslog.message LIKE ? OR syslog.host LIKE ? OR syslog.app LIKE ?)")
                    params.extend([f"%{word}%"] * 3)
    if f.host:
        if "*" in f.host:
            clauses.append("(syslog.host LIKE ? OR syslog.source_ip LIKE ?)")
            params.extend([f.host.replace("*", "%")] * 2)
        else:
            clauses.append("(syslog.host = ? OR syslog.source_ip = ?)")
            params.extend([f.host, f.host])
    if f.app:
        clauses.append("syslog.app LIKE ?")
        params.append(f.app.replace("*", "%"))
    if f.device_id is not None:
        clauses.append("syslog.device_id = ?")
        params.append(f.device_id)
    if f.severity is not None:
        clauses.append("syslog.severity <= ?")
        params.append(f.severity)
    if f.facility is not None:
        clauses.append("syslog.facility = ?")
        params.append(f.facility)
    if f.start is not None:
        clauses.append("syslog.ts >= ?")
        params.append(f.start)
    if f.end is not None:
        clauses.append("syslog.ts <= ?")
        params.append(f.end)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return join, where, params


def _run(db: Database, f: SyslogFilter, build) -> list[dict[str, Any]]:
    join, where, params = _where(db, f)
    try:
        return db.query(*build(join, where, params))
    except sqlite3.OperationalError:
        if not f.q:
            raise
        join, where, params = _where(db, f, use_fts=False)
        return db.query(*build(join, where, params))


def search(db: Database, f: SyslogFilter, limit: int = 200, before_id: int | None = None) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 5000))

    def build(join: str, where: str, params: list[Any]):
        p = list(params)
        if before_id:
            where = (where + " AND " if where else "WHERE ") + "syslog.id < ?"
            p.append(before_id)
        return (
            f"SELECT syslog.* FROM syslog {join} {where} ORDER BY syslog.id DESC LIMIT ?",
            p + [limit],
        )

    rows = _run(db, f, build)
    for row in rows:
        sev = row.get("severity")
        fac = row.get("facility")
        row["severity_name"] = SEVERITIES[sev] if sev is not None and 0 <= sev < 8 else ""
        row["facility_name"] = FACILITIES[fac] if fac is not None and 0 <= fac < 24 else ""
    return rows


def count(db: Database, f: SyslogFilter) -> int:
    rows = _run(db, f, lambda j, w, p: (f"SELECT COUNT(*) AS n FROM syslog {j} {w}", p))
    return int(rows[0]["n"]) if rows else 0


def histogram(db: Database, f: SyslogFilter, buckets: int = 60) -> dict[str, Any]:
    end = f.end or time.time()
    start = f.start or end - 86400
    step = max(1, int((end - start) / max(1, buckets)))
    bounded = SyslogFilter(**{**f.__dict__, "start": start, "end": end})

    def build(join: str, where: str, params: list[Any]):
        return (
            f"SELECT CAST((syslog.ts - ?) / ? AS INTEGER) AS b, "
            f"SUM(CASE WHEN syslog.severity <= 3 THEN 1 ELSE 0 END) AS error, "
            f"SUM(CASE WHEN syslog.severity = 4 THEN 1 ELSE 0 END) AS warning, "
            f"SUM(CASE WHEN syslog.severity >= 5 OR syslog.severity IS NULL THEN 1 ELSE 0 END) AS info "
            f"FROM syslog {join} {where} GROUP BY b ORDER BY b",
            [start, step, *params],
        )

    rows = {r["b"]: r for r in _run(db, bounded, build)}
    out = []
    for i in range(int((end - start) // step) + 1):
        r = rows.get(i, {})
        out.append({
            "ts": start + i * step,
            "error": r.get("error") or 0,
            "warning": r.get("warning") or 0,
            "info": r.get("info") or 0,
        })
    return {"start": start, "end": end, "step": step, "buckets": out}


def top(db: Database, f: SyslogFilter, field: str, limit: int = 10) -> list[dict[str, Any]]:
    if field not in {"host", "app", "severity", "facility", "source_ip"}:
        raise ValueError(f"cannot aggregate on {field!r}")

    def build(join: str, where: str, params: list[Any]):
        return (
            f"SELECT syslog.{field} AS value, COUNT(*) AS count FROM syslog {join} {where} "
            f"GROUP BY syslog.{field} ORDER BY count DESC LIMIT ?",
            [*params, limit],
        )

    return _run(db, f, build)
