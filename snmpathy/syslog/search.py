"""Syslog search, histograms, top-N aggregations and field discovery.

Query language (Lucene / Kibana flavoured)::

    error                      free text (FTS5 when available, else LIKE)
    "changed state to down"    quoted phrase
    fail*   *timeout*          wildcards (``*``)
    -debug   NOT debug         negation (also ``-host:sw1``, ``NOT (a OR b)``)
    a OR b   a AND b   (a OR b) c
                               boolean operators (upper case), implicit AND
    host:core-sw1              hostname or source IP (``host:10.0.0.0/8`` too)
    app:sshd  msgid:4625  procid:123  message:"link down"
    severity:err  severity:<=3  severity:<=warning
                               lower numbers are more severe
    facility:local7  facility:>=16
    source_ip:10.0.0.0/8       CIDR, wildcard (``10.0.*``) or exact
    device_id:5
    EventID:4625  user.name:bob  bytes:>1000
                               any other field is looked up in the flattened
                               JSON stored in ``syslog.structured``
    field:*                    field is present / not empty

Field names of the fixed columns are case-insensitive; structured keys are
matched exactly as stored. ``SyslogFilter.must`` / ``must_not`` hold
``(field, value)`` pairs (from filter pills) matched literally.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import time
from collections import Counter
from dataclasses import dataclass, field as _dc_field, replace
from functools import lru_cache
from typing import Any, Iterable

from ..db import Database
from .parser import FACILITIES, SEVERITIES, SEVERITY_LABELS


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
    # (field, value) pairs that must / must not match (filter pills). A value
    # of None means "field is missing or empty".
    must: list[tuple[str, Any]] = _dc_field(default_factory=list)
    must_not: list[tuple[str, Any]] = _dc_field(default_factory=list)

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
            must=parse_pairs(params.get("must")),
            must_not=parse_pairs(params.get("must_not")),
        )


def parse_pairs(value: Any, limit: int = 50) -> list[tuple[str, Any]]:
    """Filter pills from a query parameter.

    Accepts a JSON list of ``[field, value]`` pairs / ``{"field", "value"}``
    objects / ``"field:value"`` strings, a single ``"field:value"`` string, or
    the same structures already decoded.
    """
    if value in (None, "", [], ()):
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            value = [value]
    if isinstance(value, (str, dict)):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    if len(value) == 2 and all(isinstance(v, (str, int, float)) or v is None for v in value) \
            and isinstance(value[0], str) and ":" not in value[0]:
        value = [value]  # a single bare pair
    out: list[tuple[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            name, val = item.get("field"), item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            name, val = item
        elif isinstance(item, str) and ":" in item:
            name, _, val = item.partition(":")
        else:
            continue
        if not name or not isinstance(name, str):
            continue
        out.append((name.strip(), None if val is None else str(val)))
        if len(out) >= limit:
            break
    return out


def parse_duration(text: str) -> float:
    """``"15m"`` -> 900, ``"24h"`` -> 86400, ``"7d"`` -> 604800, plain numbers are seconds."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*", text or "")
    if not match:
        return 3600.0
    value = float(match.group(1))
    return value * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2)]


def _fts_query(q: str) -> str:
    """Turn free text into a safe FTS5 query (each token as a phrase / prefix).

    Kept for backward compatibility; :func:`_where` now compiles the full
    query language.
    """
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


# ================================================================ query language
@dataclass
class Text:
    text: str
    phrase: bool = False


@dataclass
class Field:
    name: str
    value: str | None
    op: str = ""          # "", "<", "<=", ">", ">="
    phrase: bool = False  # value was quoted: no wildcards / operators
    exact: bool = False   # literal value (filter pills)


@dataclass
class Not:
    child: Any


@dataclass
class And:
    children: list[Any]


@dataclass
class Or:
    children: list[Any]


_FIELD_RE = re.compile(r"([A-Za-z_@][\w.@\-]*):(?=[^\s)])")
_HEXISH = re.compile(r"^[0-9A-Fa-f]{1,4}$")
_OPS = ("<=", ">=", "<", ">", "=")


def _tokenize(q: str) -> list[tuple]:
    """Tokens: ("(",) (")",) ("OR",) ("AND",) ("NOT",) ("TERM", field, value, quoted, neg)."""
    toks: list[tuple] = []
    i, n, depth = 0, len(q), 0

    def quoted(pos: int) -> tuple[str, int]:
        out = []
        pos += 1
        while pos < n:
            ch = q[pos]
            if ch == "\\" and pos + 1 < n and q[pos + 1] in '"\\':
                out.append(q[pos + 1])
                pos += 2
                continue
            if ch == '"':
                return "".join(out), pos + 1
            out.append(ch)
            pos += 1
        return "".join(out), pos  # unterminated: rest of the string

    def bare(pos: int) -> tuple[str, int]:
        start = pos
        while pos < n and not q[pos].isspace() and not (q[pos] == ")" and depth > 0):
            pos += 1
        return q[start:pos], pos

    while i < n:
        ch = q[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            toks.append(("(",))
            depth += 1
            i += 1
            continue
        if ch == ")":
            toks.append((")",))
            depth = max(0, depth - 1)
            i += 1
            continue
        neg = False
        if ch in "-!" and i + 1 < n and not q[i + 1].isspace():
            if q[i + 1] == "(":
                toks.append(("NOT",))
                i += 1
                continue
            neg = True
            i += 1
        elif ch in "-!":
            i += 1  # a lone dash
            continue
        name = None
        m = _FIELD_RE.match(q, i)
        if m:
            candidate = m.group(1)
            # "aa:bb:cc:..." (MAC / IPv6) is text, not a field query.
            if not (_HEXISH.match(candidate) and _resolve(candidate)[0] == "json" and ":" in q[m.end():m.end() + 6]):
                name = candidate
                i = m.end()
        if i < n and q[i] == '"':
            value, i = quoted(i)
            is_quoted = True
        else:
            value, i = bare(i)
            is_quoted = False
        if name is None and not is_quoted and not neg and value in ("OR", "||", "AND", "&&", "NOT"):
            toks.append(({"||": "OR", "&&": "AND"}.get(value, value),))
            continue
        toks.append(("TERM", name, value, is_quoted, neg))
    return toks


class _Parser:
    def __init__(self, toks: list[tuple]):
        self.toks = toks
        self.i = 0

    def peek(self) -> tuple | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def parse(self) -> Any:
        parts = []
        while self.peek() is not None:
            if self.peek()[0] == ")":  # stray closing parenthesis
                self.i += 1
                continue
            node = self.or_()
            if node is not None:
                parts.append(node)
        return _and(parts)

    def or_(self) -> Any:
        parts = [self.and_()]
        while self.peek() is not None and self.peek()[0] == "OR":
            self.i += 1
            parts.append(self.and_())
        parts = [p for p in parts if p is not None]
        if not parts:
            return None
        return parts[0] if len(parts) == 1 else Or(parts)

    def and_(self) -> Any:
        parts = []
        while self.peek() is not None and self.peek()[0] not in ("OR", ")"):
            if self.peek()[0] == "AND":
                self.i += 1
                continue
            node = self.unary()
            if node is not None:
                parts.append(node)
        return _and(parts)

    def unary(self) -> Any:
        tok = self.toks[self.i]
        self.i += 1
        if tok[0] == "NOT":
            if self.peek() is None or self.peek()[0] in ("OR", ")", "AND"):
                return None
            child = self.unary()
            return Not(child) if child is not None else None
        if tok[0] == "(":
            node = self.or_()
            if self.peek() is not None and self.peek()[0] == ")":
                self.i += 1
            return node
        if tok[0] != "TERM":
            return None
        _, name, value, is_quoted, neg = tok
        node: Any
        if name:
            op = ""
            if not is_quoted:
                for candidate in _OPS:
                    if value.startswith(candidate) and len(value) > len(candidate):
                        op, value = candidate, value[len(candidate):]
                        break
                if op == "=":
                    op = ""
            node = Field(name, value, op=op, phrase=is_quoted)
        else:
            if not value or (not is_quoted and not value.strip("*")):
                return None
            node = Text(value, phrase=is_quoted)
        return Not(node) if neg else node


def _and(parts: list[Any]) -> Any:
    parts = [p for p in parts if p is not None]
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else And(parts)


def parse_query(q: str) -> Any:
    """Parse a query string into a tree of Text / Field / Not / And / Or (None if empty)."""
    return _Parser(_tokenize(q or "")).parse()


# ================================================================ field mapping
# Fixed columns (case-insensitive names and aliases).
_COLUMN_ALIASES = {
    "host": "host", "hostname": "host",
    "app": "app", "program": "app", "appname": "app", "application": "app", "tag": "app",
    "severity": "severity", "sev": "severity", "level": "severity",
    "facility": "facility", "fac": "facility",
    "source_ip": "source_ip", "sourceip": "source_ip", "ip": "source_ip",
    "msgid": "msgid", "msg_id": "msgid",
    "procid": "procid", "pid": "procid",
    "message": "message", "msg": "message",
    "device_id": "device_id", "device": "device_id",
    "id": "id",
}
# Structured keys that the JSON inputs move into a column (NXLog's EventID ->
# msgid, ...): match the column or the key, whichever is set.
_DUAL = {"eventid": ("msgid", "EventID"), "event_id": ("msgid", "event_id"),
         "sourcename": ("app", "SourceName"), "processid": ("procid", "ProcessID")}

COLUMN_FIELDS = ["host", "source_ip", "app", "severity", "facility", "procid", "msgid", "message", "device_id"]
_INT_COLUMNS = {"severity", "facility", "device_id", "id"}

_SEVERITY_NAMES: dict[str, int] = {name: i for i, name in enumerate(SEVERITIES)}
_SEVERITY_NAMES.update({label.lower(): i for i, label in enumerate(SEVERITY_LABELS)})
_SEVERITY_NAMES.update({"emergency": 0, "panic": 0, "critical": 2, "fatal": 2, "error": 3, "warn": 4,
                        "information": 6, "informational": 6, "trace": 7})


def _resolve(name: str) -> tuple[str, Any]:
    low = name.lower()
    if low in _COLUMN_ALIASES:
        return "column", _COLUMN_ALIASES[low]
    if low in _DUAL:
        return "dual", _DUAL[low]
    return "json", name


def canonical_field(name: str) -> str:
    """The canonical name of a field (``Hostname`` -> ``host``; structured keys unchanged)."""
    kind, info = _resolve(name)
    return info if kind == "column" else name


def _enum_value(column: str, value: str) -> int | None:
    text = value.strip().lower()
    if text.lstrip("-").isdigit():
        return int(text)
    if column == "severity":
        return _SEVERITY_NAMES.get(text)
    if column == "facility" and text in FACILITIES:
        return FACILITIES.index(text)
    return None


def _like(value: str, wildcards: bool = True, contains: bool = False) -> str:
    """Escape LIKE metacharacters; ``*`` becomes ``%`` when ``wildcards``."""
    out = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    if wildcards:
        out = out.replace("*", "%")
    return f"%{out}%" if contains else out


_ESC = " ESCAPE '\\'"


def _network(value: str):
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


@lru_cache(maxsize=256)
def _cached_network(spec: str):
    try:
        return ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return None


def _ip_in(ip: Any, spec: Any) -> int:
    """SQLite function ``snmpathy_ip_in(ip, cidr)``."""
    if not ip or not spec:
        return 0
    net = _cached_network(str(spec))
    if net is None:
        return 0
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return 0
    if addr.version != net.version:
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is None:
            return 0
        addr = mapped
    return 1 if addr in net else 0


def _caps(db: Database) -> dict[str, bool]:
    """Detect JSON1 and register the CIDR helper once per database connection."""
    caps = getattr(db, "_snmpathy_search_caps", None)
    if caps is not None:
        return caps
    caps = {"json": False, "cidr": False}
    try:
        db.query("SELECT json_valid('{}') AS ok, json_extract('{\"a\":1}', '$.a') AS v")
        caps["json"] = True
    except sqlite3.OperationalError:
        pass
    try:
        with db._lock:
            db.conn.create_function("snmpathy_ip_in", 2, _ip_in, deterministic=True)
        caps["cidr"] = True
    except Exception:  # pragma: no cover - very old SQLite / exotic connection
        pass
    try:
        db._snmpathy_search_caps = caps  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover
        pass
    return caps


def _json_path_literal(key: str) -> str | None:
    if '"' in key or not key:
        return None
    path = '$."' + key + '"'
    return "'" + path.replace("'", "''") + "'"


def _json_expr(key: str) -> str | None:
    path = _json_path_literal(key)
    if path is None:
        return None
    return (f"(CASE WHEN json_valid(syslog.structured) THEN "
            f"CAST(json_extract(syslog.structured, {path}) AS TEXT) END)")


class _Compiler:
    def __init__(self, db: Database, use_fts: bool = True):
        caps = _caps(db)
        self.use_fts = bool(use_fts and db.has_fts)
        self.json = caps["json"]
        self.cidr = caps["cidr"]

    # ------------------------------------------------------------ FTS
    def fts(self, node: Any) -> str | None:
        """An FTS5 expression for a subtree made of free text only, else None."""
        if not self.use_fts:
            return None
        if isinstance(node, Text):
            return _fts_phrase(node)
        if isinstance(node, And):
            return self.fts_and(node.children)
        if isinstance(node, Or):
            parts = [self.fts(c) for c in node.children]
            if any(p is None for p in parts):
                return None
            return "(" + " OR ".join(parts) + ")"
        return None

    def _textish(self, node: Any) -> bool:
        inner = node.child if isinstance(node, Not) else node
        return self.fts(inner) is not None

    def fts_and(self, children: list[Any]) -> str | None:
        pos, neg = [], []
        for c in children:
            if isinstance(c, Not):
                expr = self.fts(c.child)
                if expr is None:
                    return None
                neg.append(expr)
            else:
                expr = self.fts(c)
                if expr is None:
                    return None
                pos.append(expr)
        if not pos:
            return None
        out = " AND ".join(pos)
        if neg:
            out = f"({out}) NOT ({' OR '.join(neg)})"
        elif len(pos) > 1:
            out = f"({out})"
        return out

    def _split_text(self, children: list[Any]) -> tuple[str | None, list[Any]]:
        """Merge the free-text children of an AND into one FTS expression."""
        if not self.use_fts:
            return None, children
        textish = [c for c in children if self._textish(c)]
        if not any(not isinstance(c, Not) for c in textish):
            return None, children
        expr = self.fts_and(textish)
        if expr is None:
            return None, children
        rest = [c for c in children if not any(c is t for t in textish)]
        return expr, rest

    # ------------------------------------------------------------ SQL
    def top(self, children: list[Any]) -> tuple[str, list[str], list[Any]]:
        expr, rest = self._split_text(children)
        join, clauses, params = "", [], []
        if expr is not None:
            join = "JOIN syslog_fts ON syslog_fts.rowid = syslog.id"
            clauses.append("syslog_fts MATCH ?")
            params.append(expr)
        for c in rest:
            sql, p = self.sql(c)
            clauses.append(sql)
            params.extend(p)
        return join, clauses, params

    def sql(self, node: Any) -> tuple[str, list[Any]]:
        expr = self.fts(node)
        if expr is not None:
            return "syslog.id IN (SELECT rowid FROM syslog_fts WHERE syslog_fts MATCH ?)", [expr]
        if isinstance(node, Text):
            pat = _like(node.text, wildcards=not node.phrase, contains=True)
            return (f"(syslog.message LIKE ?{_ESC} OR syslog.host LIKE ?{_ESC} OR syslog.app LIKE ?{_ESC})",
                    [pat, pat, pat])
        if isinstance(node, Field):
            return self.field(node)
        if isinstance(node, Not):
            sql, params = self.sql(node.child)
            return f"NOT COALESCE(({sql}), 0)", params
        if isinstance(node, And):
            expr, rest = self._split_text(node.children)
            parts, params = [], []
            if expr is not None:
                parts.append("syslog.id IN (SELECT rowid FROM syslog_fts WHERE syslog_fts MATCH ?)")
                params.append(expr)
            for c in rest:
                sql, p = self.sql(c)
                parts.append(sql)
                params.extend(p)
            return "(" + " AND ".join(parts) + ")", params
        if isinstance(node, Or):
            parts, params = [], []
            for c in node.children:
                sql, p = self.sql(c)
                parts.append(sql)
                params.extend(p)
            return "(" + " OR ".join(parts) + ")", params
        return "1", []

    # ------------------------------------------------------------ fields
    def field(self, node: Field) -> tuple[str, list[Any]]:
        kind, info = _resolve(node.name)
        value, op = node.value, node.op
        literal = node.exact or node.phrase
        if kind == "column":
            col = info
            if col == "host":
                a, pa = self._match("syslog.host", value, op, literal, ip=True)
                b, pb = self._match("syslog.source_ip", value, op, literal, ip=True)
                return f"({a} {_either(value)} {b})", pa + pb
            if col == "message":
                if value is None:
                    return "syslog.message = ''", []
                if value == "*" and not literal:
                    return "syslog.message != ''", []
                return f"syslog.message LIKE ?{_ESC}", [_like(value, wildcards=not literal, contains=True)]
            if col in _INT_COLUMNS:
                return self._int_match(col, value, op, literal)
            return self._match(f"syslog.{col}", value, op, literal, ip=col == "source_ip")
        if kind == "dual":
            col, key = info
            a, pa = self._match(f"syslog.{col}", value, op, literal)
            jexpr = _json_expr(key) if self.json else None
            b, pb = self._match(jexpr, value, op, literal) if jexpr else self._json_like(key, value, op, literal)
            return f"({a} {_either(value)} {b})", pa + pb
        key = info
        jexpr = _json_expr(key) if self.json else None
        if jexpr:
            sql, params = self._match(jexpr, value, op, literal, ip=True)
        else:
            sql, params = self._json_like(key, value, op, literal)
        sd = self._sd_like(key, value, op, literal)
        if sd:
            sql, params = f"({sql} OR {sd[0]})", params + sd[1]
        return sql, params

    def _match(self, expr: str, value: str | None, op: str, literal: bool, ip: bool = False) -> tuple[str, list[Any]]:
        if value is None:
            return f"({expr} IS NULL OR {expr} = '')", []
        if not literal and value == "*":
            return f"({expr} IS NOT NULL AND {expr} != '')", []
        if op and not literal:
            try:
                number = float(value)
            except ValueError:
                return f"({expr} != '' AND {expr} {op} ?)", [value]
            return f"({expr} != '' AND CAST({expr} AS REAL) {op} ?)", [number]
        if ip and not literal and self.cidr:
            net = _network(value)
            if net is not None:
                return f"snmpathy_ip_in({expr}, ?)", [str(net)]
        if not literal and "*" in value:
            return f"{expr} LIKE ?{_ESC}", [_like(value)]
        return f"{expr} = ? COLLATE NOCASE", [value]

    def _int_match(self, col: str, value: str | None, op: str, literal: bool) -> tuple[str, list[Any]]:
        expr = f"syslog.{col}"
        if value is None:
            return f"{expr} IS NULL", []
        if not literal and value == "*":
            return f"{expr} IS NOT NULL", []
        number = _enum_value(col, value) if col in ("severity", "facility") else None
        if number is None:
            try:
                number = int(float(value))
            except ValueError:
                return "0", []
        if op and not literal:
            return f"{expr} {op} ?", [number]
        return f"{expr} = ?", [number]

    def _json_like(self, key: str, value: str | None, op: str, literal: bool) -> tuple[str, list[Any]]:
        """Fallback when SQLite has no JSON1: LIKE on the serialised object."""
        k = _like(json.dumps(key, ensure_ascii=False), wildcards=False)
        if value is None:
            return f"syslog.structured NOT LIKE ?{_ESC}", [f"%{k}:%"]
        if (not literal and value == "*") or (op and not literal):
            return f"syslog.structured LIKE ?{_ESC}", [f"%{k}:%"]
        text = json.dumps(value, ensure_ascii=False)[1:-1]
        v = _like(text, wildcards=not literal)
        return (f"(syslog.structured LIKE ?{_ESC} OR syslog.structured LIKE ?{_ESC} "
                f"OR syslog.structured LIKE ?{_ESC})",
                [f'%{k}:"{v}"%', f"%{k}:{v},%", f"%{k}:{v}}}%"])

    def _sd_like(self, key: str, value: str | None, op: str, literal: bool) -> tuple[str, list[Any]] | None:
        """RFC 5424 structured data (``[id key="value"]``) is stored raw."""
        if value is None or op or not re.fullmatch(r"[\w.\-@]+", key):
            return None
        if not literal and value == "*":
            return f"syslog.structured LIKE ?{_ESC}", [f"[% {_like(key, False)}=\"%"]
        v = _like(value, wildcards=not literal)
        return f"syslog.structured LIKE ?{_ESC}", [f"[% {_like(key, False)}=\"{v}\"%"]


def _either(value: str | None) -> str:
    """Alternatives (host / source IP, column / structured key): any may match, all must be missing."""
    return "AND" if value is None else "OR"


def _fts_phrase(node: Text) -> str | None:
    text = node.text
    prefix = False
    if not node.phrase:
        if text.endswith("*"):
            prefix = True
            text = text.rstrip("*")
        if "*" in text:
            return None  # inner / leading wildcard: LIKE
    if not re.search(r"\w", text):
        return None
    return '"' + text.replace('"', '""') + '"' + ("*" if prefix else "")


def _filter_nodes(f: SyslogFilter) -> list[Any]:
    nodes: list[Any] = []
    tree = parse_query(f.q) if f.q else None
    if isinstance(tree, And):
        nodes.extend(tree.children)
    elif tree is not None:
        nodes.append(tree)
    for name, value in f.must or []:
        nodes.append(Field(str(name), None if value is None else str(value), exact=True))
    for name, value in f.must_not or []:
        nodes.append(Not(Field(str(name), None if value is None else str(value), exact=True)))
    return nodes


def _where(db: Database, f: SyslogFilter, use_fts: bool = True) -> tuple[str, str, list[Any]]:
    join, clauses, params = _Compiler(db, use_fts).top(_filter_nodes(f))
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


def _and_where(where: str, clause: str) -> str:
    return (where + " AND " if where else "WHERE ") + clause


def _run(db: Database, f: SyslogFilter, build) -> list[dict[str, Any]]:
    join, where, params = _where(db, f)
    try:
        return db.query(*build(join, where, params))
    except sqlite3.OperationalError:
        if not f.q:
            raise
        # Odd input FTS5 rejects: retry with LIKE matching.
        join, where, params = _where(db, f, use_fts=False)
        return db.query(*build(join, where, params))


def _decorate(row: dict[str, Any]) -> dict[str, Any]:
    sev = row.get("severity")
    fac = row.get("facility")
    row["severity_name"] = SEVERITIES[sev] if sev is not None and 0 <= sev < 8 else ""
    row["facility_name"] = FACILITIES[fac] if fac is not None and 0 <= fac < 24 else ""
    return row


def search(db: Database, f: SyslogFilter, limit: int = 200, before_id: int | None = None) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 5000))

    def build(join: str, where: str, params: list[Any]):
        p = list(params)
        if before_id:
            where = _and_where(where, "syslog.id < ?")
            p.append(before_id)
        return (
            f"SELECT syslog.* FROM syslog {join} {where} ORDER BY syslog.id DESC LIMIT ?",
            p + [limit],
        )

    return [_decorate(row) for row in _run(db, f, build)]


def count(db: Database, f: SyslogFilter) -> int:
    rows = _run(db, f, lambda j, w, p: (f"SELECT COUNT(*) AS n FROM syslog {j} {w}", p))
    return int(rows[0]["n"]) if rows else 0


def _span(f: SyslogFilter, buckets: int) -> tuple[float, float, int]:
    end = f.end or time.time()
    start = f.start or end - 86400
    step = max(1, int((end - start) / max(1, buckets)))
    return start, end, step


def histogram(db: Database, f: SyslogFilter, buckets: int = 60) -> dict[str, Any]:
    start, end, step = _span(f, buckets)
    bounded = replace(f, start=start, end=end)

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


MAX_QUERIES = 8


def histogram_multi(db: Database, base_filter: SyslogFilter, queries: Iterable[str] | None,
                    buckets: int = 60) -> dict[str, Any]:
    """One count-per-bucket series per query, all on the same time axis.

    Each query string replaces ``base_filter.q``; everything else in the base
    filter (time range, host, severity, filter pills...) applies to all.
    """
    queries = [str(q or "").strip() for q in (queries or [])][:MAX_QUERIES] or [base_filter.q]
    start, end, step = _span(base_filter, buckets)
    n = int((end - start) // step) + 1
    series = []
    for q in queries:
        f = replace(base_filter, q=q, start=start, end=end)

        def build(join: str, where: str, params: list[Any]):
            return (f"SELECT CAST((syslog.ts - ?) / ? AS INTEGER) AS b, COUNT(*) AS n "
                    f"FROM syslog {join} {where} GROUP BY b", [start, step, *params])

        counts = {r["b"]: int(r["n"]) for r in _run(db, f, build)}
        points = [[start + i * step, counts.get(i, 0)] for i in range(n)]
        series.append({"q": q, "count": sum(counts.values()), "points": points})
    return {"start": start, "end": end, "step": step, "series": series}


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


# ================================================================ field discovery
def _structured_dict(text: str | None) -> dict[str, Any]:
    if not text or not text.startswith("{"):
        return {}
    try:
        obj = json.loads(text)
    except ValueError:
        return {}
    return obj if isinstance(obj, dict) else {}


def fields(db: Database, f: SyslogFilter, sample: int = 2000) -> list[dict[str, Any]]:
    """Fields present in the most recent ``sample`` matching messages.

    Returns ``[{"name", "kind": "column"|"structured", "count", "pct"}]``:
    the fixed columns first, then structured (JSON) keys by frequency.
    """
    sample = max(1, min(int(sample), 20000))
    cols = ", ".join(f"syslog.{c}" for c in COLUMN_FIELDS)
    rows = _run(db, f, lambda j, w, p: (
        f"SELECT {cols}, syslog.structured FROM syslog {j} {w} ORDER BY syslog.id DESC LIMIT ?", [*p, sample]))
    n = len(rows)
    if not n:
        return []
    column_counts = Counter()
    keys: Counter[str] = Counter()
    for r in rows:
        for c in COLUMN_FIELDS:
            if r[c] not in (None, ""):
                column_counts[c] += 1
        for k, v in _structured_dict(r["structured"]).items():
            if v not in (None, ""):
                keys[k] += 1
    pct = lambda c: round(100.0 * c / n, 1)  # noqa: E731
    out = [{"name": c, "kind": "column", "count": column_counts[c], "pct": pct(column_counts[c])}
           for c in COLUMN_FIELDS if column_counts[c]]
    for k, c in sorted(keys.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:500]:
        out.append({"name": k, "kind": "structured", "count": c, "pct": pct(c)})
    return out


def field_top(db: Database, f: SyslogFilter, field: str, limit: int = 10) -> list[dict[str, Any]]:
    """Most common values of a column or structured key: ``[{"value", "count"}]``.

    Severity and facility values also carry a ``label`` (``"err"``, ``"local7"``).
    """
    if not field or len(field) > 256:
        raise ValueError("field name required")
    limit = max(1, min(int(limit), 100))
    kind, info = _resolve(field)
    caps = _caps(db)
    if kind == "column":
        col = info
        if col == "id":
            raise ValueError("cannot aggregate on 'id'")

        def build(join: str, where: str, params: list[Any]):
            return (f"SELECT syslog.{col} AS value, COUNT(*) AS count FROM syslog {join} {where} "
                    f"GROUP BY syslog.{col} ORDER BY count DESC LIMIT ?", [*params, limit])

        rows = _run(db, f, build)
        if col in ("severity", "facility"):
            names = SEVERITIES if col == "severity" else FACILITIES
            for r in rows:
                v = r["value"]
                r["label"] = names[v] if isinstance(v, int) and 0 <= v < len(names) else ""
        return rows
    jexpr = _json_expr(info[1] if kind == "dual" else info) if caps["json"] else None
    if jexpr:
        expr = f"COALESCE(NULLIF(syslog.{info[0]}, ''), {jexpr})" if kind == "dual" else jexpr

        def build(join: str, where: str, params: list[Any]):
            return (f"SELECT {expr} AS value, COUNT(*) AS count FROM syslog {join} "
                    f"{_and_where(where, f'{expr} IS NOT NULL AND {expr} != {chr(39)}{chr(39)}')} "
                    f"GROUP BY value ORDER BY count DESC, value LIMIT ?", [*params, limit])

        return _run(db, f, build)
    # No JSON1: count in Python over a recent sample.
    key = info[1] if kind == "dual" else info
    column = f"syslog.{info[0]}" if kind == "dual" else "NULL"
    rows = _run(db, f, lambda j, w, p: (
        f"SELECT syslog.structured AS structured, {column} AS col_value FROM syslog {j} {w} "
        f"ORDER BY syslog.id DESC LIMIT 20000", p))
    counter: Counter[str] = Counter()
    for r in rows:
        value = r["col_value"] or _structured_dict(r["structured"]).get(key)
        if value in (None, ""):
            continue
        if isinstance(value, bool):
            value = int(value)
        counter[value if isinstance(value, str) else json.dumps(value)] += 1
    return [{"value": v, "count": c} for v, c in counter.most_common(limit)]
