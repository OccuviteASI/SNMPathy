"""Structured (JSON) log inputs: GELF, NXLog Windows Event Log and JSON lines.

Three wire formats end up in the same ``syslog`` table as classic syslog:

* **GELF 1.1** (Graylog Extended Log Format) over UDP, optionally zlib/gzip
  compressed and chunked, or NUL-delimited over TCP.
* **NXLog** ``to_json()`` output, typically Windows Event Log events read with
  ``im_msvistalog`` (``EventTime``, ``Hostname``, ``SourceName``, ``EventID``...).
* **Generic JSON lines** as written by Filebeat, Fluent Bit, Vector,
  ``journalctl -o json`` and most structured application loggers.

Each event becomes a :class:`~snmpathy.syslog.parser.SyslogMessage`. Fields that
map onto a syslog column (time, host, severity, app, ...) are taken out of the
event; everything else is flattened with dot notation (``{"a": {"b": 1}}`` ->
``{"a.b": 1}``) and stored as a compact JSON object in ``structured`` so the UI
can show and search it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import socket
import time
import zlib
from collections import OrderedDict
from typing import Any, Callable

from ..db import Database
from .parser import CLOCK_SKEW_LIMIT, FACILITIES, SyslogMessage, _parse_iso
from .server import SyslogServer, message_row, store_messages

log = logging.getLogger(__name__)

# Events whose own timestamp is older than this are stored with receipt time.
MAX_EVENT_AGE = 30 * 86400
# Limits for the extra fields kept in ``structured``.
MAX_FIELDS = 100
MAX_FIELD_VALUE = 1000
MAX_FIELD_KEY = 128
MAX_FLATTEN_DEPTH = 10
# server.message_row truncates ``structured`` to this many characters; we keep
# the JSON below it so the stored value is always valid JSON.
MAX_STRUCTURED = 4096

MAX_TCP_LINE = 256 * 1024
MAX_GELF_MESSAGE = 1024 * 1024  # decompressed / reassembled size limit

GELF_CHUNK_MAGIC = b"\x1e\x0f"
GELF_MAX_CHUNKS = 128
GELF_CHUNK_TIMEOUT = 5.0

# --------------------------------------------------------------------- severity
_SEVERITY_NAMES = {
    "emerg": 0, "emergency": 0, "panic": 0,
    "alert": 1,
    "crit": 2, "critical": 2, "fatal": 2,
    "err": 3, "error": 3, "eror": 3,
    "warn": 4, "warning": 4,
    "notice": 5, "audit_failure": 5,
    "info": 6, "information": 6, "informational": 6, "audit_success": 6,
    "debug": 7, "trace": 7, "verbose": 7, "dbug": 7,
}
# NXLog's own 1-5 scale (SeverityValue).
_NXLOG_SEVERITY_VALUES = {1: 7, 2: 6, 3: 4, 4: 3, 5: 2}
# bunyan / pino numeric levels.
_BUNYAN_LEVELS = {10: 7, 20: 7, 30: 6, 40: 4, 50: 3, 60: 2}

DEFAULT_SEVERITY = 6  # info
DEFAULT_FACILITY = 1  # user


def _severity(value: Any) -> int | None:
    """Map a level name ("warn", "ERROR") or number (0-7) to a syslog severity."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.lstrip("-").isdigit():
            value = int(text)
        else:
            return _SEVERITY_NAMES.get(text.lower())
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, int):
        if 0 <= value <= 7:
            return value
        return _BUNYAN_LEVELS.get(value)
    return None


def _facility(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text.isdigit():
            value = int(text)
        elif text in FACILITIES:
            return FACILITIES.index(text)
        else:
            return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, int) and 0 <= value < 24:
        return value
    return None


# ------------------------------------------------------------------- timestamps
def _epoch(value: float) -> float | None:
    if not math.isfinite(value) or value <= 0:
        return None
    if value > 1e17:  # nanoseconds
        return value / 1e9
    if value > 1e14:  # microseconds (journald __REALTIME_TIMESTAMP)
        return value / 1e6
    if value > 1e11:  # milliseconds
        return value / 1e3
    return float(value)


def _to_ts(value: Any) -> float | None:
    """Epoch seconds/ms/us/ns (number or numeric string) or an ISO-8601 string."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _epoch(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return _epoch(float(text))
        except ValueError:
            pass
        return _parse_iso(text)
    return None


def _trust_ts(ts: float | None, received_at: float) -> float:
    """Device clocks more than a day ahead or 30 days behind are not trusted."""
    if ts is None or ts - received_at > CLOCK_SKEW_LIMIT or received_at - ts > MAX_EVENT_AGE:
        return received_at
    return ts


# ------------------------------------------------------------------- flattening
def _flatten(obj: dict[str, Any], prefix: str = "", out: dict[str, Any] | None = None,
             depth: int = 0) -> dict[str, Any]:
    out = {} if out is None else out
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and value and depth < MAX_FLATTEN_DEPTH:
            _flatten(value, name + ".", out, depth + 1)
        else:
            out.setdefault(name, value)
    return out


def _clean(text: str) -> str:
    """Drop lone surrogates (valid in JSON escapes, rejected by SQLite)."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return str(value)


def _field_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, dict) and not value:
        return {}
    text = value if isinstance(value, str) else _text(value)
    return _clean(text[:MAX_FIELD_VALUE])


def _structured_json(fields: dict[str, Any]) -> str:
    """Serialise extra fields as a flat JSON object that fits the column."""
    if not fields:
        return ""
    kept: dict[str, Any] = {}
    total = 2  # "{}"
    for key, value in fields.items():
        if len(kept) >= MAX_FIELDS:
            break
        key = _clean(str(key)[:MAX_FIELD_KEY])
        if not key or key in kept:
            continue
        value = _field_value(value)
        cost = len(json.dumps(key, ensure_ascii=False)) + 1 + len(json.dumps(value, ensure_ascii=False))
        cost += 1 if kept else 0
        if total + cost > MAX_STRUCTURED:
            continue  # a smaller field further on may still fit
        kept[key] = value
        total += cost
    return json.dumps(kept, ensure_ascii=False, separators=(",", ":")) if kept else ""


def _pop_first(flat: dict[str, Any], *keys: str) -> Any:
    """Pop and return the value of the first present, non-empty key; other keys stay."""
    for key in keys:
        if key in flat and flat[key] not in (None, ""):
            return flat.pop(key)
    return None


# ----------------------------------------------------------------------- parse
def parse_json_event(data: bytes | str, source_ip: str = "", received_at: float | None = None) -> SyslogMessage:
    """Map one GELF / NXLog / generic JSON object to a :class:`SyslogMessage`.

    Raises ``ValueError`` if ``data`` is not a JSON object.
    """
    received_at = received_at or time.time()
    text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else data
    text = text.strip("\x00\r\n\t ﻿")
    if not text.startswith("{"):
        raise ValueError("not a JSON object")
    try:
        obj = json.loads(text)
    except RecursionError as exc:
        raise ValueError("JSON nested too deeply") from exc
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")

    msg = SyslogMessage(received_at=received_at, ts=received_at, source_ip=source_ip)
    flat = _flatten(obj)
    if "short_message" in obj:
        kind = "gelf"
        _map_gelf(msg, flat)
    elif _is_nxlog(obj):
        kind = "nxlog"
        _map_nxlog(msg, flat)
    else:
        kind = "json"
        _map_generic(msg, flat)

    if msg.severity is None:
        msg.severity = DEFAULT_SEVERITY
    if msg.facility is None:
        msg.facility = DEFAULT_FACILITY
    msg.ts = _trust_ts(msg.ts if msg.ts != received_at else None, received_at)
    msg.host = _clean(msg.host.strip()) or source_ip
    msg.app = _clean(msg.app.strip())
    msg.procid = _clean(msg.procid.strip())
    msg.msgid = _clean(msg.msgid.strip())
    msg.message = _clean(msg.message.strip())
    msg.structured = _structured_json(flat)
    msg.sd = {kind: {k: _text(v)[:MAX_FIELD_VALUE] for k, v in list(flat.items())[:MAX_FIELDS]}} if flat else {}
    return msg


def _set_ts(msg: SyslogMessage, value: Any) -> None:
    ts = _to_ts(value)
    if ts is not None:
        msg.ts = ts


def _map_gelf(msg: SyslogMessage, flat: dict[str, Any]) -> None:
    flat.pop("version", None)
    msg.host = _text(flat.pop("host", None))
    short = _text(flat.pop("short_message", None))
    full = _text(flat.pop("full_message", None))
    if full and full != short:
        msg.message = full if full.startswith(short) else f"{short}\n{full}"
    else:
        msg.message = short
    _set_ts(msg, flat.pop("timestamp", None))
    msg.severity = _severity(flat.pop("level", None))
    facility = flat.pop("facility", None)
    msg.facility = _facility(facility)
    if facility is not None and msg.facility is None:
        # GELF 1.0 senders put the application name in "facility".
        msg.app = _text(facility)
    # Additional fields: "_name" -> "name".
    for key in [k for k in flat if k.startswith("_")]:
        flat.setdefault(key[1:] or key, flat.pop(key))
    flat.pop("id", None)  # "_id" is reserved by GELF
    app = _pop_first(flat, "application_name", "app", "program", "service", "SYSLOG_IDENTIFIER", "logger_name",
                     "logger", "tag")
    if app is not None:
        msg.app = _text(app)
    procid = _pop_first(flat, "pid", "process_id", "procid")
    if procid is not None:
        msg.procid = _text(procid)
    msgid = flat.pop("msgid", None)
    if msgid is not None:
        msg.msgid = _text(msgid)


def _is_nxlog(obj: dict[str, Any]) -> bool:
    if "EventTime" in obj or "EventReceivedTime" in obj or "SeverityValue" in obj:
        return True
    return "EventID" in obj and ("SourceName" in obj or "Channel" in obj or "Hostname" in obj)


def _map_nxlog(msg: SyslogMessage, flat: dict[str, Any]) -> None:
    _set_ts(msg, flat.pop("EventTime", None))
    if msg.ts == msg.received_at and "EventReceivedTime" in flat:
        _set_ts(msg, flat["EventReceivedTime"])
    msg.host = _text(flat.pop("Hostname", None))
    msg.app = _text(flat.pop("SourceName", None))
    event_id = flat.pop("EventID", None)
    msg.msgid = _text(event_id)
    msg.procid = _text(flat.pop("ProcessID", None))
    msg.message = _text(flat.pop("Message", None))

    event_type = flat.get("EventType")
    severity_name = flat.pop("Severity", None)
    severity_value = flat.pop("SeverityValue", None)
    syslog_severity = flat.pop("SyslogSeverityValue", None)
    flat.pop("SyslogSeverity", None)
    sev = None
    if isinstance(event_type, str) and event_type.upper().startswith("AUDIT_"):
        sev = _severity(event_type)
    if sev is None:
        sev = _severity(syslog_severity)
    if sev is None:
        sev = _severity(severity_name)
    if sev is None and severity_value is not None:
        try:
            sev = _NXLOG_SEVERITY_VALUES.get(int(severity_value))
        except (TypeError, ValueError):
            sev = None
    if sev is None:
        sev = _severity(event_type)
    msg.severity = sev

    facility = flat.pop("SyslogFacilityValue", None)
    flat.pop("SyslogFacility", None)
    msg.facility = _facility(facility)


def _map_generic(msg: SyslogMessage, flat: dict[str, Any]) -> None:
    message = _pop_first(flat, "message", "msg", "MESSAGE", "log", "short_message")
    _set_ts(msg, _pop_first(flat, "@timestamp", "timestamp", "time", "ts", "__REALTIME_TIMESTAMP"))
    host = _pop_first(flat, "host", "host.name", "host.hostname", "hostname", "_HOSTNAME")
    msg.host = _text(host)
    msg.severity = _severity(_pop_first(flat, "level", "severity", "log.level", "PRIORITY", "levelname",
                                        "loglevel"))
    msg.facility = _facility(_pop_first(flat, "facility", "SYSLOG_FACILITY", "log.syslog.facility.code"))
    msg.app = _text(_pop_first(flat, "app", "program", "service", "service.name", "SYSLOG_IDENTIFIER",
                               "logger", "logger_name"))
    msg.procid = _text(_pop_first(flat, "pid", "procid", "SYSLOG_PID", "_PID", "process.pid"))
    msg.msgid = _text(_pop_first(flat, "msgid", "MESSAGE_ID"))
    if message is None:
        # No recognisable message key: show the event itself.
        msg.message = _text({k: v for k, v in flat.items()})
    else:
        msg.message = _text(message)


# ------------------------------------------------------------------------- GELF
class GelfChunkBuffer:
    """Reassembly state for chunked GELF datagrams.

    Partial messages expire after ``timeout`` seconds; at most ``max_pending``
    messages / ``max_bytes`` of chunk payload are buffered (oldest dropped).
    """

    def __init__(self, timeout: float = GELF_CHUNK_TIMEOUT, max_pending: int = 1000,
                 max_bytes: int = 32 * 1024 * 1024, max_message: int = MAX_GELF_MESSAGE):
        self.timeout = timeout
        self.max_pending = max_pending
        self.max_bytes = max_bytes
        self.max_message = max_message
        self._pending: OrderedDict[Any, tuple[float, int, dict[int, bytes], int]] = OrderedDict()
        self._bytes = 0
        self.expired = 0
        self.dropped = 0

    def __len__(self) -> int:
        return len(self._pending)

    def _discard(self, key: Any) -> None:
        entry = self._pending.pop(key, None)
        if entry:
            self._bytes -= entry[3]

    def expire(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        while self._pending:
            key, (first_seen, *_rest) = next(iter(self._pending.items()))
            if now - first_seen <= self.timeout:
                break
            self._discard(key)
            self.expired += 1

    def add(self, key: Any, seq: int, count: int, payload: bytes, now: float | None = None) -> bytes | None:
        now = time.monotonic() if now is None else now
        self.expire(now)
        entry = self._pending.get(key)
        if entry is not None and entry[1] != count:
            self._discard(key)
            self.dropped += 1
            raise ValueError("GELF chunk count changed within one message")
        if entry is None:
            if count == 1:
                return payload
            entry = (now, count, {}, 0)
        first_seen, count, parts, size = entry
        if seq in parts:
            return None  # duplicate
        if size + len(payload) > self.max_message:
            self._discard(key)
            self.dropped += 1
            raise ValueError("chunked GELF message too large")
        parts[seq] = payload
        size += len(payload)
        self._bytes += len(payload)
        self._pending[key] = (first_seen, count, parts, size)
        if len(parts) == count:
            self._discard(key)
            return b"".join(parts[i] for i in range(count))
        while self._pending and (len(self._pending) > self.max_pending or self._bytes > self.max_bytes):
            self._discard(next(iter(self._pending)))
            self.dropped += 1
        return None


def _inflate(data: bytes, wbits: int, limit: int) -> bytes:
    decomp = zlib.decompressobj(wbits)
    try:
        out = decomp.decompress(data, limit)
    except zlib.error as exc:
        raise ValueError(f"bad compressed GELF payload: {exc}") from exc
    if decomp.unconsumed_tail:
        raise ValueError("decompressed GELF message too large")
    return out


def decode_gelf_datagram(data: bytes, chunks: GelfChunkBuffer, source: str = "") -> bytes | None:
    """Return the JSON bytes of a GELF UDP datagram.

    Handles chunking (``0x1e 0x0f`` + 8-byte id + seq + count) and zlib /
    gzip compression. Returns ``None`` while a chunked message is incomplete;
    raises ``ValueError`` for malformed chunks or compressed payloads. ``source``
    (the sender address) keeps message ids from different senders apart.
    """
    if data[:2] == GELF_CHUNK_MAGIC:
        if len(data) < 12:
            raise ValueError("truncated GELF chunk header")
        message_id = bytes(data[2:10])
        seq, count = data[10], data[11]
        if not 1 <= count <= GELF_MAX_CHUNKS or seq >= count:
            raise ValueError(f"invalid GELF chunk {seq}/{count}")
        data = chunks.add((source, message_id), seq, count, bytes(data[12:]))
        if data is None:
            return None
    if data[:2] == b"\x1f\x8b":
        return _inflate(data, 16 + zlib.MAX_WBITS, chunks.max_message)
    if data[:1] == b"\x78":
        return _inflate(data, zlib.MAX_WBITS, chunks.max_message)
    return bytes(data)


# ----------------------------------------------------------------------- server
class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: Callable[[bytes, str], None]):
        self.handler = handler

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        self.handler(data, addr[0])

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - OS specific
        log.debug("structured log UDP error: %s", exc)


class StructuredLogServer(SyslogServer):
    """GELF/UDP, JSON-lines/TCP (also NUL-delimited GELF/TCP) and JSON/UDP listeners.

    Reuses :class:`SyslogServer`'s queue, batched writer, device mapping and
    ``message_row`` / ``store_messages``; only the wire handling and the parser
    differ. A port of 0 or ``None`` disables that listener.
    """

    def __init__(
        self,
        db: Database,
        host: str = "0.0.0.0",
        gelf_udp_port: int | None = 12201,
        json_tcp_port: int | None = 5544,
        json_udp_port: int | None = 5545,
        batch_size: int = 500,
        flush_interval: float = 1.0,
        queue_size: int = 100_000,
    ):
        super().__init__(db, host, udp_port=0, tcp_port=0, batch_size=batch_size,
                         flush_interval=flush_interval, queue_size=queue_size)
        self.gelf_udp_port = gelf_udp_port or 0
        self.json_tcp_port = json_tcp_port or 0
        self.json_udp_port = json_udp_port or 0
        self.chunks = GelfChunkBuffer()
        self._udp_transports: list[asyncio.DatagramTransport] = []

    # ---------------------------------------------------------------- intake
    def _gelf_datagram(self, data: bytes, source_ip: str) -> None:
        try:
            payload = decode_gelf_datagram(data, self.chunks, source_ip)
        except ValueError as exc:
            self.stats.errors += 1
            log.debug("bad GELF datagram from %s: %s", source_ip, exc)
            return
        if payload is not None:
            self.enqueue(payload, source_ip)

    def _json_datagram(self, data: bytes, source_ip: str) -> None:
        self.enqueue(data, source_ip)

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        source_ip = peer[0]
        buffer = bytearray()
        discarding = False  # inside an over-long line, skip to the next delimiter
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                # GELF TCP frames are NUL-terminated; raw NUL is never valid inside JSON.
                buffer.extend(chunk.replace(b"\x00", b"\n"))
                start = 0
                while (end := buffer.find(b"\n", start)) != -1:
                    if not discarding:
                        frame = bytes(buffer[start:end]).strip(b"\r\t ")
                        if frame:
                            self.enqueue(frame, source_ip)
                    discarding = False
                    start = end + 1
                del buffer[:start]
                if len(buffer) > MAX_TCP_LINE:
                    if not discarding:
                        self.stats.dropped += 1
                        log.debug("dropping JSON line over %d bytes from %s", MAX_TCP_LINE, source_ip)
                    discarding = True
                    buffer.clear()
            if buffer.strip() and not discarding:
                self.enqueue(bytes(buffer).strip(), source_ip)
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # ---------------------------------------------------------------- lifecycle
    async def _bind_udp(self, name: str, port: int, handler: Callable[[bytes, str], None]) -> int:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _DatagramProtocol(handler), local_addr=(self.host, port), family=family
            )
        except OSError as exc:
            log.error("cannot bind %s %s:%s: %s", name, self.host, port, exc)
            return port
        self._udp_transports.append(transport)
        sock = transport.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            port = sock.getsockname()[1]
        self.listening[name] = f"{self.host}:{port}"
        log.info("%s listening on %s:%s", name, self.host, port)
        return port

    async def start(self) -> None:
        if self.gelf_udp_port:
            self.gelf_udp_port = await self._bind_udp("gelf_udp", self.gelf_udp_port, self._gelf_datagram)
        if self.json_udp_port:
            self.json_udp_port = await self._bind_udp("json_udp", self.json_udp_port, self._json_datagram)
        if self.json_tcp_port:
            try:
                self._tcp_server = await asyncio.start_server(self._handle_tcp, self.host, self.json_tcp_port)
                sockets = self._tcp_server.sockets or []
                if sockets:
                    self.json_tcp_port = sockets[0].getsockname()[1]
                self.listening["json_tcp"] = f"{self.host}:{self.json_tcp_port}"
                log.info("json_tcp listening on %s:%s", self.host, self.json_tcp_port)
            except OSError as exc:
                log.error("cannot bind json_tcp %s:%s: %s", self.host, self.json_tcp_port, exc)
        self._writer_task = asyncio.create_task(self._writer(), name="structured-log-writer")

    async def stop(self) -> None:
        for transport in self._udp_transports:
            transport.close()
        self._udp_transports.clear()
        await super().stop()  # closes TCP, stops the writer and flushes the queue

    # ---------------------------------------------------------------- storage
    def store(self, batch: list[tuple[bytes, str, float]]) -> int:
        devices = self._devices()
        rows = []
        for data, source_ip, received in batch:
            try:
                msg = parse_json_event(data, source_ip, received)
            except Exception:
                self.stats.errors += 1
                continue
            rows.append(message_row(msg, devices))
        store_messages(self.db, rows)
        self.stats.stored += len(rows)
        return len(rows)
