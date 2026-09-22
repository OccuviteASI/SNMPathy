"""Syslog message parsing.

Handles RFC 5424, RFC 3164 (BSD) and the common real-world variations:
ISO-8601 timestamps in BSD messages (rsyslog), messages without a
hostname, Cisco IOS sequence numbers / ``%FAC-SEV-MNEMONIC`` tags,
Juniper and Fortinet key/value messages, and missing ``<PRI>`` headers.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
SEVERITY_LABELS = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]
FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]

MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}

# Maximum distance between a device's own timestamp and the time we received
# the message before we distrust the device clock and use receipt time.
CLOCK_SKEW_LIMIT = 24 * 3600


@dataclass
class SyslogMessage:
    received_at: float
    ts: float
    facility: int | None = None
    severity: int | None = None
    host: str = ""
    app: str = ""
    procid: str = ""
    msgid: str = ""
    message: str = ""
    structured: str = ""
    source_ip: str = ""
    sd: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def severity_name(self) -> str:
        return SEVERITIES[self.severity] if self.severity is not None and 0 <= self.severity < 8 else ""

    @property
    def facility_name(self) -> str:
        return FACILITIES[self.facility] if self.facility is not None and 0 <= self.facility < 24 else ""


_PRI_RE = re.compile(r"^<(\d{1,3})>")
_5424_RE = re.compile(
    r"^(?P<ver>[1-9]\d{0,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) ?(?P<rest>.*)$",
    re.DOTALL,
)
_BSD_TS_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?:(?P<year>\d{4})\s+)?"
    r"(?P<time>\d{1,2}:\d{2}:\d{2})(?P<frac>\.\d+)?(?:\s+(?P<tz>[A-Z]{2,5}|[+-]\d{2}:?\d{2}))?:?\s*"
)
_ISO_TS_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?):?\s+"
)
_TAG_RE = re.compile(r"^(?P<app>[^\s\[\]:]{1,64})(?:\[(?P<pid>[^\]]{0,32})\])?:\s?")
_CISCO_SEQ_RE = re.compile(r"^(\d{1,10}):\s+")
_CISCO_TAG_RE = re.compile(r"%(?P<tag>[A-Z0-9_]+-(?:[A-Z0-9_]+-)?(?P<sev>[0-7])-[A-Z0-9_]+):?\s*")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-:]*$")


def parse(data: bytes | str, source_ip: str = "", received_at: float | None = None) -> SyslogMessage:
    received_at = received_at or time.time()
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    text = text.strip("\x00\r\n ")
    msg = SyslogMessage(received_at=received_at, ts=received_at, source_ip=source_ip)

    pri_match = _PRI_RE.match(text)
    if pri_match:
        pri = int(pri_match.group(1))
        if pri <= 191:
            msg.facility, msg.severity = pri >> 3, pri & 7
        text = text[pri_match.end():]
    else:
        # RFC 3164 section 4.3.3: no PRI means user.notice
        msg.facility, msg.severity = 1, 5

    m5424 = _5424_RE.match(text)
    if m5424 and _looks_like_5424_ts(m5424.group("ts")):
        _parse_5424(msg, m5424)
    else:
        _parse_bsd(msg, text)

    if not msg.host:
        msg.host = source_ip
    msg.message = msg.message.strip()
    return msg


def _looks_like_5424_ts(value: str) -> bool:
    return value == "-" or bool(re.match(r"^\d{4}-\d{2}-\d{2}T", value))


def _nil(value: str) -> str:
    return "" if value == "-" else value


def _parse_5424(msg: SyslogMessage, m: re.Match) -> None:
    ts = _parse_iso(m.group("ts")) if m.group("ts") != "-" else None
    msg.ts = _trust(ts, msg.received_at)
    msg.host = _nil(m.group("host"))
    msg.app = _nil(m.group("app"))
    msg.procid = _nil(m.group("procid"))
    msg.msgid = _nil(m.group("msgid"))
    rest = m.group("rest")
    if rest.startswith("-"):
        rest = rest[1:]
    elif rest.startswith("["):
        sd_text, rest, sd = _parse_structured_data(rest)
        msg.structured = sd_text
        msg.sd = sd
    rest = rest[1:] if rest.startswith(" ") else rest
    if rest.startswith("﻿"):
        rest = rest[1:]
    msg.message = rest


def _parse_structured_data(text: str) -> tuple[str, str, dict[str, dict[str, str]]]:
    """Parse ``[id k="v"]...`` returning (raw_sd, remainder, parsed)."""
    parsed: dict[str, dict[str, str]] = {}
    i = 0
    n = len(text)
    while i < n and text[i] == "[":
        j = i + 1
        # SD-ID
        while j < n and text[j] not in " ]":
            j += 1
        sd_id = text[i + 1 : j]
        params: dict[str, str] = {}
        while j < n and text[j] == " ":
            j += 1
            k = j
            while k < n and text[k] != "=":
                k += 1
            name = text[j:k]
            if k + 1 >= n or text[k + 1] != '"':
                break
            k += 2
            value_chars = []
            while k < n:
                ch = text[k]
                if ch == "\\" and k + 1 < n and text[k + 1] in '"\\]':
                    value_chars.append(text[k + 1])
                    k += 2
                    continue
                if ch == '"':
                    break
                value_chars.append(ch)
                k += 1
            params[name] = "".join(value_chars)
            j = k + 1
        if j < n and text[j] == "]":
            j += 1
        else:
            # Malformed SD; treat everything as message.
            return "", text, {}
        parsed[sd_id] = params
        i = j
    return text[:i], text[i:], parsed


def _parse_bsd(msg: SyslogMessage, text: str) -> None:
    # Cisco IOS: "<189>52: router1: *Mar  1 00:01:02.345 UTC: %LINK-3-UPDOWN: ..."
    seq = _CISCO_SEQ_RE.match(text)
    if seq:
        text = text[seq.end():]
        maybe_host, sep, remainder = text.partition(": ")
        if sep and _HOSTNAME_RE.match(maybe_host) and not maybe_host[0].isdigit() and (
            remainder[:1] in "*." or _BSD_TS_RE.match(remainder) or remainder.startswith("%")
        ):
            msg.host = maybe_host
            text = remainder

    unsynced = False
    if text[:1] in "*.":
        # Cisco marks timestamps from an unsynchronised clock with '*' (or '.').
        unsynced = True
        text = text[1:]

    ts = None
    m = _BSD_TS_RE.match(text)
    if m:
        ts = _parse_bsd_ts(m, msg.received_at)
        text = text[m.end():]
    else:
        m = _ISO_TS_RE.match(text)
        if m:
            ts = _parse_iso(m.group("iso"))
            text = text[m.end():]
    msg.ts = msg.received_at if unsynced else _trust(ts, msg.received_at)

    # Hostname: next token, unless it is obviously the tag.
    if ts is not None and not msg.host:
        token, sep, remainder = text.partition(" ")
        if sep and token and _HOSTNAME_RE.match(token) and not token.endswith(":") and "[" not in token \
                and not token.startswith("%"):
            msg.host = token
            text = remainder

    cisco = _CISCO_TAG_RE.match(text) or (_CISCO_TAG_RE.search(text[:80]) if "%" in text[:80] else None)
    if cisco and (cisco.start() == 0 or text[: cisco.start()].rstrip().endswith(":")):
        msg.app = cisco.group("tag")
        msg.message = text[cisco.end():]
        return

    tag = _TAG_RE.match(text)
    if tag:
        msg.app = tag.group("app")
        msg.procid = tag.group("pid") or ""
        text = text[tag.end():]
    msg.message = text


def _parse_bsd_ts(m: re.Match, received_at: float) -> float | None:
    mon = MONTHS.get(m.group("mon").lower())
    if not mon:
        return None
    try:
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        day = int(m.group("day"))
        local_now = datetime.fromtimestamp(received_at)
        year = int(m.group("year")) if m.group("year") else local_now.year
        dt = datetime(year, mon, day, hh, mm, ss)
    except ValueError:
        return None
    if m.group("frac"):
        dt += timedelta(seconds=float(m.group("frac")))
    tz = m.group("tz")
    if tz and (tz in {"UTC", "GMT", "Z"}):
        dt = dt.replace(tzinfo=timezone.utc)
    elif tz and tz[0] in "+-":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0))
        dt = dt.replace(tzinfo=timezone(sign * offset))
    ts = dt.timestamp()  # naive -> local time, which is what BSD syslog means
    if not m.group("year") and ts - received_at > 2 * 86400:
        # "Dec 31" received on Jan 1st belongs to last year.
        try:
            ts = dt.replace(year=year - 1).timestamp()
        except ValueError:
            pass
    return ts


def _parse_iso(value: str) -> float | None:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    # Python 3.10's fromisoformat only accepts exactly 3 or 6 fractional digits and +HH:MM offsets.
    value = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], value, count=1)
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
    try:
        dt = datetime.fromisoformat(value.replace(" ", "T", 1))
    except ValueError:
        return None
    return dt.timestamp()


def _trust(ts: float | None, received_at: float) -> float:
    if ts is None or abs(ts - received_at) > CLOCK_SKEW_LIMIT:
        return received_at
    return ts


def split_octet_counted(buffer: bytearray) -> list[bytes]:
    """Extract complete frames from a TCP syslog stream buffer (in place).

    Supports RFC 6587 octet-counting (``LEN SP MSG``) and newline / NUL
    delimited framing, as sent by rsyslog, syslog-ng, NXLog and network gear.
    """
    frames: list[bytes] = []
    while buffer:
        # Skip stray delimiters between frames.
        while buffer[:1] in (b"\n", b"\r", b"\x00", b" "):
            del buffer[:1]
        if not buffer:
            break
        if buffer[:1].isdigit():
            space = buffer.find(b" ", 0, 12)
            if space > 0 and buffer[:space].isdigit() and buffer[space + 1 : space + 2] == b"<":
                length = int(buffer[:space])
                end = space + 1 + length
                if len(buffer) < end:
                    break
                frames.append(bytes(buffer[space + 1 : end]))
                del buffer[:end]
                continue
        newline = -1
        for delim in (b"\n", b"\x00"):
            pos = buffer.find(delim)
            if pos != -1 and (newline == -1 or pos < newline):
                newline = pos
        if newline == -1:
            break
        frames.append(bytes(buffer[:newline]).rstrip(b"\r"))
        del buffer[: newline + 1]
    return frames
