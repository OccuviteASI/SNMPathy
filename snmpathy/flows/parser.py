"""Dependency-free decoders for NetFlow v5/v9, IPFIX and sFlow v5 datagrams.

Every decoder turns one UDP payload into a list of normalized flow records::

    {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 51000, "dport": 443, "proto": 6,
     "in_if": 1, "out_if": 2, "bytes": 1500, "packets": 3, "start": 1.7e9, "end": 1.7e9}

``bytes``/``packets`` are already scaled by the sampling rate when it is known; ``start``/``end``
(epoch seconds) are only present when the export format carries usable timestamps.

NetFlow v9 and IPFIX are template based: templates arrive in their own (Flow)Sets and are cached in a
:class:`TemplateCache` owned by the caller, keyed by (exporter, source id / observation domain,
template id). Data that refers to a template we have not seen yet is skipped and counted.

Anything malformed raises :class:`FlowDecodeError`; low-level ``struct``/``IndexError`` exceptions
never escape :func:`decode`.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "DecodeResult",
    "FlowDecodeError",
    "Template",
    "TemplateCache",
    "decode",
    "decode_ipfix",
    "decode_netflow_v5",
    "decode_netflow_v9",
    "decode_sflow",
    "parse_ethernet",
]

# -- information elements (NetFlow v9 field types == IPFIX IE ids for this range) ---------------
IN_BYTES = 1               # IPFIX octetDeltaCount
IN_PKTS = 2                # IPFIX packetDeltaCount
PROTOCOL = 4
L4_SRC_PORT = 7
IPV4_SRC_ADDR = 8
INPUT_SNMP = 10            # IPFIX ingressInterface
L4_DST_PORT = 11
IPV4_DST_ADDR = 12
OUTPUT_SNMP = 14           # IPFIX egressInterface
LAST_SWITCHED = 21         # IPFIX flowEndSysUpTime
FIRST_SWITCHED = 22        # IPFIX flowStartSysUpTime
OUT_BYTES = 23
OUT_PKTS = 24
IPV6_SRC_ADDR = 27
IPV6_DST_ADDR = 28
ICMP_TYPE = 32             # IPFIX icmpTypeCodeIPv4
SAMPLING_INTERVAL = 34
SAMPLING_ALGORITHM = 35
SAMPLER_RANDOM_INTERVAL = 50
OCTET_TOTAL_COUNT = 85
PACKET_TOTAL_COUNT = 86
ICMP_TYPE_IPV6 = 139       # IPFIX icmpTypeCodeIPv6
FLOW_START_SECONDS = 150
FLOW_END_SECONDS = 151
FLOW_START_MILLISECONDS = 152
FLOW_END_MILLISECONDS = 153
SYSTEM_INIT_TIME_MS = 160
SAMPLING_PACKET_INTERVAL = 305
SAMPLING_PACKET_SPACE = 306

VARIABLE_LENGTH = 65535
MAX_TEMPLATES = 20_000      # per cache; protects against template floods
MAX_TEMPLATE_FIELDS = 512

_V5_HEADER = struct.Struct("!HHIIIIBBH")
_V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHxBBBHHBBxx")
_V9_HEADER = struct.Struct("!HHIIII")
_IPFIX_HEADER = struct.Struct("!HHIII")
_SET_HEADER = struct.Struct("!HH")

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)
_PORT_PROTOCOLS = (6, 17, 132, 33)   # TCP, UDP, SCTP, DCCP: ports in the first 4 bytes
_IPV6_EXT_HEADERS = (0, 43, 60, 135, 139, 140)


class FlowDecodeError(ValueError):
    """Raised for truncated, inconsistent or unsupported flow export datagrams."""


@dataclass
class DecodeResult:
    """Outcome of decoding one datagram.

    ``kind`` is one of ``netflow5``, ``netflow9``, ``ipfix`` or ``sflow``; ``sampling`` is the
    sampling rate that was applied (1 = unsampled / unknown); ``skipped`` counts records or sets that
    could not be turned into flow records (unknown templates, non-IP samples, ...). For sFlow,
    ``agent`` holds the agent address carried inside the datagram.
    """

    kind: str
    records: list[dict[str, Any]] = field(default_factory=list)
    sampling: int = 1
    skipped: int = 0
    agent: str = ""


@dataclass(frozen=True)
class Template:
    """A cached v9/IPFIX template: ``fields`` holds ``(element_id, length, enterprise)`` tuples."""

    fields: tuple[tuple[int, int, int], ...]
    options: bool = False

    @property
    def min_length(self) -> int:
        """Smallest number of bytes one record can occupy (variable-length fields count as 1)."""
        return sum(1 if length == VARIABLE_LENGTH else length for _, length, _ in self.fields)

    @property
    def fixed(self) -> bool:
        return all(length != VARIABLE_LENGTH for _, length, _ in self.fields)


class TemplateCache:
    """Templates and per-exporter sampling rates learned from v9 / IPFIX exports.

    One instance is shared by every datagram from every exporter; keys include the exporter
    address so source ids from different devices never collide.
    """

    def __init__(self, max_templates: int = MAX_TEMPLATES):
        self.max_templates = max_templates
        self.templates: dict[tuple[str, int, int], Template] = {}
        self.sampling: dict[str, int] = {}

    def get(self, exporter: str, domain: int, template_id: int) -> Template | None:
        return self.templates.get((exporter, domain, template_id))

    def put(self, exporter: str, domain: int, template_id: int, template: Template) -> None:
        key = (exporter, domain, template_id)
        if key not in self.templates and len(self.templates) >= self.max_templates:
            raise FlowDecodeError("template cache full")
        self.templates[key] = template

    def withdraw(self, exporter: str, domain: int, template_id: int | None = None) -> None:
        """Forget one template, or every template of the (exporter, domain) when id is None."""
        if template_id is not None:
            self.templates.pop((exporter, domain, template_id), None)
            return
        for key in [k for k in self.templates if k[0] == exporter and k[1] == domain]:
            del self.templates[key]

    def set_sampling(self, exporter: str, rate: int) -> None:
        if rate > 0:
            self.sampling[exporter] = rate

    def sampling_for(self, exporter: str) -> int:
        return self.sampling.get(exporter, 1)

    def __len__(self) -> int:
        return len(self.templates)


# ---------------------------------------------------------------------------- helpers
def _need(data: bytes, offset: int, size: int, what: str) -> None:
    if size < 0 or offset + size > len(data):
        raise FlowDecodeError(f"truncated {what}: need {size} bytes at offset {offset}, have {len(data) - offset}")


def _uint(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def _addr(raw: bytes) -> str | None:
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    return None


def _uptime_to_epoch(export_secs: float, sys_uptime_ms: int, switched_ms: int) -> float:
    """Convert a sysUpTime-relative timestamp to epoch seconds (handles 32-bit wrap)."""
    delta = (sys_uptime_ms - switched_ms) & 0xFFFFFFFF
    if delta >= 0x80000000:  # switched slightly *after* the header uptime
        delta -= 0x100000000
    return export_secs - delta / 1000.0


def _sampling_from(values: dict[int, bytes]) -> int:
    """Sampling rate carried by an options/data record, 0 if none."""
    for fid in (SAMPLING_INTERVAL, SAMPLER_RANDOM_INTERVAL):
        raw = values.get(fid)
        if raw:
            rate = _uint(raw)
            if rate > 0:
                return rate
    interval = values.get(SAMPLING_PACKET_INTERVAL)
    space = values.get(SAMPLING_PACKET_SPACE)
    if interval and space is not None:
        n = _uint(interval)
        if n > 0:
            return max(1, (n + _uint(space)) // n)
    return 0


def _record_from_fields(
    values: dict[int, bytes], export_secs: float, sys_uptime_ms: int | None, sampling: int
) -> dict[str, Any] | None:
    """Normalize one v9/IPFIX data record; ``None`` when it does not describe an IP flow."""
    src = dst = None
    if IPV4_SRC_ADDR in values or IPV4_DST_ADDR in values:
        src = _addr(values.get(IPV4_SRC_ADDR, b""))
        dst = _addr(values.get(IPV4_DST_ADDR, b""))
    if (src is None or dst is None) and (IPV6_SRC_ADDR in values or IPV6_DST_ADDR in values):
        src = _addr(values.get(IPV6_SRC_ADDR, b""))
        dst = _addr(values.get(IPV6_DST_ADDR, b""))
    if src is None or dst is None:
        return None

    def num(*ids: int) -> int | None:
        for fid in ids:
            raw = values.get(fid)
            if raw is not None:
                return _uint(raw)
        return None

    rate = _sampling_from(values) or sampling
    proto = num(PROTOCOL) or 0
    sport = num(L4_SRC_PORT) or 0
    dport = num(L4_DST_PORT) or 0
    if proto in (1, 58) and not dport:
        dport = num(ICMP_TYPE, ICMP_TYPE_IPV6) or 0
    rec: dict[str, Any] = {
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "proto": proto,
        "in_if": num(INPUT_SNMP) or 0,
        "out_if": num(OUTPUT_SNMP) or 0,
        "bytes": (num(IN_BYTES, OCTET_TOTAL_COUNT, OUT_BYTES) or 0) * rate,
        "packets": (num(IN_PKTS, PACKET_TOTAL_COUNT, OUT_PKTS) or 0) * rate,
    }

    start = end = None
    if FLOW_START_MILLISECONDS in values or FLOW_END_MILLISECONDS in values:
        ms_start, ms_end = num(FLOW_START_MILLISECONDS), num(FLOW_END_MILLISECONDS)
        start = ms_start / 1000.0 if ms_start else None
        end = ms_end / 1000.0 if ms_end else None
    if end is None and (FLOW_START_SECONDS in values or FLOW_END_SECONDS in values):
        start = float(num(FLOW_START_SECONDS) or 0) or None
        end = float(num(FLOW_END_SECONDS) or 0) or None
    if end is None and (FIRST_SWITCHED in values or LAST_SWITCHED in values):
        first, last = num(FIRST_SWITCHED), num(LAST_SWITCHED)
        init_ms = num(SYSTEM_INIT_TIME_MS)
        if init_ms:  # IPFIX: sysUpTime fields are relative to systemInitTimeMilliseconds
            start = (init_ms + first) / 1000.0 if first is not None else None
            end = (init_ms + last) / 1000.0 if last is not None else None
        elif sys_uptime_ms is not None:  # NetFlow v9: relative to the header uptime
            start = _uptime_to_epoch(export_secs, sys_uptime_ms, first) if first is not None else None
            end = _uptime_to_epoch(export_secs, sys_uptime_ms, last) if last is not None else None
    if start is not None:
        rec["start"] = start
    if end is not None:
        rec["end"] = end
    elif start is not None:
        rec["end"] = start
    return rec


# ---------------------------------------------------------------------------- NetFlow v5
def decode_netflow_v5(data: bytes) -> DecodeResult:
    """Decode a NetFlow v5 datagram (24-byte header + ``count`` fixed 48-byte records)."""
    _need(data, 0, _V5_HEADER.size, "NetFlow v5 header")
    version, count, uptime, secs, nsecs, _seq, _etype, _eid, sampling = _V5_HEADER.unpack_from(data, 0)
    if version != 5:
        raise FlowDecodeError(f"not a NetFlow v5 datagram (version {version})")
    _need(data, _V5_HEADER.size, count * _V5_RECORD.size, "NetFlow v5 records")
    rate = (sampling & 0x3FFF) or 1
    export = secs + nsecs / 1e9
    records = []
    offset = _V5_HEADER.size
    for _ in range(count):
        (src, dst, _nh, in_if, out_if, pkts, octets, first, last, sport, dport,
         _flags, proto, _tos, _sas, _das, _smask, _dmask) = _V5_RECORD.unpack_from(data, offset)
        offset += _V5_RECORD.size
        records.append({
            "src": str(ipaddress.IPv4Address(src)),
            "dst": str(ipaddress.IPv4Address(dst)),
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "in_if": in_if,
            "out_if": out_if,
            "bytes": octets * rate,
            "packets": pkts * rate,
            "start": _uptime_to_epoch(export, uptime, first),
            "end": _uptime_to_epoch(export, uptime, last),
        })
    return DecodeResult("netflow5", records, rate, 0)


# ---------------------------------------------------------------------------- NetFlow v9
def _v9_template_set(data: bytes, start: int, end: int, exporter: str, domain: int, cache: TemplateCache) -> None:
    offset = start
    while end - offset >= 4:
        template_id, count = struct.unpack_from("!HH", data, offset)
        offset += 4
        if template_id < 256:
            raise FlowDecodeError(f"invalid NetFlow v9 template id {template_id}")
        if count == 0 or count > MAX_TEMPLATE_FIELDS:
            raise FlowDecodeError(f"invalid NetFlow v9 field count {count}")
        if offset + count * 4 > end:
            raise FlowDecodeError("truncated NetFlow v9 template")
        fields = tuple((fid, length, 0) for fid, length in
                       (struct.unpack_from("!HH", data, offset + 4 * i) for i in range(count)))
        offset += count * 4
        cache.put(exporter, domain, template_id, Template(fields))


def _v9_options_set(data: bytes, start: int, end: int, exporter: str, domain: int, cache: TemplateCache) -> None:
    offset = start
    while end - offset >= 6:
        template_id, scope_len, option_len = struct.unpack_from("!HHH", data, offset)
        offset += 6
        if template_id < 256 or scope_len % 4 or option_len % 4:
            raise FlowDecodeError("invalid NetFlow v9 options template")
        total = scope_len + option_len
        if offset + total > end:
            raise FlowDecodeError("truncated NetFlow v9 options template")
        # Scope field types live in a different namespace (1=System, 2=Interface, ...): mark them so
        # they are never mistaken for flow fields when the options data is read.
        scope = [(0x10000 | fid, length, 0) for fid, length in
                 (struct.unpack_from("!HH", data, offset + i) for i in range(0, scope_len, 4))]
        options = [(fid, length, 0) for fid, length in
                   (struct.unpack_from("!HH", data, offset + scope_len + i) for i in range(0, option_len, 4))]
        offset += total
        if not scope and not options:
            raise FlowDecodeError("empty NetFlow v9 options template")
        cache.put(exporter, domain, template_id, Template(tuple(scope + options), options=True))
        # Anything left that is shorter than an options template header is padding.


def _read_fields(data: bytes, offset: int, end: int, template: Template) -> tuple[dict[int, bytes], int]:
    """Read one record laid out by ``template``; returns ({element id: raw}, new offset)."""
    values: dict[int, bytes] = {}
    for fid, length, enterprise in template.fields:
        if length == VARIABLE_LENGTH:
            if offset >= end:
                raise FlowDecodeError("truncated variable-length field")
            length = data[offset]
            offset += 1
            if length == 255:
                if offset + 2 > end:
                    raise FlowDecodeError("truncated variable-length field")
                length = struct.unpack_from("!H", data, offset)[0]
                offset += 2
        if offset + length > end:
            raise FlowDecodeError("truncated data record")
        if not enterprise:
            values.setdefault(fid, data[offset:offset + length])
        offset += length
    return values, offset


def _data_set(
    data: bytes, start: int, end: int, template: Template, exporter: str, cache: TemplateCache,
    export_secs: float, sys_uptime_ms: int | None, result: DecodeResult,
) -> None:
    min_len = template.min_length
    if min_len <= 0:
        result.skipped += 1
        return
    offset = start
    while end - offset >= min_len:
        if template.fixed:
            values, offset = _read_fields(data, offset, offset + min_len, template)
        else:
            values, offset = _read_fields(data, offset, end, template)
        if template.options:
            rate = _sampling_from(values)
            if rate:
                cache.set_sampling(exporter, rate)
            continue
        rate = cache.sampling_for(exporter)
        rec = _record_from_fields(values, export_secs, sys_uptime_ms, rate)
        if rec is None:
            result.skipped += 1
            continue
        result.sampling = max(result.sampling, _sampling_from(values) or rate)
        result.records.append(rec)


def decode_netflow_v9(data: bytes, exporter: str, cache: TemplateCache) -> DecodeResult:
    """Decode a NetFlow v9 export packet (RFC 3954)."""
    _need(data, 0, _V9_HEADER.size, "NetFlow v9 header")
    version, _count, uptime, secs, _seq, source_id = _V9_HEADER.unpack_from(data, 0)
    if version != 9:
        raise FlowDecodeError(f"not a NetFlow v9 packet (version {version})")
    result = DecodeResult("netflow9", sampling=1)
    pending: list[tuple[int, int, int]] = []
    offset = _V9_HEADER.size
    while len(data) - offset >= 4:
        set_id, length = _SET_HEADER.unpack_from(data, offset)
        if length < 4 or offset + length > len(data):
            raise FlowDecodeError(f"bad NetFlow v9 FlowSet length {length} at offset {offset}")
        body, end = offset + 4, offset + length
        if set_id == 0:
            _v9_template_set(data, body, end, exporter, source_id, cache)
        elif set_id == 1:
            _v9_options_set(data, body, end, exporter, source_id, cache)
        elif set_id >= 256:
            pending.append((set_id, body, end))
        offset = end
    # Data FlowSets are processed after the templates of the same packet were learned.
    _decode_data_sets(data, pending, exporter, source_id, cache, float(secs), uptime, result)
    return result


def _decode_data_sets(
    data: bytes, pending: list[tuple[int, int, int]], exporter: str, domain: int, cache: TemplateCache,
    export_secs: float, sys_uptime_ms: int | None, result: DecodeResult,
) -> None:
    # Options data first so sampling learned in this packet applies to its flow records.
    lookups = [(cache.get(exporter, domain, set_id), body, end) for set_id, body, end in pending]
    lookups.sort(key=lambda item: 0 if item[0] is not None and item[0].options else 1)
    for template, body, end in lookups:
        if template is None:
            result.skipped += 1
            continue
        _data_set(data, body, end, template, exporter, cache, export_secs, sys_uptime_ms, result)
    if result.sampling == 1:
        result.sampling = cache.sampling_for(exporter)


# ---------------------------------------------------------------------------- IPFIX
def _ipfix_fields(data: bytes, offset: int, end: int, count: int) -> tuple[list[tuple[int, int, int]], int]:
    fields = []
    for _ in range(count):
        if offset + 4 > end:
            raise FlowDecodeError("truncated IPFIX template")
        ie, length = struct.unpack_from("!HH", data, offset)
        offset += 4
        enterprise = 0
        if ie & 0x8000:
            if offset + 4 > end:
                raise FlowDecodeError("truncated IPFIX enterprise field")
            enterprise = struct.unpack_from("!I", data, offset)[0] or 0xFFFFFFFF
            ie &= 0x7FFF
            offset += 4
        fields.append((ie, length, enterprise))
    return fields, offset


def _ipfix_template_set(
    data: bytes, start: int, end: int, exporter: str, domain: int, cache: TemplateCache, options: bool
) -> None:
    offset = start
    header = 6 if options else 4
    while end - offset >= header:
        if options:
            template_id, count, scope_count = struct.unpack_from("!HHH", data, offset)
        else:
            (template_id, count), scope_count = struct.unpack_from("!HH", data, offset), 0
        if template_id == 0 and count == 0:
            break  # padding
        offset += 4 if count == 0 else header
        if count == 0:  # template withdrawal (set-id-as-template-id withdraws all)
            cache.withdraw(exporter, domain, None if template_id in (2, 3) else template_id)
            continue
        if template_id < 256:
            raise FlowDecodeError(f"invalid IPFIX template id {template_id}")
        if count > MAX_TEMPLATE_FIELDS or scope_count > count or (options and scope_count == 0):
            raise FlowDecodeError(f"invalid IPFIX template field count {count}")
        fields, offset = _ipfix_fields(data, offset, end, count)
        if options:  # keep scope fields out of the flow-field namespace
            fields = [(0x10000 | fid, ln, ent) for fid, ln, ent in fields[:scope_count]] + fields[scope_count:]
        cache.put(exporter, domain, template_id, Template(tuple(fields), options=options))


def decode_ipfix(data: bytes, exporter: str, cache: TemplateCache) -> DecodeResult:
    """Decode an IPFIX message (RFC 7011)."""
    _need(data, 0, _IPFIX_HEADER.size, "IPFIX header")
    version, length, export_time, _seq, domain = _IPFIX_HEADER.unpack_from(data, 0)
    if version != 10:
        raise FlowDecodeError(f"not an IPFIX message (version {version})")
    if length < _IPFIX_HEADER.size or length > len(data):
        raise FlowDecodeError(f"bad IPFIX message length {length} (datagram {len(data)})")
    result = DecodeResult("ipfix", sampling=1)
    pending: list[tuple[int, int, int]] = []
    offset = _IPFIX_HEADER.size
    while length - offset >= 4:
        set_id, set_len = _SET_HEADER.unpack_from(data, offset)
        if set_len < 4 or offset + set_len > length:
            raise FlowDecodeError(f"bad IPFIX set length {set_len} at offset {offset}")
        body, end = offset + 4, offset + set_len
        if set_id == 2:
            _ipfix_template_set(data, body, end, exporter, domain, cache, options=False)
        elif set_id == 3:
            _ipfix_template_set(data, body, end, exporter, domain, cache, options=True)
        elif set_id >= 256:
            pending.append((set_id, body, end))
        elif set_id in (0, 1):
            raise FlowDecodeError(f"NetFlow v9 set id {set_id} in IPFIX message")
        offset = end
    _decode_data_sets(data, pending, exporter, domain, cache, float(export_time), None, result)
    return result


# ---------------------------------------------------------------------------- sFlow v5
def parse_ethernet(frame: bytes) -> dict[str, Any] | None:
    """Extract src/dst/proto/ports from a (possibly truncated) Ethernet frame header.

    Handles 802.1Q / QinQ tags, IPv4 (non-first fragments carry no ports) and IPv6 with the common
    extension headers. Returns ``None`` for non-IP frames or headers too short to hold addresses.
    """
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ethertype in ETH_VLAN:
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ethertype == ETH_IPV4:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        if frame[offset] >> 4 != 4 or ihl < 20:
            return None
        frag = struct.unpack_from("!H", frame, offset + 6)[0] & 0x1FFF
        proto = frame[offset + 9]
        src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
        dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
        l4 = offset + ihl if frag == 0 else -1
    elif ethertype == ETH_IPV6:
        if len(frame) < offset + 40:
            return None
        if frame[offset] >> 4 != 6:
            return None
        proto = frame[offset + 6]
        src = str(ipaddress.IPv6Address(frame[offset + 8:offset + 24]))
        dst = str(ipaddress.IPv6Address(frame[offset + 24:offset + 40]))
        l4 = offset + 40
        for _ in range(8):  # walk extension headers
            if proto == 44:  # fragment header: ports only in the first fragment
                if len(frame) < l4 + 8:
                    l4 = -1
                    break
                first = (struct.unpack_from("!H", frame, l4 + 2)[0] >> 3) == 0
                proto = frame[l4]
                l4 = l4 + 8 if first else -1
                if l4 < 0:
                    break
            elif proto in _IPV6_EXT_HEADERS:
                if len(frame) < l4 + 2:
                    l4 = -1
                    break
                proto, l4 = frame[l4], l4 + (frame[l4 + 1] + 1) * 8
            else:
                break
    else:
        return None
    sport = dport = 0
    if l4 >= 0:
        if proto in _PORT_PROTOCOLS and len(frame) >= l4 + 4:
            sport, dport = struct.unpack_from("!HH", frame, l4)
        elif proto in (1, 58) and len(frame) >= l4 + 2:
            dport = frame[l4] << 8 | frame[l4 + 1]  # ICMP type/code, as NetFlow encodes it
    return {"src": src, "dst": dst, "proto": proto, "sport": sport, "dport": dport}


class _XdrReader:
    """Tiny bounds-checked reader for sFlow's XDR (big-endian, 4-byte aligned) encoding."""

    def __init__(self, data: bytes, offset: int = 0, end: int | None = None):
        self.data = data
        self.offset = offset
        self.end = len(data) if end is None else end

    def u32(self) -> int:
        if self.offset + 4 > self.end:
            raise FlowDecodeError("truncated sFlow datagram")
        value = struct.unpack_from("!I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def raw(self, size: int) -> bytes:
        if size < 0 or self.offset + size > self.end:
            raise FlowDecodeError("truncated sFlow datagram")
        value = self.data[self.offset:self.offset + size]
        self.offset += (size + 3) & ~3
        self.offset = min(self.offset, self.end)
        return value

    def sub(self, size: int) -> "_XdrReader":
        if size < 0 or self.offset + size > self.end:
            raise FlowDecodeError("truncated sFlow structure")
        reader = _XdrReader(self.data, self.offset, self.offset + size)
        self.offset += size
        return reader

    def address(self) -> str:
        kind = self.u32()
        if kind == 1:
            return str(ipaddress.IPv4Address(self.raw(4)))
        if kind == 2:
            return str(ipaddress.IPv6Address(self.raw(16)))
        if kind == 0:
            return ""
        raise FlowDecodeError(f"unknown sFlow address type {kind}")


def _sflow_interface(value: int) -> int:
    """Decode a compact (format 1) interface: 2-bit format, 30-bit value; only ifIndex is kept."""
    if value >> 30 != 0:
        return 0
    value &= 0x3FFFFFFF
    return 0 if value == 0x3FFFFFFF else value


def _sflow_flow_sample(reader: _XdrReader, expanded: bool, result: DecodeResult) -> None:
    reader.u32()  # sequence number
    if expanded:
        reader.u32()  # source id type
        reader.u32()  # source id index
    else:
        reader.u32()  # source id (type << 24 | index)
    rate = reader.u32() or 1
    reader.u32()  # sample pool
    reader.u32()  # drops
    if expanded:
        in_fmt, in_val, out_fmt, out_val = reader.u32(), reader.u32(), reader.u32(), reader.u32()
        in_if = in_val if in_fmt == 0 and in_val != 0x3FFFFFFF else 0
        out_if = out_val if out_fmt == 0 and out_val != 0x3FFFFFFF else 0
    else:
        in_if, out_if = _sflow_interface(reader.u32()), _sflow_interface(reader.u32())
    nrecords = reader.u32()
    if nrecords > 1024:
        raise FlowDecodeError(f"implausible sFlow record count {nrecords}")
    found: dict[str, Any] | None = None
    frame_length = 0
    for _ in range(nrecords):
        fmt = reader.u32()
        body = reader.sub(reader.u32())
        if fmt == 1 and found is None:  # raw packet header
            header_protocol = body.u32()
            frame_length = body.u32()
            body.u32()  # stripped
            header = body.raw(body.u32())
            if header_protocol == 1:
                found = parse_ethernet(header)
        elif fmt in (3, 4) and found is None:  # sampled IPv4 / IPv6
            frame_length = body.u32()
            proto = body.u32()
            src_dst = (body.raw(4), body.raw(4)) if fmt == 3 else (body.raw(16), body.raw(16))
            sport, dport = body.u32(), body.u32()
            found = {"src": _addr(src_dst[0]), "dst": _addr(src_dst[1]), "proto": proto & 0xFF,
                     "sport": sport & 0xFFFF, "dport": dport & 0xFFFF}
    if found is None:
        result.skipped += 1
        return
    result.sampling = max(result.sampling, rate)
    result.records.append({
        **found,
        "in_if": in_if,
        "out_if": out_if,
        "bytes": frame_length * rate,
        "packets": rate,
    })


def decode_sflow(data: bytes) -> DecodeResult:
    """Decode an sFlow v5 datagram: flow samples (formats 1 and 3) with packet header records."""
    reader = _XdrReader(data)
    version = reader.u32()
    if version != 5:
        raise FlowDecodeError(f"unsupported sFlow version {version}")
    result = DecodeResult("sflow", sampling=1)
    result.agent = reader.address()
    reader.u32()  # sub agent id
    reader.u32()  # sequence
    reader.u32()  # uptime
    nsamples = reader.u32()
    if nsamples > 4096:
        raise FlowDecodeError(f"implausible sFlow sample count {nsamples}")
    for _ in range(nsamples):
        fmt = reader.u32()
        sample = reader.sub(reader.u32())
        enterprise, kind = fmt >> 12, fmt & 0xFFF
        if enterprise == 0 and kind in (1, 3):
            _sflow_flow_sample(sample, kind == 3, result)
        # counter samples (2, 4) and vendor structures are ignored
    return result


# ---------------------------------------------------------------------------- dispatch
def decode(data: bytes, exporter: str, cache: TemplateCache) -> DecodeResult:
    """Sniff the export format of ``data`` and decode it.

    ``exporter`` is the datagram's source address (used to key cached templates and sampling).
    Raises :class:`FlowDecodeError` for anything that cannot be decoded.
    """
    if len(data) < 4:
        raise FlowDecodeError("datagram too short")
    try:
        if data[:4] == b"\x00\x00\x00\x05":
            return decode_sflow(data)
        version = struct.unpack_from("!H", data, 0)[0]
        if version == 5:
            return decode_netflow_v5(data)
        if version == 9:
            return decode_netflow_v9(data, exporter, cache)
        if version == 10:
            return decode_ipfix(data, exporter, cache)
    except FlowDecodeError:
        raise
    except (struct.error, IndexError, ValueError, TypeError, OverflowError) as exc:
        raise FlowDecodeError(f"malformed flow datagram: {exc}") from exc
    raise FlowDecodeError(f"unsupported flow export version {version}")
