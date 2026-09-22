"""Async SNMP client built on pysnmp.

The rest of SNMPathy only depends on the small :class:`SnmpClient`
protocol (``get`` / ``walk``), which keeps the poller testable with the
in-memory :class:`FakeSnmpClient`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import warnings
from dataclasses import dataclass
from typing import Any, Protocol

# pysnmp's AES module triggers a noisy deprecation warning in newer
# versions of `cryptography`; it is harmless.
warnings.filterwarnings("ignore", message=".*CFB has been moved.*")


class SnmpError(Exception):
    """Raised when an SNMP request fails (timeout, auth error, ...)."""


@dataclass
class SnmpCredentials:
    version: str = "2c"          # "1", "2c" or "3"
    community: str = "public"
    port: int = 161
    v3_user: str = ""
    v3_auth_proto: str = "sha"   # none|md5|sha|sha224|sha256|sha384|sha512
    v3_auth_key: str = ""
    v3_priv_proto: str = "aes"   # none|des|3des|aes|aes192|aes256
    v3_priv_key: str = ""
    v3_context: str = ""

    @classmethod
    def from_device(cls, device: dict[str, Any]) -> "SnmpCredentials":
        return cls(
            version=str(device.get("snmp_version") or "2c"),
            community=device.get("snmp_community") or "public",
            port=int(device.get("snmp_port") or 161),
            v3_user=device.get("v3_user") or "",
            v3_auth_proto=device.get("v3_auth_proto") or "sha",
            v3_auth_key=device.get("v3_auth_key") or "",
            v3_priv_proto=device.get("v3_priv_proto") or "aes",
            v3_priv_key=device.get("v3_priv_key") or "",
            v3_context=device.get("v3_context") or "",
        )


# Values returned to callers are plain Python types:
#   int for INTEGER/Counter*/Gauge32/TimeTicks, str for OID / text,
#   bytes for non-printable OCTET STRINGs, None for noSuch*/endOfMib.
SnmpValue = int | float | str | bytes | None


class SnmpClient(Protocol):
    async def get(self, oids: list[str]) -> dict[str, SnmpValue]: ...

    async def walk(self, oid: str) -> dict[str, SnmpValue]: ...

    def close(self) -> None: ...


def normalize_oid(oid: str) -> str:
    return oid.strip().lstrip(".")


def convert_value(value: Any) -> SnmpValue:
    """Convert a pysnmp value object into a plain Python value."""
    name = type(value).__name__
    if name in {"NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"}:
        return None
    if name in {"Integer", "Integer32", "Unsigned32", "Counter32", "Counter64", "Gauge32", "TimeTicks"}:
        return int(value)
    if name in {"ObjectIdentifier", "ObjectName", "ObjectIdentity"}:
        return str(value)
    if name == "IpAddress":
        return ".".join(str(b) for b in value.asOctets())
    if name in {"OctetString", "Opaque", "Bits"} or hasattr(value, "asOctets"):
        raw = bytes(value.asOctets())
        return decode_octets(raw)
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


def decode_octets(raw: bytes) -> str | bytes:
    """Return text for printable OCTET STRINGs, raw bytes otherwise."""
    if not raw:
        return ""
    stripped = raw.rstrip(b"\x00")
    try:
        text = stripped.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
        return text
    return raw


def format_mac(value: SnmpValue) -> str:
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{b:02x}" for b in value)
    if isinstance(value, str) and len(value) == 6 and not value.isprintable():
        return ":".join(f"{ord(c):02x}" for c in value)
    if isinstance(value, bytes):
        return value.hex(":")
    return str(value or "")


def as_text(value: SnmpValue) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


class PySnmpClient:
    """Real SNMP client (v1/v2c/v3) using the pysnmp asyncio HLAPI."""

    GET_BATCH = 24          # varbinds per GET PDU
    MAX_REPETITIONS = 25    # GETBULK repetitions

    def __init__(self, host: str, creds: SnmpCredentials, timeout: float = 2.0, retries: int = 1):
        from pysnmp.hlapi.v3arch import asyncio as hl

        self._hl = hl
        self.host = host
        self.creds = creds
        self.timeout = timeout
        self.retries = retries
        self.engine = hl.SnmpEngine()
        self._target = None
        self._auth = self._build_auth()
        self._context = hl.ContextData(contextName=creds.v3_context) if creds.v3_context else hl.ContextData()

    # -- setup -----------------------------------------------------------
    def _build_auth(self):
        hl = self._hl
        c = self.creds
        if c.version in {"1", "v1"}:
            return hl.CommunityData(c.community, mpModel=0)
        if c.version in {"2", "2c", "v2c"}:
            return hl.CommunityData(c.community, mpModel=1)
        if c.version in {"3", "v3"}:
            auth_protocols = {
                "none": hl.usmNoAuthProtocol,
                "md5": hl.usmHMACMD5AuthProtocol,
                "sha": hl.usmHMACSHAAuthProtocol,
                "sha224": hl.usmHMAC128SHA224AuthProtocol,
                "sha256": hl.usmHMAC192SHA256AuthProtocol,
                "sha384": hl.usmHMAC256SHA384AuthProtocol,
                "sha512": hl.usmHMAC384SHA512AuthProtocol,
            }
            priv_protocols = {
                "none": hl.usmNoPrivProtocol,
                "des": hl.usmDESPrivProtocol,
                "3des": hl.usm3DESEDEPrivProtocol,
                "aes": hl.usmAesCfb128Protocol,
                "aes128": hl.usmAesCfb128Protocol,
                "aes192": hl.usmAesCfb192Protocol,
                "aes256": hl.usmAesCfb256Protocol,
            }
            auth_proto = auth_protocols.get((c.v3_auth_proto or "none").lower())
            priv_proto = priv_protocols.get((c.v3_priv_proto or "none").lower())
            if auth_proto is None:
                raise SnmpError(f"unsupported SNMPv3 auth protocol {c.v3_auth_proto!r}")
            if priv_proto is None:
                raise SnmpError(f"unsupported SNMPv3 privacy protocol {c.v3_priv_proto!r}")
            auth_key = c.v3_auth_key or None
            priv_key = c.v3_priv_key or None
            if not auth_key:
                auth_proto, priv_proto, priv_key = hl.usmNoAuthProtocol, hl.usmNoPrivProtocol, None
            elif not priv_key:
                priv_proto = hl.usmNoPrivProtocol
            return hl.UsmUserData(
                c.v3_user,
                authKey=auth_key,
                privKey=priv_key,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        raise SnmpError(f"unsupported SNMP version {c.version!r}")

    async def _get_target(self):
        if self._target is None:
            hl = self._hl
            try:
                is_v6 = ipaddress.ip_address(self.host).version == 6
            except ValueError:
                is_v6 = False
            cls = hl.Udp6TransportTarget if is_v6 else hl.UdpTransportTarget
            try:
                self._target = await cls.create(
                    (self.host, self.creds.port), timeout=self.timeout, retries=self.retries
                )
            except Exception as exc:  # DNS failures etc.
                raise SnmpError(f"cannot resolve {self.host}: {exc}") from exc
        return self._target

    # -- operations ------------------------------------------------------
    async def get(self, oids: list[str]) -> dict[str, SnmpValue]:
        hl = self._hl
        target = await self._get_target()
        result: dict[str, SnmpValue] = {}
        oids = [normalize_oid(o) for o in oids]
        for start in range(0, len(oids), self.GET_BATCH):
            chunk = oids[start : start + self.GET_BATCH]
            err_ind, err_status, err_index, var_binds = await hl.get_cmd(
                self.engine,
                self._auth,
                target,
                self._context,
                *[hl.ObjectType(hl.ObjectIdentity(o)) for o in chunk],
                lookupMib=False,
            )
            if err_ind:
                raise SnmpError(str(err_ind))
            if err_status:
                # v1 agents answer noSuchName for the whole PDU; retry one by one.
                if len(chunk) > 1:
                    for oid in chunk:
                        try:
                            result.update(await self.get([oid]))
                        except SnmpError:
                            result[oid] = None
                    continue
                if err_status.prettyPrint() in {"noSuchName"}:
                    result[chunk[0]] = None
                    continue
                raise SnmpError(err_status.prettyPrint())
            for name, value in var_binds:
                result[str(name)] = convert_value(value)
        return result

    async def walk(self, oid: str) -> dict[str, SnmpValue]:
        hl = self._hl
        target = await self._get_target()
        oid = normalize_oid(oid)
        result: dict[str, SnmpValue] = {}
        if self.creds.version in {"1", "v1"}:
            iterator = hl.walk_cmd(
                self.engine, self._auth, target, self._context,
                hl.ObjectType(hl.ObjectIdentity(oid)),
                lexicographicMode=False, lookupMib=False,
            )
        else:
            iterator = hl.bulk_walk_cmd(
                self.engine, self._auth, target, self._context, 0, self.MAX_REPETITIONS,
                hl.ObjectType(hl.ObjectIdentity(oid)),
                lexicographicMode=False, lookupMib=False,
            )
        prefix = oid + "."
        async for err_ind, err_status, _err_index, var_binds in iterator:
            if err_ind:
                raise SnmpError(str(err_ind))
            if err_status:
                if err_status.prettyPrint() == "noSuchName":
                    break
                raise SnmpError(err_status.prettyPrint())
            for name, value in var_binds:
                name = str(name)
                if not name.startswith(prefix):
                    continue
                converted = convert_value(value)
                if converted is None and type(value).__name__ == "EndOfMibView":
                    continue
                result[name] = converted
        return result

    def close(self) -> None:
        try:
            self.engine.close_dispatcher()
        except Exception:
            pass


class FakeSnmpClient:
    """In-memory SNMP agent used by tests and the demo mode."""

    def __init__(self, data: dict[str, SnmpValue] | None = None, fail: bool = False):
        self.data = {normalize_oid(k): v for k, v in (data or {}).items()}
        self.fail = fail
        self.requests: list[tuple[str, Any]] = []

    def _check(self) -> None:
        if self.fail:
            raise SnmpError("No SNMP response received before timeout")

    async def get(self, oids: list[str]) -> dict[str, SnmpValue]:
        self.requests.append(("get", list(oids)))
        self._check()
        await asyncio.sleep(0)
        return {normalize_oid(o): self.data.get(normalize_oid(o)) for o in oids}

    async def walk(self, oid: str) -> dict[str, SnmpValue]:
        self.requests.append(("walk", oid))
        self._check()
        await asyncio.sleep(0)
        prefix = normalize_oid(oid) + "."
        items = {k: v for k, v in self.data.items() if k.startswith(prefix)}
        return dict(sorted(items.items(), key=lambda kv: oid_sort_key(kv[0])))

    def close(self) -> None:
        pass


def oid_sort_key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in normalize_oid(oid).split(".") if p.isdigit())


def index_of(oid: str, base: str) -> str:
    """Return the table index suffix of ``oid`` relative to column ``base``."""
    return normalize_oid(oid)[len(normalize_oid(base)) + 1 :]
