"""HTTPS downloads for the updater and the maker list.

Tries the system's certificate store first (company proxies that inspect HTTPS add their
root there), then certifi's bundle (frozen builds on macOS / Linux may have no usable
system store).
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from . import __version__


class CertificateError(OSError):
    pass


def _contexts() -> list[ssl.SSLContext]:
    out = [ssl.create_default_context()]
    try:
        import certifi

        out.append(ssl.create_default_context(cafile=certifi.where()))
    except Exception:
        pass
    return out


def open_url(url: str, timeout: float = 30, headers: dict[str, str] | None = None, agent: str = "SNMPathy"):
    """urlopen() with SNMPathy's User-Agent; raises urllib errors, or CertificateError."""
    request = urllib.request.Request(url, headers={"User-Agent": f"{agent}/{__version__}", **(headers or {})})
    last: Exception | None = None
    for context in _contexts():
        try:
            return urllib.request.urlopen(request, timeout=timeout, context=context)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                last = exc
                continue
            raise
    raise CertificateError(f"could not verify the certificate of {url.split('/')[2]}: {last}")
