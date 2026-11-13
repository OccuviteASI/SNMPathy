"""SNMPathy - self-hosted network monitoring (SNMP, syslog, uptime)."""

__version__ = "0.6.2"

# Filled in by scripts/build_executable.py (git commit and build date) so a built
# executable can be told apart from older builds of the same version.
try:
    from ._build import BUILD
except ImportError:  # running from a source checkout or a pip install
    BUILD = ""


def version_string() -> str:
    """``0.6.0`` or ``0.6.0 (build 5c25a54, 2026-11-12)``."""
    return f"{__version__} (build {BUILD})" if BUILD else __version__
