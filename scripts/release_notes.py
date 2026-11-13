"""Release notes for the GitHub release CI publishes: this version's CHANGELOG section.

    python scripts/release_notes.py --version     prints the version (from snmpathy/__init__.py)
    python scripts/release_notes.py <commit>      prints the notes (the commit is recorded as "build <sha>")
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def version() -> str:
    text = (ROOT / "snmpathy" / "__init__.py").read_text(encoding="utf-8")
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def changelog_section(ver: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(rf"^## {re.escape(ver)}\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    return match.group(1).strip() if match else ""


def notes(commit: str) -> str:
    ver = version()
    body = changelog_section(ver) or "See CHANGELOG.md."
    return (f"{body}\n\n---\nbuild {commit}\n\n"
            "**Updating:** choose **Update SNMPathy** in the tray menu. To install, download the file for "
            "your system below (`SNMPathy-windows.exe` → rename to `SNMPathy.exe`).\n")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    print(version() if arg == "--version" else notes(arg))
