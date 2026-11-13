"""Rebuild snmpathy/data/oui.tsv.gz (MAC address prefix -> maker) from the IEEE registry.

Usage: python scripts/build_oui.py oui.txt

``oui.txt`` is the IEEE MA-L registry in its text format
(https://standards-oui.ieee.org/oui/oui.txt; netaddr ships a copy as netaddr/eui/oui.txt).
"""

import gzip
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "snmpathy" / "data" / "oui.tsv.gz"


def main(src: str) -> None:
    table: dict[str, str] = {}
    for line in open(src, encoding="utf-8", errors="replace"):
        m = re.match(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.*\S)?\s*$", line)
        if m and (m.group(2) or "").strip() and m.group(2).strip().lower() != "private":
            table[m.group(1).upper()] = m.group(2).strip()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8", compresslevel=9) as fh:
        fh.writelines(f"{k}\t{v}\n" for k, v in sorted(table.items()))
    print(f"{len(table)} prefixes -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
