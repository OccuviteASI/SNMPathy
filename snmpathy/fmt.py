"""Human-friendly number formatting shared by the UI, reports and notifications."""

from __future__ import annotations

import time
from typing import Any

from .reports import format_duration


def fmt_bps(value: Any) -> str:
    if value is None:
        return "-"
    value = float(value)
    for div, suffix in ((1e12, "Tbps"), (1e9, "Gbps"), (1e6, "Mbps"), (1e3, "kbps")):
        if abs(value) >= div:
            n = value / div
            text = f"{n:.2f}" if n < 100 else f"{n:.1f}"
            return f"{text.rstrip('0').rstrip('.')} {suffix}"
    return f"{value:.0f} bps"


def fmt_bytes(value: Any) -> str:
    if value is None:
        return "-"
    value = float(value)
    for div, suffix in ((1 << 50, "PiB"), (1 << 40, "TiB"), (1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")):
        if abs(value) >= div:
            return f"{value / div:.1f} {suffix}"
    return f"{value:.0f} B"


def fmt_speed(value: Any) -> str:
    if not value:
        return "-"
    value = float(value)
    for div, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if value >= div:
            n = value / div
            return f"{n:.0f}{suffix}" if n == int(n) else f"{n:.1f}{suffix}"
    return f"{value:.0f}"


def fmt_pct(value: Any, digits: int = 2) -> str:
    if value is None:
        return "-"
    value = float(value)
    if value >= 100:
        return "100%"
    return f"{value:.{digits}f}%"


def fmt_value(value: Any, unit: str = "") -> str:
    if value is None:
        return "-"
    if unit == "bps":
        return fmt_bps(value)
    if unit == "B":
        return fmt_bytes(value)
    if unit == "s":
        return format_duration(value)
    if unit == "%":
        return f"{float(value):.1f}%"
    value = float(value)
    text = f"{value:.2f}".rstrip("0").rstrip(".") if abs(value) < 1000 else f"{value:,.0f}"
    return f"{text} {unit}".strip()


def ago(ts: Any) -> str:
    if not ts:
        return "never"
    delta = time.time() - float(ts)
    if delta < 0:
        return "in " + format_duration(-delta)
    if delta < 5:
        return "just now"
    return format_duration(delta) + " ago"
