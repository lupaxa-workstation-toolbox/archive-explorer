"""Human-readable sizes and timestamps."""

from __future__ import annotations

from datetime import datetime


def format_bytes(size: int | None) -> str:
    """Format a byte count using binary units."""
    if size is None:
        return "unavailable"
    value = float(size)
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    unit = units[0]
    for name in units:
        unit = name
        if value < 1024 or name == units[-1]:
            break
        value /= 1024
    if unit == "B":
        return f"{size} B"
    return f"{value:.1f} {unit}"


def format_count(value: int) -> str:
    """Format an integer with grouping separators."""
    return f"{value:,}"


def format_percent(ratio: float | None) -> str:
    """Format a saving ratio in the range 0 to 1."""
    if ratio is None:
        return "unavailable"
    return f"{ratio * 100:.1f}%"


def format_time(value: datetime | None, timezone: str | None) -> str:
    """Format a timestamp without inventing a zone."""
    if value is None:
        return "unavailable"
    if timezone:
        return f"{value.isoformat()} ({timezone})"
    return value.isoformat()
