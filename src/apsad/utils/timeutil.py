from __future__ import annotations

from datetime import datetime, timezone


def utc_timestamp_ms() -> str:
    """UTC timestamp with millisecond precision, e.g. 2026-04-28 12:34:56.789Z"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"