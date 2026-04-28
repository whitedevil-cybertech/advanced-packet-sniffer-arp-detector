"""
logger.py – Packet and alert logging for forensic review.

Improvements:
- Configurable log directory / file paths (via functions, not globals).
- Rotating alert logs to prevent unbounded disk usage.
- UTC timestamps in alert logs for consistent correlation.
"""

from __future__ import annotations

import csv
import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional, Tuple


_PACKET_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_mac", "dst_mac",
    "protocol", "src_port", "dst_port", "length", "summary",
]


def ensure_log_dir(log_dir: str) -> None:
    os.makedirs(log_dir, exist_ok=True)


def setup_alert_logger(
    *,
    log_dir: str = "logs",
    alert_log_name: str = "alerts.log",
    level: int = logging.WARNING,
    rotate_max_bytes: int = 1_000_000,
    rotate_backup_count: int = 5,
) -> logging.Logger:
    """Return a logger that writes alert messages to both console and file."""
    ensure_log_dir(log_dir)
    logger = logging.getLogger("arp_alerts")

    # Avoid duplicate handlers when main() is invoked multiple times/tests
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    # Use UTC timestamps in logs
    fmt = logging.Formatter(
        "%(asctime)sZ  [%(levelname)s]  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    fmt.converter = __import__("time").gmtime  # force UTC

    alert_path = os.path.join(log_dir, alert_log_name)

    fh = RotatingFileHandler(
        alert_path,
        maxBytes=rotate_max_bytes,
        backupCount=rotate_backup_count,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def open_packet_csv(
    *,
    log_dir: str = "logs",
    packet_log_name: str = "packets.csv",
) -> Tuple[object, csv.DictWriter]:
    """Open the packet CSV log and return (file_handle, csv_writer)."""
    ensure_log_dir(log_dir)
    packet_path = os.path.join(log_dir, packet_log_name)
    file_exists = os.path.isfile(packet_path)
    fh = open(packet_path, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=_PACKET_FIELDS)
    if not file_exists:
        writer.writeheader()
    return fh, writer


def log_packet(writer: csv.DictWriter, record: dict) -> None:
    """Append a single packet record to the CSV log."""
    row = {field: record.get(field, "") for field in _PACKET_FIELDS}
    writer.writerow(row)