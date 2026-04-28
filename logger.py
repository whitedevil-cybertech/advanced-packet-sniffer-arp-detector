"""
logger.py – Packet and alert logging for forensic review.
"""

import csv
import logging
import os
from datetime import datetime


LOG_DIR = "logs"
PACKET_LOG = os.path.join(LOG_DIR, "packets.csv")
ALERT_LOG = os.path.join(LOG_DIR, "alerts.log")

_PACKET_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_mac", "dst_mac",
    "protocol", "src_port", "dst_port", "length", "summary",
]


def _ensure_log_dir() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)


def setup_alert_logger() -> logging.Logger:
    """Return a logger that writes alert messages to both console and file."""
    _ensure_log_dir()
    logger = logging.getLogger("arp_alerts")
    if logger.handlers:
        return logger
    logger.setLevel(logging.WARNING)

    fmt = logging.Formatter("%(asctime)s  [%(levelname)s]  %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(ALERT_LOG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def open_packet_csv() -> tuple:
    """Open the packet CSV log and return (file_handle, csv_writer)."""
    _ensure_log_dir()
    file_exists = os.path.isfile(PACKET_LOG)
    fh = open(PACKET_LOG, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(fh, fieldnames=_PACKET_FIELDS)
    if not file_exists:
        writer.writeheader()
    return fh, writer


def log_packet(writer, record: dict) -> None:
    """Append a single packet record to the CSV log."""
    row = {field: record.get(field, "") for field in _PACKET_FIELDS}
    writer.writerow(row)
