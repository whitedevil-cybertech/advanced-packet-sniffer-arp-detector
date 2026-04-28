from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Optional

from scapy.packet import Packet
from scapy.sendrecv import sniff

from apsad.parsing.extractors import extract_packet_info, format_packet_info

log = logging.getLogger(__name__)

VALID_FILTERS = {"tcp", "udp", "icmp", "arp", "all"}


@dataclass
class SnifferStats:
    captured: int = 0
    callback_ok: int = 0
    callback_failed: int = 0


class PacketSniffer:
    def __init__(
        self,
        iface: Optional[str] = None,
        protocol_filter: str = "all",
        packet_callback: Optional[Callable[[Packet], None]] = None,
        count: int = 0,
        max_captured_packets: int = 0,
        poll_timeout: int = 1,  # NEW: seconds per sniff slice (Windows-safe)
    ) -> None:
        if protocol_filter.lower() not in VALID_FILTERS:
            raise ValueError(
                f"Invalid protocol filter {protocol_filter!r}. "
                f"Choose from: {', '.join(sorted(VALID_FILTERS))}"
            )

        self._iface = iface
        self._filter = self._build_bpf(protocol_filter.lower())
        self._callback = packet_callback or self._default_callback
        self._count = count
        self._poll_timeout = max(1, int(poll_timeout))

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.stats = SnifferStats()

        self._capture_buf: Optional[Deque[Packet]] = None
        if max_captured_packets > 0:
            self._capture_buf = deque(maxlen=max_captured_packets)

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def sniff_blocking(self) -> None:
        self._run()

    def _run(self) -> None:
        """
        Windows-safe sniff loop:
        - sniff() can block indefinitely and not evaluate stop_filter until packets arrive.
        - We run sniff() in short timeout slices so Ctrl+C and stop() work even on quiet networks.
        """
        target = self._count if self._count > 0 else None

        while not self._stop_event.is_set():
            if target is not None and self.stats.captured >= target:
                break

            remaining = None
            if target is not None:
                remaining = max(0, target - self.stats.captured)
                if remaining == 0:
                    break

            # Capture for a short time slice. Count is used only to avoid extra processing.
            slice_count = remaining if (remaining is not None and remaining < 5000) else 0

            sniff(
                iface=self._iface,
                filter=self._filter if self._filter else None,
                prn=self._handle_packet,
                count=slice_count,          # 0 means "no limit" within the slice
                timeout=self._poll_timeout, # KEY: ensures we wake up regularly
                store=False,
            )

        log.info(
            "Sniffer exiting: captured=%d ok=%d failed=%d",
            self.stats.captured,
            self.stats.callback_ok,
            self.stats.callback_failed,
        )

    def _handle_packet(self, pkt: Packet) -> None:
        self.stats.captured += 1
        try:
            if self._capture_buf is not None:
                self._capture_buf.append(pkt)
            self._callback(pkt)
            self.stats.callback_ok += 1
        except Exception:
            self.stats.callback_failed += 1
            log.debug("packet callback failed", exc_info=True)

    @staticmethod
    def _default_callback(pkt: Packet) -> None:
        info = extract_packet_info(pkt)
        if info:
            print(format_packet_info(info))

    @staticmethod
    def _build_bpf(protocol: str) -> str:
        mapping = {
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "arp": "arp",
            "all": "",
        }
        return mapping[protocol]