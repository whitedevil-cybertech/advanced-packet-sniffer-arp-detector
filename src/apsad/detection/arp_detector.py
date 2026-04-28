"""
arp_detector.py – ARP table monitoring and spoofing / MITM detection (defensive).

Security logic (false-positive reduction)
----------------------------------------
Instead of alerting immediately on any IP→MAC change (which can happen
legitimately due to DHCP renewals, virtualization, HA gateways), we:

- Maintain a "current mapping" per IP with last_seen timestamps.
- Expire stale entries after ttl_seconds.
- Track mapping-change events within a rolling window_seconds.
- Alert only if the number of changes within the window reaches change_threshold.
- Support whitelists (IPs, MACs, and allowed IP↔MAC pairs).

This provides more SOC-realistic behavior: observe → score → alert,
with optional active confirmation (implemented elsewhere).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Optional, Set, Tuple


@dataclass
class MappingState:
    mac: str
    last_seen: float


class ARPDetector:
    """Thread-safe ARP spoofing detector (defensive-first).

    Parameters
    ----------
    alert_callback:
        Callable ``(message: str)`` invoked when a suspicious mapping crosses
        the configured threshold.
    ttl_seconds:
        Expire unseen mappings after this many seconds.
    window_seconds:
        Rolling window for counting mapping changes.
    change_threshold:
        Number of IP→MAC changes within window_seconds required to alert.
    whitelist_ips / whitelist_macs / whitelist_pairs:
        Suppress alerts for known-legitimate entities.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[str], None]] = None,
        *,
        ttl_seconds: int = 600,
        window_seconds: int = 30,
        change_threshold: int = 2,
        whitelist_ips: Optional[Set[str]] = None,
        whitelist_macs: Optional[Set[str]] = None,
        whitelist_pairs: Optional[Set[Tuple[str, str]]] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._alert = alert_callback or self._default_alert

        self.ttl_seconds = ttl_seconds
        self.window_seconds = window_seconds
        self.change_threshold = change_threshold

        self.whitelist_ips: Set[str] = set(whitelist_ips or set())
        self.whitelist_macs: Set[str] = set(whitelist_macs or set())
        self.whitelist_pairs: Set[Tuple[str, str]] = set(whitelist_pairs or set())

        # Current "best known" mapping per IP
        self._ip_state: Dict[str, MappingState] = {}

        # Recent mapping changes per IP: deque[timestamps]
        self._ip_change_times: Dict[str, Deque[float]] = defaultdict(deque)

        # Observed MACs per IP (for reporting)
        self._ip_to_macs: Dict[str, Set[str]] = defaultdict(set)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process_arp(self, src_ip: str, src_mac: str, op: int) -> None:
        """Analyse one ARP packet (request or reply).

        We treat both requests and replies as potentially cache-influencing
        events because some systems update caches on gratuitous patterns.
        """
        if not src_ip or not src_mac:
            return

        now = time.time()

        # Whitelist suppression
        if src_ip in self.whitelist_ips:
            return
        if src_mac in self.whitelist_macs:
            return
        if (src_ip, src_mac) in self.whitelist_pairs:
            return

        with self._lock:
            self._expire_old(now)
            self._check_and_update(src_ip, src_mac, now, op)

    def get_arp_table(self) -> Dict[str, Set[str]]:
        """Return a snapshot of the learned IP → MAC(s) mapping."""
        with self._lock:
            return {ip: set(macs) for ip, macs in self._ip_to_macs.items()}

    def reset(self) -> None:
        """Clear all learned mappings (useful for testing)."""
        with self._lock:
            self._ip_state.clear()
            self._ip_change_times.clear()
            self._ip_to_macs.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _expire_old(self, now: float) -> None:
        """Expire old IP states to reduce stale-data false positives."""
        if self.ttl_seconds <= 0:
            return

        expired = [ip for ip, st in self._ip_state.items() if (now - st.last_seen) > self.ttl_seconds]
        for ip in expired:
            self._ip_state.pop(ip, None)
            self._ip_change_times.pop(ip, None)
            # Keep historical ip_to_macs for operator visibility, or clear it:
            # self._ip_to_macs.pop(ip, None)

    def _check_and_update(self, src_ip: str, src_mac: str, now: float, op: int) -> None:
        # Track MAC history for reporting/visibility
        self._ip_to_macs[src_ip].add(src_mac)

        prev = self._ip_state.get(src_ip)
        if prev is None:
            self._ip_state[src_ip] = MappingState(mac=src_mac, last_seen=now)
            return

        # Update last_seen even if MAC stays same
        if prev.mac == src_mac:
            prev.last_seen = now
            return

        # MAC changed: record a change event (rolling window)
        changes = self._ip_change_times[src_ip]
        changes.append(now)
        self._prune_deque(changes, now, self.window_seconds)

        # Update current state to latest observed mapping (we continue tracking)
        self._ip_state[src_ip] = MappingState(mac=src_mac, last_seen=now)

        # Threshold check
        if self.change_threshold > 0 and len(changes) >= self.change_threshold:
            observed = ", ".join(sorted(self._ip_to_macs[src_ip]))
            self._alert(
                "[ARP SPOOF SUSPECT] "
                f"IP {src_ip!r} changed MAC {len(changes)} time(s) within "
                f"{self.window_seconds}s (threshold={self.change_threshold}). "
                f"Now={src_mac!r}. Observed MACs=[{observed}]. "
                "This can be ARP poisoning, but may also be DHCP/HA/virtualization. "
                "Consider enabling active confirmation and/or whitelisting."
            )

    @staticmethod
    def _prune_deque(dq: Deque[float], now: float, window_seconds: int) -> None:
        if window_seconds <= 0:
            return
        cutoff = now - window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    @staticmethod
    def _default_alert(message: str) -> None:
        print(f"\n[!] {message}\n")