"""
arp_detector.py – ARP table monitoring and spoofing / MITM detection.

How it works
------------
Every time an ARP *reply* is observed the module checks the IP→MAC mapping
stored in the local ARP table.  A conflict is flagged when:

  1. The IP address is already bound to a *different* MAC address, OR
  2. The same MAC address claims to own *multiple* IP addresses (unlikely in
     normal operation, common in ARP poisoning).

Alerts are issued via the alert logger (console + file) so the operator sees
them immediately even when packet logging is disabled.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Callable, Dict, Optional, Set


class ARPDetector:
    """Thread-safe ARP spoofing detector.

    Parameters
    ----------
    alert_callback:
        Optional callable ``(message: str)`` that is invoked whenever a
        suspicious ARP mapping is detected.  Defaults to printing to stdout.
    """

    def __init__(self, alert_callback: Optional[Callable[[str], None]] = None) -> None:
        # ip  -> set of MACs that have claimed to own it
        self._ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
        # mac -> set of IPs that the MAC has claimed to own
        self._mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        self._lock = threading.Lock()
        self._alert = alert_callback or self._default_alert

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process_arp(self, src_ip: str, src_mac: str, op: int) -> None:
        """Analyse one ARP packet.

        Parameters
        ----------
        src_ip:  sender IP address from the ARP payload.
        src_mac: sender MAC address from the ARP payload.
        op:      ARP operation code (1 = request, 2 = reply).
        """
        # Monitor both requests and replies; attackers sometimes use requests
        # to poison caches on hosts that implement "gratuitous" updates.
        with self._lock:
            self._check_and_update(src_ip, src_mac)

    def get_arp_table(self) -> Dict[str, Set[str]]:
        """Return a snapshot of the current IP → MAC(s) mapping."""
        with self._lock:
            return {ip: set(macs) for ip, macs in self._ip_to_macs.items()}

    def reset(self) -> None:
        """Clear all learned mappings (useful for testing)."""
        with self._lock:
            self._ip_to_macs.clear()
            self._mac_to_ips.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_and_update(self, src_ip: str, src_mac: str) -> None:
        known_macs = self._ip_to_macs[src_ip]
        known_ips = self._mac_to_ips[src_mac]

        # --- Conflict 1: same IP claimed by more than one MAC ---------------
        if known_macs and src_mac not in known_macs:
            existing = ", ".join(sorted(known_macs))
            self._alert(
                f"[ARP SPOOFING DETECTED] IP {src_ip!r} was previously "
                f"mapped to MAC(s) [{existing}] but now claims MAC "
                f"{src_mac!r}.  Possible ARP poisoning / MITM attack!"
            )

        # --- Conflict 2: same MAC claiming many IPs -------------------------
        if len(known_ips) >= 2 and src_ip not in known_ips:
            existing_ips = ", ".join(sorted(known_ips))
            self._alert(
                f"[ARP ANOMALY] MAC {src_mac!r} already owns IPs "
                f"[{existing_ips}] and now also claims {src_ip!r}.  "
                f"Possible ARP flooding or multi-IP gateway – verify!"
            )

        # Update tables regardless (so we keep tracking the attacker's MACs)
        self._ip_to_macs[src_ip].add(src_mac)
        self._mac_to_ips[src_mac].add(src_ip)

    @staticmethod
    def _default_alert(message: str) -> None:
        print(f"\n⚠  {message}\n")
