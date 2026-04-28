"""
packet_sniffer.py – Real-time packet capture and protocol-level analysis.

Supports filtering by protocol (TCP / UDP / ICMP / ARP) and optional
per-packet callbacks for display and logging.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import sniff


# Protocols we can recognise and name
_PROTO_NAMES: Dict[int, str] = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
}

VALID_FILTERS = {"tcp", "udp", "icmp", "arp", "all"}


def extract_packet_info(pkt: Packet) -> Optional[Dict]:
    """Return a dictionary of parsed fields for *pkt*, or ``None`` if the
    packet does not contain an IP or ARP layer (e.g. raw Ethernet noise)."""

    info: Dict = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "src_mac":   "",
        "dst_mac":   "",
        "src_ip":    "",
        "dst_ip":    "",
        "protocol":  "UNKNOWN",
        "src_port":  "",
        "dst_port":  "",
        "length":    len(pkt),
        "summary":   pkt.summary(),
    }

    # Ethernet layer
    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    # ARP packets (no IP layer in the traditional sense)
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info["protocol"] = "ARP"
        info["src_ip"]   = arp.psrc
        info["dst_ip"]   = arp.pdst
        info["src_mac"]  = arp.hwsrc
        info["dst_mac"]  = arp.hwdst
        return info

    # IP-based packets
    if pkt.haslayer(IP):
        ip = pkt[IP]
        info["src_ip"]  = ip.src
        info["dst_ip"]  = ip.dst
        info["protocol"] = _PROTO_NAMES.get(ip.proto, f"IP/{ip.proto}")

        if pkt.haslayer(TCP):
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
            info["protocol"] = "TCP"
        elif pkt.haslayer(UDP):
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
            info["protocol"] = "UDP"
        elif pkt.haslayer(ICMP):
            info["protocol"] = "ICMP"

        return info

    return None


def format_packet_info(info: Dict) -> str:
    """Return a human-readable single-line summary of *info*."""
    proto = info["protocol"]
    ts    = info["timestamp"]

    if proto == "ARP":
        return (
            f"[{ts}] ARP  {info['src_mac']} ({info['src_ip']}) → "
            f"{info['dst_mac']} ({info['dst_ip']})"
        )

    ports = ""
    if info["src_port"] and info["dst_port"]:
        ports = f"  ports {info['src_port']} → {info['dst_port']}"

    return (
        f"[{ts}] {proto:<5}  {info['src_ip']} → {info['dst_ip']}"
        f"{ports}  len={info['length']}"
    )


class PacketSniffer:
    """Wraps Scapy's sniff() in a stoppable background thread.

    Parameters
    ----------
    iface:
        Network interface to listen on (``None`` = all interfaces).
    protocol_filter:
        One of ``'tcp'``, ``'udp'``, ``'icmp'``, ``'arp'``, or ``'all'``.
    packet_callback:
        Called for every captured packet (receives the raw Scapy ``Packet``).
    count:
        Stop after capturing this many packets (``0`` = capture indefinitely).
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        protocol_filter: str = "all",
        packet_callback: Optional[Callable[[Packet], None]] = None,
        count: int = 0,
    ) -> None:
        if protocol_filter.lower() not in VALID_FILTERS:
            raise ValueError(
                f"Invalid protocol filter {protocol_filter!r}. "
                f"Choose from: {', '.join(sorted(VALID_FILTERS))}"
            )

        self._iface    = iface
        self._filter   = self._build_bpf(protocol_filter.lower())
        self._callback = packet_callback or self._default_callback
        self._count    = count
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.captured_packets: List[Packet] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start sniffing in a background daemon thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the sniffer to stop and wait for the thread to finish."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def sniff_blocking(self) -> None:
        """Run the sniffer in the calling thread (blocking)."""
        self._run()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self) -> None:
        sniff(
            iface=self._iface,
            filter=self._filter if self._filter else None,
            prn=self._handle_packet,
            count=self._count,
            stop_filter=lambda _: self._stop_event.is_set(),
            store=False,
        )

    def _handle_packet(self, pkt: Packet) -> None:
        self.captured_packets.append(pkt)
        self._callback(pkt)

    @staticmethod
    def _default_callback(pkt: Packet) -> None:
        info = extract_packet_info(pkt)
        if info:
            print(format_packet_info(info))

    @staticmethod
    def _build_bpf(protocol: str) -> str:
        """Convert our simple protocol name to a BPF filter string."""
        mapping = {
            "tcp":  "tcp",
            "udp":  "udp",
            "icmp": "icmp",
            "arp":  "arp",
            "all":  "",
        }
        return mapping[protocol]
