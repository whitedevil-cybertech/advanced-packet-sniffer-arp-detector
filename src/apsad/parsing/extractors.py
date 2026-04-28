from __future__ import annotations

import logging
from typing import Dict, Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from apsad.utils.timeutil import utc_timestamp_ms

log = logging.getLogger(__name__)

_PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def extract_packet_info(pkt: Packet, include_summary: bool = False) -> Optional[Dict]:
    """Parse Scapy packet into a normalized dict for display/logging."""
    try:
        info: Dict = {
            "timestamp": utc_timestamp_ms(),
            "src_mac": "",
            "dst_mac": "",
            "src_ip": "",
            "dst_ip": "",
            "protocol": "UNKNOWN",
            "src_port": "",
            "dst_port": "",
            "length": len(pkt),
            "summary": "",
        }

        if include_summary:
            info["summary"] = pkt.summary()

        if pkt.haslayer(Ether):
            info["src_mac"] = pkt[Ether].src
            info["dst_mac"] = pkt[Ether].dst

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            info["protocol"] = "ARP"
            info["src_ip"] = arp.psrc
            info["dst_ip"] = arp.pdst
            info["src_mac"] = arp.hwsrc
            info["dst_mac"] = arp.hwdst
            return info

        if pkt.haslayer(IP):
            ip = pkt[IP]
            info["src_ip"] = ip.src
            info["dst_ip"] = ip.dst
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
    except Exception:
        log.debug("extract_packet_info failed", exc_info=True)
        return None


def format_packet_info(info: Dict) -> str:
    proto = info["protocol"]
    ts = info["timestamp"]

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