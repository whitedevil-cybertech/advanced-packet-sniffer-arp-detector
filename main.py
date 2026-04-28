"""
main.py – CLI entry point for the Advanced Packet Sniffer + ARP Detector.

Usage
-----
    sudo python main.py [options]

Examples
--------
    # Capture all traffic on the default interface, log to CSV
    sudo python main.py --log

    # Capture only ARP packets on eth0 and detect spoofing
    sudo python main.py -i eth0 -p arp --log

    # Capture 50 TCP packets, show the ARP table on exit
    sudo python main.py -p tcp -c 50 --show-arp-table

    # Quiet mode – only show ARP spoofing alerts
    sudo python main.py -p arp --quiet
"""

from __future__ import annotations

import argparse
import signal
import sys

from arp_detector import ARPDetector
from logger import open_packet_csv, log_packet, setup_alert_logger
from packet_sniffer import (
    PacketSniffer,
    VALID_FILTERS,
    extract_packet_info,
    format_packet_info,
)

from scapy.layers.l2 import ARP as ScapyARP


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advanced Packet Sniffer with ARP Spoofing Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-i", "--iface",
        metavar="INTERFACE",
        default=None,
        help="Network interface to sniff (default: all interfaces)",
    )
    parser.add_argument(
        "-p", "--protocol",
        metavar="PROTO",
        default="all",
        choices=sorted(VALID_FILTERS),
        help="Protocol filter: %(choices)s (default: all)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        metavar="N",
        help="Stop after capturing N packets (default: 0 = unlimited)",
    )
    parser.add_argument(
        "--log",
        action="store_true",
        help="Write captured packets to logs/packets.csv",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-packet output; only show ARP alerts",
    )
    parser.add_argument(
        "--show-arp-table",
        action="store_true",
        dest="show_arp_table",
        help="Print the learned ARP table when the sniffer exits",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()

    alert_logger = setup_alert_logger()

    def alert_callback(msg: str) -> None:
        alert_logger.warning(msg)

    arp_detector = ARPDetector(alert_callback=alert_callback)

    # Optionally open the CSV log file
    csv_file, csv_writer = None, None
    if args.log:
        csv_file, csv_writer = open_packet_csv()
        print(f"[*] Logging packets to logs/packets.csv")

    def packet_callback(pkt):
        info = extract_packet_info(pkt)
        if info is None:
            return

        # Print human-readable line (unless --quiet)
        if not args.quiet:
            print(format_packet_info(info))

        # Log to CSV if requested
        if csv_writer:
            log_packet(csv_writer, info)

        # Feed ARP packets into the detector
        if pkt.haslayer(ScapyARP):
            arp = pkt[ScapyARP]
            arp_detector.process_arp(
                src_ip=arp.psrc,
                src_mac=arp.hwsrc,
                op=arp.op,
            )

    sniffer = PacketSniffer(
        iface=args.iface,
        protocol_filter=args.protocol,
        packet_callback=packet_callback,
        count=args.count,
    )

    # Graceful shutdown on Ctrl-C / SIGTERM
    def _shutdown(signum, frame):
        print("\n[*] Stopping sniffer…")
        sniffer.stop()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    iface_label = args.iface or "all interfaces"
    print(f"[*] Starting sniffer on {iface_label}  filter={args.protocol}  "
          f"count={'unlimited' if args.count == 0 else args.count}")
    print("[*] Press Ctrl-C to stop.\n")

    sniffer.sniff_blocking()

    # Cleanup
    if csv_file:
        csv_file.close()
        print("[*] Packet log saved.")

    if args.show_arp_table:
        table = arp_detector.get_arp_table()
        print("\n--- Learned ARP Table ---")
        if not table:
            print("  (empty)")
        else:
            for ip, macs in sorted(table.items()):
                print(f"  {ip:<18}  →  {', '.join(sorted(macs))}")
        print("-------------------------\n")

    print("[*] Done.")


if __name__ == "__main__":
    main()
