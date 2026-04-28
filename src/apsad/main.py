"""
main.py – CLI entry point for the Advanced Packet Sniffer + ARP Detector.

Senior defensive notes:
- Validates interface early (Windows-friendly) and supports listing interfaces.
- Keeps packet capture stoppable on Windows via PacketSniffer's poll timeout loop.
- Adds minimal instrumentation counters so count/print/log mismatches are observable.
- Avoids expensive pkt.summary() unless CSV logging is enabled.
"""

from __future__ import annotations

import argparse
import signal
from typing import Set, Tuple

from scapy.layers.l2 import ARP as ScapyARP

from apsad.capture.interfaces import interface_exists, list_interfaces
from apsad.capture.packet_sniffer import PacketSniffer, VALID_FILTERS
from apsad.detection.arp_detector import ARPDetector
from apsad.logging.logger import open_packet_csv, log_packet, setup_alert_logger
from apsad.parsing.extractors import extract_packet_info, format_packet_info


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advanced Packet Sniffer with ARP Spoofing Detection",
    )
    parser.add_argument(
        "-i",
        "--iface",
        metavar="INTERFACE",
        default=None,
        help="Interface to sniff. On Windows use a \\Device\\NPF_{GUID}.",
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="List available interfaces and exit (recommended on Windows).",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        default="all",
        choices=sorted(VALID_FILTERS),
        help="Protocol filter (default: all)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        metavar="N",
        help="Stop after capturing N packets (default: unlimited)",
    )

    # Output/logging
    parser.add_argument("--log", action="store_true", help="Write packets to CSV")
    parser.add_argument("--log-dir", default="logs", help="Log directory (default: logs)")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-packet output; only show ARP alerts")
    parser.add_argument("--show-arp-table", action="store_true", help="Print learned ARP table on exit")

    # Capture safety/perf
    parser.add_argument(
        "--max-captured",
        type=int,
        default=0,
        metavar="N",
        help="Keep last N raw packets in memory (default: 0)",
    )
    parser.add_argument(
        "--poll-timeout",
        type=int,
        default=1,
        metavar="SEC",
        help="Sniff loop timeout slice in seconds (Windows-safe stop). Default: 1",
    )

    # ARP detector tuning (false-positive reduction)
    parser.add_argument("--arp-ttl", type=int, default=600, metavar="SEC", help="ARP mapping TTL seconds (default: 600)")
    parser.add_argument("--arp-window", type=int, default=30, metavar="SEC", help="Window seconds for mapping changes (default: 30)")
    parser.add_argument("--arp-threshold", type=int, default=2, metavar="N", help="Changes within window to alert (default: 2)")

    # Whitelists (repeatable)
    parser.add_argument("--whitelist-ip", action="append", default=[], help="IP to ignore for ARP alerts (repeatable)")
    parser.add_argument("--whitelist-mac", action="append", default=[], help="MAC to ignore for ARP alerts (repeatable)")
    parser.add_argument(
        "--whitelist-pair",
        action="append",
        default=[],
        metavar="IP,MAC",
        help="Allowed IP,MAC pair (repeatable). Example: --whitelist-pair 192.168.1.1,aa:bb:cc:dd:ee:ff",
    )

    # Future hook (defensive only; no offensive code here)
    parser.add_argument(
        "--active-confirm",
        action="store_true",
        help="Enable active confirmation probes on suspicious ARP events (implementation will be added later)",
    )

    return parser


def _parse_pairs(pairs: list[str]) -> Set[Tuple[str, str]]:
    out: Set[Tuple[str, str]] = set()
    for item in pairs:
        try:
            ip, mac = [x.strip() for x in item.split(",", 1)]
            if ip and mac:
                out.add((ip, mac.lower()))
        except ValueError:
            continue
    return out


def main() -> None:
    args = build_arg_parser().parse_args()

    # ------------------------------------------------------------------
    # Defensive UX: list/validate interfaces before starting capture
    # ------------------------------------------------------------------
    if args.list_ifaces:
        print("Available interfaces:")
        for i, iface in enumerate(list_interfaces(), start=1):
            print(f"  {i:>2}. {iface}")
        return

    if args.iface is not None and not interface_exists(args.iface):
        print(f"[!] Interface not found: {args.iface!r}\n")
        print("Available interfaces:")
        for i, iface in enumerate(list_interfaces(), start=1):
            print(f"  {i:>2}. {iface}")
        return

    # ------------------------------------------------------------------
    # Alert logger + ARP detector configuration
    # ------------------------------------------------------------------
    alert_logger = setup_alert_logger(log_dir=args.log_dir)

    def alert_callback(msg: str) -> None:
        alert_logger.warning(msg)

    arp_detector = ARPDetector(
        alert_callback=alert_callback,
        ttl_seconds=args.arp_ttl,
        window_seconds=args.arp_window,
        change_threshold=args.arp_threshold,
        whitelist_ips=set(args.whitelist_ip),
        whitelist_macs={m.lower() for m in args.whitelist_mac},
        whitelist_pairs=_parse_pairs(args.whitelist_pair),
    )

    # ------------------------------------------------------------------
    # Optional CSV packet logging
    # ------------------------------------------------------------------
    csv_file, csv_writer = (None, None)
    if args.log:
        csv_file, csv_writer = open_packet_csv(log_dir=args.log_dir)
        print(f"[*] Logging packets to {args.log_dir}/packets.csv")

    # ------------------------------------------------------------------
    # Minimal instrumentation (defensive observability)
    # These counters explain mismatches like: captured=10 but printed=8.
    # ------------------------------------------------------------------
    parsed_ok = 0
    parsed_none = 0
    printed = 0
    logged = 0
    arp_seen = 0
    arp_processed = 0

    def packet_callback(pkt):
        nonlocal parsed_ok, parsed_none, printed, logged, arp_seen, arp_processed

        # Only compute expensive pkt.summary() when we're logging to CSV
        include_summary = bool(csv_writer)
        info = extract_packet_info(pkt, include_summary=include_summary)

        if info is None:
            parsed_none += 1
            return

        parsed_ok += 1

        if not args.quiet:
            print(format_packet_info(info))
            printed += 1

        if csv_writer:
            log_packet(csv_writer, info)
            logged += 1

        if pkt.haslayer(ScapyARP):
            arp_seen += 1
            arp = pkt[ScapyARP]
            arp_detector.process_arp(
                src_ip=getattr(arp, "psrc", ""),
                src_mac=getattr(arp, "hwsrc", ""),
                op=int(getattr(arp, "op", 0)),
            )
            arp_processed += 1

    # ------------------------------------------------------------------
    # Start sniffer
    # ------------------------------------------------------------------
    sniffer = PacketSniffer(
        iface=args.iface,
        protocol_filter=args.protocol,
        packet_callback=packet_callback,
        count=args.count,
        max_captured_packets=args.max_captured,
        poll_timeout=args.poll_timeout,
    )

    def _shutdown(signum, frame):
        print("\n[*] Stopping sniffer…")
        sniffer.stop()

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)

    iface_label = args.iface or "all interfaces"
    print(
        f"[*] Starting sniffer on {iface_label} "
        f"filter={args.protocol} "
        f"count={'unlimited' if args.count == 0 else args.count}"
    )
    print("[*] Press Ctrl-C to stop.\n")

    try:
        sniffer.sniff_blocking()
    finally:
        if csv_file:
            csv_file.close()
            print("[*] Packet log saved.")

    # ------------------------------------------------------------------
    # Optional ARP table display
    # ------------------------------------------------------------------
    if args.show_arp_table:
        table = arp_detector.get_arp_table()
        print("\n--- Learned ARP Table ---")
        if not table:
            print("  (empty)")
        else:
            for ip, macs in sorted(table.items()):
                print(f"  {ip:<18}  →  {', '.join(sorted(macs))}")
        print("-------------------------\n")

    if args.active_confirm:
        print("[*] Note: --active-confirm is enabled; active probe logic will be implemented later.")

    # ------------------------------------------------------------------
    # Combined stats (capture + processing)
    # ------------------------------------------------------------------
    if hasattr(sniffer, "stats"):
        print(
            "[*] Stats: "
            f"captured={sniffer.stats.captured} "
            f"cb_ok={sniffer.stats.callback_ok} "
            f"cb_failed={sniffer.stats.callback_failed} "
            f"parsed_ok={parsed_ok} parsed_none={parsed_none} "
            f"printed={printed} logged={logged} "
            f"arp_seen={arp_seen} arp_processed={arp_processed}"
        )

    print("[*] Done.")


if __name__ == "__main__":
    main()