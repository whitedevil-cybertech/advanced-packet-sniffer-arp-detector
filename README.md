# Advanced Packet Sniffer with ARP Spoofing Detection

A real-time network monitoring and security tool built with **Python** and **Scapy**.  
It captures live packets, analyses traffic at the protocol level, and detects ARP spoofing / Man-in-the-Middle (MITM) attacks by monitoring IP-to-MAC address mappings.

---

## Features

| Feature | Description |
|---|---|
| Real-time packet sniffing | Live capture on any interface via Scapy |
| Protocol filtering | Filter by TCP, UDP, ICMP, ARP, or capture all |
| ARP spoofing detection | Alerts when an IP→MAC binding changes or a MAC claims many IPs |
| Packet logging | Optional CSV log for forensic review (`logs/packets.csv`) |
| Alert logging | Suspicious activity written to `logs/alerts.log` and printed to console |
| ARP table dump | Print the learned IP→MAC table on exit |

---

## Project Structure

```
.
├── main.py            # CLI entry point
├── packet_sniffer.py  # Packet capture & parsing module
├── arp_detector.py    # ARP spoofing detection module
├── logger.py          # CSV packet log + alert logger setup
├── requirements.txt   # Python dependencies
└── logs/              # Created automatically at runtime
    ├── packets.csv    # Per-packet log (when --log is used)
    └── alerts.log     # ARP spoofing alerts
```

---

## Requirements

- Python 3.8+
- `scapy >= 2.5.0`
- Root / administrator privileges (required for raw packet capture)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

> **All capture commands must be run as root (or with `sudo`) because raw socket access requires elevated privileges.**

### Basic syntax

```bash
sudo python main.py [options]
```

### Options

| Flag | Description |
|---|---|
| `-i INTERFACE` | Network interface to sniff (default: all interfaces) |
| `-p PROTO` | Protocol filter: `tcp`, `udp`, `icmp`, `arp`, `all` (default: `all`) |
| `-c N` | Stop after capturing N packets (default: unlimited) |
| `--log` | Write captured packets to `logs/packets.csv` |
| `--quiet` | Suppress per-packet output; only show ARP alerts |
| `--show-arp-table` | Print the learned ARP table when the sniffer exits |

### Examples

```bash
# Capture all traffic on the default interface and log to CSV
sudo python main.py --log

# Capture only ARP traffic on eth0, detect spoofing, and show the table on exit
sudo python main.py -i eth0 -p arp --log --show-arp-table

# Capture 100 TCP packets then stop
sudo python main.py -p tcp -c 100

# Silent ARP-only monitoring (alerts only, no per-packet lines)
sudo python main.py -p arp --quiet
```

---

## How ARP Spoofing Detection Works

The `ARPDetector` class maintains two in-memory tables:

1. **IP → set of MACs** – every MAC that has claimed ownership of an IP.
2. **MAC → set of IPs** – every IP that a MAC has claimed to own.

An **alert is raised** when:

- A new ARP packet binds an IP address to a *different* MAC than the one(s) previously seen — classic ARP poisoning.
- A single MAC address claims ownership of more than two IP addresses — indicative of ARP flooding or a misconfigured gateway.

Alerts are printed to the console *and* written to `logs/alerts.log`.

---

## Packet Log Format (`logs/packets.csv`)

| Column | Description |
|---|---|
| `timestamp` | Capture time (`YYYY-MM-DD HH:MM:SS.mmm`) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_mac` | Source MAC address |
| `dst_mac` | Destination MAC address |
| `protocol` | Protocol name (TCP / UDP / ICMP / ARP / …) |
| `src_port` | Source port (TCP/UDP only) |
| `dst_port` | Destination port (TCP/UDP only) |
| `length` | Total packet length in bytes |
| `summary` | Scapy one-line packet summary |

---

## Practical Applications

- Network monitoring and troubleshooting
- Cybersecurity labs and education
- Intrusion detection demonstrations
- Basic network forensics
- Detecting MITM attacks on LANs
- Security monitoring in small office or home networks

---

## Tech Stack

- **Python 3.8+**
- **Scapy** – packet capture, parsing, and BPF filtering
- **Threading** – non-blocking background sniffing
- **CSV / logging** – built-in Python modules for forensic output

---

## Disclaimer

This tool is intended for **educational purposes and authorised network monitoring only**.  
Capturing or intercepting network traffic without permission may be illegal.  
Always obtain proper authorisation before running this tool on any network.