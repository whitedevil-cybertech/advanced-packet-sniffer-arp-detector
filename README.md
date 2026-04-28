# Advanced Packet Sniffer with ARP Spoofing Detection (APSAD)

A real-time network monitoring and defensive security tool built with **Python** and **Scapy**.  
It captures live packets, analyses traffic at the protocol level, and detects ARP spoofing / Man-in-the-Middle (MITM) attacks by monitoring IP-to-MAC address mappings — with **false-positive controls**, **whitelisting**, and **configurable thresholds**.

---

## Table of Contents

1. [Features](#features)
2. [Project Structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Step-by-Step Setup Guide](#step-by-step-setup-guide)
5. [Running the Tool](#running-the-tool)
6. [Command-Line Options](#command-line-options)
7. [Usage Examples](#usage-examples)
8. [How ARP Spoofing Detection Works](#how-arp-spoofing-detection-works)
9. [Packet Log Format](#packet-log-format-logspacketcsv)
10. [Troubleshooting](#troubleshooting)
11. [Disclaimer](#disclaimer)

---

## Features

| Feature | Description |
|---|---|
| Real-time packet sniffing | Live capture on any interface via Scapy |
| Protocol filtering | Filter by TCP, UDP, ICMP, ARP, or capture all |
| ARP spoofing detection | Detects suspicious IP→MAC changes with TTL + window + thresholds |
| False-positive control | Whitelists for IPs, MACs, and IP–MAC pairs |
| Packet logging | Optional CSV log for forensic review |
| Alert logging | Alerts written to rotating `alerts.log` + console |
| UTC timestamps | All timestamps are UTC/Z for forensic correlation |
| ARP table dump | Print learned IP→MAC mappings on exit |
| Windows-safe stopping | Sniffer loop uses timeout slicing for reliable Ctrl+C |

---

## Project Structure

```
advanced-packet-sniffer-arp-detector/
├── src/
│   └── apsad/
│       ├── main.py                  # CLI entry point
│       ├── capture/
│       │   ├── packet_sniffer.py    # Capture engine (Windows-safe)
│       │   └── interfaces.py        # List/validate interfaces
│       ├── parsing/
│       │   └── extractors.py        # Protocol parsing + formatting
│       ├── detection/
│       │   └── arp_detector.py      # ARP spoofing detection logic
│       └── logging/
│           └── logger.py            # CSV + rotating alert logger
├── logs/                            # Created automatically at runtime
│   ├── packets.csv
│   └── alerts.log
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Prerequisites

- **Python 3.10+**
- **pip**
- **Npcap** (Windows only) — [Download here](https://npcap.com/#download)
- **Administrator / root privileges** — required for raw packet capture

---

## Step-by-Step Setup Guide

### Step 1 — Clone the repository

```bash
git clone https://github.com/whitedevil-cybertech/advanced-packet-sniffer-arp-detector.git
cd advanced-packet-sniffer-arp-detector
```

---

### Step 2 — (Recommended) Create a virtual environment

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Step 3 — Install dependencies (editable install)

```bash
pip install -e .
```

This makes the `apsad` package importable without setting `PYTHONPATH`.

---

### Step 4 — (Windows only) Install Npcap

1. Download from: https://npcap.com/#download  
2. During install, check **"Install Npcap in WinPcap API-compatible mode"**
3. Restart if prompted

---

## Running the Tool

> ⚠️ Raw packet capture requires elevated privileges.  
> Run as **Administrator** (Windows) or with **sudo** (Linux/macOS).

### Windows (PowerShell or CMD)
```cmd
py -m apsad.main --help
```

### Linux / macOS
```bash
sudo python3 -m apsad.main --help
```

---

## Command-Line Options

| Flag | Description |
|---|---|
| `-i INTERFACE` | Network interface to sniff (default: all) |
| `--list-ifaces` | List available interfaces and exit |
| `-p PROTO` | Protocol filter: `tcp`, `udp`, `icmp`, `arp`, `all` |
| `-c N` | Stop after capturing N packets (0 = unlimited) |
| `--log` | Write packets to `logs/packets.csv` |
| `--log-dir DIR` | Log directory (default: logs) |
| `--quiet` | Suppress per-packet output (alerts only) |
| `--show-arp-table` | Print learned ARP table on exit |
| `--max-captured N` | Keep last N raw packets in memory |
| `--poll-timeout SEC` | Sniff timeout slice (Windows-safe stop) |
| `--arp-ttl SEC` | ARP mapping TTL (default: 600) |
| `--arp-window SEC` | Window for ARP change threshold |
| `--arp-threshold N` | Changes within window to alert |
| `--whitelist-ip IP` | Ignore ARP alerts for this IP |
| `--whitelist-mac MAC` | Ignore ARP alerts for this MAC |
| `--whitelist-pair IP,MAC` | Allow a specific IP–MAC pair |
| `--active-confirm` | Placeholder hook (future module) |

---

## Usage Examples

### List available interfaces (Windows-friendly)
```bash
py -m apsad.main --list-ifaces
```

### Capture all traffic and log to CSV
```bash
py -m apsad.main --log
```

### Capture only ARP packets on a specific interface
```bash
py -m apsad.main -i "\Device\NPF_{GUID}" -p arp --log --show-arp-table
```

### Capture 100 TCP packets and exit
```bash
py -m apsad.main -p tcp -c 100
```

### Quiet ARP monitoring (alerts only)
```bash
py -m apsad.main -p arp --quiet
```

---

## How ARP Spoofing Detection Works

The detector maintains **current IP→MAC mappings** and **recent mapping changes**.  
An alert is raised only when **suspicious behavior persists**, which reduces false positives from:

- DHCP renewals
- virtualization / VM MAC churn
- HA gateways / multi-IP devices

### Alert conditions (defensive model)
- An IP changes MAC **more than N times within a window** (e.g., 2 changes in 30s)
- Mappings expire after a configurable TTL to avoid stale alerts
- Whitelists suppress known-safe IPs, MACs, and IP–MAC pairs

---

## Packet Log Format (`logs/packets.csv`)

When `--log` is enabled, packets are written to CSV:

| Column | Description |
|---|---|
| `timestamp` | UTC timestamp (`YYYY-MM-DD HH:MM:SS.mmmZ`) |
| `src_ip` | Source IP |
| `dst_ip` | Destination IP |
| `src_mac` | Source MAC |
| `dst_mac` | Destination MAC |
| `protocol` | Protocol (TCP / UDP / ICMP / ARP) |
| `src_port` | TCP/UDP source port |
| `dst_port` | TCP/UDP destination port |
| `length` | Packet length |
| `summary` | Scapy summary (only if logging enabled) |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: apsad` | Run `pip install -e .` from repo root |
| `Permission denied` | Run as Admin (Windows) or `sudo` (Linux/macOS) |
| No packets captured | Try `--list-ifaces` and specify correct interface |
| Ctrl+C doesn't stop | Increase `--poll-timeout` or verify you are not inside a blocked terminal |
| `Npcap not found` (Windows) | Install Npcap in WinPcap-compatible mode |

---

## Disclaimer

This tool is intended for **educational and authorized defensive monitoring only**.  
Capturing or inspecting traffic without permission may be illegal in your jurisdiction.  
Always obtain authorization before running on any network you do not own or administer.