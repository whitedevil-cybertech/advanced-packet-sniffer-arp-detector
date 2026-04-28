# Advanced Packet Sniffer with ARP Spoofing Detection

A real-time network monitoring and security tool built with **Python** and **Scapy**.  
It captures live packets, analyses traffic at the protocol level, and detects ARP spoofing / Man-in-the-Middle (MITM) attacks by monitoring IP-to-MAC address mappings.

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
10. [Practical Applications](#practical-applications)
11. [Troubleshooting](#troubleshooting)
12. [Disclaimer](#disclaimer)

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
advanced-packet-sniffer-arp-detector/
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

## Prerequisites

Before you begin, make sure you have the following installed:

- **Python 3.8 or higher** — [Download here](https://www.python.org/downloads/)
- **pip** — comes bundled with Python
- **Npcap** (Windows only) — [Download here](https://npcap.com/#download) — required by Scapy for raw packet capture on Windows
- **Administrator / root privileges** — required to capture raw network packets

---

## Step-by-Step Setup Guide

### Step 1 — Clone or download the repository

```bash
git clone https://github.com/whitedevil-cybertech/advanced-packet-sniffer-arp-detector.git
cd advanced-packet-sniffer-arp-detector
```

Or download and extract the ZIP from GitHub, then open a terminal inside the extracted folder.

---

### Step 2 — (Recommended) Create a virtual environment

A virtual environment keeps the project's dependencies isolated from your system Python.

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

You'll see `(venv)` appear in your terminal prompt when the environment is active.

---

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs **Scapy**, the only external dependency.

---

### Step 4 — (Windows only) Install Npcap

Scapy requires a packet capture driver on Windows.

1. Download **Npcap** from [https://npcap.com/#download](https://npcap.com/#download)
2. Run the installer — make sure to check **"Install Npcap in WinPcap API-compatible mode"** during setup
3. Restart your machine if prompted

---

### Step 5 — Find your network interface name *(optional)*

If you want to sniff on a specific interface (rather than all interfaces), you need its name.

**Windows** — open Command Prompt as Administrator:
```cmd
ipconfig
```
Look for the adapter name, e.g. `Ethernet`, `Wi-Fi`, `Local Area Connection`.

**Linux / macOS:**
```bash
ip link show
# or
ifconfig
```
Common names: `eth0`, `wlan0`, `en0`, `ens33`.

---

## Running the Tool

> ⚠️ **Raw packet capture requires elevated privileges.**  
> Always run the tool as **Administrator on Windows** or with **`sudo` on Linux/macOS**.

### 🪟 Windows (Command Prompt or PowerShell — run as Administrator)

```cmd
py main.py
```

> **Note:** On Windows, the Python launcher command is `py` instead of `python`.  
> If `py` doesn't work, try `python main.py`.  
> If neither works, make sure Python is added to your system PATH during installation.

### 🐧 Linux / macOS

```bash
sudo python3 main.py
```

> **Note:** On some Linux/macOS systems, `python` may point to Python 2 or may not exist at all.  
> Use `python3` to ensure you're running Python 3. Inside a virtual environment, plain `python` also works.

---

## Command-Line Options

| Flag | Description |
|---|---|
| `-i INTERFACE` | Network interface to sniff on (default: all interfaces) |
| `-p PROTO` | Protocol filter: `tcp`, `udp`, `icmp`, `arp`, `all` (default: `all`) |
| `-c N` | Stop after capturing N packets (default: 0 = unlimited) |
| `--log` | Write captured packets to `logs/packets.csv` |
| `--quiet` | Suppress per-packet output; show ARP alerts only |
| `--show-arp-table` | Print the learned IP→MAC table when the sniffer exits |

---

## Usage Examples

### Capture all traffic and log everything to CSV

**Windows:**
```cmd
py main.py --log
```
**Linux / macOS:**
```bash
sudo python3 main.py --log
```

---

### Monitor ARP traffic only on a specific interface

**Windows:**
```cmd
py main.py -i "Wi-Fi" -p arp --log --show-arp-table
```
**Linux / macOS:**
```bash
sudo python3 main.py -i eth0 -p arp --log --show-arp-table
```

---

### Capture exactly 100 TCP packets then stop

**Windows:**
```cmd
py main.py -p tcp -c 100
```
**Linux / macOS:**
```bash
sudo python3 main.py -p tcp -c 100
```

---

### Silent ARP-only monitoring (alerts only, no per-packet output)

**Windows:**
```cmd
py main.py -p arp --quiet
```
**Linux / macOS:**
```bash
sudo python3 main.py -p arp --quiet
```

---

### Stop the tool

Press **Ctrl + C** at any time to stop the sniffer gracefully.

---

## How ARP Spoofing Detection Works

The `ARPDetector` class maintains two in-memory tables:

1. **IP → set of MACs** — every MAC that has claimed ownership of an IP.
2. **MAC → set of IPs** — every IP that a MAC has claimed to own.

An **alert is raised** when:

- A new ARP packet binds an IP address to a *different* MAC than the one previously seen — this is the classic sign of ARP poisoning / MITM.
- A single MAC address claims ownership of more than two IP addresses — indicative of ARP flooding or a misconfigured gateway.

Alerts appear instantly in the terminal **and** are saved to `logs/alerts.log` for later review.

---

## Packet Log Format (`logs/packets.csv`)

When `--log` is used, every captured packet is appended to `logs/packets.csv` with these columns:

| Column | Description |
|---|---|
| `timestamp` | Capture time (`YYYY-MM-DD HH:MM:SS.mmm`) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_mac` | Source MAC address |
| `dst_mac` | Destination MAC address |
| `protocol` | Protocol name (TCP / UDP / ICMP / ARP) |
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

## Troubleshooting

| Problem | Solution |
|---|---|
| `'python' is not recognized` | Use `py` on Windows, or `python3` on Linux/macOS |
| `'py' is not recognized` | Install Python from [python.org](https://www.python.org/downloads/) and ensure "Add to PATH" is checked |
| `Permission denied` / `Operation not permitted` | Run as Administrator (Windows) or with `sudo` (Linux/macOS) |
| `ModuleNotFoundError: scapy` | Run `pip install -r requirements.txt` inside your virtual environment |
| No packets captured | Check that you used the correct interface name with `-i`; try without `-i` to capture on all interfaces |
| `Npcap not found` (Windows) | Install Npcap from [https://npcap.com](https://npcap.com/#download) |
| Scapy `WARNING: No route found` | Usually harmless; packets are still captured |

---

## Tech Stack

- **Python 3.8+**
- **Scapy** — packet capture, parsing, and BPF filtering
- **Threading** — non-blocking background sniffing
- **CSV / logging** — built-in Python modules for forensic output

---

## Disclaimer

This tool is intended for **educational purposes and authorized network monitoring only**.  
Capturing or intercepting network traffic without permission may be illegal in your country.  
Always obtain proper authorization before running this tool on any network you do not own.