<div align="center">

# 🛡️ Advanced Packet Sniffer + ARP Spoofing Detector

**Real-time network packet capture and ARP poisoning detection, built on Scapy.**

A professional-grade tool for penetration testers, network administrators, and security researchers to identify man-in-the-middle (MITM) attacks on local networks — with passive monitoring, active verification, and vendor-level forensics.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Scapy](https://img.shields.io/badge/built%20with-Scapy-orange)
![Status](https://img.shields.io/badge/status-active-success)

</div>

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Detection Layers](#detection-layers)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Testing the Detector](#testing-the-detector)
- [Architecture Overview](#architecture-overview)
- [Ethical Notice](#ethical-notice)
- [Dependencies](#dependencies)
- [File Structure](#file-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 👁️ | **Passive ARP Monitoring** | Sniffs all ARP reply packets and cross-references IP→MAC mappings against a live table in real time |
| 📡 | **Active Probing** | Periodically sends ARP requests to independently verify MAC address mappings |
| 🔒 | **Gateway Protection** | Special handling for the router MAC — any change triggers an immediate re-verification |
| 🏷️ | **OUI/Vendor Analysis** | Compares MAC OUI prefixes against a known vendor database to flag virtualised or spoofed MACs |
| 🚩 | **MAC Heuristics** | Detects the multicast and locally-administered bits set on claimed MACs |
| 🚫 | **Self-MAC Filtering** | Automatically excludes the local machine's own MAC to prevent false positives |
| 💾 | **PCAP Export** | Writes all captured packets to a `.pcap` file for offline analysis in Wireshark |
| 📄 | **JSON Alert Export** | Exports detected spoofing alerts as structured JSON on exit |
| 📊 | **Live Dashboard** | Real-time stats bar showing packet counts, bandwidth, alert count, and host table size |
| 📝 | **Full Logging** | Timestamped logs to console plus an optional log file |
| 🧾 | **Session Summary** | Comprehensive summary table on exit with all metrics |
| 🖥️ | **Cross-Platform** | Fully supports Linux, macOS, and Windows (with Npcap) |

---

## 🧠 How It Works

```
 Packet on the wire
        │
        ▼
 Is it an ARP reply?
        │
   ┌────┴────┐
   │ No      │ Yes
   ▼         ▼
 Count    Is this IP already in the table?
 traffic       │
           ┌───┴────┐
           │ No     │ Yes
           ▼        ▼
      Add to table   MAC same as before?
      (new host)          │
                     ┌─────┴─────┐
                     │ Yes       │ No
                     ▼           ▼
                  All good   🚨 Raise alert
                             + OUI/vendor check
                             + MAC flag check
                             + gateway re-verify
```

In parallel, a background thread re-sends ARP requests for every known host every `--active` seconds (default 30s), so even a silent attacker who never sends a fresh reply still gets caught.

---

## 🔍 Detection Layers

The detector employs five independent detection layers:

1. **Passive Cross-Reference** — Every ARP reply on the wire is checked against the known IP→MAC table. A mismatch triggers an immediate alert.
2. **Active Probe Verification** — At a configurable interval, the tool sends its own ARP requests for every tracked IP and compares the response against the passively observed MAC.
3. **Gateway Hardening** — The default gateway MAC is resolved at startup and monitored specially. Any change in the gateway's MAC triggers an instant re-verification and alert.
4. **OUI/Vendor Fingerprinting** — Each MAC's first 3 bytes (OUI) are looked up against a curated database of known vendors. Spoofed MACs from a different manufacturer are flagged.
5. **MAC Flag Heuristics** — The first byte of each claimed MAC is checked for the multicast bit (`0x01`) and the locally-administered bit (`0x02`). Legitimate NICs should have neither set.

### Detection Triggers

An alert is raised when any of the following conditions are met:

- An IP address previously mapped to MAC **A** is now claimed by MAC **B**
- The default gateway's MAC address changes (classic ARP spoofing MiTM setup)
- Active probing returns a different MAC than what was passively observed
- The claimed MAC has a different OUI/vendor than the original
- The claimed MAC belongs to a known virtualisation platform (VMware, VirtualBox, Hyper-V, QEMU)
- The multicast bit or locally-administered bit is set on the claimed MAC

---

## ⚙️ Installation

### Prerequisites

- Python 3.8 or higher
- Root/Administrator privileges (required for raw packet capture)
- Npcap (Windows only) — [Download here](https://npcap.com/)

### Install Dependencies

```bash
pip install scapy netifaces
```

### Verify Installation

```bash
python3 -c "from scapy.all import *; print('Scapy OK')"
python3 -c "import netifaces; print('netifaces OK')"
```

---

## 🚀 Usage

### Quick Start

```bash
# Auto-detect interface and gateway
sudo python3 advanced_sniffer.py
```

### Common Usage Patterns

```bash
# Specify interface and gateway explicitly
sudo python3 advanced_sniffer.py -i eth0 -g 192.168.1.1

# Full forensic capture with logging, PCAP, and JSON export
sudo python3 advanced_sniffer.py -i eth0 \
    --log session.log \
    --pcap capture.pcap \
    --json alerts.json

# Live dashboard with reduced console verbosity
sudo python3 advanced_sniffer.py -i eth0 -q --live

# Fast active probing (check every 10 seconds)
sudo python3 advanced_sniffer.py -i eth0 --active 10

# Passive-only mode (no active probing)
sudo python3 advanced_sniffer.py -i eth0 --no-active
```

### Command-Line Options

| Argument | Short | Default | Description |
|---|---|---|---|
| `--interface` | `-i` | Auto-detect | Network interface to sniff on |
| `--gateway` | `-g` | Auto-detect | Default gateway IP address |
| `--active` | — | `30` | Active probe interval in seconds |
| `--no-active` | — | `False` | Disable active probing entirely |
| `--log` | — | `None` | Path to log file |
| `--pcap` | — | `None` | Path to PCAP output file |
| `--json` | — | `None` | Path to write alerts as JSON on exit |
| `--quiet` | `-q` | `False` | Reduce console output verbosity |
| `--live` | — | `False` | Show live stats dashboard |

---

## 🖥️ Example Output

### Normal Operation

```
[2026-07-05 14:30:01] INFO     [*] Interface      : eth0
[2026-07-05 14:30:01] INFO     [*] Gateway IP      : 192.168.1.1
[2026-07-05 14:30:01] INFO     [*] Gateway MAC     : 00:11:22:33:44:55
[2026-07-05 14:30:02] INFO     [+] Detector started — press Ctrl+C to stop

[2026-07-05 14:30:05] DEBUG    [ARP] 192.168.1.100 → AA:BB:CC:DD:EE:01 (new)
[2026-07-05 14:30:08] DEBUG    [ARP] 192.168.1.101 → AA:BB:CC:DD:EE:02 (new)
[2026-07-05 14:30:12] DEBUG    [ARP] 192.168.1.102 → AA:BB:CC:DD:EE:03 (new)
```

### ARP Spoofing Detected

```
[2026-07-05 14:31:15] WARNING
============================================================
[!] ARP SPOOFING DETECTED
    IP Address       : 192.168.1.1
    Original MAC     : 00:11:22:33:44:55
    Claimed MAC      : AA:BB:CC:DD:EE:FF
    First Seen       : 2026-07-05 14:30:01
    Last Seen (orig) : 2026-07-05 14:31:10
    Gateway          : YES
    Original vendor: Cisco (00:11:22X) | Claimed vendor: Unknown (AA:BB:CCX) | [!] Vendor mismatch
============================================================
```

### Session Summary

```
╔══════════════════ SESSION SUMMARY ═══════════════════════════════════════════╗
║  Duration : 187.3s                                                           ║
║  Packets  : 14239                                                            ║
║  ARP      :   245                                                            ║
║  IP       : 13994                                                            ║
║  TCP      : 10821                                                            ║
║  UDP      :  2783                                                            ║
║  ICMP     :   390                                                            ║
║  DNS      :   521                                                            ║
║  Traffic  : 12456.2 KB  (66.5 KB/s)                                          ║
║  Alerts   :     1                                                            ║
║  ARP Tbl  :    14 entries                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🧪 Testing the Detector

To verify the detector works correctly, you can simulate an ARP spoofing attack from another terminal while the sniffer runs:

### Terminal 1 — Start the Detector

```bash
sudo python3 advanced_sniffer.py -i eth0 --live
```

### Terminal 2 — Simulate ARP Spoofing

```bash
sudo python3 -c "
from scapy.all import *
import time
# Broadcast a fake ARP reply claiming the gateway (192.168.1.1) is at MAC aa:bb:cc:dd:ee:ff
packet = ARP(
    op=2,
    pdst='192.168.1.255',
    hwdst='ff:ff:ff:ff:ff:ff',
    psrc='192.168.1.1',
    hwsrc='aa:bb:cc:dd:ee:ff'
)
send(packet, loop=1, inter=2, verbose=0)
"
```

The detector will immediately flag the gateway MAC mismatch with full diagnostic context.

> **Note:** Only run this test on a network you own or have explicit permission to test.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Main Thread                                                    │
│  ┌────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │ Sniffer Thread │  │ Active Probe     │  │ Alert Callback   │ │
│  │ sniff()        │  │ Thread   srp()   │  │ (optional)       │ │
│  └───────┬────────┘  └────────┬─────────┘  │ JSON / Logging   │ │
│          │                    │            └──────────────────┘ │
│          └──────────┬─────────┘                                 │
│                     ▼                                           │
│         ┌────────────────────────────────┐                      │
│         │  Detection Engine              │                      │
│         │  ┌──────────┐ ┌──────┐ ┌─────┐ │                      │
│         │  │ARP Table │ │OUI   │ │MAC  │ │                      │
│         │  │          │ │Lookup│ │Flags│ │                      │
│         │  └──────────┘ └──────┘ └─────┘ │                      │
│         └────────────────┬───────────────┘                      │
│                          ▼                                      │
│        ┌────────────────────┐  ┌──────────────────────┐         │
│        │ PCAP Writer        │  │ Stats Counter        │         │
│        │ (thread-safe)      │  │ (thread-safe)        │         │
│        └────────────────────┘  └──────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

The sniffer thread continuously captures packets via Scapy's `sniff()`, while an independent active-probe thread periodically re-verifies IP→MAC mappings using `srp()`. Both feed into a shared, thread-safe detection engine that performs ARP table cross-referencing, OUI/vendor lookups, and MAC flag heuristics. Results are logged, optionally written to PCAP/JSON, and reflected in thread-safe stats counters used by the live dashboard.

---

## ⚠️ Ethical Notice

> **This tool is designed for authorized security testing only.**
>
> - Only run this tool on networks you **own** or have **explicit written permission** to monitor.
> - Packet capture and network monitoring may be illegal or violate acceptable-use policies in some environments and jurisdictions.
> - Always obtain proper authorization before scanning, sniffing, or testing any network.
> - The authors assume no liability for misuse of this software.

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| [Scapy](https://scapy.net/) | ≥ 2.5.0 | Packet capture, crafting, and sending |
| [netifaces](https://pypi.org/project/netifaces/) | ≥ 0.11.0 | Cross-platform network interface and gateway detection |
| Python stdlib | ≥ 3.8 | `threading`, `logging`, `argparse`, `json`, `signal`, `subprocess`, `dataclasses` |

### Windows-Specific

- [Npcap](https://npcap.com/) — Required by Scapy for raw packet capture on Windows (WinPcap is **not** supported)

---

## 📁 File Structure

```
.
├── advanced_sniffer.py   # Main script — detector, dashboard, and CLI entry point
└── README.md             # This file
```

---

## 🛠️ Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| `Permission denied` | Not running as root/Administrator | Run with `sudo` (Linux/macOS) or as Administrator (Windows) |
| `Scapy is required` | Scapy not installed | `pip install scapy` |
| `Unknown network interface` | Wrong interface name | Run without `-i` for auto-detection, or use `ip link show` (Linux) / `getmac` (Windows) to list interfaces |
| `No gateway detected` | Network stack unrecognised | Specify gateway manually with `-g 192.168.1.1` |
| Windows: `ValueError` | Interface GUID without NPF prefix | Use `-i` with the full device name, or let auto-detection handle it |
| Windows: no packets captured | Npcap not installed or in WinPcap mode | Install Npcap with "WinPcap API-compatible Mode" checked |
| High CPU usage | Very high traffic volume | Use `-q` to reduce logging; consider a BPF filter (future feature) |

---

## 📜 License

Released under the **MIT License**. See [LICENSE](LICENSE) for details.