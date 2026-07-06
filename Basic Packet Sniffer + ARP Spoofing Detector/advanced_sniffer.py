import os
import re
import sys
import json
import time
import socket
import signal
import struct
import logging
import platform
import argparse
import threading
import subprocess
from datetime import datetime
from collections import defaultdict
from typing import Dict, Optional, Tuple, List, Callable
from dataclasses import dataclass, asdict
from contextlib import contextmanager

# ---------------------------------------------------------------------------
# Scapy import with informative error
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        sniff, ARP, Ether, IP, TCP, UDP, ICMP, DNS, Raw,
        srp, srp1, conf, get_if_list, get_if_hwaddr, get_if_addr,
    )
    from scapy.utils import PcapWriter
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print(
        "[!] Scapy is required. Install it with:\n"
        "    pip install scapy\n",
        file=sys.stderr,
    )

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


# =======================================================================
# CONSTANTS
# =======================================================================

BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
ZERO_MAC = "00:00:00:00:00:00"

# Common OUIs for quick vendor identification
KNOWN_OUIS: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "00:15:5D": "Hyper-V",
    "00:03:FF": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1A:11": "Xen",
    "B8:CA:3A": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "CC:DB:A7": "Apple",
    "F0:18:98": "Apple",
    "3C:22:FB": "Dell",
    "00:1E:4F": "Dell",
    "F8:BC:12": "Dell",
    "00:1A:A0": "HP",
    "00:23:7D": "HP",
    "F0:1F:AF": "Intel",
    "10:3D:1C": "TP-Link",
    "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:1A:3F": "Cisco",
    "70:73:CB": "Cisco",
}

VIRTUALIZATION_OUIS = frozenset({
    "00:50:56", "00:0C:29", "00:1C:42",
    "00:15:5D", "00:03:FF", "08:00:27", "52:54:00",
})


# =======================================================================
# DATA CLASSES
# =======================================================================

@dataclass
class ARPEntry:
    """IP→MAC mapping with temporal metadata."""
    mac: str
    first_seen: float
    last_seen: float
    count: int = 1
    is_gateway: bool = False


@dataclass
class SpoofAlert:
    """Detailed spoofing incident record."""
    timestamp: float
    ip: str
    original_mac: str
    claimed_mac: str
    interface: str
    details: str = ""


@dataclass
class PacketStats:
    """Aggregate traffic counters."""
    total: int = 0
    arp: int = 0
    ip: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    dns: int = 0
    bytes: int = 0
    start_time: float = 0.0


# =======================================================================
# CORE DETECTOR
# =======================================================================

class ARPSpoofDetector:
    """
    Detects ARP spoofing using passive monitoring and active verification.

    Detection layers:
    1. Passive — cross-references each ARP reply against known IP→MAC
    2. Active  — periodically sends ARP requests to re-verify mappings
    3. Gateway — special handling; any change triggers immediate re-check
    4. OUI    — compares vendor of original vs. claimed MAC
    5. Heuristics — checks multicast/local-admin bits on claimed MACs
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        active_check_interval: int = 30,
        quiet: bool = False,
        log_file: Optional[str] = None,
        pcap_file: Optional[str] = None,
        alert_callback: Optional[Callable[[SpoofAlert], None]] = None,
    ):
        self.interface = self._resolve_interface(interface)
        self.gateway_ip = gateway_ip or self._get_default_gateway()
        self.active_interval = active_check_interval
        self.quiet = quiet
        self.pcap_file = pcap_file
        self.alert_callback = alert_callback

        # State
        self._arp_table: Dict[str, ARPEntry] = {}
        self._alerts: List[SpoofAlert] = []
        self._stats = PacketStats(start_time=time.time())
        self._running = False
        self._lock = threading.Lock()
        self._gateway_mac: Optional[str] = None
        self._active_thread: Optional[threading.Thread] = None
        self._sniff_thread: Optional[threading.Thread] = None
        self._pcap_writer: Optional[PcapWriter] = None
        self._pcap_lock = threading.Lock()

        # Logger setup
        self._setup_logging(log_file)

        # Auto-detect gateway MAC
        self._gateway_mac = self._resolve_mac(self.gateway_ip, timeout=3)
        if self._gateway_mac:
            self._upsert_entry(self.gateway_ip, self._gateway_mac, is_gateway=True)
            self.log.info(f"[*] Gateway {self.gateway_ip} → {self._gateway_mac}")
        else:
            self.log.warning(
                f"[!] Could not resolve MAC for gateway {self.gateway_ip}. "
                "Active checks will still run."
            )

    # ------------------------------------------------------------------
    # Interface / Gateway Resolution
    # ------------------------------------------------------------------

    def _resolve_interface(self, iface: Optional[str]) -> str:
        """Return a valid interface name, auto-detecting if necessary."""
        if iface and iface in get_if_list():
            return iface

        candidates = ["eth0", "wlan0", "en0", "enp3s0", "ens33", "wlp2s0", "enp0s3"]
        available = get_if_list()
        for c in candidates:
            if c in available:
                return c
        # Fall back to first non-loopback interface
        for a in available:
            name = a.strip()
            if name != "lo":
                return name
        return available[0] if available else "eth0"

    def _get_default_gateway(self) -> str:
        """Detect default gateway IP via netifaces, ip route, or route -n."""
        if NETIFACES_AVAILABLE:
            try:
                gws = netifaces.gateways()
                return gws["default"][netifaces.AF_INET][0]
            except Exception:
                pass

        for cmd, extract in [
            (["ip", "route", "show", "default"],
                lambda o: o.split()[2]),
            (["route", "-n"],
                lambda o: next(
                    line.split()[1] for line in o.splitlines()
                    if line.startswith("0.0.0.0") and len(line.split()) >= 2
                )
            ),
        ]:
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                                timeout=3).decode()
                return extract(out)
            except Exception:
                continue

        self.log.warning("[!] Could not detect gateway; defaulting to 192.168.1.1")
        return "192.168.1.1"

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _setup_logging(self, log_file: Optional[str]):
        self.log = logging.getLogger("ARPSniffer")
        self.log.setLevel(logging.DEBUG)
        fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO if self.quiet else logging.DEBUG)
        ch.setFormatter(fmt)
        self.log.addHandler(ch)
        # File handler
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(fmt)
            self.log.addHandler(fh)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Begin sniffing and active probing in background threads."""
        if self._running:
            self.log.warning("[!] Already running.")
            return
        self._running = True

        # Start active probing thread
        if self.active_interval > 0:
            self._active_thread = threading.Thread(
                target=self._active_loop, daemon=True
            )
            self._active_thread.start()

        # Start sniffer thread
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self._sniff_thread.start()

        self.log.info("[+] Detector started — press Ctrl+C to stop")
        if not self.quiet:
            self._print_banner()

    def stop(self):
        """Gracefully stop all threads and close resources."""
        self._running = False
        # Close PCAP writer
        if self._pcap_writer:
            with self._pcap_lock:
                try:
                    self._pcap_writer.close()
                except Exception:
                    pass
                self._pcap_writer = None
        self.log.info("[+] Detector stopped.")
        if not self.quiet:
            self._print_summary()

    def wait(self):
        """Block until Ctrl+C is received."""
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.log.info("\n[!] Interrupted by user.")
            self.stop()

    def get_alerts(self) -> List[SpoofAlert]:
        with self._lock:
            return list(self._alerts)

    def get_arp_table(self) -> Dict[str, ARPEntry]:
        with self._lock:
            return dict(self._arp_table)

    def get_stats(self) -> PacketStats:
        with self._lock:
            return PacketStats(**asdict(self._stats))

    # ------------------------------------------------------------------
    # Sniffing Loop
    # ------------------------------------------------------------------

    def _sniff_loop(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            self.log.error(
                "[!] Permission denied. Run with sudo or as Administrator."
            )
            self._running = False
        except OSError as e:
            self.log.error(f"[!] Interface error on {self.interface}: {e}")
            self._running = False
        except Exception as e:
            self.log.error(f"[!] Sniffing error: {e}")
            self._running = False

    # ------------------------------------------------------------------
    # Packet Handler
    # ------------------------------------------------------------------

    def _handle_packet(self, packet):
        if not self._running:
            return

        # Update stats
        pkt_len = len(packet) if hasattr(packet, "__len__") else 0
        with self._lock:
            self._stats.total += 1
            self._stats.bytes += pkt_len

        # PCAP write (thread-safe)
        if self.pcap_file:
            self._write_pcap(packet)

        # ARP handling
        if packet.haslayer(ARP):
            with self._lock:
                self._stats.arp += 1
            self._handle_arp(packet)

        # IP layer counters
        if packet.haslayer(IP):
            with self._lock:
                self._stats.ip += 1
            ip_layer = packet[IP]
            if packet.haslayer(TCP):
                with self._lock:
                    self._stats.tcp += 1
            elif packet.haslayer(UDP):
                with self._lock:
                    self._stats.udp += 1
                if packet.haslayer(DNS):
                    with self._lock:
                        self._stats.dns += 1
            elif packet.haslayer(ICMP):
                with self._lock:
                    self._stats.icmp += 1

    # ------------------------------------------------------------------
    # ARP Detection Logic
    # ------------------------------------------------------------------

    def _handle_arp(self, packet):
        """Analyse ARP packets for spoofing indicators."""
        arp = packet[ARP]

        # We only inspect ARP replies (op=2)
        if arp.op != 2:
            return

        src_ip = arp.psrc
        src_mac = arp.hwsrc.upper().strip()

        # Sanity checks
        if src_mac in (BROADCAST_MAC, ZERO_MAC, ""):
            return

        entry = self._arp_table.get(src_ip)

        if entry is None:
            # New mapping — insert
            self._upsert_entry(src_ip, src_mac)
            if not self.quiet:
                self.log.debug(f"[ARP] {src_ip} → {src_mac} (new)")
            return

        # --- Existing mapping found — check for mismatch ---
        if entry.mac != src_mac:
            self._raise_alert(src_ip, entry, src_mac, packet)
        else:
            entry.last_seen = time.time()
            entry.count += 1

    def _raise_alert(self, ip: str, entry: ARPEntry, claimed_mac: str,
                        packet) -> None:
        """Create and broadcast a spoofing alert."""
        alert = SpoofAlert(
            timestamp=time.time(),
            ip=ip,
            original_mac=entry.mac,
            claimed_mac=claimed_mac,
            interface=self.interface,
            details=self._build_alert_details(entry.mac, claimed_mac),
        )

        with self._lock:
            self._alerts.append(alert)

        self.log.warning(
            f"\n{'=' * 60}"
            f"\n[!] ARP SPOOFING DETECTED"
            f"\n    IP Address       : {ip}"
            f"\n    Original MAC     : {entry.mac}"
            f"\n    Claimed MAC      : {claimed_mac}"
            f"\n    First Seen       : {datetime.fromtimestamp(entry.first_seen)}"
            f"\n    Last Seen (orig) : {datetime.fromtimestamp(entry.last_seen)}"
            f"\n    Gateway           : {'YES' if entry.is_gateway else 'no'}"
            f"\n    {alert.details}"
            f"\n{'=' * 60}\n"
        )

        # User-defined callback
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception:
                pass

        # If gateway is being spoofed, immediately re-verify
        if entry.is_gateway:
            threading.Thread(target=self._verify_gateway, daemon=True).start()

    # ------------------------------------------------------------------
    # Active Probing
    # ------------------------------------------------------------------

    def _active_loop(self):
        while self._running:
            time.sleep(self.active_interval)
            if not self._running:
                break
            try:
                self._active_probe_all()
            except Exception as e:
                self.log.debug(f"[*] Active probe error: {e}")

    def _active_probe_all(self):
        """Resolve MAC for all tracked IPs and cross-check."""
        with self._lock:
            targets = list(self._arp_table.items())

        for ip, entry in targets:
            if not self._running:
                break
            try:
                resolved = self._resolve_mac(ip, timeout=2)
                if resolved and resolved != entry.mac:
                    alert = SpoofAlert(
                        timestamp=time.time(),
                        ip=ip,
                        original_mac=entry.mac,
                        claimed_mac=resolved,
                        interface=self.interface,
                        details="[ACTIVE PROBE] Cross-verified MAC mismatch",
                    )
                    with self._lock:
                        self._alerts.append(alert)
                    self.log.warning(
                        f"[!] ACTIVE PROBE: {ip} was {entry.mac}, now {resolved}"
                    )
                    if self.alert_callback:
                        try:
                            self.alert_callback(alert)
                        except Exception:
                            pass
            except Exception:
                pass

    def _verify_gateway(self):
        """Re-resolve gateway MAC immediately and log changes."""
        mac = self._resolve_mac(self.gateway_ip, timeout=3)
        if mac and mac != self._gateway_mac:
            self.log.warning(
                f"[!] GATEWAY MAC CHANGED: {self.gateway_ip} "
                f"was {self._gateway_mac}, now {mac}"
            )
            self._gateway_mac = mac

    # ------------------------------------------------------------------
    # MAC Resolution
    # ------------------------------------------------------------------

    def _resolve_mac(self, ip: str, timeout: int = 3) -> Optional[str]:
        """Send ARP request and return the MAC, or None on failure."""
        try:
            ans, _ = srp(
                Ether(dst=BROADCAST_MAC) / ARP(pdst=ip),
                timeout=timeout,
                verbose=False,
                iface=self.interface,
            )
            if ans:
                return ans[0][1].hwsrc.upper()
        except Exception:
            pass
        return None

    def _upsert_entry(self, ip: str, mac: str, is_gateway: bool = False) -> None:
        """Insert or update ARP table entry."""
        now = time.time()
        mac = mac.upper()
        entry = ARPEntry(
            mac=mac,
            first_seen=now,
            last_seen=now,
            count=1,
            is_gateway=is_gateway or (ip == self.gateway_ip),
        )
        with self._lock:
            self._arp_table[ip] = entry

    # ------------------------------------------------------------------
    # Alert Enrichment
    # ------------------------------------------------------------------

    @staticmethod
    def _build_alert_details(orig_mac: str, new_mac: str) -> str:
        """Return diagnostic string comparing original and claimed MACs."""
        parts = []
        orig_oui = orig_mac[:8].upper()
        new_oui = new_mac[:8].upper()

        orig_vendor = KNOWN_OUIS.get(orig_oui, "Unknown")
        new_vendor = KNOWN_OUIS.get(new_oui, "Unknown")

        parts.append(f"Original: {orig_vendor} ({orig_oui}X)")
        parts.append(f"Claimed : {new_vendor} ({new_oui}X)")

        if orig_oui != new_oui:
            parts.append("[!] Vendor mismatch — different manufacturers")

        if new_oui in VIRTUALIZATION_OUIS:
            parts.append("[!] Claimed MAC is from a virtualisation vendor")

        # Check MAC flags in first byte
        try:
            first_byte = int(new_mac.split(":")[0], 16)
            if first_byte & 0x01:
                parts.append("[!] Multicast bit set (suspicious)")
            if first_byte & 0x02:
                parts.append("[!] Locally-administered bit set (likely spoofed)")
        except (ValueError, IndexError):
            pass

        return " | ".join(parts)

    # ------------------------------------------------------------------
    # PCAP Writer
    # ------------------------------------------------------------------

    def _write_pcap(self, packet):
        """Thread-safe write to PCAP file."""
        if self._pcap_writer is None and self.pcap_file:
            try:
                self._pcap_writer = PcapWriter(
                    self.pcap_file, append=True, sync=True
                )
            except Exception as e:
                self.log.error(f"[!] PCAP init error: {e}")
                self.pcap_file = None
                return

        with self._pcap_lock:
            try:
                self._pcap_writer.write(packet)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _print_banner(self):
        print(
            f"\n╔═══ Advanced Packet Sniffer + ARP Spoof Detector ═══╗"
            f"\n║  Interface : {self.interface:<22}  ║"
            f"\n║  Gateway   : {self.gateway_ip:<22}  ║"
            f"\n║  Active    : every {self.active_interval:<3}s{' (disabled)' if self.active_interval <= 0 else ''}"
            f"{' ' * (13 if self.active_interval > 0 else 0)}║"
            f"\n╚═══════════════════════════════════════════════════╝\n"
        )

    def _print_summary(self):
        elapsed = time.time() - self._stats.start_time
        bps = self._stats.bytes / elapsed if elapsed > 0 else 0
        print(
            f"\n╔══════════════════ SESSION SUMMARY ═══════════════════════════════════════════╗"
            f"\n║  Duration : {elapsed:>8.1f}s                                                 ║"
            f"\n║  Packets  : {self._stats.total:>8}                                           ║"
            f"\n║  ARP      : {self._stats.arp:>8}                                             ║"
            f"\n║  IP       : {self._stats.ip:>8}                                              ║"
            f"\n║  TCP      : {self._stats.tcp:>8}                                             ║"
            f"\n║  UDP      : {self._stats.udp:>8}                                             ║"
            f"\n║  ICMP     : {self._stats.icmp:>8}                                            ║"
            f"\n║  DNS      : {self._stats.dns:>8}                                             ║"
            f"\n║  Traffic  : {self._stats.bytes / 1024:>8.1f} KB  ({bps / 1024:.1f} KB/s)     ║"
            f"\n║  Alerts   : {len(self._alerts):>8}                                           ║"
            f"\n║  ARP Tbl  : {len(self._arp_table):>8} entries                                ║"
            f"\n╚══════════════════════════════════════════════════════════════════════════════╝\n"
        )


# =======================================================================
# LIVE DASHBOARD
# =======================================================================

class LiveDashboard:
    """Real-time console stats line updating every N seconds."""

    def __init__(self, detector: ARPSpoofDetector, interval: float = 3.0):
        self.detector = detector
        self.interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running and self.detector._running:
            time.sleep(self.interval)
            self._refresh()

    def _refresh(self):
        stats = self.detector.get_stats()
        elapsed = time.time() - stats.start_time
        bps = stats.bytes / elapsed if elapsed > 0 else 0
        alerts = len(self.detector.get_alerts())
        entries = len(self.detector.get_arp_table())

        sys.stdout.write(
            f"\r[⏱ {elapsed:>7.1f}s] "
            f"[📦 {stats.total:>6}] "
            f"[ARP {stats.arp:>4}] "
            f"[TCP {stats.tcp:>4}] "
            f"[UDP {stats.udp:>4}] "
            f"[⬇ {stats.bytes // 1024:>5}KB @ {bps // 1024:>3}KB/s] "
            f"[⚠ {alerts:>2}] "
            f"[📋 {entries:>2} hosts]   "
        )
        sys.stdout.flush()


# =======================================================================
# COMMAND LINE
# =======================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced Packet Sniffer + ARP Spoofing Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Auto-detect everything
    sudo %(prog)s

    # Specific interface + gateway
    sudo %(prog)s -i eth0 -g 192.168.1.1

    # Full logging + PCAP capture
    sudo %(prog)s -i eth0 --log capture.log --pcap traffic.pcap

    # Live dashboard (compact stats line)
    sudo %(prog)s -i eth0 -q --live

    # Passive-only (disable active probing)
    sudo %(prog)s -i eth0 --no-active
        """,
    )
    parser.add_argument("-i", "--interface", help="Network interface (auto-detect if omitted)")
    parser.add_argument("-g", "--gateway", help="Gateway IP address (auto-detect if omitted)")
    parser.add_argument("--active", type=int, default=30,
                        help="Active probe interval in seconds (default: 30)")
    parser.add_argument("--no-active", action="store_true",
                        help="Disable active probing")
    parser.add_argument("--log", help="Log file path")
    parser.add_argument("--pcap", help="PCAP output file path")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Less verbose console output")
    parser.add_argument("--live", action="store_true",
                        help="Show live stats dashboard")
    parser.add_argument("--json", help="Path to write alert JSON on exit")
    return parser.parse_args()


def check_admin():
    """Exit with a clear message if not running with sufficient privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Administrator privileges required on Windows.",
                        file=sys.stderr)
                sys.exit(1)
        except (ImportError, AttributeError, Exception):
            # Fallback: try creating a file in System32
            test_path = os.path.join(
                os.environ.get("SystemRoot", "C:\\Windows"), "System32",
                ".admin_test_tmp"
            )
            try:
                with open(test_path, "w") as f:
                    f.write("")
                os.remove(test_path)
            except (IOError, OSError):
                print("[!] Administrator privileges required.", file=sys.stderr)
                sys.exit(1)
    elif os.name == "posix" and os.geteuid() != 0:
        print("[!] Root privileges required. Use: sudo python3 advanced_sniffer.py",
                file=sys.stderr)
        sys.exit(1)


def main():
    if not SCAPY_AVAILABLE:
        sys.exit(1)

    check_admin()
    args = parse_args()

    active_interval = 0 if args.no_active else args.active

    detector = ARPSpoofDetector(
        interface=args.interface,
        gateway_ip=args.gateway,
        active_check_interval=active_interval,
        quiet=args.quiet,
        log_file=args.log,
        pcap_file=args.pcap,
    )

    # Live dashboard
    dashboard = None
    if args.live:
        dashboard = LiveDashboard(detector, interval=3.0)
        dashboard.start()

    # Clean shutdown on SIGINT/SIGTERM
    def shutdown(sig=None, frame=None):
        if dashboard:
            dashboard.stop()
        detector.stop()
        if args.json:
            alerts = detector.get_alerts()
            with open(args.json, "w") as f:
                json.dump(
                    [asdict(a, dict_factory=lambda x:
                            {k: (v.isoformat() if isinstance(v, datetime) else v)
                                for k, v in x})
                        for a in alerts],
                    f, indent=2, default=str,
                )
            detector.log.info(f"[*] Alerts written to {args.json}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    detector.start()
    detector.wait()
    shutdown()


if __name__ == "__main__":
    main()