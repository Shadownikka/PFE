"""
NetMind Tool — Windows Edition
Network monitoring, device discovery, and bandwidth management.
Uses psutil + Npcap (scapy) instead of iptables / /proc.
"""
import os
import sys
import time
import threading
import socket
import json
from collections import defaultdict, deque, OrderedDict

# Windows platform layer
from core.platform_win import (
    has_admin, require_admin,
    get_default_interface, get_gateway_ip, get_local_ip, get_subnet_cidr,
    enable_ip_forwarding, disable_ip_forwarding,
    discover_devices_arp,
    WinTrafficMonitor, WinBandwidthLimiter,
)


# ─── Configuration ─────────────────────────────────────────────────────
class Config:
    MONITOR_INTERVAL = 1
    DISCOVERY_INTERVAL = 10
    HISTORY_LENGTH = 20
    MAX_SINGLE_DEVICE_PERCENT = 40
    MIN_GUARANTEED_KBPS = 256
    AUTO_LIMIT_ENABLED = True
    BANDWIDTH_ABUSE_THRESHOLD = 5000  # KB/s
    TOTAL_BANDWIDTH_KBPS = None
    STATE_FILE = os.path.join(os.environ.get('APPDATA', '.'), 'NetMind', 'ai_state.json')


# ─── Network Gatekeeper ─────────────────────────────────────────────────
class NetworkGatekeeper:
    """Holds trusted/target lists and enforces exclusion checks."""

    def __init__(self, trusted_macs=None, trusted_ips=None):
        self._trusted_macs = set(mac.lower() for mac in (trusted_macs or []))
        self._trusted_ips = set(str(ip) for ip in (trusted_ips or []))
        self._targets = {}

    def set_targets(self, devices):
        self._targets = {}
        for key, info in devices.items():
            ip = info.get("ip", key) if isinstance(info, dict) else key
            mac = info.get("mac", "").lower() if isinstance(info, dict) else ""
            if mac in self._trusted_macs or ip in self._trusted_ips:
                continue
            self._targets[ip] = info

    def add_trusted_mac(self, mac):
        if not mac:
            return
        normalized = mac.lower()
        self._trusted_macs.add(normalized)
        to_remove = [ip for ip, info in self._targets.items()
                     if isinstance(info, dict) and info.get("mac", "").lower() == normalized]
        for ip in to_remove:
            self._targets.pop(ip, None)

    def is_trusted_mac(self, mac):
        return bool(mac) and mac.lower() in self._trusted_macs

    def get_trusted_macs(self):
        return set(self._trusted_macs)

    def add_trusted_ip(self, ip):
        if not ip:
            return
        self._trusted_ips.add(str(ip))
        self._targets.pop(str(ip), None)

    def is_trusted_ip(self, ip):
        return bool(ip) and str(ip) in self._trusted_ips

    def get_trusted_ips(self):
        return set(self._trusted_ips)

    def get_target_devices(self):
        return dict(self._targets)


# ─── Background Scanner ────────────────────────────────────────────────
class BackgroundScanner:
    """Background ARP discovery engine with thread-safe device registry."""

    def __init__(self, scan_interval=60):
        self.scan_interval = max(10, int(scan_interval))
        self._lock = threading.Lock()
        self._discovered_devices = {}
        self._new_active_ips = set()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        print("[+] Background scanner started")

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def seed_devices(self, devices):
        now = time.time()
        with self._lock:
            for key, info in devices.items():
                ip = info.get("ip", str(key)) if isinstance(info, dict) else str(key)
                self._discovered_devices[ip] = {
                    "ip": ip,
                    "mac": info.get("mac", "") if isinstance(info, dict) else "",
                    "name": info.get("hostname", "Unknown") if isinstance(info, dict) else "Unknown",
                    "last_seen": now,
                }

    def get_new_ips(self):
        with self._lock:
            new = set(self._new_active_ips)
            self._new_active_ips.clear()
            return new

    def get_all_devices(self):
        with self._lock:
            return dict(self._discovered_devices)

    def _scan_loop(self):
        while not self._stop_event.is_set():
            try:
                devices = discover_devices_arp()
                now = time.time()
                with self._lock:
                    for _, info in devices.items():
                        ip = info["ip"]
                        if ip not in self._discovered_devices:
                            self._new_active_ips.add(ip)
                        self._discovered_devices[ip] = {
                            "ip": ip,
                            "mac": info.get("mac", ""),
                            "name": info.get("hostname", "Unknown"),
                            "last_seen": now,
                        }
            except Exception as e:
                print(f"[!] Scan error: {e}")

            self._stop_event.wait(self.scan_interval)


# ─── Main NetMind Tool Engine ──────────────────────────────────────────
class NetMindEngine:
    """
    Core network management engine for Windows.
    Provides device discovery, traffic monitoring, and bandwidth control.
    """

    def __init__(self):
        self.interface = get_default_interface()
        self.gateway_ip = get_gateway_ip()
        self.local_ip = get_local_ip()
        self.subnet = get_subnet_cidr()
        self.devices = {}
        self.gatekeeper = NetworkGatekeeper()
        self.scanner = BackgroundScanner(scan_interval=30)
        self.monitor = None
        self.limiter = WinBandwidthLimiter()
        self.running = False
        self._lock = threading.Lock()

        # Add gateway and local machine to trusted
        self.gatekeeper.add_trusted_ip(self.gateway_ip)
        self.gatekeeper.add_trusted_ip(self.local_ip)

    def start(self):
        """Start the network monitoring engine."""
        if self.running:
            return

        print(f"[*] NetMind Windows Engine starting...")
        print(f"    Interface: {self.interface}")
        print(f"    Gateway:   {self.gateway_ip}")
        print(f"    Local IP:  {self.local_ip}")
        print(f"    Subnet:    {self.subnet}")

        # Initial device discovery
        self.devices = discover_devices_arp()
        print(f"[+] Found {len(self.devices)} devices on network")

        # Start traffic monitor
        device_ips = {}
        for _, info in self.devices.items():
            device_ips[info["ip"]] = info
        self.monitor = WinTrafficMonitor(device_ips)
        self.monitor.start()

        # Start background scanner
        self.scanner.seed_devices(self.devices)
        self.scanner.start()

        self.running = True

    def stop(self):
        """Stop the engine and clean up."""
        self.running = False
        if self.monitor:
            self.monitor.stop()
        self.scanner.stop()
        self.limiter.cleanup()
        print("[✓] NetMind engine stopped cleanly")

    def get_device_list(self):
        """Get current devices for UI display."""
        result = []
        all_devs = self.scanner.get_all_devices()
        bw_stats = self.monitor.get_device_stats() if self.monitor else {}

        for ip, info in all_devs.items():
            stats = bw_stats.get(ip, {"up": 0, "down": 0})
            status = "active" if time.time() - info.get("last_seen", 0) < 120 else "idle"
            result.append({
                "ip": ip,
                "mac": info.get("mac", ""),
                "name": info.get("name", "Unknown"),
                "status": status,
                "upload": f"{stats['up']:.1f}",
                "download": f"{stats['down']:.1f}",
            })
        return result

    def get_bandwidth_totals(self):
        """Get total bandwidth in Mbps."""
        if not self.monitor:
            return {"total_download_mbps": 0, "total_upload_mbps": 0}
        bw = self.monitor.get_total_bandwidth()
        return {
            "total_download_mbps": round(bw["down_kbps"] / 1024 * 8, 2),
            "total_upload_mbps": round(bw["up_kbps"] / 1024 * 8, 2),
        }

    def get_status(self):
        """Get engine status."""
        return {
            "running": self.running,
            "interface": self.interface,
            "device_count": len(self.scanner.get_all_devices()),
            "gateway": self.gateway_ip,
        }
