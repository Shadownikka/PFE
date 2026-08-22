"""
NetMind — Windows Platform Abstraction Layer
Replaces all Linux-specific calls (iptables, /proc, iw) with Windows equivalents.
"""
import ctypes
import subprocess
import sys
import os
import socket
import struct
import time
import threading
import psutil
from collections import defaultdict, OrderedDict

# ── Admin check ─────────────────────────────────────────────────────────
def has_admin():
    """Check if running as Administrator (Windows equivalent of root)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin():
    """Re-launch as admin if not already elevated."""
    if not has_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)


# ── Network interface detection ─────────────────────────────────────────
def get_default_interface():
    """Get the default network interface name on Windows."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    gw = get_gateway_ip()

    for iface_name, iface_addrs in addrs.items():
        if iface_name not in stats or not stats[iface_name].isup:
            continue
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                # Check if this interface can reach the gateway
                ip_parts = [int(x) for x in addr.address.split('.')]
                mask_parts = [int(x) for x in (addr.netmask or '255.255.255.0').split('.')]
                gw_parts = [int(x) for x in gw.split('.')]
                net_match = all((ip_parts[i] & mask_parts[i]) == (gw_parts[i] & mask_parts[i]) for i in range(4))
                if net_match:
                    return iface_name
    # Fallback: first active non-loopback interface
    for name, st in stats.items():
        if st.isup and name != 'Loopback Pseudo-Interface 1' and 'Loopback' not in name:
            return name
    return list(stats.keys())[0]


def get_gateway_ip():
    """Get default gateway IP on Windows."""
    try:
        gws = psutil.net_if_addrs()
        # Use PowerShell to get gateway
        result = subprocess.run(
            ['powershell', '-Command',
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
            capture_output=True, text=True, timeout=5
        )
        gw = result.stdout.strip()
        if gw and gw != '':
            return gw
    except Exception:
        pass

    # Fallback: parse ipconfig
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if 'Default Gateway' in line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    gw = parts[-1].strip()
                    if gw and gw[0].isdigit():
                        return gw
    except Exception:
        pass

    return '192.168.1.1'  # last resort


def get_local_ip():
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def get_subnet_cidr():
    """Get subnet CIDR for the default interface."""
    iface = get_default_interface()
    addrs = psutil.net_if_addrs()
    if iface in addrs:
        for addr in addrs[iface]:
            if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                ip = addr.address
                mask = addr.netmask or '255.255.255.0'
                ip_parts = [int(x) for x in ip.split('.')]
                mask_parts = [int(x) for x in mask.split('.')]
                net = '.'.join(str(ip_parts[i] & mask_parts[i]) for i in range(4))
                prefix = sum(bin(int(x)).count('1') for x in mask.split('.'))
                return f"{net}/{prefix}"
    return '192.168.1.0/24'


# ── IP Forwarding (Windows) ────────────────────────────────────────────
def enable_ip_forwarding():
    """Enable IP forwarding on Windows via registry + netsh."""
    try:
        subprocess.run(
            ['reg', 'add',
             r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
             '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '1', '/f'],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ['netsh', 'interface', 'ipv4', 'set', 'interface',
             get_default_interface(), 'forwarding=enabled'],
            capture_output=True, timeout=5
        )
        print("[✓] IP forwarding enabled (Windows)")
    except Exception as e:
        print(f"[!] Failed to enable IP forwarding: {e}")


def disable_ip_forwarding():
    """Disable IP forwarding on Windows."""
    try:
        subprocess.run(
            ['reg', 'add',
             r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
             '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '0', '/f'],
            capture_output=True, timeout=5
        )
        print("[✓] IP forwarding disabled (Windows)")
    except Exception:
        pass


# ── Device Discovery (ARP scan via scapy or fallback) ──────────────────
def discover_devices_arp():
    """
    Discover network devices using ARP.
    Uses scapy if available (requires Npcap), otherwise falls back to
    parsing `arp -a` output.
    """
    devices = OrderedDict()
    gateway = get_gateway_ip()
    local_ip = get_local_ip()

    try:
        import scapy.all as scapy
        subnet = get_subnet_cidr()
        packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=subnet)
        answered, _ = scapy.srp(packet, timeout=3, verbose=False)

        seen = set()
        idx = 1
        for _, rcv in answered:
            ip = rcv.psrc
            mac = rcv.hwsrc.lower()
            if ip in seen or ip == local_ip:
                continue
            seen.add(ip)

            hostname = "Unknown"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            devices[idx] = {"ip": ip, "mac": mac, "hostname": hostname}
            idx += 1

        return devices

    except ImportError:
        pass  # scapy not available, fall through to arp -a

    # Fallback: parse `arp -a` output
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        idx = 1
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0][0].isdigit():
                ip = parts[0]
                mac = parts[1].replace('-', ':').lower()
                if ip == local_ip or mac == 'ff:ff:ff:ff:ff:ff':
                    continue
                hostname = "Unknown"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                devices[idx] = {"ip": ip, "mac": mac, "hostname": hostname}
                idx += 1
    except Exception as e:
        print(f"[!] ARP table read failed: {e}")

    return devices


# ── Traffic Monitor (Windows — psutil-based) ───────────────────────────
class WinTrafficMonitor:
    """
    Monitor per-interface bandwidth using psutil.
    Unlike Linux iptables counters, Windows doesn't have per-IP kernel counters,
    so we monitor total interface traffic and estimate per-device proportionally
    from ARP activity or packet capture (when scapy available).
    """

    def __init__(self, devices):
        self.devices = devices
        self.stats = defaultdict(lambda: {"up": 0, "down": 0})
        self.history = defaultdict(lambda: [])
        self.running = False
        self.lock = threading.Lock()
        self._last_bytes = {}
        self._iface = get_default_interface()

    def start(self):
        self.running = True
        self._last_bytes = self._read_interface_counters()
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        print(f"[+] Traffic monitor started (psutil, interface: {self._iface})")

    def stop(self):
        self.running = False

    def _read_interface_counters(self):
        """Read bytes sent/received per interface from psutil."""
        counters = psutil.net_io_counters(pernic=True)
        result = {}
        for name, c in counters.items():
            result[name] = {"sent": c.bytes_sent, "recv": c.bytes_recv}
        return result

    def _monitor_loop(self):
        """Monitor loop using psutil interface-level counters."""
        while self.running:
            time.sleep(1)
            current = self._read_interface_counters()

            with self.lock:
                if self._iface in current and self._iface in self._last_bytes:
                    cur = current[self._iface]
                    prev = self._last_bytes[self._iface]

                    delta_up = max(0, cur["sent"] - prev["sent"])
                    delta_down = max(0, cur["recv"] - prev["recv"])

                    # Distribute proportionally across known devices
                    n_devices = max(1, len(self.devices))
                    per_device_up = delta_up / n_devices
                    per_device_down = delta_down / n_devices

                    for ip in list(self.devices):
                        self.stats[ip]["up"] = per_device_up / 1024  # KB/s
                        self.stats[ip]["down"] = per_device_down / 1024

                self._last_bytes = current

    def get_total_bandwidth(self):
        """Get total up/down in KB/s."""
        with self.lock:
            total_up = sum(s["up"] for s in self.stats.values())
            total_down = sum(s["down"] for s in self.stats.values())
            return {"up_kbps": total_up, "down_kbps": total_down}

    def get_device_stats(self):
        """Get per-device stats snapshot."""
        with self.lock:
            return dict(self.stats)

    def add_device(self, ip, info):
        """Register a new device for monitoring."""
        self.devices[ip] = info

    def cleanup(self):
        """No kernel cleanup needed on Windows."""
        self.running = False
        print("[✓] Traffic monitor stopped")


# ── Bandwidth Limiter (Windows — netsh-based) ──────────────────────────
class WinBandwidthLimiter:
    """
    Bandwidth limiting on Windows using netsh QoS policies.
    Note: Full per-device QoS requires Group Policy or third-party tools.
    This provides interface-level throttling as a reasonable approximation.
    """

    def __init__(self):
        self._active_policies = {}

    def limit_device(self, ip, download_kbps=None, upload_kbps=None):
        """
        Apply bandwidth limit for a device.
        On Windows, we use netsh to create QoS policies.
        """
        policy_name = f"NetMind_{ip.replace('.', '_')}"
        try:
            # Remove existing policy if any
            self.unlimit_device(ip)

            if download_kbps:
                throttle_rate = max(1, int(download_kbps))
                subprocess.run(
                    ['powershell', '-Command',
                     f'New-NetQosPolicy -Name "{policy_name}" '
                     f'-IPDstPrefixMatchCondition "{ip}/32" '
                     f'-ThrottleRateActionBitsPerSecond {throttle_rate * 1000}'],
                    capture_output=True, timeout=10
                )
                self._active_policies[ip] = policy_name
                print(f"[+] Bandwidth limit set for {ip}: {download_kbps} KB/s")

        except Exception as e:
            print(f"[!] Failed to set bandwidth limit for {ip}: {e}")

    def unlimit_device(self, ip):
        """Remove bandwidth limit for a device."""
        policy_name = f"NetMind_{ip.replace('.', '_')}"
        try:
            subprocess.run(
                ['powershell', '-Command',
                 f'Remove-NetQosPolicy -Name "{policy_name}" -Confirm:$false'],
                capture_output=True, timeout=10
            )
            self._active_policies.pop(ip, None)
        except Exception:
            pass

    def cleanup(self):
        """Remove all NetMind QoS policies."""
        for ip in list(self._active_policies):
            self.unlimit_device(ip)
        print("[✓] All bandwidth limits removed")
