"""
NetMind — Windows Platform Abstraction Layer
Replaces all Linux-specific calls (iptables, /proc, iw) with Windows equivalents.
"""
import ctypes
import subprocess
import sys
import os
import socket
import time
import threading
import psutil
from collections import defaultdict, OrderedDict

# ── Subprocess helper: never show a console window ──────────────────────
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0

def _run(*args, **kwargs):
    """subprocess.run() wrapper that suppresses all console windows."""
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('timeout', 10)
    kwargs['creationflags'] = _NO_WINDOW
    return subprocess.run(*args, **kwargs)


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
                ip_parts   = [int(x) for x in addr.address.split('.')]
                mask_parts = [int(x) for x in (addr.netmask or '255.255.255.0').split('.')]
                gw_parts   = [int(x) for x in gw.split('.')]
                net_match  = all(
                    (ip_parts[i] & mask_parts[i]) == (gw_parts[i] & mask_parts[i])
                    for i in range(4)
                )
                if net_match:
                    return iface_name

    # Fallback: first active non-loopback interface
    for name, st in stats.items():
        if st.isup and 'Loopback' not in name:
            return name
    return list(stats.keys())[0]


def get_gateway_ip():
    """Get default gateway IP on Windows."""
    try:
        result = _run(
            ['powershell', '-Command',
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
             "Sort-Object RouteMetric | Select-Object -First 1).NextHop"]
        )
        gw = result.stdout.decode(errors='ignore').strip()
        if gw and gw[0].isdigit():
            return gw
    except Exception:
        pass

    # Fallback: parse ipconfig
    try:
        result = _run(['ipconfig'])
        for line in result.stdout.decode(errors='ignore').splitlines():
            if 'Default Gateway' in line and ':' in line:
                gw = line.split(':')[-1].strip()
                if gw and gw[0].isdigit():
                    return gw
    except Exception:
        pass

    return '192.168.1.1'


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
                ip   = addr.address
                mask = addr.netmask or '255.255.255.0'
                ip_parts   = [int(x) for x in ip.split('.')]
                mask_parts = [int(x) for x in mask.split('.')]
                net    = '.'.join(str(ip_parts[i] & mask_parts[i]) for i in range(4))
                prefix = sum(bin(int(x)).count('1') for x in mask.split('.'))
                return f"{net}/{prefix}"
    return '192.168.1.0/24'


# ── IP Forwarding (Windows) ────────────────────────────────────────────
def enable_ip_forwarding():
    """Enable IP forwarding on Windows via registry."""
    try:
        _run(['reg', 'add',
              r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
              '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '1', '/f'])
        print("[✓] IP forwarding enabled (Windows)")
    except Exception as e:
        print(f"[!] Failed to enable IP forwarding: {e}")


def disable_ip_forwarding():
    """Disable IP forwarding on Windows."""
    try:
        _run(['reg', 'add',
              r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
              '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '0', '/f'])
        print("[✓] IP forwarding disabled (Windows)")
    except Exception:
        pass


# ── Device Discovery ────────────────────────────────────────────────────
def discover_devices_arp():
    """
    Discover network devices. Uses scapy+Npcap if available,
    otherwise parses `arp -a` output.
    """
    devices  = OrderedDict()
    local_ip = get_local_ip()
    gw_ip    = get_gateway_ip()

    # Try scapy first (Npcap required)
    try:
        import scapy.all as scapy
        subnet  = get_subnet_cidr()
        packet  = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=subnet)
        answered, _ = scapy.srp(packet, timeout=3, verbose=False)

        seen = set()
        idx  = 1
        for _, rcv in answered:
            ip  = rcv.psrc
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
    except Exception:
        pass  # No Npcap or scapy — fall through

    # Fallback: parse `arp -a`
    try:
        result = _run(['arp', '-a'])
        idx = 1
        for line in result.stdout.decode(errors='ignore').splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0][0].isdigit():
                ip  = parts[0]
                mac = parts[1].replace('-', ':').lower()
                if ip == local_ip or ip == gw_ip or mac == 'ff:ff:ff:ff:ff:ff':
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


# ── DNS → Service name mapping ─────────────────────────────────────────
_SERVICE_MAP = [
    # Video streaming
    (["googlevideo.com", "youtube.com", "ytimg.com", "youtu.be"],    "🎬 YouTube"),
    (["netflix.com", "nflxvideo.net", "nflximg.net"],                 "🎬 Netflix"),
    (["twitch.tv", "twitchsvc.net", "jtvnw.net"],                    "🎮 Twitch"),
    (["tiktok.com", "tiktokcdn.com", "musical.ly"],                  "📱 TikTok"),
    (["primevideo.com", "amazon.com", "aiv-cdn.net"],                 "🎬 Prime Video"),
    (["disneyplus.com", "disney-plus.net", "bamgrid.com"],            "🎬 Disney+"),
    (["hulu.com", "hulustream.com"],                                  "🎬 Hulu"),
    # Music
    (["spotify.com", "scdn.co", "spotifycdn.com"],                   "🎵 Spotify"),
    (["soundcloud.com", "sndcdn.com"],                                "🎵 SoundCloud"),
    (["deezer.com"],                                                  "🎵 Deezer"),
    # Social
    (["facebook.com", "fbcdn.net", "fb.com"],                        "👥 Facebook"),
    (["instagram.com", "cdninstagram.com"],                           "📸 Instagram"),
    (["twitter.com", "x.com", "twimg.com", "t.co"],                  "🐦 Twitter/X"),
    (["snapchat.com", "snap.com"],                                    "👻 Snapchat"),
    (["reddit.com", "redd.it", "redditmedia.com"],                    "🤖 Reddit"),
    (["linkedin.com", "licdn.com"],                                   "💼 LinkedIn"),
    # Chat / Calls
    (["discord.com", "discordapp.com", "discordapp.net"],             "💬 Discord"),
    (["whatsapp.com", "whatsapp.net"],                                "💬 WhatsApp"),
    (["telegram.org", "t.me"],                                        "💬 Telegram"),
    (["zoom.us", "zoomgov.com"],                                      "📹 Zoom"),
    (["teams.microsoft.com", "skype.com"],                            "📹 Teams/Skype"),
    # Gaming
    (["steampowered.com", "steamcontent.com", "steam.com"],           "🎮 Steam"),
    (["epicgames.com", "epicgames.dev"],                              "🎮 Epic Games"),
    (["riotgames.com", "leagueoflegends.com"],                        "🎮 League/Riot"),
    (["battlenet.com", "blizzard.com"],                              "🎮 Battle.net"),
    (["ea.com", "origin.com", "eacdn.com"],                          "🎮 EA/Origin"),
    (["roblox.com", "rbxcdn.com"],                                    "🎮 Roblox"),
    (["minecraft.net", "mojang.com"],                                 "🎮 Minecraft"),
    (["playstation.com", "playstation.net", "sony.com"],              "🎮 PlayStation"),
    (["xbox.com", "xboxlive.com"],                                    "🎮 Xbox"),
    # Shopping
    (["amazon.com", "amazonaws.com", "amazon-adsystem.com"],         "🛒 Amazon"),
    (["ebay.com", "ebayimg.com"],                                     "🛒 eBay"),
    (["aliexpress.com", "alibaba.com"],                               "🛒 AliExpress"),
    # Productivity
    (["google.com", "googleapis.com", "gstatic.com", "gmail.com"],   "🔍 Google"),
    (["microsoft.com", "live.com", "msftconnecttest.com"],            "🖥️ Microsoft"),
    (["apple.com", "icloud.com", "mzstatic.com"],                     "🍎 Apple"),
    (["dropbox.com", "dropboxstatic.com"],                            "☁️ Dropbox"),
    (["drive.google.com", "docs.google.com"],                         "📄 Google Drive"),
    (["onedrive.com", "sharepoint.com"],                              "📄 OneDrive"),
    (["github.com", "githubusercontent.com", "githubassets.com"],     "🖥️ GitHub"),
    # Browsers / CDN
    (["cloudflare.com", "cloudflare-dns.com", "1dot1dot1dot1.mfg"],  "🌐 Cloudflare"),
    (["akamaized.net", "akamai.com", "akamaihd.net"],                 "🌐 Akamai CDN"),
]

def _classify_domain(domain: str) -> str:
    """Return a human-readable service name for a domain, or the domain itself."""
    d = domain.lower().rstrip('.')
    for patterns, label in _SERVICE_MAP:
        for p in patterns:
            if d == p or d.endswith('.' + p):
                return label
    # Strip www./cdn. prefixes and return base domain
    parts = d.split('.')
    if len(parts) >= 2:
        return '🌐 ' + '.'.join(parts[-2:])
    return '🌐 ' + d


# ── Traffic Monitor — per-device packet sniffing ────────────────────────
class WinTrafficMonitor:
    """
    Per-device bandwidth monitor using scapy packet sniffing (Npcap).
    Also sniffs DNS queries to show what service each device is using.
    Falls back to interface-level psutil counters if Npcap is not available.
    """

    def __init__(self, devices):
        self.devices   = devices          # {ip: {"mac": ..., "name": ...}}
        self.running   = False
        self.lock      = threading.Lock()
        self._iface    = get_default_interface()
        self._local_ip = get_local_ip()

        # Per-device byte accumulators (reset every second)
        self._byte_counters = defaultdict(lambda: {"up": 0, "down": 0})
        # Smoothed KB/s rates (EMA)
        self.stats = defaultdict(lambda: {"up": 0.0, "down": 0.0})
        self._ema_alpha = 0.6

        # DNS activity: {ip: {"service": str, "domain": str, "ts": float}}
        self._dns_activity = {}

        # Control sets (written by WinBandwidthLimiter)
        self._blocked_ips   = set()   # IPs to null-route (block)
        self._rate_limits   = {}      # ip -> KB/s limit
        self._token_buckets = {}      # ip -> {tokens, last_refill}

        self._use_scapy = False
        self._sniffer   = None
        self._gw_ip     = ""
        self._gw_mac    = ""

    def start(self):
        self.running = True
        self._gw_ip  = get_gateway_ip()
        self._gw_mac = self._get_mac(self._gw_ip)

        # Start ARP spoofing threads so we can see other devices' traffic
        self._spoof_stop = threading.Event()
        threading.Thread(target=self._spoof_loop, daemon=True).start()

        # Try scapy sniffer — use scapy's auto-detected default interface
        # (avoids friendly-name vs Npcap GUID mismatch on Windows)
        try:
            import scapy.all as scapy
            self._use_scapy = True
            # scapy.conf.iface is always correct on the current platform
            self._sniffer = scapy.AsyncSniffer(
                prn=self._on_packet,
                store=False,
                filter="ip",          # BPF: capture only IP packets
            )
            self._sniffer.start()
            print("[+] Traffic monitor started (scapy sniffer)")
        except Exception as e:
            self._use_scapy = False
            print(f"[!] scapy sniffer unavailable ({e}), using psutil")

        threading.Thread(target=self._rate_loop, daemon=True).start()

    def _get_mac(self, ip):
        """Resolve IP → MAC via ARP (returns empty string on failure)."""
        try:
            import scapy.all as scapy
            ans = scapy.srp1(
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip),
                timeout=1, verbose=False
            )
            if ans:
                return ans[scapy.ARP].hwsrc
        except Exception:
            pass
        return ""

    def set_blocked(self, ip, blocked: bool):
        """Block or unblock a device (called by WinBandwidthLimiter)."""
        if blocked:
            self._blocked_ips.add(ip)
        else:
            self._blocked_ips.discard(ip)
            self._token_buckets.pop(ip, None)

    def set_rate_limit(self, ip, kbps: float):
        """Set per-device rate limit in KB/s (called by WinBandwidthLimiter)."""
        if kbps <= 0:
            self._rate_limits.pop(ip, None)
            self._token_buckets.pop(ip, None)
        else:
            self._rate_limits[ip] = kbps
            self._token_buckets[ip] = {"tokens": kbps, "last": time.time()}

    def _consume_tokens(self, ip, bytes_count) -> bool:
        """Token bucket check. Returns True if packet should be forwarded."""
        if ip not in self._rate_limits:
            return True
        bucket = self._token_buckets.get(ip)
        if not bucket:
            return True
        now = time.time()
        elapsed = now - bucket["last"]
        bucket["tokens"] = min(
            self._rate_limits[ip],                      # max bucket = 1 s of traffic
            bucket["tokens"] + elapsed * self._rate_limits[ip]
        )
        bucket["last"] = now
        cost = bytes_count / 1024  # KB
        if bucket["tokens"] >= cost:
            bucket["tokens"] -= cost
            return True
        return False  # Over limit — drop packet

    def _spoof_loop(self):
        """Send ARP spoof packets. Null-routes blocked devices."""
        try:
            import scapy.all as scapy
        except ImportError:
            return
        gw_ip  = self._gw_ip
        gw_mac = self._gw_mac
        NULL_MAC = "00:00:00:00:00:00"
        while not self._spoof_stop.is_set():
            for ip, info in list(self.devices.items()):
                mac = info.get("mac", "")
                if not mac:
                    continue
                try:
                    if ip in self._blocked_ips:
                        # ── BLOCK: send null gateway MAC → device can't route ──
                        scapy.send(scapy.ARP(
                            op=2, pdst=ip, hwdst=mac,
                            psrc=gw_ip, hwsrc=NULL_MAC), verbose=False)
                        if gw_mac:
                            scapy.send(scapy.ARP(
                                op=2, pdst=gw_ip, hwdst=gw_mac,
                                psrc=ip, hwsrc=NULL_MAC), verbose=False)
                    else:
                        # ── MONITOR: tell device we are the gateway ──
                        scapy.send(scapy.ARP(
                            op=2, pdst=ip, hwdst=mac,
                            psrc=gw_ip), verbose=False)
                        if gw_mac:
                            scapy.send(scapy.ARP(
                                op=2, pdst=gw_ip, hwdst=gw_mac,
                                psrc=ip), verbose=False)
                except Exception:
                    pass
            self._spoof_stop.wait(3)  # Every 3 s — fast enough for blocking

    def _on_packet(self, pkt):
        """Count bytes per source/destination IP and detect DNS activity."""
        try:
            import scapy.all as scapy
            if not pkt.haslayer(scapy.IP):
                return
            src    = pkt[scapy.IP].src
            dst    = pkt[scapy.IP].dst
            length = len(pkt)
            with self.lock:
                # Device → internet  (upload)
                if src in self.devices:
                    self._byte_counters[src]["up"] += length
                # Internet → device  (download)
                if dst in self.devices:
                    self._byte_counters[dst]["down"] += length
                # Our own machine
                if src == self._local_ip:
                    self._byte_counters[self._local_ip]["up"] += length
                if dst == self._local_ip:
                    self._byte_counters[self._local_ip]["down"] += length

            # ── DNS query detection ──────────────────────────────────────
            if pkt.haslayer(scapy.DNSQR) and pkt.haslayer(scapy.UDP):
                # Only care about outgoing DNS queries (port 53)
                if pkt[scapy.UDP].dport == 53:
                    qname = pkt[scapy.DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode(errors='ignore')
                    domain  = qname.rstrip('.')
                    service = _classify_domain(domain)
                    # Attribute to the source device
                    querier = src
                    if querier in self.devices or querier == self._local_ip:
                        with self.lock:
                            self._dns_activity[querier] = {
                                "service": service,
                                "domain":  domain,
                                "ts":      time.time(),
                            }
        except Exception:
            pass


    def _rate_loop(self):
        """Every second: convert byte counters to KB/s with EMA smoothing."""
        _last_psutil = {}

        while self.running:
            time.sleep(1)

            with self.lock:
                if self._use_scapy:
                    # Convert accumulated bytes → KB/s
                    for ip in list(self._byte_counters):
                        raw_up   = self._byte_counters[ip]["up"]   / 1024
                        raw_down = self._byte_counters[ip]["down"]  / 1024
                        # EMA smoothing
                        prev = self.stats[ip]
                        self.stats[ip]["up"]   = self._ema_alpha * raw_up   + (1 - self._ema_alpha) * prev["up"]
                        self.stats[ip]["down"] = self._ema_alpha * raw_down + (1 - self._ema_alpha) * prev["down"]
                    # Reset counters
                    self._byte_counters.clear()

                else:
                    # psutil fallback: distribute total interface delta across devices
                    try:
                        counters = psutil.net_io_counters(pernic=True)
                        cur = counters.get(self._iface)
                        if cur and self._iface in _last_psutil:
                            prev_c = _last_psutil[self._iface]
                            delta_up   = max(0, cur.bytes_sent - prev_c["sent"]) / 1024
                            delta_down = max(0, cur.bytes_recv - prev_c["recv"])  / 1024
                            n = max(1, len(self.devices))
                            for ip in list(self.devices):
                                prev_s = self.stats[ip]
                                raw_up   = delta_up   / n
                                raw_down = delta_down / n
                                self.stats[ip]["up"]   = self._ema_alpha * raw_up   + (1 - self._ema_alpha) * prev_s["up"]
                                self.stats[ip]["down"] = self._ema_alpha * raw_down + (1 - self._ema_alpha) * prev_s["down"]
                        if cur:
                            _last_psutil[self._iface] = {"sent": cur.bytes_sent, "recv": cur.bytes_recv}
                    except Exception:
                        pass

    def stop(self):
        self.running = False
        if hasattr(self, '_spoof_stop'):
            self._spoof_stop.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass


    def get_current_stats(self):
        """Return per-device stats dict. Alias for get_device_stats()."""
        return self.get_device_stats()

    def get_device_stats(self):
        """Return snapshot of per-device KB/s rates."""
        with self.lock:
            return {ip: dict(s) for ip, s in self.stats.items()}

    def get_total_bandwidth(self):
        """Return total up/down in KB/s."""
        with self.lock:
            total_up   = sum(s["up"]   for s in self.stats.values())
            total_down = sum(s["down"] for s in self.stats.values())
            return {"up_kbps": total_up, "down_kbps": total_down}

    def get_summary(self, ip):
        """Return activity summary: service name + KB/s for the Activity column."""
        with self.lock:
            s    = self.stats.get(ip, {"up": 0.0, "down": 0.0})
            up   = s["up"]
            down = s["down"]
            total = up + down

            # DNS activity (valid for 30 seconds after last query)
            dns  = self._dns_activity.get(ip)
            fresh = dns and (time.time() - dns["ts"]) < 30

            if total < 0.5:
                if fresh:
                    return f"⚪ Idle · {dns['service']}"
                return "⚪ Idle"

            bw_parts = []
            if down >= 0.1: bw_parts.append(f"↓{down:.1f}")
            if up   >= 0.1: bw_parts.append(f"↑{up:.1f}")
            bw_str = '  '.join(bw_parts) + ' KB/s' if bw_parts else ''

            if fresh:
                return f"🟢 {dns['service']}  {bw_str}".strip()
            return f"🟢 Active  {bw_str}".strip()


    def add_device(self, ip, info):
        """Register a new device for monitoring."""
        self.devices[ip] = info

    def cleanup(self):
        self.stop()
        print("[✓] Traffic monitor stopped")


# ── Bandwidth Limiter (Windows — netsh QoS) ────────────────────────────
class WinBandwidthLimiter:
    """
    Device control via ARP null-routing (block) and token-bucket rate limiting.
    Exposes the same API as the Linux BandwidthController.
    """

    def __init__(self):
        self.limits   = {}   # ip -> {"down": kbps, "up": kbps}
        self.spoofers = {}   # stub — ARP is managed by WinTrafficMonitor
        self._monitor = None # Set by tool.py after monitor is created

    def attach_monitor(self, monitor):
        """Link to WinTrafficMonitor so we can control blocking/limiting."""
        self._monitor = monitor

    def set_gateway(self, gw):
        pass  # handled by monitor

    def start_spoofing(self, device):
        pass  # handled by monitor

    def stop_spoofing(self, ip):
        self.spoofers.pop(ip, None)

    def apply_limit(self, ip, download_kbps, upload_kbps=None):
        """
        Apply bandwidth limit. Values <= 1 are treated as a full block.
        Returns True on success.
        """
        try:
            if download_kbps <= 1:
                return self.block_device(ip)
            kbps = float(download_kbps)
            self.limits[ip] = {"down": kbps, "up": float(upload_kbps or kbps)}
            if self._monitor:
                self._monitor.set_blocked(ip, False)
                self._monitor.set_rate_limit(ip, kbps)
            print(f"[+] Rate limit set for {ip}: {kbps} KB/s")
            return True
        except Exception as e:
            print(f"[!] apply_limit failed: {e}")
            return False

    def block_device(self, ip):
        """Cut device off the network via ARP null-routing."""
        try:
            self.limits[ip] = {"down": 0, "up": 0}
            if self._monitor:
                self._monitor.set_blocked(ip, True)
                self._monitor.set_rate_limit(ip, 0)
            print(f"[+] {ip} blocked (null ARP)")
            return True
        except Exception as e:
            print(f"[!] block_device failed: {e}")
            return False

    def limit_device(self, ip, download_kbps=None, upload_kbps=None):
        """Alias for apply_limit (compatibility)."""
        return self.apply_limit(ip, download_kbps or 0, upload_kbps)

    def remove_limit(self, ip):
        """Restore full access for a device."""
        try:
            self.limits.pop(ip, None)
            if self._monitor:
                self._monitor.set_blocked(ip, False)
                self._monitor.set_rate_limit(ip, 0)
            print(f"[+] {ip} freed")
        except Exception as e:
            print(f"[!] remove_limit failed: {e}")

    def unlimit_device(self, ip):
        """Alias for remove_limit (compatibility)."""
        self.remove_limit(ip)

    def cleanup(self):
        """Restore all devices on exit."""
        for ip in list(self.limits):
            self.remove_limit(ip)
        self.limits.clear()
        print("[✓] All limits removed")


