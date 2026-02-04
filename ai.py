#!/usr/bin/env python3
"""
NetCut AI - Intelligent Bandwidth Management Engine
Machine learning-based traffic analysis and adaptive bandwidth allocation
"""

import os
import subprocess
import threading
import sys
import time
import signal
import select
import tty
import termios
from termcolor import colored
from tool import (
    Config, has_root, get_gateway_ip, get_default_interface, 
    get_subnet_cidr, enable_ip_forwarding, discover_clients,
    TrafficMonitor, BandwidthController, ConnectionTracker
)
import scapy.all as scapy

# -------------------------
# Intelligent Bandwidth Controller
# -------------------------
class IntelligentController:
    def __init__(self, iface, monitor):
        self.iface = iface
        self.monitor = monitor
        self.controller = BandwidthController(iface, monitor)

    def set_gateway(self, gateway):
        """Set gateway for ARP spoofing"""
        self.controller.set_gateway(gateway)

    def start_spoofing(self, target):
        """Start ARP spoofing for a device"""
        self.controller.start_spoofing(target)

    def apply_limit(self, ip, down_kbps, up_kbps):
        """Apply bandwidth limit"""
        self.controller.apply_limit(ip, down_kbps, up_kbps)

    def remove_limit(self, ip):
        """Remove bandwidth limit"""
        self.controller.remove_limit(ip)

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
        
        num_devices = len(stats)
        if num_devices == 0:
            return
        
        # Find bandwidth hogs
        for ip, usage in stats.items():
            avg_usage = self.monitor.get_average_usage(ip, duration=30)
            
            # Check if device is abusing bandwidth
            if avg_usage["down"] > Config.BANDWIDTH_ABUSE_THRESHOLD or avg_usage["up"] > Config.BANDWIDTH_ABUSE_THRESHOLD:
                # Calculate fair share (avoid division by zero)
                if Config.MAX_SINGLE_DEVICE_PERCENT > 0:
                    fair_share = Config.BANDWIDTH_ABUSE_THRESHOLD * (100.0 / Config.MAX_SINGLE_DEVICE_PERCENT) / num_devices
                else:
                    fair_share = Config.BANDWIDTH_ABUSE_THRESHOLD / num_devices
                
                limit_down = max(int(fair_share * 0.8), Config.MIN_GUARANTEED_KBPS)  # 80% of fair share, minimum guaranteed
                limit_up = max(int(fair_share * 0.5), Config.MIN_GUARANTEED_KBPS // 2)  # 50% for upload
                
                if ip not in self.controller.limits:
                    print(colored(f"\n[AI] Device {ip} consuming excessive bandwidth!", "red"))
                    print(colored(f"[AI] Applying fair limit: ↓{limit_down}KB/s ↑{limit_up}KB/s", "cyan"))
                    self.apply_limit(ip, limit_down, limit_up)
            else:
                # Remove limit if usage normalized
                if ip in self.controller.limits and avg_usage["down"] < Config.BANDWIDTH_ABUSE_THRESHOLD * 0.5:
                    print(colored(f"\n[AI] Device {ip} usage normalized. Removing limits.", "green"))
                    self.remove_limit(ip)

    @property
    def limits(self):
        """Get current limits from controller"""
        return self.controller.limits

    def cleanup(self):
        """Cleanup all rules"""
        self.controller.cleanup()

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
        self.conn_tracker = None  # Connection tracker for activity monitoring
        self.running = False
        self.old_terminal_settings = None  # Store terminal settings
        
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
        
        # Start connection tracker
        print(colored("[+] Starting connection tracker...", "cyan"))
        self.conn_tracker = ConnectionTracker(self.devices, self.iface)
        self.conn_tracker.start()
        print(colored("  ✓ Tracking device activity", "green"))
        
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
                result = self.show_menu()
                if result == 'main_menu':
                    return 'main_menu'  # Return to main menu
                elif result:
                    break  # Quit

    def _display_loop(self):
        """Display real-time stats and handle user interaction"""
        iteration = 0
        
        # Set terminal to raw mode for non-blocking input
        try:
            self.old_terminal_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except:
            self.old_terminal_settings = None
        
        try:
            while self.running:
                time.sleep(Config.MONITOR_INTERVAL)
                iteration += 1
                
                # Auto-balance if enabled
                if Config.AUTO_LIMIT_ENABLED and iteration % 3 == 0:
                    self.controller.auto_balance()
                
                # Display stats
                self._display_stats()
                
                # Check for menu key press (non-blocking)
                if self._check_for_menu_key():
                    # Restore terminal before showing menu
                    if self.old_terminal_settings:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_terminal_settings)
                    
                    print(colored("\n\n[+] Opening menu...", "cyan"))
                    time.sleep(0.5)
                    result = self.show_menu()
                    
                    # Set terminal back to raw mode
                    try:
                        tty.setcbreak(sys.stdin.fileno())
                    except:
                        pass
                    
                    if result == 'main_menu':
                        return 'main_menu'
                    elif result:
                        return True  # Quit
                    # Otherwise continue monitoring
        finally:
            # Always restore terminal settings
            if self.old_terminal_settings:
                try:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_terminal_settings)
                except:
                    pass
    
    def _check_for_menu_key(self):
        """Non-blocking check for 'm' key press"""
        try:
            # Check if input is available (non-blocking)
            if select.select([sys.stdin], [], [], 0)[0]:
                key = sys.stdin.read(1)
                if key.lower() == 'm':
                    return True
        except:
            pass
        return False

    def _display_stats(self):
        """Display current statistics"""
        os.system('clear')
        print(colored("="*90, "cyan"))
        print(colored("🤖 NetCut AI - Intelligent Bandwidth Management System", "green", attrs=["bold"]))
        ai_status = colored("AI: ON", "green") if Config.AUTO_LIMIT_ENABLED else colored("AI: OFF", "red")
        print(colored(f"Interface: {self.iface} | Gateway: {self.gateway_ip} | {ai_status}", "cyan"))
        print(colored("="*90, "cyan"))
        
        stats = self.monitor.get_current_stats()
        
        print(colored("\n📊 REAL-TIME BANDWIDTH USAGE & ACTIVITY:", "yellow", attrs=["bold"]))
        print(colored("-" * 110, "white"))
        print(f"{'IP Address':<15} {'↑ Upload':<20} {'↓ Download':<20} {'Status':<15} {'Activity':<40}")
        print(colored("-" * 110, "white"))
        
        total_up = 0
        total_down = 0
        
        for ip, info in self.devices.items():
            usage = stats.get(ip, {"up": 0, "down": 0})
            avg = self.monitor.get_average_usage(ip, 60)
            
            total_up += usage["up"]
            total_down += usage["down"]
            
            # Format speeds with Mbps for easy comparison with phone speed tests
            # Convert KB/s to Mbps: KB/s * 8 / 1000 = Mbps
            up_mbps = usage['up'] * 8 / 1000
            down_mbps = usage['down'] * 8 / 1000
            
            up_str = f"{usage['up']:>6.1f}KB/s ({up_mbps:>4.1f}Mbps)"
            down_str = f"{usage['down']:>6.1f}KB/s ({down_mbps:>4.1f}Mbps)"
            
            # Get activity summary
            if self.conn_tracker:
                activity = self.conn_tracker.get_summary(ip)
            else:
                activity = "N/A"
            
            # Truncate activity if too long
            if len(activity) > 38:
                activity = activity[:35] + "..."
            
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
            
            print(colored(f"{ip:<15} {up_str:<20} {down_str:<20} {status:<15} {activity:<40}", color))
        
        print(colored("-" * 110, "white"))
        # Total with Mbps conversion
        total_up_mbps = total_up * 8 / 1000
        total_down_mbps = total_down * 8 / 1000
        total_up_str = f"{total_up:.1f}KB/s ({total_up_mbps:.1f}Mbps)"
        total_down_str = f"{total_down:.1f}KB/s ({total_down_mbps:.1f}Mbps)"
        print(colored(f"{'TOTAL':<15} {total_up_str:<20} {total_down_str:<20}", "cyan", attrs=["bold"]))
        
        # Show active limits
        if self.controller.limits:
            print(colored("\n🔴 ACTIVE LIMITS:", "red", attrs=["bold"]))
            for ip, limits in self.controller.limits.items():
                print(colored(f"  • {ip}: ↓{limits['down']}KB/s ↑{limits['up']}KB/s", "yellow"))
        
        # Show instruction for accessing menu
        print(colored("\n💡 TIP: Press 'm' key to access the control menu (or Ctrl+C to quit)", "yellow"))

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
            print("  [v] View detailed device activity")
            print("  [a] Toggle AI Auto-Balance (Currently: " + (colored("ON", "green") if Config.AUTO_LIMIT_ENABLED else colored("OFF", "red")) + ")")
            print("  [s] Show detailed statistics")
            print("  [c] Continue monitoring (return to live view)")
            print("  [m] Return to main menu (rescan/change mode)")
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
            elif choice == 'v':
                self._view_device_activity()
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
                return False  # Don't quit
            elif choice == 'm':
                print(colored("\n[+] Returning to main menu...", "cyan"))
                self.stop()
                return 'main_menu'  # Return to main menu
            elif choice == 'q':
                self.stop()
                return True  # Quit
            else:
                print(colored("\n[!] Invalid choice", "red"))
                time.sleep(1)
    
    def _manual_limit(self):
        """Manually set bandwidth limit for a device"""
        try:
            ip_list = list(self.devices.keys())
            if not ip_list:
                print(colored("\nNo devices available!", "red"))
                time.sleep(1)
                return
            
            device_input = input(colored("Device number to limit: ", "yellow"))
            if not device_input.strip():
                return
            
            idx = int(device_input) - 1
            
            if idx < 0 or idx >= len(ip_list):
                print(colored("Invalid device number!", "red"))
                time.sleep(1)
                return
            
            ip = ip_list[idx]
            print(colored(f"\nLimiting {ip}", "cyan"))
            
            down_input = input(colored("Download limit (KB/s): ", "yellow"))
            up_input = input(colored("Upload limit (KB/s): ", "yellow"))
            
            if not down_input.strip() or not up_input.strip():
                print(colored("Cancelled", "yellow"))
                time.sleep(1)
                return
            
            down = int(down_input)
            up = int(up_input)
            
            if down <= 0 or up <= 0:
                print(colored("Invalid speed values! Must be positive integers.", "red"))
                time.sleep(1)
                return
            
            # Warn if values are extremely low
            if down < 10 or up < 10:
                confirm = input(colored("Warning: Very low speeds. Continue? (y/n): ", "yellow"))
                if confirm.lower() != 'y':
                    return
            
            self.controller.apply_limit(ip, down, up)
            print(colored(f"\n✓ Limit applied: {ip} → ↓{down}KB/s ↑{up}KB/s", "green"))
            time.sleep(2)
        except (ValueError, IndexError) as e:
            print(colored(f"Invalid input! {e}", "red"))
            time.sleep(1)
        except KeyboardInterrupt:
            print(colored("\n[!] Cancelled", "yellow"))
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
    
    def _view_device_activity(self):
        """View detailed activity for a specific device"""
        if not self.conn_tracker:
            print(colored("\n[!] Connection tracker not available", "red"))
            time.sleep(2)
            return
        
        os.system('clear')
        print(colored("="*80, "cyan"))
        print(colored("🔍 VIEW DEVICE ACTIVITY", "yellow", attrs=["bold"]))
        print(colored("="*80, "cyan"))
        
        print(colored("\n📡 SELECT DEVICE:", "cyan"))
        ip_list = list(self.devices.keys())
        for i, ip in enumerate(ip_list, 1):
            info = self.devices[ip]
            print(f"  [{i}] {ip:<15} {info['mac']}")
        
        try:
            choice = input(colored("\n➤ Device number (or 'b' to go back): ", "green")).strip()
            if choice.lower() == 'b':
                return
            
            idx = int(choice) - 1
            if idx < 0 or idx >= len(ip_list):
                print(colored("\n[!] Invalid device number", "red"))
                time.sleep(2)
                return
            
            selected_ip = ip_list[idx]
            
            # Get detailed activity
            activity = self.conn_tracker.get_activity(selected_ip)
            stats = self.monitor.get_current_stats().get(selected_ip, {"up": 0, "down": 0})
            
            os.system('clear')
            print(colored("="*80, "cyan"))
            print(colored(f"🔍 ACTIVITY DETAILS: {selected_ip}", "yellow", attrs=["bold"]))
            print(colored("="*80, "cyan"))
            
            # Current bandwidth
            up_mbps = stats['up'] * 8 / 1000
            down_mbps = stats['down'] * 8 / 1000
            print(colored(f"\n📊 Current Speed:", "cyan", attrs=["bold"]))
            print(f"  Upload:   {stats['up']:.1f} KB/s ({up_mbps:.1f} Mbps)")
            print(f"  Download: {stats['down']:.1f} KB/s ({down_mbps:.1f} Mbps)")
            
            # Recent domains accessed
            if activity["domains"]:
                print(colored(f"\n🌐 Recent Domains/Websites (Last 10):", "cyan", attrs=["bold"]))
                for domain in activity["domains"]:
                    print(f"  • {domain}")
            else:
                print(colored(f"\n🌐 No domains detected yet", "yellow"))
            
            # Recent IPs
            if activity["ips"]:
                print(colored(f"\n🔗 Recent Connections (Last 10):", "cyan", attrs=["bold"]))
                for ip_info in activity["ips"]:
                    print(f"  • {ip_info}")
            
            # Top ports/protocols
            if activity["top_ports"]:
                print(colored(f"\n🔌 Top Ports/Protocols:", "cyan", attrs=["bold"]))
                for port_info in activity["top_ports"]:
                    print(f"  • {port_info}")
            
            print(colored("\n" + "="*80, "cyan"))
            input(colored("\n[Press Enter to continue]", "green"))
            
        except (ValueError, IndexError):
            print(colored("\n[!] Invalid input", "red"))
            time.sleep(2)
    
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
        print(colored("\n[+] Stopping system...", "yellow"))
        self.running = False
        time.sleep(1)  # Allow threads to finish
        
        # Restore terminal settings
        if self.old_terminal_settings:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_terminal_settings)
            except:
                pass
        
        if self.conn_tracker:
            try:
                self.conn_tracker.stop()
                print(colored("[✓] Connection tracker stopped", "green"))
            except Exception as e:
                print(colored(f"[!] Tracker stop error: {e}", "yellow"))
        
        if self.monitor:
            try:
                self.monitor.stop()
                print(colored("[✓] Monitor stopped", "green"))
            except Exception as e:
                print(colored(f"[!] Monitor stop error: {e}", "yellow"))
        
        if self.controller:
            try:
                self.controller.cleanup()
            except Exception as e:
                print(colored(f"[!] Cleanup error: {e}", "yellow"))
        
        print(colored("\n[✓] System stopped. Network restored.", "green"))
