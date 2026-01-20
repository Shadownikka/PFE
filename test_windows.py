"""
Quick test script for Windows version
Shows if basic functionality works
"""

import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

print("="*60)
print("Testing NetCut3 Windows Version")
print("="*60)

# Test 1: Admin check
print("\n[TEST 1] Administrator Check:")
if is_admin():
    print("✓ Running as Administrator")
else:
    print("✗ NOT running as Administrator")
    print("  Please run this script as Administrator to continue")

# Test 2: Import dependencies
print("\n[TEST 2] Checking Dependencies:")
deps = {
    'scapy': False,
    'termcolor': False,
    'tqdm': False,
    'psutil': False
}

for module in deps.keys():
    try:
        __import__(module)
        deps[module] = True
        print(f"✓ {module} installed")
    except ImportError:
        print(f"✗ {module} NOT installed")

# Test 3: Npcap check
print("\n[TEST 3] Npcap/WinPcap Check:")
try:
    import scapy.all as scapy
    scapy.conf.use_pcap = True
    if hasattr(scapy.conf, 'L2socket'):
        print("✓ Packet capture library detected")
    else:
        print("⚠ Packet capture may not work")
        print("  Install Npcap from: https://npcap.com/")
except Exception as e:
    print(f"✗ Error: {e}")
    print("  Install Npcap from: https://npcap.com/")

# Test 4: Network detection
print("\n[TEST 4] Network Detection:")
try:
    import scapy.all as scapy
    import psutil
    
    # Try to get gateway
    gateways = scapy.conf.route.route("0.0.0.0")
    if gateways:
        iface_name, gateway_ip, _ = gateways
        print(f"✓ Gateway detected: {gateway_ip}")
        print(f"✓ Interface: {iface_name}")
        
        # Get local IP
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if iface_name in iface:
                for addr in addr_list:
                    if addr.family == 2:  # AF_INET
                        print(f"✓ Local IP: {addr.address}")
                        break
    else:
        print("✗ Could not detect gateway")
        print("  Make sure you're connected to a network")
except Exception as e:
    print(f"✗ Error: {e}")

# Summary
print("\n" + "="*60)
print("TEST SUMMARY:")
print("="*60)

all_deps = all(deps.values())
if is_admin() and all_deps:
    print("✓ Ready to run NetCut3_Windows.py")
    print("\nRun: python NetCut3_Windows.py")
else:
    print("⚠ Issues detected:")
    if not is_admin():
        print("  - Run as Administrator")
    if not all_deps:
        print("  - Install missing dependencies: pip install scapy termcolor tqdm psutil")
    print("  - Install Npcap: https://npcap.com/")

print("="*60)
