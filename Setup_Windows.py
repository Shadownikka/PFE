"""
Windows Setup Script for NetCut3
Run as Administrator
"""

import os
import sys
import subprocess
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("[-] Please run as Administrator!")
    print("[!] Right-click on this script and select 'Run as administrator'")
    sys.exit(1)

print("[+] Running as Administrator")
print("[+] Installing Python dependencies...")

# Install Python packages
packages = [
    "scapy",
    "termcolor",
    "tqdm",
    "psutil"
]

for package in packages:
    print(f"[+] Installing {package}...")
    subprocess.run(f"pip install {package}", shell=True)

print("\n" + "="*60)
print("[+] Installation complete!")
print("="*60)
print("\n[!] IMPORTANT: You must install Npcap for packet capture:")
print("    1. Download from: https://npcap.com/")
print("    2. Run installer")
print("    3. Select 'Install Npcap in WinPcap API-compatible Mode'")
print("    4. Restart your computer after installation")
print("\n[+] After installing Npcap, run:")
print("    python NetCut3_Windows.py")
print("\n[!] Remember to always run as Administrator!")
