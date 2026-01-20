# NetCut3 - Windows Edition

## 🪟 Windows-Compatible Network Control Tool

A complete rewrite of NetCut3 for Windows, providing network monitoring and control capabilities.

---

## ✅ Features (Windows Version)

- **Network Scanning**: Discover all devices on local network via ARP
- **Bandwidth Monitoring**: Real-time upload/download speed tracking via packet capture
- **Device Blocking**: Block internet access using Windows Firewall
- **Bandwidth Limiting**: Software-based rate limiting (less precise than Linux)
- **ARP Spoofing**: MITM positioning for traffic control

---

## ⚙️ Requirements

### System Requirements
- **Windows 10/11** (64-bit recommended)
- **Administrator privileges** (required)
- **Python 3.7+**
- **Npcap** (for packet capture)

### Python Dependencies
- scapy
- termcolor
- tqdm
- psutil

---

## 📦 Installation

### Step 1: Install Npcap (REQUIRED)
1. Download Npcap from: https://npcap.com/
2. Run the installer
3. **IMPORTANT**: Check "Install Npcap in WinPcap API-compatible Mode"
4. Restart your computer after installation

### Step 2: Install Python Dependencies
```powershell
# Open PowerShell as Administrator
cd path\to\PFE

# Run setup script
python Setup_Windows.py

# OR manually install dependencies
pip install -r requirements_windows.txt
```

---

## 🚀 Usage

### Run the Tool
```powershell
# MUST run as Administrator!
python NetCut3_Windows.py
```

### Menu Options

1. **Scan for Devices**
   - Discovers all devices on your network
   - Shows IP and MAC addresses

2. **Block Device**
   - Completely blocks internet access
   - Uses Windows Firewall rules
   - Requires ARP spoofing to be effective

3. **Set Bandwidth Limit**
   - Software-based rate limiting
   - Format: `down/up` in KB/s (e.g., `100/50`)
   - Note: Less precise than Linux version

4. **Monitor Bandwidth**
   - Real-time traffic monitoring
   - Shows upload/download speeds
   - Updates every 3 seconds

5. **Restore Network**
   - Removes all firewall rules
   - Stops ARP spoofing
   - Restores normal operation

6. **Exit**
   - Clean shutdown with automatic restoration

---

## 🎯 Example Workflow

```
1. Run as Administrator
2. Choose option 1 (Scan)
3. Wait for scan to complete
4. Choose option 4 (Monitor)
5. Watch real-time bandwidth usage
6. Choose option 3 to limit a device (e.g., 500/500)
7. Choose option 5 to restore when done
```

---

## ⚠️ Important Notes

### Windows vs Linux Differences

| Feature | Linux Version | Windows Version |
|---------|--------------|-----------------|
| Blocking | iptables/NFQUEUE | Windows Firewall |
| Rate Limiting | tc (precise) | Software-based (approximate) |
| Monitoring | iptables counters | Packet sniffing |
| IP Forwarding | /proc/sys | Registry + RemoteAccess service |
| Precision | Very High | Moderate |

### Limitations
- **Rate limiting is less precise** than Linux tc (traffic control)
- **Requires Npcap** for packet capture
- **Must run as Administrator** for all operations
- **Firewall rules** may conflict with existing security software

### Troubleshooting

**"Access Denied" errors**
- Make sure you're running as Administrator
- Right-click Python/PowerShell → "Run as administrator"

**"No packets captured"**
- Verify Npcap is installed correctly
- Check if "WinPcap API-compatible Mode" was enabled
- Restart computer after Npcap installation

**"Could not find gateway"**
- Check your network connection
- Make sure you're connected to a network with a router

**Rate limiting doesn't work well**
- Windows doesn't have native QoS like Linux tc
- Software-based limiting is approximate
- Consider using router-level QoS instead

---

## 🔒 Security & Ethics

⚠️ **WARNING**: This tool is for educational and network administration purposes only.

- Only use on networks you own or have permission to manage
- Unauthorized network manipulation is illegal
- ARP spoofing can be detected by modern security tools
- Use responsibly and ethically

---

## 🆚 Which Version Should You Use?

**Use Linux Version if:**
- You need precise bandwidth control
- You're running Linux/Ubuntu
- You need production-grade reliability

**Use Windows Version if:**
- You can only use Windows
- You need basic monitoring/blocking
- You're testing/learning

**Recommended for Production:**
- Linux version on Ubuntu/Debian
- Or dedicated network appliance

---

## 📝 Technical Details

### How It Works (Windows)

1. **ARP Spoofing**: Scapy sends crafted ARP packets to position as MITM
2. **IP Routing**: Windows routing service forwards packets
3. **Monitoring**: Scapy sniffs forwarded packets and counts bytes
4. **Blocking**: Windows Firewall rules drop packets to/from target
5. **Rate Limiting**: Python-based packet delay/buffer (software simulation)

### Why Less Precise Than Linux?

- Windows lacks native tc (traffic control) equivalent
- No HTB/TBF/SFQ qdiscs available
- Software-based limiting has higher overhead
- Firewall API is less granular than iptables/nftables

---

## 🛠️ Future Improvements

Possible enhancements:
- [ ] Windows driver for precise rate limiting
- [ ] GUI interface with real-time graphs
- [ ] Integration with Windows QoS policies
- [ ] Better visualization of network traffic
- [ ] Export statistics to CSV/JSON

---

## 📄 License

Educational use only. See main LICENSE file.

---

## 👥 Credits

**Original Linux Version**: Mahdi (Shadownikka)  
**Windows Port**: AI-assisted rewrite for cross-platform compatibility

---

## 🔗 Resources

- Npcap Download: https://npcap.com/
- Scapy Documentation: https://scapy.readthedocs.io/
- Windows Firewall: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/

---

**Project**: PFE (Final Year Project)  
**Year**: 2025-2026
