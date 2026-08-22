# NetMind — Windows Edition

**AI-Powered Network Management for Windows**

NetMind monitors your network devices, manages bandwidth, and provides intelligent automation — all from a sleek desktop interface.

---

## 🖥️ For Users — Installation

1. **Download** `NetMind-Setup-2.4.1.exe` from the [Releases](https://github.com/your-org/netmind/releases) page
2. **Run** the setup wizard — it will:
   - Install NetMind to `C:\Program Files\NetMind`
   - Install **Npcap** (required for network scanning)
   - Create Desktop & Start Menu shortcuts
   - Optionally add to Windows startup
3. **Launch** NetMind from the Desktop shortcut (right-click → Run as Administrator for full features)

### Requirements
- Windows 10/11 (64-bit)
- Administrator privileges (for network scanning)
- [Npcap](https://npcap.com/) — installed automatically by the setup wizard

### Linking to Your Account
1. Open NetMind and click **🔗 API Token** in the toolbar
2. Log in at [netmind.io](https://netmind.io) → Dashboard → Settings
3. Paste your API token to link the desktop tool to your web account
4. Your dashboard will show real-time device data from this machine

---

## 🛠️ For Developers — Building the Installer

### Prerequisites
1. **Python 3.10+** — [python.org/downloads](https://www.python.org/downloads/)
2. **Inno Setup 6** — [jrsoftware.org/isdl.php](https://jrsoftware.org/isdl.php)
3. **Npcap installer** — download from [npcap.com](https://npcap.com/#download) and place in `installer/`

### Build Steps

```powershell
# 1. Clone this folder
cd NetMind_Windows

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Build everything (app + installer)
.\build_installer.ps1

# 4. Output:
#    dist\NetMind\NetMind.exe       — standalone app
#    dist\installer\NetMind-Setup-2.4.1.exe — full installer
```

### Build Options

```powershell
# Skip PyInstaller (re-compile installer only)
.\build_installer.ps1 -SkipPyInstaller

# Skip Inno Setup (build app only)
.\build_installer.ps1 -SkipInnoSetup

# Clean build artifacts first
.\build_installer.ps1 -Clean
```

---

## 📁 Project Structure

```
NetMind_Windows/
├── NetMindDesktop.py          # Main PyQt6 desktop application
├── NetMind.spec               # PyInstaller build specification
├── build_installer.ps1        # PowerShell build script
├── requirements.txt           # Python dependencies
├── LICENSE                    # License file
├── core/
│   ├── __init__.py
│   ├── platform_win.py        # Windows platform layer (replaces iptables/proc)
│   ├── tool.py                # Windows network engine
│   ├── ai.py                  # AI/LLM engine (Ollama)
│   ├── api_server.py          # Local REST API (port 7070)
│   ├── autopilot.py           # Autonomous network management
│   ├── net_agent.py           # AI chat agent
│   ├── onboarding.py          # Setup wizard
│   ├── voice_handler.py       # Voice input (optional)
│   └── metrics_exporter.py    # Prometheus metrics
├── assets/
│   ├── icon.ico               # App icon (add your own)
│   ├── installer_banner.bmp   # Installer sidebar image (optional)
│   └── installer_icon.bmp     # Installer small icon (optional)
└── installer/
    ├── netmind_setup.iss       # Inno Setup script
    └── npcap-installer.exe     # Npcap (download separately)
```

---

## 🔧 How It Works (vs. Linux)

| Feature | Linux | Windows |
|---------|-------|---------|
| Device Discovery | scapy raw sockets | scapy + Npcap (or `arp -a` fallback) |
| Traffic Monitoring | iptables FORWARD counters | psutil interface counters |
| Bandwidth Control | tc qdisc + iptables | netsh QoS policies |
| IP Forwarding | `/proc/sys/net/ipv4/ip_forward` | Registry + netsh |
| Admin Check | `os.geteuid() == 0` | `ctypes.windll.shell32.IsUserAnAdmin()` |
| Desktop UI | PyQt6 | PyQt6 (identical) |
| AI Engine | Ollama | Ollama (identical) |

---

## 📋 Notes

- **Npcap is required** for full network scanning. Without it, NetMind falls back to parsing `arp -a` output (fewer features).
- **Run as Administrator** for full network monitoring capabilities.
- The Windows version uses **passive monitoring** (no ARP spoofing). Bandwidth data comes from interface-level counters distributed across detected devices.
- The AI agent (Ollama) must be installed separately: [ollama.ai](https://ollama.ai)
