# NetCut AI - Intelligent Bandwidth Management System

## 🛡️ Project Overview

**NetCut AI** is an advanced, machine learning-powered bandwidth management system designed for Linux-based networks (Kali Linux, Ubuntu, etc.). It automatically monitors and intelligently manages network traffic to ensure fair and efficient bandwidth allocation across all connected devices.

### Core Features

- **Automatic Monitoring**: Real-time bandwidth tracking for all connected devices
- **Intelligent Fair Allocation**: AI-driven algorithms prevent bandwidth hogging
- **Dual Modes**: 
  - 🤖 **Automatic AI Mode** - Hands-off intelligent management
  - 🎮 **Manual Mode** - User control with AI assistance
- **Four Core Actions**:
  1. **Monitor**: Real-time upload/download speed tracking
  2. **Block**: Complete internet cut-off for a specific device
  3. **Limit**: Cap device bandwidth (e.g., 2 Mbps)
  4. **Restore**: Remove all restrictions and return to full speed

---

## 📁 Project Structure

```
NetCut/
├── NetCut.py          # Main entry point (combines tool and AI)
├── tool.py             # Core networking tool module
│                       #  - ARP spoofing
│                       #  - Traffic monitoring
│                       #  - Bandwidth control
├── ai.py               # AI engine module
│                       #  - Intelligent bandwidth controller
│                       #  - Auto-balancing algorithm
│                       #  - Interactive menu system
├── README.md           # This file
├── Setup.py            # Installation script
├── Dependance.txt      # Required dependencies
└── requirements.txt    # Python package requirements
```

---

## 🏗️ Architecture

### Module Separation

The project is organized into three layers:

#### **1. Core Tool (tool.py)**
Provides low-level network operations:
- **ARPSpoofer**: Performs Man-in-the-Middle (MITM) attacks via ARP spoofing
- **TrafficMonitor**: Monitors bandwidth using iptables
- **BandwidthController**: Applies traffic control using tc (traffic control)
- **Utilities**: Network discovery, gateway detection, IP forwarding

#### **2. AI Engine (ai.py)**
Implements intelligent management:
- **IntelligentController**: Wraps BandwidthController with smart algorithms
- **NetCutAI**: Main system orchestrator
- **Auto-Balancing**: Detects bandwidth hogs and applies fair limits
- **Interactive UI**: Menu-driven manual control system

#### **3. Entry Point (NetCut.py)**
- Simple main program that imports and launches the AI system
- Mode selection (Automatic vs Manual)
- Clean, modular startup sequence

---

## ⚙️ Installation & Setup

### Prerequisites

```bash
# Ensure you're on Linux with sudo privileges
sudo apt-get update
sudo apt-get install -y python3 python3-pip
```

### Automatic Setup

```bash
# Clone repository
git clone https://github.com/Shadownikka/PFE.git
cd PFE

# Run setup script
sudo python3 Setup.py
```

### Manual Setup

```bash
# Install dependencies
sudo pip3 install -r requirements.txt

# Required Linux tools (should be pre-installed)
sudo apt-get install -y iptables iproute2 scapy
```

---

## 🚀 Usage

### Basic Launch

```bash
sudo python3 NetCut.py
```

### Step-by-Step Operation

1. **Network Scan**
   - Automatically discovers connected devices
   - Displays IP addresses and MAC addresses

2. **Mode Selection**
   - **[1] Automatic AI Mode**: System runs autonomously
   - **[2] Manual + AI Mode**: You have full control
   - **[3] Cancel**: Exit without starting

3. **Automatic Mode**
   - AI monitors all devices continuously
   - Auto-applies limits when bandwidth abuse detected
   - Press `Ctrl+C` to pause and access menu

4. **Manual Mode**
   - Real-time dashboard shows all devices
   - Interactive menu for device control
   - Options: Limit, Block, Restore, View Stats

---

## 📊 Configuration

Edit settings in `tool.py` (Config class):

```python
# Monitoring interval (seconds)
MONITOR_INTERVAL = 3

# Traffic history length
HISTORY_LENGTH = 20

# Fairness thresholds
MAX_SINGLE_DEVICE_PERCENT = 40      # Max % of bandwidth per device
MIN_GUARANTEED_KBPS = 256            # Minimum guaranteed speed

# Auto-limit activation
AUTO_LIMIT_ENABLED = True
BANDWIDTH_ABUSE_THRESHOLD = 5000     # KB/s - trigger threshold
```

---

## 🎮 Interactive Menu Options

### Manual Control Menu

```
[l] Limit specific device bandwidth
    → Enter device number and speed limits (KB/s)

[r] Remove limit from device
    → Select a limited device to remove restrictions

[b] Block device completely
    → Set bandwidth to 1 KB/s (effectively blocking)

[u] Unblock device
    → Same as remove limit

[a] Toggle AI Auto-Balance
    → Enable/disable automatic intelligent limits

[s] Show detailed statistics
    → View comprehensive bandwidth data for all devices

[c] Continue monitoring
    → Return to live dashboard

[q] Quit and restore network
    → Stop all operations and restore normal traffic
```

---

## 🔧 Technical Details

### How It Works

1. **ARP Spoofing (MITM)**
   - Intercepts traffic from target devices
   - Routes all traffic through this machine
   - Transparent to target devices

2. **Traffic Monitoring**
   - Uses iptables to count packets
   - Calculates speed: bytes/second
   - Maintains 20-second history for averaging

3. **Bandwidth Limiting**
   - Uses Linux tc (traffic control)
   - HTB (Hierarchical Token Bucket) queuing
   - SFQ (Stochastic Fairness Queuing) per-device

4. **Intelligent Algorithm**
   - Calculates total network usage
   - Detects devices exceeding threshold
   - Applies fair-share limits automatically
   - Removes limits when usage normalizes

---

## ✅ Status & Development

### Current Status: **Active Development**

#### Completed Features ✅
- ✓ Multi-module architecture (tool.py, ai.py, NetCut.py)
- ✓ Traffic monitoring implementation
- ✓ Bandwidth limiting (Token Bucket algorithm)
- ✓ Manual control interface
- ✓ Auto-balancing algorithm
- ✓ Code modularization and separation of concerns

#### Known Limitations ⚠️
- Requires root/sudo privileges
- Best results on local networks (LAN)
- Some encrypted traffic may not be limited efficiently
- Target devices must actively use internet for monitoring

#### Future Enhancements 🚀
- Web dashboard interface
- Machine learning predictive analytics
- Device profiles and scheduling
- Traffic shaping by protocol type

---

## 📦 Dependencies

### System Requirements
- Python 3.6+
- Linux kernel with iptables support
- iproute2 (tc command)

### Python Packages
```
scapy>=2.4.5          # Packet manipulation
termcolor>=1.1.0      # Colored terminal output
netifaces>=0.11.0     # Network interface detection
```

Install all: `pip3 install -r requirements.txt`

---

## 🔐 Security & Ethics

**Important**: This tool is designed for:
- ✅ Network administration and management
- ✅ Fair bandwidth distribution on your own network
- ✅ Educational purposes
- ✅ Technical learning

**Do NOT use for**:
- ❌ Unauthorized network access
- ❌ Illegal interception of traffic
- ❌ Networks you don't own/manage

---

## 📝 Project Information

- **Name**: NetCut AI - Intelligent Bandwidth Management System
- **Author**: Mahdi
- **Project Type**: Final Year Project (PFE)
- **Academic Year**: 2025-2026
- **Repository**: [GitHub - Shadownikka/PFE](https://github.com/Shadownikka/PFE)

---

## 🤝 Contributing

To contribute improvements:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📞 Support & Issues

For bugs, feature requests, or questions:
- Open an issue on GitHub
- Include system information (OS, Python version)
- Describe the problem with error messages

---

## 📚 Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Linux Traffic Control](https://linux.die.net/man/8/tc)
- [iptables Manual](https://linux.die.net/man/8/iptables)
- [ARP Spoofing Explanation](https://en.wikipedia.org/wiki/ARP_spoofing)

---

**Last Updated**: January 2026
