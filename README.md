# NetMind - Intelligent Bandwidth Management System

## 🛡️ Project Overview

**NetMind** is an advanced, machine learning-powered bandwidth management system designed for Linux-based networks (Kali Linux, Ubuntu, etc.). It automatically monitors and intelligently manages network traffic to ensure fair and efficient bandwidth allocation across all connected devices.

### Core Features

- **Automatic Monitoring**: Real-time bandwidth tracking for all connected devices
- **Activity Tracking**: See what websites/services each device is accessing (YouTube, Netflix, etc.)
- **Intelligent Fair Allocation**: AI-driven algorithms prevent bandwidth hogging
- **Dual Display Modes**: Shows speeds in both KB/s and Mbps for easy comparison
- **Dual Operation Modes**: 
  - 🤖 **Automatic AI Mode** - Hands-off intelligent management
  - 🎮 **Manual Mode** - User control with AI assistance
- **Four Core Actions**:
  1. **Monitor**: Real-time upload/download speed tracking with activity visibility
  2. **Block**: Complete internet cut-off for a specific device
  3. **Limit**: Cap device bandwidth (e.g., 2 Mbps)
  4. **Restore**: Remove all restrictions and return to full speed

---

## ⚠️ Important Information - Please Read

### Startup Behavior

**Initial Setup Delay (5-6 seconds)**: When you start monitoring (both Automatic or Manual mode), the system performs several initialization tasks:

1. **Clearing old iptables rules** - Removes any previous firewall rules to start fresh
2. **Setting up traffic counters** - Configures iptables to track bandwidth per device
3. **Initializing ARP spoofing** - Establishes MITM (Man-in-the-Middle) position for each device
4. **Starting connection tracker** - Begins packet sniffing to detect websites/services
5. **Waiting for initial traffic** - Captures baseline data (5 seconds)

**This is normal and necessary** - During this time, you'll see messages like:
```
[+] Clearing old iptables rules...
[+] Starting ARP spoofing for all devices...
[+] Starting connection tracker...
[+] Waiting 5 seconds to capture initial traffic...
```

### Monitoring Accuracy

**The monitoring is not 100% accurate** - This is expected for several technical reasons:

#### Why Accuracy Varies:

1. **Sampling Interval (3 seconds)**: 
   - Traffic is measured every 3 seconds
   - Speeds are calculated as averages over this period
   - Very short bursts may be averaged out or missed

2. **iptables Counting Overhead**:
   - The system counts packets at the kernel level
   - Small overhead in processing can affect precise measurements
   - Typically accurate within 5-10% margin

3. **Network Layer Differences**:
   - Your phone's speed test measures at the application layer
   - NetMind measures at the network layer (includes headers/overhead)
   - This can show slight differences (usually NetMind shows slightly higher)

4. **Buffering and Caching**:
   - TCP buffering can cause momentary delays in measurement
   - Browser/app caching may reduce measured traffic
   - Some traffic may be compressed or encrypted

5. **Concurrent Connections**:
   - Modern apps use multiple parallel connections
   - Traffic spikes may occur between measurement intervals
   - Averaging smooths out these variations

#### Expected Accuracy:
- **Upload speeds**: Very accurate (±5%)
- **Download speeds**: Accurate (±10-15%)
- **Activity tracking**: Shows recent 60 seconds, very reliable for active services
- **Total bandwidth**: Good overall accuracy for traffic patterns

#### Tips for Better Accuracy:
- ✅ Let the system run for 15-30 seconds to stabilize
- ✅ Use the 60-second average (more accurate than instant speed)
- ✅ Compare Mbps values (shown in parentheses) with phone speed tests
- ✅ Remember: KB/s × 8 ÷ 1000 = Mbps

---

## 📁 Project Structure

```
NetMind/
├── NetMind.py          # Main entry point (combines tool and AI)
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
- **NetMindAI**: Main system orchestrator
- **Auto-Balancing**: Detects bandwidth hogs and applies fair limits
- **Interactive UI**: Menu-driven manual control system

#### **3. Entry Point (NetMind.py)**
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
sudo python3 NetMind.py
```

### Step-by-Step Operation

1. **Network Scan**
   - Automatically discovers connected devices
   - Displays IP addresses and MAC addresses

2. **Mode Selection**
   - **[1] Automatic AI Mode**: System runs autonomously
   - **[2] Manual + AI Mode**: You have full control
   - **[3] Rescan Network**: Scan again for new devices
   - **[4] Cancel**: Exit without starting

3. **Initialization Phase (5-6 seconds)**
   - System clears old rules and sets up monitoring
   - ARP spoofing starts for each device
   - Connection tracker begins packet analysis
   - Initial traffic collection (shows baseline)

4. **Automatic Mode**
   - AI monitors all devices continuously
   - Auto-applies limits when bandwidth abuse detected
   - Real-time display shows speeds in KB/s and Mbps
   - Activity column shows what devices are accessing
   - Press **'m' key** to access menu (not Ctrl+C!)

5. **Manual Mode**
   - Real-time dashboard shows all devices with activity
   - Press **'m' key** anytime to open menu
   - Interactive menu for device control
   - Options: Limit, Block, Restore, View Activity, Stats

### Understanding the Display

The monitoring screen shows:
```
IP Address      ↑ Upload             ↓ Download           Status          Activity
192.168.1.50    125.5KB/s (1.0Mbps)  1250.0KB/s (10.0Mbps) 🟢 ACTIVE      YouTube, Google
```

- **Upload/Download**: Shows both KB/s and Mbps (for easy phone comparison)
- **Status**: 
  - 🟢 ACTIVE - Device is using internet
  - 🔴 LIMITED - Bandwidth limit applied
  - ⚪ IDLE - No recent activity
- **Activity**: Shows websites/services accessed in last 60 seconds

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

### Accessing the Menu

**Press 'm' key** during monitoring to open the control menu
- **NOT Ctrl+C** - that will quit the program!
- Just tap the 'm' key once - menu opens instantly
- Works in both Automatic and Manual modes

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

[v] View detailed device activity
    → See all websites, IPs, and ports device is accessing
    → Shows DNS queries and connection details

[a] Toggle AI Auto-Balance
    → Enable/disable automatic intelligent limits

[s] Show detailed statistics
    → View comprehensive bandwidth data for all devices

[c] Continue monitoring
    → Return to live dashboard

[m] Return to main menu
    → Rescan network or change mode

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
   - Allows monitoring and control

2. **Traffic Monitoring**
   - Uses iptables to count packets at kernel level
   - Calculates speed: (bytes difference) / time interval
   - Maintains 20-sample history for averaging
   - Updates every 3 seconds (configurable)
   - Converts to both KB/s and Mbps for display

3. **Activity Tracking**
   - Packet sniffing using Scapy
   - DNS query interception to identify websites
   - Protocol and port analysis
   - Time-based tracking (shows last 60 seconds)
   - Smart service detection (YouTube, Netflix, etc.)

4. **Bandwidth Limiting**
   - Uses Linux tc (traffic control)
   - HTB (Hierarchical Token Bucket) queuing
   - SFQ (Stochastic Fairness Queuing) per-device
   - Dynamic burst calculation for smooth traffic

5. **Intelligent Algorithm**
   - Calculates total network usage
   - Detects devices exceeding threshold
   - Applies fair-share limits automatically
   - Removes limits when usage normalizes

### Why the 5-6 Second Startup?

The initialization performs critical tasks:
```python
1. IP forwarding enable          (~0.5s)
2. Clearing old iptables rules   (~1s)
3. Setting up traffic counters   (~0.5s)
4. Starting ARP spoofing (×N)    (~2s for N devices)
5. Starting packet sniffer       (~0.5s)
6. Initial traffic capture       (5s - configured wait)
```

This ensures clean state and accurate baseline measurements.

### Accuracy Factors

**Upload Speed**: Very accurate because:
- Direct measurement from device
- Simple packet counting
- Minimal buffering

**Download Speed**: Slightly less accurate because:
- Network layer vs application layer difference
- TCP window scaling and buffering
- Packet aggregation in network stack
- Background traffic overhead

**Activity Tracking**: Highly accurate because:
- Captures all DNS queries in real-time
- Direct packet inspection
- Time-stamped records

---

## ✅ Status & Development

### Current Status: **Active Development**

#### Completed Features ✅
- ✓ Multi-module architecture (tool.py, ai.py, NetMind.py)
- ✓ Traffic monitoring implementation (iptables-based)
- ✓ Bandwidth limiting (Token Bucket algorithm with tc)
- ✓ Manual control interface with menu system
- ✓ Auto-balancing algorithm (AI-driven)
- ✓ Code modularization and separation of concerns
- ✓ Real-time activity tracking (DNS and packet analysis)
- ✓ Dual speed display (KB/s and Mbps)
- ✓ Non-blocking menu access (press 'm' key)
- ✓ Service detection (YouTube, Netflix, Facebook, etc.)
- ✓ Connection history tracking with timestamps

#### Known Limitations ⚠️
- Requires root/sudo privileges
- Best results on local networks (LAN)
- Some encrypted traffic may not be limited efficiently
- Target devices must actively use internet for monitoring
- 5-6 second initialization delay on startup (normal behavior)
- Monitoring accuracy is ±5-15% due to:
  - Sampling intervals (3 seconds)
  - Network layer vs application layer measurements
  - TCP buffering and overhead
  - Concurrent connection handling
- Activity tracking shows last 60 seconds only (by design)

#### Future Enhancements 🚀
- Web dashboard interface
- Machine learning predictive analytics
- Device profiles and scheduling
- Traffic shaping by protocol type
- Historical bandwidth usage graphs
- Per-device bandwidth quotas

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

- **Name**: NetMind - Intelligent Bandwidth Management System
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

## ❓ Frequently Asked Questions (FAQ)

### Q: Why does the program pause for 5-6 seconds at startup?
**A:** This is normal initialization. The system needs to:
- Clear old network rules
- Set up packet counters
- Start ARP spoofing for each device
- Initialize the connection tracker
- Collect baseline traffic data

### Q: Why isn't the monitoring 100% accurate?
**A:** Network monitoring has inherent limitations:
- **Sampling interval**: Measures every 3 seconds (bursts may be averaged)
- **Layer differences**: Phone measures at app layer, NetMind at network layer
- **Overhead**: TCP/IP headers add ~5-10% extra data
- **Expected accuracy**: Upload ±5%, Download ±10-15%

### Q: My phone shows 10 Mbps but NetMind shows 8 Mbps, why?
**A:** Several reasons:
1. Different measurement layers (see above)
2. Time averaging - NetMind uses 3-second intervals
3. Concurrent connections may spread across intervals
4. Use the 60-second average for better comparison

### Q: How do I access the menu? Ctrl+C doesn't work anymore!
**A:** Press the **'m' key** (just once) during monitoring. Ctrl+C now only quits the program.

### Q: What does "No activity" mean in the Activity column?
**A:** The device hasn't made any DNS queries or connections in the last 60 seconds. It might be:
- Idle (not using internet)
- Using cached data
- Accessing only local network resources

### Q: The activity shows wrong services!
**A:** Activity tracking shows the last 60 seconds. If it shows "YouTube" but you're browsing, the device probably accessed YouTube recently. The display refreshes to show current activity.

### Q: Can I monitor HTTPS traffic?
**A:** You can see:
- ✅ DNS queries (websites being accessed)
- ✅ IP addresses and ports
- ✅ Upload/download speeds
- ❌ Encrypted content (protected by SSL/TLS)

### Q: Does this work on WiFi and Ethernet?
**A:** Yes! Works on any network interface where:
- You're on the same local network
- You can perform ARP spoofing
- You have gateway access

### Q: Why do I need sudo/root?
**A:** The program needs root to:
- Modify iptables firewall rules
- Configure traffic control (tc)
- Perform packet sniffing
- Send ARP packets

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

**Last Updated**: February 2026  
**Version**: 2.0 (with Activity Tracking & Enhanced Monitoring)
