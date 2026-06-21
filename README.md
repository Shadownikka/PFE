# 🧠 NetMind — AI-Powered Network Manager

> **A native desktop application that lets you see, control, and intelligently manage every device on your home or office network — powered by a local AI that runs entirely on your machine.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-41CD52)
![AI](https://img.shields.io/badge/AI-Llama%203.1%20%28Local%29-orange)
![Platform](https://img.shields.io/badge/Platform-Linux-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Table of Contents

- [What Is NetMind?](#what-is-netmind)
- [Key Features](#key-features)
- [How It Works (Simple Version)](#how-it-works-simple-version)
- [Screenshots & UI Overview](#screenshots--ui-overview)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Using the App](#using-the-app)
  - [First Launch & Onboarding](#first-launch--onboarding)
  - [Dashboard Overview](#dashboard-overview)
  - [Device List](#device-list)
  - [Manual Controls](#manual-controls)
  - [Trusted Devices](#trusted-devices)
  - [AutoPilot (AI Mode)](#autopilot-ai-mode)
  - [AI Chat Assistant](#ai-chat-assistant)
  - [Grafana Dashboard](#grafana-dashboard)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Prometheus Metrics](#prometheus-metrics)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [License](#license)

---

## What Is NetMind?

NetMind is a **standalone desktop application** for Linux that gives you complete visibility and control over every device connected to your local network. Whether you're a home user tired of someone hogging the bandwidth, a parent wanting to manage screen time, or a small office admin needing fair usage policies — NetMind handles it all automatically.

The core idea is simple:

- **See** every device on your network with real-time download/upload speeds
- **Know** what each device is doing (streaming, gaming, browsing, etc.)
- **Control** their bandwidth with a single click — limit, block, or free any device
- **Automate** everything with a local AI that understands your goals in plain English

Everything runs **locally on your machine** — no cloud, no subscriptions, no data leaves your network.

> ⚠️ **Legal Notice**: NetMind should only be used on networks you own or have explicit written permission to manage. Unauthorized network management is illegal in most countries.

---

## Key Features

### 🔍 Real-Time Device Discovery
- Automatically scans your network and lists every connected device
- Continuously re-scans every 30 seconds for newly connected devices
- Displays IP address, device name, and a live bandwidth meter for each device

### 📊 Live Bandwidth Monitoring
- Per-device real-time download and upload speeds (KB/s)
- Network-wide totals displayed prominently in the stats bar
- Historical data stored in Prometheus for long-term trend analysis

### 🕵️ Activity Tracking
- Identifies what each device is doing based on its network activity
- Recognizes popular services: YouTube, Netflix, Instagram, Spotify, gaming platforms, video calls, and more
- Shows status per device: Active, Idle, Limited, Blocked, or Trusted

### ⚡ Manual Bandwidth Control
- **Limit** — Set a custom speed cap for any device
- **Block** — Completely cut off a device's internet access
- **Free** — Instantly restore full-speed access
- Changes take effect immediately with no restart needed

### 🔒 Trusted Device List
- Mark any device as **Trusted** to completely exclude it from monitoring and control
- Trusted devices pass through at full speed, untouched
- One click to trust or untrust at any time

### 🤖 AI AutoPilot
- Describe your network goals once during setup (e.g., *"prioritize work laptops, limit gaming at night"*)
- The AutoPilot runs in the background and automatically applies smart policies every 30 seconds
- Makes decisions based on real-time bandwidth data and your stated priorities
- Every decision is logged with a clear explanation of why it was made

### 💬 AI Chat Assistant
- Talk to the built-in AI in plain English
- Ask questions like *"Which device is using the most bandwidth?"* or *"Block the phone for the next hour"*
- The AI can read live stats and take actions on your behalf

### 📈 Grafana Dashboard (Optional)
- Beautiful time-series graphs of per-device bandwidth over time
- Auto-provisioned — zero configuration needed
- Accessible from any browser on your network at `http://localhost:3000`

### 🖥️ Native Desktop App
- No browser required — runs as a proper desktop window
- Dark-themed, modern UI built with PyQt6
- Fully frameless custom window with smooth animations

---

## How It Works (Simple Version)

When NetMind starts monitoring, it positions itself as an **invisible intermediary** between your devices and your router. All network traffic flows through your machine, which allows NetMind to:

1. **Measure** exactly how much data each device sends and receives
2. **Identify** what services each device is communicating with
3. **Shape** the traffic for any device — speeding it up, slowing it down, or blocking it entirely

Your internet connection continues working normally for all devices. NetMind just observes and manages the flow.

The **AI engine** (Llama 3.1, running fully offline on your machine via Ollama) processes your network goals, analyzes live traffic data, and makes bandwidth management decisions automatically.

```
   Your Devices                 NetMind                    Router
  ┌──────────┐               ┌──────────┐               ┌──────────┐
  │  Phone   │──────────────►│          │──────────────►│          │
  │  Laptop  │──────────────►│ Monitors │──────────────►│ Internet │
  │  TV      │──────────────►│ Controls │──────────────►│ Gateway  │
  │  Console │──────────────►│    AI    │──────────────►│          │
  └──────────┘               └──────────┘               └──────────┘
                                   │
                              ┌────▼─────┐
                              │ Grafana  │
                              │Dashboard │
                              └──────────┘
```

---

## Screenshots & UI Overview

The NetMind interface is split into several areas:

```
┌─────────────────────────────────────────────────────────────────┐
│ 🧠 NetMind   [System●] [Monitor●] [AutoPilot●]   [▶ Start] [■ Stop] │
├────────────┬────────────┬────────────┬────────────┬────────────┤
│  Devices   │  ↓ MB/s   │  ↑ MB/s   │  Limited   │  Blocked  │
├─────────────────────────────────────────────────────────────────┤
│ 🤖 AutoPilot Status                              [Start] [Stop]│
├─────────────────────────────────────────────────────────────────┤
│ 📡 Connected Devices                              [⟳ Scan]     │
│ ┌──────────┬──────┬──────┬─────────┬──────────┬──────────┬───┐ │
│ │IP / Name │↓KB/s │↑KB/s │ Status  │ Activity │ Actions  │Trs│ │
│ ├──────────┼──────┼──────┼─────────┼──────────┼──────────┼───┤ │
│ │192.168.. │ 1240 │  80  │🟢 Active│ YouTube  │Lmt Blk Fr│Trs│ │
│ │192.168.. │  0.0 │  0.0 │⚪ Idle  │    —     │Lmt Blk Fr│Trs│ │
│ └──────────┴──────┴──────┴─────────┴──────────┴──────────┴───┘ │
├───────────────────────────┬─────────────────────────────────────┤
│ 📋 AI Decision Log        │  💬 AI Chat                         │
│                           │  ┌────────────────────────────────┐ │
│ [14:22:01] Llama 3.1      │  │ You: Who is using the most     │ │
│ detected high usage on    │  │ bandwidth?                      │ │
│ 192.168.1.45 → applying  │  │                                 │ │
│ 5 Mbps limit             │  │ AI: Device 192.168.1.45 is ...  │ │
│                           │  └────────────────────────────────┘ │
└───────────────────────────┴─────────────────────────────────────┘
```

---

## System Requirements

| Requirement | Details |
|-------------|---------|
| **Operating System** | Linux (Ubuntu 20.04+, Debian 11+, Kali, Fedora 35+, Arch) |
| **Python** | 3.10 or higher |
| **Privileges** | Must run as root / with `sudo` |
| **RAM** | 6 GB minimum (4 GB is used by the Llama 3.1 AI model) |
| **Disk Space** | ~5 GB free (AI model: ~4.9 GB) |
| **Network** | Must be connected to the same Wi-Fi or Ethernet network as the devices you want to manage |
| **Ollama** | Installed and running with the `llama3.1` model pulled |
| **Docker** | Optional — only needed for the Grafana/Prometheus dashboard |

> **WiFi vs Ethernet:** NetMind works on both. With Wi-Fi, you may see ~15–30% lower speeds compared to a direct Ethernet connection on your monitoring machine — this is normal overhead from routing traffic wirelessly.

---

## Installation

### ⚡ One Command — Full Automatic Setup

Clone the repo and run the setup script. It handles **everything**:

```bash
git clone https://github.com/Shadownikka/PFE.git
cd PFE
sudo bash setup.sh
```

**What `setup.sh` does automatically:**

| Step | What Happens |
|------|-------------|
| 1 | Detects your Linux distro (Ubuntu, Debian, Kali, Fedora, Arch, Mint…) |
| 2 | Installs all required system packages |
| 3 | Installs all Python dependencies |
| 4 | Installs Docker + Docker Compose |
| 5 | Installs Ollama (local AI runtime) |
| 6 | Downloads the Llama 3.1 AI model (~4.9 GB) |
| 7 | Fixes file permissions and git configuration |
| 8 | Runs a full health check and offers to launch the app |

> The script asks you at the end: **"Launch NetMind now? [y/N]"** — press `y` to start immediately.

---

### Manual Installation (Step by Step)

If you prefer to install manually or something failed in the auto setup:


Ollama is the local AI runtime that powers NetMind's intelligence.

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start Ollama and download the AI model (~4.9 GB):

```bash
ollama serve &
ollama pull llama3.1
```

Verify it's working:

```bash
ollama list
# Should show: llama3.1:latest
```

### Step 2 — Install Python Dependencies

```bash
cd NetMind
pip3 install -r requirements.txt
```

If you get an "externally managed environment" error (newer Ubuntu/Debian):

```bash
pip3 install --break-system-packages -r requirements.txt
# Or use a virtual environment:
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

### Step 3 — Install Docker (Optional — for Dashboard)

Only needed if you want the Grafana visual dashboard:

```bash
# Ubuntu/Debian:
sudo apt install docker.io docker-compose-plugin -y
sudo systemctl enable --now docker
```

### Step 4 — Verify Everything

```bash
# Check Python version (needs 3.10+)
python3 --version

# Check Ollama
curl http://localhost:11434/api/tags

# Check PyQt6
python3 -c "from PyQt6.QtWidgets import QApplication; print('PyQt6 OK')"
```

---

## Quick Start

```bash
# Start all services and launch the app:
sudo bash start.sh

# Or launch just the desktop app directly:
sudo python3 NetMindDesktop.py
```

To stop everything:

```bash
sudo bash stop.sh
```

---

## Using the App

### First Launch & Onboarding

The very first time you start NetMind, you'll see the **Onboarding Wizard**. This is where you tell the AI what your network management goals are.

Type a plain-English description of what you want, for example:

- *"I have 4 people at home. Prioritize my work laptop for video calls. Limit gaming consoles to 10 Mbps. Don't touch my smart TV."*
- *"Fair bandwidth sharing for everyone. No single device should use more than 40% of the total."*
- *"Limit all devices between 9pm and 7am to 5 Mbps."*

The AI will process your goals and generate a policy. You can review it before confirming. This profile is saved and used by AutoPilot going forward.

You can re-run the onboarding at any time via **⚙ Config** in the top bar.

---

### Dashboard Overview

Once you click **Initialize** → **▶ Start**, the main dashboard appears.

**Top Status Bar:**
| Pill | Color | Meaning |
|------|-------|---------|
| System ● | Green | Network engine is ready |
| Monitor ● | Green | Actively monitoring traffic |
| AutoPilot ● | Amber | AI is running and making decisions |

**Stats Row** — five at-a-glance numbers:
| Card | Shows |
|------|-------|
| Devices | Total number of discovered devices |
| ↓ MB/s | Total network download speed right now |
| ↑ MB/s | Total network upload speed right now |
| Limited | Number of devices with a speed cap applied |
| Blocked | Number of fully blocked devices |

---

### Device List

The **📡 Connected Devices** table is the heart of the app. It updates every 3 seconds and shows:

| Column | Description |
|--------|-------------|
| **IP / Name** | IP address and auto-assigned device name |
| **↓ KB/s** | Current download speed |
| **↑ KB/s** | Current upload speed |
| **Status** | 🟢 Active / ⚪ Idle / 🔴 Limited / ⛔ Blocked / 🔒 Trusted |
| **Activity** | What the device is currently doing (YouTube, Netflix, browsing, gaming…) |
| **Actions** | Limit / Block / Free buttons |
| **Trust** | Trust or Untrust this device |

Click **⟳ Scan** to immediately scan for new devices instead of waiting for the 30-second auto-scan.

---

### Manual Controls

Each device row has three action buttons:

| Button | Color | What It Does |
|--------|-------|--------------|
| **Limit** | Amber | Opens a dialog to set a custom speed cap (e.g., 2 Mbps down, 1 Mbps up) |
| **Block** | Red | Immediately cuts off the device's internet access |
| **Free** | Green | Removes any limit or block — restores full speed |

These actions are **immediate** — they take effect within seconds.

---

### Trusted Devices

Marking a device as **Trusted** tells NetMind to leave it completely alone:

- ✅ Not monitored for bandwidth
- ✅ Not subject to AutoPilot decisions
- ✅ Not limited or blocked — ever
- ✅ Passes through at full network speed

**To trust a device:** Click the **Trust** button (cyan) in the device row.  
**To untrust a device:** Click **Untrust** — monitoring resumes immediately.

**Common use case:** Mark your own laptop as trusted so NetMind never accidentally limits it.

---

### AutoPilot (AI Mode)

AutoPilot is the autonomous AI manager. Once started, it:

1. Runs a decision cycle every **30 seconds**
2. Reads live bandwidth data for all non-trusted devices
3. Compares it against your stated goals from the Onboarding profile
4. Applies limits, removes limits, or leaves devices alone as needed
5. Logs every decision with a timestamp and reasoning in the **AI Decision Log**

**To start AutoPilot:** Click **Start AP** in the AutoPilot card.  
**To stop AutoPilot:** Click **Stop AP** — all existing limits remain until you manually remove them.

The **AI Decision Log** shows recent decisions in real time, for example:

```
[16:45:03] Device 192.168.1.33 using 8,450 KB/s (above threshold).
           Applying 5,000 KB/s limit to ensure fair sharing.

[16:45:33] Device 192.168.1.33 now at 4,200 KB/s — within bounds.
           No action needed.
```

> **Note:** AutoPilot automatically starts if you have a saved onboarding profile when you click ▶ Start.

---

### AI Chat Assistant

The **💬 AI Chat** panel lets you talk directly to the AI in natural language. Type any question or command and the AI will respond — and can take real actions on your network.

**Example conversations:**

```
You:  Which device is using the most bandwidth right now?
AI:   192.168.1.45 is downloading at 9,234 KB/s — the highest on your network.

You:  Limit it to 3 Mbps.
AI:   Done. Applied a 3,000 KB/s download limit to 192.168.1.45.

You:  Show me all devices and their current speeds.
AI:   Here's a snapshot of all 6 devices on your network: [...]

You:  Free everyone.
AI:   Removed all bandwidth limits. All devices are now running at full speed.
```

The AI has access to live network data and can execute: **limit**, **block**, **free/unblock**, **get stats**, and **describe activity**.

---

### Grafana Dashboard

If you started NetMind with `sudo bash start.sh`, the Grafana dashboard is available at:

**http://localhost:3000** — Login: `admin` / `admin`

The dashboard includes:

| Panel | What It Shows |
|-------|--------------|
| Real-Time Bandwidth | Per-device download/upload graph over time |
| Active Devices | Live count of devices transferring data |
| Limited / Blocked | Count of managed devices |
| Per-Device Download | Individual speed chart per device |
| Per-Device Upload | Individual upload chart per device |
| AI Status | Whether AutoPilot is active |
| AI Inference Time | How long the AI takes to make each decision |

Dashboard auto-refreshes every **5 seconds**.

Prometheus metrics are available at: **http://localhost:9091**

---

## Project Structure

```
NetMind/
│
├── NetMindDesktop.py        ← Application entry point
├── start.sh                 ← Starts Ollama, Docker services, then launches app
├── stop.sh                  ← Stops Docker services and cleans up
├── requirements.txt         ← Python dependencies
├── README.md
│
├── core/                    ← Engine modules
│   ├── tool.py              ← Network engine: device discovery, traffic monitoring, bandwidth control
│   ├── autopilot.py         ← AI AutoPilot decision loop
│   ├── net_agent.py         ← AI network agent with function-calling support
│   ├── ai.py                ← AI utilities and Ollama integration
│   ├── onboarding.py        ← User profile manager
│   ├── voice_handler.py     ← Voice input support (experimental)
│   └── metrics_exporter.py  ← Prometheus metrics exporter
│
├── observability/           ← Monitoring stack (Docker)
│   ├── docker-compose.yml   ← Prometheus + Grafana services
│   ├── prometheus.yml       ← Prometheus configuration
│   └── grafana/
│       ├── datasources.yml  ← Auto-configures Prometheus as data source
│       ├── dashboards.yml   ← Auto-provisions dashboards
│       └── *.json           ← Pre-built dashboard definitions
│
└── packaging/               ← Build and distribution
    ├── NetMind.spec         ← PyInstaller spec for standalone binary
    ├── NetMind.iss          ← Inno Setup script (Windows installer)
    ├── Dockerfile           ← Docker image definition
    ├── Dockerfile.ai-agent  ← AI agent Docker image
    └── BUILD.md             ← Build instructions
```

---

## Configuration

### Bandwidth Thresholds

Found in `core/tool.py` under the `Config` class:

| Setting | Default | Description |
|---------|---------|-------------|
| `MONITOR_INTERVAL` | 3 seconds | How often speeds are recalculated |
| `HISTORY_LENGTH` | 20 samples | How many samples are averaged |
| `MAX_SINGLE_DEVICE_PERCENT` | 40% | Max share of total bandwidth per device before AutoPilot acts |
| `MIN_GUARANTEED_KBPS` | 256 KB/s | Minimum speed a limited device always keeps |
| `BANDWIDTH_ABUSE_THRESHOLD` | 5000 KB/s | Speed above which AutoPilot may intervene |

### AI Settings

Found in `core/net_agent.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `model` | `llama3.1` | Ollama model name |
| `temperature` | 0.2 | Lower = faster, more predictable responses |
| `num_predict` | 150 | Maximum response length in tokens |
| `num_ctx` | 2048 | Context window size |

### Ollama Host

By default NetMind connects to Ollama at `http://localhost:11434`. If Ollama runs on a different port, update the `ollama` field in `DashboardPage.__init__` in `NetMindDesktop.py`.

### AutoPilot Interval

The AutoPilot runs every 30 seconds by default. To change this, edit `core/autopilot.py` and change the `interval_seconds` parameter in the `AutoPilot` class constructor.

---

## Prometheus Metrics

When the observability stack is running, NetMind exposes these metrics at `http://localhost:9091`:

| Metric | Type | Description |
|--------|------|-------------|
| `netmind_bandwidth_download_kbps` | Gauge | Per-device download speed |
| `netmind_bandwidth_upload_kbps` | Gauge | Per-device upload speed |
| `netmind_bandwidth_total_download_mb` | Gauge | Cumulative download per device |
| `netmind_bandwidth_total_upload_mb` | Gauge | Cumulative upload per device |
| `netmind_device_status` | Gauge | 0=normal, 1=limited, 2=blocked |
| `netmind_device_limit_download_kbps` | Gauge | Currently applied download limit |
| `netmind_device_limit_upload_kbps` | Gauge | Currently applied upload limit |
| `netmind_active_devices_total` | Gauge | Number of active devices |
| `netmind_limited_devices_total` | Gauge | Number of limited devices |
| `netmind_blocked_devices_total` | Gauge | Number of blocked devices |
| `netmind_network_total_download_kbps` | Gauge | Total network download speed |
| `netmind_network_total_upload_kbps` | Gauge | Total network upload speed |
| `netmind_ai_inference_time_seconds` | Gauge | Time taken by last AI decision |
| `netmind_ai_agent_status` | Gauge | 0=off, 1=on, 2=error |

All per-device metrics include labels: `ip`, `mac`, `hostname`.

---

## Troubleshooting

### 🔴 App Doesn't Start / Import Errors

```bash
# Make sure you're running as root
sudo python3 NetMindDesktop.py

# Reinstall dependencies
pip3 install --break-system-packages -r requirements.txt
```

---

### 🔴 "Ollama not reachable" / AutoPilot Errors

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# If not running, start it
ollama serve

# Check the model is downloaded
ollama list
# Should show: llama3.1:latest

# If model is missing, pull it
ollama pull llama3.1
```

---

### 🔴 No Devices Appearing After Initialize

1. Make sure you're connected to the same Wi-Fi / Ethernet as the target devices
2. Make sure you're running with `sudo`
3. Click **⟳ Scan** to force an immediate re-scan
4. Check that your firewall isn't blocking raw network access:
   ```bash
   sudo ufw disable   # temporarily disable to test
   ```

---

### 🔴 Bandwidth Readings Show Zero

- The device may not be generating any traffic — try loading a website or YouTube on it
- Wait 5–10 seconds after starting monitoring for the first readings to appear
- Make sure IP forwarding is enabled:
  ```bash
  cat /proc/sys/net/ipv4/ip_forward
  # Must show: 1
  # If not:
  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
  ```

---

### 🔴 Devices Lost Internet When Monitoring Started

This can happen if the app closes unexpectedly. Fix:

```bash
# Emergency restore — run this to bring devices back online
sudo bash stop.sh

# Then restart the router as a last resort (clears all device caches)
```

**Prevention:** Always click **■ Stop** in the app or run `stop.sh` before closing the terminal.

---

### 🔴 Speed Is Slower Than Expected on Monitored Devices

Some overhead is expected because traffic routes through your machine. Typical impact:

| Connection Type | Expected Overhead |
|----------------|-------------------|
| Ethernet (wired machine) | 3–10% |
| Wi-Fi (same adapter) | 15–30% |
| Wi-Fi with power-save ON | 40–60% |

To minimize overhead:

```bash
# Disable Wi-Fi power-save mode (biggest improvement)
sudo iw dev wlan0 set power_save off
```

---

### 🔴 Grafana Dashboard Is Empty

1. Make sure the observability stack is running: `docker compose -f observability/docker-compose.yml ps`
2. Check that NetMind is actively monitoring (Monitor pill is green)
3. Open `http://localhost:9091/targets` — the NetMind target should show **UP**
4. In Grafana: **⚙ Settings → Data Sources → Prometheus → Test**

---

### 🔴 Port Already in Use

```bash
# Find what's using the port
sudo ss -tlnp | grep -E '3000|9091|11434'

# Change ports in observability/docker-compose.yml
# e.g. change "3000:3000" to "3001:3000" for Grafana
```

---

## FAQ

**Q: Do I need an internet connection to use NetMind?**  
A: Only for the initial setup (downloading Ollama and the AI model). Once installed, NetMind runs 100% offline. The AI runs locally on your machine.

**Q: Will devices on my network notice anything is different?**  
A: No. Their internet continues to work exactly as before. NetMind is invisible to normal users and devices.

**Q: Does NetMind interfere with HTTPS or encrypted traffic?**  
A: No. NetMind only measures how much data flows, not what the data contains. All encrypted traffic (HTTPS, VPN, etc.) passes through untouched.

**Q: Can I run NetMind on a Raspberry Pi?**  
A: The monitoring and control features work fine. However, the Llama 3.1 AI model requires ~4.9 GB of RAM, which most Raspberry Pi models don't have. You can run NetMind in manual-only mode without AutoPilot.

**Q: What happens if I close the app without clicking Stop?**  
A: Devices may temporarily lose internet until their network caches refresh (usually 1–2 minutes) or you restart your router. Always use **■ Stop** or `stop.sh`.

**Q: Can NetMind monitor devices on a different network or VLAN?**  
A: No. NetMind can only see and manage devices that are on the same local network segment as your machine.

**Q: How do I change the AI model?**  
A: Pull a different model with Ollama (`ollama pull llama3.2`), then update the model name in `core/net_agent.py`, `core/autopilot.py`, and `core/onboarding.py`.

**Q: Does NetMind work on Windows or macOS?**  
A: Currently Linux only. The network management engine relies on Linux-specific kernel features. A Windows/macOS port is on the roadmap.

**Q: Can I build a standalone executable?**  
A: Yes — use PyInstaller with the spec file in `packaging/NetMind.spec`. See `packaging/BUILD.md` for instructions.

**Q: Is my network usage data sent anywhere?**  
A: Never. All data stays on your local machine. The AI model runs entirely offline. No telemetry, no cloud.

---

## License

Copyright © 2026 NetMind. All rights reserved.

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

*Built with ❤️ using Python, PyQt6, and Llama 3.1 (Ollama). Runs entirely on your hardware.*
