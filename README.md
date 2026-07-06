<div align="center">

<img src="assets/netmind.png" width="120" alt="NetMind Logo" />

# NetMind

### AI-Powered Network Manager for Linux

**See every device. Control every connection. Let AI do the thinking.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PyQt6](https://img.shields.io/badge/UI-PyQt6-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://riverbankcomputing.com/software/pyqt/)
[![AI](https://img.shields.io/badge/AI-Llama%203.1%20%28100%25%20Local%29-FF6B35?style=for-the-badge&logo=meta&logoColor=white)](https://ollama.com)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://kernel.org)
[![Docker](https://img.shields.io/badge/Grafana-Prometheus-E6522C?style=for-the-badge&logo=grafana&logoColor=white)](https://grafana.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

[**Features**](#-features) · [**Quick Start**](#-quick-start) · [**Install as App**](#-install-as-desktop-app-no-terminal) · [**Grafana**](#-grafana-dashboard) · [**Docs**](#-using-the-app) · [**FAQ**](#-faq)

---

> **NetMind is a standalone desktop application** for Linux that gives you complete visibility and control over every device on your home or office network — powered by a local AI that runs entirely on your machine. No cloud. No subscriptions. No data leaves your network.

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%">

**🔍 Real-Time Device Discovery**
Automatically detects every connected device. Re-scans every 30 seconds for new arrivals. Shows IP, name, and live speed per device.

**📊 Live Bandwidth Monitoring**
Per-device download and upload speeds updated every 3 seconds. Network-wide totals always visible.

**🕵️ Activity Recognition**
Identifies what each device is doing: YouTube, Netflix, Spotify, gaming, video calls, browsing — automatically.

**⚡ Instant Bandwidth Control**
- **Limit** — set a custom speed cap
- **Block** — cut off internet access instantly
- **Free** — restore full speed in one click

</td>
<td width="50%">

**🤖 AI AutoPilot**
Describe your goals once in plain English. AutoPilot applies smart policies every 30 seconds and logs every decision with its reasoning.

**💬 AI Chat Assistant**
Talk to your network in natural language. *"Which device is using the most bandwidth?"* → AI answers and can take action.

**📈 Grafana Dashboard**
Beautiful real-time graphs. Auto-provisioned, zero configuration. Access from any browser on your network.

**🔒 Trusted Devices**
Mark any device as trusted — it gets excluded from monitoring and control permanently, passing at full speed.

</td>
</tr>
</table>

> ⚠️ **Legal Notice** — NetMind should only be used on networks you own or have explicit written permission to manage.

---

## ⚡ Quick Start

### Step 1 — Clone the repo

```bash
git clone https://github.com/Shadownikka/PFE.git
cd PFE
```

### Step 2 — Run setup *(the only time you use a terminal)*

```bash
sudo bash setup.sh
```

`setup.sh` is a fully automatic 9-step installer:

| Step | What happens |
|------|-------------|
| 1 | Detects your distro (Ubuntu, Debian, Kali, Fedora, Arch, Mint…) |
| 2 | Installs all system packages |
| 3 | Installs all Python dependencies (including for root) |
| 4 | Installs Docker + Docker Compose |
| 5 | Installs Ollama (local AI runtime) |
| 6 | Downloads the Llama 3.1 AI model (~4.9 GB) |
| 7 | Copies project files to `/opt/netmind/` (clean system install) |
| 8 | Installs desktop icon, app menu entry, and desktop shortcut automatically |
| 9 | Health check + optional immediate launch |

### Step 3 — Double-click to launch *(from now on, always)*

After setup, **NetMind appears on your Desktop**. Just double-click it.

> No terminal needed — ever again.

On first launch:
1. Enter your password when prompted
2. Click **Initialize** — scans your network
3. Click **▶ Start** — begins monitoring
4. Open **http://localhost:3000** for live Grafana charts

---

## 🖥️ Desktop App Launch

After running `sudo bash setup.sh`, NetMind is already installed as a desktop app. The setup handles everything — **no extra commands needed**.

When you double-click the icon, NetMind automatically:
1. Prompts for your password (once per session via GUI)
2. Starts Prometheus + Grafana containers in the background
3. Starts Ollama if not already running
4. Opens the NetMind window

---

## 🖱️ Using the App

### First Launch — Onboarding

The first time you open NetMind, the **AI Onboarding Wizard** asks you to describe your network goals in plain English:

> *"I run a coffee shop. Give customers fast WiFi. My office PC gets priority. Limit any single device to 20 Mbps."*

> *"Fair sharing at home. No one should hog the bandwidth. Gaming consoles limited to 10 Mbps after 10pm."*

The AI generates a complete bandwidth policy from your description. Review it, then confirm. This profile powers the AutoPilot from that point on.

---

### Dashboard Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 🧠 NetMind  ●System  ●Monitor  ●AutoPilot   [Init] [▶Start] [■Stop] [📊]│
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────────┤
│  6       │  24.3    │  3.1     │  2       │  1       │  47             │
│ Devices  │ ↓ MB/s   │ ↑ MB/s   │ Limited  │ Blocked  │ AI Cycles       │
├─────────────────────────────────────────────────────────────────────────┤
│ 🤖 AutoPilot  ● Running · Decisions: 47 · Interval: 30s · Last: 12s ago │
├─────────────────────────────────────────────────────────────────────────┤
│ 📡 Connected Devices                                          [⟳ Scan]  │
│ ┌────────────────┬───────┬──────┬───────────┬──────────────┬──────┬───┐ │
│ │ IP / Name      │↓ KB/s │↑KB/s │  Status   │   Activity   │Action│Trs│ │
│ ├────────────────┼───────┼──────┼───────────┼──────────────┼──────┼───┤ │
│ │ 192.168.1.45   │ 9,234 │  182 │ 🟢 Active │ YouTube 4K   │L B F │Trs│ │
│ │ Device-23      │ 2,100 │  400 │ 🔴 Limited│ Video Call   │L B F │Trs│ │
│ │ 192.168.1.12   │     0 │    0 │ ⚪ Idle   │     —        │L B F │Trs│ │
│ │ 192.168.1.67   │   340 │   55 │ 🔒 Trusted│ Browsing     │  —   │Utr│ │
│ └────────────────┴───────┴──────┴───────────┴──────────────┴──────┴───┘ │
├─────────────────────────────┬───────────────────────────────────────────┤
│ 📋 AI Decision Log          │ 💬 AI Chat Assistant                      │
│ 16:45:03 [limit_device]     │ You: Which device uses the most bandwidth?│
│ 192.168.1.45 at 9,234 KB/s  │                                           │
│ → applying 5,000 KB/s limit │ AI: 192.168.1.45 — downloading at        │
│                             │ 9,234 KB/s. Currently streaming YouTube.  │
│ 16:45:33 [no_action]        │                                           │
│ All devices within bounds   │ You: Limit it to 3 Mbps.                  │
│                             │ AI: Done. Limit applied.                  │
└─────────────────────────────┴───────────────────────────────────────────┘
```

### Status Indicators

| Pill | What it means |
|------|--------------|
| ● **System** (green) | Network engine initialized, devices discovered |
| ● **Monitor** (green) | Actively measuring traffic for all devices |
| ● **AutoPilot** (amber) | AI is running and making autonomous decisions |

### Device Actions

| Button | Effect |
|--------|--------|
| **Limit** | Set a custom speed cap (e.g. 2,048 KB/s down / 512 KB/s up) |
| **Block** | Immediately cut off all internet access |
| **Free** | Remove any limit or block — restore full speed |
| **Trust** | Exclude device from all monitoring and control forever |

---

## 📈 Grafana Dashboard

After clicking **▶ Start**, real-time metrics flow automatically to Grafana:

**→ http://localhost:3000** &nbsp; Login: `admin` / `admin`

| Panel | Shows |
|-------|-------|
| Active / Limited / Blocked | Live device counts |
| Total Network Bandwidth | Real-time download + upload combined |
| Device Download Bandwidth | Per-device speed graph over time |
| Device Upload Bandwidth | Per-device upload over time |

Dashboard auto-refreshes every **5 seconds**. Prometheus data is available at **http://localhost:9091/targets** — the `netmind` target shows **UP** while monitoring is active.

---

## 📦 Build Standalone Executable

Create a portable binary that runs without Python installed:

```bash
# Install build tool
pip3 install pyinstaller

# Build (1-3 minutes)
bash packaging/build.sh

# Test the binary
sudo dist/NetMind/NetMind
```

The output is `dist/NetMind/` — a self-contained folder you can copy anywhere.

---

## 🗂️ Project Structure

```
NetMind/
├── NetMindDesktop.py          ← PyQt6 desktop application (entry point)
├── start.sh                   ← Starts services + launches app
├── stop.sh                    ← Stops all services, restores network
├── netmind-launch.sh          ← GUI launcher (called by the .desktop file)
├── requirements.txt           ← Python dependencies
│
├── core/                      ← Network & AI engine
│   ├── tool.py                ← Device discovery, ARP spoofing, TC, iptables
│   ├── metrics_exporter.py    ← Prometheus metrics exporter (:9090)
│   ├── autopilot.py           ← AI AutoPilot decision loop
│   ├── net_agent.py           ← Llama 3.1 tool-calling agent
│   ├── onboarding.py          ← Profile manager (natural language → policy)
│   ├── ai.py                  ← AI utilities and Ollama integration
│   └── voice_handler.py       ← Voice input (experimental)
│
├── assets/
│   └── netmind.png            ← Application icon
│
├── observability/             ← Monitoring stack (Docker)
│   ├── docker-compose.yml     ← Prometheus + Grafana services
│   ├── prometheus.yml         ← Scrape config (targets NetMind on :9090)
│   └── grafana/
│       ├── datasources.yml    ← Auto-configures Prometheus datasource
│       ├── dashboards.yml     ← Auto-provisions dashboard folder
│       ├── NetMind Bandwidth Monitor.json
│       └── netmind-professional-dashboard.json
│
└── packaging/                 ← Build & distribution
    ├── install-app.sh         ← Installs as desktop app (double-click launch)
    ├── build.sh               ← Builds standalone executable via PyInstaller
    ├── NetMind.spec           ← PyInstaller configuration
    ├── NetMind.iss            ← Inno Setup script (Windows installer)
    └── BUILD.md               ← Detailed build documentation
```

---

## ⚙️ Configuration

### Bandwidth Thresholds (`core/tool.py` → `Config`)

| Setting | Default | Description |
|---------|---------|-------------|
| `MONITOR_INTERVAL` | `3s` | How often speeds are recalculated |
| `HISTORY_LENGTH` | `20` | Number of samples averaged per reading |
| `MAX_SINGLE_DEVICE_PERCENT` | `40%` | Share of total bandwidth before AutoPilot acts |
| `MIN_GUARANTEED_KBPS` | `256` | Minimum speed a limited device always keeps |
| `BANDWIDTH_ABUSE_THRESHOLD` | `5000 KB/s` | Threshold for AutoPilot to intervene |

### AI Settings (`core/net_agent.py`)

| Setting | Default | Description |
|---------|---------|-------------|
| `model` | `llama3.1` | Ollama model used for decisions |
| `temperature` | `0.2` | Lower = more predictable, faster responses |
| `num_predict` | `150` | Max response length in tokens |
| `num_ctx` | `2048` | Context window size |

### AutoPilot interval

Edit `core/autopilot.py` → `AutoPilot(interval_seconds=30)`.

### Ollama host

Default: `http://localhost:11434`. Change the `ollama` field in `DashboardPage.__init__` in `NetMindDesktop.py`.

---

## 📡 Prometheus Metrics Reference

Metrics are exposed at `http://localhost:9090/metrics` while monitoring is active (scraped by Prometheus at **http://localhost:9091**).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `netmind_bandwidth_download_kbps` | Gauge | `ip, mac, hostname` | Current download speed |
| `netmind_bandwidth_upload_kbps` | Gauge | `ip, mac, hostname` | Current upload speed |
| `netmind_bandwidth_total_download_mb` | Gauge | `ip, mac, hostname` | Cumulative download |
| `netmind_bandwidth_total_upload_mb` | Gauge | `ip, mac, hostname` | Cumulative upload |
| `netmind_device_status` | Gauge | `ip, mac, hostname` | `0`=normal, `1`=limited, `2`=blocked |
| `netmind_device_limit_download_kbps` | Gauge | `ip, mac, hostname` | Applied download cap |
| `netmind_device_limit_upload_kbps` | Gauge | `ip, mac, hostname` | Applied upload cap |
| `netmind_active_devices_total` | Gauge | — | Devices currently transferring data |
| `netmind_limited_devices_total` | Gauge | — | Devices with a speed cap |
| `netmind_blocked_devices_total` | Gauge | — | Fully blocked devices |
| `netmind_network_total_download_kbps` | Gauge | — | Total network download speed |
| `netmind_network_total_upload_kbps` | Gauge | — | Total network upload speed |
| `netmind_monitoring_uptime_seconds` | Gauge | — | Time since monitoring started |
| `netmind_ai_inference_time_seconds` | Gauge | — | Last AI decision duration |
| `netmind_ai_agent_status` | Gauge | — | `0`=off, `1`=on, `2`=error |
| `netmind_limits_applied_total` | Counter | `type` | Total limits applied |
| `netmind_limits_removed_total` | Counter | — | Total limits removed |

---

## 🔧 Troubleshooting

### App won't start / import errors

```bash
# Always run with sudo
sudo python3 NetMindDesktop.py

# Reinstall all dependencies
sudo pip3 install --break-system-packages -r requirements.txt
```

### Ollama not reachable / AI errors

```bash
curl http://localhost:11434/api/tags      # check if running
ollama serve                              # start if not running
ollama list                              # confirm llama3.1 is present
ollama pull llama3.1                     # download if missing
```

### No devices appearing after Initialize

- Confirm you're on the same Wi-Fi or Ethernet as the target devices
- Confirm you ran with `sudo`
- Click **⟳ Scan** for an immediate re-scan
- Check firewall: `sudo ufw status` (disable temporarily to test)

### Bandwidth readings show zero

- The device may be idle — open YouTube or a website on it to generate traffic
- Wait 5–10 seconds after clicking ▶ Start for the first reading
- Confirm IP forwarding is on: `cat /proc/sys/net/ipv4/ip_forward` (must be `1`)

### Grafana shows "No data"

1. Confirm monitoring is active (Monitor pill is **green**)
2. Check Prometheus target: **http://localhost:9091/targets** → should show **UP**
3. The target turns UP only after you click **▶ Start** — it's expected to show DOWN before that
4. Test the datasource: Grafana → Connections → Prometheus → **Save & test**

### Devices lost internet after app closed unexpectedly

```bash
# Emergency restore
sudo bash stop.sh
```

Always click **■ Stop** before closing the app.

### Port conflicts

```bash
sudo ss -tlnp | grep -E '3000|9090|9091|11434'
# Change ports in observability/docker-compose.yml if needed
```

### Speed overhead on monitored devices

| Connection type | Typical overhead |
|-----------------|-----------------|
| Wired Ethernet | 3–10% |
| Wi-Fi | 15–30% |
| Wi-Fi with power-save | 40–60% |

```bash
# Reduce Wi-Fi overhead
sudo iw dev wlan0 set power_save off
```

---

## 💻 System Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Linux — Ubuntu 20.04+, Debian 11+, Kali, Fedora 35+, Arch, Mint |
| **Python** | 3.10+ |
| **Privileges** | `sudo` / root required (for ARP, iptables, TC) |
| **RAM** | 6 GB minimum (Llama 3.1 uses ~4 GB) |
| **Disk** | ~5 GB free (AI model: ~4.9 GB) |
| **Network** | Same LAN as devices you want to manage |
| **Ollama** | Running locally with `llama3.1` pulled |
| **Docker** | Optional — only needed for Grafana/Prometheus dashboard |

---

## ❓ FAQ

**Q: Does my data go anywhere?**
No. Everything runs on your machine. The AI is local (Ollama). No telemetry, no cloud sync, no data leaves your network.

**Q: Will devices notice anything is different?**
No. Their internet continues normally. NetMind is invisible to regular users and devices.

**Q: Does it work with HTTPS / encrypted traffic?**
Yes — NetMind only measures data volume, never content. All encrypted traffic passes through untouched.

**Q: Can I run it on a Raspberry Pi?**
The monitoring and control features work fine. The Llama 3.1 AI model needs ~4 GB RAM — most Pi models can't run it. You can use NetMind in manual mode (no AutoPilot) on a Pi.

**Q: What happens if I close the app without clicking Stop?**
Devices may briefly lose internet for 1–2 minutes until their ARP caches expire. Always use **■ Stop** or `stop.sh`.

**Q: Can I change the AI model?**
Yes. Pull any Ollama model (`ollama pull llama3.2`), then set the model name in `core/net_agent.py`, `core/autopilot.py`, and `core/onboarding.py`.

**Q: Does NetMind work on Windows or macOS?**
Currently Linux only. The engine uses Linux-specific features (iptables, TC/HTB, raw sockets). Windows/macOS support is on the roadmap.

**Q: How do I build a standalone executable?**
Run `bash packaging/build.sh`. Requires PyInstaller (`pip3 install pyinstaller`). Output is `dist/NetMind/NetMind`.

**Q: Can NetMind monitor devices on a different VLAN or subnet?**
No. NetMind only manages devices on the same local network segment as your machine.

---

## 🔬 How It Works

When you click **▶ Start**, NetMind positions itself as an invisible intermediary using **ARP spoofing** — it tells each device that it is the router, and tells the router about each device. All traffic flows through your machine, which gives NetMind:

- **Full visibility** — exact bytes in/out per device
- **Full control** — TC/HTB kernel shaping, iptables rules per IP
- **No interception** — encrypted data is passed through intact

The **Prometheus metrics exporter** starts on port `:9090` and the Docker-based Prometheus container scrapes it every 5 seconds. Grafana queries Prometheus and renders live dashboards.

```
Your Devices ──────► NetMind (ARP man-in-middle) ──────► Router ──────► Internet
                          │
                          ├── TrafficMonitor  (iptables byte counters)
                          ├── BandwidthController  (TC/HTB shaping)
                          ├── ConnectionTracker  (DNS/port activity)
                          ├── MetricsExporter  → Prometheus → Grafana
                          └── AutoPilot  (Llama 3.1 via Ollama)
```

---

## 📄 License

Copyright © 2026 NetMind. All rights reserved.

Licensed under the [MIT License](LICENSE).

---

<div align="center">

Built with ❤️ using **Python**, **PyQt6**, **Llama 3.1**, **Prometheus**, and **Grafana**

*Runs 100% on your hardware. No cloud required.*

</div>
