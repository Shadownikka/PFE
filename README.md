# NetMind — AI-Powered Network Bandwidth Monitor & Controller

> **Real-time MITM bandwidth monitoring with Llama 3.2 AI agent, Grafana dashboards, and intelligent per-device bandwidth management — all running inside Docker.**

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![AI](https://img.shields.io/badge/AI-Llama%203.2-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Table of Contents

- [What Is NetMind?](#what-is-netmind)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Grafana Dashboard](#grafana-dashboard)
- [Web Interface (Optional)](#web-interface-optional)
- [Docker Management](#docker-management)
- [Configuration](#configuration)
- [Prometheus Metrics](#prometheus-metrics)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [FAQ](#faq)
- [License](#license)

---

## What Is NetMind?

NetMind is a **network monitoring and bandwidth control tool** that runs on your Linux machine (laptop/desktop/server) and lets you:

- **See every device** on your local network and their real-time bandwidth usage
- **Limit or block** any device's internet speed with one command
- **Use AI** (Llama 3.2 running locally) to automatically manage bandwidth or respond to natural language commands like *"limit the device that uses the most bandwidth"*
- **Visualise everything** on a live Grafana dashboard with per-device graphs
- **Track what devices are doing** — DNS-based activity detection (YouTube, Netflix, Instagram, etc.)

It works by performing a **Man-in-the-Middle (MITM)** attack via ARP spoofing on your own network, routing all traffic through your machine so it can measure and control it.

> ⚠️ **Legal Notice**: Only use NetMind on networks you own or have explicit permission to monitor. Unauthorised network interception is illegal.

---

## How It Works

```
  ┌──────────────┐        ARP Spoof         ┌──────────────┐
  │  Phone / PC  │ ◄─────────────────────►   │  Your Machine│
  │  (target)    │   "I'm the router"        │  (NetMind)   │
  └──────┬───────┘                           └──────┬───────┘
         │                                          │
         │  All traffic flows through NetMind        │
         │  (measured, optionally shaped)             │
         │                                          │
  ┌──────▼───────┐                           ┌──────▼───────┐
  │              │                           │              │
  │   Internet   │ ◄─────────────────────►   │    Router    │
  │              │                           │   (gateway)  │
  └──────────────┘                           └──────────────┘
```

1. **ARP Spoofing** — NetMind tells every target device *"I'm the router"* and tells the router *"I'm every device"*. All traffic now flows through your machine.
2. **IP Forwarding** — The Linux kernel forwards packets between devices and the real router so internet keeps working normally.
3. **iptables Counting** — Per-device byte counters in the kernel's FORWARD chain measure upload/download with zero CPU overhead (no packet copying to userspace).
4. **Traffic Control (TC)** — Linux TC with HTB qdiscs shapes per-device bandwidth when you apply limits.
5. **DNS Tracking** — A lightweight `tcpdump` captures only DNS queries to identify what services each device is using.
6. **AI Agent** — Ollama runs Llama 3.2 locally. It receives network stats and can call functions (limit, block, unblock) via tool-calling.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Docker Host                       │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  netmind-core  (host network, privileged)      │  │
│  │  • NetMind.py — main TUI application           │  │
│  │  • ai.py — AI controller & display loop        │  │
│  │  • tool.py — ARP spoof, TC, iptables, DNS      │  │
│  │  • metrics_exporter.py — Prometheus on :9090    │  │
│  └──────────────────┬─────────────────────────────┘  │
│                     │ HTTP (localhost:11435)          │
│  ┌──────────────────▼─────────────────────────────┐  │
│  │  ai-agent  (Ollama + Llama 3.2)                │  │
│  │  • Port 11435 → internal 11434                 │  │
│  │  • ~4 GB RAM for model inference               │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  prometheus  (port 9091)                       │  │
│  │  • Scrapes netmind-core:9090 every 3s          │  │
│  │  • Time-series storage for Grafana             │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  grafana  (port 3000)                          │  │
│  │  • Auto-provisioned dashboards                 │  │
│  │  • Login: admin / admin                        │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

| Container | Network Mode | Port(s) | Purpose |
|-----------|-------------|---------|---------|
| `netmind-core` | host | 9090 (metrics) | Core app — ARP spoofing, monitoring, bandwidth control |
| `ai-agent` | bridge | 11435→11434 | Ollama + Llama 3.2 AI inference |
| `prometheus` | bridge | 9091→9090 | Metrics collection & storage |
| `grafana` | bridge | 3000→3000 | Dashboard visualisation |

---

## Prerequisites

| Requirement | Why |
|-------------|-----|
| **Linux** (Kali, Ubuntu, Debian, Arch, Fedora) | Needs iptables, TC, raw sockets |
| **Root / sudo** | ARP spoofing and iptables require root |
| **~6 GB free disk** | Docker images (~1 GB) + Llama 3.2 model (~2 GB) + overhead |
| **~6 GB RAM** | Llama 3.2 uses ~4 GB; the rest for containers |
| **Same LAN as targets** | ARP spoofing only works on the local network segment |

> **Works on both WiFi and Ethernet.** WiFi has slightly higher overhead due to the radio layer (see [Known Limitations](#known-limitations)).

---

## Installation

### One-Command Install

```bash
git clone https://github.com/YOUR_USERNAME/NetMind.git
cd NetMind
sudo python3 Setup.py
```

The setup script **automatically**:

1. ✅ Detects your Linux distribution (Kali/Ubuntu/Debian/Arch/Fedora)
2. ✅ Installs system packages (iptables, tcpdump, iproute2, build tools, etc.)
3. ✅ Installs Docker & Docker Compose (if not present)
4. ✅ Installs Python dependencies (scapy, netifaces, prometheus-client, etc.)
5. ✅ Configures Grafana datasource and Prometheus scraping
6. ✅ Tunes the kernel for optimal forwarding (rp_filter, backlog, WiFi power-save)
7. ✅ Builds all 4 Docker images
8. ✅ Starts all services
9. ✅ Downloads the Llama 3.2 AI model (~2 GB)
10. ✅ Verifies everything is running

### Verify Existing Setup

```bash
sudo python3 Setup.py --check
```

---

## Quick Start

After `Setup.py` finishes:

```bash
# 1. Enter the NetMind container
sudo docker exec -it netmind-core python3 NetMind.py

# 2. Choose a mode:
#    [1] 🤖 Automatic AI Mode — AI manages bandwidth for all devices
#    [2] 🎮 Manual + AI Mode  — You control, with AI assist on demand

# 3. Open Grafana in your browser
#    http://localhost:3000   (admin / admin)
```

That's it — you'll see a live table of every device on your network with real-time upload/download speeds.

---

## Usage Guide

### Mode Selection

After scanning the network, you pick a mode:

| Mode | Description |
|------|-------------|
| **[1] Automatic AI** | AI monitors all devices and auto-limits bandwidth hogs (> 5000 KB/s). You can still override via the menu. |
| **[2] Manual + AI** | You have full control. AI only acts when you invoke it via the agent chat. Press `m` to open the menu. |
| **[3] Rescan** | Re-scan the network to discover new devices |
| **[4] Cancel** | Exit |

### Menu Commands (press `m` during monitoring)

| Key | Action |
|-----|--------|
| `l` | **Limit** — Set download/upload speed for one or more devices |
| `b` | **Block** — Completely block a device's internet (sets 1 KB/s limit) |
| `r` | **Remove limit** — Restore a limited/blocked device to full speed |
| `x` | **Restore all** — Remove ALL limits and blocks at once |
| `u` | **Unblock** — Same as remove limit |
| `v` | **View activity** — See what domains/services a device is visiting |
| `g` | **Go Agentic** — Open AI chat. Talk in natural language: *"who is using the most bandwidth?"* |
| `a` | **Toggle AI auto-balance** — Turn automatic bandwidth management on/off |
| `s` | **Detailed stats** — Show 30s/60s averages for every device |
| `c` | **Continue** — Return to the live monitoring display |
| `m` | **Main menu** — Go back to mode selection (stops monitoring) |
| `q` | **Quit** — Cleanly stops everything and restores ARP tables |

### Multi-Device Selection

When limiting or blocking, you can select multiple devices:
- Single: `2`
- Multiple: `1,3,5`
- All: `all`

### AI Agent Chat (Agentic Mode)

Press `g` from the menu to chat with the AI. Examples:

```
💬 You: Who is using the most bandwidth?
🤖 NetMind: Device 192.168.1.45 is downloading at 8,234 KB/s...

💬 You: Limit it to 2 Mbps
🤖 NetMind: Applied limit to 192.168.1.45: ↓256KB/s ↑128KB/s

💬 You: Show me all stats
🤖 NetMind: [calls get_network_stats and displays results]
```

Type `back`, `exit`, or `q` to return to the menu.

---

## Grafana Dashboard

Open **http://localhost:3000** (login: `admin` / `admin`).

The pre-provisioned dashboard includes:

| Panel | Description |
|-------|-------------|
| AI Performance Gauge | Shows AI inference time (red ≥ 30s) |
| Real-Time Bandwidth Graph | Per-device download/upload over time |
| Active Devices | Count of devices currently transferring data |
| Limited Devices | Count of devices with bandwidth limits |
| Blocked Devices | Count of fully blocked devices |
| Per-Device Download | Individual download speed per device |
| Per-Device Upload | Individual upload speed per device |
| Device Status Table | IP, MAC, hostname, status, speeds |
| AI Actions Rate | How often the AI makes decisions |
| AI Status | Whether the AI agent is active |

Dashboard auto-refreshes every **5 seconds**.

---

## Web Interface (Optional)

A Flask-based web interface is available in `NetMind_Interface/`:

```bash
# From inside the container or host:
cd NetMind_Interface
sudo python3 backend.py
```

Then open `http://localhost:5000` in your browser. Features:
- Initialize, start/stop monitoring
- View devices and stats
- Chat with the AI agent
- Apply/remove bandwidth limits

> The web interface is **separate** from the Docker TUI workflow. Use either one, not both simultaneously.

---

## Docker Management

```bash
# View all container logs
sudo docker compose logs -f

# View one container's logs
sudo docker compose logs -f netmind-core

# Restart all services
sudo docker compose restart

# Stop all services (removes containers, keeps volumes)
sudo docker compose down

# Stop and remove everything (including data)
sudo docker compose down -v

# Rebuild after code changes
sudo docker compose up --build -d

# Check container status
sudo docker compose ps

# Enter the NetMind container for debugging
sudo docker exec -it netmind-core bash

# Check if Llama model is downloaded
sudo docker exec netmind-ai-agent ollama list
```

---

## Configuration

### Bandwidth Thresholds (`tool.py` → `Config` class)

| Setting | Default | Description |
|---------|---------|-------------|
| `MONITOR_INTERVAL` | 3s | How often stats are refreshed |
| `HISTORY_LENGTH` | 20 | Number of samples kept for averaging |
| `MAX_SINGLE_DEVICE_PERCENT` | 40% | Max share of total bandwidth per device |
| `MIN_GUARANTEED_KBPS` | 256 | Minimum guaranteed speed when limiting |
| `BANDWIDTH_ABUSE_THRESHOLD` | 5000 KB/s | Auto-limit kicks in above this |

### AI Performance (`net_agent.py`)

| Setting | Default | Description |
|---------|---------|-------------|
| `temperature` | 0.2 | Lower = faster, more deterministic responses |
| `num_predict` | 150 | Max response tokens |
| `top_k` | 5 | Sampling pool size |
| `num_ctx` | 2048 | Context window |

### Prometheus (`prometheus.yml`)

```yaml
scrape_interval: 3s  # How often Prometheus pulls metrics
```

### Grafana

- **Dashboard refresh**: 5 seconds (adjustable in Grafana UI)
- **Default login**: `admin` / `admin` (change on first login)
- **Dashboards** are auto-provisioned from `grafana/*.json`

---

## Prometheus Metrics

NetMind exposes these metrics at `http://localhost:9090/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `netmind_bandwidth_download_kbps` | Gauge | Per-device download speed |
| `netmind_bandwidth_upload_kbps` | Gauge | Per-device upload speed |
| `netmind_bandwidth_total_download_mb` | Gauge | Cumulative download per device |
| `netmind_bandwidth_total_upload_mb` | Gauge | Cumulative upload per device |
| `netmind_device_status` | Gauge | 0=normal, 1=limited, 2=blocked |
| `netmind_device_limit_download_kbps` | Gauge | Applied download limit |
| `netmind_device_limit_upload_kbps` | Gauge | Applied upload limit |
| `netmind_active_devices_total` | Gauge | Number of devices with traffic |
| `netmind_limited_devices_total` | Gauge | Number of limited devices |
| `netmind_blocked_devices_total` | Gauge | Number of blocked devices |
| `netmind_network_total_download_kbps` | Gauge | Total network download |
| `netmind_network_total_upload_kbps` | Gauge | Total network upload |
| `netmind_ai_inference_time_seconds` | Gauge | Last AI response time |
| `netmind_ai_agent_status` | Gauge | 0=off, 1=on, 2=error |
| `netmind_limits_applied_total` | Counter | Cumulative limits applied |
| `netmind_limits_removed_total` | Counter | Cumulative limits removed |

All per-device metrics have labels: `ip`, `mac`, `hostname`.

---

## Project Structure

```
NetMind/
├── NetMind.py                  # Main entry point — TUI menu
├── ai.py                       # AI controller, display loop, menu system
├── tool.py                     # Core: ARP spoof, traffic monitor, TC, DNS tracker
├── net_agent.py                # Llama 3.2 AI agent with function calling
├── metrics_exporter.py         # Prometheus metrics exporter (port 9090)
├── Setup.py                    # Automated installer (this file)
├── test_agent.py               # Quick test for Ollama connectivity
│
├── Dockerfile                  # netmind-core image (Python 3.11 + network tools)
├── Dockerfile.ai-agent         # ai-agent image (Ollama + Llama 3.2)
├── docker-compose.yml          # All 4 services definition
├── prometheus.yml              # Prometheus scrape config
│
├── requirements.txt            # Python deps for core app
├── requirements-agent.txt      # Python deps for AI agent
│
├── grafana/
│   ├── datasources.yml         # Prometheus datasource for Grafana
│   ├── dashboards.yml          # Dashboard provisioning config
│   ├── NetMind Bandwidth Monitor.json
│   └── netmind-professional-dashboard.json
│
├── NetMind_Interface/          # Optional Flask web interface
│   ├── backend.py              # REST API server
│   ├── index.html              # Web frontend
│   ├── requirements.txt        # Flask dependencies
│   ├── README.md
│   ├── COMPLETE_SETUP_GUIDE.md
│   ├── launch_interface.sh
│   ├── setup_and_run.sh
│   └── start.sh
│
├── verify_deployment.sh        # Deployment verification script
├── TECHNICAL.md                # Deep technical documentation
└── README.md                   # This file
```

---

## Troubleshooting

### 🔴 Setup Problems

#### "Docker not found" after install
```bash
# Restart your shell to pick up the new PATH
exec bash
# Or source the profile
source ~/.bashrc
docker --version
```

#### "Permission denied" when running Docker
```bash
# Either use sudo:
sudo docker compose up -d
# Or add your user to the docker group (re-login needed):
sudo usermod -aG docker $USER
```

#### Docker Compose not found
```bash
# Try the plugin syntax:
docker compose version
# If that fails, install standalone:
sudo pip3 install docker-compose
```

#### Setup.py fails on "pip install"
```bash
# On newer Python (externally managed), use:
pip3 install --break-system-packages -r requirements.txt
# Or create a venv:
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

---

### 🔴 No Metrics in Grafana

**Step 1** — Is NetMind monitoring running?
```bash
sudo docker exec netmind-core ps aux | grep python
# Should show: python3 NetMind.py
```

**Step 2** — Are metrics being exported?
```bash
curl http://localhost:9090/metrics | grep netmind_
# Should return lines like: netmind_bandwidth_download_kbps{...} 123.45
```

**Step 3** — Is Prometheus scraping?
```bash
# Open http://localhost:9091/targets in your browser
# The "netmind" target should show state "UP"
```

**Step 4** — Is Grafana's datasource working?
```
Grafana UI → ⚙️ Configuration → Data Sources → Prometheus → "Test"
# Should say "Data source is working"
```

---

### 🔴 No Bandwidth Readings (all zeros)

**Cause 1: Target devices aren't generating traffic**
- Open YouTube / download a file on the target device
- Wait 10-15 seconds for counters to accumulate

**Cause 2: ARP spoofing not working**
```bash
# Inside the container:
iptables -L FORWARD -v -n -x | head -20
# You should see non-zero byte counters per device IP
```

**Cause 3: iptables rules being flushed by another process**
- Check if another firewall manager (ufw, firewalld) is running:
```bash
sudo systemctl status ufw firewalld 2>/dev/null
# If active, stop them:
sudo systemctl stop ufw
```

**Cause 4: rp_filter dropping spoofed packets**
```bash
cat /proc/sys/net/ipv4/conf/all/rp_filter
# Should be 0. If not:
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
```

---

### 🔴 AI Agent Not Responding

```bash
# Check if the model is downloaded:
sudo docker exec netmind-ai-agent ollama list
# Should show "llama3.2"

# If not, pull it manually:
sudo docker exec netmind-ai-agent ollama pull llama3.2

# Check if Ollama is reachable:
curl http://localhost:11435/api/tags
# Should return JSON with model info

# Check AI container logs:
sudo docker logs netmind-ai-agent
```

---

### 🔴 Devices Lose Internet When NetMind Runs

**This is the most common issue.** It happens when IP forwarding is not enabled or ARP tables aren't restored.

**While running:**
```bash
# Verify IP forwarding is on:
cat /proc/sys/net/ipv4/ip_forward
# Must be 1

# Verify FORWARD chain allows traffic:
iptables -L FORWARD -n | head -5
# Should show ACCEPT rules
```

**After quitting:**
- **Always** quit with `q` from the menu or `Ctrl+C` → menu → `q`
- **Never** just close the terminal or kill the container

**Emergency fix** (if devices lost internet):
```bash
# Re-enable forwarding:
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD ACCEPT
iptables -F FORWARD
iptables -A FORWARD -j ACCEPT

# Or simply restart the router (clears ARP cache on all devices)
```

---

### 🔴 Speed Drops Significantly When NetMind Runs

Some overhead is expected because all traffic routes through your machine. Typical numbers:

| Setup | Expected Overhead |
|-------|------------------|
| Ethernet (wired) | ~5-10% |
| WiFi (same adapter) | ~15-30% |
| WiFi with power-save ON | ~50-70% |

**To minimise overhead:**

1. **Disable WiFi power-save** (biggest win):
   ```bash
   sudo iw dev wlan0 set power_save off
   ```

2. **Run Setup.py** — it applies kernel tuning automatically

3. **Use Ethernet** if possible — much less overhead than WiFi

4. **Don't run the web interface and TUI simultaneously** — use one or the other

---

### 🔴 Port Conflicts

```bash
# Check what's using a port:
sudo ss -tlnp | grep -E '3000|9090|9091|11435'

# Kill the conflicting process or change NetMind's ports in docker-compose.yml:
# e.g., change "3000:3000" to "3001:3000"
```

---

### 🔴 "Container is unhealthy" / Keeps Restarting

```bash
# Check which container is failing:
sudo docker compose ps

# Read its logs:
sudo docker compose logs <container-name>

# Common fixes:
sudo docker compose down
sudo docker compose up --build -d
```

---

### 🔴 New Devices Not Appearing

NetMind auto-scans for new devices every 30 seconds. If a device doesn't appear:

1. Make sure the device is on the **same LAN subnet**
2. The device must respond to ARP requests (most do)
3. You can force a rescan: go to menu → `m` → `[3] Rescan`

---

## Known Limitations

| Limitation | Explanation |
|------------|-------------|
| **WiFi overhead** | Packets traverse the radio twice (device→you→router), adding inherent latency. This is physics, not software. |
| **Same subnet only** | ARP spoofing only works within a single L2 broadcast domain. Cannot monitor devices on other VLANs/subnets. |
| **DNS-only activity tracking** | NetMind identifies services via DNS queries. If a device uses DoH (DNS over HTTPS) or hardcoded IPs, activity tracking won't work. |
| **Single machine** | NetMind must run on a single machine on the target network. Running multiple instances will cause ARP conflicts. |
| **AI model size** | Llama 3.2 requires ~4 GB RAM. Machines with less than 6 GB total RAM may struggle. |
| **No IPv6** | Currently only monitors IPv4 traffic. |
| **Privileged container** | `netmind-core` runs in privileged mode (required for raw sockets, iptables, TC). |

---

## FAQ

**Q: Does this work on Windows / macOS?**
A: No. It requires Linux-specific tools (iptables, TC, raw sockets). You could run it in a Linux VM with bridged networking.

**Q: Can targets detect they're being MITM'd?**
A: Sophisticated users might notice duplicate MAC entries in their ARP table, or use ARP detection tools. Normal users won't notice.

**Q: Does it break HTTPS?**
A: No. NetMind only monitors *bandwidth* (byte counts) and *DNS queries*. It does not decrypt or modify HTTPS traffic. All encrypted content passes through untouched.

**Q: Can I run it on a Raspberry Pi?**
A: The monitoring works, but the AI model (Llama 3.2) needs ~4 GB RAM which most Pis don't have. You can disable AI mode and use manual mode only.

**Q: What if I just close the terminal without quitting properly?**
A: Target devices may lose internet because their ARP tables still point to your machine. Fix: restart your router, or run NetMind again and quit properly with `q`.

**Q: Can I monitor devices on a different network/VLAN?**
A: No, ARP spoofing only works within the same L2 broadcast domain.

**Q: How do I change the AI model?**
A: Edit `net_agent.py` and change `self.model = 'llama3.2'` to another model. Then pull it: `docker exec netmind-ai-agent ollama pull <model_name>`.

**Q: Port 9090/3000/9091/11435 is already in use.**
A: Edit `docker-compose.yml` and change the left side of the port mapping (e.g., `"3001:3000"`).

---

## License

Copyright © 2026 NetMind. All rights reserved.

---

For deep technical details, see [TECHNICAL.md](TECHNICAL.md)
