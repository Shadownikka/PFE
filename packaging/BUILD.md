# NetMind — Desktop App Build Guide

## Architecture Summary

```
NetMindDesktop.py          ← PyQt6 native window (entry point)
├── BackendThread          ← Flask backend in a background thread
│   └── NetMind_Interface_archived/backend.py  ← REST API
│       ├── onboarding.py  ← LLM profile generation
│       ├── autopilot.py   ← Autonomous AI decision loop
│       ├── net_agent.py   ← Llama 3.2 tool-calling agent
│       └── tool.py        ← ARP, iptables, TC (Linux core)
└── QWebEngineView         ← Renders HTML/CSS/JS UI at localhost:9000
    ├── index.html
    ├── style.css
    └── app.js
```

---

## Step 1 — Install Build Dependencies

```bash
# Linux (build machine)
pip3 install pyinstaller PyQt6 PyQt6-WebEngine PyQt6-Qt6 flask flask-cors scapy netifaces ollama SpeechRecognition termcolor prometheus-client

# Verify PyQt6 WebEngine is available
python3 -c "from PyQt6.QtWebEngineWidgets import QWebEngineView; print('OK')"
```

---

## Step 2 — Test the Desktop App (Linux)

```bash
cd "/home/mahdi/NetMind Project/NetMind"

# Run in development mode (no packaging needed)
sudo python3 NetMindDesktop.py
```

> The app needs `sudo` because the networking backend (ARP spoofing, iptables) requires root.

---

## Step 3 — Add Your Logo

Place your logo file at:
```
/home/mahdi/NetMind Project/NetMind/logo.png    ← 256×256 PNG (used in app)
/home/mahdi/NetMind Project/NetMind/logo.ico    ← Windows icon (multi-size .ico)
```

Then uncomment the icon lines in `NetMind.spec` and `NetMind.iss`.

---

## Step 4 — Build Linux Executable

```bash
cd "/home/mahdi/NetMind Project/NetMind"
pyinstaller NetMind.spec --clean

# Output: dist/NetMind/NetMind   (run with sudo on Linux)
sudo dist/NetMind/NetMind
```

---

## Step 5 — Build Windows Executable

### Option A: Build natively on Windows
1. Install Python 3.11+ on Windows
2. Install all pip dependencies (same as Step 1)
3. Copy the project folder to Windows
4. Run `pyinstaller NetMind.spec --clean`
5. Install **Inno Setup 6** from https://jrsoftware.org/issetup.php
6. Run `iscc NetMind.iss` → produces `installer/NetMindSetup-1.0.0.exe`

### Option B: Cross-compile from Linux (via Wine)
```bash
# Install Wine + Python on Wine (complex — Option A recommended)
wine python.exe -m PyInstaller NetMind.spec
```

---

## Step 6 — Windows Prerequisites for Full Functionality

| Requirement | Purpose | Download |
|-------------|---------|----------|
| **Ollama** | Local Llama 3.2 inference | https://ollama.com/download |
| **Npcap** | Packet capture (replaces libpcap) | https://npcap.com |
| **WSL2** | Linux kernel for ARP/iptables | Windows Settings → WSL |

> **Important**: The AI/chat/onboarding features work **natively on Windows**.
> The full network management (ARP spoofing, bandwidth limiting) requires WSL2
> because it uses Linux-specific tools (iptables, tc, raw sockets).
>
> A future release will add Windows-native equivalents (WinDivert + netsh).

---

## Windows Networking — Road Map

To make full networking work natively on Windows (without WSL2), these
replacements are needed for a future `tool_windows.py`:

| Linux Tool | Windows Equivalent | Library |
|------------|-------------------|---------|
| iptables   | WFP / netsh       | pydivert |
| tc (HTB)   | netsh qos / WFP   | ctypes + WFP API |
| ARP spoof  | Scapy + Npcap     | scapy (already works) |
| ip_forward | IP routing registry| winreg |

---

## Quick Reference

```bash
# Run desktop app (development)
sudo python3 NetMindDesktop.py

# Build standalone executable
pyinstaller NetMind.spec --clean

# Run standalone
sudo dist/NetMind/NetMind

# Build Windows installer (on Windows)
pyinstaller NetMind.spec --clean
iscc NetMind.iss
```
