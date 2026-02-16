# 🚀 NetMind Web Interface - Complete Setup Guide (FROM ZERO)

This guide will walk you through **EVERYTHING** you need to do to get the NetMind web interface running from a fresh start.

---

## 📋 PREREQUISITES

### System Requirements
- **Operating System**: Linux (Kali, Ubuntu, Debian, etc.)
- **Python**: 3.8 or higher
- **Root Access**: Required (sudo privileges)
- **Internet Connection**: For downloading dependencies

---

## 🔧 STEP 1: Install Ollama (AI Engine)

Ollama is the AI engine that powers the intelligent agent.

### 1.1 Install Ollama

```bash
# Download and install Ollama
curl -fsSL https://ollama.ai/install.sh | sh
```

### 1.2 Verify Installation

```bash
# Check if Ollama is installed
ollama --version
```

You should see something like: `ollama version is 0.x.x`

### 1.3 Start Ollama Service

```bash
# Start Ollama in the background
ollama serve &
```

Or if you want it in a separate terminal:
```bash
# In a new terminal window
ollama serve
```

**Keep this terminal open!** Ollama must be running for the AI agent to work.

### 1.4 Download the AI Model

```bash
# This downloads the Llama 3.1 model (about 4-5 GB)
ollama pull llama3.1
```

This may take several minutes depending on your internet speed.

### 1.5 Verify the Model

```bash
# List installed models
ollama list
```

You should see `llama3.1` in the list.

---

## 🐍 STEP 2: Set Up Python Environment

Since you're on Kali Linux with externally-managed Python, you need a virtual environment.

### 2.1 Navigate to the Interface Folder

```bash
cd /home/mahdi/Documents/NetMind/NetMind_Interface
```

### 2.2 Create Virtual Environment

```bash
# Create a virtual environment named 'venv'
python3 -m venv venv
```

### 2.3 Activate Virtual Environment

```bash
# Activate the virtual environment
source venv/bin/activate
```

You should see `(venv)` at the beginning of your terminal prompt.

### 2.4 Install Python Dependencies

```bash
# Install all required packages
pip install -r requirements.txt
```

This will install:
- Flask (web framework)
- Flask-CORS (for cross-origin requests)
- Scapy (network packet manipulation)
- Netifaces (network interface info)
- Termcolor (colored terminal output)
- Ollama (AI model client)

---

## ✅ STEP 3: Verify Everything is Ready

### 3.1 Check Ollama is Running

```bash
# Test if Ollama is accessible
curl http://localhost:11434
```

You should see: `Ollama is running`

### 3.2 Check Virtual Environment

```bash
# Make sure you're in the venv (you should see (venv) in your prompt)
which python3
```

Should show: `/home/mahdi/Documents/NetMind/NetMind_Interface/venv/bin/python3`

### 3.3 Check Python Packages

```bash
# Verify Flask is installed
python3 -c "import flask; print('Flask version:', flask.__version__)"
```

---

## 🎯 STEP 4: Start the Backend Server

The backend MUST run with sudo because it needs root privileges for network operations.

### Option A: Using the Automated Script (RECOMMENDED)

```bash
# Make sure you're in the NetMind_Interface folder
cd /home/mahdi/Documents/NetMind/NetMind_Interface

# Run the automated start script
sudo ./start.sh
```

The script will:
1. Check if running as root ✓
2. Create virtual environment (if needed) ✓
3. Install dependencies (if needed) ✓
4. Check Ollama is running ✓
5. Start the backend server ✓

### Option B: Manual Start

```bash
# Make sure Ollama is running first!
# In one terminal:
ollama serve

# In another terminal, navigate to the folder
cd /home/mahdi/Documents/NetMind/NetMind_Interface

# Activate the virtual environment
source venv/bin/activate

# Run the backend with sudo (using venv's python)
sudo venv/bin/python3 backend.py
```

### 4.1 Verify Backend is Running

You should see output like:
```
============================================================
NetMind Web Interface - Backend Server
============================================================
Root privileges: True

 * Serving Flask app 'backend'
 * Running on http://0.0.0.0:5000
```

**Keep this terminal open!** The backend must keep running.

---

## 🌐 STEP 5: Open the Frontend Interface

You have two options:

### Option A: Direct File Open (Simple)

```bash
# Open in Firefox
firefox /home/mahdi/Documents/NetMind/NetMind_Interface/index.html

# OR open in Chrome/Chromium
google-chrome /home/mahdi/Documents/NetMind/NetMind_Interface/index.html

# OR use default browser
xdg-open /home/mahdi/Documents/NetMind/NetMind_Interface/index.html
```

### Option B: Using HTTP Server (Better for Development)

```bash
# In a NEW terminal (don't close the backend!)
cd /home/mahdi/Documents/NetMind/NetMind_Interface

# Start a simple HTTP server
python3 -m http.server 8080
```

Then open your browser and go to: **http://localhost:8080**

---

## 🎮 STEP 6: Using the Interface

### 6.1 Initialize the System

1. **Click "Initialize System"** button
2. Wait for the success message
3. Status indicators should turn **green**:
   - System (green) = Core system initialized
   - AI Agent (green) = AI is ready
   - Monitoring (grey) = Not started yet

**If AI Agent stays grey:**
- Make sure Ollama is running: `ollama serve`
- Check if model is installed: `ollama list`
- Look at backend terminal for error messages

### 6.2 Start Monitoring

1. **Click "Start Monitoring"**
2. The "Monitoring" indicator turns green
3. Devices will appear in the table below
4. Data refreshes automatically every 5 seconds

### 6.3 View Connected Devices

The table shows:
- **IP Address**: Device identifier
- **MAC Address**: Hardware address
- **Download/Upload**: Current speed in kbps
- **Total Down/Up**: Total data transferred in MB
- **Status**: Normal or Limited
- **Actions**: Quick select button

### 6.4 Chat with AI Agent

**In the AI Agent Chat box:**
- Type questions like:
  - "What devices are using the most bandwidth?"
  - "Limit bandwidth for 192.168.1.100 to 500 kbps"
  - "Which device is the heaviest user?"
  - "Analyze my network"

**Quick Analysis:**
- Click **"Analyze Network"** button
- AI analyzes all devices automatically
- Provides recommendations

### 6.5 Manual Bandwidth Control

1. Enter device IP (or click "Select" from the table)
2. Set Download limit (in kbps)
3. Set Upload limit (in kbps)
4. Click **"Apply Limit"** or **"Remove Limit"**

---

## 🔍 TROUBLESHOOTING

### Problem: "Root privileges required"

**Solution:**
```bash
# Always run backend with sudo
sudo venv/bin/python3 backend.py
# OR
sudo ./start.sh
```

---

### Problem: "AI agent not initialized" or AI Agent indicator is grey

**Cause:** Ollama is not running or model is missing

**Solution:**

1. **Check if Ollama is running:**
```bash
curl http://localhost:11434
```

If it fails:
```bash
# Start Ollama
ollama serve &
```

2. **Check if model is installed:**
```bash
ollama list
```

If `llama3.1` is missing:
```bash
ollama pull llama3.1
```

3. **Reinitialize the system:**
   - Stop monitoring if running
   - Refresh the browser page
   - Click "Initialize System" again

---

### Problem: "No network interface found"

**Solution:**
```bash
# Check your network interfaces
ip link show

# Or
ifconfig
```

Make sure you have an active network connection (WiFi or Ethernet).

---

### Problem: Frontend can't connect to backend

**Check:**
1. Backend is running on port 5000
2. No firewall blocking localhost
3. Using correct URL in browser

**Test:**
```bash
# Test if backend is accessible
curl http://localhost:5000/api/status
```

Should return JSON with system status.

---

### Problem: "externally-managed-environment" error

**This is normal on Kali Linux!**

**Solution:** Always use the virtual environment:
```bash
# Create venv
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

---

### Problem: Devices not showing up

**Solutions:**
1. Make sure monitoring is started (green indicator)
2. Wait a few seconds for network scan
3. Check if you're connected to a network
4. Look at backend terminal for errors

---

### Problem: Permission denied errors in backend

**Solution:**
```bash
# Make sure you're using sudo
sudo ./start.sh

# Or manually:
sudo venv/bin/python3 backend.py
```

---

## 📚 QUICK REFERENCE

### Start Everything (Complete Process)

```bash
# Terminal 1: Start Ollama
ollama serve

# Terminal 2: Start Backend
cd /home/mahdi/Documents/NetMind/NetMind_Interface
sudo ./start.sh

# Terminal 3 (Optional): Start HTTP Server for Frontend
cd /home/mahdi/Documents/NetMind/NetMind_Interface
python3 -m http.server 8080

# Browser: Open http://localhost:8080
```

### Stop Everything

```bash
# In backend terminal: Press Ctrl+C

# In HTTP server terminal: Press Ctrl+C

# Stop Ollama:
pkill ollama
```

---

## 🎯 FEATURES SUMMARY

✅ **Real-time Network Monitoring**
- See all connected devices
- Live bandwidth usage
- Total data transferred

✅ **AI-Powered Agent**
- Chat in natural language
- Automatic network analysis
- Intelligent recommendations
- Function calling for actions

✅ **Manual Control**
- Set bandwidth limits
- Remove limits
- Per-device control

✅ **Beautiful Interface**
- Modern design
- Real-time updates
- Status indicators
- Responsive layout

---

## 🔐 SECURITY NOTES

⚠️ **Important:**
- Requires root privileges (for ARP spoofing and traffic control)
- Only use on networks you own/control
- No authentication built-in (use only on trusted networks)
- Can disrupt network traffic if misused

---

## 📞 SUPPORT

If you encounter issues:

1. **Check backend terminal** for error messages
2. **Check browser console** (F12) for JavaScript errors
3. **Verify all prerequisites** are installed
4. **Test each component** individually (Ollama, backend, frontend)

Common check commands:
```bash
# Is Ollama running?
curl http://localhost:11434

# Is backend running?
curl http://localhost:5000/api/status

# Is model installed?
ollama list

# Is venv activated?
which python3
```

---

## 🎉 SUCCESS CHECKLIST

Before using, verify:

- ✅ Ollama is installed and running (`ollama serve`)
- ✅ Llama 3.1 model is downloaded (`ollama list`)
- ✅ Virtual environment is created (`venv/` folder exists)
- ✅ Dependencies are installed (no import errors)
- ✅ Backend is running with sudo
- ✅ Browser can reach frontend
- ✅ All three status indicators are green after initialization

---

## 🚀 READY TO GO!

Once everything is green, you can:
1. Monitor your network in real-time
2. Chat with the AI agent
3. Control bandwidth for any device
4. Get AI-powered recommendations

**Enjoy your AI-powered network management! 🌐🤖**
