# NetMind Web Interface

A modern web interface for NetMind AI Network Manager with real-time monitoring and AI-powered bandwidth management.

## 🌟 Features

- **Real-time Network Monitoring**: Track all connected devices and their bandwidth usage
- **AI Agent Chat**: Interact with the AI agent using natural language
- **Manual Bandwidth Control**: Set limits for specific devices
- **Automatic Analysis**: Let the AI analyze and optimize your network
- **Beautiful UI**: Modern, responsive design with real-time updates

## 📋 Prerequisites

- **Linux System** (tested on Ubuntu/Debian)
- **Python 3.8+**
- **Root/sudo privileges** (required for network operations)
- **Ollama** with Llama 3.1 model (for AI features)

## 🚀 Quick Start

### 1. Install Ollama (if not already installed)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.1
```

### 2. Install Python Dependencies

```bash
cd NetMind_Interface
pip install -r requirements.txt
```

### 3. Start the Backend Server

**Important: Must run with sudo for network operations**

```bash
sudo python3 backend.py
```

The backend will start on `http://localhost:5000`

### 4. Open the Frontend

Open `index.html` in your web browser:

```bash
# Option 1: Direct file open
firefox index.html

# Option 2: Using Python's HTTP server
python3 -m http.server 8080
# Then visit http://localhost:8080
```

## 📖 Usage Guide

### Initialize the System

1. Click **"Initialize System"** button
2. Wait for the system to detect your network interface and gateway
3. System status indicators will turn green when ready

### Start Monitoring

1. Click **"Start Monitoring"** to begin tracking devices
2. Devices will appear in the table below with real-time stats
3. Data refreshes automatically every 5 seconds

### Using the AI Agent

**Chat with the Agent:**
- Type questions like "What devices are using the most bandwidth?"
- Ask it to "Limit bandwidth for 192.168.1.100"
- Request "Analyze my network and optimize it"

**Quick Analysis:**
- Click **"Analyze Network"** for instant AI recommendations
- The agent will analyze all devices and suggest actions

### Manual Bandwidth Control

1. Select a device from the table (or enter IP manually)
2. Set download and upload limits in kbps
3. Click **"Apply Limit"** or **"Remove Limit"**

## 🎯 API Endpoints

The backend provides the following REST API:

- `GET /api/status` - Get system status
- `POST /api/initialize` - Initialize the system
- `POST /api/start-monitoring` - Start monitoring
- `POST /api/stop-monitoring` - Stop monitoring
- `GET /api/devices` - Get all devices with stats
- `POST /api/agent/chat` - Chat with AI agent
- `POST /api/agent/analyze` - Request network analysis
- `POST /api/bandwidth/limit` - Apply bandwidth limit
- `POST /api/bandwidth/remove` - Remove bandwidth limit
- `GET /api/config` - Get configuration
- `POST /api/config` - Update configuration

## 🔧 Troubleshooting

### "Root privileges required"
- The backend must be run with `sudo python3 backend.py`
- Network operations require root access

### "No network interface found"
- Check your network connection
- Try specifying the interface manually in the code

### "AI agent not initialized"
- Make sure Ollama is running: `systemctl status ollama`
- Verify Llama 3.1 is installed: `ollama list`
- Check Ollama is accessible: `curl http://localhost:11434`

### Frontend can't connect to backend
- Ensure backend is running on port 5000
- Check firewall settings
- Verify CORS is enabled in backend

## 🔒 Security Notes

- This tool requires root privileges for ARP spoofing and traffic control
- Only use on networks you own or have permission to manage
- The web interface has no authentication - use only on trusted networks
- Consider adding authentication for production use

## 📁 Project Structure

```
NetMind_Interface/
├── backend.py          # Flask REST API server
├── index.html          # Web interface frontend
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## 🤝 Integration

This interface integrates with:
- `../tool.py` - Core network monitoring and control
- `../net_agent.py` - AI agent with Ollama
- `../ai.py` - Intelligent bandwidth controller

## 📝 License

Part of the NetMind project. See main project documentation for license information.

## 🆘 Support

For issues or questions:
1. Check the main NetMind documentation
2. Verify all prerequisites are installed
3. Check the console for error messages
4. Ensure you're running with sudo privileges
