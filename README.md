# 🤖 NetMind AI - Intelligent Network Management System

A full-stack AI-powered network monitoring and bandwidth management system with a modern web interface.

---

## 🌟 Features

### 🎯 Core Capabilities
- **Real-time Network Monitoring** - Track all devices and bandwidth usage
- **AI-Powered Control** - Natural language commands via Ollama LLM
- **Bandwidth Management** - Intelligent traffic shaping and limiting
- **Device Detection** - Automatic network scanning and device identification
- **Live Dashboard** - Beautiful, real-time updating interface
- **Conversational AI** - Chat with your network like it's a personal assistant

### 💬 Example AI Commands
- "Show me all devices on the network"
- "Which device is using the most bandwidth?"
- "Limit the device at 192.168.1.100 to 10 Mbps"
- "Remove all bandwidth limits"
- "Is anyone streaming video right now?"
- "Prioritize my work computer"

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User's Browser                       │
│              http://localhost:3000                      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       │ REST API
                       │
┌──────────────────────▼──────────────────────────────────┐
│              Flask Backend Server                       │
│              http://localhost:5000                      │
│  ┌─────────────────────────────────────────────────┐   │
│  │  NetMind AI Agent (Ollama Integration)          │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Network Monitor (Scapy)                        │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Bandwidth Controller (tc/iptables)             │   │
│  └─────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────┘
                       │
                       │ HTTP API
                       │
┌──────────────────────▼──────────────────────────────────┐
│                  Ollama Server                          │
│              http://localhost:11434                     │
│                 (llama3.2:3b)                           │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Tech Stack

### Frontend
- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Styling
- **Framer Motion** - Smooth animations
- **Lucide React** - Beautiful icons

### Backend
- **Python 3.8+** - Core language
- **Flask** - Web server
- **Scapy** - Network monitoring
- **Ollama** - LLM integration (llama3.2:3b)

---

## 🚀 Quick Start

### Prerequisites

1. **Node.js 18+** - [Download](https://nodejs.org/)
2. **Python 3.8+** - [Download](https://python.org/)
3. **Ollama** - [Install](https://ollama.com/download)
4. **Root/Sudo access** - Required for network monitoring

### Installation

**Option 1: Automated (Recommended)**

```bash
# Make the script executable
chmod +x start-netmind.sh

# Run with sudo
sudo ./start-netmind.sh
```

This will automatically:
- ✅ Check and start Ollama
- ✅ Install Python dependencies
- ✅ Start the backend server
- ✅ Start the frontend dev server
- ✅ Show you all running services

**Option 2: Manual**

See `INTEGRATION_GUIDE.md` for detailed step-by-step instructions.

---

## 📁 Project Structure

```
netmind-ai/
├── backend/
│   ├── netmind_backend.py      # Flask API server
│   ├── ai.py                    # Core NetMind AI
│   ├── tool.py                  # Network tools
│   ├── net_agent.py             # Ollama AI agent
│   └── netmind_ai_interface.html
│
├── frontend/
│   └── my-netmind/              # Next.js app
│       ├── app/
│       │   ├── page.tsx         # Main dashboard
│       │   ├── layout.tsx
│       │   └── globals.css
│       ├── package.json
│       └── tailwind.config.ts
│
├── start-netmind.sh             # Quick start script
├── INTEGRATION_GUIDE.md         # Detailed setup guide
└── README.md                    # This file
```

---

## 🎮 Usage

### Starting the System

```bash
# Easy way
sudo ./start-netmind.sh

# Manual way
# Terminal 1: Start Ollama
ollama serve

# Terminal 2: Start Backend
cd backend
sudo python3 netmind_backend.py

# Terminal 3: Start Frontend
cd frontend/my-netmind
npm run dev
```

### Access Points

- **Dashboard**: http://localhost:3000
- **API**: http://localhost:5000/api/status
- **Ollama**: http://localhost:11434

### Using the AI

1. Open http://localhost:3000
2. Wait for "AI Active" status (top-right)
3. Type commands in the chat interface
4. Watch real-time stats update

**Example Conversation:**

```
You: Show me network usage

AI: I found 5 devices on your network:
    - 192.168.1.100 (Your Computer): 15.2 Mbps
    - 192.168.1.105 (Phone): 42.8 Mbps - High usage detected!
    - 192.168.1.110 (Smart TV): 8.1 Mbps
    - 192.168.1.115 (Tablet): 2.3 Mbps
    - 192.168.1.120 (IoT Device): 0.5 Mbps

You: Limit the phone to 20 Mbps

AI: Applied 20 Mbps bandwidth limit to device at 192.168.1.105.
    This will prevent it from consuming too much bandwidth.
    
You: Remove all limits

AI: Removed all bandwidth limitations. All devices now have unrestricted access.
```

---

## 🔧 Configuration

### Backend Configuration

Edit `backend/ai.py` to configure:

```python
# Network interface
INTERFACE = "eth0"  # or "wlan0" for WiFi

# Bandwidth thresholds
BANDWIDTH_ABUSE_THRESHOLD = 50  # MB/s
MAX_SINGLE_DEVICE_PERCENT = 60  # % of total bandwidth

# Auto-limit mode
AUTO_LIMIT_ENABLED = True
```

### Frontend Configuration

Edit `frontend/my-netmind/app/page.tsx`:

```typescript
// API endpoint
const API_BASE_URL = 'http://localhost:5000/api';

// Refresh interval (milliseconds)
const REFRESH_INTERVAL = 3000;  // 3 seconds
```

---

## 📊 API Reference

### GET /api/status

Returns current system status.

**Response:**
```json
{
  "total_bandwidth": 125.4,
  "devices": [...],
  "active_devices": 5,
  "optimizations": 2,
  "ai_active": true,
  "agent_ready": true
}
```

### POST /api/chat

Send message to AI agent.

**Request:**
```json
{
  "message": "Show me network usage",
  "conversation_id": "web_interface"
}
```

**Response:**
```json
{
  "success": true,
  "response": "AI response here...",
  "actions_performed": true
}
```

### POST /api/start-monitoring

Start network monitoring.

**Response:**
```json
{
  "success": true,
  "devices_found": 5,
  "agent_ready": true
}
```

See `INTEGRATION_GUIDE.md` for complete API documentation.

---

## 🐛 Troubleshooting

### Backend won't start

```bash
# Check if port 5000 is in use
sudo lsof -i :5000

# Kill the process
sudo kill -9 <PID>

# Check Python dependencies
pip3 install -r requirements.txt
```

### Frontend shows "Offline"

```bash
# Test backend API
curl http://localhost:5000/api/status

# Check backend logs
tail -f backend/backend.log

# Restart backend
sudo python3 netmind_backend.py
```

### Ollama not responding

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama
ollama serve

# Pull model again
ollama pull llama3.2:3b
```

### No devices detected

```bash
# Check network interface
ip addr

# Update INTERFACE in ai.py
# Restart backend with sudo
```

See `TROUBLESHOOTING.md` for more solutions.

---

## 🔒 Security Notes

⚠️ **Important Security Considerations:**

1. **Root Access**: Backend needs sudo - be careful!
2. **Network Access**: Only run on trusted networks
3. **Authentication**: Add login system before deploying publicly
4. **HTTPS**: Use SSL/TLS in production
5. **Rate Limiting**: Implement API rate limits
6. **Firewall**: Don't expose ports 5000/11434 to internet

### Recommended Production Setup

```bash
# Use environment variables
export NETMIND_SECRET_KEY="your-secret-key"
export NETMIND_ALLOWED_IPS="192.168.1.0/24"

# Run behind nginx reverse proxy
# Add authentication (JWT, OAuth, etc.)
# Use HTTPS only
# Implement audit logging
```

---

## 🎯 Roadmap

### Planned Features

- [ ] User authentication and authorization
- [ ] Historical bandwidth graphs and analytics
- [ ] Scheduled bandwidth rules
- [ ] Device categorization (work, entertainment, IoT)
- [ ] Mobile app (React Native)
- [ ] Email/SMS notifications
- [ ] Advanced AI features (anomaly detection, predictions)
- [ ] Multi-network support
- [ ] Docker deployment
- [ ] Cloud dashboard

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- **Ollama** - For making LLMs accessible
- **Scapy** - For powerful network tools
- **Next.js** - For the amazing framework
- **Tailwind CSS** - For beautiful styling

---

## 📞 Support

- **Documentation**: See `INTEGRATION_GUIDE.md`
- **Troubleshooting**: See `TROUBLESHOOTING.md`
- **Issues**: Open an issue on GitHub
- **Questions**: Check existing issues first

---

## ⚡ Performance Tips

1. **Limit polling frequency** - Don't refresh too often
2. **Use production builds** - `npm run build` for frontend
3. **Optimize AI model** - Use smaller models if needed
4. **Cache responses** - Implement Redis caching
5. **Database** - Add PostgreSQL for historical data

---

**Built with ❤️ for network administrators who want AI superpowers!**

Version: 1.0.0
Last Updated: February 2026
