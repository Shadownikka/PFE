# NetMind Agent - Quick Reference Guide

## 🤖 AI-Powered Network Management with Ollama

### Overview
NetMind now includes an AI Agent powered by Llama 3.1 through Ollama, enabling natural language network management.

---

## Prerequisites

### 1. Install Ollama
```bash
# Download and install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama server
ollama serve
```

### 2. Pull Llama 3.1 Model
```bash
# In a new terminal
ollama pull llama3.1
```

### 3. Install Python Dependencies
```bash
pip3 install ollama --break-system-packages
# or
pip3 install -r Depandance.txt --break-system-packages
```

---

## How to Use Agent Mode

### Starting Agent Mode

1. **Run NetMind** (requires sudo):
```bash
sudo python3 NetMind.py
```

2. **Select mode**: Choose Automatic or Manual mode

3. **Access menu**: Press `m` key during monitoring

4. **Go Agentic**: Select `[g] 🤖 Go Agentic (Ollama Mode)`

---

## Example Commands

### Check Network Status
```
💬 You: Who is using the most bandwidth?
🤖 NetMind: [Checks stats] Device 192.168.1.50 is using 15 Mbps...
```

### Fix Lag Issues
```
💬 You: I'm lagging, fix it
🤖 NetMind: [Analyzes network] I found device 192.168.1.50 using 
            excessive bandwidth (12 Mbps download). I'll limit it to 
            2 Mbps. [Applies limit] Done! Your lag should be fixed.
```

### Limit Specific Device
```
💬 You: Limit the heaviest user to 3 Mbps
🤖 NetMind: [Finds top user] Limiting 192.168.1.50 to 3 Mbps...
```

### Show Statistics
```
💬 You: Show me current network stats
🤖 NetMind: [Gets stats] Here's what I see:
            - 192.168.1.50: 8.5 Mbps down, 1.2 Mbps up
            - 192.168.1.51: 2.1 Mbps down, 0.5 Mbps up
            ...
```

### Remove Limits
```
💬 You: Remove all limits
🤖 NetMind: [Removes limits] All bandwidth limits have been removed.
```

### Complex Scenarios
```
💬 You: My video call is stuttering, help
🤖 NetMind: [Analyzes] I see two devices using heavy bandwidth...
            I'll limit them to give you better performance.
```

---

## Agent Features

### 🛠️ Available Tools

The AI agent has access to three tools:

1. **get_network_stats()** - Retrieves current bandwidth usage for all devices
2. **enforce_limit(ip, down, up)** - Applies bandwidth limits to specific IPs
3. **remove_limit(ip)** - Removes bandwidth limits from devices

### 🛡️ Safety Guards

- **Protected IPs**: Gateway and host IPs are NEVER limited
- **Validation**: All IP addresses are validated before limiting
- **Reversible**: All limits can be easily removed

### 🧠 AI Behavior

The agent:
- Analyzes network stats before making decisions
- Explains its reasoning and actions
- Applies reasonable limits based on usage patterns
- Maintains conversation context for follow-up questions
- Understands conversational language

---

## Commands

| Command | Description |
|---------|-------------|
| Natural language | Ask anything about your network |
| `reset` | Clear conversation history |
| `back`, `exit`, `quit` | Return to menu |

---

## Technical Details

### Architecture

```
User Input (Natural Language)
    ↓
NetMindAgent.chat()
    ↓
Ollama Llama 3.1 (with Function Calling)
    ↓
Tools: get_network_stats, enforce_limit, remove_limit
    ↓
TrafficMonitor & BandwidthController
    ↓
iptables & tc (Linux Traffic Control)
```

### Configuration

- **Model**: llama3.1
- **Endpoint**: http://localhost:11434
- **Context**: Maintains conversation history
- **Temperature**: Default (Ollama settings)

---

## Troubleshooting

### "Error communicating with Ollama"
```bash
# Make sure Ollama is running
ollama serve

# In another terminal, verify it's working
ollama list
```

### "Model not found"
```bash
# Pull the Llama 3.1 model
ollama pull llama3.1
```

### Agent not limiting correctly
- Check if device IP is protected (gateway/host)
- Verify you have root privileges
- Check iptables rules: `sudo iptables -L -n -v`

---

## Advanced Usage

### Custom Prompts

The agent understands various phrasings:
- "I'm lagging" / "Fix my lag" / "Network is slow"
- "Who's hogging bandwidth?" / "Top user?" / "Bandwidth hog?"
- "Limit X to Y Mbps" / "Cap X at Y" / "Restrict X"
- "Show stats" / "What's happening?" / "Network status"

### Speed Units

The agent understands:
- KB/s (KiloBytes per second)
- Mbps (Megabits per second)
- Automatic conversion (1024 KB/s = 1 MB/s = 8 Mbps)

---

## Example Session

```
🤖 AGENTIC MODE - AI-Powered Network Control
================================================================

[+] Initializing NetMind AI Agent with Ollama...
[Agent] Protected IPs: {'192.168.1.1', '192.168.1.100'}
[✓] Agent initialized successfully!

📚 How to use:
  • Type natural language commands like:
    - 'I'm lagging, fix it'
    - 'Who is using the most bandwidth?'
    ...

================================================================

💬 You: I'm experiencing lag, can you help?

[Agent] Thinking...
[Agent] Calling: get_network_stats({})
[Agent] Result: {
  "devices": [
    {"ip": "192.168.1.50", "download_mbps": 12.5, ...},
    {"ip": "192.168.1.51", "download_mbps": 1.2, ...}
  ]
}

🤖 NetMind: I can see the issue! Device 192.168.1.50 is using 
            12.5 Mbps download, which is quite high. I'll limit 
            it to 3 Mbps to free up bandwidth for you.

[Agent] Calling: enforce_limit({"ip": "192.168.1.50", 
                                "download_kbps": 3072, 
                                "upload_kbps": 1024})
[Agent] Result: {"success": true, "message": "Applied limit..."}

🤖 NetMind: Done! I've limited 192.168.1.50 to 3 Mbps download 
            and 1 Mbps upload. Your lag should be resolved now. 
            Let me know if you need any other adjustments!

💬 You: Thanks! Show me the current stats

[Agent] Calling: get_network_stats({})
...
```

---

## Benefits

✅ **Natural Language** - No need to remember commands or IP addresses
✅ **Intelligent** - AI analyzes and makes smart decisions
✅ **Conversational** - Follow-up questions and context awareness
✅ **Safe** - Protected IPs prevent network lockout
✅ **Explainable** - Agent explains what it's doing and why
✅ **Flexible** - Handles various phrasings and requests

---

**Last Updated**: February 5, 2026
**Version**: 3.0 (Agentic Mode)
