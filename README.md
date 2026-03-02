# NetMind - AI-Powered Network Bandwidth Monitor

**Professional network monitoring with Llama 3.2 AI agent, real-time Grafana dashboards, and intelligent bandwidth management.**

---

## 🚀 Quick Start

### Launch NetMind
```bash
# Start all services
sudo docker-compose up -d

# Wait for Llama 3.2 download (~2GB, 5-10 min)
sudo docker logs -f netmind-ai-agent

# Run NetMind
sudo docker exec -it netmind-core python3 NetMind.py
```

### Access Dashboard
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9091
- **Metrics**: http://localhost:9090/metrics

---

## 🎮 Commands

**Main Menu**: `[1]` Scan | `[2]` Manual Mode | `[3]` AI Agent Mode

**During Monitoring**: `[l]` Limit | `[b]` Block | `[r]` Remove | `[s]` Status | `[x]` Restore All | `[q]` Quit

**Multi-Device**: Enter `1,3,5` or `all`

---

## 🐳 Docker Services

- **netmind-core**: Network monitoring (host network, port 9090)
- **ai-agent**: Ollama + Llama 3.2 (port 11435)
- **prometheus**: Metrics collection (port 9091)
- **grafana**: Dashboard (port 3000)

---

## 🔧 Management

```bash
# Logs
sudo docker-compose logs -f

# Restart
sudo docker-compose restart

# Stop
sudo docker-compose down

# Rebuild
sudo docker-compose up --build -d

# Status
sudo docker-compose ps

# Metrics check
curl http://localhost:9090/metrics | grep netmind_
```

---

## 📊 Grafana Dashboard

**10 Panels**:
1. AI Performance Gauge (RED at ≥30s)
2. Real-Time Bandwidth Graph
3. Active Devices
4. Limited Devices
5. Blocked Devices
6. Per-Device Download
7. Per-Device Upload
8. Device Status Table
9. AI Actions Rate
10. AI Status

Auto-refresh: **5 seconds**

---

## 🛠️ Troubleshooting

**No metrics in Grafana?**
```bash
curl http://localhost:9090/metrics | grep netmind_
curl http://localhost:9091/targets
```

**AI not responding?**
```bash
sudo docker exec netmind-ai-agent ollama list
curl http://localhost:11435/api/tags
```

**Network disconnects?**
- Always quit with `[q]`, NOT Ctrl+C
- Check: `cat /proc/sys/net/ipv4/ip_forward` (should be 1)

**Port conflicts?**
```bash
sudo netstat -tulpn | grep -E '3000|9091|11435'
```

---

## ⚙️ Configuration

**Prometheus scrape interval** (`prometheus.yml`):
```yaml
scrape_interval: 3s  # Adjust as needed
```

**Grafana datasource** (`NetMind_Interface/grafana/datasources.yml`):
```yaml
url: http://YOUR_HOST_IP:9091
```

**AI performance** (`net_agent.py`):
```python
'temperature': 0.2,   # Lower = faster
'num_predict': 150,   # Response length
'num_ctx': 2048,      # Context window
```

---

## 📁 Structure

```
NetMind/
├── NetMind.py, ai.py, tool.py, net_agent.py
├── metrics_exporter.py
├── Dockerfile, Dockerfile.ai-agent
├── docker-compose.yml, prometheus.yml
├── requirements.txt, requirements-agent.txt
├── NetMind_Interface/grafana/
│   ├── datasources.yml, dashboards.yml
│   ├── netmind-dashboard.json
│   └── netmind-professional-dashboard.json
├── README.md (this file)
├── TECHNICAL.md (architecture details)
└── verify_deployment.sh
```

---

## 📈 Metrics

**Bandwidth**: `netmind_bandwidth_{download|upload}_kbps`  
**Status**: `netmind_device_status` (0=normal, 1=limited, 2=blocked)  
**AI**: `netmind_ai_inference_time_seconds`, `netmind_ai_agent_status`  
**Counters**: `netmind_active_devices_total`, `netmind_limits_applied_total`

---

## 🎯 Use Cases

- Home network bandwidth management
- Small office device control
- IoT device monitoring
- Parental controls
- Network performance testing

---

## 📜 License

MIT - Free to use and modify

---

**Made with ❤️ for network admins and power users**

For technical details, see [TECHNICAL.md](TECHNICAL.md)
