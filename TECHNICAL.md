# NetMind Technical Documentation

## Architecture

### Multi-Container Design

```
┌─────────────────────────────────────────────────┐
│              Docker Host System                 │
│                                                 │
│  ┌──────────────────────────────────────────┐  │
│  │  netmind-core (host network)             │  │
│  │  - ai.py, tool.py, net_agent.py          │  │
│  │  - metrics_exporter.py (port 9090)       │  │
│  │  - ARP spoofing + TC bandwidth control   │  │
│  └──────────────────────────────────────────┘  │
│                     ↓ HTTP                      │
│  ┌──────────────────────────────────────────┐  │
│  │  ai-agent (port 11435)                   │  │
│  │  - Ollama + Llama 3.2 (~4GB)             │  │
│  │  - AI inference for decisions            │  │
│  └──────────────────────────────────────────┘  │
│                     ↓                           │
│  ┌──────────────────────────────────────────┐  │
│  │  prometheus (host network, port 9091)    │  │
│  │  - Scrapes localhost:9090 every 3s       │  │
│  │  - Time-series database                  │  │
│  └──────────────────────────────────────────┘  │
│                     ↓                           │
│  ┌──────────────────────────────────────────┐  │
│  │  grafana (port 3000)                     │  │
│  │  - Queries prometheus via host IP:9091   │  │
│  │  - Auto-provisioned dashboards           │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### Data Flow

```
Network Devices (ARP Spoofed)
    ↓ packets
Host Network Interface
    ↓ iptables FORWARD ACCEPT
netmind-core (scapy captures)
    ↓ TrafficMonitor.stats
metrics_exporter.py
    ↓ HTTP :9090/metrics
Prometheus (scrapes + stores)
    ↓ PromQL queries
Grafana (visualizes)
    ↓ HTTPS
User Browser
```

---

## Network Manipulation

### ARP Spoofing
```python
# tool.py - ARPSpoofer class
# Sends fake ARP replies to devices:
# "Hey device, I'm the gateway (but I'm really the host)"
scapy.send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac))
```

### IP Forwarding
```bash
# Enabled in ai.py
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD ACCEPT
iptables -A FORWARD -j ACCEPT
```

### Traffic Control (Bandwidth Limiting)
```python
# tool.py - BandwidthController
# Uses Linux TC qdisc (token bucket filter)
tc qdisc add dev eth0 root handle 1: htb default 10
tc class add dev eth0 parent 1: classid 1:10 htb rate 100kbps
tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst {ip} flowid 1:10
```

---

## AI Agent (Llama 3.2)

### Function Calling
```python
# net_agent.py - Available functions
tools = [
    {"name": "apply_limit", "description": "Limit device bandwidth"},
    {"name": "remove_limit", "description": "Remove bandwidth limit"},
    {"name": "get_device_info", "description": "Get device details"}
]

# AI receives network stats and calls functions
response = ollama.chat(model="llama3.2", messages=messages, tools=tools)
```

### Optimization for <30s Inference
```python
options = {
    'temperature': 0.2,   # More deterministic = faster
    'num_predict': 150,   # Shorter responses
    'top_k': 5,           # Faster sampling
    'num_ctx': 2048,      # Smaller context
}
```

### Manual Locks Protection
```python
# ai.py - Prevents AI from removing manual limits
self.manual_locks = set()  # IPs with manual limits

def auto_balance():
    for ip in devices:
        if ip in self.manual_locks:
            continue  # Skip AI processing
```

---

## Metrics Exporter

### Prometheus Client
```python
# metrics_exporter.py
from prometheus_client import start_http_server, Gauge, Counter

# Define metrics
bandwidth_download = Gauge('netmind_bandwidth_download_kbps', 
                           'Download speed', 
                           ['ip', 'mac', 'hostname'])

# Update in background thread (every 3s)
def update_metrics():
    stats = monitor.get_current_stats()
    for ip, data in stats.items():
        bandwidth_download.labels(ip=ip, ...).set(data['down'])
```

### Exposed Metrics
- Gauges: Real-time values (bandwidth, status, counts)
- Counters: Cumulative totals (limits applied, removed)
- Labels: Device metadata (ip, mac, hostname)

---

## Grafana Provisioning

### Auto-Configuration
```yaml
# datasources.yml
datasources:
  - name: Prometheus
    url: http://HOST_IP:9091
    isDefault: true

# dashboards.yml
providers:
  - folder: 'NetMind'
    options:
      path: /var/lib/grafana/dashboards
```

### Dashboard Panels
```json
{
  "targets": [{
    "expr": "netmind_bandwidth_download_kbps",
    "legendFormat": "{{hostname}} ({{ip}})"
  }],
  "type": "timeseries",
  "fieldConfig": {
    "unit": "KBs"
  }
}
```

---

## Docker Compose Details

### Network Modes

**Host Network** (netmind-core, prometheus):
```yaml
network_mode: host
# Direct access to host network stack
# Required for iptables/tc manipulation
# Containers share host's IP
```

**Bridge Network** (ai-agent, grafana):
```yaml
ports:
  - "11435:11434"  # External:Internal
# Isolated network with port mapping
# Containers get their own IPs
```

### Volume Persistence
```yaml
volumes:
  ollama_data:      # ~4GB Llama model
  prometheus_data:  # Time-series metrics
  grafana_data:     # Dashboards, users, settings
```

---

## Performance Optimization

### Metrics Update Loop
```python
# 3-second update interval
while self.running:
    self.update_metrics()
    time.sleep(3)
```

### Prometheus Scrape
```yaml
# prometheus.yml
scrape_interval: 3s  # Balance: freshness vs overhead
```

### Grafana Refresh
```json
{
  "refresh": "5s",  # Auto-refresh dashboard
  "liveNow": true   # Real-time mode
}
```

### Resource Usage
- netmind-core: ~100MB RAM, <10% CPU
- ai-agent: ~4GB RAM (model), variable CPU/GPU
- prometheus: ~200MB RAM, <5% CPU
- grafana: ~100MB RAM, <5% CPU

---

## Security Considerations

### Privileged Container
```yaml
netmind-core:
  privileged: true  # Required for:
  # - iptables manipulation
  # - tc (traffic control)
  # - Raw socket access (scapy)
```

### Network Access
- Host network mode = full host network access
- Can intercept/modify all traffic
- Use in trusted environments only

### Authentication
- Grafana: Change default admin/admin
- Prometheus: No auth by default (localhost only)
- Metrics endpoint: Unprotected (consider firewall)

---

## Troubleshooting Deep Dive

### Metrics Not Flowing

**Check 1: NetMind monitoring active?**
```bash
sudo docker exec netmind-core ps aux | grep python
# Should show: python3 NetMind.py
```

**Check 2: Metrics endpoint responding?**
```bash
curl http://localhost:9090/metrics
# Should return Prometheus format metrics
```

**Check 3: Prometheus scraping?**
```bash
curl http://localhost:9091/api/v1/targets
# Look for "health": "up"
```

**Check 4: Grafana datasource connected?**
- Grafana UI → Configuration → Data Sources → Prometheus → Test
- Should show green "Data source is working"

### AI Agent Issues

**Ollama not starting?**
```bash
sudo docker exec netmind-ai-agent ps aux | grep ollama
# Should show: /usr/bin/ollama serve
```

**Model not downloaded?**
```bash
sudo docker exec netmind-ai-agent ollama list
# Should show: llama3.2 (~2GB)
```

**Connection refused?**
```python
# Check ai.py uses correct host
ollama_host = os.getenv('OLLAMA_HOST', 'http://localhost:11435')
```

### Network Disconnects

**Root cause**: Improper cleanup when quitting
```bash
# WRONG: Ctrl+C (leaves ARP spoofing active)
# RIGHT: Press [q] in menu (proper cleanup)
```

**Fix manually**:
```bash
# Flush iptables
sudo iptables -F
sudo iptables -P FORWARD ACCEPT

# Disable IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# Clear ARP cache on devices
arp -d GATEWAY_IP  # Run on each device
```

---

## Deployment Scenarios

### Home Network
```
Router (192.168.1.1)
  ↓
NetMind Host (192.168.1.100)
  ↓ ARP Spoof
Devices (192.168.1.x)
```

### Docker Host on Separate Machine
```yaml
# Update datasources.yml with actual host IP
url: http://192.168.100.60:9091
```

### Multiple Networks
```python
# Scan specific subnet in NetMind.py
subnet = "10.0.0.0/24"  # Change as needed
```

---

## Advanced Configuration

### Custom Bandwidth Limits
```python
# ai.py - Config class
BANDWIDTH_ABUSE_THRESHOLD = 5000  # KB/s (default)
MIN_LIMIT_DURATION = 60           # seconds
```

### Prometheus Retention
```yaml
# docker-compose.yml prometheus command
- '--storage.tsdb.retention.time=30d'  # Keep 30 days
```

### Grafana Plugins
```yaml
# docker-compose.yml grafana environment
- GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
```

---

## Monitoring Stack Alternatives

### Replace Grafana with Chronograf
```yaml
chronograf:
  image: chronograf:latest
  ports:
    - "8888:8888"
```

### Add InfluxDB for Long-Term Storage
```yaml
influxdb:
  image: influxdb:latest
  volumes:
    - influxdb_data:/var/lib/influxdb
```

### Prometheus Federation
```yaml
# For multi-host monitoring
- job_name: 'federation'
  honor_labels: true
  metrics_path: '/federate'
  params:
    'match[]':
      - '{job="netmind"}'
  static_configs:
    - targets:
      - 'prometheus-host-1:9091'
      - 'prometheus-host-2:9091'
```

---

## Development

### Hot Reload
```yaml
# docker-compose.yml
volumes:
  - .:/app  # Code changes reflect immediately
```

### Debug Mode
```python
# ai.py
import pdb; pdb.set_trace()  # Set breakpoint
```

### Testing
```bash
# Run unit tests
python3 test_agent.py

# Manual testing
sudo docker exec -it netmind-core python3 -c "from tool import *; print(get_gateway_ip())"
```

---

## Backup & Restore

### Backup Volumes
```bash
sudo docker run --rm \
  -v docker_grafana_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/grafana-backup.tar.gz /data
```

### Restore
```bash
sudo docker run --rm \
  -v docker_grafana_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/grafana-backup.tar.gz -C /
```

---

## Performance Tuning

### Reduce Metric Cardinality
```python
# Remove hostname label if not needed
bandwidth_download = Gauge('netmind_bandwidth_download_kbps',
                           'Download speed',
                           ['ip'])  # Removed mac, hostname
```

### Increase Scrape Interval
```yaml
# prometheus.yml - Less frequent = less overhead
scrape_interval: 10s
```

### Limit Prometheus Memory
```yaml
# docker-compose.yml
prometheus:
  deploy:
    resources:
      limits:
        memory: 512M
```

---

## Contributing

1. Fork the repository
2. Make changes in feature branch
3. Test with `./verify_deployment.sh`
4. Submit pull request

---

## Changelog

**v2.0** (Current)
- Llama 3.2 integration
- Multi-container architecture
- Grafana professional dashboard
- Prometheus metrics exporter
- <30s AI inference optimization

**v1.0**
- Basic HTML interface
- Llama 3.1
- Single container
- Manual bandwidth control

---

**For quick start guide, see [README.md](README.md)**
