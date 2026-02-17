#!/usr/bin/env python3
"""
NetMind Web Interface - Flask Backend
Provides REST API for network monitoring and AI agent control
"""

import sys
import os

# Add parent directory to path to import tool and agent modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
from tool import (
    Config, has_root, get_gateway_ip, get_default_interface,
    get_subnet_cidr, enable_ip_forwarding, discover_clients,
    TrafficMonitor, BandwidthController, ConnectionTracker
)
from net_agent import NetMindAgent

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global state
monitor = None
controller = None
tracker = None
agent = None
gateway_ip = None
interface = None
is_monitoring = False
monitor_thread = None

# -------------------------
# Helper Functions
# -------------------------

def initialize_netmind():
    """Initialize NetMind monitoring system"""
    global monitor, controller, tracker, agent, gateway_ip, interface
    
    if not has_root():
        return {"error": "Root privileges required"}, 403
    
    # Get network interface
    interface = get_default_interface()
    if not interface:
        return {"error": "No network interface found"}, 500
    
    # Get gateway
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        return {"error": "No gateway found"}, 500
    
    # Discover devices
    subnet = get_subnet_cidr(interface)
    clients = discover_clients(subnet)
    devices = {client['ip']: {'mac': client.get('mac', 'Unknown')} for client in clients}
    
    # Initialize components
    monitor = TrafficMonitor(devices)
    print(f"[DEBUG] Initialized monitor with {len(devices)} devices: {list(devices.keys())}")
    tracker = ConnectionTracker(devices, interface)
    controller = BandwidthController(interface, monitor)
    controller.set_gateway(gateway_ip)
    
    # Initialize AI agent
    agent_error = None
    try:
        agent = NetMindAgent(monitor, controller, Config)
        print("✓ AI Agent initialized successfully")
    except Exception as e:
        agent_error = str(e)
        print(f"⚠️  AI Agent initialization failed: {e}")
        print("   Make sure Ollama is running: ollama serve")
        print("   And llama3.1 is installed: ollama pull llama3.1")
        agent = None
    
    return {
        "success": True, 
        "interface": interface, 
        "gateway": gateway_ip,
        "agent_available": agent is not None,
        "agent_error": agent_error
    }, 200

def monitoring_loop():
    """Background monitoring loop"""
    global is_monitoring
    while is_monitoring:
        try:
            # Monitor is already running its own packet capture
            # Just keep this loop alive to maintain the monitoring state
            time.sleep(Config.MONITOR_INTERVAL)
        except Exception as e:
            print(f"Monitoring error: {e}")
            time.sleep(5)

# -------------------------
# API Routes
# -------------------------

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        "initialized": monitor is not None,
        "monitoring": is_monitoring,
        "has_root": has_root(),
        "interface": interface,
        "gateway": gateway_ip,
        "agent_available": agent is not None
    })

@app.route('/api/initialize', methods=['POST'])
def initialize():
    """Initialize the NetMind system"""
    result, status = initialize_netmind()
    return jsonify(result), status

@app.route('/api/start-monitoring', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    global is_monitoring, monitor_thread
    
    if not monitor:
        return jsonify({"error": "System not initialized"}), 400
    
    if is_monitoring:
        return jsonify({"message": "Already monitoring"}), 200
    
    enable_ip_forwarding()
    
    # Start the traffic monitor
    print("[DEBUG] Starting traffic monitor...")
    monitor.start()
    print(f"[DEBUG] Monitor running: {monitor.running}")
    print(f"[DEBUG] Monitor devices: {list(monitor.devices.keys())}")
    
    # Start ARP spoofing for all devices to intercept traffic
    if controller:
        print("[+] Starting ARP spoofing for traffic interception...")
        gateway = {"ip": gateway_ip, "mac": None}
        controller.set_gateway(gateway)
        
        subnet = get_subnet_cidr(interface)
        clients = discover_clients(subnet)
        
        for client in clients:
            if client['ip'] != gateway_ip:
                target = {"ip": client['ip'], "mac": client['mac']}
                controller.start_spoofing(target)
                print(f"  ✓ Spoofing {client['ip']}")
        #!/usr/bin/env python3
"""
NetMind Web Interface - Flask Backend
Provides REST API for network monitoring and AI agent control
"""

import sys
import os

# Add parent directory to path to import tool and agent modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
from tool import (
    Config, has_root, get_gateway_ip, get_default_interface,
    get_subnet_cidr, enable_ip_forwarding, discover_clients,
    TrafficMonitor, BandwidthController, ConnectionTracker
)
from net_agent import NetMindAgent

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global state
monitor = None
controller = None
tracker = None
agent = None
gateway_ip = None
interface = None
is_monitoring = False
monitor_thread = None

# -------------------------
# Helper Functions
# -------------------------

def initialize_netmind():
    """Initialize NetMind monitoring system"""
    global monitor, controller, tracker, agent, gateway_ip, interface
    
    if not has_root():
        return {"error": "Root privileges required"}, 403
    
    # Get network interface
    interface = get_default_interface()
    if not interface:
        return {"error": "No network interface found"}, 500
    
    # Get gateway
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        return {"error": "No gateway found"}, 500
    
    # Discover devices
    subnet = get_subnet_cidr(interface)
    clients = discover_clients(subnet)
    devices = {client['ip']: {'mac': client.get('mac', 'Unknown')} for client in clients}
    
    # Initialize components
    monitor = TrafficMonitor(devices)
    print(f"[DEBUG] Initialized monitor with {len(devices)} devices: {list(devices.keys())}")
    tracker = ConnectionTracker(devices, interface)
    controller = BandwidthController(interface, monitor)
    controller.set_gateway(gateway_ip)
    
    # Initialize AI agent
    agent_error = None
    try:
        agent = NetMindAgent(monitor, controller, Config)
        print("✓ AI Agent initialized successfully")
    except Exception as e:
        agent_error = str(e)
        print(f"⚠️  AI Agent initialization failed: {e}")
        print("   Make sure Ollama is running: ollama serve")
        print("   And llama3.1 is installed: ollama pull llama3.1")
        agent = None
    
    return {
        "success": True, 
        "interface": interface, 
        "gateway": gateway_ip,
        "agent_available": agent is not None,
        "agent_error": agent_error
    }, 200

def monitoring_loop():
    """Background monitoring loop"""
    global is_monitoring
    while is_monitoring:
        try:
            # Monitor is already running its own packet capture
            # Just keep this loop alive to maintain the monitoring state
            time.sleep(Config.MONITOR_INTERVAL)
        except Exception as e:
            print(f"Monitoring error: {e}")
            time.sleep(5)

# -------------------------
# API Routes
# -------------------------

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        "initialized": monitor is not None,
        "monitoring": is_monitoring,
        "has_root": has_root(),
        "interface": interface,
        "gateway": gateway_ip,
        "agent_available": agent is not None
    })

@app.route('/api/initialize', methods=['POST'])
def initialize():
    """Initialize the NetMind system"""
    result, status = initialize_netmind()
    return jsonify(result), status

@app.route('/api/start-monitoring', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    global is_monitoring, monitor_thread
    
    if not monitor:
        return jsonify({"error": "System not initialized"}), 400
    
    if is_monitoring:
        return jsonify({"message": "Already monitoring"}), 200
    
    enable_ip_forwarding()
    
    # Start the traffic monitor
    print("[DEBUG] Starting traffic monitor...")
    monitor.start()
    print(f"[DEBUG] Monitor running: {monitor.running}")
    print(f"[DEBUG] Monitor devices: {list(monitor.devices.keys())}")
    
    # Start ARP spoofing for all devices to intercept traffic
    if controller:
        print("[+] Starting ARP spoofing for traffic interception...")
        gateway = {"ip": gateway_ip, "mac": None}
        controller.set_gateway(gateway)
        
        subnet = get_subnet_cidr(interface)
        clients = discover_clients(subnet)
        
        for client in clients:
            if client['ip'] != gateway_ip:
                target = {"ip": client['ip'], "mac": client['mac']}
                controller.start_spoofing(target)
                print(f"  ✓ Spoofing {client['ip']}")
        
        print("[+] ARP spoofing active - intercepting traffic")
    
    # Start connection tracker
    if tracker:
        tracker.start()
        print("[+] Connection tracker started")
    
    is_monitoring = True
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()
    
    return jsonify({"success": True, "message": "Monitoring started"})

@app.route('/api/stop-monitoring', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    global is_monitoring
    
    is_monitoring = False
    
    if monitor:
        monitor.stop()
    
    if tracker:
        tracker.running.set()  # Signal tracker to stop
    
    if controller:
        controller.cleanup()
    
    return jsonify({"success": True, "message": "Monitoring stopped"})

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get list of all detected devices with their stats"""
    if not monitor:
        return jsonify({"error": "System not initialized"}), 400
    
    subnet = get_subnet_cidr(interface)
    clients = discover_clients(subnet)
    
    # Get current stats from monitor
    current_stats = monitor.get_current_stats() if monitor.running else {}
    
    devices = []
    for client in clients:
        ip = client['ip']
        
        # Skip the gateway/router
        if ip == gateway_ip:
            continue
        
        stats = current_stats.get(ip, {"up": 0, "down": 0})
        
        # Get activity information (visited sites)
        activity = {"domains": [], "summary": "No activity"}
        if tracker:
            try:
                activity_data = tracker.get_activity(ip)
                summary = tracker.get_summary(ip)
                activity = {
                    "domains": activity_data.get("domains", [])[:10],  # Last 10 domains
                    "summary": summary
                }
            except:
                pass
        
        devices.append({
            "ip": ip,
            "mac": client.get('mac', 'Unknown'),
            "download_kbps": round(stats.get('down', 0), 2),
            "upload_kbps": round(stats.get('up', 0), 2),
            "total_download_mb": 0,  # Not tracked in current implementation
            "total_upload_mb": 0,    # Not tracked in current implementation
            "limited": ip in controller.limits if controller else False,
            "activity": activity
        })
    
    return jsonify({"devices": devices})

@app.route('/api/agent/chat', methods=['POST'])
def agent_chat():
    """Send a message to the AI agent"""
    if not agent:
        return jsonify({
            "error": "AI agent not initialized. Make sure Ollama is running (ollama serve) and llama3.1 model is installed (ollama pull llama3.1). Then reinitialize the system."
        }), 400
    
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({"error": "No message provided"}), 400
    
    try:
        response = agent.chat(message)
        return jsonify({
            "success": True,
            "response": response
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/agent/analyze', methods=['POST'])
def agent_analyze():
    """Ask the AI agent to analyze network and make recommendations"""
    if not agent:
        return jsonify({
            "error": "AI agent not initialized. Make sure Ollama is running (ollama serve) and llama3.1 model is installed (ollama pull llama3.1). Then reinitialize the system."
        }), 400
    
    try:
        # Use short, direct request for faster response
        response = agent.chat("Analyze network now. Check stats and report issues briefly.")
        return jsonify({
            "success": True,
            "analysis": response
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/bandwidth/limit', methods=['POST'])
def set_bandwidth_limit():
    """Manually set bandwidth limit for a device"""
    if not controller:
        return jsonify({"error": "System not initialized"}), 400
    
    data = request.json
    ip = data.get('ip')
    download = data.get('download_kbps', 1000)
    upload = data.get('upload_kbps', 1000)
    
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    
    try:
        controller.apply_limit(ip, download, upload)
        return jsonify({
            "success": True,
            "message": f"Limit applied to {ip}: {download}/{upload} kbps"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/bandwidth/remove', methods=['POST'])
def remove_bandwidth_limit():
    """Remove bandwidth limit from a device"""
    if not controller:
        return jsonify({"error": "System not initialized"}), 400
    
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    
    try:
        controller.remove_limit(ip)
        return jsonify({
            "success": True,
            "message": f"Limit removed from {ip}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    return jsonify({
        "monitor_interval": Config.MONITOR_INTERVAL,
        "auto_limit_enabled": Config.AUTO_LIMIT_ENABLED,
        "bandwidth_abuse_threshold": Config.BANDWIDTH_ABUSE_THRESHOLD,
        "max_single_device_percent": Config.MAX_SINGLE_DEVICE_PERCENT,
        "min_guaranteed_kbps": Config.MIN_GUARANTEED_KBPS
    })

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration"""
    data = request.json
    
    if 'monitor_interval' in data:
        Config.MONITOR_INTERVAL = data['monitor_interval']
    if 'auto_limit_enabled' in data:
        Config.AUTO_LIMIT_ENABLED = data['auto_limit_enabled']
    if 'bandwidth_abuse_threshold' in data:
        Config.BANDWIDTH_ABUSE_THRESHOLD = data['bandwidth_abuse_threshold']
    
    return jsonify({"success": True, "message": "Configuration updated"})

# -------------------------
# Main
# -------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("NetMind Web Interface - Backend Server")
    print("=" * 60)
    print(f"Root privileges: {has_root()}")
    
    if not has_root():
        print("\n⚠️  WARNING: Root privileges required for network operations")
        print("   Please run with: sudo python3 backend.py\n")
    
    # Run Flask server
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

        print("[+] ARP spoofing active - intercepting traffic")
    
    # Start connection tracker
    if tracker:
        tracker.start()
        print("[+] Connection tracker started")
    
    is_monitoring = True
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()
    
    return jsonify({"success": True, "message": "Monitoring started"})

@app.route('/api/stop-monitoring', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    global is_monitoring
    
    is_monitoring = False
    
    if monitor:
        monitor.stop()
    
    if tracker:
        tracker.running.set()  # Signal tracker to stop
    
    if controller:
        controller.cleanup()
    
    return jsonify({"success": True, "message": "Monitoring stopped"})

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get list of all detected devices with their stats"""
    if not monitor:
        return jsonify({"error": "System not initialized"}), 400
    
    subnet = get_subnet_cidr(interface)
    clients = discover_clients(subnet)
    
    # Get current stats from monitor
    current_stats = monitor.get_current_stats() if monitor.running else {}
    
    devices = []
    for client in clients:
        ip = client['ip']
        
        # Skip the gateway/router
        if ip == gateway_ip:
            continue
        
        stats = current_stats.get(ip, {"up": 0, "down": 0})
        
        # Get activity information (visited sites)
        activity = {"domains": [], "summary": "No activity"}
        if tracker:
            try:
                activity_data = tracker.get_activity(ip)
                summary = tracker.get_summary(ip)
                activity = {
                    "domains": activity_data.get("domains", [])[:10],  # Last 10 domains
                    "summary": summary
                }
            except:
                pass
        
        devices.append({
            "ip": ip,
            "mac": client.get('mac', 'Unknown'),
            "download_kbps": round(stats.get('down', 0), 2),
            "upload_kbps": round(stats.get('up', 0), 2),
            "total_download_mb": 0,  # Not tracked in current implementation
            "total_upload_mb": 0,    # Not tracked in current implementation
            "limited": ip in controller.limits if controller else False,
            "activity": activity
        })
    
    return jsonify({"devices": devices})

@app.route('/api/agent/chat', methods=['POST'])
def agent_chat():
    """Send a message to the AI agent"""
    if not agent:
        return jsonify({
            "error": "AI agent not initialized. Make sure Ollama is running (ollama serve) and llama3.1 model is installed (ollama pull llama3.1). Then reinitialize the system."
        }), 400
    
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({"error": "No message provided"}), 400
    
    try:
        response = agent.chat(message)
        return jsonify({
            "success": True,
            "response": response
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/agent/analyze', methods=['POST'])
def agent_analyze():
    """Ask the AI agent to analyze network and make recommendations"""
    if not agent:
        return jsonify({
            "error": "AI agent not initialized. Make sure Ollama is running (ollama serve) and llama3.1 model is installed (ollama pull llama3.1). Then reinitialize the system."
        }), 400
    
    try:
        # Use short, direct request for faster response
        response = agent.chat("Analyze network now. Check stats and report issues briefly.")
        return jsonify({
            "success": True,
            "analysis": response
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/bandwidth/limit', methods=['POST'])
def set_bandwidth_limit():
    """Manually set bandwidth limit for a device"""
    if not controller:
        return jsonify({"error": "System not initialized"}), 400
    
    data = request.json
    ip = data.get('ip')
    download = data.get('download_kbps', 1000)
    upload = data.get('upload_kbps', 1000)
    
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    
    try:
        controller.apply_limit(ip, download, upload)
        return jsonify({
            "success": True,
            "message": f"Limit applied to {ip}: {download}/{upload} kbps"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/bandwidth/remove', methods=['POST'])
def remove_bandwidth_limit():
    """Remove bandwidth limit from a device"""
    if not controller:
        return jsonify({"error": "System not initialized"}), 400
    
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    
    try:
        controller.remove_limit(ip)
        return jsonify({
            "success": True,
            "message": f"Limit removed from {ip}"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    return jsonify({
        "monitor_interval": Config.MONITOR_INTERVAL,
        "auto_limit_enabled": Config.AUTO_LIMIT_ENABLED,
        "bandwidth_abuse_threshold": Config.BANDWIDTH_ABUSE_THRESHOLD,
        "max_single_device_percent": Config.MAX_SINGLE_DEVICE_PERCENT,
        "min_guaranteed_kbps": Config.MIN_GUARANTEED_KBPS
    })

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration"""
    data = request.json
    
    if 'monitor_interval' in data:
        Config.MONITOR_INTERVAL = data['monitor_interval']
    if 'auto_limit_enabled' in data:
        Config.AUTO_LIMIT_ENABLED = data['auto_limit_enabled']
    if 'bandwidth_abuse_threshold' in data:
        Config.BANDWIDTH_ABUSE_THRESHOLD = data['bandwidth_abuse_threshold']
    
    return jsonify({"success": True, "message": "Configuration updated"})

# -------------------------
# Main
# -------------------------

if __name__ == '__main__':
    print("=" * 60)
    print("NetMind Web Interface - Backend Server")
    print("=" * 60)
    print(f"Root privileges: {has_root()}")
    
    if not has_root():
        print("\n⚠️  WARNING: Root privileges required for network operations")
        print("   Please run with: sudo python3 backend.py\n")
    
    # Run Flask server
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
