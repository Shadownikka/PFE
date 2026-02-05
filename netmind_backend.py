#!/usr/bin/env python3
"""
NetMind AI - Web Backend with Ollama Integration
Flask server that bridges web interface with NetMind AI Agent
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import json
import threading
import time
from datetime import datetime
import os
import sys

app = Flask(__name__)
CORS(app)

# Import NetMind components
try:
    from ai import NetMindAI, Config
    from net_agent import NetMindAgent
except ImportError as e:
    print(f"Error importing NetMind modules: {e}")
    print("Make sure this file is in the same directory as ai.py, tool.py, and net_agent.py")
    sys.exit(1)

# Configuration
STATE_FILE = "/tmp/netmind_state.json"
netmind_ai = None
ai_agent = None
monitor_thread = None

class SystemState:
    def __init__(self):
        self.data = {
            'total_bandwidth': 0.0,
            'devices': [],
            'active_devices': 0,
            'optimizations': 0,
            'ai_active': False,
            'agent_ready': False,
            'conversation_history': {}
        }
    
    def update_from_netmind(self):
        """Update state from NetMind AI"""
        global netmind_ai
        
        if not netmind_ai or not netmind_ai.monitor:
            return False
        
        try:
            stats = netmind_ai.monitor.get_current_stats()
            
            # Calculate totals
            total_bandwidth = 0
            active_count = 0
            devices = []
            
            for ip, info in netmind_ai.devices.items():
                usage = stats.get(ip, {"up": 0, "down": 0})
                
                # Convert KB/s to Mbps
                bandwidth_mbps = usage['down'] * 8 / 1000
                total_bandwidth += bandwidth_mbps
                
                if usage['down'] > 1 or usage['up'] > 1:
                    active_count += 1
                
                # Check if limited
                is_limited = False
                if netmind_ai.controller and ip in netmind_ai.controller.limits:
                    is_limited = True
                
                device = {
                    'ip': ip,
                    'mac': info.get('mac', 'Unknown'),
                    'name': info.get('name', f'Device-{ip.split(".")[-1]}'),
                    'bandwidth': round(bandwidth_mbps, 2),
                    'upload': round(usage['up'] * 8 / 1000, 2),
                    'icon': self.get_device_icon(ip),
                    'limited': is_limited,
                    'last_seen': datetime.now().isoformat()
                }
                
                devices.append(device)
            
            # Update state
            self.data['total_bandwidth'] = round(total_bandwidth, 2)
            self.data['devices'] = devices
            self.data['active_devices'] = active_count
            self.data['ai_active'] = netmind_ai.running
            
            # Count optimizations
            if netmind_ai.controller:
                self.data['optimizations'] = len(netmind_ai.controller.limits)
            
            # Save to file
            self.save()
            
            return True
            
        except Exception as e:
            print(f"Error updating state: {e}")
            return False
    
    def get_device_icon(self, ip):
        """Get icon for device based on IP"""
        last_octet = int(ip.split('.')[-1])
        
        if last_octet < 10:
            return '📡'
        elif last_octet < 50:
            return '💻'
        elif last_octet < 100:
            return '📱'
        elif last_octet < 150:
            return '🖥️'
        else:
            return '💾'
    
    def save(self):
        """Save state to file"""
        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            print(f"Error saving state: {e}")
    
    def load(self):
        """Load state from file"""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, 'r') as f:
                    self.data = json.load(f)
        except Exception as e:
            print(f"Error loading state: {e}")

# Global state
state = SystemState()
state.load()

# Background monitoring
class NetMindMonitor(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
    
    def run(self):
        """Monitor NetMind and update state"""
        global netmind_ai, state
        
        while self.running:
            try:
                if netmind_ai and netmind_ai.running:
                    state.update_from_netmind()
                
                time.sleep(3)
                
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(3)

# API Routes

@app.route('/')
def index():
    """Serve the main HTML interface"""
    return send_from_directory('.', 'netmind_ai_interface.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current system status"""
    return jsonify(state.data)

@app.route('/api/chat', methods=['POST'])
def chat_with_ai():
    """Chat with NetMind AI Agent"""
    global ai_agent
    
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        conversation_id = data.get('conversation_id', 'default')
        
        if not message:
            return jsonify({
                'success': False,
                'error': 'No message provided'
            }), 400
        
        # Check if agent is initialized
        if not ai_agent:
            return jsonify({
                'success': False,
                'error': 'AI Agent not initialized. Start NetMind monitoring first.'
            }), 503
        
        print(f"[Chat] User: {message}")
        
        # Send message to AI agent
        response = ai_agent.chat(message)
        
        print(f"[Chat] AI: {response[:100]}...")
        
        # Save conversation to state
        if conversation_id not in state.data['conversation_history']:
            state.data['conversation_history'][conversation_id] = []
        
        state.data['conversation_history'][conversation_id].append({
            'user': message,
            'ai': response,
            'timestamp': datetime.now().isoformat()
        })
        
        state.save()
        
        # Update network stats after AI actions
        state.update_from_netmind()
        
        return jsonify({
            'success': True,
            'response': response,
            'actions_performed': True
        })
        
    except Exception as e:
        print(f"Chat error: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/start-monitoring', methods=['POST'])
def start_monitoring():
    """Start NetMind AI monitoring"""
    global netmind_ai, ai_agent, monitor_thread
    
    try:
        # Initialize NetMind AI
        if not netmind_ai:
            netmind_ai = NetMindAI()
            netmind_ai.scan_network()
        
        # Start monitoring in background
        if not netmind_ai.running:
            # Start monitoring thread
            monitoring_thread = threading.Thread(
                target=start_netmind_monitoring,
                daemon=True
            )
            monitoring_thread.start()
            
            # Wait for initialization
            time.sleep(5)
        
        # Initialize AI Agent
        if not ai_agent and netmind_ai.running:
            ai_agent = NetMindAgent(
                netmind_ai.monitor,
                netmind_ai.controller,
                Config
            )
            
            # Set protected IPs
            ai_agent.set_protected_ips(
                netmind_ai.gateway_ip,
                netmind_ai.iface  # This should be host IP
            )
            
            state.data['agent_ready'] = True
            state.save()
        
        # Start monitor thread
        if not monitor_thread or not monitor_thread.is_alive():
            monitor_thread = NetMindMonitor()
            monitor_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'NetMind AI monitoring started',
            'devices_found': len(netmind_ai.devices),
            'agent_ready': ai_agent is not None
        })
        
    except Exception as e:
        print(f"Start monitoring error: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def start_netmind_monitoring():
    """Start NetMind monitoring in background"""
    global netmind_ai
    
    try:
        print("[+] Starting NetMind monitoring in background...")
        netmind_ai.start_monitoring(mode='auto')
    except Exception as e:
        print(f"Monitoring error: {e}")

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get list of all devices"""
    return jsonify({
        'devices': state.data['devices'],
        'total': len(state.data['devices']),
        'active': state.data['active_devices']
    })

@app.route('/api/agent/reset', methods=['POST'])
def reset_agent():
    """Reset AI agent conversation"""
    global ai_agent
    
    try:
        if ai_agent:
            ai_agent.reset_conversation()
            
            # Clear conversation history
            data = request.get_json() or {}
            conversation_id = data.get('conversation_id', 'default')
            
            if conversation_id in state.data['conversation_history']:
                del state.data['conversation_history'][conversation_id]
            
            state.save()
            
            return jsonify({
                'success': True,
                'message': 'Conversation reset'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Agent not initialized'
            }), 503
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get current settings"""
    return jsonify({
        'ml_mode': Config.AUTO_LIMIT_ENABLED,
        'bandwidth_threshold': Config.BANDWIDTH_ABUSE_THRESHOLD,
        'max_device_percent': Config.MAX_SINGLE_DEVICE_PERCENT
    })

@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Update settings"""
    try:
        data = request.get_json()
        
        if 'ml_mode' in data:
            Config.AUTO_LIMIT_ENABLED = data['ml_mode']
        
        state.save()
        
        return jsonify({
            'success': True,
            'settings': {
                'ml_mode': Config.AUTO_LIMIT_ENABLED
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Initialize on startup
def initialize_on_startup():
    """Initialize NetMind on server startup"""
    global netmind_ai, ai_agent, monitor_thread
    
    print("\n" + "="*70)
    print("NetMind AI - Web Backend Server")
    print("="*70)
    print()
    
    try:
        # Try to initialize NetMind
        print("[+] Initializing NetMind AI...")
        netmind_ai = NetMindAI()
        
        print("[+] Scanning network...")
        netmind_ai.scan_network()
        
        print(f"[+] Found {len(netmind_ai.devices)} devices")
        
        # Start monitoring
        print("[+] Starting monitoring...")
        monitoring_thread = threading.Thread(
            target=start_netmind_monitoring,
            daemon=True
        )
        monitoring_thread.start()
        
        # Wait for initialization
        time.sleep(5)
        
        # Initialize AI Agent
        if netmind_ai.monitor and netmind_ai.controller:
            print("[+] Initializing AI Agent...")
            ai_agent = NetMindAgent(
                netmind_ai.monitor,
                netmind_ai.controller,
                Config
            )
            
            # Set protected IPs
            ai_agent.set_protected_ips(
                netmind_ai.gateway_ip,
                '192.168.1.100'  # Adjust this to your host IP
            )
            
            state.data['agent_ready'] = True
            print("[✓] AI Agent ready!")
        
        # Start monitor thread
        monitor_thread = NetMindMonitor()
        monitor_thread.start()
        print("[✓] Background monitoring started")
        
        print()
        print("="*70)
        print("Server ready!")
        print("Web interface: http://localhost:5000")
        print("API endpoint: http://localhost:5000/api/status")
        print("="*70)
        print()
        
    except Exception as e:
        print(f"[!] Warning: Could not auto-initialize: {e}")
        print("[!] You can manually start monitoring via API")
        print()

if __name__ == '__main__':
    # Initialize on startup
    initialize_on_startup()
    
    # Run Flask server
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
