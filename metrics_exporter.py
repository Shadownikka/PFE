#!/usr/bin/env python3
"""
NetMind Metrics Exporter for Prometheus/Grafana
Exposes network monitoring metrics in Prometheus format
"""

from prometheus_client import start_http_server, Gauge, Counter, Info
import time
import threading

# Define Prometheus metrics
bandwidth_download = Gauge('netmind_bandwidth_download_kbps', 'Download bandwidth usage per device', ['ip', 'mac', 'hostname'])
bandwidth_upload = Gauge('netmind_bandwidth_upload_kbps', 'Upload bandwidth usage per device', ['ip', 'mac', 'hostname'])
bandwidth_total_download = Gauge('netmind_bandwidth_total_download_mb', 'Total download per device', ['ip', 'mac', 'hostname'])
bandwidth_total_upload = Gauge('netmind_bandwidth_total_upload_mb', 'Total upload per device', ['ip', 'mac', 'hostname'])

device_status = Gauge('netmind_device_status', 'Device status: 0=normal, 1=limited, 2=blocked', ['ip', 'mac', 'hostname'])
device_limit_download = Gauge('netmind_device_limit_download_kbps', 'Applied download limit', ['ip', 'mac', 'hostname'])
device_limit_upload = Gauge('netmind_device_limit_upload_kbps', 'Applied upload limit', ['ip', 'mac', 'hostname'])

active_devices = Gauge('netmind_active_devices_total', 'Total number of active devices')
limited_devices = Gauge('netmind_limited_devices_total', 'Number of devices with limits')
blocked_devices = Gauge('netmind_blocked_devices_total', 'Number of blocked devices')

network_total_download = Gauge('netmind_network_total_download_kbps', 'Total network download speed')
network_total_upload = Gauge('netmind_network_total_upload_kbps', 'Total network upload speed')

limits_applied = Counter('netmind_limits_applied_total', 'Total number of limits applied', ['type'])
limits_removed = Counter('netmind_limits_removed_total', 'Total number of limits removed')

# AI Agent metrics
ai_inference_time = Gauge('netmind_ai_inference_time_seconds', 'AI agent inference time in seconds')
ai_decisions_total = Counter('netmind_ai_decisions_total', 'Total number of AI decisions made')
ai_agent_status = Gauge('netmind_ai_agent_status', 'AI agent status: 0=inactive, 1=active, 2=error')
monitoring_uptime = Gauge('netmind_monitoring_uptime_seconds', 'Time since monitoring started')


class MetricsExporter:
    """Exports NetMind monitoring data to Prometheus"""
    
    def __init__(self, ai_instance, port=9090):
        """
        Initialize metrics exporter
        
        Args:
            ai_instance: NetMindAI instance with monitor and controller
            port: Port to expose metrics on (default: 9090)
        """
        self.ai = ai_instance
        self.port = port
        self.running = False
        self.update_thread = None
        
    def start(self):
        """Start Prometheus metrics HTTP server"""
        try:
            start_http_server(self.port)
            print(f"[+] Metrics server started on port {self.port}")
            print(f"    Access metrics at: http://localhost:{self.port}/metrics")
            
            # Start background update thread
            self.running = True
            self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
            self.update_thread.start()
            
        except Exception as e:
            print(f"[!] Failed to start metrics server: {e}")
    
    def stop(self):
        """Stop the metrics update loop"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=2)
    
    def _update_loop(self):
        """Background loop to continuously update metrics"""
        while self.running:
            try:
                self.update_metrics()
                time.sleep(3)  # Update every 3 seconds
            except Exception as e:
                print(f"[!] Metrics update error: {e}")
                time.sleep(5)
    
    def update_metrics(self):
        """Update all Prometheus metrics from NetMind data"""
        if not self.ai.monitor or not self.ai.devices:
            return
        
        try:
            # Get current stats
            stats = self.ai.monitor.get_current_stats()
            
            total_down = 0
            total_up = 0
            limited_count = 0
            blocked_count = 0
            active_count = 0
            
            # Update per-device metrics
            for ip, device_info in self.ai.devices.items():
                mac = device_info.get('mac', 'unknown')
                hostname = device_info.get('hostname', ip.replace('.', '_'))
                
                # Get bandwidth stats
                device_stats = stats.get(ip, {'up': 0, 'down': 0})
                up_kbps = device_stats['up']
                down_kbps = device_stats['down']
                
                # Update bandwidth gauges
                bandwidth_download.labels(ip=ip, mac=mac, hostname=hostname).set(down_kbps)
                bandwidth_upload.labels(ip=ip, mac=mac, hostname=hostname).set(up_kbps)
                
                # Get total bandwidth from byte counters
                total_down_mb = self.ai.monitor.byte_counters[ip]['down'] / (1024 * 1024)
                total_up_mb = self.ai.monitor.byte_counters[ip]['up'] / (1024 * 1024)
                bandwidth_total_download.labels(ip=ip, mac=mac, hostname=hostname).set(total_down_mb)
                bandwidth_total_upload.labels(ip=ip, mac=mac, hostname=hostname).set(total_up_mb)
                
                # Determine device status
                if ip in self.ai.controller.limits:
                    limits = self.ai.controller.limits[ip]
                    limit_down = limits['down']
                    limit_up = limits['up']
                    
                    # Check if blocked (limit <= 1 KB/s)
                    if limit_down <= 1 and limit_up <= 1:
                        status = 2  # Blocked
                        blocked_count += 1
                    else:
                        status = 1  # Limited
                        limited_count += 1
                    
                    device_limit_download.labels(ip=ip, mac=mac, hostname=hostname).set(limit_down)
                    device_limit_upload.labels(ip=ip, mac=mac, hostname=hostname).set(limit_up)
                else:
                    status = 0  # Normal
                    device_limit_download.labels(ip=ip, mac=mac, hostname=hostname).set(0)
                    device_limit_upload.labels(ip=ip, mac=mac, hostname=hostname).set(0)
                
                device_status.labels(ip=ip, mac=mac, hostname=hostname).set(status)
                
                # Count active devices
                if up_kbps > 1 or down_kbps > 1:
                    active_count += 1
                
                # Accumulate totals
                total_down += down_kbps
                total_up += up_kbps
            
            # Update aggregate metrics
            active_devices.set(active_count)
            limited_devices.set(limited_count)
            blocked_devices.set(blocked_count)
            network_total_download.set(total_down)
            network_total_upload.set(total_up)
            
        except Exception as e:
            print(f"[!] Error updating metrics: {e}")
    
    def record_limit_applied(self, limit_type='manual'):
        """Record when a limit is applied"""
        limits_applied.labels(type=limit_type).inc()
    
    def record_limit_removed(self):
        """Record when a limit is removed"""
        limits_removed.inc()
