#!/usr/bin/env python3
"""
NetMind Agent - AI-Powered Network Management using Ollama
Uses Llama 3.1 with function calling for intelligent bandwidth decisions
"""

import json
import ollama
from termcolor import colored


class NetMindAgent:
    """AI Agent that uses Ollama LLM with function calling to manage network bandwidth"""
    
    def __init__(self, monitor, controller, config):
        """
        Initialize the NetMind AI Agent
        
        Args:
            monitor: TrafficMonitor instance from tool.py
            controller: BandwidthController instance from tool.py
            config: Config instance from tool.py
        """
        self.monitor = monitor
        self.controller = controller
        self.config = config
        self.client = ollama.Client(host='http://localhost:11434')
        self.model = 'llama3.1'
        
        # Safety: IPs that should NEVER be limited
        self.protected_ips = set()
        
        # Conversation history for context
        self.conversation_history = []
        
        # Define available tools for the LLM
        self.tools = [
            {
                'type': 'function',
                'function': {
                    'name': 'get_network_stats',
                    'description': 'Get current network statistics for all connected devices including IP addresses, upload/download speeds, and activity status. Use this to analyze who is using bandwidth.',
                    'parameters': {
                        'type': 'object',
                        'properties': {},
                        'required': []
                    }
                }
            },
            {
                'type': 'function',
                'function': {
                    'name': 'enforce_limit',
                    'description': 'Apply bandwidth limit to a specific device IP address. Limits both download and upload speeds in KB/s. Use this to control bandwidth usage after analyzing stats.',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'ip': {
                                'type': 'string',
                                'description': 'The IP address of the device to limit (e.g., "192.168.1.50")'
                            },
                            'download_kbps': {
                                'type': 'integer',
                                'description': 'Download speed limit in KB/s (e.g., 512 for 512KB/s = ~4Mbps)'
                            },
                            'upload_kbps': {
                                'type': 'integer',
                                'description': 'Upload speed limit in KB/s (e.g., 128 for 128KB/s = ~1Mbps)'
                            }
                        },
                        'required': ['ip', 'download_kbps', 'upload_kbps']
                    }
                }
            },
            {
                'type': 'function',
                'function': {
                    'name': 'remove_limit',
                    'description': 'Remove bandwidth limits from a specific device IP address, restoring full speed. Use this to restore normal speed after limiting.',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'ip': {
                                'type': 'string',
                                'description': 'The IP address of the device to restore (e.g., "192.168.1.50")'
                            }
                        },
                        'required': ['ip']
                    }
                }
            }
        ]
    
    def set_protected_ips(self, gateway_ip, host_ip):
        """
        Set IPs that should never be limited (safety guard)
        
        Args:
            gateway_ip: Router/gateway IP address
            host_ip: Host machine IP address
        """
        self.protected_ips.add(gateway_ip)
        self.protected_ips.add(host_ip)
        print(colored(f"[Agent] Protected IPs: {self.protected_ips}", "yellow"))
    
    def get_network_stats(self):
        """
        Tool function: Get current network statistics
        
        Returns:
            dict: Network statistics for all devices
        """
        try:
            stats = self.monitor.get_current_stats()
            
            # Format stats for LLM understanding
            formatted_stats = {
                'devices': [],
                'total_devices': len(stats),
                'timestamp': 'current'
            }
            
            for ip, data in stats.items():
                device_info = {
                    'ip': ip,
                    'upload_kbps': round(data.get('upload_kbps', 0), 2),
                    'download_kbps': round(data.get('download_kbps', 0), 2),
                    'upload_mbps': round(data.get('upload_kbps', 0) / 1024, 2),
                    'download_mbps': round(data.get('download_kbps', 0) / 1024, 2),
                    'status': data.get('status', 'UNKNOWN'),
                    'is_limited': data.get('is_limited', False),
                    'is_protected': ip in self.protected_ips
                }
                formatted_stats['devices'].append(device_info)
            
            return formatted_stats
            
        except Exception as e:
            return {'error': str(e), 'devices': []}
    
    def enforce_limit(self, ip, download_kbps, upload_kbps):
        """
        Tool function: Apply bandwidth limit to a device
        
        Args:
            ip: Device IP address
            download_kbps: Download limit in KB/s
            upload_kbps: Upload limit in KB/s
            
        Returns:
            dict: Result of the operation
        """
        # Safety guard: Never limit protected IPs
        if ip in self.protected_ips:
            return {
                'success': False,
                'message': f'Cannot limit {ip} - it is a protected IP (gateway or host)',
                'ip': ip
            }
        
        try:
            self.controller.apply_limit(ip, download_kbps, upload_kbps)
            return {
                'success': True,
                'message': f'Applied limit to {ip}: ↓{download_kbps}KB/s ({download_kbps/1024:.1f}Mbps) ↑{upload_kbps}KB/s ({upload_kbps/1024:.1f}Mbps)',
                'ip': ip,
                'download_kbps': download_kbps,
                'upload_kbps': upload_kbps
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to limit {ip}: {str(e)}',
                'ip': ip
            }
    
    def remove_limit(self, ip):
        """
        Tool function: Remove bandwidth limit from a device
        
        Args:
            ip: Device IP address
            
        Returns:
            dict: Result of the operation
        """
        try:
            self.controller.remove_limit(ip)
            return {
                'success': True,
                'message': f'Removed limit from {ip} - restored to full speed',
                'ip': ip
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to remove limit from {ip}: {str(e)}',
                'ip': ip
            }
    
    def execute_function(self, name, arguments):
        """
        Execute a function call from the LLM
        
        Args:
            name: Function name
            arguments: Function arguments as dict
            
        Returns:
            dict: Function execution result
        """
        if name == 'get_network_stats':
            return self.get_network_stats()
        
        elif name == 'enforce_limit':
            ip = arguments.get('ip')
            download_kbps = arguments.get('download_kbps')
            upload_kbps = arguments.get('upload_kbps')
            return self.enforce_limit(ip, download_kbps, upload_kbps)
        
        elif name == 'remove_limit':
            ip = arguments.get('ip')
            return self.remove_limit(ip)
        
        else:
            return {'error': f'Unknown function: {name}'}
    
    def chat(self, user_message):
        """
        Chat with the AI agent using natural language
        
        Args:
            user_message: User's natural language command
            
        Returns:
            str: Agent's response
        """
        # Add user message to history
        self.conversation_history.append({
            'role': 'user',
            'content': user_message
        })
        
        # System prompt to guide the agent
        system_prompt = """You are NetMind, an intelligent network bandwidth management assistant. 

Your role:
- Analyze network statistics when users report issues
- Make smart decisions about bandwidth limiting
- Help users optimize their network performance
- Always explain your reasoning and actions

Guidelines:
- When user reports lag/issues, ALWAYS check network stats first using get_network_stats
- Look for devices using excessive bandwidth (high MB/s values)
- Apply reasonable limits (e.g., 2-5 Mbps for normal browsing, 1-2 Mbps for background devices)
- NEVER limit gateway or protected IPs
- Be conversational and helpful
- Explain what you're doing and why

Convert KB/s to Mbps by dividing by 1024 (e.g., 2048 KB/s = 2 Mbps).
Typical limits: Light usage 512KB/s (0.5Mbps), Normal 2048KB/s (2Mbps), Heavy 5120KB/s (5Mbps)."""

        messages = [
            {'role': 'system', 'content': system_prompt}
        ] + self.conversation_history
        
        try:
            print(colored("\n[Agent] Thinking...", "cyan"))
            
            # Call Ollama with tools
            response = self.client.chat(
                model=self.model,
                messages=messages,
                tools=self.tools
            )
            
            # Handle tool calls
            while response['message'].get('tool_calls'):
                # Add assistant message with tool calls to history
                self.conversation_history.append(response['message'])
                
                # Execute each tool call
                for tool in response['message']['tool_calls']:
                    function_name = tool['function']['name']
                    arguments = tool['function']['arguments']
                    
                    print(colored(f"[Agent] Calling: {function_name}({arguments})", "yellow"))
                    
                    # Execute the function
                    function_result = self.execute_function(function_name, arguments)
                    
                    print(colored(f"[Agent] Result: {json.dumps(function_result, indent=2)}", "green"))
                    
                    # Add function result to conversation
                    self.conversation_history.append({
                        'role': 'tool',
                        'content': json.dumps(function_result)
                    })
                
                # Get final response after tool execution
                messages = [
                    {'role': 'system', 'content': system_prompt}
                ] + self.conversation_history
                
                response = self.client.chat(
                    model=self.model,
                    messages=messages,
                    tools=self.tools
                )
            
            # Add final assistant response to history
            assistant_message = response['message']['content']
            self.conversation_history.append({
                'role': 'assistant',
                'content': assistant_message
            })
            
            return assistant_message
            
        except Exception as e:
            error_msg = f"Error communicating with Ollama: {str(e)}\nMake sure Ollama is running with 'ollama serve'"
            return error_msg
    
    def reset_conversation(self):
        """Reset conversation history"""
        self.conversation_history = []
        print(colored("[Agent] Conversation history cleared", "yellow"))
