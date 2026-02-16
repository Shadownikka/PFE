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
            },
            {
                'type': 'function',
                'function': {
                    'name': 'block_device',
                    'description': 'Completely block internet access for a specific device IP address. Use this when user wants to completely cut off a device from internet.',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'ip': {
                                'type': 'string',
                                'description': 'The IP address of the device to block (e.g., "192.168.1.50")'
                            }
                        },
                        'required': ['ip']
                    }
                }
            },
            {
                'type': 'function',
                'function': {
                    'name': 'unblock_device',
                    'description': 'Restore internet access for a previously blocked device IP address. Use this to unblock a device.',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'ip': {
                                'type': 'string',
                                'description': 'The IP address of the device to unblock (e.g., "192.168.1.50")'
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
                # TrafficMonitor returns 'up' and 'down' keys, not 'upload_kbps' and 'download_kbps'
                up_kbps = data.get('up', 0)
                down_kbps = data.get('down', 0)
                
                device_info = {
                    'ip': ip,
                    'upload_kbps': round(up_kbps, 2),
                    'download_kbps': round(down_kbps, 2),
                    'upload_mbps': round(up_kbps / 1024, 2),
                    'download_mbps': round(down_kbps / 1024, 2),
                    'is_active': up_kbps > 1 or down_kbps > 1,  # Consider active if > 1 KB/s
                    'is_limited': ip in self.controller.limits if hasattr(self.controller, 'limits') else False,
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
            # Convert to int in case LLM passes strings
            download_kbps = int(download_kbps)
            upload_kbps = int(upload_kbps)
            
            # Controller returns True/False, not exception
            result = self.controller.apply_limit(ip, download_kbps, upload_kbps)
            print(f"[DEBUG] apply_limit returned: {result} (type: {type(result)})")
            
            if result is True:
                return {
                    'success': True,
                    'message': f'Applied limit to {ip}: ↓{download_kbps}KB/s ({download_kbps/1024:.1f}Mbps) ↑{upload_kbps}KB/s ({upload_kbps/1024:.1f}Mbps)',
                    'ip': ip,
                    'download_kbps': download_kbps,
                    'upload_kbps': upload_kbps
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to limit {ip} - check console for TC error details',
                    'ip': ip
                }
        except ValueError as e:
            return {
                'success': False,
                'message': f'Invalid bandwidth values for {ip}: download={download_kbps}, upload={upload_kbps}',
                'ip': ip
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
    
    def block_device(self, ip):
        """
        Tool function: Completely block internet access for a device
        
        Args:
            ip: Device IP address
            
        Returns:
            dict: Result of the operation
        """
        # Safety guard: Never block protected IPs
        if ip in self.protected_ips:
            return {
                'success': False,
                'message': f'Cannot block {ip} - it is a protected IP (gateway or host)',
                'ip': ip
            }
        
        try:
            # Block by setting extremely low limit (1 KB/s effectively blocks everything)
            result = self.controller.apply_limit(ip, 1, 1)
            
            # Check if the IP is now in limits (successful)
            if ip in self.controller.limits or result is True or result:
                return {
                    'success': True,
                    'message': f'Blocked internet access for {ip} (set to 1KB/s)',
                    'ip': ip,
                    'action': 'blocked'
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to block {ip} - check console for TC error details',
                    'ip': ip
                }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to block {ip}: {str(e)}',
                'ip': ip
            }
    
    def unblock_device(self, ip):
        """
        Tool function: Restore internet access for a blocked device
        
        Args:
            ip: Device IP address
            
        Returns:
            dict: Result of the operation
        """
        try:
            self.controller.remove_limit(ip)
            return {
                'success': True,
                'message': f'Unblocked {ip} - restored full internet access',
                'ip': ip,
                'action': 'unblocked'
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to unblock {ip}: {str(e)}',
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
        
        elif name == 'block_device':
            ip = arguments.get('ip')
            return self.block_device(ip)
        
        elif name == 'unblock_device':
            ip = arguments.get('ip')
            return self.unblock_device(ip)
        
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
        
        # Optimized shorter system prompt for faster responses
        system_prompt = """You are NetMind, a network bandwidth manager. Be brief and direct.

Rules:
- Check stats first: use get_network_stats
- Active device: upload/download > 1 kbps
- Typical limits: 512-5120 KB/s
- NEVER limit gateway/protected IPs
- Use block_device to block (NOT enforce_limit with 0)

IMPORTANT INSTRUCTIONS:
1. READ USER REQUEST CAREFULLY - pay attention to "except", "but", "only", "all but", "everyone except"
2. "Block everyone except X" = block ALL devices EXCEPT device X (keep X unblocked)
3. "Block all but X" = block ALL devices EXCEPT device X (keep X unblocked)
4. "Block only X" = block ONLY device X (block just that one device)
5. When a function executes, state what you DID (past tense), NOT what you could do
6. Double-check your logic before executing - if user says "except", that device should NOT be blocked

Example correct logic:
User: "Block everyone except 192.168.1.5"
Correct action: Block all IPs EXCEPT 192.168.1.5 (leave 192.168.1.5 normal)
Wrong action: Block 192.168.1.5 (this is the OPPOSITE of what was requested!)"""

        # Keep only last 6 messages for speed (3 exchanges)
        recent_history = self.conversation_history[-6:] if len(self.conversation_history) > 6 else self.conversation_history
        
        messages = [
            {'role': 'system', 'content': system_prompt}
        ] + recent_history
        
        try:
            print(colored("\n[Agent] Thinking...", "cyan"))
            
            # Call Ollama with tools (optimized for speed)
            response = self.client.chat(
                model=self.model,
                messages=messages,
                tools=self.tools,
                options={
                    'temperature': 0.3,  # Lower = faster, more deterministic
                    'num_predict': 200,  # Limit response length
                    'top_k': 10,  # Faster token selection
                    'top_p': 0.9,
                }
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
                    tools=self.tools,
                    options={
                        'temperature': 0.3,
                        'num_predict': 200,
                        'top_k': 10,
                        'top_p': 0.9,
                    }
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
