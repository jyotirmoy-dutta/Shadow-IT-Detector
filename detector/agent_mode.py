import json
import time
import threading
import requests
from datetime import datetime
from typing import Dict, List, Optional
import os
import sys

class AgentMode:
    """Agent mode for running Shadow IT Detector as a background service"""
    
    def __init__(self, config, alert_manager, real_time_monitor):
        self.config = config
        self.alert_manager = alert_manager
        self.real_time_monitor = real_time_monitor
        self.agent_id = self._generate_agent_id()
        self.server_url = os.environ.get('SHADOWIT_SERVER_URL', 'http://localhost:8000')
        self.api_key = os.environ.get('SHADOWIT_API_KEY', '')
        self.is_running = False
        self.reporting_thread = None
        
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        import uuid
        import platform
        import socket
        
        hostname = socket.gethostname()
        system = platform.system()
        agent_id = f"{hostname}-{system}-{uuid.uuid4().hex[:8]}"
        return agent_id
    
    def start_agent(self):
        """Start agent mode"""
        if self.is_running:
            print("Agent is already running")
            return
        
        self.is_running = True
        
        # Register with server
        if not self._register_with_server():
            print("Failed to register with server. Running in standalone mode.")
        
        # Start real-time monitoring
        if self.real_time_monitor:
            self.real_time_monitor.start_monitoring()
        
        # Start reporting thread
        self.reporting_thread = threading.Thread(target=self._reporting_loop, daemon=True)
        self.reporting_thread.start()
        
        print(f"Agent started with ID: {self.agent_id}")
        print(f"Reporting to: {self.server_url}")
    
    def stop_agent(self):
        """Stop agent mode"""
        self.is_running = False
        
        if self.real_time_monitor:
            self.real_time_monitor.stop_monitoring()
        
        if self.reporting_thread:
            self.reporting_thread.join(timeout=5)
        
        # Unregister from server
        self._unregister_from_server()
        
        print("Agent stopped")
    
    def _register_with_server(self) -> bool:
        """Register agent with central server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                'platform': sys.platform,
                'python_version': sys.version,
                'capabilities': {
                    'network_scanning': True,
                    'endpoint_scanning': True,
                    'browser_scanning': True,
                    'real_time_monitoring': True
                }
            }
            
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            
            response = requests.post(
                f"{self.server_url}/api/agents/register",
                json=data,
                headers=headers,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Failed to register with server: {e}")
            return False
    
    def _unregister_from_server(self):
        """Unregister agent from central server"""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            
            requests.post(
                f"{self.server_url}/api/agents/unregister",
                json={'agent_id': self.agent_id},
                headers=headers,
                timeout=5
            )
            
        except Exception as e:
            print(f"Failed to unregister from server: {e}")
    
    def _reporting_loop(self):
        """Main reporting loop"""
        while self.is_running:
            try:
                # Collect current status
                status_data = self._collect_status_data()
                
                # Send to server
                self._send_status_to_server(status_data)
                
                # Wait for next report interval
                time.sleep(60)  # Report every minute
                
            except Exception as e:
                print(f"Error in reporting loop: {e}")
                time.sleep(30)  # Wait before retrying
    
    def _collect_status_data(self) -> Dict:
        """Collect current status data"""
        status = {
            'agent_id': self.agent_id,
            'timestamp': datetime.now().isoformat(),
            'monitoring_status': {},
            'alerts': [],
            'findings_summary': {}
        }
        
        # Get monitoring status
        if self.real_time_monitor:
            status['monitoring_status'] = self.real_time_monitor.get_monitoring_status()
        
        # Get recent alerts
        if self.alert_manager:
            alerts_summary = self.alert_manager.get_alerts_summary()
            status['alerts'] = alerts_summary
        
        # Get findings summary (if available)
        # This would be populated from recent scans
        
        return status
    
    def _send_status_to_server(self, status_data: Dict):
        """Send status data to central server"""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            
            response = requests.post(
                f"{self.server_url}/api/agents/status",
                json=status_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"Server returned status {response.status_code}")
                
        except Exception as e:
            print(f"Failed to send status to server: {e}")
    
    def send_findings_to_server(self, findings: Dict):
        """Send scan findings to central server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'timestamp': datetime.now().isoformat(),
                'findings': findings
            }
            
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            
            response = requests.post(
                f"{self.server_url}/api/agents/findings",
                json=data,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                print("Findings sent to server successfully")
            else:
                print(f"Server returned status {response.status_code}")
                
        except Exception as e:
            print(f"Failed to send findings to server: {e}")
    
    def get_server_commands(self) -> List[Dict]:
        """Get commands from central server"""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            
            response = requests.get(
                f"{self.server_url}/api/agents/commands",
                params={'agent_id': self.agent_id},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return []
                
        except Exception as e:
            print(f"Failed to get commands from server: {e}")
            return []
    
    def execute_command(self, command: Dict):
        """Execute command from central server"""
        command_type = command.get('type')
        
        if command_type == 'scan':
            # Trigger a manual scan
            print("Executing manual scan command")
            # This would trigger a scan and send results back
            
        elif command_type == 'update_config':
            # Update configuration
            new_config = command.get('config', {})
            print(f"Updating configuration: {new_config}")
            # This would update the local configuration
            
        elif command_type == 'stop_monitoring':
            # Stop monitoring
            print("Executing stop monitoring command")
            if self.real_time_monitor:
                self.real_time_monitor.stop_monitoring()
                
        elif command_type == 'start_monitoring':
            # Start monitoring
            print("Executing start monitoring command")
            if self.real_time_monitor:
                self.real_time_monitor.start_monitoring()
        
        # Send command acknowledgment
        command_id = command.get('id')
        if command_id:
            self._send_command_ack(command_id)
    
    def _send_command_ack(self, command_id: str):
        """Send command acknowledgment to server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'command_id': command_id,
                'status': 'executed',
                'timestamp': datetime.now().isoformat()
            }
            
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}
            
            requests.post(
                f"{self.server_url}/api/agents/command-ack",
                json=data,
                headers=headers,
                timeout=10
            )
            
        except Exception as e:
            print(f"Failed to send command acknowledgment: {e}")
    
    def run_command_loop(self):
        """Run command processing loop"""
        while self.is_running:
            try:
                commands = self.get_server_commands()
                
                for command in commands:
                    self.execute_command(command)
                
                time.sleep(30)  # Check for commands every 30 seconds
                
            except Exception as e:
                print(f"Error in command loop: {e}")
                time.sleep(60)  # Wait before retrying 