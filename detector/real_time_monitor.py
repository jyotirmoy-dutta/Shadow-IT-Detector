import time
import threading
from datetime import datetime
from typing import Dict, List, Callable, Optional
import psutil
import os

# Optional schedule import for advanced scheduling
try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

class RealTimeMonitor:
    """Real-time monitoring system for Shadow IT detection"""
    
    def __init__(self, config, alert_manager, network_scanner, endpoint_scanner, browser_scanner):
        self.config = config
        self.alert_manager = alert_manager
        self.network_scanner = network_scanner
        self.endpoint_scanner = endpoint_scanner
        self.browser_scanner = browser_scanner
        self.is_running = False
        self.monitor_thread = None
        self.previous_findings = {
            'network': set(),
            'endpoint': set(),
            'browser': set()
        }
        self.callbacks = []
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_running:
            print("Monitoring is already running")
            return
        
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("Real-time monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        if SCHEDULE_AVAILABLE:
            # Schedule different types of scans
            schedule.every(self.config.scan_config.network_scan_interval).seconds.do(self._network_scan)
            schedule.every(self.config.scan_config.endpoint_scan_interval).seconds.do(self._endpoint_scan)
            schedule.every(self.config.scan_config.browser_scan_interval).seconds.do(self._browser_scan)
            
            # Run initial scans
            self._network_scan()
            self._endpoint_scan()
            self._browser_scan()
            
            while self.is_running:
                schedule.run_pending()
                time.sleep(1)
        else:
            # Fallback to simple timing without schedule library
            last_network_scan = 0
            last_endpoint_scan = 0
            last_browser_scan = 0
            
            while self.is_running:
                current_time = time.time()
                
                if current_time - last_network_scan >= self.config.scan_config.network_scan_interval:
                    self._network_scan()
                    last_network_scan = current_time
                
                if current_time - last_endpoint_scan >= self.config.scan_config.endpoint_scan_interval:
                    self._endpoint_scan()
                    last_endpoint_scan = current_time
                
                if current_time - last_browser_scan >= self.config.scan_config.browser_scan_interval:
                    self._browser_scan()
                    last_browser_scan = current_time
                
                time.sleep(1)
    
    def _network_scan(self):
        """Perform network scan and check for new findings"""
        try:
            from .saas_db import load_saas_domains
            saas_domains = load_saas_domains()
            
            connections = self.network_scanner.get_active_connections()
            saas_conns = self.network_scanner.match_saas_connections(connections, saas_domains)
            
            # Create unique identifiers for findings
            current_findings = set()
            for conn in saas_conns:
                finding_id = f"{conn.get('saas_domain')}_{conn.get('raddr')}"
                current_findings.add(finding_id)
                
                # Check if this is a new finding
                if finding_id not in self.previous_findings['network']:
                    self._create_network_alert(conn)
            
            self.previous_findings['network'] = current_findings
            
        except Exception as e:
            print(f"Error in network scan: {e}")
    
    def _endpoint_scan(self):
        """Perform endpoint scan and check for new findings"""
        try:
            from .saas_db import load_saas_domains
            saas_domains = load_saas_domains()
            
            processes = self.endpoint_scanner.get_running_processes()
            
            # Create unique identifiers for findings
            current_findings = set()
            for proc in processes:
                proc_name = proc.get('name', '').lower()
                
                # Check if process matches any SaaS service
                for saas in saas_domains:
                    if saas.split('.')[0] in proc_name:
                        finding_id = f"{proc.get('pid')}_{proc_name}"
                        current_findings.add(finding_id)
                        
                        # Check if this is a new finding
                        if finding_id not in self.previous_findings['endpoint']:
                            self._create_endpoint_alert(proc, saas)
                        break
            
            self.previous_findings['endpoint'] = current_findings
            
        except Exception as e:
            print(f"Error in endpoint scan: {e}")
    
    def _browser_scan(self):
        """Perform browser scan and check for new findings"""
        try:
            # Scan browser extensions
            extensions = self.browser_scanner.scan_browser_extensions()
            
            # Create unique identifiers for findings
            current_findings = set()
            for ext in extensions:
                finding_id = f"{ext.get('browser')}_{ext.get('id')}"
                current_findings.add(finding_id)
                
                # Check if this is a new finding
                if finding_id not in self.previous_findings['browser']:
                    self._create_browser_alert(ext)
            
            self.previous_findings['browser'] = current_findings
            
        except Exception as e:
            print(f"Error in browser scan: {e}")
    
    def _create_network_alert(self, connection: Dict):
        """Create alert for network finding"""
        alert = self.alert_manager.create_alert(
            severity='medium',
            category='network',
            title=f"SaaS Network Connection Detected",
            description=f"Connection to {connection.get('saas_domain', 'Unknown SaaS service')}",
            details={
                'saas_domain': connection.get('saas_domain', 'Unknown'),
                'remote_address': connection.get('raddr', 'Unknown'),
                'local_address': connection.get('laddr', 'Unknown'),
                'process_id': connection.get('pid', 'Unknown')
            },
            source='network'
        )
        self.alert_manager.send_alert(alert)
    
    def _create_endpoint_alert(self, process: Dict, saas_domain: str):
        """Create alert for endpoint finding"""
        alert = self.alert_manager.create_alert(
            severity='medium',
            category='endpoint',
            title=f"SaaS Application Detected",
            description=f"Running process related to {saas_domain}",
            details={
                'process_name': process.get('name', 'Unknown'),
                'process_id': process.get('pid', 'Unknown'),
                'executable': process.get('exe', 'Unknown'),
                'saas_domain': saas_domain
            },
            source='endpoint'
        )
        self.alert_manager.send_alert(alert)
    
    def _create_browser_alert(self, extension: Dict):
        """Create alert for browser finding"""
        alert = self.alert_manager.create_alert(
            severity='low',
            category='browser',
            title=f"Browser Extension Detected",
            description=f"Extension {extension.get('name', 'Unknown')} in {extension.get('browser', 'Unknown browser')}",
            details={
                'extension_name': extension.get('name', 'Unknown'),
                'extension_id': extension.get('id', 'Unknown'),
                'browser': extension.get('browser', 'Unknown'),
                'version': extension.get('version', 'Unknown'),
                'description': extension.get('description', 'No description')
            },
            source='browser'
        )
        self.alert_manager.send_alert(alert)
    
    def add_callback(self, callback: Callable):
        """Add callback function to be called when new findings are detected"""
        self.callbacks.append(callback)
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            'is_running': self.is_running,
            'network_findings_count': len(self.previous_findings['network']),
            'endpoint_findings_count': len(self.previous_findings['endpoint']),
            'browser_findings_count': len(self.previous_findings['browser']),
            'scan_intervals': {
                'network': self.config.scan_config.network_scan_interval,
                'endpoint': self.config.scan_config.endpoint_scan_interval,
                'browser': self.config.scan_config.browser_scan_interval
            }
        }
    
    def reset_findings(self):
        """Reset previous findings (useful for testing)"""
        self.previous_findings = {
            'network': set(),
            'endpoint': set(),
            'browser': set()
        }
        print("Previous findings reset") 