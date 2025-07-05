import os
import yaml
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class ScanConfig:
    """Configuration for scanning behavior"""
    network_scan_interval: int = 300  # 5 minutes
    endpoint_scan_interval: int = 3600  # 1 hour
    browser_scan_interval: int = 1800  # 30 minutes
    max_connections_per_scan: int = 1000
    enable_real_time_monitoring: bool = True
    enable_browser_extension_scan: bool = True
    enable_cloud_storage_scan: bool = True
    enable_social_media_scan: bool = True

@dataclass
class AlertConfig:
    """Configuration for alerts and notifications"""
    enable_email_alerts: bool = False
    enable_console_alerts: bool = True
    enable_log_file: bool = True
    alert_threshold: str = "medium"  # low, medium, high
    email_recipients: Optional[List[str]] = None
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""

@dataclass
class ReportConfig:
    """Configuration for reporting"""
    enable_html_reports: bool = True
    enable_csv_reports: bool = True
    enable_json_reports: bool = True
    report_directory: str = "reports"
    auto_generate_reports: bool = True
    report_retention_days: int = 30

@dataclass
class SecurityConfig:
    """Configuration for security settings"""
    enable_whitelist: bool = False
    whitelist_domains: Optional[List[str]] = None
    enable_blacklist: bool = False
    blacklist_domains: Optional[List[str]] = None
    enable_user_consent: bool = True
    data_retention_days: int = 90
    encrypt_reports: bool = False

class ConfigManager:
    """Manages configuration for the Shadow IT Detector"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.scan_config = ScanConfig()
        self.alert_config = AlertConfig()
        self.report_config = ReportConfig()
        self.security_config = SecurityConfig()
        self.load_config()
    
    def load_config(self):
        """Load configuration from YAML file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                    self._parse_config(config_data)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
    
    def _parse_config(self, config_data: Dict):
        """Parse configuration data"""
        if 'scan' in config_data:
            scan_data = config_data['scan']
            for key, value in scan_data.items():
                if hasattr(self.scan_config, key):
                    setattr(self.scan_config, key, value)
        
        if 'alerts' in config_data:
            alert_data = config_data['alerts']
            for key, value in alert_data.items():
                if hasattr(self.alert_config, key):
                    setattr(self.alert_config, key, value)
        
        if 'reports' in config_data:
            report_data = config_data['reports']
            for key, value in report_data.items():
                if hasattr(self.report_config, key):
                    setattr(self.report_config, key, value)
        
        if 'security' in config_data:
            security_data = config_data['security']
            for key, value in security_data.items():
                if hasattr(self.security_config, key):
                    setattr(self.security_config, key, value)
    
    def save_config(self):
        """Save current configuration to YAML file"""
        config_data = {
            'scan': self.scan_config.__dict__,
            'alerts': self.alert_config.__dict__,
            'reports': self.report_config.__dict__,
            'security': self.security_config.__dict__
        }
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False)
        except Exception as e:
            print(f"Warning: Could not save config file: {e}")
    
    def get_risk_levels(self) -> Dict[str, List[str]]:
        """Get risk levels for different categories"""
        return {
            'high': ['storage', 'crm', 'payment', 'accounting', 'finance', 'social', 'transportation', 'food', 'travel'],
            'medium': ['communication', 'productivity', 'development', 'support', 'marketing', 'database'],
            'low': ['project_management', 'design', 'content', 'entertainment']
        } 