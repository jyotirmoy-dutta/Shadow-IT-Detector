import smtplib
import logging
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
from dataclasses import dataclass

# Optional rich imports for enhanced console output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

@dataclass
class Alert:
    """Represents a security alert"""
    timestamp: datetime
    severity: str  # low, medium, high
    category: str
    title: str
    description: str
    details: Dict
    source: str  # network, endpoint, browser

class AlertManager:
    """Manages alerts and notifications for Shadow IT detection"""
    
    def __init__(self, config):
        self.config = config
        self.console = Console() if RICH_AVAILABLE else None
        self.logger = self._setup_logger()
        self.alerts = []
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('shadowit_detector')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # File handler
        if self.config.alert_config.enable_log_file:
            file_handler = logging.FileHandler('logs/shadowit_alerts.log')
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def create_alert(self, severity: str, category: str, title: str, 
                    description: str, details: Dict, source: str) -> Alert:
        """Create a new alert"""
        alert = Alert(
            timestamp=datetime.now(),
            severity=severity,
            category=category,
            title=title,
            description=description,
            details=details,
            source=source
        )
        
        self.alerts.append(alert)
        return alert
    
    def should_alert(self, severity: str) -> bool:
        """Check if alert should be triggered based on threshold"""
        severity_levels = {'low': 1, 'medium': 2, 'high': 3}
        threshold_levels = {'low': 1, 'medium': 2, 'high': 3}
        
        alert_level = severity_levels.get(severity, 1)
        threshold_level = threshold_levels.get(self.config.alert_config.alert_threshold, 2)
        
        return alert_level >= threshold_level
    
    def send_alert(self, alert: Alert):
        """Send alert through configured channels"""
        if not self.should_alert(alert.severity):
            return
        
        # Log the alert
        self.logger.warning(f"ALERT: {alert.severity.upper()} - {alert.title}: {alert.description}")
        
        # Console alert
        if self.config.alert_config.enable_console_alerts:
            self._send_console_alert(alert)
        
        # Email alert
        if self.config.alert_config.enable_email_alerts:
            self._send_email_alert(alert)
    
    def _send_console_alert(self, alert: Alert):
        """Send alert to console with rich formatting"""
        # Create severity color mapping
        severity_colors = {
            'low': 'green',
            'medium': 'yellow',
            'high': 'red'
        }
        
        color = severity_colors.get(alert.severity, 'white')
        
        # Create alert panel
        alert_text = Text()
        alert_text.append(f"🚨 {alert.title}\n", style=f"bold {color}")
        alert_text.append(f"Category: {alert.category}\n", style="cyan")
        alert_text.append(f"Source: {alert.source}\n", style="cyan")
        alert_text.append(f"Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")
        alert_text.append(f"\n{alert.description}", style="white")
        
        panel = Panel(
            alert_text,
            title=f"[{color}]Shadow IT Alert - {alert.severity.upper()}[/{color}]",
            border_style=color
        )
        
        self.console.print(panel)
    
    def _send_email_alert(self, alert: Alert):
        """Send alert via email"""
        if not self.config.alert_config.email_recipients:
            return
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config.alert_config.smtp_username
            msg['To'] = ', '.join(self.config.alert_config.email_recipients)
            msg['Subject'] = f"Shadow IT Alert: {alert.severity.upper()} - {alert.title}"
            
            # Create email body
            body = f"""
Shadow IT Detection Alert

Severity: {alert.severity.upper()}
Category: {alert.category}
Source: {alert.source}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

Title: {alert.title}
Description: {alert.description}

Details:
"""
            
            # Add details
            for key, value in alert.details.items():
                body += f"{key}: {value}\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(
                self.config.alert_config.smtp_server,
                self.config.alert_config.smtp_port
            )
            server.starttls()
            server.login(
                self.config.alert_config.smtp_username,
                self.config.alert_config.smtp_password
            )
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent to {self.config.alert_config.email_recipients}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def get_alerts_summary(self) -> Dict:
        """Get summary of all alerts"""
        if not self.alerts:
            return {'total': 0, 'by_severity': {}, 'by_category': {}}
        
        summary = {
            'total': len(self.alerts),
            'by_severity': {},
            'by_category': {},
            'by_source': {}
        }
        
        for alert in self.alerts:
            # Count by severity
            summary['by_severity'][alert.severity] = summary['by_severity'].get(alert.severity, 0) + 1
            
            # Count by category
            summary['by_category'][alert.category] = summary['by_category'].get(alert.category, 0) + 1
            
            # Count by source
            summary['by_source'][alert.source] = summary['by_source'].get(alert.source, 0) + 1
        
        return summary
    
    def display_alerts_summary(self):
        """Display alerts summary in console"""
        summary = self.get_alerts_summary()
        
        if summary['total'] == 0:
            self.console.print("[green]No alerts generated.[/green]")
            return
        
        # Create summary table
        table = Table(title="Shadow IT Alerts Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")
        
        table.add_row("Total Alerts", str(summary['total']))
        
        # Add severity breakdown
        for severity, count in summary['by_severity'].items():
            table.add_row(f"  {severity.title()} Severity", str(count))
        
        # Add category breakdown
        for category, count in summary['by_category'].items():
            table.add_row(f"  {category.title()} Category", str(count))
        
        # Add source breakdown
        for source, count in summary['by_source'].items():
            table.add_row(f"  {source.title()} Source", str(count))
        
        self.console.print(table)
    
    def clear_alerts(self):
        """Clear all stored alerts"""
        self.alerts.clear()
        self.logger.info("All alerts cleared")
    
    def export_alerts(self, filename: str, format: str = 'json'):
        """Export alerts to file"""
        import json
        import csv
        
        if not self.alerts:
            return
        
        try:
            if format.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump([{
                        'timestamp': alert.timestamp.isoformat(),
                        'severity': alert.severity,
                        'category': alert.category,
                        'title': alert.title,
                        'description': alert.description,
                        'details': alert.details,
                        'source': alert.source
                    } for alert in self.alerts], f, indent=2)
            
            elif format.lower() == 'csv':
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Severity', 'Category', 'Title', 'Description', 'Source'])
                    for alert in self.alerts:
                        writer.writerow([
                            alert.timestamp.isoformat(),
                            alert.severity,
                            alert.category,
                            alert.title,
                            alert.description,
                            alert.source
                        ])
            
            self.logger.info(f"Alerts exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to export alerts: {e}") 