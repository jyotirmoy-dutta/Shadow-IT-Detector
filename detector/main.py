import argparse
import sys
import os
from datetime import datetime

# Optional rich imports for enhanced console output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Import our modules
from .config import ConfigManager
from .saas_db import load_saas_domains
from .network_scanner import get_active_connections, match_saas_connections
from .endpoint_scanner import get_running_processes, get_installed_apps
from .browser_scanner import BrowserScanner
from .alert_manager import AlertManager
from .report_generator import ReportGenerator
from .real_time_monitor import RealTimeMonitor

class ShadowITDetector:
    """Main Shadow IT Detection application"""
    
    def __init__(self):
        self.console = Console()
        self.config = ConfigManager()
        self.alert_manager = AlertManager(self.config)
        self.browser_scanner = BrowserScanner()
        self.report_generator = ReportGenerator(self.config)
        self.real_time_monitor = None
        
    def run_scan(self, args):
        """Run a comprehensive scan"""
        self.console.print(Panel.fit("🔍 Shadow IT Detector", style="bold blue"))
        
        findings = {
            'network_findings': [],
            'endpoint_findings': [],
            'browser_findings': {},
            'total_findings': 0,
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Load SaaS database
            task = progress.add_task("Loading SaaS database...", total=None)
            saas_domains = load_saas_domains()
            progress.update(task, description="SaaS database loaded")
            
            # Network scan
            task = progress.add_task("Scanning network connections...", total=None)
            connections = get_active_connections()
            saas_conns = match_saas_connections(connections, saas_domains)
            findings['network_findings'] = saas_conns
            progress.update(task, description=f"Network scan complete - {len(saas_conns)} findings")
            
            # Endpoint scan
            task = progress.add_task("Scanning endpoint applications...", total=None)
            processes = get_running_processes()
            apps = get_installed_apps()
            
            # Match processes and apps against SaaS domains
            endpoint_findings = []
            for proc in processes:
                proc_name = proc.get('name', '').lower()
                for saas in saas_domains:
                    if saas.split('.')[0] in proc_name:
                        endpoint_findings.append({
                            **proc,
                            'saas_domain': saas,
                            'type': 'process'
                        })
                        break
            
            for app in apps:
                app_name = app.lower()
                for saas in saas_domains:
                    if saas.split('.')[0] in app_name:
                        endpoint_findings.append({
                            'name': app,
                            'saas_domain': saas,
                            'type': 'application'
                        })
                        break
            
            findings['endpoint_findings'] = endpoint_findings
            progress.update(task, description=f"Endpoint scan complete - {len(endpoint_findings)} findings")
            
            # Browser scan
            if self.config.scan_config.enable_browser_extension_scan:
                task = progress.add_task("Scanning browser activity...", total=None)
                extensions = self.browser_scanner.scan_browser_extensions()
                bookmarks = self.browser_scanner.scan_browser_bookmarks()
                history = self.browser_scanner.scan_browser_history()
                
                findings['browser_findings'] = {
                    'extensions': extensions,
                    'bookmarks': bookmarks,
                    'history': history
                }
                progress.update(task, description=f"Browser scan complete - {len(extensions)} extensions, {len(bookmarks)} bookmarks")
        
        # Calculate totals and risk levels
        findings['total_findings'] = (
            len(findings['network_findings']) + 
            len(findings['endpoint_findings']) + 
            len(findings['browser_findings'].get('extensions', []))
        )
        
        # Count by risk level (simplified - you can enhance this based on your SaaS database)
        for finding in findings['network_findings'] + findings['endpoint_findings']:
            risk_level = finding.get('risk_level', 'medium')
            if risk_level == 'high':
                findings['high_risk_count'] += 1
            elif risk_level == 'medium':
                findings['medium_risk_count'] += 1
            else:
                findings['low_risk_count'] += 1
        
        return findings
    
    def display_results(self, findings):
        """Display scan results in console"""
        self.console.print("\n" + "="*60)
        self.console.print("📊 SCAN RESULTS", style="bold blue")
        self.console.print("="*60)
        
        # Summary table
        summary_table = Table(title="Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="magenta")
        
        summary_table.add_row("Total Findings", str(findings['total_findings']))
        summary_table.add_row("High Risk", str(findings['high_risk_count']))
        summary_table.add_row("Medium Risk", str(findings['medium_risk_count']))
        summary_table.add_row("Low Risk", str(findings['low_risk_count']))
        
        self.console.print(summary_table)
        
        # Network findings
        if findings['network_findings']:
            self.console.print("\n🌐 Network Connections:", style="bold")
            network_table = Table()
            network_table.add_column("Service", style="cyan")
            network_table.add_column("Remote Address", style="yellow")
            network_table.add_column("Process ID", style="green")
            
            for finding in findings['network_findings']:
                network_table.add_row(
                    finding.get('saas_domain', 'Unknown'),
                    finding.get('raddr', 'Unknown'),
                    str(finding.get('pid', 'Unknown'))
                )
            self.console.print(network_table)
        
        # Endpoint findings
        if findings['endpoint_findings']:
            self.console.print("\n💻 Endpoint Applications:", style="bold")
            endpoint_table = Table()
            endpoint_table.add_column("Application", style="cyan")
            endpoint_table.add_column("Type", style="yellow")
            endpoint_table.add_column("SaaS Domain", style="green")
            
            for finding in findings['endpoint_findings']:
                endpoint_table.add_row(
                    finding.get('name', 'Unknown'),
                    finding.get('type', 'Unknown'),
                    finding.get('saas_domain', 'Unknown')
                )
            self.console.print(endpoint_table)
        
        # Browser findings
        browser_findings = findings['browser_findings']
        if browser_findings.get('extensions'):
            self.console.print("\n🌐 Browser Extensions:", style="bold")
            browser_table = Table()
            browser_table.add_column("Browser", style="cyan")
            browser_table.add_column("Extension", style="yellow")
            browser_table.add_column("Version", style="green")
            
            for ext in browser_findings['extensions']:
                browser_table.add_row(
                    ext.get('browser', 'Unknown'),
                    ext.get('name', 'Unknown'),
                    ext.get('version', 'Unknown')
                )
            self.console.print(browser_table)
    
    def generate_reports(self, findings, args):
        """Generate reports based on command line arguments"""
        if args.export_csv:
            csv_file = self.report_generator.generate_csv_report(findings, args.export_csv)
            self.console.print(f"📄 CSV report generated: {csv_file}")
        
        if args.export_json:
            json_file = self.report_generator.generate_json_report(findings, args.export_json)
            self.console.print(f"📄 JSON report generated: {json_file}")
        
        if args.export_html:
            html_file = self.report_generator.generate_html_report(findings, args.export_html)
            self.console.print(f"📄 HTML report generated: {html_file}")
        
        # Auto-generate reports if enabled
        if self.config.report_config.auto_generate_reports:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if self.config.report_config.enable_html_reports:
                html_file = self.report_generator.generate_html_report(findings, f"auto_report_{timestamp}.html")
                self.console.print(f"📄 Auto-generated HTML report: {html_file}")
            
            if self.config.report_config.enable_csv_reports:
                csv_file = self.report_generator.generate_csv_report(findings, f"auto_report_{timestamp}.csv")
                self.console.print(f"📄 Auto-generated CSV report: {csv_file}")
    
    def start_monitoring(self, args):
        """Start real-time monitoring"""
        if not self.real_time_monitor:
            from .network_scanner import get_active_connections, match_saas_connections
            from .endpoint_scanner import get_running_processes, get_installed_apps
            
            # Create scanner instances
            class NetworkScanner:
                def get_active_connections(self):
                    return get_active_connections()
                
                def match_saas_connections(self, connections, saas_domains):
                    return match_saas_connections(connections, saas_domains)
            
            class EndpointScanner:
                def get_running_processes(self):
                    return get_running_processes()
                
                def get_installed_apps(self):
                    return get_installed_apps()
            
            self.real_time_monitor = RealTimeMonitor(
                self.config,
                self.alert_manager,
                NetworkScanner(),
                EndpointScanner(),
                self.browser_scanner
            )
        
        self.console.print("🚀 Starting real-time monitoring...")
        self.real_time_monitor.start_monitoring()
        
        try:
            while True:
                # Keep the main thread alive
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            self.console.print("\n⏹️ Stopping real-time monitoring...")
            self.real_time_monitor.stop_monitoring()
            self.alert_manager.display_alerts_summary()

def main():
    parser = argparse.ArgumentParser(
        description='Shadow IT Detector - Comprehensive SaaS Usage Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m detector.main                    # Run full scan
  python -m detector.main --monitor          # Start real-time monitoring
  python -m detector.main --export-csv report.csv
  python -m detector.main --export-html report.html
  python -m detector.main --export-json report.json
        """
    )
    
    parser.add_argument('--monitor', action='store_true',
                       help='Start real-time monitoring mode')
    parser.add_argument('--export-csv', metavar='FILE',
                       help='Export findings to CSV file')
    parser.add_argument('--export-json', metavar='FILE',
                       help='Export findings to JSON file')
    parser.add_argument('--export-html', metavar='FILE',
                       help='Export findings to HTML file')
    parser.add_argument('--config', metavar='FILE',
                       help='Use custom configuration file')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress console output')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = ShadowITDetector()
    
    if args.config:
        detector.config = ConfigManager(args.config)
    
    if args.quiet:
        detector.console = Console(quiet=True)
    
    try:
        if args.monitor:
            detector.start_monitoring(args)
        else:
            # Run scan
            findings = detector.run_scan(args)
            detector.display_results(findings)
            detector.generate_reports(findings, args)
            
            # Display alerts summary
            detector.alert_manager.display_alerts_summary()
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 