import os
import json
import csv
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

class ReportGenerator:
    """Generates comprehensive reports for Shadow IT detection findings"""
    
    def __init__(self, config):
        self.config = config
        self.report_dir = Path(self.config.report_config.report_directory)
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_html_report(self, findings: Dict[str, Any], filename: str = None) -> str:
        """Generate a comprehensive HTML report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shadowit_report_{timestamp}.html"
        
        filepath = self.report_dir / filename
        
        html_content = self._create_html_content(findings)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _create_html_content(self, findings: Dict[str, Any]) -> str:
        """Create HTML content for the report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow IT Detection Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .summary {{
            padding: 30px;
            border-bottom: 1px solid #eee;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .section {{
            padding: 30px;
            border-bottom: 1px solid #eee;
        }}
        .section:last-child {{
            border-bottom: none;
        }}
        .section h2 {{
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .risk-high {{ color: #dc3545; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-low {{ color: #28a745; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 500;
        }}
        .badge-high {{ background-color: #dc3545; color: white; }}
        .badge-medium {{ background-color: #ffc107; color: black; }}
        .badge-low {{ background-color: #28a745; color: white; }}
        .footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Shadow IT Detection Report</h1>
            <p>Generated on {timestamp}</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Findings</h3>
                    <div class="number">{findings.get('total_findings', 0)}</div>
                </div>
                <div class="summary-card">
                    <h3>High Risk</h3>
                    <div class="number risk-high">{findings.get('high_risk_count', 0)}</div>
                </div>
                <div class="summary-card">
                    <h3>Medium Risk</h3>
                    <div class="number risk-medium">{findings.get('medium_risk_count', 0)}</div>
                </div>
                <div class="summary-card">
                    <h3>Low Risk</h3>
                    <div class="number risk-low">{findings.get('low_risk_count', 0)}</div>
                </div>
            </div>
        </div>
        
        {self._generate_network_section(findings.get('network_findings', []))}
        {self._generate_endpoint_section(findings.get('endpoint_findings', []))}
        {self._generate_browser_section(findings.get('browser_findings', []))}
        {self._generate_recommendations_section(findings)}
        
        <div class="footer">
            <p>This report was generated by Shadow IT Detector</p>
            <p>For security inquiries, contact your IT department</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _generate_network_section(self, network_findings: List[Dict]) -> str:
        """Generate HTML for network findings section"""
        if not network_findings:
            return """
        <div class="section">
            <h2>🌐 Network Connections</h2>
            <p>No suspicious network connections detected.</p>
        </div>
            """
        
        html = """
        <div class="section">
            <h2>🌐 Network Connections</h2>
            <table>
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Domain</th>
                        <th>Local Address</th>
                        <th>Remote Address</th>
                        <th>Risk Level</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for finding in network_findings:
            risk_class = f"risk-{finding.get('risk_level', 'low')}"
            badge_class = f"badge-{finding.get('risk_level', 'low')}"
            
            html += f"""
                    <tr>
                        <td>{finding.get('saas_domain', 'Unknown')}</td>
                        <td>{finding.get('fqdn', 'Unknown')}</td>
                        <td>{finding.get('laddr', 'Unknown')}</td>
                        <td>{finding.get('raddr', 'Unknown')}</td>
                        <td><span class="badge {badge_class}">{finding.get('risk_level', 'low').upper()}</span></td>
                        <td>{finding.get('category', 'Unknown')}</td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
        </div>
        """
        
        return html
    
    def _generate_endpoint_section(self, endpoint_findings: List[Dict]) -> str:
        """Generate HTML for endpoint findings section"""
        if not endpoint_findings:
            return """
        <div class="section">
            <h2>💻 Endpoint Applications</h2>
            <p>No suspicious applications detected.</p>
        </div>
            """
        
        html = """
        <div class="section">
            <h2>💻 Endpoint Applications</h2>
            <table>
                <thead>
                    <tr>
                        <th>Application</th>
                        <th>Process ID</th>
                        <th>Executable Path</th>
                        <th>Risk Level</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for finding in endpoint_findings:
            risk_class = f"risk-{finding.get('risk_level', 'low')}"
            badge_class = f"badge-{finding.get('risk_level', 'low')}"
            
            html += f"""
                    <tr>
                        <td>{finding.get('name', 'Unknown')}</td>
                        <td>{finding.get('pid', 'Unknown')}</td>
                        <td>{finding.get('exe', 'Unknown')}</td>
                        <td><span class="badge {badge_class}">{finding.get('risk_level', 'low').upper()}</span></td>
                        <td>{finding.get('category', 'Unknown')}</td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
        </div>
        """
        
        return html
    
    def _generate_browser_section(self, browser_findings: Dict) -> str:
        """Generate HTML for browser findings section"""
        if not browser_findings:
            return """
        <div class="section">
            <h2>🌐 Browser Activity</h2>
            <p>No suspicious browser activity detected.</p>
        </div>
            """
        
        html = """
        <div class="section">
            <h2>🌐 Browser Activity</h2>
        """
        
        # Extensions
        if browser_findings.get('extensions'):
            html += """
            <h3>Browser Extensions</h3>
            <table>
                <thead>
                    <tr>
                        <th>Browser</th>
                        <th>Extension Name</th>
                        <th>Version</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for ext in browser_findings['extensions']:
                html += f"""
                    <tr>
                        <td>{ext.get('browser', 'Unknown')}</td>
                        <td>{ext.get('name', 'Unknown')}</td>
                        <td>{ext.get('version', 'Unknown')}</td>
                        <td>{ext.get('description', 'No description')}</td>
                    </tr>
                """
            
            html += """
                </tbody>
            </table>
            """
        
        # Bookmarks
        if browser_findings.get('bookmarks'):
            html += """
            <h3>Browser Bookmarks</h3>
            <table>
                <thead>
                    <tr>
                        <th>Browser</th>
                        <th>Title</th>
                        <th>URL</th>
                        <th>Date Added</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for bookmark in browser_findings['bookmarks']:
                html += f"""
                    <tr>
                        <td>{bookmark.get('browser', 'Unknown')}</td>
                        <td>{bookmark.get('title', 'Unknown')}</td>
                        <td>{bookmark.get('url', 'Unknown')}</td>
                        <td>{bookmark.get('date_added', 'Unknown')}</td>
                    </tr>
                """
            
            html += """
                </tbody>
            </table>
            """
        
        html += """
        </div>
        """
        
        return html
    
    def _generate_recommendations_section(self, findings: Dict) -> str:
        """Generate HTML for recommendations section"""
        recommendations = []
        
        if findings.get('high_risk_count', 0) > 0:
            recommendations.append("Immediate action required for high-risk findings")
        
        if findings.get('network_findings'):
            recommendations.append("Review network policies and firewall rules")
        
        if findings.get('endpoint_findings'):
            recommendations.append("Implement application whitelisting")
        
        if findings.get('browser_findings'):
            recommendations.append("Review browser extension policies")
        
        if not recommendations:
            recommendations.append("Continue monitoring for new Shadow IT usage")
        
        html = """
        <div class="section">
            <h2>📋 Recommendations</h2>
            <ul>
        """
        
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        
        html += """
            </ul>
        </div>
        """
        
        return html
    
    def generate_csv_report(self, findings: Dict[str, Any], filename: str = None) -> str:
        """Generate CSV report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shadowit_report_{timestamp}.csv"
        
        filepath = self.report_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Type', 'Service/Application', 'Risk Level', 'Category', 'Details', 'Source'])
            
            # Write network findings
            for finding in findings.get('network_findings', []):
                writer.writerow([
                    'Network Connection',
                    finding.get('saas_domain', 'Unknown'),
                    finding.get('risk_level', 'low'),
                    finding.get('category', 'Unknown'),
                    f"Remote: {finding.get('raddr', 'Unknown')}",
                    'Network Scanner'
                ])
            
            # Write endpoint findings
            for finding in findings.get('endpoint_findings', []):
                writer.writerow([
                    'Application',
                    finding.get('name', 'Unknown'),
                    finding.get('risk_level', 'low'),
                    finding.get('category', 'Unknown'),
                    f"PID: {finding.get('pid', 'Unknown')}",
                    'Endpoint Scanner'
                ])
            
            # Write browser findings
            for ext in findings.get('browser_findings', {}).get('extensions', []):
                writer.writerow([
                    'Browser Extension',
                    ext.get('name', 'Unknown'),
                    'low',  # Default risk for extensions
                    'Browser',
                    f"Browser: {ext.get('browser', 'Unknown')}",
                    'Browser Scanner'
                ])
        
        return str(filepath)
    
    def generate_json_report(self, findings: Dict[str, Any], filename: str = None) -> str:
        """Generate JSON report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"shadowit_report_{timestamp}.json"
        
        filepath = self.report_dir / filename
        
        # Add metadata to findings
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '1.0',
                'total_findings': findings.get('total_findings', 0),
                'high_risk_count': findings.get('high_risk_count', 0),
                'medium_risk_count': findings.get('medium_risk_count', 0),
                'low_risk_count': findings.get('low_risk_count', 0)
            },
            'findings': findings
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        return str(filepath)
    
    def cleanup_old_reports(self):
        """Clean up old reports based on retention policy"""
        if not self.config.report_config.report_retention_days:
            return
        
        cutoff_date = datetime.now().timestamp() - (self.config.report_config.report_retention_days * 24 * 3600)
        
        for file_path in self.report_dir.glob("shadowit_report_*"):
            if file_path.stat().st_mtime < cutoff_date:
                try:
                    file_path.unlink()
                except Exception as e:
                    print(f"Could not delete old report {file_path}: {e}") 