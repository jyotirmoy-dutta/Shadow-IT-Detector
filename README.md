# 🔍 Shadow IT Detector

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/your-org/shadowit-detector)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](https://github.com/your-org/shadowit-detector/actions)

> **Enterprise-grade Shadow IT detection tool for comprehensive SaaS usage monitoring and security compliance.**

Shadow IT Detector is a robust, cross-platform solution designed to identify unauthorized SaaS applications and services within corporate environments. Built with enterprise security in mind, it provides real-time monitoring, comprehensive reporting, and seamless integration capabilities.

## 🌟 Key Features

### 🔍 **Comprehensive Detection**
- **Network Traffic Analysis**: Real-time monitoring of outbound connections to SaaS domains
- **Endpoint Application Scanning**: Detection of installed SaaS applications and running processes
- **Browser Activity Monitoring**: Extension detection, bookmark analysis, and browsing history scanning
- **Cross-Platform Support**: Windows, macOS, and Linux compatibility

### 🚨 **Real-Time Monitoring**
- **Continuous Background Scanning**: Configurable scan intervals for different detection types
- **Instant Alert System**: Email notifications, console alerts, and comprehensive logging
- **Risk Assessment**: Automatic categorization (High/Medium/Low risk) based on service type
- **Threshold-Based Alerts**: Configurable alert levels to reduce noise

### 📊 **Enterprise Reporting**
- **Multiple Report Formats**: HTML, CSV, JSON with professional styling
- **Auto-Generated Reports**: Scheduled report generation with retention policies
- **Executive Dashboards**: Rich visualizations and risk summaries
- **Audit Trail**: Complete logging for compliance and investigation

### 🏢 **Enterprise Features**
- **Agent Mode**: Centralized management with remote command execution
- **Web Dashboard**: Real-time monitoring interface with REST API
- **Configuration Management**: YAML-based settings with environment-specific configs
- **Docker Support**: Containerized deployment with health checks
- **Zero-Cost Solution**: 100% open source with no licensing fees

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Configuration](#-configuration)
- [Deployment Options](#-deployment-options)
- [API Reference](#-api-reference)
- [Contributing](#-contributing)
- [Security](#-security)
- [License](#-license)

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for full system access)
- Network access for SaaS domain resolution

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/your-org/shadowit-detector.git
cd shadowit-detector

# Install dependencies
pip install -r requirements.txt

# Run initial scan
python -m detector.main
```

### Docker Installation

```bash
# Build and run with Docker
docker build -t shadowit-detector .
docker run -p 5000:5000 shadowit-detector

# Or use Docker Compose for full stack
docker-compose up -d
```

### Package Installation

```bash
# Install from PyPI (when available)
pip install shadowit-detector

# Or install from source
pip install -e .
```

## ⚡ Quick Start

### 1. Basic Scan
```bash
# Run a comprehensive scan
python -m detector.main

# Output: Real-time scan results with findings summary
```

### 2. Real-Time Monitoring
```bash
# Start continuous monitoring
python -m detector.main --monitor

# Press Ctrl+C to stop monitoring
```

### 3. Generate Reports
```bash
# Export findings to multiple formats
python -m detector.main --export-html report.html --export-csv report.csv --export-json report.json
```

### 4. Web Dashboard
```bash
# Start web interface
python -m detector.web_dashboard

# Access at http://localhost:5000
```

## 📖 Usage Examples

### Command Line Interface

```bash
# Basic scan with console output
python -m detector.main

# Real-time monitoring mode
python -m detector.main --monitor

# Export to specific files
python -m detector.main --export-csv findings.csv --export-json findings.json

# Use custom configuration
python -m detector.main --config custom_config.yaml

# Quiet mode (minimal output)
python -m detector.main --quiet

# Agent mode for centralized management
python -m detector.agent_mode
```

### Configuration Examples

```yaml
# config.yaml
scan:
  network_scan_interval: 300      # 5 minutes
  endpoint_scan_interval: 3600    # 1 hour
  browser_scan_interval: 1800     # 30 minutes
  enable_real_time_monitoring: true

alerts:
  enable_email_alerts: true
  alert_threshold: medium
  email_recipients: ["admin@company.com"]
  smtp_server: "smtp.company.com"
  smtp_port: 587

reports:
  enable_html_reports: true
  auto_generate_reports: true
  report_retention_days: 30

security:
  enable_whitelist: true
  whitelist_domains: ["approved-saas.com"]
  data_retention_days: 90
```

### API Usage

```python
from detector.main import ShadowITDetector

# Initialize detector
detector = ShadowITDetector()

# Run scan
findings = detector.run_scan()

# Display results
detector.display_results(findings)

# Generate reports
detector.generate_reports(findings)
```

## ⚙️ Configuration

### Environment Variables

```bash
# Agent mode configuration
export SHADOWIT_SERVER_URL="http://central-server:8000"
export SHADOWIT_API_KEY="your-api-key"

# Database configuration (optional)
export POSTGRES_PASSWORD="your-db-password"
```

### Configuration File Structure

The `config.yaml` file supports the following sections:

- **scan**: Scan intervals and monitoring settings
- **alerts**: Notification and alerting configuration
- **reports**: Report generation and retention settings
- **security**: Whitelist/blacklist and data retention policies

## 🚀 Deployment Options

### 1. Standalone Deployment

```bash
# Build standalone executable
python build.py all

# Run executable
./dist/shadowit-main
```

### 2. Docker Deployment

```bash
# Production deployment
docker-compose -f docker-compose.prod.yml up -d

# Development deployment
docker-compose up -d
```

### 3. Enterprise Agent Deployment

```bash
# Deploy as system service
sudo cp shadowit-agent /usr/local/bin/
sudo systemctl enable shadowit-agent
sudo systemctl start shadowit-agent
```

### 4. Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shadowit-detector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: shadowit-detector
  template:
    metadata:
      labels:
        app: shadowit-detector
    spec:
      containers:
      - name: shadowit-detector
        image: shadowit-detector:latest
        ports:
        - containerPort: 5000
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
```

## 📊 Sample Output

### Console Output
```
╭───────────────────────╮
│ 🔍 Shadow IT Detector │
⠏ SaaS database loaded
⠏ Network scan complete - 5 findings
⠏ Endpoint scan complete - 12 findings
⠏ Browser scan complete - 8 extensions, 23 bookmarks

============================================================
📊 SCAN RESULTS
============================================================
         Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric         ┃ Count ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Total Findings │ 25    │
│ High Risk      │ 3     │
│ Medium Risk    │ 8     │
│ Low Risk       │ 14    │
└────────────────┴───────┘

🌐 Network Connections:
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Service              ┃ Remote Address                               ┃ Process ID                                 ┃ Risk Level                                ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ slack.com            ┃ 52.84.123.45:443                             ┃ 1234                                       ┃ Medium                                    ┃
│ dropbox.com          ┃ 162.125.1.1:443                              ┃ 5678                                       ┃ High                                      ┃
│ zoom.us              ┃ 18.154.227.133:443                           ┃ 9012                                       ┃ Medium                                    ┃
└──────────────────────┴───────────────────────────────────────────────┴───────────────────────────────────────────────┴───────────────────────────────────────────────┘
```

### HTML Report Preview
The generated HTML reports include:
- Executive summary with risk distribution
- Detailed findings tables
- Interactive charts and visualizations
- Export capabilities
- Professional styling

## 🔧 API Reference

### Core Classes

#### `ShadowITDetector`
Main application class for running scans and managing the detection system.

```python
detector = ShadowITDetector()
findings = detector.run_scan()
detector.display_results(findings)
```

#### `ConfigManager`
Manages application configuration and settings.

```python
config = ConfigManager("config.yaml")
config.scan_config.network_scan_interval = 300
config.save_config()
```

#### `AlertManager`
Handles alert generation and notification delivery.

```python
alert_manager = AlertManager(config)
alert = alert_manager.create_alert(
    severity='high',
    category='network',
    title='SaaS Connection Detected',
    description='Unauthorized SaaS service detected',
    details={'service': 'dropbox.com'},
    source='network'
)
```

### REST API Endpoints

When running in web mode, the following endpoints are available:

- `GET /api/stats` - Get current statistics
- `GET /api/findings` - Get latest findings
- `GET /api/alerts` - Get recent alerts
- `POST /api/scan` - Trigger manual scan
- `GET /api/config` - Get current configuration
- `POST /api/config` - Update configuration

## 🛡️ Security

### Privacy & Data Protection
- **Local Analysis**: All scanning and analysis performed locally
- **No Data Exfiltration**: No sensitive data sent to external services
- **Configurable Retention**: Automatic data cleanup based on policies
- **User Consent**: Optional user consent requirements

### Security Features
- **Whitelist/Blacklist**: Domain-based filtering
- **Risk Assessment**: Automatic risk categorization
- **Audit Logging**: Comprehensive activity logging
- **Secure Communication**: TLS encryption for agent-server communication

### Compliance
- **GDPR Compliant**: Configurable data retention and user consent
- **SOC 2 Ready**: Comprehensive logging and audit trails
- **Enterprise Security**: Role-based access and secure configurations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-org/shadowit-detector.git
cd shadowit-detector

# Install development dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Run tests
python -m unittest discover tests

# Run linting
flake8 detector/
black detector/
mypy detector/
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints
- Write comprehensive tests
- Update documentation

## 📈 Roadmap

### Upcoming Features
- [ ] Machine learning-based anomaly detection
- [ ] Integration with SIEM systems
- [ ] Advanced threat intelligence feeds
- [ ] Mobile device monitoring
- [ ] Cloud infrastructure scanning
- [ ] Automated remediation actions

### Version History
- **v1.0.0** - Initial release with core detection capabilities
- **v1.1.0** - Added web dashboard and agent mode
- **v1.2.0** - Enhanced reporting and configuration management

## 🙏 Acknowledgments

- Built with ❤️ by the Shadow IT Detector team
- Inspired by enterprise security challenges
- Powered by the open-source community
- Special thanks to all contributors and users

---

**Ready to secure your enterprise? Get started with Shadow IT Detector today!** 🚀
