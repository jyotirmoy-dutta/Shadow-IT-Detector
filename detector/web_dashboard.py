from flask import Flask, render_template, jsonify, request, redirect, url_for
import json
import os
from datetime import datetime
from typing import Dict, List
import threading
import time

class WebDashboard:
    """Web dashboard for Shadow IT detection monitoring"""
    
    def __init__(self, config, alert_manager, real_time_monitor):
        self.config = config
        self.alert_manager = alert_manager
        self.real_time_monitor = real_time_monitor
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'shadowit-secret-key'
        self.dashboard_data = {
            'findings': [],
            'alerts': [],
            'stats': {
                'total_findings': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'last_scan': None
            }
        }
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            return render_template('dashboard.html', data=self.dashboard_data)
        
        @self.app.route('/api/stats')
        def get_stats():
            return jsonify(self.dashboard_data['stats'])
        
        @self.app.route('/api/findings')
        def get_findings():
            return jsonify(self.dashboard_data['findings'])
        
        @self.app.route('/api/alerts')
        def get_alerts():
            return jsonify(self.dashboard_data['alerts'])
        
        @self.app.route('/api/start-monitoring', methods=['POST'])
        def start_monitoring():
            if self.real_time_monitor:
                self.real_time_monitor.start_monitoring()
                return jsonify({'status': 'success', 'message': 'Monitoring started'})
            return jsonify({'status': 'error', 'message': 'Real-time monitor not available'})
        
        @self.app.route('/api/stop-monitoring', methods=['POST'])
        def stop_monitoring():
            if self.real_time_monitor:
                self.real_time_monitor.stop_monitoring()
                return jsonify({'status': 'success', 'message': 'Monitoring stopped'})
            return jsonify({'status': 'error', 'message': 'Real-time monitor not available'})
        
        @self.app.route('/api/scan', methods=['POST'])
        def run_scan():
            # This would trigger a manual scan
            return jsonify({'status': 'success', 'message': 'Scan initiated'})
        
        @self.app.route('/api/config', methods=['GET', 'POST'])
        def config():
            if request.method == 'POST':
                # Update configuration
                data = request.json
                # Update config based on data
                return jsonify({'status': 'success', 'message': 'Configuration updated'})
            else:
                # Return current configuration
                return jsonify({
                    'scan': self.config.scan_config.__dict__,
                    'alerts': self.config.alert_config.__dict__,
                    'reports': self.config.report_config.__dict__,
                    'security': self.config.security_config.__dict__
                })
    
    def update_dashboard_data(self, findings: Dict, alerts: List):
        """Update dashboard data with new findings and alerts"""
        self.dashboard_data['findings'] = findings
        self.dashboard_data['alerts'] = [alert.__dict__ for alert in alerts]
        self.dashboard_data['stats'] = {
            'total_findings': findings.get('total_findings', 0),
            'high_risk': findings.get('high_risk_count', 0),
            'medium_risk': findings.get('medium_risk_count', 0),
            'low_risk': findings.get('low_risk_count', 0),
            'last_scan': datetime.now().isoformat()
        }
    
    def start_dashboard(self, host='0.0.0.0', port=5000, debug=False):
        """Start the web dashboard"""
        print(f"Starting web dashboard at http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)
    
    def create_templates(self):
        """Create HTML templates for the dashboard"""
        templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
        os.makedirs(templates_dir, exist_ok=True)
        
        # Create base template
        base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow IT Detector Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-shield-alt"></i> Shadow IT Detector
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text" id="last-update">
                    Last updated: <span id="update-time">Never</span>
                </span>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh dashboard data
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-findings').textContent = data.total_findings;
                    document.getElementById('high-risk').textContent = data.high_risk;
                    document.getElementById('medium-risk').textContent = data.medium_risk;
                    document.getElementById('low-risk').textContent = data.low_risk;
                    document.getElementById('update-time').textContent = new Date().toLocaleTimeString();
                });
        }

        // Update every 30 seconds
        setInterval(updateDashboard, 30000);
        updateDashboard();
    </script>
</body>
</html>
        """
        
        # Create dashboard template
        dashboard_template = """
{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h1 class="mb-4">Dashboard</h1>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <h5 class="card-title">Total Findings</h5>
                <h2 id="total-findings">0</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-danger text-white">
            <div class="card-body">
                <h5 class="card-title">High Risk</h5>
                <h2 id="high-risk">0</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-dark">
            <div class="card-body">
                <h5 class="card-title">Medium Risk</h5>
                <h2 id="medium-risk">0</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body">
                <h5 class="card-title">Low Risk</h5>
                <h2 id="low-risk">0</h2>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>Recent Alerts</h5>
            </div>
            <div class="card-body">
                <div id="alerts-list">
                    <p class="text-muted">No recent alerts</p>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>Risk Distribution</h5>
            </div>
            <div class="card-body">
                <canvas id="riskChart" width="400" height="200"></canvas>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5>Recent Findings</h5>
            </div>
            <div class="card-body">
                <div id="findings-list">
                    <p class="text-muted">No recent findings</p>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    // Initialize risk chart
    const ctx = document.getElementById('riskChart').getContext('2d');
    const riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High Risk', 'Medium Risk', 'Low Risk'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#dc3545', '#ffc107', '#28a745']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });

    // Update chart data
    function updateChart() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                riskChart.data.datasets[0].data = [
                    data.high_risk,
                    data.medium_risk,
                    data.low_risk
                ];
                riskChart.update();
            });
    }

    setInterval(updateChart, 30000);
    updateChart();
</script>
{% endblock %}
        """
        
        # Write templates
        with open(os.path.join(templates_dir, 'base.html'), 'w') as f:
            f.write(base_template)
        
        with open(os.path.join(templates_dir, 'dashboard.html'), 'w') as f:
            f.write(dashboard_template) 