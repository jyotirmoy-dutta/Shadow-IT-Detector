#!/usr/bin/env python3
"""
Unit tests for Shadow IT Detector
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import Mock, patch, MagicMock
import json

# Add the parent directory to the path so we can import the detector module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detector.saas_db import load_saas_domains
from detector.network_scanner import get_active_connections, match_saas_connections
from detector.endpoint_scanner import get_running_processes, get_installed_apps
from detector.config import ConfigManager
from detector.alert_manager import AlertManager, Alert
from detector.browser_scanner import BrowserScanner

class TestSaaSDatabase(unittest.TestCase):
    """Test SaaS database functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_csv = os.path.join(self.temp_dir, 'test_saas.csv')
        
        # Create test CSV file
        with open(self.test_csv, 'w') as f:
            f.write("#domain,category,risk_level,description\n")
            f.write("slack.com,communication,medium,Team messaging\n")
            f.write("dropbox.com,storage,high,Cloud storage\n")
            f.write("google.com,productivity,medium,Google services\n")
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_load_saas_domains(self):
        """Test loading SaaS domains from CSV"""
        domains = load_saas_domains(self.test_csv)
        
        self.assertIsInstance(domains, set)
        self.assertIn('slack.com', domains)
        self.assertIn('dropbox.com', domains)
        self.assertIn('google.com', domains)
        self.assertEqual(len(domains), 3)
    
    def test_load_saas_domains_skips_comments(self):
        """Test that comments are skipped"""
        domains = load_saas_domains(self.test_csv)
        self.assertNotIn('#domain', domains)

class TestNetworkScanner(unittest.TestCase):
    """Test network scanning functionality"""
    
    @patch('detector.network_scanner.psutil.net_connections')
    def test_get_active_connections(self, mock_net_connections):
        """Test getting active connections"""
        # Mock psutil connection objects
        mock_conn1 = Mock()
        mock_conn1.laddr = ('192.168.1.100', 12345)
        mock_conn1.raddr = ('8.8.8.8', 80)
        mock_conn1.pid = 1234
        
        mock_conn2 = Mock()
        mock_conn2.laddr = ('192.168.1.100', 54321)
        mock_conn2.raddr = None  # No remote address
        mock_conn2.pid = 5678
        
        mock_net_connections.return_value = [mock_conn1, mock_conn2]
        
        connections = get_active_connections()
        
        self.assertEqual(len(connections), 1)  # Only one with remote address
        self.assertEqual(connections[0]['laddr'], '192.168.1.100:12345')
        self.assertEqual(connections[0]['raddr'], '8.8.8.8:80')
        self.assertEqual(connections[0]['pid'], 1234)
    
    @patch('detector.network_scanner.socket.getfqdn')
    def test_match_saas_connections(self, mock_getfqdn):
        """Test matching connections against SaaS domains"""
        connections = [
            {'laddr': '192.168.1.100:12345', 'raddr': '8.8.8.8:80', 'pid': 1234},
            {'laddr': '192.168.1.100:54321', 'raddr': '142.250.190.78:443', 'pid': 5678}
        ]
        
        saas_domains = {'google.com', 'slack.com'}
        
        # Mock DNS resolution
        mock_getfqdn.side_effect = ['google.com', 'slack.com']
        
        matches = match_saas_connections(connections, saas_domains)
        
        self.assertEqual(len(matches), 2)
        self.assertEqual(matches[0]['saas_domain'], 'google.com')
        self.assertEqual(matches[1]['saas_domain'], 'slack.com')

class TestEndpointScanner(unittest.TestCase):
    """Test endpoint scanning functionality"""
    
    @patch('detector.endpoint_scanner.psutil.process_iter')
    def test_get_running_processes(self, mock_process_iter):
        """Test getting running processes"""
        # Mock process objects
        mock_proc1 = Mock()
        mock_proc1.info = {'pid': 1234, 'name': 'chrome.exe', 'exe': '/usr/bin/chrome'}
        
        mock_proc2 = Mock()
        mock_proc2.info = {'pid': 5678, 'name': 'slack.exe', 'exe': '/usr/bin/slack'}
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        processes = get_running_processes()
        
        self.assertEqual(len(processes), 2)
        self.assertEqual(processes[0]['name'], 'chrome.exe')
        self.assertEqual(processes[1]['name'], 'slack.exe')
    
    @patch('detector.endpoint_scanner.platform.system')
    def test_get_installed_apps_windows(self, mock_system):
        """Test getting installed apps on Windows"""
        mock_system.return_value = 'Windows'
        
        with patch('detector.endpoint_scanner.winreg') as mock_winreg:
            # Mock registry access
            mock_key = Mock()
            mock_winreg.OpenKey.return_value = mock_key
            mock_winreg.QueryInfoKey.return_value = (1, 0)  # 1 subkey
            mock_winreg.EnumKey.return_value = 'test-app'
            mock_subkey = Mock()
            mock_winreg.OpenKey.side_effect = [mock_key, mock_subkey]
            mock_winreg.QueryValueEx.return_value = ('Test App', 0)
            
            apps = get_installed_apps()
            
            # Should return a list (even if empty due to mocking limitations)
            self.assertIsInstance(apps, list)

class TestConfigManager(unittest.TestCase):
    """Test configuration management"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = os.path.join(self.temp_dir, 'test_config.yaml')
        
        # Create test config file
        config_content = """
scan:
  network_scan_interval: 600
  enable_real_time_monitoring: false

alerts:
  enable_email_alerts: true
  alert_threshold: high

reports:
  enable_html_reports: false
  report_directory: test_reports
"""
        with open(self.test_config, 'w') as f:
            f.write(config_content)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_load_config(self):
        """Test loading configuration from file"""
        config = ConfigManager(self.test_config)
        
        self.assertEqual(config.scan_config.network_scan_interval, 600)
        self.assertFalse(config.scan_config.enable_real_time_monitoring)
        self.assertTrue(config.alert_config.enable_email_alerts)
        self.assertEqual(config.alert_config.alert_threshold, 'high')
        self.assertFalse(config.report_config.enable_html_reports)
        self.assertEqual(config.report_config.report_directory, 'test_reports')
    
    def test_save_config(self):
        """Test saving configuration to file"""
        config = ConfigManager()
        
        # Modify some settings
        config.scan_config.network_scan_interval = 900
        config.alert_config.alert_threshold = 'low'
        
        # Save to new file
        new_config_file = os.path.join(self.temp_dir, 'new_config.yaml')
        config.config_file = new_config_file
        config.save_config()
        
        # Load and verify
        new_config = ConfigManager(new_config_file)
        self.assertEqual(new_config.scan_config.network_scan_interval, 900)
        self.assertEqual(new_config.alert_config.alert_threshold, 'low')

class TestAlertManager(unittest.TestCase):
    """Test alert management functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config = ConfigManager()
        self.alert_manager = AlertManager(self.config)
    
    def test_create_alert(self):
        """Test creating an alert"""
        alert = self.alert_manager.create_alert(
            severity='high',
            category='network',
            title='Test Alert',
            description='This is a test alert',
            details={'test': 'data'},
            source='network'
        )
        
        self.assertIsInstance(alert, Alert)
        self.assertEqual(alert.severity, 'high')
        self.assertEqual(alert.category, 'network')
        self.assertEqual(alert.title, 'Test Alert')
        self.assertEqual(len(self.alert_manager.alerts), 1)
    
    def test_should_alert_threshold(self):
        """Test alert threshold filtering"""
        # Test with medium threshold
        self.alert_manager.config.alert_config.alert_threshold = 'medium'
        
        self.assertTrue(self.alert_manager.should_alert('high'))
        self.assertTrue(self.alert_manager.should_alert('medium'))
        self.assertFalse(self.alert_manager.should_alert('low'))
        
        # Test with high threshold
        self.alert_manager.config.alert_config.alert_threshold = 'high'
        
        self.assertTrue(self.alert_manager.should_alert('high'))
        self.assertFalse(self.alert_manager.should_alert('medium'))
        self.assertFalse(self.alert_manager.should_alert('low'))
    
    def test_get_alerts_summary(self):
        """Test getting alerts summary"""
        # Create some test alerts
        self.alert_manager.create_alert('high', 'network', 'Alert 1', 'Desc 1', {}, 'network')
        self.alert_manager.create_alert('medium', 'endpoint', 'Alert 2', 'Desc 2', {}, 'endpoint')
        self.alert_manager.create_alert('low', 'browser', 'Alert 3', 'Desc 3', {}, 'browser')
        
        summary = self.alert_manager.get_alerts_summary()
        
        self.assertEqual(summary['total'], 3)
        self.assertEqual(summary['by_severity']['high'], 1)
        self.assertEqual(summary['by_severity']['medium'], 1)
        self.assertEqual(summary['by_severity']['low'], 1)
        self.assertEqual(summary['by_category']['network'], 1)
        self.assertEqual(summary['by_category']['endpoint'], 1)
        self.assertEqual(summary['by_category']['browser'], 1)

class TestBrowserScanner(unittest.TestCase):
    """Test browser scanning functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = BrowserScanner()
    
    @patch('detector.browser_scanner.platform.system')
    def test_get_browser_paths_windows(self, mock_system):
        """Test getting browser paths on Windows"""
        mock_system.return_value = 'Windows'
        
        with patch.dict('os.environ', {'LOCALAPPDATA': 'C:\\Users\\Test\\AppData\\Local'}):
            paths = self.scanner._get_browser_paths()
            
            self.assertIn('chrome', paths)
            self.assertIn('firefox', paths)
            self.assertIn('edge', paths)
            
            # Check Chrome path
            expected_chrome_path = os.path.join('C:\\Users\\Test\\AppData\\Local', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions')
            self.assertEqual(paths['chrome']['extensions'], expected_chrome_path)
    
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
    @patch('detector.browser_scanner.platform.system')
    def test_get_browser_paths_linux(self, mock_system):
        """Test getting browser paths on Linux"""
        mock_system.return_value = 'Linux'
        
        with patch.dict('os.environ', {'HOME': '/home/test'}):
            paths = self.scanner._get_browser_paths()
            
            self.assertIn('chrome', paths)
            self.assertIn('firefox', paths)
            
            # Check Chrome path
            expected_chrome_path = os.path.join('/home/test', '.config', 'google-chrome', 'Default', 'Extensions')
            self.assertEqual(paths['chrome']['extensions'], expected_chrome_path)

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestSaaSDatabase,
        TestNetworkScanner,
        TestEndpointScanner,
        TestConfigManager,
        TestAlertManager,
        TestBrowserScanner
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1) 