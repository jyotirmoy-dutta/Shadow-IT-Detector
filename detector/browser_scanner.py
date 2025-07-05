import os
import json
import sqlite3
import platform
from pathlib import Path
from typing import List, Dict, Optional
import shutil

class BrowserScanner:
    """Scans browsers for SaaS usage including extensions, bookmarks, and history"""
    
    def __init__(self):
        self.system = platform.system()
        self.browser_paths = self._get_browser_paths()
    
    def _get_browser_paths(self) -> Dict[str, Dict[str, str]]:
        """Get browser data paths for different operating systems"""
        paths = {}
        
        if self.system == "Windows":
            appdata = os.environ.get('APPDATA', '')
            local_appdata = os.environ.get('LOCALAPPDATA', '')
            
            paths = {
                'chrome': {
                    'extensions': os.path.join(local_appdata, 'Google', 'Chrome', 'User Data', 'Default', 'Extensions'),
                    'bookmarks': os.path.join(local_appdata, 'Google', 'Chrome', 'User Data', 'Default', 'Bookmarks'),
                    'history': os.path.join(local_appdata, 'Google', 'Chrome', 'User Data', 'Default', 'History')
                },
                'firefox': {
                    'extensions': os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles'),
                    'bookmarks': os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles'),
                    'history': os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')
                },
                'edge': {
                    'extensions': os.path.join(local_appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions'),
                    'bookmarks': os.path.join(local_appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'Bookmarks'),
                    'history': os.path.join(local_appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'History')
                }
            }
        
        elif self.system == "Darwin":  # macOS
            home = os.path.expanduser("~")
            
            paths = {
                'chrome': {
                    'extensions': os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions'),
                    'bookmarks': os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Bookmarks'),
                    'history': os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'History')
                },
                'firefox': {
                    'extensions': os.path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles'),
                    'bookmarks': os.path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles'),
                    'history': os.path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')
                },
                'safari': {
                    'extensions': os.path.join(home, 'Library', 'Safari', 'Extensions'),
                    'bookmarks': os.path.join(home, 'Library', 'Safari', 'Bookmarks.plist'),
                    'history': os.path.join(home, 'Library', 'Safari', 'History.db')
                }
            }
        
        elif self.system == "Linux":
            home = os.path.expanduser("~")
            
            paths = {
                'chrome': {
                    'extensions': os.path.join(home, '.config', 'google-chrome', 'Default', 'Extensions'),
                    'bookmarks': os.path.join(home, '.config', 'google-chrome', 'Default', 'Bookmarks'),
                    'history': os.path.join(home, '.config', 'google-chrome', 'Default', 'History')
                },
                'firefox': {
                    'extensions': os.path.join(home, '.mozilla', 'firefox'),
                    'bookmarks': os.path.join(home, '.mozilla', 'firefox'),
                    'history': os.path.join(home, '.mozilla', 'firefox')
                }
            }
        
        return paths
    
    def scan_browser_extensions(self) -> List[Dict]:
        """Scan for browser extensions that might be SaaS-related"""
        extensions = []
        
        for browser, paths in self.browser_paths.items():
            ext_path = paths.get('extensions')
            if not ext_path or not os.path.exists(ext_path):
                continue
            
            try:
                if browser == 'chrome' or browser == 'edge':
                    extensions.extend(self._scan_chrome_extensions(ext_path, browser))
                elif browser == 'firefox':
                    extensions.extend(self._scan_firefox_extensions(ext_path, browser))
                elif browser == 'safari':
                    extensions.extend(self._scan_safari_extensions(ext_path, browser))
            except Exception as e:
                print(f"Error scanning {browser} extensions: {e}")
        
        return extensions
    
    def _scan_chrome_extensions(self, ext_path: str, browser: str) -> List[Dict]:
        """Scan Chrome/Edge extensions"""
        extensions = []
        
        if not os.path.exists(ext_path):
            return extensions
        
        for ext_id in os.listdir(ext_path):
            ext_dir = os.path.join(ext_path, ext_id)
            if os.path.isdir(ext_dir):
                # Look for manifest.json in version subdirectories
                for version_dir in os.listdir(ext_dir):
                    manifest_path = os.path.join(ext_dir, version_dir, 'manifest.json')
                    if os.path.exists(manifest_path):
                        try:
                            with open(manifest_path, 'r', encoding='utf-8') as f:
                                manifest = json.load(f)
                                ext_info = {
                                    'browser': browser,
                                    'id': ext_id,
                                    'name': manifest.get('name', 'Unknown'),
                                    'version': manifest.get('version', 'Unknown'),
                                    'description': manifest.get('description', ''),
                                    'permissions': manifest.get('permissions', []),
                                    'host_permissions': manifest.get('host_permissions', [])
                                }
                                extensions.append(ext_info)
                                break  # Only get the first version found
                        except Exception:
                            continue
        
        return extensions
    
    def _scan_firefox_extensions(self, ext_path: str, browser: str) -> List[Dict]:
        """Scan Firefox extensions"""
        extensions = []
        
        # Firefox stores extensions in profile directories
        if os.path.exists(ext_path):
            for profile_dir in os.listdir(ext_path):
                if profile_dir.endswith('.default') or profile_dir.endswith('.default-release'):
                    profile_path = os.path.join(ext_path, profile_dir)
                    extensions_path = os.path.join(profile_path, 'extensions')
                    
                    if os.path.exists(extensions_path):
                        for ext_file in os.listdir(extensions_path):
                            ext_path_full = os.path.join(extensions_path, ext_file)
                            if ext_file.endswith('.xpi') or os.path.isdir(ext_path_full):
                                ext_info = {
                                    'browser': browser,
                                    'id': ext_file,
                                    'name': ext_file,
                                    'version': 'Unknown',
                                    'description': '',
                                    'permissions': [],
                                    'host_permissions': []
                                }
                                extensions.append(ext_info)
        
        return extensions
    
    def _scan_safari_extensions(self, ext_path: str, browser: str) -> List[Dict]:
        """Scan Safari extensions"""
        extensions = []
        
        if os.path.exists(ext_path):
            for ext_file in os.listdir(ext_path):
                if ext_file.endswith('.safariextz') or ext_file.endswith('.safariextension'):
                    ext_info = {
                        'browser': browser,
                        'id': ext_file,
                        'name': ext_file,
                        'version': 'Unknown',
                        'description': '',
                        'permissions': [],
                        'host_permissions': []
                    }
                    extensions.append(ext_info)
        
        return extensions
    
    def scan_browser_bookmarks(self) -> List[Dict]:
        """Scan browser bookmarks for SaaS domains"""
        bookmarks = []
        
        for browser, paths in self.browser_paths.items():
            bookmark_path = paths.get('bookmarks')
            if not bookmark_path or not os.path.exists(bookmark_path):
                continue
            
            try:
                if browser in ['chrome', 'edge']:
                    bookmarks.extend(self._scan_chrome_bookmarks(bookmark_path, browser))
                elif browser == 'firefox':
                    bookmarks.extend(self._scan_firefox_bookmarks(bookmark_path, browser))
            except Exception as e:
                print(f"Error scanning {browser} bookmarks: {e}")
        
        return bookmarks
    
    def _scan_chrome_bookmarks(self, bookmark_path: str, browser: str) -> List[Dict]:
        """Scan Chrome/Edge bookmarks"""
        bookmarks = []
        
        try:
            with open(bookmark_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            def extract_bookmarks(bookmark_data):
                results = []
                if 'children' in bookmark_data:
                    for child in bookmark_data['children']:
                        if child.get('type') == 'url':
                            results.append({
                                'browser': browser,
                                'title': child.get('name', ''),
                                'url': child.get('url', ''),
                                'date_added': child.get('date_added', 0)
                            })
                        elif child.get('type') == 'folder':
                            results.extend(extract_bookmarks(child))
                return results
            
            if 'roots' in data:
                for root_name, root_data in data['roots'].items():
                    bookmarks.extend(extract_bookmarks(root_data))
        
        except Exception as e:
            print(f"Error reading Chrome bookmarks: {e}")
        
        return bookmarks
    
    def _scan_firefox_bookmarks(self, bookmark_path: str, browser: str) -> List[Dict]:
        """Scan Firefox bookmarks"""
        bookmarks = []
        
        # Firefox stores bookmarks in SQLite databases within profile directories
        if os.path.exists(bookmark_path):
            for profile_dir in os.listdir(bookmark_path):
                if profile_dir.endswith('.default') or profile_dir.endswith('.default-release'):
                    profile_path = os.path.join(bookmark_path, profile_dir)
                    places_path = os.path.join(profile_path, 'places.sqlite')
                    
                    if os.path.exists(places_path):
                        try:
                            # Create a copy to avoid database lock issues
                            temp_path = places_path + '.temp'
                            shutil.copy2(places_path, temp_path)
                            
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            
                            cursor.execute("""
                                SELECT moz_bookmarks.title, moz_places.url, moz_bookmarks.dateAdded
                                FROM moz_bookmarks
                                JOIN moz_places ON moz_bookmarks.fk = moz_places.id
                                WHERE moz_bookmarks.type = 1
                            """)
                            
                            for row in cursor.fetchall():
                                bookmarks.append({
                                    'browser': browser,
                                    'title': row[0] or '',
                                    'url': row[1] or '',
                                    'date_added': row[2] or 0
                                })
                            
                            conn.close()
                            os.remove(temp_path)
                            
                        except Exception as e:
                            print(f"Error reading Firefox bookmarks: {e}")
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
        
        return bookmarks
    
    def scan_browser_history(self) -> List[Dict]:
        """Scan browser history for SaaS domains"""
        history = []
        
        for browser, paths in self.browser_paths.items():
            history_path = paths.get('history')
            if not history_path or not os.path.exists(history_path):
                continue
            
            try:
                if browser in ['chrome', 'edge']:
                    history.extend(self._scan_chrome_history(history_path, browser))
                elif browser == 'firefox':
                    history.extend(self._scan_firefox_history(history_path, browser))
            except Exception as e:
                print(f"Error scanning {browser} history: {e}")
        
        return history
    
    def _scan_chrome_history(self, history_path: str, browser: str) -> List[Dict]:
        """Scan Chrome/Edge history"""
        history = []
        
        try:
            # Create a copy to avoid database lock issues
            temp_path = history_path + '.temp'
            shutil.copy2(history_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT url, title, last_visit_time, visit_count
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                history.append({
                    'browser': browser,
                    'url': row[0] or '',
                    'title': row[1] or '',
                    'last_visit': row[2] or 0,
                    'visit_count': row[3] or 0
                })
            
            conn.close()
            os.remove(temp_path)
            
        except Exception as e:
            print(f"Error reading Chrome history: {e}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
        return history
    
    def _scan_firefox_history(self, history_path: str, browser: str) -> List[Dict]:
        """Scan Firefox history"""
        history = []
        
        # Firefox stores history in SQLite databases within profile directories
        if os.path.exists(history_path):
            for profile_dir in os.listdir(history_path):
                if profile_dir.endswith('.default') or profile_dir.endswith('.default-release'):
                    profile_path = os.path.join(history_path, profile_dir)
                    places_path = os.path.join(profile_path, 'places.sqlite')
                    
                    if os.path.exists(places_path):
                        try:
                            # Create a copy to avoid database lock issues
                            temp_path = places_path + '.temp'
                            shutil.copy2(places_path, temp_path)
                            
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            
                            cursor.execute("""
                                SELECT url, title, last_visit_date, visit_count
                                FROM moz_places
                                WHERE last_visit_date IS NOT NULL
                                ORDER BY last_visit_date DESC
                                LIMIT 1000
                            """)
                            
                            for row in cursor.fetchall():
                                history.append({
                                    'browser': browser,
                                    'url': row[0] or '',
                                    'title': row[1] or '',
                                    'last_visit': row[2] or 0,
                                    'visit_count': row[3] or 0
                                })
                            
                            conn.close()
                            os.remove(temp_path)
                            
                        except Exception as e:
                            print(f"Error reading Firefox history: {e}")
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
        
        return history 