import psutil
import platform
import os
try:
    import winreg
except ImportError:
    winreg = None
import socket

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

def get_installed_apps():
    system = platform.system()
    apps = []
    if system == 'Windows':
        # Use registry for installed apps (best effort, partial)
        try:
            reg_paths = [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            ]
            for reg_path in reg_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        subkey = winreg.OpenKey(key, winreg.EnumKey(key, i))
                        try:
                            name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                            apps.append(name)
                        except Exception:
                            continue
                except Exception:
                    continue
        except ImportError:
            pass
    elif system == 'Darwin':
        # macOS: list /Applications
        apps = [f for f in os.listdir('/Applications') if f.endswith('.app')]
    elif system == 'Linux':
        # Linux: list from /usr/share/applications
        desktop_files = '/usr/share/applications'
        if os.path.isdir(desktop_files):
            for f in os.listdir(desktop_files):
                if f.endswith('.desktop'):
                    apps.append(f)
    return apps 