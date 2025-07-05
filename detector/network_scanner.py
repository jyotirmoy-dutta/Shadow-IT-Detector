import psutil
from urllib.parse import urlparse
import socket

def get_active_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            laddr_ip, laddr_port = conn.laddr if conn.laddr else ('', '')
            raddr_ip, raddr_port = conn.raddr if conn.raddr else ('', '')
            connections.append({
                'laddr': f"{laddr_ip}:{laddr_port}",
                'raddr': f"{raddr_ip}:{raddr_port}",
                'pid': conn.pid
            })
    return connections

def match_saas_connections(connections, saas_domains):
    matches = []
    for conn in connections:
        try:
            host = conn['raddr'].split(':')[0]
            domain = socket.getfqdn(host)
            for saas in saas_domains:
                if saas in domain:
                    matches.append({**conn, 'saas_domain': saas, 'fqdn': domain})
        except Exception:
            continue
    return matches 