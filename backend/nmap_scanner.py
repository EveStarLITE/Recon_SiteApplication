"""
Nmap scanner module for service and version detection
"""
import os
import nmap
import socket
from typing import Dict, List, Optional


class NmapScanner:
    """Handles Nmap scanning operations"""
    
   
import nmap

class NmapScanner:
    def __init__(self):
        nmap_dir = r"C:\Program Files (x86)\Nmap"
        
        if nmap_dir not in os.environ["PATH"]:
            os.environ["PATH"] += os.pathsep + nmap_dir
        
        try:
            self.nm = nmap.PortScanner()
        except nmap.nmap.PortScannerError:
            self.nm = nmap.PortScanner(nmap_search_path=(os.path.join(nmap_dir, 'nmap.exe'),))
    
    def scan_target(self, target: str, ports: str = "80,443,8080,8443") -> Dict:
        """
        Scan target for open ports and service versions
        
        Args:
            target: IP address or hostname
            ports: Comma-separated port list
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Perform version detection scan
            self.nm.scan(target, ports, arguments='-sV')
            
            results = {
                'target': target,
                'hostname': target,
                'ip_address': None,
                'ports': [],
                'services': [],
                'host_info': {}
            }
            
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                # Get IP address
                results['ip_address'] = host['addresses'].get('ipv4', target)
                
                # Get hostname if available
                if 'hostnames' in host and host['hostnames']:
                    results['hostname'] = host['hostnames'][0].get('name', target)
                
                # Get host info
                if 'osmatch' in host:
                    results['host_info']['os'] = host['osmatch']
                
                # Get port and service information
                for proto in host.all_protocols():
                    ports_info = host[proto]
                    for port, port_info in ports_info.items():
                        port_data = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                        }
                        results['ports'].append(port_data)
                        results['services'].append(port_data)
            
            return results
            
        except Exception as e:
            return {
                'target': target,
                'error': str(e),
                'ports': [],
                'services': []
            }
    
    def get_host_info(self, target: str) -> Dict:
        """
        Get basic host information
        
        Args:
            target: IP address or hostname
            
        Returns:
            Dictionary with host information
        """
        try:
            # Resolve hostname to IP
            ip_address = socket.gethostbyname(target)
            
            # Try reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except:
                hostname = target
            
            return {
                'ip_address': ip_address,
                'hostname': hostname,
                'target': target
            }
        except Exception as e:
            return {
                'target': target,
                'error': str(e)
            }