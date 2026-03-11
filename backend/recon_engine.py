"""
Main reconnaissance engine that coordinates all modules
"""
from typing import Dict, List
from backend.nmap_scanner import NmapScanner
from backend.subdomain_enum import SubdomainEnumerator
from backend.whois_lookup import WhoisLookup
from backend.tech_detector import TechDetector
import socket
import re


class ReconEngine:
    """Main engine that coordinates all reconnaissance modules"""
    
    def __init__(self):
        self.nmap_scanner = NmapScanner()
        self.subdomain_enum = SubdomainEnumerator()
        self.whois_lookup = WhoisLookup()
        self.tech_detector = TechDetector()
    
    def is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, target))
    
    def clean_target(self, target: str) -> str:
        """Clean target input"""
        # Remove protocol
        target = target.replace('http://', '').replace('https://', '')
        
        # Remove path
        if '/' in target:
            target = target.split('/')[0]
        
        # Remove port
        if ':' in target:
            target = target.split(':')[0]
        
        return target.strip()
    
    def get_domain_from_target(self, target: str) -> str:
        """Extract domain from target"""
        target = self.clean_target(target)
        
        if self.is_ip_address(target):
            # Try reverse DNS
            try:
                domain = socket.gethostbyaddr(target)[0]
                return domain
            except:
                return target
        
        # Remove www. prefix
        if target.startswith('www.'):
            target = target[4:]
        
        return target
    
    def run_reconnaissance(self, target: str) -> Dict:
        """
        Run full reconnaissance on target
        
        Args:
            target: Target URL, domain, or IP address
            
        Returns:
            Dictionary containing all reconnaissance data
        """
        target = self.clean_target(target)
        is_ip = self.is_ip_address(target)
        
        results = {
            'target': target,
            'is_ip': is_ip,
            'domain': None,
            'ip_address': None,
            'hostname': None,
            'hosting_provider': None,
            'whois': {},
            'subdomains': [],
            'nmap_scan': {},
            'technologies': {},
            'summary': {}
        }
        
        # Get basic host info
        try:
            if is_ip:
                results['ip_address'] = target
                try:
                    results['hostname'] = socket.gethostbyaddr(target)[0]
                    results['domain'] = self.get_domain_from_target(results['hostname'])
                except:
                    results['domain'] = target
            else:
                results['domain'] = self.get_domain_from_target(target)
                try:
                    results['ip_address'] = socket.gethostbyname(target)
                    results['hostname'] = target
                except:
                    pass
        except Exception as e:
            results['error'] = str(e)
        
        # Run Whois lookup
        if results['domain']:
            results['whois'] = self.whois_lookup.lookup_domain(results['domain'])
            if 'organization' in results['whois'] and results['whois']['organization']:
                results['hosting_provider'] = results['whois']['organization']
        
        # Run subdomain enumeration
        if results['domain'] and not is_ip:
            try:
                results['subdomains'] = self.subdomain_enum.enumerate_all(results['domain'])
            except Exception as e:
                results['subdomain_error'] = str(e)
        
        # Run Nmap scan
        scan_target = results['ip_address'] or results['domain'] or target
        if scan_target:
            try:
                results['nmap_scan'] = self.nmap_scanner.scan_target(scan_target)
            except Exception as e:
                results['nmap_error'] = str(e)
        
        # Detect technologies
        url = f"https://{target}" if not target.startswith(('http://', 'https://')) else target
        try:
            results['technologies'] = self.tech_detector.detect_technologies(url)
        except Exception as e:
            results['tech_error'] = str(e)
        
        # Create summary
        results['summary'] = self._create_summary(results)
        
        return results
    
    def _create_summary(self, results: Dict) -> Dict:
        """Create summary of findings"""
        summary = {
            'primary_ip': results.get('ip_address', 'Unknown'),
            'hostname': results.get('hostname', 'Unknown'),
            'hosting_provider': results.get('hosting_provider', 'Unknown'),
            'subdomain_count': len(results.get('subdomains', [])),
            'open_ports': len(results.get('nmap_scan', {}).get('ports', [])),
            'technologies_found': len(results.get('technologies', {}).get('technologies', [])),
            'server': results.get('technologies', {}).get('server', 'Unknown'),
            'cms': results.get('technologies', {}).get('cms', 'Unknown'),
        }
        return summary