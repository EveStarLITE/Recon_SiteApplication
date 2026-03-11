"""
Whois lookup module for domain registration information
"""
import whois
import socket
from typing import Dict, Optional
from datetime import datetime


class WhoisLookup:
    """Handles Whois lookups"""
    
    def lookup_domain(self, domain: str) -> Dict:
        """
        Perform Whois lookup on domain
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary containing Whois information
        """
        try:
            # Clean domain (remove protocol, path, etc.)
            domain = self._clean_domain(domain)
            
            # Perform whois lookup
            w = whois.whois(domain)
            
            result = {
                'domain': domain,
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'updated_date': None,
                'name_servers': [],
                'status': [],
                'emails': [],
                'organization': None,
                'country': None,
            }
            
            # Extract information
            if hasattr(w, 'registrar') and w.registrar:
                result['registrar'] = str(w.registrar)
            
            if hasattr(w, 'creation_date') and w.creation_date:
                if isinstance(w.creation_date, list):
                    result['creation_date'] = str(w.creation_date[0])
                else:
                    result['creation_date'] = str(w.creation_date)
            
            if hasattr(w, 'expiration_date') and w.expiration_date:
                if isinstance(w.expiration_date, list):
                    result['expiration_date'] = str(w.expiration_date[0])
                else:
                    result['expiration_date'] = str(w.expiration_date)
            
            if hasattr(w, 'updated_date') and w.updated_date:
                if isinstance(w.updated_date, list):
                    result['updated_date'] = str(w.updated_date[0])
                else:
                    result['updated_date'] = str(w.updated_date)
            
            if hasattr(w, 'name_servers') and w.name_servers:
                result['name_servers'] = [str(ns) for ns in w.name_servers]
            
            if hasattr(w, 'status') and w.status:
                result['status'] = [str(s) for s in w.status] if isinstance(w.status, list) else [str(w.status)]
            
            if hasattr(w, 'emails') and w.emails:
                result['emails'] = [str(e) for e in w.emails] if isinstance(w.emails, list) else [str(w.emails)]
            
            if hasattr(w, 'org') and w.org:
                result['organization'] = str(w.org)
            
            if hasattr(w, 'country') and w.country:
                result['country'] = str(w.country)
            
            return result
            
        except Exception as e:
            return {
                'domain': domain,
                'error': str(e)
            }
    
    def lookup_ip(self, ip_address: str) -> Dict:
        """
        Get IP information (simplified - full IP whois requires additional tools)
        
        Args:
            ip_address: Target IP address
            
        Returns:
            Dictionary with IP information
        """
        try:
            # Resolve hostname
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except:
                pass
            
            return {
                'ip_address': ip_address,
                'hostname': hostname,
                'note': 'Full IP whois requires additional tools like whois command-line'
            }
        except Exception as e:
            return {
                'ip_address': ip_address,
                'error': str(e)
            }
    
    def _clean_domain(self, domain: str) -> str:
        """
        Clean domain string to extract just the domain name
        
        Args:
            domain: Raw domain input
            
        Returns:
            Cleaned domain name
        """
        # Remove protocol
        domain = domain.replace('http://', '').replace('https://', '')
        
        # Remove path
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www. prefix for whois lookup
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain.strip()