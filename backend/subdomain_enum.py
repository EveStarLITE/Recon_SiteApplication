"""
Subdomain enumeration module using Sublist3r and Amass
"""
import subprocess
import json
import re
from typing import List, Set
import socket


class SubdomainEnumerator:
    """Handles subdomain enumeration"""
    
    def enumerate_sublist3r(self, domain: str, timeout: int = 300) -> List[str]:
        """
        Enumerate subdomains using Sublist3r
        
        Args:
            domain: Target domain
            timeout: Timeout in seconds
            
        Returns:
            List of discovered subdomains
        """
        subdomains = []
        try:
            # Run sublist3r
            cmd = ['sublist3r', '-d', domain, '-o', '-']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                # Parse output (one subdomain per line)
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        subdomains.append(line)
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # Sublist3r not installed, skip
            pass
        except Exception as e:
            print(f"Sublist3r error: {e}")
        
        return subdomains
    
    def enumerate_amass(self, domain: str, timeout: int = 300) -> List[str]:
        """
        Enumerate subdomains using Amass
        
        Args:
            domain: Target domain
            timeout: Timeout in seconds
            
        Returns:
            List of discovered subdomains
        """
        subdomains = []
        try:
            # Run amass enum
            cmd = ['amass', 'enum', '-d', domain, '-json', '-']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                # Parse JSON output
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if 'name' in data:
                                subdomains.append(data['name'])
                        except json.JSONDecodeError:
                            continue
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # Amass not installed, skip
            pass
        except Exception as e:
            print(f"Amass error: {e}")
        
        return subdomains
    
    def enumerate_all(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using all available tools
        
        Args:
            domain: Target domain
            
        Returns:
            List of unique subdomains
        """
        all_subdomains: Set[str] = set()
        
        # Add main domain
        all_subdomains.add(domain)
        
        # Try Sublist3r
        sublist3r_results = self.enumerate_sublist3r(domain)
        all_subdomains.update(sublist3r_results)
        
        # Try Amass
        amass_results = self.enumerate_amass(domain)
        all_subdomains.update(amass_results)
        
        # Verify subdomains resolve
        verified = []
        for subdomain in all_subdomains:
            try:
                socket.gethostbyname(subdomain)
                verified.append(subdomain)
            except:
                # Subdomain doesn't resolve, but include it anyway
                verified.append(subdomain)
        
        return sorted(verified)
    
    def get_subdomain_info(self, subdomain: str) -> dict:
        """
        Get information about a subdomain
        
        Args:
            subdomain: Subdomain to check
            
        Returns:
            Dictionary with subdomain information
        """
        info = {
            'subdomain': subdomain,
            'ip_address': None,
            'resolves': False
        }
        
        try:
            ip = socket.gethostbyname(subdomain)
            info['ip_address'] = ip
            info['resolves'] = True
        except:
            pass
        
        return info