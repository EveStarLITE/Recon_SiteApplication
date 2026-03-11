"""
Technology stack detection module using HTTP headers and content analysis
"""
import requests
from bs4 import BeautifulSoup
from typing import Dict, List
import re
import urllib3

# Disable SSL warnings for development (not recommended for production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TechDetector:
    """Detects technologies used by target website"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def detect_technologies(self, url: str) -> Dict:
        """
        Detect technologies used by target website
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary containing detected technologies
        """
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        result = {
            'url': url,
            'headers': {},
            'server': None,
            'technologies': [],
            'frameworks': [],
            'cms': None,
            'languages': [],
            'cookies': [],
            'status_code': None,
            'error': None
        }
        
        try:
            # Make request
            response = requests.get(url, headers=self.headers, timeout=10, verify=False)
            result['status_code'] = response.status_code
            
            # Extract headers
            result['headers'] = dict(response.headers)
            
            # Detect server from headers
            if 'Server' in response.headers:
                result['server'] = response.headers['Server']
            
            # Detect technologies from headers
            self._detect_from_headers(response.headers, result)
            
            # Detect technologies from content
            if response.text:
                self._detect_from_content(response.text, result)
            
            # Extract cookies
            result['cookies'] = [{'name': c.name, 'value': c.value[:50]} for c in response.cookies]
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            url = url.replace('https://', 'http://')
            try:
                response = requests.get(url, headers=self.headers, timeout=10)
                result['status_code'] = response.status_code
                result['headers'] = dict(response.headers)
                if 'Server' in response.headers:
                    result['server'] = response.headers['Server']
                self._detect_from_headers(response.headers, result)
                if response.text:
                    self._detect_from_content(response.text, result)
            except Exception as e:
                result['error'] = str(e)
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _detect_from_headers(self, headers: Dict, result: Dict):
        """Detect technologies from HTTP headers"""
        
        # Server detection
        server_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in server_headers:
            if header in headers:
                value = headers[header]
                result['technologies'].append(f"{header}: {value}")
                
                # Detect specific technologies
                value_lower = value.lower()
                if 'apache' in value_lower:
                    result['server'] = 'Apache'
                elif 'nginx' in value_lower:
                    result['server'] = 'Nginx'
                elif 'iis' in value_lower or 'microsoft' in value_lower:
                    result['server'] = 'IIS'
                elif 'cloudflare' in value_lower:
                    result['technologies'].append('Cloudflare CDN')
        
        # Framework detection
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            if 'PHP' in powered_by:
                result['languages'].append('PHP')
            if 'ASP.NET' in powered_by:
                result['frameworks'].append('ASP.NET')
        
        # CMS detection
        if 'X-Drupal-Cache' in headers:
            result['cms'] = 'Drupal'
        elif 'X-WordPress' in headers or 'wp-content' in str(headers):
            result['cms'] = 'WordPress'
        elif 'X-Joomla' in headers:
            result['cms'] = 'Joomla'
        
        # Language detection
        if 'X-PHP-Version' in headers:
            result['languages'].append(f"PHP {headers['X-PHP-Version']}")
    
    def _detect_from_content(self, html_content: str, result: Dict):
        """Detect technologies from HTML content"""
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Detect CMS from meta tags and content
        if soup.find('meta', {'name': 'generator'}):
            generator = soup.find('meta', {'name': 'generator'}).get('content', '')
            if 'wordpress' in generator.lower():
                result['cms'] = 'WordPress'
            elif 'drupal' in generator.lower():
                result['cms'] = 'Drupal'
            elif 'joomla' in generator.lower():
                result['cms'] = 'Joomla'
        
        # Detect frameworks from script tags
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '').lower()
            
            # React
            if 'react' in src or 'reactjs' in src:
                result['frameworks'].append('React')
            
            # Angular
            if 'angular' in src:
                result['frameworks'].append('Angular')
            
            # Vue
            if 'vue' in src:
                result['frameworks'].append('Vue.js')
            
            # jQuery
            if 'jquery' in src:
                result['frameworks'].append('jQuery')
        
        # Detect from inline scripts
        inline_scripts = soup.find_all('script', string=True)
        for script in inline_scripts:
            script_text = script.string.lower() if script.string else ''
            
            if 'react' in script_text or 'reactjs' in script_text:
                result['frameworks'].append('React')
            if 'angular' in script_text:
                result['frameworks'].append('Angular')
            if 'vue' in script_text:
                result['frameworks'].append('Vue.js')
        
        # Detect WordPress
        if 'wp-content' in html_content.lower() or 'wp-includes' in html_content.lower():
            result['cms'] = 'WordPress'
        
        # Detect Drupal
        if '/sites/default/files' in html_content or 'drupal' in html_content.lower():
            if not result['cms']:
                result['cms'] = 'Drupal'
        
        # Remove duplicates
        result['frameworks'] = list(set(result['frameworks']))
        result['languages'] = list(set(result['languages']))