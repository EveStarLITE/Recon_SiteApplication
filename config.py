"""
Configuration file for Reconnaissance Tool
"""
import os

# Tool paths (adjust if tools are not in PATH)
TOOL_PATHS = {
    'nmap': 'nmap',
    'sublist3r': 'sublist3r',
    'amass': 'amass',
    'whatweb': 'whatweb',
}

# Default scan options
SCAN_OPTIONS = {
    'nmap_ports': '80,443,8080,8443',  # Common web ports
    'nmap_timing': '-T4',  # Aggressive timing
    'subdomain_timeout': 300,  # 5 minutes timeout for subdomain enumeration
}

# Output settings
OUTPUT_DIR = 'reports'