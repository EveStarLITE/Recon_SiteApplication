"""
Export functionality for reconnaissance reports
"""
import json
from typing import Dict
from datetime import datetime


class ReportExporter:
    """Handles export of reconnaissance data to various formats"""
    
    def export_json(self, data: Dict, filename: str = None) -> str:
        """
        Export data to JSON format
        
        Args:
            data: Reconnaissance data dictionary
            filename: Optional filename (without extension)
            
        Returns:
            JSON string
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_report_{timestamp}"
        
        export_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'target': data.get('target', 'Unknown'),
                'tool': 'Reconnaissance Tool - Educational Use Only'
            },
            'data': data
        }
        
        return json.dumps(export_data, indent=2, default=str)
    
    def export_markdown(self, data: Dict, filename: str = None) -> str:
        """
        Export data to Markdown format
        
        Args:
            data: Reconnaissance data dictionary
            filename: Optional filename (without extension)
            
        Returns:
            Markdown string
        """
        md = []
        
        # Header
        md.append("# Reconnaissance Report")
        md.append("")
        md.append("**⚠️ EDUCATIONAL USE ONLY - This tool is for authorized security testing only**")
        md.append("")
        md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Target:** {data.get('target', 'Unknown')}")
        md.append("")
        md.append("---")
        md.append("")
        
        # Summary
        md.append("## Summary")
        md.append("")
        summary = data.get('summary', {})
        md.append(f"- **Primary IP:** {summary.get('primary_ip', 'Unknown')}")
        md.append(f"- **Hostname:** {summary.get('hostname', 'Unknown')}")
        md.append(f"- **Hosting Provider:** {summary.get('hosting_provider', 'Unknown')}")
        md.append(f"- **Subdomains Found:** {summary.get('subdomain_count', 0)}")
        md.append(f"- **Open Ports:** {summary.get('open_ports', 0)}")
        md.append(f"- **Technologies Detected:** {summary.get('technologies_found', 0)}")
        md.append(f"- **Web Server:** {summary.get('server', 'Unknown')}")
        md.append(f"- **CMS:** {summary.get('cms', 'Unknown')}")
        md.append("")
        
        # Whois Information
        md.append("## Domain Registration Information (Whois)")
        md.append("")
        whois_data = data.get('whois', {})
        if whois_data and 'error' not in whois_data:
            md.append(f"- **Registrar:** {whois_data.get('registrar', 'Unknown')}")
            md.append(f"- **Creation Date:** {whois_data.get('creation_date', 'Unknown')}")
            md.append(f"- **Expiration Date:** {whois_data.get('expiration_date', 'Unknown')}")
            md.append(f"- **Organization:** {whois_data.get('organization', 'Unknown')}")
            md.append(f"- **Country:** {whois_data.get('country', 'Unknown')}")
            if whois_data.get('name_servers'):
                md.append("- **Name Servers:**")
                for ns in whois_data['name_servers']:
                    md.append(f"  - {ns}")
        else:
            md.append("*Whois lookup failed or not available*")
        md.append("")
        
        # Subdomains
        md.append("## Discovered Subdomains")
        md.append("")
        subdomains = data.get('subdomains', [])
        if subdomains:
            md.append("| Subdomain |")
            md.append("|-----------|")
            for subdomain in subdomains:
                md.append(f"| {subdomain} |")
        else:
            md.append("*No subdomains discovered*")
        md.append("")
        
        # Nmap Scan Results
        md.append("## Port Scan Results (Nmap)")
        md.append("")
        nmap_data = data.get('nmap_scan', {})
        if nmap_data and 'ports' in nmap_data and nmap_data['ports']:
            md.append("| Port | Protocol | State | Service | Version |")
            md.append("|------|----------|-------|---------|---------|")
            for port_info in nmap_data['ports']:
                port = port_info.get('port', '')
                protocol = port_info.get('protocol', '')
                state = port_info.get('state', '')
                service = port_info.get('service', '')
                version = port_info.get('version', '') or port_info.get('product', '')
                md.append(f"| {port} | {protocol} | {state} | {service} | {version} |")
        else:
            md.append("*No port scan results available*")
        md.append("")
        
        # Technologies
        md.append("## Technology Stack Detection")
        md.append("")
        tech_data = data.get('technologies', {})
        if tech_data:
            if tech_data.get('server'):
                md.append(f"- **Web Server:** {tech_data['server']}")
            if tech_data.get('cms'):
                md.append(f"- **CMS:** {tech_data['cms']}")
            if tech_data.get('frameworks'):
                md.append("- **Frameworks:**")
                for framework in tech_data['frameworks']:
                    md.append(f"  - {framework}")
            if tech_data.get('languages'):
                md.append("- **Languages:**")
                for lang in tech_data['languages']:
                    md.append(f"  - {lang}")
            if tech_data.get('technologies'):
                md.append("- **Technologies:**")
                for tech in tech_data['technologies']:
                    md.append(f"  - {tech}")
            md.append("")
            
            # HTTP Headers
            if tech_data.get('headers'):
                md.append("### HTTP Headers")
                md.append("")
                md.append("| Header | Value |")
                md.append("|--------|-------|")
                for header, value in list(tech_data['headers'].items())[:20]:  # Limit to first 20
                    # Truncate long values
                    value_str = str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
                    md.append(f"| {header} | {value_str} |")
        else:
            md.append("*Technology detection failed or not available*")
        md.append("")
        
        # Footer
        md.append("---")
        md.append("")
        md.append("**⚠️ REMINDER: This tool is for EDUCATIONAL USE ONLY**")
        md.append("")
        md.append("*Report generated by Reconnaissance Tool*")
        
        return "\n".join(md)