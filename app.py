"""
Main Streamlit application for Reconnaissance Tool
"""
import streamlit as st
import json
from backend.recon_engine import ReconEngine
from backend.export import ReportExporter
import time

# Page configuration
st.set_page_config(
    page_title="Reconnaissance Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'recon_data' not in st.session_state:
    st.session_state.recon_data = None
if 'scan_in_progress' not in st.session_state:
    st.session_state.scan_in_progress = False

# Initialize engines
@st.cache_resource
def get_recon_engine():
    return ReconEngine()

@st.cache_resource
def get_exporter():
    return ReportExporter()

recon_engine = get_recon_engine()
exporter = get_exporter()

# Custom CSS for styling
st.markdown("""
    <style>
    .warning-banner {
        background-color: #ff6b6b;
        color: white;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 20px;
        text-align: center;
        font-weight: bold;
        font-size: 18px;
    }
    .summary-card {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    .stButton>button {
        width: 100%;
    }
    </style>
""", unsafe_allow_html=True)

# Educational Use Only Banner
st.markdown("""
    <div class="warning-banner">
        ⚠️ EDUCATIONAL USE ONLY - This tool is for authorized security testing only ⚠️
    </div>
""", unsafe_allow_html=True)

# Title and description
st.title("🔍 Reconnaissance Tool")
st.markdown("""
    **Web-based OSINT (Open Source Intelligence) collection tool for reconnaissance phase**
    
    This tool automates the collection of publicly available information about a target domain or IP address.
    It performs subdomain enumeration, port scanning, technology detection, and Whois lookups.
""")

# Sidebar
with st.sidebar:
    st.header("Configuration")
    st.markdown("---")
    
    st.subheader("Scan Options")
    scan_subdomains = st.checkbox("Enumerate Subdomains", value=True)
    scan_ports = st.checkbox("Port Scanning (Nmap)", value=True)
    scan_tech = st.checkbox("Technology Detection", value=True)
    scan_whois = st.checkbox("Whois Lookup", value=True)
    
    st.markdown("---")
    st.markdown("""
    ### Tool Requirements
    - **Nmap**: For port scanning
    - **Sublist3r/Amass**: For subdomain enumeration (optional)
    - **Python packages**: See requirements.txt
    
    ### Note
    Some features may require external tools to be installed and available in your PATH.
    """)

# Main input section
st.header("Target Input")
col1, col2 = st.columns([3, 1])

with col1:
    target_input = st.text_input(
        "Enter target URL, domain, or IP address",
        placeholder="example.com or 192.168.1.1",
        help="Enter a domain name (e.g., example.com) or IP address"
    )

with col2:
    st.write("")  # Spacing
    st.write("")  # Spacing
    scan_button = st.button("🚀 Start Scan", type="primary", use_container_width=True)

# Scan execution
if scan_button and target_input:
    if not st.session_state.scan_in_progress:
        st.session_state.scan_in_progress = True
        
        with st.spinner("Running reconnaissance scan... This may take a few minutes."):
            try:
                # Run reconnaissance
                results = recon_engine.run_reconnaissance(target_input)
                st.session_state.recon_data = results
                st.success("Scan completed successfully!")
            except Exception as e:
                st.error(f"Error during scan: {str(e)}")
                st.session_state.recon_data = None
            finally:
                st.session_state.scan_in_progress = False
                st.rerun()

# Display results
if st.session_state.recon_data:
    data = st.session_state.recon_data
    
    st.markdown("---")
    st.header("📊 Scan Results")
    
    # Summary Cards
    st.subheader("Summary")
    summary = data.get('summary', {})
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Primary IP", summary.get('primary_ip', 'Unknown'))
    
    with col2:
        provider_val = summary.get('hosting_provider') or 'Unknown'

        if len(provider_val) > 20:
            display_name = provider_val[:20] + "..."
        else:
            display_name = provider_val

        st.metric("Hosting Provider", display_name)
    with col3:
        st.metric("Subdomains Found", summary.get('subdomain_count', 0))
    
    with col4:
        st.metric("Open Ports", summary.get('open_ports', 0))
    
    # Tabs for different sections
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🌐 Subdomains",
        "🔌 Ports & Services",
        "🛠️ Technologies",
        "📋 Whois",
        "📄 Export"
    ])
    
    # Subdomains Tab
    with tab1:
        st.subheader("Discovered Subdomains")
        subdomains = data.get('subdomains', [])
        if subdomains:
            st.dataframe(
                subdomains,
                column_config={
                    "value": st.column_config.TextColumn("Subdomain", width="large")
                },
                use_container_width=True,
                hide_index=True
            )
            st.info(f"Total subdomains discovered: {len(subdomains)}")
        else:
            st.warning("No subdomains discovered. This may be because:")
            st.markdown("- Subdomain enumeration tools (Sublist3r/Amass) are not installed")
            st.markdown("- The target has no subdomains")
            st.markdown("- Network connectivity issues")
    
    # Ports & Services Tab
    with tab2:
        st.subheader("Port Scan Results")
        nmap_data = data.get('nmap_scan', {})
        if nmap_data and 'ports' in nmap_data and nmap_data['ports']:
            ports_df_data = []
            for port_info in nmap_data['ports']:
                ports_df_data.append({
                    'Port': port_info.get('port', ''),
                    'Protocol': port_info.get('protocol', ''),
                    'State': port_info.get('state', ''),
                    'Service': port_info.get('service', ''),
                    'Version': port_info.get('version', '') or port_info.get('product', '')
                })
            
            import pandas as pd
            ports_df = pd.DataFrame(ports_df_data)
            st.dataframe(ports_df, use_container_width=True, hide_index=True)
        else:
            st.warning("No port scan results available. Ensure Nmap is installed and accessible.")
    
    # Technologies Tab
    with tab3:
        st.subheader("Technology Stack Detection")
        tech_data = data.get('technologies', {})
        
        if tech_data and 'error' not in tech_data:
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Web Server:**", tech_data.get('server', 'Unknown'))
                st.write("**CMS:**", tech_data.get('cms', 'Unknown'))
                
                if tech_data.get('frameworks'):
                    st.write("**Frameworks:**")
                    for framework in tech_data['frameworks']:
                        st.write(f"- {framework}")
                
                if tech_data.get('languages'):
                    st.write("**Languages:**")
                    for lang in tech_data['languages']:
                        st.write(f"- {lang}")
            
            with col2:
                if tech_data.get('technologies'):
                    st.write("**Technologies Detected:**")
                    for tech in tech_data['technologies']:
                        st.write(f"- {tech}")
            
            # HTTP Headers
            st.subheader("HTTP Headers")
            if tech_data.get('headers'):
                headers_df_data = []
                for header, value in list(tech_data['headers'].items())[:30]:  # Limit display
                    headers_df_data.append({
                        'Header': header,
                        'Value': str(value)[:200]  # Truncate long values
                    })
                
                import pandas as pd
                headers_df = pd.DataFrame(headers_df_data)
                st.dataframe(headers_df, use_container_width=True, hide_index=True)
        else:
            st.warning("Technology detection failed or not available.")
    
    # Whois Tab
    with tab4:
        st.subheader("Domain Registration Information")
        whois_data = data.get('whois', {})
        
        if whois_data and 'error' not in whois_data:
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Domain:**", whois_data.get('domain', 'Unknown'))
                st.write("**Registrar:**", whois_data.get('registrar', 'Unknown'))
                st.write("**Organization:**", whois_data.get('organization', 'Unknown'))
                st.write("**Country:**", whois_data.get('country', 'Unknown'))
            
            with col2:
                st.write("**Creation Date:**", whois_data.get('creation_date', 'Unknown'))
                st.write("**Expiration Date:**", whois_data.get('expiration_date', 'Unknown'))
                st.write("**Updated Date:**", whois_data.get('updated_date', 'Unknown'))
            
            if whois_data.get('name_servers'):
                st.subheader("Name Servers")
                for ns in whois_data['name_servers']:
                    st.write(f"- {ns}")
        else:
            error_msg = whois_data.get('error', 'Unknown error') if whois_data else 'No data available'
            st.warning(f"Whois lookup failed: {error_msg}")
    
    # Export Tab
    with tab5:
        st.subheader("Export Report")
        st.markdown("Download the reconnaissance report in your preferred format.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            json_data = exporter.export_json(data)
            st.download_button(
                label="📥 Download JSON Report",
                data=json_data,
                file_name=f"recon_report_{data.get('target', 'unknown')}_{int(time.time())}.json",
                mime="application/json",
                use_container_width=True
            )
        
        with col2:
            md_data = exporter.export_markdown(data)
            st.download_button(
                label="📥 Download Markdown Report",
                data=md_data,
                file_name=f"recon_report_{data.get('target', 'unknown')}_{int(time.time())}.md",
                mime="text/markdown",
                use_container_width=True
            )
        
        st.markdown("---")
        st.subheader("Preview Report")
        
        preview_format = st.radio("Preview format:", ["Markdown", "JSON"], horizontal=True)
        
        if preview_format == "Markdown":
            st.markdown(md_data)
        else:
            st.code(json_data, language="json")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; padding: 20px;'>
    <p><strong>⚠️ EDUCATIONAL USE ONLY</strong></p>
    <p>This tool is designed for authorized security testing and educational purposes only.</p>
    <p>Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal.</p>
</div>
""", unsafe_allow_html=True)