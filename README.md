# Recon_SiteApplication

Web Browser application for reconnaissance as part of Pen Testing and Ethical Hacking course.

## ⚠️ EDUCATIONAL USE ONLY

**This tool is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.**

## Overview

A web-based reconnaissance tool that automates the collection of publicly available information (OSINT) about a target domain or IP address. The tool provides a centralized Streamlit interface to view and export discovery data.

## Features

- **Subdomain Enumeration**: Discovers subdomains using Sublist3r and Amass
- **Port Scanning**: Uses Nmap for service and version detection
- **Technology Detection**: Identifies web servers, frameworks, CMS, and technologies from HTTP headers and content
- **Whois Lookup**: Retrieves domain registration information
- **Export Reports**: Download findings as JSON or Markdown reports
- **Dashboard View**: Summary cards showing key information at a glance

## Requirements

### Python Packages
All Python dependencies are listed in `requirements.txt`. Install them using:

```bash
pip install -r requirements.txt
```

### External Tools (Optional but Recommended)

Some features require external tools to be installed and available in your system PATH:

- **Nmap**: For port scanning
  - Windows: Download from https://nmap.org/download.html
  - Linux: `sudo apt-get install nmap` or `sudo yum install nmap`
  - macOS: `brew install nmap`

- **Sublist3r**: For subdomain enumeration (optional)
  - Install: `pip install sublist3r`
  - Or clone: `git clone https://github.com/aboul3la/Sublist3r.git`

- **Amass**: For subdomain enumeration (optional)
  - Download from: https://github.com/OWASP/Amass/releases
  - Or install via: `go install -v github.com/owasp-amass/amass/v4/...@master`

**Note**: The tool will still function without these external tools, but some features may be limited.

## Installation

1. Clone or download this repository
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install external tools as listed above

## Usage

1. Start the Streamlit application:
   ```bash
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL shown in the terminal (typically `http://localhost:8501`)

3. Enter a target URL, domain, or IP address in the input field

4. Click "Start Scan" to begin reconnaissance

5. View results in the dashboard tabs:
   - **Subdomains**: List of discovered subdomains
   - **Ports & Services**: Nmap scan results
   - **Technologies**: Detected web technologies
   - **Whois**: Domain registration information
   - **Export**: Download reports in JSON or Markdown format

## Project Structure

```
Recon_SiteApplication/
├── app.py                 # Main Streamlit application
├── config.py              # Configuration settings
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── backend/              # Backend modules
│   ├── __init__.py
│   ├── recon_engine.py   # Main reconnaissance engine
│   ├── nmap_scanner.py   # Nmap integration
│   ├── subdomain_enum.py # Subdomain enumeration
│   ├── whois_lookup.py   # Whois lookup
│   ├── tech_detector.py  # Technology detection
│   └── export.py         # Report export functionality
└── reports/              # Generated reports (created automatically)
```

## Configuration

Edit `config.py` to customize:
- Tool paths (if tools are not in system PATH)
- Default scan options
- Output directory

## Safety Features

- Prominent "EDUCATIONAL USE ONLY" warnings throughout the interface
- Focus on reconnaissance only - no exploitation capabilities
- Strict scope limitation to prevent aggressive scanning

## Troubleshooting

### Nmap not found
- Ensure Nmap is installed and available in your system PATH
- On Windows, you may need to add Nmap to your PATH environment variable

### Subdomain enumeration not working
- Install Sublist3r or Amass
- Ensure tools are accessible from command line
- Check network connectivity

### SSL Certificate Warnings
- The tool disables SSL verification warnings for development purposes
- This is acceptable for reconnaissance but not recommended for production use

### Port scan taking too long
- Adjust timeout settings in `config.py`
- Reduce the number of ports scanned
- Check firewall settings

## Limitations

- Some features require external tools to be installed
- Subdomain enumeration may take several minutes
- Port scanning requires appropriate network permissions
- Whois data availability depends on domain registrar policies

## Contributing

This is an educational project. Feel free to submit issues or improvements.

## License

Educational use only. See the warning banner in the application for details.

## Author

Created for CSUSB Pen Testing and Ethical Hacking course.

---

**Remember: Always obtain proper authorization before testing any system. Unauthorized access is illegal.**