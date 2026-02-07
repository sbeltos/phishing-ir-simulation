# Phishing Incident Response Simulation & Playbook

**Author**: Imam Uddin Mohammed  
**Project Duration**: 02-03-2026 to 02-07-2026 (5 days)  
**Status**: Complete

## Project Overview

A comprehensive phishing incident response simulation demonstrating enterprise SOC workflows including email forensics, IOC extraction, threat intelligence enrichment, and NIST-aligned playbook development.

## Objectives

- Simulate realistic phishing campaign targeting corporate environment
- Perform complete email forensics analysis (headers, links, attachments)
- Extract and enrich Indicators of Compromise (IOCs)
- Develop production-ready incident response playbook
- Document findings in professional incident report format

## Technology Stack

- **Platform**: Kali Linux
- **Language**: Python 3
- **Threat Intelligence**: VirusTotal API
- **Analysis Tools**: Custom scripts for email parsing, IOC extraction, URL analysis
- **Documentation**: Markdown, JSON, CSV

## Project Timeline

| Date | Phase | Activities |
|------|-------|------------|
| 02-03-2026 | Setup & Sample Creation | Environment configuration, 3 phishing email samples |
| 02-04-2026 | Email Analysis | Developed email_analyzer.py, analyzed all samples |
| 02-05-2026 | Threat Intelligence | IOC enrichment with VirusTotal API |
| 02-06-2026 | Response Procedures | Blocklist generation, IR playbook development |
| 02-07-2026 | Documentation | Incident report, executive summary, GitHub publication |

## Key Findings

### Email Analysis Results

| Email | Type | Risk Score | Key Indicators |
|-------|------|------------|----------------|
| Email 1 | Credential Harvesting | CRITICAL (145/100) | SPF fail, typosquatting, URL shortener |
| Email 2 | Invoice Fraud | HIGH (50/100) | Malicious .pdf.exe attachment |
| Email 3 | BEC (CEO Fraud) | HIGH (45/100) | Display name spoofing, wire transfer request |

### Threat Intelligence Results

- **Total IOCs Extracted**: 10 (3 domains, 4 IPs, 3 URLs)
- **Confirmed Malicious**: 2 IPs
  - `185.220.101.45` - Flagged by 14/90 vendors
  - `203.45.67.89` - Flagged by 1/90 vendors
- **Fresh Infrastructure**: All domains not in VirusTotal (< 48 hours old)

## Project Structure
```
phishing-ir-simulation/
├── README.md                 # Project overview
├── PROJECT_LOG.md            # Detailed activity log
├── samples/                  # Sanitized phishing email samples (.eml)
├── scripts/                  # Custom Python forensic tools
│   ├── email_analyzer.py     # Email header & IOC analysis
│   ├── ioc_enrichment.py     # VirusTotal integration
│   └── generate_blocklist.py # Security control generation
├── analysis/                 # Email analysis outputs (JSON)
├── iocs/                     # Enriched IOCs and blocklists
├── playbook/                 # NIST-aligned IR playbook
├── reports/                  # Incident reports (pending)
└── docs/                     # Screenshots and diagrams (pending)
```

## Tools Developed

### 1. Email Analyzer (`email_analyzer.py`)
- **Purpose**: Forensic analysis of phishing emails
- **Features**:
  - SPF/DKIM/DMARC validation
  - Header parsing and IP extraction
  - Attachment analysis (double extensions, dangerous file types)
  - URL extraction and defanging
  - Risk scoring algorithm
  - JSON report generation

**Usage:**
```bash
python3 scripts/email_analyzer.py samples/email_01_low_sophistication.eml -o analysis/
```

### 2. IOC Enrichment Tool (`ioc_enrichment.py`)
- **Purpose**: Threat intelligence enrichment via VirusTotal
- **Features**:
  - Automated IOC extraction from analysis reports
  - Domain, IP, and URL reputation lookup
  - Rate-limited API requests (4/minute free tier)
  - CSV and JSON output formats

**Usage:**
```bash
python3 scripts/ioc_enrichment.py -a analysis/ -o iocs/
```

### 3. Blocklist Generator (`generate_blocklist.py`)
- **Purpose**: Generate security tool-ready blocklists
- **Features**:
  - Filters IOCs by confidence level
  - Firewall/IDS/SIEM compatible format
  - Categorizes malicious vs suspicious

**Usage:**
```bash
python3 scripts/generate_blocklist.py iocs/enriched_iocs_*.json
```

## Incident Response Playbook

NIST SP 800-61 Rev. 2 aligned playbook covering:
1. **Preparation** - Tools, roles, procedures
2. **Detection & Analysis** - Triage, forensics, IOC extraction
3. **Containment** - Email quarantine, account lockdown, IOC blocking
4. **Eradication** - Malware removal, access revocation
5. **Recovery** - Service restoration, validation
6. **Post-Incident** - Lessons learned, continuous improvement

Includes:
- Real-world commands (PowerShell, Splunk, firewall CLI)
- Decision trees and severity matrices
- Communication templates
- Tool references

## Skills Demonstrated

**Technical:**
- Email forensics (header analysis, authentication validation)
- Python scripting (parsing, API integration, automation)
- Threat intelligence (VirusTotal API, IOC enrichment)
- SIEM concepts (correlation, alerting)
- Network security (firewall rules, blocklists)

**Analytical:**
- Phishing campaign analysis
- Risk assessment and scoring
- Incident prioritization
- Root cause analysis

**Documentation:**
- Technical writing (playbooks, reports)
- Professional communication (executive summaries)
- Project management (timeline, deliverables)

## Installation & Setup

### Prerequisites
- Kali Linux (or Ubuntu/Debian-based system)
- Python 3.8+
- VirusTotal API key (free tier)

### Installation
```bash
# Clone repository
git clone https://github.com/itsmiu/phishing-ir-simulation.git
cd phishing-ir-simulation

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install email-validator requests beautifulsoup4 python-magic dnspython \
            pandas openpyxl pyyaml tabulate colorama tldextract python-whois

# Configure VirusTotal API key
mkdir -p ~/.config/phishing-ir
echo "YOUR_VT_API_KEY" > ~/.config/phishing-ir/vt_api_key
chmod 600 ~/.config/phishing-ir/vt_api_key
```

### Running Analysis
```bash
# Analyze single email
python3 scripts/email_analyzer.py samples/email_01_low_sophistication.eml

# Enrich IOCs (requires VT API key)
python3 scripts/ioc_enrichment.py -a analysis/ -o iocs/

# Generate blocklist
python3 scripts/generate_blocklist.py iocs/enriched_iocs_*.json
```

## Future Enhancements

- [ ] YARA rule generation for malware detection
- [ ] STIX/TAXII format IOC export
- [ ] Automated sandbox integration (ANY.RUN, Joe Sandbox)
- [ ] ELK Stack integration for visualization
- [ ] Machine learning-based phishing detection

## License

MIT License - See LICENSE file for details

## Contact

**Imam Uddin Mohammed**  
[LinkedIn](https://www.linkedin.com/in/imamuddinmohammed/) | [GitHub](https://github.com/itsmiu)

---

*Last Updated: 02-07-2026*
