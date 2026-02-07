#!/usr/bin/env python3
"""
IOC Blocklist Generator
Author: Imam Uddin Mohammed
Date: 02-06-2026
Description: Generates security tool-ready blocklists from enriched IOC data
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def generate_blocklist(enriched_json):
    """Generate blocklists from enriched IOC data"""
    
    # Load enriched data
    with open(enriched_json, 'r') as f:
        iocs = json.load(f)
    
    # Separate by type and maliciousness
    malicious_ips = []
    malicious_domains = []
    malicious_urls = []
    suspicious_ips = []
    suspicious_domains = []
    
    for ioc in iocs:
        ioc_type = ioc.get('type')
        malicious = ioc.get('malicious', 0)
        suspicious = ioc.get('suspicious', 0)
        value = ioc.get('value')
        
        # Skip if not available in VT
        if not ioc.get('vt_available'):
            continue
        
        # Categorize
        if isinstance(malicious, int) and malicious > 0:
            if ioc_type == 'ip':
                malicious_ips.append(value)
            elif ioc_type == 'domain':
                malicious_domains.append(value)
            elif ioc_type == 'url':
                malicious_urls.append(value)
        elif isinstance(suspicious, int) and suspicious > 5:
            if ioc_type == 'ip':
                suspicious_ips.append(value)
            elif ioc_type == 'domain':
                suspicious_domains.append(value)
    
    # Generate blocklist file
    output_dir = Path(enriched_json).parent
    blocklist_file = output_dir / 'blocklist.txt'
    
    with open(blocklist_file, 'w') as f:
        f.write(f"# Phishing Campaign IOC Blocklist\n")
        f.write(f"# Generated: {datetime.now().strftime('%m-%d-%Y %H:%M:%S')}\n")
        f.write(f"# Source: Phishing IR Simulation - Imam Uddin Mohammed\n")
        f.write(f"# Campaign: Multi-vector phishing (credential theft, BEC, invoice fraud)\n")
        f.write(f"#\n")
        f.write(f"# VirusTotal Enrichment Summary:\n")
        f.write(f"#   Total IOCs analyzed: {len(iocs)}\n")
        f.write(f"#   Confirmed malicious: {len(malicious_ips) + len(malicious_domains) + len(malicious_urls)}\n")
        f.write(f"#\n")
        f.write(f"# MALICIOUS IOCs (High Confidence - BLOCK IMMEDIATELY)\n")
        f.write(f"#\n\n")
        
        if malicious_ips:
            f.write("# Malicious IP Addresses\n")
            for ip in malicious_ips:
                f.write(f"{ip}\n")
            f.write("\n")
        
        if malicious_domains:
            f.write("# Malicious Domains\n")
            for domain in malicious_domains:
                f.write(f"{domain}\n")
            f.write("\n")
        
        if malicious_urls:
            f.write("# Malicious URLs\n")
            for url in malicious_urls:
                f.write(f"{url}\n")
            f.write("\n")
        
        f.write("#\n# SUSPICIOUS IOCs (Medium Confidence - Monitor/Alert)\n#\n\n")
        
        if suspicious_ips:
            f.write("# Suspicious IP Addresses\n")
            for ip in suspicious_ips:
                f.write(f"{ip}\n")
            f.write("\n")
        
        if suspicious_domains:
            f.write("# Suspicious Domains\n")
            for domain in suspicious_domains:
                f.write(f"{domain}\n")
    
    print(f"[+] Blocklist generated: {blocklist_file}")
    print(f"    - Malicious IPs: {len(malicious_ips)}")
    print(f"    - Malicious Domains: {len(malicious_domains)}")
    print(f"    - Malicious URLs: {len(malicious_urls)}")
    print(f"    - Suspicious IPs: {len(suspicious_ips)}")
    print(f"    - Suspicious Domains: {len(suspicious_domains)}")
    
    return blocklist_file

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 generate_blocklist.py <enriched_iocs.json>")
        sys.exit(1)
    
    generate_blocklist(sys.argv[1])
