#!/usr/bin/env python3
"""
Email Header Analyzer - Phishing Incident Response Tool
Author: Imam Uddin Mohammed
Date: 02-04-2026
Description: Parses email headers, validates authentication, extracts IOCs,
             and identifies phishing indicators.
"""

import email
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from datetime import datetime
from pathlib import Path
import argparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''

class EmailAnalyzer:
    def __init__(self, eml_file):
        self.eml_file = Path(eml_file)
        self.msg = None
        self.analysis = {
            'file': str(self.eml_file.name),
            'analysis_date': datetime.now().strftime('%m-%d-%Y %H:%M:%S'),
            'headers': {},
            'authentication': {},
            'indicators': {},
            'suspicious_flags': [],
            'risk_score': 0
        }
    
    def parse_email(self):
        """Parse the .eml file"""
        try:
            with open(self.eml_file, 'rb') as f:
                self.msg = BytesParser(policy=policy.default).parse(f)
            return True
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to parse email: {e}")
            return False
    
    def extract_headers(self):
        """Extract key email headers"""
        headers = {
            'from': self.msg.get('From', 'N/A'),
            'to': self.msg.get('To', 'N/A'),
            'subject': self.msg.get('Subject', 'N/A'),
            'date': self.msg.get('Date', 'N/A'),
            'message_id': self.msg.get('Message-ID', 'N/A'),
            'return_path': self.msg.get('Return-Path', 'N/A'),
            'reply_to': self.msg.get('Reply-To', 'N/A'),
            'x_originating_ip': self.msg.get('X-Originating-IP', 'N/A'),
            'received_headers': []
        }
        
        # Extract all Received headers (mail path)
        received_headers = self.msg.get_all('Received')
        if received_headers:
            headers['received_headers'] = [str(r) for r in received_headers]
        
        self.analysis['headers'] = headers
    
    def parse_authentication_results(self):
        """Parse SPF, DKIM, DMARC results"""
        auth_results = self.msg.get('Authentication-Results', '')
        
        auth = {
            'spf': 'unknown',
            'dkim': 'unknown',
            'dmarc': 'unknown',
            'raw': str(auth_results)
        }
        
        # Parse SPF
        spf_match = re.search(r'spf=(\w+)', str(auth_results), re.IGNORECASE)
        if spf_match:
            auth['spf'] = spf_match.group(1).lower()
        
        # Parse DKIM
        dkim_match = re.search(r'dkim=(\w+)', str(auth_results), re.IGNORECASE)
        if dkim_match:
            auth['dkim'] = dkim_match.group(1).lower()
        
        # Parse DMARC
        dmarc_match = re.search(r'dmarc=(\w+)', str(auth_results), re.IGNORECASE)
        if dmarc_match:
            auth['dmarc'] = dmarc_match.group(1).lower()
        
        self.analysis['authentication'] = auth
    
    def extract_ips(self):
        """Extract IP addresses from headers"""
        ips = []
        
        # From X-Originating-IP
        x_orig_ip = self.analysis['headers'].get('x_originating_ip', 'N/A')
        if x_orig_ip != 'N/A':
            ip_match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', x_orig_ip)
            if ip_match:
                ips.append(ip_match.group(1))
        
        # From Received headers
        for received in self.analysis['headers'].get('received_headers', []):
            ip_matches = re.findall(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', received)
            ips.extend(ip_matches)
        
        # Remove duplicates and private IPs
        unique_ips = []
        for ip in ips:
            if ip not in unique_ips and not self._is_private_ip(ip):
                unique_ips.append(ip)
        
        self.analysis['indicators']['originating_ips'] = unique_ips
    
    def _is_private_ip(self, ip):
        """Check if IP is private/internal"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:  # Loopback
                return True
            
            return False
        except ValueError:
            return False
    
    def extract_domains(self):
        """Extract domains from email addresses and URLs"""
        domains = set()
        
        # From header addresses
        for header in ['from', 'return_path', 'reply_to']:
            value = self.analysis['headers'].get(header, '')
            domain_match = re.search(r'@([\w\.-]+\.\w+)', value)
            if domain_match:
                domains.add(domain_match.group(1))
        
        self.analysis['indicators']['domains'] = list(domains)
    
    def extract_urls(self):
        """Extract URLs from email body"""
        urls = []
        
        # Get email body
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == "text/html" or part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                body = self.msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                pass
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+'
        found_urls = re.findall(url_pattern, body)
        
        # Clean and defang URLs
        for url in found_urls:
            url = url.rstrip('.,;:)')  # Remove trailing punctuation
            defanged = url.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')
            urls.append({
                'original': url,
                'defanged': defanged
            })
        
        self.analysis['indicators']['urls'] = urls
    
    def check_attachments(self):
        """Check for suspicious attachments"""
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar', '.zip', '.rar']
        double_extensions = ['.pdf.exe', '.doc.exe', '.xls.exe', '.jpg.exe', '.png.exe', '.txt.exe']
        
        attachments = []
        
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_disp = str(part.get('Content-Disposition', ''))
                
                if 'attachment' in content_disp:
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)
                        
                        # Check for double extensions (highest priority)
                        found_double_ext = False
                        for double_ext in double_extensions:
                            if double_ext in filename.lower():
                                self.analysis['suspicious_flags'].append({
                                    'type': 'Malicious Attachment - Double Extension',
                                    'severity': 'CRITICAL',
                                    'detail': f"Attachment '{filename}' uses double extension to disguise executable"
                                })
                                self.analysis['risk_score'] += 50
                                found_double_ext = True
                                break
                        
                        # Only check single extensions if no double extension found
                        if not found_double_ext:
                            for ext in suspicious_extensions:
                                if filename.lower().endswith(ext):
                                    self.analysis['suspicious_flags'].append({
                                        'type': 'Suspicious Attachment',
                                        'severity': 'HIGH',
                                        'detail': f"Attachment '{filename}' has dangerous file extension"
                                    })
                                    self.analysis['risk_score'] += 35
                                    break
        
        self.analysis['indicators']['attachments'] = attachments
    
    def check_display_name_spoofing(self):
        """Check if display name doesn't match email address"""
        from_header = self.analysis['headers'].get('from', '')
        
        # Extract display name and email
        display_match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
        
        if display_match:
            display_name = display_match.group(1).strip()
            email_addr = display_match.group(2).strip()
            
            # Check for mismatch
            domain = email_addr.split('@')[-1] if '@' in email_addr else ''
            
            # Flag if display name suggests different entity
            suspicious_keywords = ['ceo', 'cfo', 'president', 'director', 'manager', 'payroll', 'hr', 'support']
            
            if any(keyword in display_name.lower() for keyword in suspicious_keywords):
                self.analysis['suspicious_flags'].append({
                    'type': 'Display Name Spoofing',
                    'severity': 'HIGH',
                    'detail': f"Display name '{display_name}' may not match actual sender '{email_addr}'"
                })
                self.analysis['risk_score'] += 30
    
    def check_authentication_failures(self):
        """Flag authentication failures"""
        auth = self.analysis['authentication']
        
        if auth['spf'] == 'fail':
            self.analysis['suspicious_flags'].append({
                'type': 'SPF Failure',
                'severity': 'HIGH',
                'detail': 'Sending server not authorized by domain owner'
            })
            self.analysis['risk_score'] += 40
        
        if auth['dkim'] == 'fail' or auth['dkim'] == 'none':
            self.analysis['suspicious_flags'].append({
                'type': 'DKIM Failure/Missing',
                'severity': 'MEDIUM',
                'detail': 'Email signature missing or invalid'
            })
            self.analysis['risk_score'] += 20
        
        if auth['spf'] == 'neutral':
            self.analysis['suspicious_flags'].append({
                'type': 'SPF Neutral',
                'severity': 'MEDIUM',
                'detail': 'Domain has no SPF policy or policy is inconclusive'
            })
            self.analysis['risk_score'] += 15
    
    def check_suspicious_domains(self):
        """Check for typosquatting and suspicious TLDs"""
        suspicious_tlds = ['.ru', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        typosquat_patterns = ['payro11', 'arnazon', 'g00gle', 'micros0ft', 'app1e']
        
        for domain in self.analysis['indicators'].get('domains', []):
            # Check TLD
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                self.analysis['suspicious_flags'].append({
                    'type': 'Suspicious TLD',
                    'severity': 'MEDIUM',
                    'detail': f"Domain '{domain}' uses high-risk TLD"
                })
                self.analysis['risk_score'] += 15
            
            # Check for common typosquatting
            if any(pattern in domain.lower() for pattern in typosquat_patterns):
                self.analysis['suspicious_flags'].append({
                    'type': 'Potential Typosquatting',
                    'severity': 'HIGH',
                    'detail': f"Domain '{domain}' may be typosquatting"
                })
                self.analysis['risk_score'] += 35
    
    def check_url_shorteners(self):
        """Flag URL shorteners"""
        shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        
        for url_obj in self.analysis['indicators'].get('urls', []):
            url = url_obj['original']
            if any(shortener in url.lower() for shortener in shortener_domains):
                self.analysis['suspicious_flags'].append({
                    'type': 'URL Shortener',
                    'severity': 'MEDIUM',
                    'detail': f"Shortened URL detected: {url_obj['defanged']}"
                })
                self.analysis['risk_score'] += 20
    
    def analyze(self):
        """Run complete analysis"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Email Forensic Analysis - Phishing IR Simulation")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        if not self.parse_email():
            return False
        
        print(f"{Fore.GREEN}[+] Parsing email: {self.eml_file.name}")
        
        self.extract_headers()
        self.parse_authentication_results()
        self.extract_ips()
        self.extract_domains()
        self.extract_urls()
        self.check_attachments()
        
        print(f"{Fore.GREEN}[+] Running indicator checks...")
        
        self.check_display_name_spoofing()
        self.check_authentication_failures()
        self.check_suspicious_domains()
        self.check_url_shorteners()
        
        # Calculate risk level
        score = self.analysis['risk_score']
        if score >= 70:
            risk_level = f"{Fore.RED}CRITICAL"
        elif score >= 40:
            risk_level = f"{Fore.YELLOW}HIGH"
        elif score >= 20:
            risk_level = f"{Fore.MAGENTA}MEDIUM"
        else:
            risk_level = f"{Fore.GREEN}LOW"
        
        self.analysis['risk_level'] = risk_level.replace(Fore.RED, '').replace(Fore.YELLOW, '').replace(Fore.MAGENTA, '').replace(Fore.GREEN, '')
        
        return True
    
    def print_results(self):
        """Print formatted results to terminal"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}ANALYSIS RESULTS")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        # Basic info
        print(f"{Fore.WHITE}{Style.BRIGHT}FILE: {self.analysis['file']}")
        print(f"{Fore.WHITE}ANALYZED: {self.analysis['analysis_date']}\n")
        
        # Headers
        print(f"{Fore.CYAN}--- EMAIL HEADERS ---")
        headers = self.analysis['headers']
        print(f"From:       {headers['from']}")
        print(f"To:         {headers['to']}")
        print(f"Subject:    {headers['subject']}")
        print(f"Date:       {headers['date']}")
        print(f"Return-Path: {headers['return_path']}")
        if headers['reply_to'] != 'N/A':
            print(f"Reply-To:    {headers['reply_to']}")
        
        # Authentication
        print(f"\n{Fore.CYAN}--- AUTHENTICATION RESULTS ---")
        auth = self.analysis['authentication']
        
        spf_color = Fore.RED if auth['spf'] == 'fail' else Fore.YELLOW if auth['spf'] == 'neutral' else Fore.GREEN
        dkim_color = Fore.RED if auth['dkim'] in ['fail', 'none'] else Fore.GREEN
        dmarc_color = Fore.RED if auth['dmarc'] == 'fail' else Fore.GREEN
        
        print(f"SPF:   {spf_color}{auth['spf'].upper()}{Style.RESET_ALL}")
        print(f"DKIM:  {dkim_color}{auth['dkim'].upper()}{Style.RESET_ALL}")
        print(f"DMARC: {dmarc_color}{auth['dmarc'].upper()}{Style.RESET_ALL}")
        
        # Indicators
        print(f"\n{Fore.CYAN}--- INDICATORS OF COMPROMISE ---")
        
        if self.analysis['indicators'].get('originating_ips'):
            print(f"Originating IPs: {', '.join(self.analysis['indicators']['originating_ips'])}")
        
        if self.analysis['indicators'].get('domains'):
            print(f"Domains: {', '.join(self.analysis['indicators']['domains'])}")
        
        if self.analysis['indicators'].get('attachments'):
            print(f"\nAttachments ({len(self.analysis['indicators']['attachments'])}):")
            for attachment in self.analysis['indicators']['attachments']:
                print(f"  - {attachment}")
        
        if self.analysis['indicators'].get('urls'):
            print(f"\nURLs Found ({len(self.analysis['indicators']['urls'])}):")
            for url_obj in self.analysis['indicators']['urls']:
                print(f"  - {url_obj['defanged']}")
        
        # Suspicious flags
        if self.analysis['suspicious_flags']:
            print(f"\n{Fore.RED}{Style.BRIGHT}--- SUSPICIOUS INDICATORS DETECTED ---")
            for flag in self.analysis['suspicious_flags']:
                severity_color = Fore.RED if flag['severity'] == 'CRITICAL' else Fore.RED if flag['severity'] == 'HIGH' else Fore.YELLOW if flag['severity'] == 'MEDIUM' else Fore.MAGENTA
                print(f"{severity_color}[{flag['severity']}] {flag['type']}: {flag['detail']}{Style.RESET_ALL}")
        
        # Risk assessment
        print(f"\n{Fore.CYAN}{'='*70}")
        score = self.analysis['risk_score']
        risk_level = self.analysis['risk_level']
        
        if risk_level == 'CRITICAL':
            color = Fore.RED
        elif risk_level == 'HIGH':
            color = Fore.YELLOW
        elif risk_level == 'MEDIUM':
            color = Fore.MAGENTA
        else:
            color = Fore.GREEN
        
        print(f"{color}{Style.BRIGHT}RISK ASSESSMENT: {risk_level} (Score: {score}/100){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}\n")
    
    def save_json(self, output_dir):
        """Save analysis to JSON file"""
        output_path = Path(output_dir) / f"{self.eml_file.stem}_analysis.json"
        
        # Remove color codes from risk_level for JSON
        clean_analysis = self.analysis.copy()
        
        with open(output_path, 'w') as f:
            json.dump(clean_analysis, f, indent=4)
        
        print(f"{Fore.GREEN}[+] Analysis saved to: {output_path}\n")
        return output_path

def main():
    parser = argparse.ArgumentParser(
        description='Email Header Analyzer for Phishing Incident Response',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('email_file', help='Path to .eml file to analyze')
    parser.add_argument('-o', '--output', default='analysis', 
                       help='Output directory for JSON report (default: analysis)')
    
    args = parser.parse_args()
    
    analyzer = EmailAnalyzer(args.email_file)
    
    if analyzer.analyze():
        analyzer.print_results()
        analyzer.save_json(args.output)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
