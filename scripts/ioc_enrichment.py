#!/usr/bin/env python3
"""
IOC Enrichment Tool - VirusTotal Integration
Author: Imam Uddin Mohammed
Date: 02-05-2026
Description: Extracts IOCs from analysis reports and enriches them with
             VirusTotal threat intelligence data.
"""

import json
import requests
import time
import sys
from pathlib import Path
from datetime import datetime
import argparse
import csv

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''

class IOCEnricher:
    def __init__(self, api_key_file):
        self.api_key = self._load_api_key(api_key_file)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.rate_limit_delay = 16  # VT free tier: 4 requests/minute = 15 sec between requests
        self.iocs = {
            'domains': [],
            'ips': [],
            'urls': []
        }
        self.enriched_data = []
        self.request_count = 0
    
    def _load_api_key(self, key_file):
        """Load VirusTotal API key from file"""
        try:
            key_path = Path(key_file).expanduser()
            with open(key_path, 'r') as f:
                key = f.read().strip()
                if not key:
                    raise ValueError("API key file is empty")
                return key
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] API key file not found: {key_file}")
            print(f"{Fore.YELLOW}[INFO] Create file with: echo 'YOUR_VT_API_KEY' > {key_file}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to load API key: {e}")
            sys.exit(1)
    
    def load_analysis_files(self, analysis_dir):
        """Load all JSON analysis files and extract IOCs"""
        analysis_path = Path(analysis_dir)
        
        if not analysis_path.exists():
            print(f"{Fore.RED}[ERROR] Analysis directory not found: {analysis_dir}")
            sys.exit(1)
        
        json_files = list(analysis_path.glob('*_analysis.json'))
        
        if not json_files:
            print(f"{Fore.RED}[ERROR] No analysis files found in {analysis_dir}")
            sys.exit(1)
        
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}IOC Extraction & Enrichment - Phishing IR Simulation")
        print(f"{Fore.CYAN}{'='*70}\n")
        print(f"{Fore.GREEN}[+] Loading {len(json_files)} analysis file(s)...\n")
        
        for json_file in json_files:
            with open(json_file, 'r') as f:
                data = json.load(f)
                
                # Extract IOCs
                indicators = data.get('indicators', {})
                
                # Domains
                domains = indicators.get('domains', [])
                for domain in domains:
                    if domain not in self.iocs['domains']:
                        self.iocs['domains'].append(domain)
                
                # IPs
                ips = indicators.get('originating_ips', [])
                for ip in ips:
                    if ip not in self.iocs['ips']:
                        self.iocs['ips'].append(ip)
                
                # URLs (extract original, not defanged)
                urls = indicators.get('urls', [])
                for url_obj in urls:
                    original_url = url_obj.get('original', '')
                    if original_url and original_url not in self.iocs['urls']:
                        self.iocs['urls'].append(original_url)
        
        # Print summary
        total_iocs = len(self.iocs['domains']) + len(self.iocs['ips']) + len(self.iocs['urls'])
        print(f"{Fore.GREEN}[+] IOC Extraction Summary:")
        print(f"    Domains: {len(self.iocs['domains'])}")
        print(f"    IPs:     {len(self.iocs['ips'])}")
        print(f"    URLs:    {len(self.iocs['urls'])}")
        print(f"    TOTAL:   {total_iocs}\n")
    
    def _make_vt_request(self, endpoint, ioc_type, ioc_value):
        """Make VirusTotal API request with rate limiting"""
        try:
            url = f"{self.base_url}/{endpoint}"
            
            print(f"{Fore.CYAN}[+] Querying VirusTotal for {ioc_type}: {ioc_value[:50]}...")
            
            # Rate limiting (free tier: 4 req/min)
            if self.request_count > 0:
                print(f"{Fore.YELLOW}    [Rate Limit] Waiting {self.rate_limit_delay} seconds...")
                time.sleep(self.rate_limit_delay)
            
            response = requests.get(url, headers=self.headers, timeout=30)
            self.request_count += 1
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"{Fore.YELLOW}    [Not Found] IOC not in VirusTotal database")
                return None
            elif response.status_code == 429:
                print(f"{Fore.RED}    [Rate Limit Exceeded] Waiting 60 seconds...")
                time.sleep(60)
                return self._make_vt_request(endpoint, ioc_type, ioc_value)
            else:
                print(f"{Fore.RED}    [Error] HTTP {response.status_code}: {response.text[:100]}")
                return None
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}    [Timeout] Request timed out")
            return None
        except Exception as e:
            print(f"{Fore.RED}    [Error] {str(e)[:100]}")
            return None
    
    def enrich_domain(self, domain):
        """Enrich domain with VirusTotal data"""
        endpoint = f"domains/{domain}"
        vt_data = self._make_vt_request(endpoint, "Domain", domain)
        
        if not vt_data:
            return {
                'type': 'domain',
                'value': domain,
                'vt_available': False,
                'malicious': 'Unknown',
                'suspicious': 'Unknown',
                'harmless': 'Unknown',
                'reputation': 'Not found in VT',
                'categories': []
            }
        
        # Extract analysis stats
        attributes = vt_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        categories = attributes.get('categories', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        
        # Determine reputation
        if malicious > 0:
            reputation = f"{Fore.RED}MALICIOUS"
        elif suspicious > 5:
            reputation = f"{Fore.YELLOW}SUSPICIOUS"
        elif harmless > 10:
            reputation = f"{Fore.GREEN}LIKELY SAFE"
        else:
            reputation = f"{Fore.MAGENTA}UNKNOWN"
        
        print(f"{Fore.GREEN}    [Result] Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}")
        
        return {
            'type': 'domain',
            'value': domain,
            'vt_available': True,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'reputation': reputation.replace(Fore.RED, '').replace(Fore.YELLOW, '').replace(Fore.GREEN, '').replace(Fore.MAGENTA, ''),
            'categories': list(categories.values()) if categories else []
        }
    
    def enrich_ip(self, ip):
        """Enrich IP address with VirusTotal data"""
        endpoint = f"ip_addresses/{ip}"
        vt_data = self._make_vt_request(endpoint, "IP", ip)
        
        if not vt_data:
            return {
                'type': 'ip',
                'value': ip,
                'vt_available': False,
                'malicious': 'Unknown',
                'suspicious': 'Unknown',
                'harmless': 'Unknown',
                'reputation': 'Not found in VT',
                'country': 'Unknown',
                'asn': 'Unknown'
            }
        
        # Extract data
        attributes = vt_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        country = attributes.get('country', 'Unknown')
        asn = attributes.get('asn', 'Unknown')
        
        # Determine reputation
        if malicious > 0:
            reputation = f"{Fore.RED}MALICIOUS"
        elif suspicious > 5:
            reputation = f"{Fore.YELLOW}SUSPICIOUS"
        elif harmless > 10:
            reputation = f"{Fore.GREEN}LIKELY SAFE"
        else:
            reputation = f"{Fore.MAGENTA}UNKNOWN"
        
        print(f"{Fore.GREEN}    [Result] Malicious: {malicious}, Suspicious: {suspicious}, Country: {country}")
        
        return {
            'type': 'ip',
            'value': ip,
            'vt_available': True,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'reputation': reputation.replace(Fore.RED, '').replace(Fore.YELLOW, '').replace(Fore.GREEN, '').replace(Fore.MAGENTA, ''),
            'country': country,
            'asn': asn
        }
    
    def enrich_url(self, url):
        """Enrich URL with VirusTotal data"""
        import base64
        
        # VT requires base64-encoded URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"urls/{url_id}"
        
        vt_data = self._make_vt_request(endpoint, "URL", url)
        
        if not vt_data:
            return {
                'type': 'url',
                'value': url,
                'vt_available': False,
                'malicious': 'Unknown',
                'suspicious': 'Unknown',
                'harmless': 'Unknown',
                'reputation': 'Not found in VT'
            }
        
        # Extract stats
        attributes = vt_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        
        # Determine reputation
        if malicious > 0:
            reputation = f"{Fore.RED}MALICIOUS"
        elif suspicious > 5:
            reputation = f"{Fore.YELLOW}SUSPICIOUS"
        elif harmless > 10:
            reputation = f"{Fore.GREEN}LIKELY SAFE"
        else:
            reputation = f"{Fore.MAGENTA}UNKNOWN"
        
        print(f"{Fore.GREEN}    [Result] Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}")
        
        return {
            'type': 'url',
            'value': url,
            'vt_available': True,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'reputation': reputation.replace(Fore.RED, '').replace(Fore.YELLOW, '').replace(Fore.GREEN, '').replace(Fore.MAGENTA, '')
        }
    
    def enrich_all_iocs(self):
        """Enrich all extracted IOCs"""
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Starting VirusTotal Enrichment")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        total = len(self.iocs['domains']) + len(self.iocs['ips']) + len(self.iocs['urls'])
        print(f"{Fore.YELLOW}[!] This will make {total} API requests")
        print(f"{Fore.YELLOW}[!] Estimated time: ~{total * self.rate_limit_delay // 60} minutes (rate limited)\n")
        
        # Enrich domains
        if self.iocs['domains']:
            print(f"{Fore.CYAN}--- Enriching Domains ({len(self.iocs['domains'])}) ---\n")
            for domain in self.iocs['domains']:
                enriched = self.enrich_domain(domain)
                self.enriched_data.append(enriched)
                print()
        
        # Enrich IPs
        if self.iocs['ips']:
            print(f"{Fore.CYAN}--- Enriching IP Addresses ({len(self.iocs['ips'])}) ---\n")
            for ip in self.iocs['ips']:
                enriched = self.enrich_ip(ip)
                self.enriched_data.append(enriched)
                print()
        
        # Enrich URLs
        if self.iocs['urls']:
            print(f"{Fore.CYAN}--- Enriching URLs ({len(self.iocs['urls'])}) ---\n")
            for url in self.iocs['urls']:
                enriched = self.enrich_url(url)
                self.enriched_data.append(enriched)
                print()
        
        print(f"{Fore.GREEN}[+] Enrichment complete! Total requests: {self.request_count}\n")
    
    def save_results(self, output_dir):
        """Save enriched IOC data to JSON and CSV"""
        output_path = Path(output_dir)
        timestamp = datetime.now().strftime('%m-%d-%Y_%H-%M-%S')
        
        # Save JSON
        json_file = output_path / f"enriched_iocs_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.enriched_data, f, indent=4)
        
        print(f"{Fore.GREEN}[+] JSON report saved: {json_file}")
        
        # Save CSV
        csv_file = output_path / f"enriched_iocs_{timestamp}.csv"
        
        if self.enriched_data:
            fieldnames = ['type', 'value', 'vt_available', 'malicious', 'suspicious', 'harmless', 'reputation']
            
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(self.enriched_data)
            
            print(f"{Fore.GREEN}[+] CSV report saved: {csv_file}\n")
        
        return json_file, csv_file
    
    def print_summary(self):
        """Print enrichment summary"""
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}ENRICHMENT SUMMARY")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        malicious_count = sum(1 for ioc in self.enriched_data if isinstance(ioc.get('malicious'), int) and ioc['malicious'] > 0)
        suspicious_count = sum(1 for ioc in self.enriched_data if isinstance(ioc.get('suspicious'), int) and ioc['suspicious'] > 5)
        
        print(f"{Fore.RED}MALICIOUS IOCs:   {malicious_count}")
        print(f"{Fore.YELLOW}SUSPICIOUS IOCs:  {suspicious_count}")
        print(f"{Fore.GREEN}TOTAL ENRICHED:   {len(self.enriched_data)}\n")
        
        # List malicious IOCs
        if malicious_count > 0:
            print(f"{Fore.RED}--- Confirmed Malicious IOCs ---")
            for ioc in self.enriched_data:
                if isinstance(ioc.get('malicious'), int) and ioc['malicious'] > 0:
                    print(f"{Fore.RED}[!] {ioc['type'].upper()}: {ioc['value']} (Flagged by {ioc['malicious']} vendors)")
            print()

def main():
    parser = argparse.ArgumentParser(
        description='IOC Enrichment Tool with VirusTotal Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-a', '--analysis-dir', default='analysis',
                       help='Directory containing analysis JSON files (default: analysis)')
    parser.add_argument('-k', '--api-key', default='~/.config/phishing-ir/vt_api_key',
                       help='Path to VirusTotal API key file')
    parser.add_argument('-o', '--output', default='iocs',
                       help='Output directory for enriched IOC reports (default: iocs)')
    
    args = parser.parse_args()
    
    enricher = IOCEnricher(args.api_key)
    enricher.load_analysis_files(args.analysis_dir)
    enricher.enrich_all_iocs()
    enricher.save_results(args.output)
    enricher.print_summary()

if __name__ == '__main__':
    main()
