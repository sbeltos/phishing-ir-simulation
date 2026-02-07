# Phishing Incident Response Playbook

**Author:** Imam Uddin Mohammed  
**Version:** 1.0  
**Last Updated:** 02-07-2026  
**Framework:** NIST SP 800-61 Rev. 2

---

## Table of Contents

1. [Overview](#overview)
2. [Preparation](#preparation)
3. [Detection & Analysis](#detection--analysis)
4. [Containment](#containment)
5. [Eradication](#eradication)
6. [Recovery](#recovery)
7. [Post-Incident Activity](#post-incident-activity)
8. [Appendix: Tools & Commands](#appendix-tools--commands)

---

## Overview

### Purpose
This playbook provides standardized procedures for responding to phishing incidents, from initial detection through post-incident review. It aligns with NIST Incident Response Lifecycle phases.

### Scope
- Email-based phishing attacks (credential harvesting, malware delivery, BEC)
- Applicable to all organizational users and systems
- Covers technical and non-technical response actions

### Incident Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|---------------|
| **CRITICAL** | Credentials compromised, malware executed, executive targeted | < 15 minutes |
| **HIGH** | Malicious attachment/link, multiple users affected | < 30 minutes |
| **MEDIUM** | Suspicious email detected, no user interaction | < 2 hours |
| **LOW** | Obvious spam, caught by filters | < 24 hours |

---

## Preparation

### 1.1 Team Roles & Responsibilities

| Role | Responsibilities |
|------|------------------|
| **Incident Commander** | Overall coordination, stakeholder communication, escalation decisions |
| **Triage Analyst** | Initial email analysis, IOC extraction, severity classification |
| **Threat Intel Analyst** | IOC enrichment, attribution, campaign correlation |
| **Containment Lead** | Email quarantine, account lockdown, system isolation |
| **Communications** | User notifications, executive updates, external reporting |

### 1.2 Required Tools

**Analysis Tools:**
- Email analysis platform (email_analyzer.py or commercial tool)
- VirusTotal API access
- Sandbox environment (ANY.RUN, Joe Sandbox, Cuckoo)
- WHOIS lookup tools

**Response Tools:**
- Email security gateway (Proofpoint, Mimecast, etc.)
- SIEM (Splunk, ELK, Sentinel)
- EDR platform (CrowdStrike, SentinelOne, Defender ATP)
- Firewall/proxy management console

**Communication:**
- Incident tracking system (Jira, ServiceNow)
- Secure messaging (Slack, Teams)
- Email templates (pre-approved by Legal/Comms)

### 1.3 Pre-Incident Preparation

- [ ] Maintain updated email security gateway rules
- [ ] Configure SIEM alerts for phishing indicators
- [ ] Test email quarantine procedures monthly
- [ ] Document MFA reset procedures
- [ ] Pre-stage analysis VM with required tools
- [ ] Establish communication trees (on-call rotation)

---

## Detection & Analysis

### 2.1 Detection Sources

**Common Detection Methods:**
1. **User Reports** - Security-aware users forward suspicious emails
2. **Email Gateway Alerts** - SEG flags high-risk messages
3. **SIEM Correlation** - Multiple failed login attempts after email delivery
4. **Threat Intel Feeds** - Known IOCs appear in email logs
5. **EDR Alerts** - Suspicious process execution after attachment opened

### 2.2 Initial Triage (< 15 minutes)

**Step 1: Confirm Incident**
```
[ ] Verify email is not legitimate business communication
[ ] Check sender authentication (SPF/DKIM/DMARC)
[ ] Identify phishing type:
    [ ] Credential harvesting
    [ ] Malware delivery
    [ ] Business Email Compromise (BEC)
    [ ] Invoice/payment fraud
```

**Step 2: Scope Assessment**
```
[ ] How many users received the email?
    Query: index=email sender="<suspicious_address>" | stats count by recipient
[ ] Did anyone click links or open attachments?
    Check: Web proxy logs, EDR telemetry
[ ] Are credentials compromised?
    Check: Failed login attempts, password resets, unusual access patterns
```

**Step 3: Severity Classification**
Use criteria from Overview section to assign severity level.

### 2.3 Deep Analysis (< 2 hours)

**Email Forensics:**
```bash
# Extract email headers and metadata
python3 email_analyzer.py phishing_sample.eml -o analysis/

# Review key indicators:
- Return-Path vs From address mismatch
- X-Originating-IP geolocation
- Received headers (trace email path)
- Display name spoofing
```

**IOC Extraction:**
```
[ ] Domains (sender, reply-to, embedded links)
[ ] IP addresses (originating server, relay hops)
[ ] URLs (defang and analyze)
[ ] File hashes (MD5, SHA256 of attachments)
[ ] Email addresses (sender, reply-to)
```

**Threat Intelligence Enrichment:**
```bash
# Enrich IOCs with VirusTotal
python3 ioc_enrichment.py -a analysis/ -o iocs/

# Check for:
- Known malicious infrastructure
- Attribution to threat actor groups
- Related campaigns
```

**Attachment Analysis (if applicable):**
```
[ ] Static analysis:
    - File type validation (check magic bytes vs extension)
    - Extract embedded URLs/IPs
    - Check for macros, embedded executables
    
[ ] Dynamic analysis (sandbox):
    - Upload to ANY.RUN, Joe Sandbox, or Hybrid Analysis
    - Monitor: Network connections, file modifications, registry changes
    - Document: C2 servers, dropped files, persistence mechanisms
```

**Link Analysis:**
```
[ ] Unshorten URLs (bit.ly, tinyurl, etc.)
    curl -sI <shortened_url> | grep -i location
    
[ ] Screenshot landing pages (safely via sandbox)
    
[ ] Check for:
    - Credential harvesting forms
    - Malware downloads
    - Exploit kits
```

### 2.4 Documentation

**Required Information:**
- Timeline of events (UTC timestamps)
- List of affected users
- IOC inventory (IPs, domains, URLs, hashes)
- User actions taken (clicked, downloaded, entered credentials)
- Systems potentially compromised
- Initial attack vector assessment

---

## Containment

### 3.1 Immediate Actions (< 30 minutes)

**Email Quarantine:**
```powershell
# Microsoft 365 - Purge emails
Search-Mailbox -Identity "all-users" -SearchQuery 'Subject:"Urgent: Verify Your Account"' -DeleteContent

# Alternative: Use Compliance Center Content Search
New-ComplianceSearch -Name "Phishing_Campaign_001" -ExchangeLocation All -ContentMatchQuery 'From:attacker@malicious.com'
```

**Block IOCs:**
```bash
# Firewall - Block malicious IPs
# Palo Alto example:
configure
set address malicious_ip_185 ip-netmask 185.220.101.45/32
set address malicious_ip_203 ip-netmask 203.45.67.89/32
set rulebase security rules block_phishing_ips source any destination [malicious_ip_185 malicious_ip_203] action deny
commit

# Proxy - Block domains
# Cisco WSA / Squid example:
echo "payro11-verify.com" >> /etc/squid/blocked_domains.txt
squid -k reconfigure
```

**Account Security:**
```
[ ] Force password reset for users who clicked links
    - Prioritize: Users who entered credentials
    - Method: Automated via IAM system or manual IT ticket
    
[ ] Revoke active sessions
    - Azure AD: Revoke-AzureADUserAllRefreshToken -ObjectId <user_id>
    - On-prem AD: Expire Kerberos tickets
    
[ ] Enable MFA (if not already enforced)
    - Prioritize high-value targets (executives, finance, IT)
```

### 3.2 Short-Term Containment (< 2 hours)

**Endpoint Isolation:**
```
[ ] If malware suspected:
    - Isolate affected endpoints via EDR
    - CrowdStrike: contain-host --host <hostname>
    - Disconnect from network (last resort)
```

**Monitoring:**
```
[ ] Enhanced logging:
    - Increase verbosity for affected user accounts
    - Monitor: Login locations, access patterns, file access
    
[ ] SIEM watchlist:
    - Add affected users to monitoring dashboard
    - Alert on: Off-hours access, unusual data transfers, privilege escalation
```

**Communication:**
```
[ ] Notify affected users:
    - Template: "Security Incident Notification"
    - Instructions: Change password, report unusual activity
    - Do NOT provide IOCs (avoid tipping off sophisticated attacker)
    
[ ] Inform IT Help Desk:
    - Expect increased password reset requests
    - Flag: Requests from unaffected users (potential lateral spread)
```

---

## Eradication

### 4.1 Malware Removal (if applicable)
```
[ ] Use EDR to:
    - Terminate malicious processes
    - Delete dropped files
    - Remove persistence mechanisms (registry keys, scheduled tasks, services)
    
[ ] Validate removal:
    - Re-scan with multiple AV engines
    - Check for remnants (temp files, prefetch)
    
[ ] If eradication fails:
    - Reimage compromised systems from known-good baseline
```

### 4.2 Access Revocation
```
[ ] Disable compromised accounts (if exfiltration confirmed)
    
[ ] Rotate credentials for:
    - Service accounts accessed from compromised systems
    - Privileged accounts if admin compromise suspected
    
[ ] Invalidate API keys / tokens if exposed
```

### 4.3 Update Defenses
```
[ ] Email gateway rules:
    - Add sender domains to blocklist
    - Implement advanced filtering (similar subject lines, sender patterns)
    
[ ] Web proxy:
    - Block phishing domains/IPs
    - Add URL patterns to deny list
    
[ ] Endpoint protection:
    - Update signatures with file hashes
    - Deploy custom detection rules (YARA, Sigma)
    
[ ] Network firewall:
    - Implement egress filtering (block known C2 IPs)
```

---

## Recovery

### 5.1 Service Restoration
```
[ ] Unlock accounts (after password reset + validation)
    
[ ] Return isolated endpoints to production:
    - Verify clean state
    - Restore from backup if necessary
    - Gradually reconnect (monitor for 24-48 hours)
    
[ ] Resume normal email flow:
    - Remove temporary quarantine rules
    - Transition to permanent blocklists
```

### 5.2 Verification
```
[ ] Confirm no re-infection:
    - Full environment scan
    - Review authentication logs (no unauthorized access)
    
[ ] Test business processes:
    - Users can send/receive email normally
    - Critical applications accessible
    
[ ] Validate security controls:
    - Email gateway catching similar attempts
    - SIEM alerts triggering appropriately
```

### 5.3 User Communication
```
Subject: Security Incident Resolution - Action Required

Dear [User],

The security incident reported on [DATE] has been resolved. All identified threats have been removed from our environment.

ACTION REQUIRED:
1. Your password was reset as a precaution. Please set a new password via [LINK].
2. Enable Multi-Factor Authentication (MFA) if not already active: [INSTRUCTIONS].
3. Review your recent account activity for any suspicious logins: [LINK].

If you notice any unusual activity, report immediately to security@company.com.

Thank you for your vigilance.

Security Operations Team
```

---

## Post-Incident Activity

### 6.1 Lessons Learned (within 30 days)

**Conduct post-mortem meeting with:**
- Incident response team
- Affected department managers
- IT/Security leadership

**Discussion Points:**
```
[ ] What happened? (timeline, root cause)
[ ] What went well? (effective controls, quick detection)
[ ] What could improve? (gaps in process, tool limitations)
[ ] Action items:
    - Technical improvements (tool upgrades, additional monitoring)
    - Process changes (playbook updates, training needs)
    - Policy updates (acceptable use, reporting procedures)
```

### 6.2 Metrics & Reporting

**Track KPIs:**
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Mean Time to Contain (MTTC)
- User click rate (% who interacted with phishing email)
- Recurrence rate (same user targeted again)

**Generate Reports:**
- Executive summary (business impact, high-level actions)
- Technical report (IOCs, tactics, detailed timeline)
- Compliance report (if required by regulation: GDPR, HIPAA, PCI-DSS)

### 6.3 Continuous Improvement

**Update Security Posture:**
```
[ ] Phishing simulation training:
    - Target users who fell for attack
    - Incorporate lessons from this campaign
    
[ ] Email security hardening:
    - Implement DMARC (p=reject) if not already
    - Enable link rewriting / sandboxing
    - Deploy anti-spoofing banners
    
[ ] Detection tuning:
    - Refine SIEM correlation rules
    - Adjust email gateway thresholds
    
[ ] Threat intelligence:
    - Share IOCs with industry ISACs
    - Subscribe to relevant feeds
```

---

## Appendix: Tools & Commands

### A.1 Email Analysis

**Extract .eml from Outlook:**
```
1. Open email in Outlook
2. File > Save As > Save as type: Outlook Message Format (*.msg)
3. Convert .msg to .eml using tool or script
```

**Parse email headers (Linux):**
```bash
# View full headers
cat email.eml | grep -E "^(From|To|Subject|Return-Path|Received|X-Originating-IP):"

# Trace email path
cat email.eml | grep "^Received:" | tac
```

### A.2 IOC Investigation

**WHOIS lookup:**
```bash
whois payro11-verify.com

# Key fields:
# - Creation Date (recently registered = suspicious)
# - Registrar (common abuse registrars: Namecheap, GoDaddy privacy)
# - Registrant (WHOIS privacy = hiding identity)
```

**DNS records:**
```bash
# Check MX records (does domain receive email?)
dig payro11-verify.com MX

# Check SPF record
dig payro11-verify.com TXT | grep spf

# Check A record (IP address)
dig payro11-verify.com A
```

**IP geolocation:**
```bash
# Using curl + ip-api.com
curl http://ip-api.com/json/185.220.101.45

# Fields: country, city, ISP, ASN
```

### A.3 SIEM Queries

**Splunk - Find emails from malicious sender:**
```spl
index=email sender_address="noreply@payro11-verify.com"
| table _time, recipient_address, subject, action
| sort -_time
```

**Splunk - Check if users clicked links:**
```spl
index=proxy url="*payro11-verify.com*"
| stats count by src_user, url, action
```

**Splunk - Failed login attempts after phishing:**
```spl
index=authentication action=failure
earliest=-24h
| where user IN ("victim1@company.com", "victim2@company.com")
| table _time, user, src_ip, reason
```

### A.4 Useful Websites

- **VirusTotal:** https://www.virustotal.com
- **URLScan.io:** https://urlscan.io (screenshot & analyze URLs safely)
- **ANY.RUN:** https://any.run (interactive malware sandbox)
- **MXToolbox:** https://mxtoolbox.com (email diagnostics)
- **PhishTank:** https://phishtank.org (community-sourced phishing database)
- **Abuse.ch:** https://abuse.ch (malware & botnet tracking)

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 02-06-2026 | Imam Uddin Mohammed | Initial release |

---

**END OF PLAYBOOK**
