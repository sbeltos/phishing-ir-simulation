# Phishing Incident Report

**Incident ID:** PHI-2026-001  
**Report Date:** 02-07-2026  
**Incident Period:** 02-05-2026 08:23 UTC - 02-05-2026 17:45 UTC  
**Analyst:** Imam Uddin Mohammed  
**Classification:** Multi-Vector Phishing Campaign  
**Severity:** HIGH

---

## Executive Summary

On February 5, 2026, a sophisticated multi-vector phishing campaign targeting TargetCorp employees was detected and analyzed. The campaign consisted of three distinct attack vectors:

1. **Credential Harvesting** - Low sophistication phishing attempt using typosquatting and URL shorteners
2. **Malware Delivery** - Medium sophistication invoice fraud with malicious executable attachment
3. **Business Email Compromise (BEC)** - High sophistication CEO impersonation for wire transfer fraud

Through comprehensive forensic analysis, 10 Indicators of Compromise (IOCs) were extracted and enriched with threat intelligence. Two IP addresses were confirmed as malicious infrastructure, flagged by multiple security vendors. All affected systems were contained, malicious infrastructure blocked, and preventive measures implemented.

**Impact Assessment:**
- **Users Targeted:** 3 (Finance, Accounting, Executive)
- **Credentials Compromised:** 0 (detected before exploitation)
- **Malware Executed:** 0 (attachment not opened)
- **Financial Loss:** $0 (wire transfer not completed)
- **Data Exfiltration:** None detected

**Response Effectiveness:**
- **Mean Time to Detect (MTTD):** 1 hour 52 minutes
- **Mean Time to Contain (MTTC):** 47 minutes
- **Mean Time to Eradicate (MTTE):** 9 hours 23 minutes

---

## Table of Contents

1. [Incident Timeline](#incident-timeline)
2. [Technical Analysis](#technical-analysis)
3. [Attack Chain Reconstruction](#attack-chain-reconstruction)
4. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
5. [Threat Intelligence Assessment](#threat-intelligence-assessment)
6. [Containment Actions](#containment-actions)
7. [Affected Systems](#affected-systems)
8. [Root Cause Analysis](#root-cause-analysis)
9. [Recommendations](#recommendations)
10. [Appendices](#appendices)

---

## Incident Timeline

All times in UTC.

| Time | Event | Actor |
|------|-------|-------|
| **02-05-2026 08:23** | First phishing email delivered (Email 1 - Credential harvesting) | Attacker |
| **02-05-2026 10:15** | User (finance@targetcorp.com) reports suspicious email | Victim |
| **02-05-2026 10:17** | SOC begins initial triage | Analyst |
| **02-05-2026 10:30** | Email classified as HIGH severity phishing | Analyst |
| **02-05-2026 10:45** | Forensic analysis initiated (email_analyzer.py) | Analyst |
| **02-05-2026 11:02** | Email quarantine executed across all mailboxes | SOC |
| **02-05-2026 11:15** | IOC extraction completed (10 indicators identified) | Analyst |
| **02-05-2026 11:45** | VirusTotal enrichment initiated | Analyst |
| **02-05-2026 14:12** | IOC enrichment completed (2 malicious IPs confirmed) | Analyst |
| **02-05-2026 14:30** | Malicious IPs blocked at firewall | Network Team |
| **02-05-2026 15:00** | SIEM correlation completed (no additional victims found) | Analyst |
| **02-05-2026 15:45** | Blocklist generated and distributed to security controls | Analyst |
| **02-05-2026 16:30** | User notifications sent | Communications |
| **02-05-2026 17:45** | Incident contained, monitoring phase initiated | SOC Lead |

---

## Technical Analysis

### Email 1: Low Sophistication - Credential Harvesting

**Subject:** Urgent: Verify Your Account Within 24 Hours  
**From:** Payroll Services <noreply@payro11-verify.com>  
**To:** finance@targetcorp.com  
**Date:** 02-05-2026 08:23:10 -0800  
**Risk Score:** CRITICAL (145/100)

#### Header Analysis
```
Return-Path: <noreply@payro11-verify.com>
From: "Payroll Services" <noreply@payro11-verify.com>
Reply-To: support@payro11-verify.com
X-Originating-IP: [185.220.101.45]

Authentication Results:
  SPF: FAIL (domain does not authorize 185.220.101.45)
  DKIM: NONE
  DMARC: UNKNOWN
```

**Analysis:**
- **SPF Failure:** Sending IP (185.220.101.45) not authorized by payro11-verify.com
- **Missing DKIM:** No cryptographic signature present
- **Display Name Spoofing:** "Payroll Services" suggests legitimate sender, actual domain is suspicious
- **Typosquatting:** Domain uses "payro11" (two 1's) instead of "payroll"

#### Content Analysis

**Social Engineering Tactics:**
- Urgency: "within 24 hours" deadline
- Threats: "permanent deactivation" of account
- Authority: Claims to be "Payroll Security Team"
- Fear: Loss of access to "all payroll information"

**Technical Indicators:**
- Grammatical errors: "For security reason" (missing 's'), "temporary suspended"
- URL shortener: `http://bit.ly/3xY7Kq2` (hides actual destination)
- Generic greeting: "Dear Valued Customer" (not personalized)

#### IOCs Extracted

| Type | Value | Risk |
|------|-------|------|
| Domain | payro11-verify.com | HIGH (typosquatting) |
| IP | 185.220.101.45 | CRITICAL (VT: 14/90 malicious) |
| URL | http://bit.ly/3xY7Kq2 | MEDIUM (shortener) |

---

### Email 2: Medium Sophistication - Invoice Fraud

**Subject:** Invoice #INV-2025-4782 - Payment Due 02-10-2025  
**From:** Sarah Martinez - Accounts Receivable <billing@legitimate-vendor.com>  
**To:** accounting@targetcorp.com  
**Date:** 02-06-2026 14:12:40 -0800  
**Risk Score:** HIGH (50/100)

#### Header Analysis
```
Return-Path: <billing@legitimate-vendor.com>
From: "Sarah Martinez - Accounts Receivable" <billing@legitimate-vendor.com>
X-Originating-IP: [203.45.67.89]

Authentication Results:
  SPF: PASS
  DKIM: PASS (signature verified)
  DMARC: UNKNOWN
```

**Analysis:**
- **SPF/DKIM Pass:** Attacker either compromised legitimate vendor's infrastructure OR registered lookalike domain with proper authentication
- **Professional Formatting:** Corporate letterhead, proper invoice structure
- **No Obvious Errors:** Clean grammar, realistic details (invoice number, amounts)

#### Attachment Analysis

**Filename:** Invoice_INV-2025-4782.pdf.exe  
**Type:** Windows PE Executable (disguised as PDF)  
**Size:** 2.3 MB  
**Hash (SHA256):** [Not calculated - simulated sample]

**Critical Finding:** Double extension `.pdf.exe`
- Windows hides known extensions by default
- User sees: "Invoice_INV-2025-4782.pdf" (appears safe)
- Actually: Executable malware

**Behavioral Indicators:**
- Subject mentions "updated banking details" (social engineering for payment redirection)
- Creates urgency with "Net 10 days" payment terms
- Uses realistic vendor name and contact information

#### IOCs Extracted

| Type | Value | Risk |
|------|-------|------|
| Domain | legitimate-vendor.com | MEDIUM (spoofed vendor) |
| Domain | legitimate-vendor-secure.com | MEDIUM (lookalike) |
| IP | 203.45.67.89 | HIGH (VT: 1/90 malicious) |
| File | Invoice_INV-2025-4782.pdf.exe | CRITICAL (malware) |
| URL | https://legitimate-vendor-secure.com/invoices/download?id=INV-2025-4782&token=* | MEDIUM |

---

### Email 3: High Sophistication - Business Email Compromise (BEC)

**Subject:** RE: RE: Q1 Budget Reallocation - URGENT  
**From:** "Robert Williams (CEO)" <robert.williams@targetcorp-secure.com>  
**To:** "Jennifer Chen (CFO)" <jennifer.chen@targetcorp.com>  
**Date:** 02-07-2026 09:47:10 -0800  
**Risk Score:** HIGH (45/100)

#### Header Analysis
```
Return-Path: <robert.williams@targetcorp-secure.com>
From: "Robert Williams (CEO)" <robert.williams@targetcorp-secure.com>
X-Originating-IP: [45.67.89.123]
References: <original.thread.123@targetcorp.com> <reply.thread.456@targetcorp.com>
In-Reply-To: <reply.thread.456@targetcorp.com>

Authentication Results:
  SPF: NEUTRAL
  DKIM: PASS (signature verified for targetcorp-secure.com)
  DMARC: PASS
```

**Analysis:**
- **Domain Lookalike:** targetcorp-secure.com vs. legitimate targetcorp.com
- **Display Name Spoofing:** Shows "Robert Williams (CEO)" - user likely only sees this
- **Thread Hijacking Simulation:** References fake previous emails to appear legitimate
- **SPF Neutral:** Domain has no SPF record (neither authorizes nor denies sender)

#### Social Engineering Analysis (Advanced Tactics)

**Authority Exploitation:**
- Impersonates C-level executive (CEO → CFO communication)
- Uses executive language: "board meeting," "PE firm," "due diligence"

**Urgency Creation:**
- Time pressure: "before 3PM EST deadline"
- Unavailability: "in back-to-back meetings," "unreachable by phone"

**Confidentiality Manipulation:**
- "This is confidential - please handle personally"
- "do not discuss with anyone until the public announcement"
- Prevents victim from verifying with colleagues

**Legitimacy Building:**
- References specific (fake) project: "Project Atlas"
- Mentions realistic business activities: "acquisition due diligence," "confidentiality agreements"
- Includes detailed wire transfer instructions (realistic account format)

#### IOCs Extracted

| Type | Value | Risk |
|------|-------|------|
| Domain | targetcorp-secure.com | HIGH (lookalike) |
| IP | 45.67.89.123 | LOW (VT: 0/90 malicious) |
| IP | 198.51.100.50 | LOW (test network range) |

---

## Attack Chain Reconstruction

### Phase 1: Reconnaissance (Pre-Campaign)

**Attacker Actions:**
1. Identified target organization (TargetCorp)
2. Discovered key personnel via LinkedIn/public sources:
   - Finance team (payroll functions)
   - Accounting team (invoice processing)
   - Executive team (CEO, CFO names)
3. Registered malicious domains:
   - payro11-verify.com (typosquatting)
   - legitimate-vendor.com (generic vendor name)
   - targetcorp-secure.com (corporate lookalike)

**Infrastructure Setup:**
- Obtained VPS hosting (185.220.101.45 in Germany)
- Configured email server with SPF/DKIM for legitimacy
- Created phishing landing pages

### Phase 2: Initial Access (Email Delivery)

**Attack Vector:** Spear-phishing via email
- **Email 1:** Broad credential harvesting (low effort, high volume approach)
- **Email 2:** Targeted finance team (payment fraud)
- **Email 3:** Highly targeted executive (BEC, high-value fraud)

### Phase 3: Execution (Intended - Not Achieved)

**Email 1 Intended Goal:**
1. User clicks bit.ly link → Redirected to fake login page
2. User enters credentials → Captured by attacker
3. Attacker uses credentials → Accesses email/systems
4. Lateral movement → Compromise additional accounts

**Email 2 Intended Goal:**
1. User opens .pdf.exe attachment → Malware executes
2. Malware establishes C2 connection → Attacker gains remote access
3. Data exfiltration or ransomware deployment

**Email 3 Intended Goal:**
1. CFO authorizes wire transfer → $487,500 sent to attacker account
2. Funds transferred offshore → Unrecoverable
3. Attacker disappears

### Phase 4: Detection & Disruption (Actual Outcome)

**Defensive Success:**
- User recognition and reporting prevented exploitation
- Rapid SOC response contained threat before impact
- No credentials compromised, no malware executed, no financial loss

---

## Indicators of Compromise (IOCs)

### Consolidated IOC List

| Type | Value | Malicious Score | Reputation | Source Email |
|------|-------|-----------------|------------|--------------|
| **IP** | **185.220.101.45** | **14/90** | **MALICIOUS** | Email 1 |
| **IP** | **203.45.67.89** | **1/90** | **SUSPICIOUS** | Email 2 |
| IP | 45.67.89.123 | 0/90 | LIKELY SAFE | Email 3 |
| IP | 198.51.100.50 | 0/90 | LIKELY SAFE | Email 3 |
| Domain | payro11-verify.com | Not in VT | UNKNOWN (Fresh) | Email 1 |
| Domain | legitimate-vendor.com | Not in VT | UNKNOWN (Fresh) | Email 2 |
| Domain | legitimate-vendor-secure.com | Not in VT | UNKNOWN (Fresh) | Email 2 |
| Domain | targetcorp-secure.com | Not in VT | UNKNOWN (Fresh) | Email 3 |
| URL | http://bit.ly/3xY7Kq2 | Not in VT | UNKNOWN | Email 1 |
| URL | https://legitimate-vendor-secure.com/invoices/download?id=* | Not in VT | UNKNOWN | Email 2 |

**VT = VirusTotal enrichment performed 02-05-2026**

### Critical IOC Details

**185.220.101.45** (BLOCK IMMEDIATELY)
```
Country: Germany (DE)
ASN: AS60729 (Hosting provider)
VirusTotal: Flagged by 14 security vendors including:
  - Fortinet
  - Sophos
  - ESET
  - Dr.Web
  - Kaspersky
Known association: Phishing infrastructure, spam operations
```

**203.45.67.89** (MONITOR/ALERT)
```
Country: Australia (AU)
ASN: AS1221 (Telstra - Major ISP)
VirusTotal: Flagged by 1 vendor
Assessment: Possibly compromised residential/business connection
```

---

## Threat Intelligence Assessment

### Campaign Attribution

**Threat Actor Profile:** Financially Motivated Cybercriminal  
**Sophistication Level:** Medium to High  
**Likely Geography:** Eastern Europe (based on IP geolocation, infrastructure patterns)

**Evidence:**
- Multi-vector approach suggests experienced actor
- Professional Email 2 & 3 indicate significant preparation
- Use of compromised/bulletproof hosting (185.220.101.45)
- Fresh domain registration (OPSEC to avoid blocklists)

### Campaign Objectives

**Primary:** Financial theft via:
1. Credential harvesting → Account takeover → Payroll fraud
2. Malware deployment → Ransomware or data theft
3. Wire transfer fraud → Direct monetary gain

**Secondary:** Establish persistent access for future attacks

### Tactics, Techniques, Procedures (TTPs)

Mapped to MITRE ATT&CK Framework:

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Email 1, bit.ly link |
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Email 2, .pdf.exe |
| Initial Access | Phishing: Spearphishing via Service | T1566.003 | Email 3, BEC |
| Execution | User Execution: Malicious File | T1204.002 | Email 2, intended .exe execution |
| Credential Access | Input Capture: Credential API Hooking | T1056.004 | Email 1, fake login page |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | All emails, domain spoofing |
| Impair Defenses | Impair Command History Logging | T1562.003 | N/A (not achieved) |

---

## Containment Actions

### Immediate Actions (Executed 02-05-2026 10:45 - 11:30 UTC)

1. **Email Quarantine**
```
   Platform: Microsoft 365 / Exchange
   Action: Purged all instances of phishing emails from user mailboxes
   Scope: Organization-wide (all mailboxes scanned)
   Result: 3 emails removed successfully
```

2. **IP Blocking**
```
   Device: Palo Alto PA-5220 Firewall
   Action: Added 185.220.101.45 and 203.45.67.89 to deny list
   Rule: Block all inbound/outbound traffic
   Result: 0 subsequent connection attempts detected
```

3. **Domain Blocking**
```
   Device: Cisco Web Security Appliance (WSA)
   Action: Added malicious domains to URL blocklist
   Domains: payro11-verify.com, legitimate-vendor-secure.com, targetcorp-secure.com
   Result: DNS resolution blocked for all users
```

### Short-Term Containment (Executed 02-05-2026 11:30 - 17:45 UTC)

4. **Account Monitoring**
```
   Platform: Splunk SIEM
   Action: Added targeted users to watchlist
   Monitored: Login attempts, password changes, unusual file access
   Duration: 48 hours enhanced monitoring
   Result: No suspicious activity detected
```

5. **Enhanced Email Filtering**
```
   Platform: Proofpoint Email Gateway
   Action: Created custom rules for similar sender patterns
   Rules:
     - Block emails from domains registered < 7 days ago
     - Quarantine emails with double-extension attachments
     - Flag emails with urgent payment language
   Result: 2 similar phishing attempts blocked within 24 hours
```

---

## Affected Systems

### User Accounts

| User | Department | Email Received | Action Taken | Credential Compromise | System Compromise |
|------|------------|----------------|--------------|----------------------|-------------------|
| finance@targetcorp.com | Finance | Email 1 | Reported to SOC | NO | NO |
| accounting@targetcorp.com | Accounting | Email 2 | Did not interact | NO | NO |
| jennifer.chen@targetcorp.com | Executive (CFO) | Email 3 | Did not respond | NO | NO |

**Total Affected Users:** 3  
**Users Who Interacted:** 0  
**Compromised Accounts:** 0

### Infrastructure Status

| System | Impact | Status |
|--------|--------|--------|
| Email Gateway (Proofpoint) | None | Operational - Enhanced rules active |
| Firewall (Palo Alto) | None | Operational - Blocklist updated |
| SIEM (Splunk) | None | Operational - Monitoring active |
| Endpoints | None | No malware detected |
| Domain Controllers | None | No unauthorized access |

---

## Root Cause Analysis

### Vulnerability Exploited

**Primary:** Human factor - Social engineering susceptibility

**Contributing Factors:**
1. **No External Sender Warning:** Emails from external domains not clearly marked
2. **Weak Domain Reputation Checks:** Newly registered domains not automatically flagged
3. **Insufficient User Training:** Users not familiar with advanced phishing techniques (BEC, typosquatting)
4. **Lack of DMARC Enforcement:** No p=reject policy on corporate domain allows spoofing

### Attack Success Factors (From Attacker Perspective)

**What Worked for Attacker:**
- Email delivery bypassed spam filters (2/3 emails SPF passed or neutral)
- Professional formatting reduced suspicion (Emails 2 & 3)
- Executive impersonation created urgency (Email 3)

**What Failed for Attacker:**
- User awareness and reporting (Email 1 detected quickly)
- SOC detection capabilities (rapid triage and analysis)
- Insufficient reconnaissance (Emails sent to users who didn't fall for social engineering)

### Defense Success Factors

**What Worked for Defense:**
1. **Security-Aware Culture:** User immediately reported suspicious email
2. **Rapid Response:** SOC initiated analysis within 2 minutes of report
3. **Automated Tooling:** Email analyzer and IOC enrichment enabled fast forensics
4. **Threat Intelligence:** VirusTotal confirmed malicious infrastructure
5. **Comprehensive Playbook:** NIST-aligned procedures guided systematic response

---

## Recommendations

### Immediate Actions (0-30 days)

**Priority: CRITICAL**

1. **Implement DMARC with Reject Policy**
```
   Current: No DMARC or p=none
   Recommended: p=reject for @targetcorp.com
   Impact: Prevents domain spoofing (Email 3 type attacks)
   Owner: Email Admin / DNS Team
   Timeline: 1 week
```

2. **Deploy External Email Warning Banners**
```
   Implementation: Add yellow banner to all external emails
   Text: "⚠️ This email originated from outside the organization. Exercise caution with links and attachments."
   Impact: Increases user awareness
   Owner: Email Admin
   Timeline: 3 days
```

3. **Enforce MFA for All Accounts**
```
   Current: 67% MFA adoption
   Target: 100% enforcement (no exceptions)
   Impact: Mitigates credential theft (Email 1 type attacks)
   Owner: IT Security
   Timeline: 14 days
```

### Short-Term Actions (30-90 days)

**Priority: HIGH**

4. **Advanced Phishing Training Campaign**
```
   Target: All employees, especially Finance/Executive
   Focus: BEC awareness, typosquatting, attachment safety
   Method: Simulated phishing tests + remedial training for clickers
   Frequency: Quarterly
   Owner: Security Awareness Team
   Timeline: 30 days
```

5. **Enhanced Email Gateway Rules**
```
   Rules to Implement:
     - Block emails from domains registered < 30 days
     - Quarantine double-extension attachments (.pdf.exe, .doc.exe)
     - Flag emails requesting wire transfers or urgent payments
     - Rewrite all URLs for sandboxing (Proofpoint URL Defense)
   Owner: Email Security Team
   Timeline: 45 days
```

6. **Implement Domain Monitoring**
```
   Service: Domain typosquatting monitoring (e.g., DomainTools)
   Alerts: Notify when lookalike domains registered (targetcorp-secure, etc.)
   Action: Proactive takedown requests
   Owner: Threat Intelligence Team
   Timeline: 60 days
```

### Long-Term Actions (90+ days)

**Priority: MEDIUM**

7. **Deploy Email Authentication Verification Tool**
```
   Solution: BIMI (Brand Indicators for Message Identification)
   Benefit: Display company logo only for authenticated emails
   Impact: Users can visually confirm legitimate emails
   Owner: Email Admin + Marketing
   Timeline: 90 days
```

8. **Implement User Behavior Analytics (UBA)**
```
   Platform: Splunk UBA or similar
   Detection: Anomalous login patterns, data access, email forwarding rules
   Impact: Detect compromised accounts even after initial breach
   Owner: SOC / SIEM Team
   Timeline: 120 days
```

9. **Establish Threat Intelligence Sharing**
```
   Program: Join industry ISAC (Information Sharing and Analysis Center)
   Benefit: Receive early warnings of campaigns targeting similar organizations
   Owner: Threat Intelligence Team
   Timeline: 90 days
```

### Policy & Process Updates

10. **Update Incident Response Playbook**
```
    Addition: Add specific procedures for BEC scenarios
    Include: Wire transfer verification workflows (callback verification)
    Owner: SOC Lead
    Timeline: 30 days
```

11. **Financial Controls Enhancement**
```
    Implement: Dual-authorization for wire transfers > $10,000
    Require: Voice confirmation (in-person or recorded call) for executive requests
    Owner: Finance Department
    Timeline: 30 days
```

---

## Appendices

### Appendix A: Full IOC List (Machine-Readable Format)

**JSON Format:**
```json
{
  "campaign_id": "PHI-2026-001",
  "iocs": {
    "ips": [
      {"value": "185.220.101.45", "reputation": "malicious", "vt_score": "14/90"},
      {"value": "203.45.67.89", "reputation": "suspicious", "vt_score": "1/90"}
    ],
    "domains": [
      {"value": "payro11-verify.com", "type": "typosquatting"},
      {"value": "legitimate-vendor-secure.com", "type": "lookalike"},
      {"value": "targetcorp-secure.com", "type": "lookalike"}
    ],
    "urls": [
      {"value": "http://bit.ly/3xY7Kq2", "type": "shortener"}
    ]
  }
}
```

### Appendix B: Email Samples

All email samples sanitized and stored in: `/samples/` directory
- email_01_low_sophistication.eml
- email_02_medium_sophistication.eml
- email_03_high_sophistication.eml

### Appendix C: Analysis Reports

Detailed JSON analysis reports: `/analysis/` directory
- email_01_low_sophistication_analysis.json
- email_02_medium_sophistication_analysis.json
- email_03_high_sophistication_analysis.json

### Appendix D: Enriched IOC Data

VirusTotal enrichment results: `/iocs/` directory
- enriched_iocs_02-05-2026_10-45-09.json
- enriched_iocs_02-05-2026_10-45-09.csv
- blocklist.txt

### Appendix E: Incident Response Playbook

NIST-aligned procedures: `/playbook/Phishing_Incident_Response_Playbook.md`

---

## Approval & Distribution

**Prepared By:**  
Imam Uddin Mohammed  
Security Analyst  
Date: 02-07-2026

**Reviewed By:**  
Michael Chen  
SOC Manager  
Date: 02-07-2026

**Approved By:**  
Dr. Sarah Johnson  
Chief Information Security Officer  
Date: 02-07-2026

---

**Note:** *This is a simulated incident response project for portfolio demonstration purposes. All names (except the author), company names, and scenarios are fictional.*


**Distribution List:**
- Executive Leadership (CEO, CFO, CTO)
- IT Security Team
- SOC Team
- Finance Department
- Legal / Compliance
- External: [If breach notification required]

---

**Classification:** Internal Use Only  
**Retention:** 7 years (compliance requirement)

---

**END OF REPORT**
