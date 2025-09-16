### Teaching Threat Hunting for British Airways Breach-Like Attacks (2018): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in third-party supply chain and Magecart-style client-side attacks, I'll guide you through proactive threat hunting to detect attacks resembling the 2018 British Airways (BA) data breach. This was a Magecart attack (digital skimming) attributed to the Magecart Group 10 (likely Eastern European cybercriminals, per RiskIQ and Positive Technologies analysis), targeting BA's website via a compromised third-party supplier (Swissport, a cargo handler). On June 22, 2018, attackers stole login credentials for Swissport's remote access gateway, injected malicious JavaScript (22 lines of code) into BA's checkout page (via a third-party script), and skimmed data from ~380,000-430,000 customers over 15 days (until September 5, 2018). Stolen data included names, addresses, emails, payment card numbers, CVVs, and expiration dates—enough for fraud. The script redirected data to a hacker-controlled domain (e.g., baways[.]com). BA detected it on September 5, 2018, after a third-party alert, notifying the ICO on September 6.

Dwell time: ~75 days (June 22-September 5, 2018), undetected due to no client-side script monitoring, weak third-party vetting, and no integrity checks on JS files. Detection: Internal review prompted by external tip; ICO fined BA £20M (reduced from £183M) in October 2020 for GDPR violations (Article 5(1)(f) and 32). Impacts: £20M ICO fine (1.5% turnover), £22M class-action settlement (2021), reputational damage, and PCI-DSS scrutiny. From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts T1078.004 via third-party creds), TA0002 (Execution: User Execution T1204.002 via JS), TA0005 (Defense Evasion: Obfuscated Files T1027), TA0007 (Discovery: Account Discovery T1087), TA0008 (Lateral Movement: Valid Accounts T1078.002), TA0009 (Collection: Data from Information Repositories T1213 via skimming), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0004 (Privilege Escalation: Valid Accounts T1078).

Threat hunting assumes compromise: Hypothesis-driven searches for third-party script injection and skimming in e-commerce. Realistic parameters:
- **Environment**: Web apps with third-party JS (e.g., analytics/payment scripts), no SRI (Subresource Integrity).
- **Adversary Profile**: Cybercriminals (credential stuffing for supply chain, lightweight JS skimmers; carding goals).
- **Challenges**: Client-side attacks bypass server-side, third-party trust, obfuscated JS.
- **Tools/Data Sources**: WAF (Cloudflare for JS), SIEM (Splunk for web logs), JS scanners (Retire.js), YARA/Sigma for Magecart IOCs (e.g., baways[.]com redirects).
- **Hypotheses**: E.g., "An adversary compromises third-party creds to inject skimmers into checkout JS."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from RiskIQ's Magecart report and ICO notice). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., web labs) to avoid PCI-DSS issues. Baselines: 30-60 days of web/third-party logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—BA's third-party compromise enabled JS injection; prioritize script integrity.
- **Gather Threat Intel**: Review MITRE ATT&CK for Magecart (e.g., T1195 for supply chain). IOCs: JS redirects (e.g., baways[.]com), credential patterns (Swissport logins), skimmer hashes (MD5: 22-line obfuscated JS). Cross-ref Wikipedia, RiskIQ analysis (Magecart Group 10), ICO fine notice, and Fideres case study.
- **Map Your Environment**: Inventory third-party scripts (e.g., Swissport-like gateways), checkout JS (payment forms). Use OWASP ZAP for scanning; BloodHound for access paths.
- **Baseline Normal Behavior**: Log JS loads (trusted domains), form submissions (no redirects). Tool: Sysmon (web config for process/network); enable WAF for JS changes.
- **Expert Tip**: Implement SRI/COEP for scripts. Hypothesis: "Magecart compromises third-party creds to inject skimmers; hunt anomalous JS leading to form data theft."

#### Step 2: Hunt for Initial Access (TA0001) - Valid Accounts (T1078.004: Third-party)
Compromised Swissport creds for gateway access.
- **Hypothesis**: "An adversary has stolen third-party creds for network entry."
- **Data Sources**: Auth logs (Event ID 4624), third-party access (Swissport VPN).
- **Step-by-Step Hunting**:
  1. Query Third-Party Logons: Splunk SPL: `index=auth EventID=4624 | search AccountName="third_party*" LogonType=3 src_domain="swissport" | stats count by src_ip | where src_ip!="known"`.
  2. Sigma Rule (YAML):
     ```
     title: Third-Party Credential Abuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'vendor* OR *third*'
         LogonType: 3
         SrcGeo: NOT 'EU'
       condition: selection
     ```
     Deploy in SIEM; alert on vendor anomalies.
  3. Analyze: Hunt credential stuffing (Event ID 4771 failures then success); cross-ref dark web dumps.
  4. Pivoting: Trace to JS modifications (file changes on web servers).
- **Expert Tip**: MFA for vendors. Realistic: Swissport creds; hunt external vendor logons.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.002): Malicious File/JS
Injected JS executed on client-side during checkout.
- **Hypothesis**: "Compromised access executes JS skimmer on forms."
- **Data Sources**: Web logs (JS loads), Sysmon ID 1 (if server-side), client telemetry.
- **Step-by-Step**:
  1. Query JS Injection: Splunk: `index=web sourcetype=access_combined | search uri_path="*.js" content="*baways.com*" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Malicious JS Execution
     logsource:
       category: web
     detection:
       selection:
         request_uri: '*.js'
         response_body: '*redirect* OR *post to external*'
       condition: selection
     ```
  3. Analyze: Deobfuscate JS (e.g., 22 lines redirecting form data); hunt form submissions.
  4. Pivoting: To data collection.
- **Expert Tip**: JS integrity checks (SRI). Realistic: Client-side; hunt redirects.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Reused stolen creds for ongoing injection.
- **Hypothesis**: "Adversary persists via persistent third-party access."
- **Data Sources**: Event ID 4624 (repeated logons), gateway logs.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=auth AccountName="swissport" | stats count by src_ip, _time | where count > 5/day`.
  2. Sigma Rule:
     ```
     title: Persistent Vendor Access
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'vendor*'
         Frequency: '>3/hour'
       condition: selection
     ```
  3. Scan: Session persistence in gateway.
  4. Pivoting: To discovery.
- **Expert Tip**: Session timeouts. Realistic: 15-day dwell; hunt repeated.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Escalated via unsecured admin password found post-access.
- **Hypothesis**: "Vendor creds escalated to web admin."
- **Data Sources**: Event ID 4673, gateway priv changes.
- **Step-by-Step**:
  1. Query Escalations: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" Account="vendor" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Vendor Escalation
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Account: 'third_party*'
         Privileges: '*Full*'
       condition: selection
     ```
  3. Analyze: Hunt plain-text admin pwds in configs.
  4. Pivoting: To JS injection.
- **Expert Tip**: Least-priv vendors. Realistic: Unsecured pw; hunt grants.

#### Step 6: Hunt for Defense Evasion (TA0005) - Obfuscated Files or Information (T1027)
Obfuscated JS (minified/encoded) to evade scans.
- **Hypothesis**: "Skimmer evades via obfuscated code."
- **Data Sources**: Web logs (JS entropy), WAF bypasses.
- **Step-by-Step**:
  1. Query Obfuscation: Splunk: `index=web response_body_entropy > 7 uri="*.js" | stats count by file_hash`.
  2. Sigma Rule:
     ```
     title: Obfuscated JS Skimmer
     logsource:
       category: web
     detection:
       selection:
         response_body: base64_encoded OR minified_js
         uri: '*.js'
       condition: selection
     ```
  3. Analyze: Deobfuscate with JS Beautifier.
  4. Pivoting: To collection.
- **Expert Tip**: JS scanners (Retire.js). Realistic: 22 lines; hunt entropy.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552)
Stole creds via gateway compromise.
- **Hypothesis**: "Third-party creds enable access."
- **Data Sources**: Failed logons (4771), gateway audits.
- **Step-by-Step**:
  1. Query Access: Splunk: `index=auth EventID=4771 Account="swissport" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Vendor Cred Theft
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4771
         Account: 'third_party*'
       condition: selection
     ```
  3. Forensics: Dark web scans.
  4. Pivoting: To discovery.
- **Expert Tip**: Rotate vendor creds. Realistic: Stuffing; hunt failures.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087)
Discovered web files for injection points.
- **Hypothesis**: "Access used to recon JS files."
- **Data Sources**: Web logs (directory enum), file accesses.
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=web status=200 uri="/admin*" OR "*.js" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Web Recon
     logsource:
       category: web
     detection:
       selection:
         request_uri: '/admin OR *.js'
         status: '200'
       condition: selection
     ```
  3. Analyze: Hunt for JS directories.
  4. Pivoting: To injection.
- **Expert Tip**: Dir listing disable. Realistic: Found checkout JS; hunt probes.

#### Step 9: Hunt for Lateral Movement (TA0008) - Valid Accounts (T1078.002)
Moved from gateway to web server via creds.
- **Hypothesis**: "Vendor access pivots to web assets."
- **Data Sources**: Event ID 5145 (shares), Sysmon ID 3.
- **Step-by-Step**:
  1. Query Pivots: Splunk: `index=network protocol=smb user="vendor" dest="web" | stats count by src, dest`.
  2. Sigma Rule:
     ```
     title: Vendor-to-Web Lateral
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         User: 'third_party*'
         Dest: 'web_server'
       condition: selection
     ```
  3. Traffic: Anomalous from gateway.
  4. Pivoting: To collection.
- **Expert Tip**: Vendor segmentation. Realistic: Gateway to site; hunt shares.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Skimmed form data (cards, PII) via JS.
- **Hypothesis**: "Injected JS collects payment data."
- **Data Sources**: Web logs (form posts), client telemetry.
- **Step-by-Step**:
  1. Query Skimming: Splunk: `index=web form_field="card_number" redirect="baways.com" | stats count by session`.
  2. Sigma Rule:
     ```
     title: Form Skimming
     logsource:
       category: web
     detection:
       selection:
         request_body: '*card_number OR *cvv*'
         redirect: external
       condition: selection
     ```
  3. Analyze: Regex for card patterns.
  4. Pivoting: To exfil.
- **Expert Tip**: Form validation. Realistic: 380K skimmed; hunt posts.

#### Step 11: Hunt for Command and Control (TA0011) - Minimal (Direct Redirect)
JS redirected to attacker domain for C2-like exfil.
- **Hypothesis**: "Skimmer redirects for data harvest."
- **Data Sources**: Web logs (redirects), client-side.
- **Step-by-Step**:
  1. Query Redirects: Splunk: `index=web status=302 location="baways.com" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: JS Redirect C2
     logsource:
       category: web
     detection:
       selection:
         status: '302'
         location: '*external_domain*'
       condition: selection
     ```
  3. Traffic: Client redirects.
  4. Pivoting: To impact.
- **Expert Tip**: CSP headers. Realistic: Direct; hunt 302s.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Redirected form data to baways[.]com.
- **Hypothesis**: "Skimmed data exfil via redirects."
- **Data Sources**: Web logs (POST to external), network.
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=web http_method=POST dest="baways.com" bytes_out > 1KB | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: Skimmer Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         dest: '*baways*'
       condition: selection
     ```
  3. PCAP: Card data payloads.
  4. Pivoting: To fraud.
- **Expert Tip**: Redirect blocks. Realistic: 15-day harvest; hunt external POSTs.

#### Step 13: Hunt for Impact (TA0040) - No Destruction
Impact via fraud (card theft); secondary risks (identity).
- **Hypothesis**: "Theft enables downstream fraud."
- **Data Sources**: Fraud logs, HIBP.
- **Step-by-Step**:
  1. Query Fraud: Splunk: `index=external event="card_fraud" source="ba_breach" | stats count by bin`.
  2. Sigma Rule:
     ```
     title: Post-Skim Fraud
     logsource:
       category: external
     detection:
       selection:
         event: 'card_theft'
       condition: selection
     ```
  3. Monitor: Chargeback spikes.
  4. Pivoting: Client alerts.
- **Expert Tip**: Fraud monitoring. Realistic: Carding; hunt patterns.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (remove JS, isolate vendors), eradicate (cred rotation, scan sites), recover (notify ICO, offer monitoring). Like BA, settle claims; implement PCI-DSS.
- **Lessons**: Per ICO, vet third-parties, monitor JS, enforce GDPR. Iterate monthly; simulate with Magecart in labs.
- **Expert Tip**: ATT&CK Navigator for e-comm; evolve for 2025 (e.g., AI JS analysis).
