### Teaching Threat Hunting for Equifax Breach-Like Attacks (2017): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in web application exploits and large-scale PII theft, I'll guide you through proactive threat hunting to detect attacks resembling the 2017 Equifax data breach. This was a state-sponsored operation (suspected Chinese hackers, per U.S. intelligence and Mandiant analysis), exploiting an unpatched vulnerability in Apache Struts (CVE-2017-5638, a remote code execution flaw in the web app framework) on Equifax's U.S. consumer dispute portal. Attackers gained initial access in May 2017, enumerated back-end systems, dumped ~147.9 million consumer records (names, SSNs, DOBs, addresses, driver's licenses, credit card numbers for 209K), and exfiltrated data over ~2 months. No ransomware; focus was on identity theft enablers. An expired web app security certificate further aided evasion by blocking scans.

Dwell time: ~76 days (May 13-July 30, 2017), undetected due to unpatched Struts (despite March 2017 patch), poor segmentation (web app to DB), no SIEM for app logs, and ignored alerts. Detection: July 29, 2017, via suspicious traffic by security team; full scope revealed in September 2017. Impacts: $1.4B FTC settlement (2019), CEO Richard Smith's resignation, 40 class actions consolidated, free credit monitoring for victims, and accelerated U.S. regulations (e.g., CCPA influences). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Exploit Public-Facing Application T1190), TA0002 (Execution: Exploitation for Client Execution T1203), TA0008 (Lateral Movement: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0007 (Discovery: Account Discovery T1087), TA0006 (Credential Access: OS Credential Dumping T1003), TA0009 (Collection: Data from Information Repositories T1213), and TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002).

Threat hunting assumes exploit: Hypothesis-driven searches for web app vulns leading to DB theft in financial/consumer firms. Realistic parameters:
- **Environment**: Web-facing apps (e.g., Struts on Tomcat), connected DBs (SQL Server); high-volume PII.
- **Adversary Profile**: State-sponsored (zero-day exploits, low-noise exfil; identity fraud goals).
- **Challenges**: Legacy unpatched apps, massive data masking exfil, certificate gaps.
- **Tools/Data Sources**: WAF logs (ModSecurity), EDR (Defender for endpoints), SIEM (Splunk for app/DB logs), vuln scanners (Nessus), YARA/Sigma for Struts IOCs (e.g., SHA256: 4e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f).
- **Hypotheses**: E.g., "An adversary has exploited web vulns to dump PII from DBs."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from ReliaQuest's MITRE analysis, House Oversight report, and Mandiant). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., app sims) to avoid PCI-DSS issues. Baselines: 30-60 days of web/DB logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—Equifax's unpatched Struts enabled DB access; prioritize app scanning.
- **Gather Threat Intel**: Review MITRE ATT&CK for T1190 (e.g., Struts exploits). IOCs: CVE-2017-5638 payloads (e.g., Content-Type header exploits), DB dumps (SQL injection patterns). Cross-ref ReliaQuest MITRE mapping, Breachsense case study, Wikipedia, and Equifax disclosure.
- **Map Your Environment**: Inventory web apps (Struts/Tomcat), DBs (SQL connections). Use Nessus for CVE scans; BloodHound for app-to-DB paths.
- **Baseline Normal Behavior**: Log app requests (no exploits), DB queries (no dumps). Tool: Sysmon (app config for process/network); WAF for headers.
- **Expert Tip**: Renew certs quarterly. Hypothesis: "State actors exploit web vulns for PII; hunt anomalous app traffic leading to DB queries."

#### Step 2: Hunt for Initial Access (TA0001) - Exploit Public-Facing Application (T1190)
Exploited CVE-2017-5638 in Struts for RCE.
- **Hypothesis**: "An adversary has exploited a web app vuln for shell access."
- **Data Sources**: WAF logs (ModSecurity), app errors (Tomcat catalina.out), network (port 80/443 anomalies).
- **Step-by-Step Hunting**:
  1. Query Exploits: Splunk SPL: `index=web sourcetype=modsec | search msg="CVE-2017-5638" OR header="Content-Type: %{(#nike='multipart/form-data')" | stats count by src_ip | where count > 1`.
  2. Sigma Rule (YAML):
     ```
     title: Struts RCE Exploit
     logsource:
       category: web
     detection:
       selection:
         request_header: 'Content-Type: %{(#.*)'
         status: '200'  # Success
       condition: selection
     ```
     Deploy in SIEM; alert on Struts headers.
  3. Analyze: Grep app logs for RCE indicators (e.g., command injection); hunt failed scans pre-success.
  4. Pivoting: Trace to shell (e.g., Event ID 4688 for cmd.exe).
- **Expert Tip**: Patch Struts immediately. Realistic: Zero-day use; hunt header anomalies.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution (T1203)
Executed code via Struts to enumerate DB.
- **Hypothesis**: "Exploit leads to command execution on app server."
- **Data Sources**: Sysmon ID 1 (shell spawns), Event ID 4688.
- **Step-by-Step**:
  1. Query Shells: Splunk: `index=endpoint EventID=1 | search ParentImage="*tomcat*" Image="cmd.exe" CommandLine="*sql*" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Web Shell Execution
     logsource:
       category: process_creation
     detection:
       selection:
         ParentImage: '*java.exe*'  # Struts/Tomcat
         Image: 'cmd.exe OR powershell.exe'
         CommandLine: '*whoami OR *net user*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw malfind | grep struts` (injected code).
  4. Pivoting: To DB connects.
- **Expert Tip**: WAF behavioral rules. Realistic: RCE to recon; hunt java children.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Used exploited access to create backdoors or reuse creds.
- **Hypothesis**: "Adversary persists via stolen app/DB creds."
- **Data Sources**: Event ID 4720 (accounts), Sysmon ID 13 (webshells).
- **Step-by-Step**:
  1. Query Backdoors: Splunk: `index=web file_create="*.jsp" OR EventID=4720 | search host="app_server" | stats count by user`.
  2. Sigma Rule:
     ```
     title: Web App Persistence
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.jsp OR *.asp'  # Webshell
         Host: 'web_app'
       condition: selection
     ```
  3. Scan: Autoruns for rogue services.
  4. Pivoting: To lateral.
- **Expert Tip**: File integrity monitoring. Realistic: Short dwell; hunt new files.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Escalated from app to DB via token or SQL injection.
- **Hypothesis**: "Web access escalated to DB privs."
- **Data Sources**: Sysmon ID 10 (sqlservr.exe), Event ID 4673.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" SubjectUserName="app_user" | table _time, host`.
  2. Sigma Rule:
     ```
     title: DB Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*sqlservr.exe*'
         GrantedAccess: '0x1410'
       condition: selection
     ```
  3. Analyze: SQL injection in app logs.
  4. Pivoting: To collection.
- **Expert Tip**: DB least-priv. Realistic: App-to-DB; hunt sqlservr.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
Bypassed scans via expired cert; no direct impairment.
- **Hypothesis**: "Exploit evades via config gaps."
- **Data Sources**: App logs (cert errors), WAF bypasses.
- **Step-by-Step**:
  1. Query Gaps: Splunk: `index=app error="certificate expired" | stats count by host | where count > 0`.
  2. Sigma Rule:
     ```
     title: Security Config Evasion
     logsource:
       category: application
     detection:
       selection:
         log: '*certificate expired* OR *scan blocked*'
       condition: selection
     ```
  3. Audit: Cert validity.
  4. Pivoting: To discovery.
- **Expert Tip**: Auto-renew certs. Realistic: Blocked detection; hunt errors.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped DB creds post-exploit.
- **Hypothesis**: "App shell dumps creds for DB."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4688.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr Target="lsass.exe" CallTrace="*MiniDump*" host="app" | stats dc(host)`.
  2. Sigma Rule:
     ```
     title: DB Cred Dump
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe*'
         CallTrace: '*MiniDump*'
       condition: selection
     ```
  3. Forensics: Volatility dumpfiles.
  4. Pivoting: To queries.
- **Expert Tip**: Encrypted conn strings. Realistic: Enabled dumps; hunt lsass.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087)
Enumerated DB schemas/tables for PII.
- **Hypothesis**: "Recon for consumer data in DB."
- **Data Sources**: SQL audit (SELECT information_schema), Event ID 4662.
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=db query="information_schema" OR "SHOW TABLES" | stats count by session`.
  2. Sigma Rule:
     ```
     title: DB Schema Discovery
     logsource:
       category: database
     detection:
       selection:
         query: '*DESCRIBE* OR *information_schema*'
       condition: selection
     ```
  3. Analyze: Table names like "consumers".
  4. Pivoting: To collection.
- **Expert Tip**: Schema restrictions. Realistic: Targeted PII; hunt schema.

#### Step 9: Hunt for Lateral Movement (TA0008) - Valid Accounts (T1078.002)
Pivoted from app to internal DB via creds.
- **Hypothesis**: "Web to DB via stolen creds."
- **Data Sources**: Event ID 5145 (DB connects), Sysmon ID 3 (1433).
- **Step-by-Step**:
  1. Query Pivots: Splunk: `index=network protocol=tds dest_port=1433 src="app_server" | stats count by user`.
  2. Sigma Rule:
     ```
     title: App-to-DB Lateral
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 1433
         Src: 'web_app'
       condition: selection
     ```
  3. Traffic: Anomalous SQL from web.
  4. Pivoting: To dumps.
- **Expert Tip**: DB segmentation. Realistic: Direct connect; hunt ports.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Dumped 147M records to temp files.
- **Hypothesis**: "PII collected from consumer DB."
- **Data Sources**: SQL audit (SELECT * FROM consumers), temp file creates.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=db query="SELECT * FROM consumers" rows > 1M | stats sum(rows) by session`.
  2. Sigma Rule:
     ```
     title: Mass PII Dump
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM *consumers* OR *credit*'
         rows_returned: '>100K'
       condition: selection
     ```
  3. Volume: Temp file sizes.
  4. Pivoting: To exfil.
- **Expert Tip**: Query limits. Realistic: Bulk SELECT; hunt rows.

#### Step 11: Hunt for Command and Control (TA0011) - Minimal (Direct DB)
No C2; direct app/DB access.
- **Hypothesis**: "Access via direct APIs without beacons."
- **Data Sources**: Network (no outbound), session persistence.
- **Step-by-Step**:
  1. Query Sessions: Splunk: `index=db session_duration > 1h | stats avg(duration) by ip`.
  2. Sigma Rule:
     ```
     title: Persistent DB Sessions
     logsource:
       category: database
     detection:
       selection:
         session_time: '>3600s'
       condition: selection
     ```
  3. Geoloc: External IPs.
  4. Pivoting: To exfil.
- **Expert Tip**: Session timeouts. Realistic: No malware; hunt long sessions.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated dumps via web (e.g., HTTP POST).
- **Hypothesis**: "DB data exfil over app channels."
- **Data Sources**: Network (large POSTs), app logs.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=web http_method=POST bytes_out > 100MB | stats sum(bytes) by src_ip`.
  2. Sigma Rule:
     ```
     title: PII Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_length: '>50MB'
       condition: selection
     ```
  3. PCAP: Payloads with SSNs.
  4. Pivoting: Dark web dumps.
- **Expert Tip**: WAF exfil rules. Realistic: Chunked; hunt volumes.

#### Step 13: Hunt for Impact (TA0040) - No Destruction
Impact via identity theft; no wipe.
- **Hypothesis**: "Theft enables fraud; monitor downstream."
- **Data Sources**: Fraud alerts, HIBP.
- **Step-by-Step**:
  1. Query Fraud: Splunk: `index=external event="PII_leak" domain="equifax" | stats count by source`.
  2. Sigma Rule:
     ```
     title: Post-Breach Fraud
     logsource:
       category: external
     detection:
       selection:
         event: 'ssn_theft'
       condition: selection
     ```
  3. Monitor: Credit freezes.
  4. Pivoting: Victim notifications.
- **Expert Tip**: PII monitoring. Realistic: Ongoing fraud; hunt leaks.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (patch Struts, isolate apps), eradicate (DB scan, cred reset), recover (notify FTC, offer monitoring). Like Equifax, settle class actions; disclose promptly.
- **Lessons**: Per House report, patch vulns, segment DBs, renew certs. Iterate bi-weekly; simulate with Struts in labs.
- **Expert Tip**: ATT&CK Navigator for finance; evolve for 2025 (e.g., AI vuln scanning).
