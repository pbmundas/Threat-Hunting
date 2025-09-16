### Teaching Threat Hunting for Adobe Breach-Like Attacks (2013): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with deep experience in enterprise software supply-chain compromises and large-scale data exfiltration incidents, I'll guide you through proactive threat hunting to detect attacks resembling the 2013 Adobe breach. This was a sophisticated cybercrime operation (no specific attribution, but likely Eastern European or state-linked actors based on forum dumps), targeting Adobe's customer database and intellectual property. Attackers exploited an unpatched vulnerability in Adobe's ColdFusion server (CVE-2013-3331, a remote code execution flaw in the web application framework) to gain initial access, then pivoted to dump ~153 million user records (initially reported as 38M, later expanded via HIBP analysis). Stolen data included internal IDs, usernames, emails, encrypted (unsalted 3DES) passwords, plaintext password hints, and ~2.9M credit card details. Additionally, ~40GB of source code for products like Acrobat, Reader, ColdFusion, and Photoshop was exfiltrated, enabling potential backdooring or reverse engineering.

The dwell time was ~2 months (mid-August to early October 2013), with detection via an external security researcher (Brian Krebs) spotting a 3.8GB dump on a Russian forum, prompting Adobe's internal confirmation. Impacts: $1M+ settlement from class-action lawsuits, eroded customer trust, widespread credential stuffing (e.g., cracked passwords led to ATOs), and long-term IP risks (e.g., poisoned updates). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Exploit Public-Facing Application T1190), TA0002 (Execution: Exploitation for Client Execution T1203), TA0003 (Persistence: Create or Modify System Process T1543), TA0008 (Lateral Movement: Exploitation of Remote Services T1210), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0005 (Defense Evasion: Impair Defenses T1562.001 via weak encryption).

Threat hunting assumes breach: Hypothesis-driven searches for web app exploits leading to DB/IP theft in software firms. Realistic parameters:
- **Environment**: Hybrid cloud/on-prem (e.g., ColdFusion on IIS/Apache, SQL Server/Oracle DBs, dev repos like Git); high-value targets (customer DBs, source code vaults).
- **Adversary Profile**: Cybercriminals (opportunistic RCE, bulk dumps for dark web sales; low noise, focus on monetization).
- **Challenges**: Unpatched legacy apps (ColdFusion EOL risks), weak crypto (unsalted 3DES crackable offline), massive data volumes masking exfil.
- **Tools/Data Sources**: SIEM (Splunk/ELK for web/DB logs), WAF (ModSecurity), EDR (Microsoft Defender), cloud trails (Azure/AWS), vuln scanners (Nessus), YARA/Sigma for IOCs (e.g., ColdFusion exploits).
- **Hypotheses**: E.g., "An adversary has exploited a web app vuln to access DBs and exfil source code."

This guide covers **each relevant MITRE ATT&CK technique** (inferred from Krebs reports, Adobe disclosures, and HIBP). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., staging servers) to avoid prod impact. Baselines: 30-60 days of web/DB logs for anomaly detection.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—Adobe's unpatched ColdFusion enabled RCE, leading to DB pivots.
- **Gather Threat Intel**: Review MITRE ATT&CK for T1190 (e.g., ColdFusion exploits). IOCs: CVE-2013-3331 payloads (e.g., JSP webshells like "cfinclude.jsp"), dump patterns (e.g., forum posts with Adobe hashes), source code archives (e.g., ph1.tar.gz from Krebs). Cross-ref Krebs on Security , HIBP , BBC , and Adobe's 2013 blog.
- **Map Your Environment**: Inventory public-facing apps (e.g., ColdFusion instances), DB schemas (user tables with creds), IP repos (e.g., SVN/Git). Use tools like Shodan for exposed ports (8500 for ColdFusion) or AWS Config for asset lists.
- **Baseline Normal Behavior**: Log web requests (e.g., anomalous POSTs to /CFIDE/admin), DB queries (SELECT on users), outbound traffic (large ZIP/TAR). Tool: Enable IIS advanced logging; Sysmon for server processes.
- **Expert Tip**: Scan for legacy ColdFusion (v9/10 vulnerable); hypothesis: "Attackers target unpatched web apps for RCE; hunt exploit attempts on admin endpoints."

#### Step 2: Hunt for Initial Access (TA0001) - Exploit Public-Facing Application (T1190)
Entry via CVE-2013-3331 in ColdFusion, allowing unauth RCE (e.g., uploading JSP shells).
- **Hypothesis**: "An adversary has exploited a web app vuln to upload shells or execute code."
- **Data Sources**: WAF/IIS logs (e.g., 404s on /CFIDE/), error logs (CFIDE exceptions), network metadata (Zeek for port 8500 probes).
- **Step-by-Step Hunting**:
  1. Query Exploit Attempts: Splunk SPL: `index=web sourcetype=iis | search uri_path="/CFIDE/admin/*" OR payload="*cfexecute*" | stats count by client_ip, user_agent | where count > 5`.
  2. Sigma Rule (YAML):
     ```
     title: ColdFusion RCE Exploit (CVE-2013-3331)
     logsource:
       category: web
     detection:
       selection:
         request_uri: '/CFIDE/administrator/*'
         method: 'POST'
         body: '*<cfexecute*' OR '*jsp shell*'
       condition: selection
     ```
     Deploy in SIEM; alert on anomalous POSTs from non-US IPs (Adobe breach had Eastern European ties).
  3. Analyze Payloads: Grep access logs for JSP uploads (e.g., "cfinclude.jsp" or base64 shells); use Burp Suite for replay testing.
  4. Pivoting: If hits, check for successful 200 OK on shell endpoints; trace to DB connects.
- **Expert Tip**: Patch ColdFusion; use ASLR/DEP. Realistic: 2013 exploits were public; hunt for scanner traffic (e.g., Nessus signatures).

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client/Server Execution (T1203/T1499)
Post-RCE, executed commands to pivot (e.g., cmd.exe for recon).
- **Hypothesis**: "Shells are executing system commands on compromised servers."
- **Data Sources**: Sysmon (Event ID 1: Process Creation from cfserver), Windows Event ID 4688, CF logs (cfserver.log for <cfexecute>).
- **Step-by-Step**:
  1. Query Anomalous Processes: Splunk: `index=endpoint EventID=1 | search ParentImage="*cfserver*" AND Image="cmd.exe" OR "powershell.exe" | table _time, host, CommandLine`.
  2. Sigma Rule:
     ```
     title: RCE Command Execution via ColdFusion
     logsource:
       category: process_creation
     detection:
       selection:
         ParentImage: '*cfserver* OR *coldfusion*'
         Image: 'cmd.exe'
         CommandLine: '*net user*' OR '*whoami*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f memdump.raw --profile=Win7SP1x86 pslist | grep cfserver` (scan for injected threads).
  4. Pivoting: Correlate with file creations (e.g., webshells in /CFIDE/).
- **Expert Tip**: Block <cfexecute> in CF configs. Realistic: Execution was low-volume; hunt parent-child anomalies.

#### Step 4: Hunt for Persistence (TA0003) - Create or Modify System Process (T1543), Server Software Component (T1574)
Uploaded persistent webshells (e.g., modified CF components) or scheduled tasks.
- **Hypothesis**: "Adversary maintains access via webshells or modified services."
- **Data Sources**: Sysmon (Event ID 13: Registry Modify for tasks), file integrity monitoring (e.g., Tripwire for /ColdFusion/wwwroot changes).
- **Step-by-Step**:
  1. Query Shell Uploads: Splunk: `index=web | search file_extension="jsp" OR "cfm" AND uri_path="/upload*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Webshell Persistence in ColdFusion
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*cfinclude.jsp* OR *shell.cfm*'
         Image: '*cfserver*'
       condition: selection
     ```
  3. Integrity Check: Autoruns for rogue tasks; YARA: `rule AdobeWebshell { strings: $shell = "<cfexecute name='cmd' " condition: $shell }` on web roots.
  4. Pivoting: Link to repeated accesses from same IP.
- **Expert Tip**: Immutable file systems for web roots. Realistic: Shells evaded basic AV; behavioral hunting key.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Exploitation for Privilege Escalation (T1068)
Escalated via local vulns or misconfigs (e.g., default CF admin creds).
- **Hypothesis**: "Low-priv shell escalated to DB/IP access."
- **Data Sources**: Event ID 4673 (Privilege Use), Sysmon ID 10 (Process Access to svchost).
- **Step-by-Step**:
  1. Query Escalations: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebugPrivilege*" AND SubjectUserName="IUSR" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Web App Privilege Escalation
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Account: 'IUSR' OR 'cfadmin'
         Privileges: '*SeTcbPrivilege*'
       condition: selection
     ```
  3. Analyze: Check for UAC bypass (e.g., fodhelper.exe chains).
  4. Pivoting: Follow to SQL logins (e.g., sa account use).
- **Expert Tip**: Least-priv for app pools. Realistic: CF defaults enabled escalation; audit service accounts.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001), Weak Crypto (T1552.001)
Disabled logs; exploited unsalted 3DES for easy cracking.
- **Hypothesis**: "Malware evades via log tampering; creds use crackable crypto."
- **Data Sources**: Event ID 1102 (Log Cleared), DB schema (password fields).
- **Step-by-Step**:
  1. Query Log Tampering: Splunk: `index=security EventID=1102 OR 4719 | stats count by host`.
  2. Sigma Rule:
     ```
     title: Log Impairment Post-RCE
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 1102
         Source: '*cfserver*'
       condition: selection
     ```
  3. Crypto Audit: Query DB: `SELECT COUNT(*) FROM users WHERE password LIKE '%[a-zA-Z0-9+/]{24}='` (3DES base64); test crack with John the Ripper.
  4. Pivoting: Hunt for wevtutil.exe executions.
- **Expert Tip**: Centralize logs off-host. Realistic: Unsalted 3DES cracked 90%; baseline hash strength.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552)
Dumped DB creds (unsalted 3DES passwords, hints).
- **Hypothesis**: "Adversary dumped auth data from DB."
- **Data Sources**: SQL audit logs (Event ID 33205 for SELECT on users).
- **Step-by-Step**:
  1. Query DB Dumps: Splunk: `index=db | search query="*SELECT * FROM users password*" | stats sum(rows) by session`.
  2. Sigma Rule:
     ```
     title: Credential DB Dump
     logsource:
       category: database
     detection:
       selection:
         query: '*password OR hint FROM users*'
         rows_returned: '>1M'
       condition: selection
     ```
  3. Forensics: Sample hashes for 3DES patterns; crack test.
  4. Pivoting: Check for UNION queries in web logs.
- **Expert Tip**: Salted bcrypt min. Realistic: Hints aided cracking; hunt query volumes.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087), Permission Groups Discovery (T1069)
Enumerated DB schemas and AD groups for pivots.
- **Hypothesis**: "Recon for high-value data (creds, source code)."
- **Data Sources**: DB logs for SHOW TABLES, Event ID 4662 (Object Access).
- **Step-by-Step**:
  1. Query Schema Recon: Splunk: `index=db query="INFORMATION_SCHEMA" OR "SHOW TABLES" | stats count by ip`.
  2. Sigma Rule:
     ```
     title: DB Schema Discovery
     logsource:
       category: database
     detection:
       selection:
         query: '*DESCRIBE users* OR *SELECT * FROM information_schema*'
       condition: selection
     ```
  3. AD Hunt: net.exe executions in CF logs.
  4. Pivoting: Follow to source code repo accesses (e.g., SVN queries).
- **Expert Tip**: Log schema queries. Realistic: Started with CF admin enum.

#### Step 9: Hunt for Lateral Movement (TA0008) - Exploitation of Remote Services (T1210), Valid Accounts (T1078.002)
Pivoted to DB/source repos via stolen creds or additional RCE.
- **Hypothesis**: "Movement from web server to internal DB/IP stores."
- **Data Sources**: Event ID 4624 (Logons Type 3 for network), Sysmon ID 3 (connects to 1433 SQL).
- **Step-by-Step**:
  1. Query Lateral Logons: Splunk: `index=ad EventID=4624 LogonType=3 | search AccountName="cfadmin" | stats count by src_host, dest_host`.
  2. Sigma Rule:
     ```
     title: Lateral to DB via Stolen Creds
     logsource:
       category: authentication
     detection:
       selection:
         LogonType: 3
         Account: 'db_user' OR 'svn_user'
         Source: 'web_server'
       condition: selection
     ```
  3. Network: Zeek for anomalous SQL/SVN traffic.
  4. Pivoting: Trace to file accesses in repos.
- **Expert Tip**: Network segmentation. Realistic: Pivots were credential-based.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Staged DB dumps and source code (e.g., TAR.GZ archives).
- **Hypothesis**: "Bulk collection of user data and IP."
- **Data Sources**: Sysmon ID 11 (file creates in temp), DB export logs.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FilePath="*temp*" FileName="*.gz OR *.sql" Size > 1GB | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: Source Code/Data Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.tar.gz' OR '*.sql_dump'
         Size: '>100MB'
       condition: selection
     ```
  3. Repo Audit: Git log for bulk clones.
  4. Pivoting: Correlate with compression tools (7z.exe).
- **Expert Tip**: DLP on repos. Realistic: 40GB staged; hunt large files.

#### Step 11: Hunt for Command and Control (TA0011) - Minimal (Internal Pivots)
No heavy C2; possible beaconing if external shell.
- **Hypothesis**: "Shells phoning home for commands."
- **Data Sources**: Sysmon ID 3 (outbound to high ports).
- **Step-by-Step**:
  1. Query Beacons: Splunk: `index=network dest_port>1024 | stats dc(dest_ip) by src_ip | where dc > 20/hour`.
  2. Sigma Rule:
     ```
     title: Webshell C2
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '80 OR 443'
         Image: '*cfserver*'
       condition: selection
     ```
  3. Traffic: Wireshark for POSTs with encoded dumps.
  4. Pivoting: Block IOC domains from forums.
- **Expert Tip**: Proxy all outbound. Realistic: Mostly autonomous.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated via HTTP (large POSTs) or FTP to attacker servers.
- **Hypothesis**: "Staged data exfil over web channels."
- **Data Sources**: Network logs (bytes out >1GB), WAF for uploads.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 500MB | stats sum(bytes_out) by dest_ip`.
  2. Sigma Rule:
     ```
     title: Bulk Data Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_length: '>1GB'
         uri: '*upload* OR *ftp*'
       condition: selection
     ```
  3. PCAP: tshark -Y "http.request.method == POST && http.content_length > 1G".
  4. Pivoting: Dark web scans for Adobe dumps (e.g., via HIBP API).
- **Expert Tip**: Rate-limit egress. Realistic: Chunks over weeks; anomaly on volumes.

#### Step 13: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486, via Cracking), Account Access Removal
Cracked creds led to ATOs; source code risks (backdoors).
- **Hypothesis**: "Compromised data used for downstream attacks."
- **Data Sources**: Auth logs (failed logins), HIBP alerts.
- **Step-by-Step**:
  1. Query Stuffing: Splunk: `index=auth failed_attempts > 10 user IN (adobe_breached) | stats count by ip`.
  2. Sigma Rule:
     ```
     title: Post-Breach Credential Stuffing
     logsource:
       category: authentication
     detection:
       selection:
         event: 'failed login'
         source_ip: 'tor_exit' OR 'vpn'
       condition: selection
     ```
  3. IP Impact: Scan releases for backdoored code.
  4. Pivoting: Force pw resets if hits.
- **Expert Tip**: Monitor HIBP. Realistic: Ongoing ATOs; hunt reuse.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (patch/isolate), eradicate (shell removal), recover (pw rotation, code audits). Like Adobe, notify and offer monitoring.
- **Lessons**: Patch web apps; use strong crypto. Iterate bi-weekly; simulate with Metasploit (ColdFusion modules).
- **Expert Tip**: ATT&CK Navigator for gaps; evolve for 2025 (e.g., AI exfil detection).
