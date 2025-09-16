### Teaching Threat Hunting for Change Healthcare Ransomware Attack-Like Attacks (2024): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in ransomware operations targeting critical infrastructure like healthcare, I'll guide you through proactive threat hunting to detect attacks resembling the 2024 Change Healthcare ransomware incident. This was a devastating RaaS attack attributed to the ALPHV/BlackCat ransomware group (Russian-linked cybercriminals, per UnitedHealth Group confirmation on February 29, 2024), affecting Change Healthcare (a UnitedHealth Group subsidiary processing 15 billion claims annually, 1/3 of U.S. patient records). Attackers gained access via exploitation of vulnerabilities in ConnectWise ScreenConnect (CVE-2024-1708/1709, remote code execution flaws allowing authentication bypass), deployed ransomware on February 21, 2024, encrypting systems and causing nationwide disruptions. The attack halted claims processing, prescription fills, and payments for weeks, exfiltrating data on ~192.7 million individuals (names, addresses, DOBs, SSNs, diagnoses, PHI). BlackCat claimed responsibility on February 28, 2024, posting screenshots on their leak site. A $22M Bitcoin ransom was reportedly paid on March 1, 2024, but the group vanished in March amid internal disputes, with RansomHub claiming the data in April 2024.

Dwell time: ~4 days (access February 17-20, 2024; encryption February 21), but preparation likely months (ScreenConnect flaws known since February 19, 2024). Undetected due to unpatched vulnerabilities, inadequate third-party risk management, and no real-time monitoring. Detection: Internal tools flagged unusual activity on February 21; confirmed BlackCat by February 29. Impacts: $2.87B total cost for UnitedHealth (Q3 2024 earnings), $6.3B delayed claims (Kodiak data), 94% of hospitals affected (AHA survey), ongoing lawsuits, and HHS/OCR investigations (breach report July 19, 2024). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Exploitation of Public-Facing Application T1190 via CVE-2024-1708), TA0002 (Execution: Command and Scripting Interpreter T1059.001), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0006 (Credential Access: OS Credential Dumping T1003), TA0008 (Lateral Movement: Exploitation of Remote Services T1210), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0040 (Impact: Data Encrypted for Impact T1486).

Threat hunting assumes breach: Hypothesis-driven searches for RMM/vulnerability exploits leading to ransomware in healthcare. Realistic parameters:
- **Environment**: Hybrid RMM (ConnectWise-like), unpatched servers, PHI databases.
- **Adversary Profile**: RaaS (zero-days, automated exfil; extortion via leaks).
- **Challenges**: Weekend timing, supply-chain (third-party flaws), massive PHI volume.
- **Tools/Data Sources**: EDR (CrowdStrike for behaviors), SIEM (Splunk for vuln logs), vuln scanners (Nessus for CVE-2024-1708), YARA/Sigma for BlackCat IOCs (e.g., SHA256: ransomware binaries from leaks).
- **Hypotheses**: E.g., "BlackCat exploits RMM zero-days; hunt anomalous uploads leading to encryption."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Mandiant, CISA, and HHS analyses). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., RMM labs) to avoid HIPAA risks. Baselines: 30-60 days of network/DB logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the attack—BlackCat's ConnectWise exploit enabled nationwide PHI theft; prioritize third-party patching.
- **Gather Threat Intel**: Review MITRE ATT&CK for BlackCat (S1064). IOCs: CVE-2024-1708 payloads (auth bypass in ScreenConnect), BlackCat notes ("your files are encrypted"), leak site screenshots. Cross-ref HIPAA Journal timeline, TechCrunch timeline, HHS FAQ, and AHA survey.
- **Map Your Environment**: Inventory RMM tools (ConnectWise), PHI DBs (SQL Server), third-party integrations. Use Nessus for CVE-2024-1708; BloodHound for paths.
- **Baseline Normal Behavior**: Log RMM updates (signed), DB queries (no dumps). Tool: Sysmon (process/network config); enable ConnectWise auditing.
- **Expert Tip**: Patch CVE-2024-1708/1709. Hypothesis: "BlackCat exploits RMM flaws; hunt anomalous auth bypasses leading to ransomware."

#### Step 2: Hunt for Initial Access (TA0001) - Exploitation of Public-Facing Application (T1190)
Exploited CVE-2024-1708 for auth bypass in ConnectWise.
- **Hypothesis**: "An adversary exploits RMM zero-day for access."
- **Data Sources**: RMM logs (ScreenConnect), WAF (bypass attempts), Sysmon ID 3 (port 80/443).
- **Step-by-Step Hunting**:
  1. Query Exploits: Splunk SPL: `index=rmm sourcetype=screenconnect | search uri="/auth" OR payload="CVE-2024-1708" | stats count by src_ip | where count > 1`.
  2. Sigma Rule (YAML):
     ```
     title: ConnectWise Auth Bypass Exploit
     logsource:
       category: web
     detection:
       selection:
         uri: '/auth*'
         method: 'POST'
         status: '200'  # Bypass success
       condition: selection
     ```
     Deploy in SIEM; alert on auth anomalies.
  3. Analyze: Hunt path traversal (e.g., /auth/../upload); DIVD warned February 2024.
  4. Pivoting: Trace to file uploads (Event ID 4663).
- **Expert Tip**: WAF for CVE-2024-1708. Realistic: Weekend exploit; hunt bypasses.

#### Step 3: Hunt for Execution (TA0002) - Command and Scripting Interpreter (T1059.001)
Executed PowerShell to download BlackCat ransomware.
- **Hypothesis**: "Exploit executes scripts for payload."
- **Data Sources**: Sysmon ID 1 (powershell.exe), Event ID 4688.
- **Step-by-Step**:
  1. Query Scripts: Splunk: `index=endpoint EventID=1 | search Image="*powershell.exe*" CommandLine="*blackcat*" | table _time, host, ParentImage`.
  2. Sigma Rule:
     ```
     title: Ransomware Script Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*powershell.exe*'
         CommandLine: '*download* OR *ransomware*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw procdump -p powershell` (script analysis).
  4. Pivoting: To persistence.
- **Expert Tip**: Block PowerShell. Realistic: Payload drop; hunt downloads.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Established persistence via stolen creds and BlackCat implants.
- **Hypothesis**: "Ransomware persists via creds."
- **Data Sources**: Event ID 4624, Sysmon ID 13.
- **Step-by-Step**:
  1. Query Logons: Splunk: `index=ad EventID=4624 | search AccountName="rmm_admin" src_ip!="internal" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: RMM Cred Persistence
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'connectwise*'
       condition: selection
     ```
  3. Scan: Registry for implants.
  4. Pivoting: To evasion.
- **Expert Tip**: Cred rotation. Realistic: Post-exploit; hunt external.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Escalated via token theft for DB access.
- **Hypothesis**: "RMM access escalates to PHI."
- **Data Sources**: Sysmon ID 10, Event ID 4673.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" Account="rmm" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Token Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe*'
         GrantedAccess: '0x1410'
       condition: selection
     ```
  3. Analyze: Mimikatz traces.
  4. Pivoting: To discovery.
- **Expert Tip**: LSA protect. Realistic: DB priv; hunt lsass.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
Disabled backups/logs before encryption.
- **Hypothesis**: "Ransomware evades by impairing tools."
- **Data Sources**: Event ID 1102, Sysmon ID 1.
- **Step-by-Step**:
  1. Query Disables: Splunk: `index=endpoint Image="vssadmin.exe" CommandLine="*delete*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Backup Impairment
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*vssadmin*'
         CommandLine: '*delete shadows*'
       condition: selection
     ```
  3. Analyze: Log wipes.
  4. Pivoting: To credential access.
- **Expert Tip**: Immutable backups. Realistic: Pre-encrypt; hunt vssadmin.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped creds for propagation.
- **Hypothesis**: "Ransomware dumps creds for spread."
- **Data Sources**: Sysmon ID 10, Event ID 4688.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr Target="lsass.exe" CallTrace="*MiniDump*" | stats dc(host)`.
  2. Sigma Rule:
     ```
     title: BlackCat Cred Dump
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe*'
         CallTrace: '*MiniDump*'
       condition: selection
     ```
  3. Forensics: Volatility dumpfiles.
  4. Pivoting: To discovery.
- **Expert Tip**: Guard lsass. Realistic: Propagation; hunt dumps.

#### Step 8: Hunt for Discovery (TA0007) - Network Service Discovery (T1046)
Scanned for endpoints/DBs.
- **Hypothesis**: "RMM access discovers PHI assets."
- **Data Sources**: Sysmon ID 3, DB logs.
- **Step-by-Step**:
  1. Query Scans: Splunk: `index=network dest_port=1433 OR 3389 ConnCount > 10 | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: DB Discovery
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '1433 OR 3389'
         ConnCount: '>5'
       condition: selection
     ```
  3. Analyze: DB probes.
  4. Pivoting: To collection.
- **Expert Tip**: Port ACLs. Realistic: PHI recon; hunt ports.

#### Step 9: Hunt for Lateral Movement (TA0008) - Exploitation of Remote Services (T1210)
Propagated via RMM agents to clients.
- **Hypothesis**: "RMM deploys ransomware downstream."
- **Data Sources**: Event ID 5145, Sysmon ID 3.
- **Step-by-Step**:
  1. Query Propagation: Splunk: `index=rmm deployment="agent" target="client" | stats count by msp`.
  2. Sigma Rule:
     ```
     title: RMM Lateral
     logsource:
       category: application
     detection:
       selection:
         Operation: 'deploy_ransomware'
         Target: 'downstream'
       condition: selection
     ```
  3. Traffic: Agent spikes.
  4. Pivoting: To collection.
- **Expert Tip**: Agent controls. Realistic: MSP chain; hunt deploys.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected PHI from DBs.
- **Hypothesis**: "Ransomware stages PHI."
- **Data Sources**: Sysmon ID 11, DB exports.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=db query="SELECT * FROM patients" rows > 1M | stats sum(rows)`.
  2. Sigma Rule:
     ```
     title: PHI Staging
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM *patients*'
         rows: '>100K'
       condition: selection
     ```
  3. Volume: High exports.
  4. Pivoting: To exfil.
- **Expert Tip**: Query limits. Realistic: 192M records; hunt large SELECTs.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
BlackCat C2 for commands.
- **Hypothesis**: "Ransomware beacons."
- **Data Sources**: Sysmon ID 3, Zeek.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="blackcat_c2" | stats dc(dest)`.
  2. Sigma Rule:
     ```
     title: BlackCat C2
     logsource:
       category: network_connection
     detection:
       selection:
         Domain: '*blackcat*'
       condition: selection
     ```
  3. Traffic: Beacon.
  4. Pivoting: To exfil.
- **Expert Tip**: C2 blocks. Realistic: HTTP; hunt domains.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated PHI pre-encryption.
- **Hypothesis**: "Staged PHI exfil."
- **Data Sources**: Network (POSTs), leak sites.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 50MB | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: PHI Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         length: '>10MB'
       condition: selection
     ```
  3. PCAP: PHI payloads.
  4. Pivoting: To leaks.
- **Expert Tip**: DLP PHI. Realistic: 192M; hunt large.

#### Step 13: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486)
Encrypted systems, disrupted claims.
- **Hypothesis**: "Ransomware encrypts for outage."
- **Data Sources**: Sysmon ID 11, OT logs.
- **Step-by-Step**:
  1. Query Encryption: Splunk: `index=endpoint FileModify="*.blackcat" | stats count by host`.
  2. Sigma Rule:
     ```
     title: BlackCat Encryption
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.blackcat*'
       condition: selection
     ```
  3. Impact: Claims backlog.
  4. Pivoting: Recovery.
- **Expert Tip**: Backups. Realistic: $6.3B delay; hunt encrypts.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate RMM), eradicate (patch, scan), recover (decryptor, notify HHS). Like UHG, advance funds; engage CISA.
- **Lessons**: Per HHS, patch RMM, third-party risk, audit DBs. Iterate monthly; simulate CVE-2024-1708.
- **Expert Tip**: ATT&CK for healthcare; evolve for 2025 (AI vuln scans).
