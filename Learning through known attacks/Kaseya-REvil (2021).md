### Teaching Threat Hunting for Kaseya-REvil Attack-Like Attacks (2021): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in ransomware-as-a-service (RaaS) supply-chain compromises and managed service provider (MSP) ecosystems, I'll guide you through proactive threat hunting to detect attacks resembling the 2021 Kaseya-REvil ransomware attack. This was a high-impact RaaS operation by the REvil (aka Sodinokibi) group (Russian-linked cybercriminals, per FBI and Europol attribution), exploiting zero-day vulnerabilities in Kaseya's Virtual System Administrator (VSA) remote monitoring and management (RMM) software. On July 2, 2021 (U.S. Independence Day weekend, minimizing response), REvil breached Kaseya VSA servers via CVE-2021-30116 (path traversal and arbitrary file upload, CVSS 9.8), deploying a malicious "agent hotfix" that propagated REvil ransomware to ~1,500 downstream businesses across 17 countries (via 30-60 MSPs using VSA). The attack encrypted files, deleted shadow copies, and demanded $70M in Bitcoin for a universal decryptor (unpaid; Kaseya obtained a key from a "trusted third party" on July 23). Affected entities included U.S. grocery chains (e.g., Coop Sverige, closing 800 stores), New Zealand schools, and global firms, causing widespread outages.

Dwell time: ~3 months (April 2021 DIVD disclosure of VSA flaws to Kaseya; attack execution July 2), with rapid propagation (~hours post-breach). Undetected due to zero-days, weekend timing, and no immediate patching (despite DIVD warnings). Detection: Kaseya detected unusual VSA activity on July 2; confirmed REvil by July 3 via IOCs (e.g., BlackLivesMatter mutex). Impacts: $70M ransom demand (highest ever), $18.5M+ in losses for affected MSPs, global supply-chain disruption, REvil site takedown (July 13, U.S./Russia action), and arrests (e.g., Yaroslav Vasinskyi, 22, sentenced 2022). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Exploitation of Public-Facing Application T1190 via CVE-2021-30116), TA0002 (Execution: Command and Scripting Interpreter T1059.001 via PowerShell), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001 via log deletion), TA0006 (Credential Access: OS Credential Dumping T1003), TA0008 (Lateral Movement: Exploitation of Remote Services T1210), TA0009 (Collection: Automated Collection T1119), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002, minimal), and TA0040 (Impact: Data Encrypted for Impact T1486).

Threat hunting assumes breach: Hypothesis-driven searches for zero-day exploits in RMM tools leading to ransomware propagation in MSP ecosystems. Realistic parameters:
- **Environment**: MSP-managed networks (VSA on-premises/cloud, Windows AD); high-trust updates.
- **Adversary Profile**: RaaS affiliates (zero-days, automated deployment; extortion via leaks).
- **Challenges**: Weekend attacks, supply-chain trust, rapid encryption.
- **Tools/Data Sources**: EDR (CrowdStrike for behaviors), SIEM (Splunk for VSA logs), vuln scanners (Nessus for CVE-2021-30116), YARA/Sigma for REvil IOCs (e.g., SHA256: 6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9 for mpsvc.dll).
- **Hypotheses**: E.g., "REvil exploits VSA zero-days to deploy ransomware; hunt anomalous hotfixes leading to encryption."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from ESET, Truesec, and Splunk analyses). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., VSA labs) to avoid MSP disruptions. Baselines: 30-60 days of update/network logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the attack—REvil's VSA zero-day enabled MSP-wide propagation; prioritize RMM monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for REvil (S0496). IOCs: CVE-2021-30116 payloads (SQL injection in /agentRemove/upload), REvil mutex (BlackLivesMatter), DLL side-loading (MsMpEng.exe loads mpsvc.dll). Cross-ref ESET analysis , Truesec timeline , Splunk MITRE mapping , and CISA guidance .
- **Map Your Environment**: Inventory VSA servers (on-prem/cloud), MSP clients, AD paths. Use Nessus for CVE-2021-30116; BloodHound for propagation.
- **Baseline Normal Behavior**: Log VSA updates (signed), agent deployments (no encryption). Tool: Sysmon (process/network config); enable VSA auditing.
- **Expert Tip**: Patch CVE-2021-30116 immediately. Hypothesis: "REvil exploits VSA zero-days; hunt anomalous uploads leading to ransomware."

#### Step 2: Hunt for Initial Access (TA0001) - Exploitation of Public-Facing Application (T1190)
Exploited CVE-2021-30116 for RCE on VSA servers.
- **Hypothesis**: "An adversary exploits VSA zero-day for shell access."
- **Data Sources**: VSA logs (web panel), WAF (SQL injection), Sysmon ID 3 (port 80/443).
- **Step-by-Step Hunting**:
  1. Query Exploits: Splunk SPL: `index=vsa sourcetype=web | search uri="/agentRemove/upload" OR payload="SQL injection" | stats count by src_ip | where count > 1`.
  2. Sigma Rule (YAML):
     ```
     title: VSA Zero-Day Exploit
     logsource:
       category: web
     detection:
       selection:
         uri: '/agentRemove/upload'
         method: 'POST'
         payload: '*SQL* OR *upload*'
       condition: selection
     ```
     Deploy in SIEM; alert on upload anomalies.
  3. Analyze: Hunt path traversal (e.g., ../../shell.jsp); DIVD warned April 2021.
  4. Pivoting: Trace to file uploads (Event ID 4663).
- **Expert Tip**: WAF for CVE-2021-30116. Realistic: Weekend exploit; hunt SQL payloads .

#### Step 3: Hunt for Execution (TA0002) - Command and Scripting Interpreter (T1059.001 via PowerShell)
Executed PowerShell to download REvil (agent.exe drops MsMpEng.exe).
- **Hypothesis**: "Exploit executes scripts for payload drop."
- **Data Sources**: Sysmon ID 1 (powershell.exe), Event ID 4688.
- **Step-by-Step**:
  1. Query Scripts: Splunk: `index=endpoint EventID=1 | search Image="*powershell.exe*" CommandLine="*agent.exe*" | table _time, host, ParentImage`.
  2. Sigma Rule:
     ```
     title: PowerShell Payload Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*powershell.exe*'
         CommandLine: '*agent.exe* OR *MsMpEng*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw procdump -p powershell` (script analysis).
  4. Pivoting: To DLL side-loading.
- **Expert Tip**: Constrain PowerShell. Realistic: Hotfix drop; hunt agent.exe .

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
No strong persistence; relied on VSA agent for propagation.
- **Hypothesis**: "Exploit uses VSA for ongoing access."
- **Data Sources**: Event ID 4624 (agent logons), Sysmon ID 13 (registry).
- **Step-by-Step**:
  1. Query Agents: Splunk: `index=vsa EventID=4624 | search AccountName="kaseya_agent" src_ip!="internal" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: VSA Agent Persistence
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'kaseya*'
       condition: selection
     ```
  3. Scan: Registry for agent mods (e.g., BlackLivesMatter mutex).
  4. Pivoting: To evasion.
- **Expert Tip**: Agent whitelisting. Realistic: Agent abuse; hunt logons .

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
No explicit escalation; VSA privs sufficed.
- **Hypothesis**: "VSA access escalates to client admin."
- **Data Sources**: Sysmon ID 10 (token access), Event ID 4673.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" Account="vsa" | table _time, host`.
  2. Sigma Rule:
     ```
     title: VSA Token Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe*'
         Account: 'kaseya*'
       condition: selection
     ```
  3. Analyze: Token duplication in VSA.
  4. Pivoting: To evasion.
- **Expert Tip**: VSA least-priv. Realistic: Built-in priv; hunt lsass .

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
Cleared logs, DLL side-loaded REvil (MsMpEng.exe loads mpsvc.dll).
- **Hypothesis**: "Ransomware evades via log deletion and side-loading."
- **Data Sources**: Event ID 1102 (clears), Sysmon ID 7 (DLL loads).
- **Step-by-Step**:
  1. Query Side-Loading: Splunk: `index=endpoint EventID=7 | search ImageLoaded="mpsvc.dll" Image="MsMpEng.exe" | stats count by host`.
  2. Sigma Rule:
     ```
     title: DLL Side-Loading Evasion
     logsource:
       category: module_load
     detection:
       selection:
         Image: 'MsMpEng.exe'
         Module: 'mpsvc.dll'
       condition: selection
     ```
  3. Analyze: Log clears in VSA (e.g., Kserver.log wiped).
  4. Pivoting: To credential access.
- **Expert Tip**: DLL monitoring. Realistic: Defender side-load; hunt MsMpEng .

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped creds via REvil for propagation.
- **Hypothesis**: "Ransomware dumps creds for spread."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4688.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr Target="lsass.exe" CallTrace="*MiniDump*" | stats dc(host)`.
  2. Sigma Rule:
     ```
     title: REvil Cred Dump
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
- **Expert Tip**: LSA protection. Realistic: Propagation; hunt lsass .

#### Step 8: Hunt for Discovery (TA0007) - Network Service Discovery (T1046)
Scanned for endpoints via VSA.
- **Hypothesis**: "VSA access discovers managed systems."
- **Data Sources**: VSA logs (agent scans), Sysmon ID 3.
- **Step-by-Step**:
  1. Query Scans: Splunk: `index=vsa agent_scan | stats count by target_ip | where count > baseline`.
  2. Sigma Rule:
     ```
     title: VSA Discovery
     logsource:
       category: application
     detection:
       selection:
         Operation: 'scan_agents'
         TargetCount: '>1000'
       condition: selection
     ```
  3. Analyze: Unusual agent enumerations.
  4. Pivoting: To lateral.
- **Expert Tip**: Agent limits. Realistic: MSP discovery; hunt scans .

#### Step 9: Hunt for Lateral Movement (TA0008) - Exploitation of Remote Services (T1210)
Propagated via VSA agents to clients.
- **Hypothesis**: "VSA deploys ransomware downstream."
- **Data Sources**: Event ID 5145 (agent deploys), Sysmon ID 3.
- **Step-by-Step**:
  1. Query Propagation: Splunk: `index=vsa deployment="hotfix" target="client" | stats count by msp`.
  2. Sigma Rule:
     ```
     title: VSA Lateral Deployment
     logsource:
       category: application
     detection:
       selection:
         Operation: 'deploy_agent'
         Target: 'downstream*'
       condition: selection
     ```
  3. Traffic: Agent traffic spikes.
  4. Pivoting: To collection.
- **Expert Tip**: VSA segmentation. Realistic: MSP chain; hunt deploys .

#### Step 10: Hunt for Collection (TA0009) - Automated Collection (T1119)
Automated file gathering pre-encryption.
- **Hypothesis**: "Ransomware stages data."
- **Data Sources**: Sysmon ID 11 (copies), temp files.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FileName="*.tmp" Process="revil" | stats sum(Size)`.
  2. Sigma Rule:
     ```
     title: Pre-Encryption Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.tmp'
         Process: '*revil*'
       condition: selection
     ```
  3. Volume: High copies.
  4. Pivoting: To impact.
- **Expert Tip**: Staging DLP. Realistic: Double-extortion; hunt temps .

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
REvil C2 for commands.
- **Hypothesis**: "Ransomware beacons for exfil."
- **Data Sources**: Sysmon ID 3 (HTTP), Zeek.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="revil_c2" | stats dc(dest)`.
  2. Sigma Rule:
     ```
     title: REvil C2
     logsource:
       category: network_connection
     detection:
       selection:
         Domain: '*revil*'
       condition: selection
     ```
  3. Traffic: Beacon intervals.
  4. Pivoting: To exfil.
- **Expert Tip**: C2 blocks. Realistic: HTTP; hunt domains .

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated data pre-encryption.
- **Hypothesis**: "Staged data exfil for leaks."
- **Data Sources**: Network (POSTs), leak sites.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 10MB | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: REvil Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         length: '>5MB'
       condition: selection
     ```
  3. PCAP: Data payloads.
  4. Pivoting: To leaks.
- **Expert Tip**: Exfil DLP. Realistic: Double-extortion; hunt large .

#### Step 13: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486)
Encrypted files, deleted shadows.
- **Hypothesis**: "Ransomware encrypts for outage."
- **Data Sources**: Sysmon ID 11 (encrypted), Event ID 7045.
- **Step-by-Step**:
  1. Query Encryption: Splunk: `index=endpoint FileModify="*.revil" | stats count by host`.
  2. Sigma Rule:
     ```
     title: REvil Encryption
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.revil*'
       condition: selection
     ```
  3. Shadows: vssadmin deletes.
  4. Pivoting: Outages.
- **Expert Tip**: Immutable backups. Realistic: MSP outages; hunt appends .

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate VSA), eradicate (patch CVE-2021-30116, scan), recover (decryptor, notify). Like Kaseya, use universal key; engage FBI .
- **Lessons**: Per DIVD , patch zero-days, vet MSPs, monitor hotfixes. Iterate bi-weekly; simulate with REvil in labs.
- **Expert Tip**: ATT&CK Navigator for MSPs; evolve for 2025 (e.g., AI zero-day detection).
