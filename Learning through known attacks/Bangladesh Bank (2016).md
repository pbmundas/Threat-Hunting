### Teaching Threat Hunting for Bangladesh Bank Heist-Like Attacks (2016): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with deep expertise in financial sector APTs and SWIFT ecosystem threats, I'll guide you through proactive threat hunting to detect attacks resembling the 2016 Bangladesh Bank cyber heist. This was a sophisticated financial theft operation attributed to the Lazarus Group (North Korean state-sponsored actors, per FBI and FireEye analysis), targeting the Bangladesh Bank's SWIFT messaging system. Attackers gained initial access via spear-phishing emails delivering malware (e.g., custom backdoor in ZIP files) to bank employees, then conducted extensive lateral movement to steal SWIFT credentials, map the network, and manipulate the SWIFTLIVE system. On February 4-5, 2016 (weekend timing to evade monitoring), they issued 35 fraudulent transfer requests totaling $951M to the New York Fed; five succeeded ($101M stolen, $81M laundered via RCBC in the Philippines to casinos, $20M to Sri Lanka). Malware deleted logs and spoofed printer output to delay detection. The remaining $850M was blocked due to a typo ("Shalika Fundation").

Dwell time: ~13 months (January 2015 spear-phishing to February 6, 2016 detection via printer restart), undetected due to lax email filtering, no segmentation, absent SIEM/DLP, and weekend execution. Detection: Bank staff noticed printer issues; FireEye confirmed Lazarus via TTPs (e.g., malware overlaps with Sony 2014). Impacts: $81M irrecoverable loss (only $18M recovered), $66M RCBC fallout (resignations, lawsuits), damaged global SWIFT trust (leading to Customer Security Programme, CSP), and geopolitical sanctions on North Korea. From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Spearphishing Attachment T1566.001), TA0002 (Execution: Exploitation for Client Execution T1203), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0007 (Discovery: Account Discovery T1087), TA0008 (Lateral Movement: Valid Accounts T1078.002), TA0006 (Credential Access: OS Credential Dumping T1003), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0040 (Impact: Data Manipulation T1565.001 via SWIFT fraud).

Threat hunting assumes breach: Hypothesis-driven searches for credential theft and financial messaging manipulation in banking. Realistic parameters:
- **Environment**: Hybrid finance nets (e.g., Windows AD, SWIFT terminals on isolated segments, no 2FA); high-value targets (SWIFT creds).
- **Adversary Profile**: State-sponsored (low-and-slow phishing, custom malware; financial gain for regime funding, weekend ops).
- **Challenges**: SWIFT's air-gapped nature limits logging, weekend blind spots, money laundering evades AML.
- **Tools/Data Sources**: EDR (CrowdStrike for endpoints), SIEM (Splunk for SWIFT logs), network metadata (Zeek for anomalies), SWIFT CSP tools, YARA/Sigma for Lazarus IOCs (e.g., SHA256: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b).
- **Hypotheses**: E.g., "An adversary has phished for creds to manipulate SWIFT and launder funds."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from FireEye's SWIFT report, U.S. DOJ indictments, and SWIFT CSP). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., SWIFT sim labs) to avoid regulatory issues (e.g., FFIEC compliance). Baselines: 60-90 days of transaction/email logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the heist—Bangladesh's weak defenses enabled SWIFT compromise; prioritize email/SWIFT monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for Lazarus (e.g., T1566.001 for phishing). IOCs: Malware hashes (MD5: 3e8b17d38b867f87df42321e762df34b for ZIP dropper), SWIFT typos ("foundation" misspells), laundering IOCs (RCBC accounts). Cross-ref FireEye report , FBI attribution , SWIFT CSP , and DOJ Park Jin Hyok indictment .
- **Map Your Environment**: Inventory email gateways, SWIFT terminals (e.g., Alliance Access), AD groups (SWIFT admins). Use BloodHound for paths from employees to SWIFT; Nessus for unpatched systems.
- **Baseline Normal Behavior**: Log phishing opens (Event ID 2003), SWIFT messages (MT103 transfers < $10K), outbound (no casino IPs). Tool: Sysmon (config for process/registry/network); SWIFT Logger for message audits.
- **Expert Tip**: Implement SWIFT CSP controls (e.g., 2FA on terminals). Hypothesis: "Lazarus phishes for SWIFT creds; hunt anomalous email to transaction anomalies."

#### Step 2: Hunt for Initial Access (TA0001) - Spearphishing Attachment (T1566.001)
Spear-phishing ZIP with malware to employees.
- **Hypothesis**: "An adversary has delivered malware via targeted emails."
- **Data Sources**: Email logs (Exchange), Sysmon ID 11 (.ZIP extracts), web proxy (malicious downloads).
- **Step-by-Step Hunting**:
  1. Query Phishing: Splunk SPL: `index=email sourcetype=exchange | search attachment_extension="zip" subject="*invoice*" | stats count by sender_ip, recipient | where sender_domain NOT "trusted"`.
  2. Sigma Rule (YAML):
     ```
     title: Financial Phishing
     logsource:
       category: email_activity
     detection:
       selection:
         subject: '*transfer OR *swift*'
         attachment: '*.zip'
         sender: external
       condition: selection
     ```
     Deploy in SIEM; alert on finance-themed ZIPs.
  3. Analyze: VT scan ZIPs for Lazarus droppers; hunt extracts by SWIFT users.
  4. Pivoting: Trace to process spawns (Event ID 4688).
- **Expert Tip**: Email sandboxing. Realistic: Employee clicks; hunt low-volume to ops.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution (T1203)
Malware executed to install backdoor, exploiting unpatched Windows.
- **Hypothesis**: "Phished malware executes for persistence."
- **Data Sources**: Sysmon ID 1 (dropper.exe), Event ID 4688.
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=endpoint EventID=1 | search ParentImage="*explorer.exe*" Image="*lazarus*" | table _time, host, CommandLine`.
  2. Sigma Rule:
     ```
     title: Backdoor Execution
     logsource:
       category: process_creation
     detection:
         Image: '*.exe' AND OriginalFileName: 'dropper*'
         ParentImage: '*winzip.exe*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw malfind | grep exploit` (scan shellcode).
  4. Pivoting: To credential theft.
- **Expert Tip**: Patch MS10-046. Realistic: ZIP auto-run; hunt explorer children.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Stole SWIFT creds for ongoing access.
- **Hypothesis**: "Adversary persists via stolen financial creds."
- **Data Sources**: Event ID 4624 (SWIFT logons), Sysmon ID 13 (creds stored).
- **Step-by-Step**:
  1. Query Logons: Splunk: `index=swift EventID=4624 | search AccountName="swift_user" src_ip!="internal" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: SWIFT Cred Reuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'swift*'
         LogonType: 3  # Network
       condition: selection
     ```
  3. Scan: CredMan for cached SWIFT pwds.
  4. Pivoting: To discovery.
- **Expert Tip**: 2FA on SWIFT. Realistic: No rotation; audit unusual logons.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Escalated via stolen admin creds to SWIFT system.
- **Hypothesis**: "Phishing creds escalated to privileged access."
- **Data Sources**: Event ID 4673, Sysmon ID 10.
- **Step-by-Step**:
  1. Query Escalations: Splunk: `index=ad EventID=4673 | search PrivilegeList="*SeDebug*" User="employee" | table _time, host`.
  2. Sigma Rule:
     ```
     title: SWIFT Escalation
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Privileges: '*SeTcb*'
         Account: 'bank_user'
       condition: selection
     ```
  3. Analyze: Token duplication traces.
  4. Pivoting: To network mapping.
- **Expert Tip**: Least-priv for SWIFT. Realistic: Employee to admin; hunt grants.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
Malware deleted SWIFT logs, spoofed printer.
- **Hypothesis**: "Attackers evade by tampering transaction logs."
- **Data Sources**: Event ID 1102, SWIFT audit gaps.
- **Step-by-Step**:
  1. Query Tampering: Splunk: `index=swift EventID=1102 OR missing_logs=true | stats count by host`.
  2. Sigma Rule:
     ```
     title: Log Deletion
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 1102
         Source: '*malware*'
       condition: selection
     ```
  3. Printer: Hunt spoofed outputs (Event ID 307).
  4. Pivoting: Precedes fraud.
- **Expert Tip**: Immutable SWIFT logs. Realistic: Weekend delay; hunt gaps.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped SWIFT creds from memory/registry.
- **Hypothesis**: "Dumps enable SWIFT manipulation."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4688.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr Target="lsass.exe" CallTrace="*MiniDump*" | stats dc(host)`.
  2. Sigma Rule:
     ```
     title: SWIFT Cred Dump
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe'
         CallTrace: '*MiniDump*'
       condition: selection
     ```
  3. Forensics: Volatility dumpfiles.
  4. Pivoting: To lateral.
- **Expert Tip**: Vault for creds. Realistic: Enabled transfers; hunt lsass.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087), Network Service Discovery (T1046)
Mapped network, discovered SWIFT hosts.
- **Hypothesis**: "Recon for financial systems."
- **Data Sources**: Sysmon ID 3 (scans), Event ID 4662.
- **Step-by-Step**:
  1. Query Scans: Splunk: `index=network dest_port=502 OR swift | search src="employee_host" | stats count by dest_ip`.
  2. Sigma Rule:
     ```
     title: SWIFT Discovery
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 'swift_port'
         ConnCount: '>10'
       condition: selection
     ```
  3. AD: net.exe executions.
  4. Pivoting: To movement.
- **Expert Tip**: Host isolation. Realistic: Undetected mapping; hunt scans.

#### Step 9: Hunt for Lateral Movement (TA0008) - Valid Accounts (T1078.002)
Moved via RDP/SMB to SWIFT servers.
- **Hypothesis**: "Pivot to isolated financial segments."
- **Data Sources**: Event ID 5145, Sysmon ID 3 (445).
- **Step-by-Step**:
  1. Query SMB: Splunk: `index=network protocol=smb user="swift" | stats count by src, dest`.
  2. Sigma Rule:
     ```
     title: Lateral to SWIFT
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         User: 'bank_admin'
       condition: selection
     ```
  3. RDP: LogonType=10.
  4. Pivoting: To collection.
- **Expert Tip**: Segment SWIFT. Realistic: Flat net; UEBA.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected SWIFT configs/creds.
- **Hypothesis**: "Financial data staged for fraud."
- **Data Sources**: Sysmon ID 11, SWIFT exports.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=swift File="mt103_dump*" | stats sum(Size)`.
  2. Sigma Rule:
     ```
     title: SWIFT Data Collection
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.swift OR *.mt*'
       condition: selection
     ```
  3. Volume: High message copies.
  4. Pivoting: To exfil.
- **Expert Tip**: Encrypt configs. Realistic: Pre-fraud; hunt copies.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
Backdoor C2 for commands.
- **Hypothesis**: "Malware beacons for manipulation."
- **Data Sources**: Sysmon ID 3, Zeek HTTP.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="lazarus_c2" | stats dc(dest)`.
  2. Sigma Rule:
     ```
     title: Financial C2
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '80'
         Domain: '*malware*'
       condition: selection
     ```
  3. Beacon: Intervals.
  4. Pivoting: To impact.
- **Expert Tip**: DNS monitoring. Realistic: Proxied; hunt JA3.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated configs; funds via SWIFT (not traditional exfil).
- **Hypothesis**: "Staged data exfil before fraud."
- **Data Sources**: Network (POSTs), SWIFT anomalies.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 1MB | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: Config Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content: '*swift*'
       condition: selection
     ```
  3. PCAP: Payloads with creds.
  4. Pivoting: To laundering IOCs.
- **Expert Tip**: SWIFT DLP. Realistic: Low-volume; hunt weekends.

#### Step 13: Hunt for Impact (TA0040) - Data Manipulation (T1565.001)
Falsified SWIFT messages, deleted logs.
- **Hypothesis**: "Fraudulent transactions executed."
- **Data Sources**: SWIFT logs (MT103 spikes), printer spoofs.
- **Step-by-Step**:
  1. Query Fraud: Splunk: `index=swift message_type="MT103" amount > $10M | stats count by _time`.
  2. Sigma Rule:
     ```
     title: SWIFT Fraud
     logsource:
       category: application
     detection:
       selection:
         message: 'MT103'
         amount: '>50M'
         beneficiary: 'rcbc*'
       condition: selection
     ```
  3. Logs: Missing entries.
  4. Pivoting: To laundering.
- **Expert Tip**: Transaction limits. Realistic: Typo saved $850M; hunt high-value.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate SWIFT), eradicate (cred reset, malware scan), recover (audit transfers, notify Fed). Like Bangladesh, engage FireEye; implement CSP.
- **Lessons**: Per FireEye , enforce 2FA/email filters, segment SWIFT, monitor weekends. Iterate bi-weekly; simulate with SWIFT test envs.
- **Expert Tip**: ATT&CK Navigator for finance; evolve for 2025 (e.g., AI fraud detection).
