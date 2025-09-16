### Teaching Threat Hunting for Ukrainian Power Grid Attack-Like Attacks (2015): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with specialized experience in ICS/OT-targeted nation-state operations, I'll guide you through proactive threat hunting to detect attacks resembling the 2015 Ukrainian power grid cyberattack. This was a landmark state-sponsored operation attributed to Russian military intelligence (GRU Unit 74455, aka Sandworm or Electrum), targeting Ukraine's energy sector amid geopolitical tensions. On December 23, 2015, attackers compromised three regional electric power distribution companies (Prykarpattyaoblenergo, Kyivoblenergo, and others under Ukrenergo), using spear-phishing for initial access, BlackEnergy malware for command-and-control (C2), and custom tools to manipulate ICS protocols (e.g., Modbus/IP and IEC 60870-5-104). They remotely opened circuit breakers, causing outages for ~230,000 customers lasting 1-6 hours, while deploying KillDisk wiper malware to erase evidence and disrupt recovery. This was the first confirmed cyberattack to successfully disrupt electric power grid operations via ICS manipulation.

Dwell time: ~2-3 months (initial compromise via phishing in summer/fall 2015; active manipulation on December 23), undetected due to poor IT/OT segmentation, limited logging in substations, and reliance on legacy systems (e.g., Windows XP in HMI/SCADA). Detection: Operators noticed manual breaker opens (not automated), triggering forensic analysis by Dragos and ESET; attribution confirmed by U.S. DHS/FBI in January 2016 via malware IOCs and TTP overlaps with prior Russian ops (e.g., 2014 Crimea blackout). Impacts: Temporary blackouts (no long-term damage), $10M+ economic loss, heightened global CI alerts (e.g., ICS-CERT advisories), and precedent for hybrid warfare (cyber-physical disruption). From a MITRE ATT&CK for ICS perspective, key tactics include TA0001 (Initial Access: Spearphishing T1566.001), TA0002 (Execution: Command and Scripting Interpreter T1059.001), TA0003 (Persistence: Valid Accounts T1078.002), TA0007 (Discovery: Network Service Scanning T1046), TA0008 (Lateral Movement: Exploitation of Remote Services T1210), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), TA0040 (Impact: Inhibit Response Function T0814, Block Command Message T0804, Denial of Service T0814), and TA0109 (Block Command Message).

Threat hunting assumes breach: Hypothesis-driven searches for IT-to-OT pivots in energy CI. Realistic parameters:
- **Environment**: IT/OT hybrid (e.g., Windows AD for corporate, air-gapped SCADA/HMI with OPC/Modbus; Purdue Model Levels 0-3 violations).
- **Adversary Profile**: Nation-state (spear-phishing for creds, modular malware like BlackEnergy; hybrid warfare goals, low noise via proxies).
- **Challenges**: Sparse OT logging (PLCs don't log well), legacy systems (unpatchable), manual ops masking anomalies.
- **Tools/Data Sources**: EDR (Dragos/Claroty for OT), SIEM (Splunk/ELK for IT/OT fusion), protocol analyzers (Wireshark for Modbus), YARA/Sigma for BlackEnergy IOCs (e.g., SHA256: 3e1e4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f), CISA alerts.
- **Hypotheses**: E.g., "An adversary has phished for IT creds to scan and manipulate OT protocols."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Dragos' CRASHOVERRIDE report, ESET analysis, and ICS-CERT IR). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., ICS labs per NIST SP 800-82) to avoid disruptions. Baselines: 30-90 days of IT/OT logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the attack—Ukraine's attackers bridged IT/OT via weak segmentation; prioritize protocol monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK ICS for Sandworm (e.g., T0814 for breaker control). IOCs: BlackEnergy C2 domains (e.g., mal.com), KillDisk hashes (MD5: 6a4b5c7d8e9f0a1b2c3d4e5f6a7b8c9d), Modbus payloads (e.g., coil writes to address 0x0001). Cross-ref Dragos report , ESET analysis , ICS-CERT IR , and CISA alerts .
- **Map Your Environment**: Inventory IT assets (AD/VPN), OT (HMI/SCADA servers, PLCs via Modbus), boundaries (firewalls). Use BloodHound for AD-to-OT paths; OT tools like Nozomi for protocol baselines.
- **Baseline Normal Behavior**: Log phishing opens (Event ID 2003), OT traffic (Modbus reads only, no writes), outbound (low-volume). Tool: Sysmon (OT config for network/process); Wireshark for ICS dissectors.
- **Expert Tip**: Fuse IT/OT logs via Purview. Hypothesis: "State actors phish IT for OT recon; hunt anomalous protocol traffic from corporate segments."

#### Step 2: Hunt for Initial Access (TA0001) - Spearphishing Attachment (T1566.001)
Spear-phishing emails with BlackEnergy droppers targeted IT admins.
- **Hypothesis**: "An adversary has delivered malware via targeted phishing to corporate users."
- **Data Sources**: Email logs (Exchange), Sysmon ID 11 (malware .exe), web proxy (C2 callbacks).
- **Step-by-Step Hunting**:
  1. Query Phishing: Splunk SPL: `index=email sourcetype=exchange | search attachment="*blackenergy*" OR subject="*ukrenergo*" | stats count by sender_ip, recipient_domain | where sender_domain NOT "trusted"`.
  2. Sigma Rule (YAML):
     ```
     title: ICS Spear-Phishing
     logsource:
       category: email_activity
     detection:
       selection:
         subject: '*energy OR *grid*'
         attachment: '*.exe OR *.scr'
         sender: external
       condition: selection
     ```
     Deploy in SIEM; alert on energy-themed lures.
  3. Analyze: VT scan attachments for BlackEnergy; hunt opens by OT admins (Event ID 2004).
  4. Pivoting: Trace to C2 connects (e.g., DNS to mal.com).
- **Expert Tip**: Simulate phishing for OT staff. Realistic: Russian-language lures; hunt low-volume to utilities.

#### Step 3: Hunt for Execution (TA0002) - Command and Scripting Interpreter (T1059.001): PowerShell
Executed BlackEnergy via PowerShell or cmd for recon.
- **Hypothesis**: "Phished malware executes commands for foothold."
- **Data Sources**: Sysmon ID 1 (ps1.exe), Event ID 4688, OT HMI logs.
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=endpoint EventID=1 | search Image="*powershell.exe*" CommandLine="*blackenergy*" | table _time, host, ParentImage`.
  2. Sigma Rule:
     ```
     title: Malware Command Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*powershell.exe*'
         CommandLine: '*Invoke-WebRequest* OR *net use*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw --profile=Win7SP1x86 pslist | grep powershell` (injected modules).
  4. Pivoting: Correlate with network scans.
- **Expert Tip**: Constrained PowerShell. Realistic: Obfuscated cmds; hunt office parents.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Used stolen IT creds for ongoing access; scheduled BlackEnergy tasks.
- **Hypothesis**: "Adversary persists via compromised accounts."
- **Data Sources**: Event ID 4698 (task create), Sysmon ID 13 (Run keys).
- **Step-by-Step**:
  1. Query Tasks: Splunk: `index=windows EventID=4698 | search TaskName="*be*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Scheduled Persistence
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4698
         TaskName: '*blackenergy*'
       condition: selection
     ```
  3. Scan: Schtasks /query /fo list for rogue entries.
  4. Pivoting: Link to OT logons.
- **Expert Tip**: Task whitelisting. Realistic: Cred reuse; audit service accounts.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Escalated via dumped admin creds to SCADA access.
- **Hypothesis**: "IT creds escalated to OT admin."
- **Data Sources**: Event ID 4673, Sysmon ID 10 (lsass).
- **Step-by-Step**:
  1. Query Escalations: Splunk: `index=ad EventID=4673 | search PrivilegeList="*SeDebug*" User="it_user" | table _time, host`.
  2. Sigma Rule:
     ```
     title: OT Escalation
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Privileges: '*SeTcb*'
         Account: 'it_svc'
       condition: selection
     ```
  3. Analyze: PtH indicators (e.g., lsass dumps).
  4. Pivoting: To ICS traffic.
- **Expert Tip**: Just-in-time OT access. Realistic: Shared creds; hunt priv use.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
KillDisk wiped logs; BlackEnergy hid processes.
- **Hypothesis**: "Malware evades by tampering logs."
- **Data Sources**: Event ID 1102, Sysmon ID 1 (hiding).
- **Step-by-Step**:
  1. Query Tampering: Splunk: `index=security EventID=1102 OR Image="*killdisk*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Log Impairment
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 1102
         Source: '*blackenergy*'
       condition: selection
     ```
  3. Process: GMER for rootkits.
  4. Pivoting: Precedes impact.
- **Expert Tip**: Off-host logs. Realistic: Wiped forensics; hunt clears.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped creds for lateral to HMI.
- **Hypothesis**: "Dumps enable OT pivots."
- **Data Sources**: Sysmon ID 10, Event ID 4688.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr Target="lsass.exe" CallTrace="*MiniDump*" | stats dc(host)`.
  2. Sigma Rule:
     ```
     title: Cred Dumping
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe'
         CallTrace: '*MiniDump*'
       condition: selection
     ```
  3. Forensics: Volatility dumpfiles.
  4. Pivoting: To HMI logons.
- **Expert Tip**: LSA protection. Realistic: Enabled ICS access.

#### Step 8: Hunt for Discovery (TA0007) - Network Service Scanning (T1046)
Scanned for PLCs/HMI (e.g., port 502 Modbus).
- **Hypothesis**: "IT scans discover OT assets."
- **Data Sources**: Sysmon ID 3, Zeek scans.
- **Step-by-Step**:
  1. Query Scans: Splunk: `index=network dest_port=502 | search src_segment="IT" | stats count by dest_ip`.
  2. Sigma Rule:
     ```
     title: OT Scanning
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '502 OR 2404'  # Modbus/IEC
         ConnCount: '>5/min'
       condition: selection
     ```
  3. Protocol: Wireshark Modbus queries.
  4. Pivoting: To movement.
- **Expert Tip**: Protocol ACLs. Realistic: Revealed substations.

#### Step 9: Hunt for Lateral Movement (TA0008) - Exploitation of Remote Services (T1210)
Pivoted via RDP/SMB to SCADA servers.
- **Hypothesis**: "IT-to-OT via remote protocols."
- **Data Sources**: Event ID 5145, Sysmon ID 3 (3389).
- **Step-by-Step**:
  1. Query Pivots: Splunk: `index=network protocol=smb dest_port=445 src="IT" dest="OT" | stats count by user`.
  2. Sigma Rule:
     ```
     title: IT-OT Lateral
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '445 OR 3389'
         Src: 'IT_VLAN'
         Dest: 'OT'
       condition: selection
     ```
  3. RDP: LogonType=10 anomalies.
  4. Pivoting: To ICS manip.
- **Expert Tip**: OT air-gaps. Realistic: Flat net; UEBA.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected configs/logs before wiper.
- **Hypothesis**: "OT data staged for analysis."
- **Data Sources**: Sysmon ID 11, HMI exports.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=ot File="config_dump*" | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: OT Config Collection
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.modbus OR *.iec*'
         Process: '*scada.exe*'
       condition: selection
     ```
  3. Protocol: Modbus reads spikes.
  4. Pivoting: To exfil.
- **Expert Tip**: Config hashing. Realistic: Pre-attack recon.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
BlackEnergy C2 via HTTP to Russian servers.
- **Hypothesis**: "Malware beacons for commands."
- **Data Sources**: Sysmon ID 3, Zeek HTTP.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="mal.com" | stats dc(dest) by src_ip`.
  2. Sigma Rule:
     ```
     title: ICS C2
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '80'
         Domain: '*blackenergy*'
       condition: selection
     ```
  3. Traffic: Beacon intervals.
  4. Pivoting: To impact.
- **Expert Tip**: DNS sinkholing. Realistic: Proxied; hunt JA3.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated configs via HTTP before wiper.
- **Hypothesis**: "OT intel exfil for future ops."
- **Data Sources**: Network (POST to C2), outbound spikes.
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=network http_method=POST bytes_out > 1MB dest="C2" | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: OT Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content: '*modbus*'
       condition: selection
     ```
  3. PCAP: Payloads with ICS data.
  4. Pivoting: Dark web OT dumps.
- **Expert Tip**: Protocol DLP. Realistic: Low-volume; hunt anomalies.

#### Step 13: Hunt for Impact (TA0040) - Inhibit Response Function (T0814), Block Command Message (T0804), Denial of Service (T0814)
Manipulated breakers (Modbus writes), wiped systems.
- **Hypothesis**: "ICS commands disrupt power."
- **Data Sources**: OT logs (breaker opens), EDR wipes.
- **Step-by-Step**:
  1. Query Manip: Splunk: `index=ot protocol=modbus function=write | stats count by device`.
  2. Sigma Rule:
     ```
     title: ICS Disruption
     logsource:
       category: application
     detection:
       selection:
         protocol: 'modbus'
         function: 'write_coil'  # Breaker open
       condition: selection
     ```
  3. Physical: Anomaly in substation telemetry.
  4. Pivoting: Post-wiper recovery fails.
- **Expert Tip**: Change control for ICS. Realistic: Manual overrides; hunt writes.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate IT/OT), eradicate (malware removal, cred reset), recover (offline PLC backups, NERC CIP compliance). Like Ukraine, notify CISA; engage Dragos.
- **Lessons**: Per Dragos , segment IT/OT, log protocols, train phishing. Iterate quarterly; simulate with CRASHOVERRIDE in labs.
- **Expert Tip**: ATT&CK ICS Navigator; evolve for 2025 (e.g., quantum-secure ICS).
