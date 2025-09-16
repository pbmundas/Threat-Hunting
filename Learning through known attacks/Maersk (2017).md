### Teaching Threat Hunting for Maersk NotPetya Attack-Like Attacks (2017): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with deep experience in supply-chain ransomware and OT/IT hybrid threats, I'll guide you through proactive threat hunting to detect attacks resembling the 2017 Maersk NotPetya incident. This was a destructive wiper campaign disguised as ransomware, attributed to Russia's Sandworm (GRU Unit 74455), starting June 27, 2017, primarily targeting Ukraine but spreading globally via a supply-chain compromise in M.E.Doc tax software updates. For Maersk (A.P. Moller-Maersk, the world's largest container shipping firm), NotPetya encrypted 45,000 endpoints and 4,000 servers across 600 sites in 130 countries, halting operations for 10 days. Manual processes (e.g., Excel on radios) resumed shipping, but the attack wiped backups, forcing full rebuilds. It used EternalBlue (CVE-2017-0144, SMBv1 exploit leaked from NSA) for propagation, Mimikatz for credential dumping, and a custom wiper (Petya-like bootlocker) that overwrote the MBR and files, demanding $300 BTC (unpayable). No real ransom; goal was destruction amid Ukraine conflict.

Dwell time: ~1 day for global spread (Ukraine to Maersk within hours), but preparation ~months (Sandworm's M.E.Doc breach). Undetected due to trusted update channels, unpatched Windows (SMBv1 enabled), no EDR on OT, and rapid propagation. Detection: Maersk IT spotted encryption; Cisco Talos/ESET analyzed malware, attributing to Sandworm by July 2017. Impacts: $250-300M for Maersk (lost revenue, rebuilds), $10B global (e.g., Merck $870M, FedEx $400M), accelerated patching (MS17-010), and sanctions (U.S. Treasury on Russia). From a MITRE ATT&CK ICS/Enterprise perspective, key tactics include TA0001 (Initial Access: Supply Chain Compromise T1195), TA0002 (Execution: Exploitation for Client Execution T1203), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0006 (Credential Access: OS Credential Dumping T1003), TA0008 (Lateral Movement: Lateral Tool Transfer T1570), TA0009 (Collection: Automated Collection T1119), TA0010 (Exfiltration: Minimal, focus on destruction), and TA0040 (Impact: Data Encrypted for Impact T1486, Inhibit Response Function T0814).

Threat hunting assumes infection: Hypothesis-driven searches for update compromises leading to wiper propagation in logistics/energy. Realistic parameters:
- **Environment**: IT/OT hybrid (e.g., Windows AD, unpatched SMB, supply-chain updates); global ops with flat nets.
- **Adversary Profile**: Nation-state (wiper via exploits, rapid spread; geopolitical disruption).
- **Challenges**: Trusted updates evade AV, SMB propagation, OT unmonitored.
- **Tools/Data Sources**: EDR (CrowdStrike for propagation), SIEM (Splunk for update logs), OT (Claroty for ICS), YARA/Sigma for NotPetya IOCs (e.g., SHA256: 65cee234f3ce2e3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b).
- **Hypotheses**: E.g., "An adversary has tainted updates to propagate wipers via SMB."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Talos/ESET reports). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., OT labs per NIST 800-82) to avoid disruptions. Baselines: 30-60 days of update/network logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the attack—NotPetya's M.E.Doc compromise spread via EternalBlue; prioritize update/SMB monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for NotPetya (S0368). IOCs: EternalBlue payloads (SMB \xFF SMB \x00), wiper strings ("Oops, your important files are encrypted"), C2 (e.g., sigus4.com). Cross-ref Talos analysis, Wikipedia, Wired deep dive, and Maersk case study.
- **Map Your Environment**: Inventory update servers (e.g., WSUS/M.E.Doc-like), SMB shares, OT endpoints. Use Nmap for SMBv1; BloodHound for propagation paths.
- **Baseline Normal Behavior**: Log updates (trusted sources), SMB traffic (no EternalBlue), encryption spikes. Tool: Sysmon (SMB config for network/process); Wireshark for protocol.
- **Expert Tip**: Disable SMBv1. Hypothesis: "Sandworm taints updates for SMB wipers; hunt anomalous downloads leading to propagation."

#### Step 2: Hunt for Initial Access (TA0001) - Supply Chain Compromise (T1195)
Compromised M.E.Doc updates for initial infection.
- **Hypothesis**: "An adversary has tainted trusted software updates."
- **Data Sources**: Update logs (WSUS), download anomalies, Sysmon ID 11 (malicious .exe).
- **Step-by-Step Hunting**:
  1. Query Updates: Splunk SPL: `index=update sourcetype=wsus | search DownloadURL="m.e.doc" hash!="known_good" | stats count by src_ip | where count > baseline`.
  2. Sigma Rule (YAML):
     ```
     title: Tainted Update Download
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.exe' Source: 'm.e.doc*'
         Hash: NOT IN ('trusted_hashes')
       condition: selection
     ```
     Deploy in SIEM; alert on unknown update hashes.
  3. Analyze: VirusTotal .exe from updates; hunt signed but malicious (e.g., NotPetya perseus.exe).
  4. Pivoting: Trace to execution (Event ID 4688).
- **Expert Tip**: Update signing verification. Realistic: M.E.Doc trust; hunt hash mismatches.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution (T1203): EternalBlue
Executed via EternalBlue SMB exploit for propagation.
- **Hypothesis**: "Update payload exploits SMB for execution."
- **Data Sources**: Sysmon ID 3 (port 445), Event ID 4688 (doublepulsar backdoor).
- **Step-by-Step**:
  1. Query Exploits: Splunk: `index=network dest_port=445 payload="SMB \xFF \x00 \x00" | stats count by src_ip | where count > 1`.
  2. Sigma Rule:
     ```
     title: EternalBlue Execution
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         Payload: '*doublepulsar* OR *eternalblue*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw procdump -p lsass` (scan for SMB injects).
  4. Pivoting: To lateral spread.
- **Expert Tip**: Patch MS17-010. Realistic: Rapid worm; hunt SMB anomalies.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Used dumped creds for re-infection.
- **Hypothesis**: "Exploit dumps creds for persistence."
- **Data Sources**: Event ID 4720, Sysmon ID 13 (creds).
- **Step-by-Step**:
  1. Query Creds: Splunk: `index=ad EventID=4672 | search AccountName="dumped" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Cred Persistence Post-Exploit
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4672
         Account: 'service*'
       condition: selection
     ```
  3. Scan: Mimikatz traces.
  4. Pivoting: To discovery.
- **Expert Tip**: Cred guard. Realistic: Enabled spread; hunt dumps.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Token theft via Mimikatz for local admin.
- **Hypothesis**: "SMB access escalates via tokens."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4673.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" | table _time, host`.
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
  3. Analyze: PtH indicators.
  4. Pivoting: To collection.
- **Expert Tip**: LSA protect. Realistic: Local spread; hunt lsass.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
Disabled AV/backups before wipe.
- **Hypothesis**: "Wiper evades by impairing tools."
- **Data Sources**: Event ID 4688 (taskkill), Sysmon ID 1.
- **Step-by-Step**:
  1. Query Disables: Splunk: `index=endpoint Image="taskkill.exe" CommandLine="*av*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: AV Impairment
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*taskkill.exe*'
         CommandLine: '*windows defender*'
       condition: selection
     ```
  3. Backup: vssadmin delete.
  4. Pivoting: To impact.
- **Expert Tip**: Immutable backups. Realistic: Pre-wipe; hunt stops.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Mimikatz dumped creds for propagation.
- **Hypothesis**: "Dumps enable network spread."
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
         TargetImage: '*lsass.exe*'
         CallTrace: '*MiniDump*'
       condition: selection
     ```
  3. Forensics: Volatility dumpfiles.
  4. Pivoting: To lateral.
- **Expert Tip**: Guard creds. Realistic: Worm fuel; hunt API.

#### Step 8: Hunt for Discovery (TA0007) - Network Service Discovery (T1046)
Scanned for vulnerable SMB hosts.
- **Hypothesis**: "Worm discovers propagatable systems."
- **Data Sources**: Sysmon ID 3 (port 445), Zeek scans.
- **Step-by-Step**:
  1. Query Scans: Splunk: `index=network dest_port=445 ConnCount > 10 | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: SMB Discovery
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         ConnCount: '>5'
       condition: selection
     ```
  3. Traffic: EternalBlue probes.
  4. Pivoting: To movement.
- **Expert Tip**: SMB auditing. Realistic: Self-spread; hunt bursts.

#### Step 9: Hunt for Lateral Movement (TA0008) - Lateral Tool Transfer (T1570)
Propagated via SMB/EternalBlue.
- **Hypothesis**: "Worm moves laterally via exploits."
- **Data Sources**: Event ID 5145 (SMB), Sysmon ID 3.
- **Step-by-Step**:
  1. Query SMB: Splunk: `index=network protocol=smb src_segment="infected" | stats count by dest_ip`.
  2. Sigma Rule:
     ```
     title: SMB Lateral
     logsource:
       category: network_connection
     detection:
       selection:
         Protocol: 'smb'
         DestPort: 445
         Src: 'infected_host'
       condition: selection
     ```
  3. Traffic: Doublepulsar beacons.
  4. Pivoting: To collection.
- **Expert Tip**: Disable SMBv1. Realistic: Global worm; hunt chains.

#### Step 10: Hunt for Collection (TA0009) - Automated Collection (T1119)
Automated file gathering before wipe.
- **Hypothesis**: "Pre-wipe data staged."
- **Data Sources**: Sysmon ID 11 (copies), temp files.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FileName="*.tmp" Size > 10MB | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: Pre-Wipe Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.tmp OR *.dat'
         Size: '>5MB'
       condition: selection
     ```
  3. Volume: High copies.
  4. Pivoting: To impact.
- **Expert Tip**: DLP staging. Realistic: Minimal; hunt temps.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
Minimal C2; self-propagating worm.
- **Hypothesis**: "Worm beacons for updates."
- **Data Sources**: Sysmon ID 3 (outbound), Zeek.
- **Step-by-Step**:
  1. Query Beacons: Splunk: `index=network dest_port=80 bytes_in < 100 | stats dc(dest_ip) by src_ip`.
  2. Sigma Rule:
     ```
     title: Worm C2
     logsource:
       category: network_connection
     detection:
         DestinationPort: '80'
         Bytes: '<200'  # Beacon
       condition: selection
     ```
  3. Traffic: To Russian C2.
  4. Pivoting: To wipe.
- **Expert Tip**: Outbound blocks. Realistic: Autonomous; hunt small packets.

#### Step 12: Hunt for Exfiltration (TA0010) - Minimal (Focus on Destruction)
No major exfil; some data to C2 before wipe.
- **Hypothesis**: "Limited intel exfil pre-wipe."
- **Data Sources**: Network (small POSTs).
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=network http_method=POST bytes_out > 1MB pre_wipe | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: Pre-Wipe Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         timestamp: before 'encryption'
       condition: selection
     ```
  3. PCAP: Payloads.
  4. Pivoting: To impact.
- **Expert Tip**: Pre-impact DLP. Realistic: Espionage secondary; hunt timed.

#### Step 13: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486)
Encrypted files/MBR, inhibited recovery.
- **Hypothesis**: "Wiper encrypts and wipes systems."
- **Data Sources**: EDR (encryption), OT logs.
- **Step-by-Step**:
  1. Query Encryption: Splunk: `index=ot Event="file_encrypted" OR MBR_wipe | stats count by device`.
  2. Sigma Rule:
     ```
     title: Wiper Impact
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*perseus.exe*'
         CommandLine: '*encrypt*'
       condition: selection
     ```
  3. Physical: Ops halts.
  4. Pivoting: Recovery fails.
- **Expert Tip**: Air-gapped backups. Realistic: Global disruption; hunt encrypts.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate nets), eradicate (patch EternalBlue, wipe infected), recover (offline backups, manual ops). Like Maersk, engage Talos; notify CISA.
- **Lessons**: Per Wired, vet updates, disable SMBv1, monitor propagation. Iterate weekly; simulate with NotPetya in labs.
- **Expert Tip**: ATT&CK ICS Navigator; evolve for 2025 (e.g., AI update verification).
