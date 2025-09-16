### Teaching Threat Hunting for NotPetya Attack-Like Incidents (2017): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in destructive ransomware and supply-chain attacks, I'll guide you through proactive threat hunting for attacks resembling the 2017 NotPetya incident, with a focus on its impact on Maersk as requested. NotPetya was a wiper disguised as ransomware, attributed to Russia's Sandworm Team (GRU Unit 74455, per U.S. DOJ and FireEye), targeting Ukraine but causing global disruption. It spread via a compromised M.E.Doc tax software update (a Ukrainian accounting tool) on June 27, 2017, leveraging EternalBlue (CVE-2017-0144, SMBv1 exploit) and Mimikatz for rapid propagation. At Maersk, it crippled 45,000 endpoints, 4,000 servers, and 2,500 applications across 600 sites in 130 countries, halting shipping operations for 10 days. The attack encrypted files, wiped master boot records (MBRs), and deleted backups, demanding $300 in Bitcoin (unpayable due to wiper intent). Maersk rebuilt its IT infrastructure from a single surviving domain controller in Ghana, relying on manual processes (e.g., Excel via VHF radios) to resume operations.

**Dwell time**: Hours for global spread (Ukraine to Maersk same day), but M.E.Doc compromise likely prepared months earlier (March 2017). Undetected due to trusted update channels, unpatched Windows (SMBv1 enabled), no EDR on critical systems, and worm-like speed. **Detection**: Maersk IT noticed encryption within hours; Cisco Talos and ESET confirmed Sandworm via malware analysis by July 2017. **Impacts**: $250-300M loss for Maersk (revenue, rebuilds), $10B globally (e.g., Merck $870M, FedEx $400M), accelerated MS17-010 patching, and U.S. sanctions on Russia (2018). From a MITRE ATT&CK Enterprise/ICS perspective (S0368), key tactics include TA0001 (Initial Access: Supply Chain Compromise T1195), TA0002 (Execution: Exploitation for Client Execution T1203), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0006 (Credential Access: OS Credential Dumping T1003), TA0007 (Discovery: Network Service Discovery T1046), TA0008 (Lateral Movement: Exploitation of Remote Services T1210), TA0009 (Collection: Automated Collection T1119), TA0010 (Exfiltration: Exfiltration Over C2 Channel T1041, minimal), and TA0040 (Impact: Data Encrypted for Impact T1486, Inhibit System Recovery T1490).

Threat hunting assumes compromise: Hypothesis-driven searches for supply-chain attacks and SMB propagation in logistics/OT environments. Realistic parameters:
- **Environment**: Hybrid IT/OT (Windows AD, unpatched SMBv1, global networks); supply-chain dependencies (e.g., third-party updates).
- **Adversary Profile**: Nation-state (wiper via exploits, geopolitical disruption; low ransom intent).
- **Challenges**: Trusted updates bypass AV, rapid worm spread, limited OT visibility.
- **Tools/Data Sources**: EDR (CrowdStrike for endpoints), SIEM (Splunk for network/update logs), OT monitoring (Claroty), YARA/Sigma for NotPetya IOCs (e.g., SHA256: 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745 for perseus.exe).
- **Hypotheses**: E.g., "Sandworm taints updates to deploy wipers via SMB exploits."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Talos, ESET, and Maersk’s Wired account). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., OT/IT labs per NIST 800-82) to avoid operational risks. Baselines: 30-60 days of update/SMB logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize NotPetya—Maersk’s flat network and unpatched systems enabled rapid destruction; prioritize update and SMB monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK S0368 for NotPetya. IOCs: M.E.Doc update hashes (e.g., MD5: 6f7840c77f99049d788155c1351e1560), EternalBlue payloads (SMB \xFF \x00), C2 domains (e.g., sigus4.com), ransom note ("Oops, your files are encrypted"). Cross-ref Cisco Talos report, Wired Maersk account, Wikipedia timeline, and CISA alert.
- **Map Your Environment**: Inventory update servers (e.g., WSUS, M.E.Doc-like), Windows hosts (SMBv1), OT devices (e.g., shipping terminals). Use Nmap for port 445; BloodHound for AD paths.
- **Baseline Normal Behavior**: Log update downloads (signed), SMB traffic (no exploits), encryption events (none). Tool: Sysmon (process/network config); Zeek for SMB dissectors.
- **Expert Tip**: Vet third-party updates. Hypothesis: "Sandworm compromises supply-chain updates to propagate wipers; hunt anomalous downloads and SMB spikes."

#### Step 2: Hunt for Initial Access (TA0001) - Supply Chain Compromise (T1195)
Compromised M.E.Doc update server for initial infection.
- **Hypothesis**: "An adversary has tainted trusted software updates for entry."
- **Data Sources**: Update logs (WSUS), Sysmon ID 11 (file writes), network downloads.
- **Step-by-Step Hunting**:
  1. Query Updates: Splunk SPL: `index=update sourcetype=wsus | search Source="*m.e.doc*" OR Hash NOT IN ("known_good") | stats count by src_ip, file_hash`.
  2. Sigma Rule (YAML):
     ```
     title: Suspicious Update Download
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.exe'
         Source: '*m.e.doc* OR *unknown*'
         Hash: NOT IN ('trusted')
       condition: selection
     ```
     Deploy in SIEM; alert on unverified update hashes.
  3. Analyze: VirusTotal scan for perseus.exe; check for signed but malicious binaries.
  4. Pivoting: Trace to execution (Event ID 4688 for dropper).
- **Expert Tip**: Enforce code signing checks. Realistic: Trusted M.E.Doc; hunt hash anomalies.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution (T1203)
Executed via EternalBlue SMB exploit post-update.
- **Hypothesis**: "Tainted update triggers SMB exploit for execution."
- **Data Sources**: Sysmon ID 3 (port 445 connects), Event ID 4688 (dropper).
- **Step-by-Step**:
  1. Query Exploits: Splunk: `index=network dest_port=445 payload="SMB \xFF \x00 \x00" | stats count by src_ip | where count > 2`.
  2. Sigma Rule:
     ```
     title: EternalBlue Execution
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         Payload: '*SMB \xFF \x00*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw malfind | grep smbd` (injected SMB code).
  4. Pivoting: To lateral movement.
- **Expert Tip**: Apply MS17-010 patch. Realistic: Worm-like speed; hunt SMB payloads.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Reused stolen credentials for re-infection.
- **Hypothesis**: "Dumped creds enable persistent access."
- **Data Sources**: Event ID 4624 (anomalous logons), Sysmon ID 13 (cred storage).
- **Step-by-Step**:
  1. Query Logons: Splunk: `index=ad EventID=4624 | search AccountName="service_account" src_ip!="internal" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Stolen Cred Persistence
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         LogonType: 3
         SrcGeo: NOT 'corporate'
       condition: selection
     ```
  3. Scan: Autoruns for rogue services post-exploit.
  4. Pivoting: To discovery.
- **Expert Tip**: Credential Guard. Realistic: Enabled spread; hunt external logons.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Used Mimikatz for token theft to escalate.
- **Hypothesis**: "Exploit escalates via stolen tokens."
- **Data Sources**: Sysmon ID 10 (lsass access), Event ID 4673 (privileges).
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" SubjectUserName="suspect" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Token Theft Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe*'
         GrantedAccess: '0x1410'
       condition: selection
     ```
  3. Analyze: YARA for Mimikatz signatures.
  4. Pivoting: To lateral movement.
- **Expert Tip**: Enable LSA protection. Realistic: Admin access; hunt lsass calls.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
Disabled AV and backups (vssadmin delete) before wiping.
- **Hypothesis**: "Wiper disables security tools to evade detection."
- **Data Sources**: Event ID 4688 (taskkill), Sysmon ID 1 (vssadmin).
- **Step-by-Step**:
  1. Query Disables: Splunk: `index=endpoint Image="taskkill.exe" CommandLine="*defender* OR *backup*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Security Tool Impairment
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*taskkill.exe OR *vssadmin.exe*'
         CommandLine: '*delete shadows* OR *av*'
       condition: selection
     ```
  3. Analyze: Hunt for vssadmin delete shadows /all /quiet.
  4. Pivoting: To encryption events.
- **Expert Tip**: Immutable backups. Realistic: Pre-wipe evasion; hunt tool kills.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped credentials with Mimikatz for lateral spread.
- **Hypothesis**: "Mimikatz dumps creds for network propagation."
- **Data Sources**: Sysmon ID 10 (lsass access), Event ID 4688 (mimikatz.exe).
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr TargetImage="lsass.exe" CallTrace="*MiniDumpWriteDump*" | stats dc(host) by src_ip`.
  2. Sigma Rule:
     ```
     title: Credential Dumping
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe*'
         CallTrace: '*MiniDump*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw dumpfiles` (credential dumps).
  4. Pivoting: To lateral movement.
- **Expert Tip**: Restrict lsass access. Realistic: Fuel for worm; hunt Mimikatz traces.

#### Step 8: Hunt for Discovery (TA0007) - Network Service Discovery (T1046)
Scanned for SMBv1-vulnerable hosts.
- **Hypothesis**: "Wiper discovers targets for EternalBlue."
- **Data Sources**: Sysmon ID 3 (port 445 scans), Zeek network logs.
- **Step-by-Step**:
  1. Query Scans: Splunk: `index=network dest_port=445 ConnCount > 5 | stats count by src_ip | where count > baseline`.
  2. Sigma Rule:
     ```
     title: SMB Service Discovery
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         ConnCount: '>5'
       condition: selection
     ```
  3. Analyze: Look for rapid port 445 probes (EternalBlue precursor).
  4. Pivoting: To lateral movement.
- **Expert Tip**: Monitor port 445 traffic. Realistic: Worm targeting; hunt scan bursts.

#### Step 9: Hunt for Lateral Movement (TA0008) - Exploitation of Remote Services (T1210)
Propagated via EternalBlue and stolen creds.
- **Hypothesis**: "Wiper spreads via SMB exploits and creds."
- **Data Sources**: Event ID 5145 (SMB shares), Sysmon ID 3 (port 445).
- **Step-by-Step**:
  1. Query SMB: Splunk: `index=network protocol=smb dest_port=445 src="infected" | stats count by dest_ip`.
  2. Sigma Rule:
     ```
     title: SMB Lateral Movement
     logsource:
       category: network_connection
     detection:
       selection:
         Protocol: 'smb'
         DestinationPort: 445
         Src: 'infected_host'
       condition: selection
     ```
  3. Analyze: Look for DoublePulsar beacon traffic (post-EternalBlue).
  4. Pivoting: To collection or encryption.
- **Expert Tip**: Segment networks (IT/OT). Realistic: Rapid spread to Maersk; hunt SMB chains.

#### Step 10: Hunt for Collection (TA0009) - Automated Collection (T1119)
Staged files automatically before encryption.
- **Hypothesis**: "Wiper collects data for staging pre-destruction."
- **Data Sources**: Sysmon ID 11 (temp file writes), Event ID 4663 (file access).
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FileName="*.tmp OR *.dat" Size > 5MB Process="perseus.exe" | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: Pre-Encryption Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.tmp OR *.dat'
         Size: '>5MB'
         Process: '*notpetya*'
       condition: selection
     ```
  3. Analyze: High-volume temp file creation.
  4. Pivoting: To encryption or exfiltration.
- **Expert Tip**: Implement file DLP. Realistic: Pre-wipe staging; hunt large temp files.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071.001)
Minimal C2; primarily for initial payload delivery or status.
- **Hypothesis**: "Wiper uses HTTP for C2 communication."
- **Data Sources**: Sysmon ID 3 (HTTP to C2), Zeek HTTP logs.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="sigus4.com" OR http_method=POST | stats dc(dest_ip) by src_ip`.
  2. Sigma Rule:
     ```
     title: NotPetya C2
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '80 OR 443'
         Domain: '*sigus4* OR *unknown*'
       condition: selection
     ```
  3. Analyze: JA3 fingerprints for NotPetya C2.
  4. Pivoting: To encryption events.
- **Expert Tip**: Block unknown C2 domains. Realistic: Limited C2; hunt HTTP anomalies.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over C2 Channel (T1041)
Minimal exfiltration; focus on destruction, but some data sent to C2.
- **Hypothesis**: "Limited data exfiltrated before wipe."
- **Data Sources**: Network logs (POSTs to C2), Sysmon ID 3 (outbound).
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=network http_method=POST bytes_out > 1MB dest_domain="sigus4.com" | stats sum(bytes) by src_ip`.
  2. Sigma Rule:
     ```
     title: Pre-Wipe Exfiltration
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_length: '>500KB'
         dest: '*sigus4*'
       condition: selection
     ```
  3. Analyze: PCAP for encoded payloads.
  4. Pivoting: To dark web monitoring for Maersk data.
- **Expert Tip**: Deploy outbound DLP. Realistic: Secondary to wipe; hunt small POSTs.

#### Step 13: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486), Inhibit System Recovery (T1490)
Encrypted files, wiped MBR, deleted shadow copies.
- **Hypothesis**: "Wiper encrypts systems and prevents recovery."
- **Data Sources**: Sysmon ID 11 (encrypted files), Event ID 7045 (wiper service).
- **Step-by-Step**:
  1. Query Encryption: Splunk: `index=endpoint FileModify="*.WNCRY" OR CommandLine="*vssadmin delete*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: NotPetya Wiper Impact
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.WNCRY'
         OR Command: '*vssadmin delete shadows*'
       condition: selection
     ```
  3. Analyze: Hunt for MBR overwrites (boot failures).
  4. Pivoting: To operational disruptions (e.g., Maersk terminals down).
- **Expert Tip**: Air-gapped backups. Realistic: Total wipe; hunt encryption spikes.

#### Step 14: Hunt for ICS-Specific Impact (ICS T0814: Inhibit Response Function)
Disrupted OT (Maersk terminals, logistics).
- **Hypothesis**: "Wiper halts OT operations via IT spread."
- **Data Sources**: OT logs (e.g., Claroty for terminal failures), Sysmon ID 3 (SMB to OT).
- **Step-by-Step**:
  1. Query OT Impact: Splunk: `index=ot protocol=smb OR Event="device_down" | stats count by device_ip`.
  2. Sigma Rule:
     ```
     title: OT Disruption
     logsource:
       category: network_connection
     detection:
       selection:
         Protocol: 'smb'
         Dest: 'ot_segment'
         OR Event: 'device_failure'
       condition: selection
     ```
  3. Analyze: Terminal stoppages (Modbus timeouts).
  4. Pivoting: To recovery failures.
- **Expert Tip**: IT/OT segmentation. Realistic: Maersk terminals; hunt OT SMB.

#### Step 15: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate segments, disable SMBv1), eradicate (wipe infected, patch MS17-010), recover (restore from offline backups, manual ops like Maersk’s radios). Engage Talos/ESET; notify CISA.
- **Lessons**: Per Wired, vet supply chains, patch SMB, air-gap backups. Iterate bi-weekly; simulate with NotPetya variants in labs.
- **Expert Tip**: Use ATT&CK ICS Navigator; evolve for 2025 (e.g., AI-driven anomaly detection for worms).
