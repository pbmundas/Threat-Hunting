### Teaching Threat Hunting for WannaCry Ransomware Attack-Like Attacks (2017): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with extensive experience in ransomware worm variants and rapid-propagation threats, I'll guide you through proactive threat hunting to detect attacks resembling the 2017 WannaCry ransomware outbreak. This was a global cyber event attributed to North Korea's Lazarus Group (per U.S. government attribution in 2018), deploying ransomware that exploited the EternalBlue vulnerability (CVE-2017-0144/5, an SMBv1 remote code execution flaw leaked from the NSA by Shadow Brokers). Starting on May 12, 2017, at 07:44 UTC, WannaCry spread as a self-propagating worm, infecting over 200,000 computers in 150 countries within days. It encrypted files (appending .WCRY) and demanded $300-600 in Bitcoin, but was halted at 15:03 UTC by researcher Marcus Hutchins registering a kill switch domain. The malware targeted Windows systems, using EternalBlue for lateral movement, Mimikatz for credential dumping, and a wiper component for destruction. While disguised as ransomware, it was largely destructive, with unrecoverable keys in many cases.

Dwell time: Very short per victim (~hours to days for spread and encryption), but preparation involved months (Shadow Brokers leak in April 2017; North Korean development earlier). Undetected due to unpatched SMBv1 (despite MS17-010 patch in March 2017), no network segmentation, and rapid worm behavior overwhelming defenses. Detection: Initial alerts from AV firms (e.g., Kaspersky on May 12); global response by Microsoft (emergency patches for XP) and Hutchins' sinkhole. Impacts: $4 billion+ in global losses (e.g., NHS hospitals disrupted, Renault factories halted), accelerated patching (e.g., end of XP support reconsidered), and geopolitical tensions (U.S. sanctions on North Korea). From a MITRE ATT&CK Enterprise/ICS perspective (from MITRE S0366), key tactics include TA0001 (Initial Access: Exploit Public-Facing Application T1190 via EternalBlue), TA0002 (Execution: Exploitation for Client Execution T1203), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: File and Directory Permissions Modification T1222.001), TA0006 (Credential Access: OS Credential Dumping T1003), TA0007 (Discovery: Remote System Discovery T1018), TA0008 (Lateral Movement: Exploitation of Remote Services T1210), TA0009 (Collection: File and Directory Discovery T1083), TA0010 (Exfiltration: Encrypted Channel T1573.002), and TA0040 (Impact: Data Encrypted for Impact T1486, Inhibit System Recovery T1490).

Threat hunting assumes infection: Hypothesis-driven searches for SMB exploits leading to worm-like ransomware in healthcare/manufacturing. Realistic parameters:
- **Environment**: Windows-heavy nets (SMBv1 enabled, unpatched MS17-010), OT/IT convergence (e.g., factories/hospitals).
- **Adversary Profile**: State-sponsored (worm via exploits, destruction over profit; geopolitical motives).
- **Challenges**: Rapid spread overwhelms, unpatched legacy (XP/7), limited OT logging.
- **Tools/Data Sources**: EDR (Microsoft Defender for SMB), SIEM (Splunk for network/DB), vuln scanners (Nessus for CVE-2017-0144), YARA/Sigma for WannaCry IOCs (e.g., SHA256: 65cee234f3ce2e3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b).
- **Hypotheses**: E.g., "An adversary exploits SMBv1 to propagate ransomware across segments."

This guide covers **each relevant MITRE ATT&CK technique** (from MITRE S0366 and reports). Proceed tactic-by-tactic with sub-steps: hypothesis, data sources, hunting steps (queries, Sigma, etc.), tips. Hunt in scoped envs (e.g., Windows labs) to avoid spread. Baselines: 30-60 days of SMB/network logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Context is key—WannaCry's worm spread via EternalBlue; focus on SMB patching.
- **Gather Threat Intel**: Review MITRE ATT&CK for S0366 (e.g., T1210 for EternalBlue). IOCs: Ransomware notes ("$300 BTC"), wiper binaries, C2 (Tor for ransom). Cross-ref MITRE S0366, Wikipedia, CISA alert, and Cloudflare summary.
- **Map Your Environment**: Inventory Windows hosts (SMBv1 enabled), OT (e.g., Modbus-linked). Use Nmap for vuln ports (445); BloodHound for spread paths.
- **Baseline Normal Behavior**: Log SMB connects (no exploits), encryption (none). Tool: Sysmon (SMB config for network/process); Wireshark for dissectors.
- **Expert Tip**: SMBv1 disablement. Hypothesis: "Lazarus exploits EternalBlue for worm spread; hunt SMB anomalies leading to encryption."

#### Step 2: Hunt for Initial Access (TA0001) - Exploit Public-Facing Application (T1190 via EternalBlue)
EternalBlue SMB exploit for entry.
- **Hypothesis**: "An adversary exploits SMBv1 for RCE."
- **Data Sources**: Sysmon ID 3 (port 445), WAF/network logs.
- **Step-by-Step Hunting**:
  1. Query Exploits: Splunk SPL: `index=network dest_port=445 payload="SMB \xFF \x00" | stats count by src_ip | where count > 1`.
  2. Sigma Rule (YAML):
     ```
     title: EternalBlue Exploit
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         Payload: '*SMB \xFF \x00*'
       condition: selection
     ```
     Deploy in SIEM; alert on SMB payloads.
  3. Analyze: Wireshark for EternalBlue headers.
  4. Pivoting: Trace to process spawns (Event ID 4688).
- **Expert Tip**: MS17-010 patch. Realistic: Worm entry; hunt SMBv1.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution (T1203)
Executed ransomware via exploit.
- **Hypothesis**: "Exploit drops wiper payload."
- **Data Sources**: Sysmon ID 1 (ransom.exe), Event ID 4688.
- **Step-by-Step**:
  1. Query Drops: Splunk: `index=endpoint EventID=1 | search ParentImage="*smbd.exe*" Image="*wcry.exe*" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Ransomware Drop
     logsource:
       category: process_creation
     detection:
       selection:
         ParentImage: '*smbd*'
         Image: '*.wcry OR *ransom*'
       condition: selection
     ```
  3. Forensics: Volatility malfind for injections.
  4. Pivoting: To encryption.
- **Expert Tip**: Behavioral AV. Realistic: Auto-exec; hunt SMB parents.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Used dumped creds for re-infection.
- **Hypothesis**: "Dumps persist across reboots."
- **Data Sources**: Event ID 4720, Sysmon ID 13.
- **Step-by-Step**:
  1. Query Creds: Splunk: `index=ad EventID=4672 | search AccountName="dumped" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Cred Persistence
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4672
         Account: 'admin*'
       condition: selection
     ```
  3. Scan: Mimikatz indicators.
  4. Pivoting: To discovery.
- **Expert Tip**: Cred guard. Realistic: Enabled spread; hunt dumps.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Token theft via Mimikatz for admin.
- **Hypothesis**: "Exploit escalates via tokens."
- **Data Sources**: Sysmon ID 10, Event ID 4673.
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
  3. Analyze: PtH traces.
  4. Pivoting: To collection.
- **Expert Tip**: LSA protect. Realistic: Local admin; hunt lsass.

#### Step 5: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001), File and Directory Permissions Modification (T1222.001)
Disabled AV, modified perms (attrib +h, icacls for full access).
- **Hypothesis**: "Wiper evades by impairing tools/perms."
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
         CommandLine: '*defender*'
       condition: selection
     ```
  3. Perms: Hunt icacls /grant Everyone:F.
  4. Pivoting: To impact.
- **Expert Tip**: Immutable perms. Realistic: Hid files; hunt attrib.

#### Step 6: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Mimikatz dumped creds for spread.
- **Hypothesis**: "Dumps enable lateral."
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
  4. Pivoting: To movement.
- **Expert Tip**: Guard creds. Realistic: Worm fuel; hunt API.

#### Step 7: Hunt for Discovery (TA0007) - Remote System Discovery (T1018)
Scanned for vulnerable hosts (port 445).
- **Hypothesis**: "Worm discovers spread targets."
- **Data Sources**: Sysmon ID 3, Zeek scans.
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
  4. Pivoting: To lateral.
- **Expert Tip**: SMB auditing. Realistic: Network scan; hunt bursts.

#### Step 8: Hunt for Lateral Movement (TA0008) - Exploitation of Remote Services (T1210)
Propagated via EternalBlue SMB.
- **Hypothesis**: "Exploit moves laterally."
- **Data Sources**: Event ID 5145, Sysmon ID 3 (445).
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
         Src: 'infected'
       condition: selection
     ```
  3. Traffic: Doublepulsar beacons.
  4. Pivoting: To collection.
- **Expert Tip**: Disable SMBv1. Realistic: Worm spread; hunt chains.

#### Step 9: Hunt for Collection (TA0009) - File and Directory Discovery (T1083)
Searched for encryptable files.
- **Hypothesis**: "Ransomware discovers user files."
- **Data Sources**: Sysmon ID 11 (searches), file accesses.
- **Step-by-Step**:
  1. Query Searches: Splunk: `index=endpoint FileAccess="*.doc OR *.pdf" Process="wcry" | stats count by host`.
  2. Sigma Rule:
     ```
     title: File Discovery
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.doc OR *.pdf OR *.jpg'
         Process: '*ransom*'
       condition: selection
     ```
  3. Volume: High accesses.
  4. Pivoting: To impact.
- **Expert Tip**: File DLP. Realistic: Extension hunts; hunt patterns.

#### Step 10: Hunt for Command and Control (TA0011) - Encrypted Channel (T1573.002)
Used Tor for C2.
- **Hypothesis**: "Ransomware beacons via Tor."
- **Data Sources**: Sysmon ID 3 (Tor ports), Zeek.
- **Step-by-Step**:
  1. Query Tor: Splunk: `index=network dest_port=9050 OR domain=".onion" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Tor C2
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '9050'
         OR Domain: '*.onion'
       condition: selection
     ```
  3. Traffic: Tor handshakes.
  4. Pivoting: To ransom.
- **Expert Tip**: Tor blocks. Realistic: Onion routing; hunt ports.

#### Step 11: Hunt for Exfiltration (TA0010) - Encrypted Channel (T1573.002)
Minimal exfil; keys to C2.
- **Hypothesis**: "Limited data exfil pre-encryption."
- **Data Sources**: Network (POST to Tor).
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=network http_method=POST dest=".onion" bytes_out > 1KB | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: C2 Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         dest: '*.onion'
       condition: selection
     ```
  3. PCAP: Key payloads.
  4. Pivoting: To impact.
- **Expert Tip**: Tor DLP. Realistic: Keys only; hunt small.

#### Step 12: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486), Inhibit System Recovery (T1490)
Encrypted files, deleted shadows, wiped MBR.
- **Hypothesis**: "Wiper encrypts and inhibits recovery."
- **Data Sources**: Sysmon ID 11 (wcry appends), Event ID 7045 (wiper service).
- **Step-by-Step**:
  1. Query Encryption: Splunk: `index=endpoint FileModify="*.wcry" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Ransomware Impact
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.wcry'
       condition: selection
     ```
  3. Recovery: Hunt vssadmin delete.
  4. Pivoting: Ops halts.
- **Expert Tip**: Immutable backups. Realistic: Destructive; hunt appends.

#### Step 13: Hunt for Exploitation of Remote Services (ICS T0866)
Exploited SMB in ICS nets.
- **Hypothesis**: "Exploit disrupts OT."
- **Data Sources**: OT logs (SMB in ICS).
- **Step-by-Step**:
  1. Query ICS SMB: Splunk: `index=ot dest_port=445 | stats count by src`.
  2. Sigma Rule:
     ```
     title: ICS SMB Exploit
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         Host: 'ot_device'
       condition: selection
     ```
  3. Protocol: Modbus disruptions.
  4. Pivoting: To recovery inhibits.
- **Expert Tip**: ICS segmentation. Realistic: OT spread; hunt ports.

#### Step 14: Hunt for Lateral Tool Transfer (ICS T0867)
Transferred via SMB to ICS.
- **Hypothesis**: "Worm moves to OT via SMB."
- **Data Sources**: Sysmon ID 3 (SMB in OT).
- **Step-by-Step**:
  1. Query Transfers: Splunk: `index=ot protocol=smb | stats count by dest_ip`.
  2. Sigma Rule:
     ```
     title: OT Lateral Transfer
     logsource:
       category: network_connection
     detection:
       selection:
         Protocol: 'smb'
         Dest: 'ot_segment'
       condition: selection
     ```
  3. Traffic: File copies.
  4. Pivoting: To impact.
- **Expert Tip**: OT diodes. Realistic: Hybrid spread; hunt cross.

#### Step 15: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (disable SMBv1, isolate), eradicate (wipe infected), recover (backups, patch). Like Maersk, manual ops; engage Talos.
- **Lessons**: Per Talos, patch exploits, monitor updates, segment. Iterate weekly; simulate with NotPetya variants.
- **Expert Tip**: ATT&CK ICS Navigator; evolve for 2025 (e.g., AI worm detection).
