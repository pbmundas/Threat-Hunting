### Teaching Threat Hunting for SolarWinds Attack-Like Incidents (2020): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in nation-state supply-chain attacks and advanced persistent threats (APTs), I'll guide you through proactive threat hunting to detect attacks resembling the 2020 SolarWinds Orion breach, a landmark cyber-espionage campaign attributed to APT29 (Cozy Bear, Russia’s SVR, per U.S. FBI and CISA). Discovered by FireEye on December 8, 2020, the attack compromised SolarWinds’ Orion platform (versions 2019.4–2020.2.1) via a malicious update (SUNBURST backdoor, March–June 2020), affecting ~18,000 organizations, including U.S. agencies (e.g., Treasury, Commerce), FireEye, and Microsoft. Attackers used the backdoor to deploy additional payloads (TEARDROP, BEACON), steal data, and persist for months. For example, at FireEye, attackers stole 60+ Red Team tools. The campaign was stealthy, leveraging trusted software, custom malware, and legitimate process masquerading.

Dwell time: ~9 months (March–December 2020), undetected due to signed SolarWinds updates, polymorphic SUNBURST (unique hashes per victim), and low-noise C2 (e.g., avsvmcloud[.]com). Detection: FireEye’s EDR flagged anomalous access; Mandiant linked it to SolarWinds DLLs. Impacts: $90M+ in recovery costs (SolarWinds), geopolitical fallout (U.S. sanctions on Russia, April 2021), and supply-chain security reforms (e.g., CISA’s CPGs, NIST SP 800-161). From a MITRE ATT&CK Enterprise perspective (UNC2452/SolarWinds, S0552), key tactics include TA0001 (Initial Access: Supply Chain Compromise T1195.002), TA0002 (Execution: Malicious File T1204.002), TA0003 (Persistence: External Remote Services T1133), TA0005 (Defense Evasion: Masquerading T1036.005), TA0006 (Credential Access: OS Credential Dumping T1003), TA0007 (Discovery: Network Service Discovery T1046), TA0008 (Lateral Movement: Remote Services T1021.001), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over C2 Channel T1041), and TA0004 (Privilege Escalation: Access Token Manipulation T1134).

Threat hunting assumes compromise: Hypothesis-driven searches for supply-chain backdoors and stealthy espionage in enterprise networks. Realistic parameters:
- **Environment**: SolarWinds Orion (IT monitoring), AD-integrated networks, hybrid cloud.
- **Adversary Profile**: Nation-state (low-and-slow, custom malware; espionage via tool/data theft).
- **Challenges**: Trusted updates bypass AV, polymorphic malware, minimal C2 footprint.
- **Tools/Data Sources**: EDR (CrowdStrike for behaviors), SIEM (Splunk for SolarWinds logs), supply-chain scanners (e.g., CISA’s IOC tools), YARA/Sigma for SUNBURST IOCs (e.g., SHA256: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77).
- **Hypotheses**: E.g., “APT29 uses SolarWinds backdoors to deploy payloads; hunt anomalous Orion DLLs leading to C2.”

This guide covers **each relevant MITRE ATT&CK technique** (mapped from FireEye’s blog, MITRE S0552, and CISA Alert AA20-352A). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., SolarWinds labs) to avoid disruptions. Baselines: 60-90 days of Orion/network logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the attack—SolarWinds’ signed DLL enabled stealthy espionage; prioritize update integrity.
- **Gather Threat Intel**: Review MITRE ATT&CK for UNC2452/S0552. IOCs: SUNBURST DLLs (e.g., SolarWinds.Orion.Core.BusinessLayer.dll), C2 domains (e.g., avsvmcloud[.]com), TEARDROP hashes, FireEye’s GitHub YARA rules. Cross-ref FireEye disclosure, CISA Alert AA20-352A, Wikipedia timeline, and Mandiant’s SUNBURST analysis.
- **Map Your Environment**: Inventory SolarWinds Orion instances (2019.4–2020.2.1), AD accounts, high-value assets (e.g., tool repos). Use BloodHound for lateral paths; CISA’s scanner for Orion IOCs.
- **Baseline Normal Behavior**: Log Orion updates (signed hashes), network connects (no C2), process executions (legit SolarWinds). Tool: Sysmon (process/network config); Zeek for DNS.
- **Expert Tip**: Validate update signatures. Hypothesis: “APT29 compromises SolarWinds updates; hunt anomalous DLLs leading to C2 or tool theft.”

#### Step 2: Hunt for Initial Access (TA0001) - Supply Chain Compromise (T1195.002)
Malicious Orion update (SUNBURST DLL) for entry.
- **Hypothesis**: “An adversary taints trusted software updates for backdoor deployment.”
- **Data Sources**: Update logs (SolarWinds), Sysmon ID 11 (file writes), network logs.
- **Step-by-Step Hunting**:
  1. Query Updates: Splunk SPL: `index=solarwinds sourcetype=orion_update | search version="2019.4-2020.2.1" file="*SolarWinds.Orion.Core*" | stats count by file_hash | where hash NOT IN ("trusted")`.
  2. Sigma Rule (YAML):
     ```
     title: SolarWinds SUNBURST Backdoor
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*SolarWinds.Orion.Core*'
         Hash: '32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77'
       condition: selection
     ```
     Deploy in SIEM; alert on malicious DLL hashes.
  3. Analyze: Cross-ref FireEye’s YARA rules for SUNBURST; VirusTotal for DLLs.
  4. Pivoting: Trace to execution (Sysmon ID 1 for orion.dll).
- **Expert Tip**: Deploy CISA’s Orion scanner. Realistic: Signed updates; hunt hash mismatches.

#### Step 3: Hunt for Execution (TA0002) - Malicious File (T1204.002)
Executed SUNBURST DLL for beaconing and secondary payloads (TEARDROP/BEACON).
- **Hypothesis**: “Backdoor executes via Orion processes.”
- **Data Sources**: Sysmon ID 1 (DLL loads), Event ID 4688 (process creation).
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=endpoint EventID=1 | search Image="*solarwinds.orion*" ParentImage="*orion*" CommandLine="*http*" | table _time, host, hash`.
  2. Sigma Rule:
     ```
     title: SUNBURST DLL Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*solarwinds*'
         CommandLine: '*http* OR *beacon*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw malfind | grep solarwinds` (injected code).
  4. Pivoting: To C2 or persistence.
- **Expert Tip**: Behavioral EDR rules. Realistic: Legit process; hunt child HTTP.

#### Step 4: Hunt for Persistence (TA0003) - External Remote Services (T1133)
Persisted via SUNBURST and stolen creds for VPN/RDP.
- **Hypothesis**: “Backdoor maintains access via services/credentials.”
- **Data Sources**: Event ID 4624 (anomalous logons), Sysmon ID 3 (VPN/RDP).
- **Step-by-Step**:
  1. Query Logons: Splunk: `index=ad EventID=4624 | search LogonType=3 AccountName="service*" src_ip!="internal" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Anomalous Remote Access
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         LogonType: 3
         SrcGeo: NOT 'corporate'
       condition: selection
     ```
  3. Scan: VPN session anomalies (e.g., non-standard IPs).
  4. Pivoting: To discovery.
- **Expert Tip**: MFA for remote services. Realistic: Long dwell; hunt external logons.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Used stolen tokens (via Mimikatz-like tools) for escalation.
- **Hypothesis**: “Backdoor escalates via token theft.”
- **Data Sources**: Sysmon ID 10 (lsass access), Event ID 4673 (privileges).
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" AccountName="suspect" | table _time, host`.
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
  3. Analyze: YARA for Mimikatz (FireEye GitHub rules).
  4. Pivoting: To lateral movement.
- **Expert Tip**: Enable LSA protection. Realistic: Admin access; hunt lsass calls.

#### Step 6: Hunt for Defense Evasion (TA0005) - Masquerading (T1036.005)
Masqueraded as legitimate SolarWinds processes (e.g., orion.dll).
- **Hypothesis**: “Backdoor evades by mimicking Orion.”
- **Data Sources**: Sysmon ID 1 (process names), Event ID 4688.
- **Step-by-Step**:
  1. Query Masquerade: Splunk: `index=endpoint Image="*solarwinds*" OriginalFileName!="SolarWinds.Orion.Core" | stats count by hash`.
  2. Sigma Rule:
     ```
     title: SolarWinds Masquerading
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*solarwinds*'
         OriginalFileName: NOT 'orion*'
       condition: selection
     ```
  3. Analyze: High-entropy DLLs (polymorphic SUNBURST).
  4. Pivoting: To C2.
- **Expert Tip**: Process integrity checks. Realistic: Signed DLL; hunt mismatches.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped credentials using stolen Red Team tools (e.g., Mimikatz variants).
- **Hypothesis**: “Backdoor dumps creds for lateral spread.”
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4688.
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
  3. Forensics: Volatility: `vol.py -f mem.raw dumpfiles` (cred dumps).
  4. Pivoting: To lateral movement.
- **Expert Tip**: Restrict lsass access. Realistic: Tool-enabled; hunt dumps.

#### Step 8: Hunt for Discovery (TA0007) - Network Service Discovery (T1046)
Enumerated networks for high-value assets (e.g., FireEye tools).
- **Hypothesis**: “Backdoor discovers targets for espionage.”
- **Data Sources**: Sysmon ID 3 (port scans), Zeek (LDAP/SMB).
- **Step-by-Step**:
  1. Query Scans: Splunk: `index=network dest_port=445 OR 3389 ConnCount > 5 | stats count by src_ip | where count > baseline`.
  2. Sigma Rule:
     ```
     title: Network Recon
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '445 OR 3389'
         ConnCount: '>5'
       condition: selection
     ```
  3. Analyze: Rapid SMB/RDP probes.
  4. Pivoting: To collection.
- **Expert Tip**: Monitor port 445/3389. Realistic: Targeted repos; hunt bursts.

#### Step 9: Hunt for Lateral Movement (TA0008) - Remote Services (T1021.001)
Moved via RDP/SMB using stolen creds.
- **Hypothesis**: “Backdoor pivots to sensitive systems.”
- **Data Sources**: Event ID 5145 (SMB), Sysmon ID 3 (3389).
- **Step-by-Step**:
  1. Query RDP/SMB: Splunk: `index=network protocol=rdp OR smb src="infected" | stats count by dest_ip`.
  2. Sigma Rule:
     ```
     title: Lateral RDP/SMB
     logsource:
       category: network_connection
     detection:
       selection:
         Protocol: 'rdp OR smb'
         Src: 'solarwinds_host'
       condition: selection
     ```
  3. Traffic: Anomalous RDP sessions.
  4. Pivoting: To collection.
- **Expert Tip**: Segment RDP/SMB. Realistic: Tool repos; hunt chains.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected sensitive data/tools (e.g., FireEye Red Team).
- **Hypothesis**: “Backdoor stages data for exfil.”
- **Data Sources**: Sysmon ID 11 (file copies), Event ID 4663.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FileName="red_team*" OR "*sensitive*" Size > 1MB | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: Sensitive Data Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.exe OR *.ps1' Path: '*tools*'
         Size: '>1MB'
       condition: selection
     ```
  3. Analyze: High-volume tool copies.
  4. Pivoting: To exfiltration.
- **Expert Tip**: DLP for repos. Realistic: Tool theft; hunt large files.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071.001)
SUNBURST beaconed to C2 (e.g., avsvmcloud[.]com) for commands.
- **Hypothesis**: “Backdoor uses HTTP/DNS for C2.”
- **Data Sources**: Sysmon ID 3 (HTTP), Zeek (DNS).
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="avsvmcloud.com" OR http_method=POST | stats dc(dest_ip) by src_ip`.
  2. Sigma Rule:
     ```
     title: SUNBURST C2
     logsource:
       category: network_connection
     detection:
       selection:
         Domain: '*avsvmcloud* OR *freescanonline*'
         OR Method: 'POST'
       condition: selection
     ```
  3. Analyze: JA3 fingerprints for C2; DNS anomalies.
  4. Pivoting: To exfiltration.
- **Expert Tip**: DNS sinkholing. Realistic: Stealthy C2; hunt domains.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over C2 Channel (T1041)
Exfiltrated data/tools via SUNBURST C2.
- **Hypothesis**: “Backdoor exfils sensitive data over C2.”
- **Data Sources**: Network logs (POSTs to C2), Sysmon ID 3.
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=network http_method=POST dest="avsvmcloud.com" bytes_out > 500KB | stats sum(bytes) by src_ip`.
  2. Sigma Rule:
     ```
     title: Data Exfiltration
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         dest: '*avsvmcloud*'
         content_length: '>500KB'
       condition: selection
     ```
  3. Analyze: PCAP for encoded payloads (e.g., tools).
  4. Pivoting: To dark web monitoring.
- **Expert Tip**: Outbound DLP. Realistic: Tool/data theft; hunt large POSTs.

#### Step 13: Hunt for Impact (TA0040) - No Direct Destruction
Impact via espionage and tool reuse (no encryption).
- **Hypothesis**: “Theft enables attacks on victims.”
- **Data Sources**: External monitoring (tool reuse), client alerts.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=external event="red_team_tool" source="solarwinds" | stats count by victim_ip`.
  2. Sigma Rule:
     ```
     title: Post-Breach Tool Reuse
     logsource:
       category: external
     detection:
       selection:
         event: 'tool_execution'
       condition: selection
     ```
  3. Monitor: Client breach reports.
  4. Pivoting: To attribution.
- **Expert Tip**: Tool watermarking. Realistic: Espionage; hunt reuse.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate Orion, revoke creds), eradicate (remove SUNBURST, patch), recover (notify CISA, monitor clients). Like FireEye, publish IOCs; engage FBI.
- **Lessons**: Per FireEye and CISA, vet supply chains, monitor Orion DLLs, deploy YARA rules. Iterate bi-weekly; simulate with SUNBURST in labs.
- **Expert Tip**: ATT&CK Navigator for supply-chain; evolve for 2025 (e.g., AI-driven anomaly detection for polymorphic malware).
