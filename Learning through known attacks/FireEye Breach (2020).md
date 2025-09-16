### Teaching Threat Hunting for FireEye Breach-Like Attacks (2020): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in nation-state supply-chain intrusions and red team tool abuse, I'll guide you through proactive threat hunting to detect attacks resembling the 2020 FireEye breach. This incident was a highly sophisticated espionage operation attributed to APT29 (Cozy Bear, Russia's SVR foreign intelligence service, per FBI Director Christopher Wray's June 2021 confirmation), discovered on December 8, 2020, when FireEye disclosed unauthorized access to its networks. Attackers stole FireEye's Red Team tools (60+ custom and open-source penetration testing utilities, including exploits for 16 known vulnerabilities like CVE-2017-0144 EternalBlue), used for client assessments. The breach occurred amid the broader SolarWinds supply-chain attack (SUNBURST backdoor), which FireEye uncovered during its investigation—attackers had been in FireEye's environment since at least October 2020, using the SolarWinds Orion implant for persistence. No customer data was exfiltrated, but the tools' theft enabled potential reuse against FireEye's clients (e.g., governments, Fortune 500 firms). FireEye responded transparently, publishing IOCs, YARA rules, and mitigations on GitHub, and rebranded to Mandiant.

Dwell time: ~2 months (October-December 2020), undetected due to sophisticated evasion (e.g., custom tools mimicking legitimate activity), reliance on SolarWinds (trusted supply chain), and no anomalous indicators until tool theft. Detection: FireEye's internal monitoring spotted unusual access; analysis linked it to SolarWinds. Impacts: Amplified SolarWinds fallout (18,000+ victims), FireEye stock drop (10%), accelerated supply-chain scrutiny (e.g., CISA directives), and U.S. indictments (though focused on SolarWinds actors). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Supply Chain Compromise T1195 via SolarWinds), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Masquerading T1036.005), TA0007 (Discovery: Account Discovery T1087), TA0006 (Credential Access: OS Credential Dumping T1003), TA0008 (Lateral Movement: Remote Services T1021.001), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over C2 Channel T1041), and TA0004 (Privilege Escalation: Access Token Manipulation T1134).

Threat hunting assumes compromise: Hypothesis-driven searches for supply-chain backdoors and tool theft in cybersecurity/enterprise environments. Realistic parameters:
- **Environment**: Hybrid networks (e.g., SolarWinds Orion for monitoring, AD-integrated); high-value red team tools.
- **Adversary Profile**: Nation-state (low-and-slow espionage, tool reuse; deniability via custom evasion).
- **Challenges**: Trusted software (SolarWinds), tool masquerading, long dwell without noise.
- **Tools/Data Sources**: EDR (CrowdStrike for behaviors), SIEM (Splunk for SolarWinds logs), supply-chain scanners (e.g., SolarWinds integrity checks), YARA/Sigma for Red Team IOCs (e.g., FireEye's GitHub rules).
- **Hypotheses**: E.g., "APT29 uses SolarWinds backdoors to steal tools; hunt anomalous Orion activity leading to credential dumps."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from FireEye's blog, MITRE S0368 for UNC2452/SolarWinds, and FBI attribution). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., SolarWinds sims) to avoid operational risks. Baselines: 60-90 days of network/endpoint logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—APT29's SolarWinds implant enabled tool theft; prioritize supply-chain integrity.
- **Gather Threat Intel**: Review MITRE ATT&CK for UNC2452 (SolarWinds actors). IOCs: SUNBURST backdoor (DLL hashes like SHA256: 2c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f), Red Team tools (e.g., YARA rules from FireEye GitHub), C2 IPs (e.g., avsvmcloud[.]com). Cross-ref FireEye blog, Wikipedia, Reuters, and FBI Wray attribution.
- **Map Your Environment**: Inventory SolarWinds Orion (versions 2019.4-2020.2.1), red team tools (if used), AD paths. Use BloodHound for lateral; FireEye's GitHub for tool IOCs.
- **Baseline Normal Behavior**: Log Orion updates (trusted hashes), tool executions (authorized only). Tool: Sysmon (process/network config); CloudTrail if hybrid.
- **Expert Tip**: Scan for SolarWinds IOCs via CISA tools. Hypothesis: "APT29 uses SolarWinds backdoors for persistence; hunt anomalous Orion activity leading to tool theft."

#### Step 2: Hunt for Initial Access (TA0001) - Supply Chain Compromise (T1195 via SolarWinds)
Initial entry via SUNBURST backdoor in Orion updates (March-June 2020).
- **Hypothesis**: "An adversary has compromised trusted software updates for foothold."
- **Data Sources**: Update logs (SolarWinds), Sysmon ID 11 (DLL loads).
- **Step-by-Step Hunting**:
  1. Query Updates: Splunk SPL: `index=solarwinds sourcetype=orion | search version="2019.4-2020.2.1" hash="suspect_sunburst" | stats count by host`.
  2. Sigma Rule (YAML):
     ```
     title: SolarWinds SUNBURST Access
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*solarwinds*'
         Hash: '2c3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f'
       condition: selection
     ```
     Deploy in SIEM; alert on vulnerable Orion versions.
  3. Analyze: FireEye's IOCs for DLL loads; hunt for avsvmcloud[.]com DNS.
  4. Pivoting: Trace to credential access.
- **Expert Tip**: Remove vulnerable Orion. Realistic: Supply-chain entry; hunt update hashes.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution (T1203)
Executed SUNBURST for beaconing and tool deployment.
- **Hypothesis**: "Backdoor executes for C2 and red team tool runs."
- **Data Sources**: Sysmon ID 1 (DLL execution), Event ID 4688.
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=endpoint EventID=1 | search Image="*solarwinds.dll*" CommandLine="*beacon*" | table _time, host`.
  2. Sigma Rule:
     ```
     title: SUNBURST Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*solarwinds*'
         ParentImage: '*orion*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw procdump -p orion` (backdoor modules).
  4. Pivoting: To persistence.
- **Expert Tip**: Behavioral EDR. Realistic: DLL side-loading; hunt Orion children.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Established persistence via stolen creds and SolarWinds implant.
- **Hypothesis**: "Backdoor uses valid accounts for dwell."
- **Data Sources**: Event ID 4624 (anomalous logons), Sysmon ID 13.
- **Step-by-Step**:
  1. Query Logons: Splunk: `index=ad EventID=4624 | search AccountName="red_team*" src_ip!="internal" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Stolen Account Persistence
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'service*'
         SrcGeo: 'RU'
       condition: selection
     ```
  3. Scan: Autoruns for SolarWinds hooks.
  4. Pivoting: To discovery.
- **Expert Tip**: Account monitoring. Realistic: Cred reuse; hunt external.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Used Mimikatz-like tools (stolen Red Team) for token theft.
- **Hypothesis**: "Implant escalates via token manipulation."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4673.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Red Team Token Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe*'
         GrantedAccess: '0x1410'
       condition: selection
     ```
  3. Analyze: FireEye's YARA for Mimikatz variants.
  4. Pivoting: To lateral.
- **Expert Tip**: LSA protection. Realistic: Tool theft enabled; hunt lsass.

#### Step 6: Hunt for Defense Evasion (TA0005) - Masquerading (T1036.005)
Masqueraded as legitimate SolarWinds processes.
- **Hypothesis**: "Backdoor evades via process masquerading."
- **Data Sources**: Sysmon ID 1 (fake names), AV bypasses.
- **Step-by-Step**:
  1. Query Masquerade: Splunk: `index=endpoint ImageName="solarwinds.exe" OriginalFileName!="legit" | stats count by hash`.
  2. Sigma Rule:
     ```
     title: Process Masquerading
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*solarwinds*'
         OriginalFileName: NOT 'orion*'
       condition: selection
     ```
  3. Analyze: High entropy binaries.
  4. Pivoting: To discovery.
- **Expert Tip**: Process validation. Realistic: DLL hiding; hunt mismatches.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped creds using stolen Red Team tools (e.g., Mimikatz variants).
- **Hypothesis**: "Backdoor dumps creds for pivots."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4688.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr Target="lsass.exe" CallTrace="*MiniDump*" | stats dc(host)`.
  2. Sigma Rule:
     ```
     title: Red Team Cred Dump
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
- **Expert Tip**: Restrict lsass. Realistic: Tool reuse; hunt dumps.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087)
Enumerated AD/red team tools using stolen utilities.
- **Hypothesis**: "Implant discovers high-value assets."
- **Data Sources**: Event ID 4662, Sysmon ID 3 (LDAP).
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=ad EventID=4662 ObjectClass="user" | stats values(ObjectName) by host`.
  2. Sigma Rule:
     ```
     title: AD Discovery
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4662
         ObjectType: 'user'
       condition: selection
     ```
  3. Analyze: net.exe executions.
  4. Pivoting: To collection.
- **Expert Tip**: LDAP limits. Realistic: Tool enum; hunt queries.

#### Step 9: Hunt for Lateral Movement (TA0008) - Remote Services (T1021.001)
Moved via RDP/SMB using dumped creds.
- **Hypothesis**: "Backdoor pivots to tool storage."
- **Data Sources**: Event ID 5145, Sysmon ID 3 (3389).
- **Step-by-Step**:
  1. Query RDP: Splunk: `index=network protocol=rdp dest_port=3389 | stats count by src, dest`.
  2. Sigma Rule:
     ```
     title: Lateral RDP
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 3389
         User: 'dumped*'
       condition: selection
     ```
  3. Traffic: Anomalous RDP.
  4. Pivoting: To tool theft.
- **Expert Tip**: RDP bastions. Realistic: Internal spread; hunt chains.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected red team tools from repositories.
- **Hypothesis**: "Implant stages tools for exfil."
- **Data Sources**: Sysmon ID 11 (copies), file accesses.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FileName="red_team*" Size > 1MB | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: Tool Collection
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.exe OR *.dll' Path: 'tools*'
       condition: selection
     ```
  3. Volume: High tool copies.
  4. Pivoting: To exfil.
- **Expert Tip**: Repo ACLs. Realistic: Targeted theft; hunt sizes.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
SUNBURST beaconed to C2 for commands.
- **Hypothesis**: "Backdoor C2 for tool exfil."
- **Data Sources**: Sysmon ID 3 (HTTP), Zeek.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="avsvmcloud.com" | stats dc(dest) by src_ip`.
  2. Sigma Rule:
     ```
     title: SUNBURST C2
     logsource:
       category: network_connection
     detection:
       selection:
         Domain: '*avsvmcloud*'
       condition: selection
     ```
  3. Traffic: Beacon intervals.
  4. Pivoting: To exfil.
- **Expert Tip**: DNS sinkhole. Realistic: Stealthy; hunt domains.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over C2 Channel (T1041)
Exfiltrated tools via SUNBURST C2.
- **Hypothesis**: "Stolen tools exfil over backdoor."
- **Data Sources**: Network (POSTs to C2), Sysmon ID 3.
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=network http_method=POST dest="avsvmcloud.com" bytes_out > 1MB | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: Tool Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         dest: '*avsvmcloud*'
         length: '>500KB'
       condition: selection
     ```
  3. PCAP: Encoded tools.
  4. Pivoting: Dark web tool sales.
- **Expert Tip**: C2 DLP. Realistic: Tool theft; hunt large POSTs.

#### Step 13: Hunt for Impact (TA0040) - No Direct Destruction
Impact via tool reuse against clients; potential espionage.
- **Hypothesis**: "Theft enables attacks on FireEye clients."
- **Data Sources**: External monitoring (tool use), client alerts.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=external event="red_team_tool" source="fireeye_stolen" | stats count by victim`.
  2. Sigma Rule:
     ```
     title: Post-Theft Impact
     logsource:
       category: external
     detection:
       selection:
         event: 'tool_reuse'
       condition: selection
     ```
  3. Monitor: Client breaches.
  4. Pivoting: Attribution.
- **Expert Tip**: Tool watermarking. Realistic: Espionage; hunt reuse.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate Orion, revoke creds), eradicate (tool scans, patch), recover (notify clients, monitor). Like FireEye, publish IOCs; engage FBI.
- **Lessons**: Per FireEye blog, vet supply chains, monitor Orion, use FireEye's mitigations. Iterate bi-weekly; simulate with SUNBURST in labs.
- **Expert Tip**: ATT&CK Navigator for supply-chain; evolve for 2025 (e.g., AI tool detection).
