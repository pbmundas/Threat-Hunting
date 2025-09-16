### Teaching Threat Hunting for CCleaner Supply Chain Attack-Like Attacks (2017): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in supply chain compromises and software update threats, I'll guide you through proactive threat hunting to detect attacks resembling the 2017 CCleaner supply chain attack. This incident was a sophisticated supply chain compromise attributed to the Chinese state-sponsored APT group Axiom (also known as APT17, DeputyDog, or Winnti, linked to PLA Unit 61398), targeting Piriform (CCleaner developer, acquired by Avast in July 2017). Attackers breached Piriform's build servers in March 2017 via RDP and malware, injecting backdoors into CCleaner versions 5.33.8162/8631 (32/64-bit), distributed via official updates from August 15 to September 15, 2017. The initial stage (infecting 2.27M users) used a loader to download a second-stage backdoor (ShadowPad variant) from C2 servers, targeting ~700K systems. A third stage (keylogger module, ShadowPad customized) was deployed to only 20 specific high-value targets (e.g., Akamai, Sony, Microsoft, HTC, Linksys domains), stealing data for espionage. No ransomware; focus on IP theft.

Dwell time: ~6 months (March 2017 breach to September 2017 detection by Cisco Talos/Morphisec, who analyzed the backdoor and notified Avast/FBI). Undetected due to signed malicious binaries evading AV, no build process monitoring, and targeted second-stage (only activated on specific IPs). Detection: Talos reverse-engineered the loader, revealing C2; Avast/FBI shut down infrastructure. Impacts: 2.27M infections (potential botnet), targeted espionage on tech firms, $1M+ Avast remediation, heightened supply chain scrutiny (e.g., SolarWinds precursor), and attribution to Axiom via code reuse (e.g., base64 variants from Operation Aurora 2009). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts T1078.002 via RDP), TA0002 (Execution: User Execution T1204.002 via updates), TA0003 (Persistence: Create Account T1136 on servers), TA0005 (Defense Evasion: Obfuscated Files T1027), TA0007 (Discovery: Software Discovery T1518), TA0008 (Lateral Movement: Remote Services T1021.001), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0004 (Privilege Escalation: Access Token Manipulation T1134).

Threat hunting assumes compromise: Hypothesis-driven searches for build server breaches leading to tainted updates in software vendors. Realistic parameters:
- **Environment**: DevOps pipelines (e.g., build servers, GitHub, update mirrors); high-trust updates (signed binaries).
- **Adversary Profile**: State-sponsored (RDP for foothold, modular backdoors like ShadowPad; targeted espionage on tech).
- **Challenges**: Signed malware evades detection, supply chain trust, second-stage geo-fencing.
- **Tools/Data Sources**: EDR (CrowdStrike for endpoints), SIEM (Splunk for build logs), code scanners (TruffleHog), YARA/Sigma for ShadowPad IOCs (e.g., SHA256: 6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9 for loader).
- **Hypotheses**: E.g., "An adversary has breached build servers to inject backdoors into updates."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Cisco Talos, Intezer, and Avast reports). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., CI/CD labs) to avoid prod builds. Baselines: 30-90 days of update/download logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the attack—Piriform's compromised build servers tainted updates; prioritize CI/CD monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for Axiom/APT17 (e.g., T1195 for supply chain). IOCs: Loader hashes (MD5: 6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9), ShadowPad C2 (e.g., mal.com variants), targeted domains (akamai.com, sony.com). Cross-ref Cisco Talos analysis, Intezer attribution, Avast timeline, and Hacker News summary.
- **Map Your Environment**: Inventory build servers (e.g., Jenkins), update endpoints (S3 mirrors), signing certs. Use tools like GitHub Advanced Security or Sonatype for supply chain; BloodHound for RDP paths.
- **Baseline Normal Behavior**: Log build jobs (no anomalies), update downloads (internal IPs), second-stage activations (none). Tool: Sysmon (build config for process/registry); enable CI/CD auditing.
- **Expert Tip**: Sign updates with hardware security modules (HSMs). Hypothesis: "APT17 breaches via RDP to inject into builds; hunt anomalous build logs leading to tainted updates."

#### Step 2: Hunt for Initial Access (TA0001) - Valid Accounts (T1078.002 via RDP)
Compromised internal machines via RDP backdoor.
- **Hypothesis**: "An adversary has used weak RDP for server access."
- **Data Sources**: RDP logs (Event ID 4624 LogonType=10), Sysmon ID 3 (RDP connects).
- **Step-by-Step Hunting**:
  1. Query RDP: Splunk SPL: `index=windows EventID=4624 LogonType=10 | search AccountName="admin" src_country!="US" | stats count by src_ip | where count > 1`.
  2. Sigma Rule (YAML):
     ```
     title: Anomalous RDP Access
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         LogonType: 10
         SrcGeo: NOT 'US'
       condition: selection
     ```
     Deploy in SIEM; alert on external RDP.
  3. Analyze: Failed logons (Event ID 4625) for brute-force precursors; hunt RDP from build servers.
  4. Pivoting: Trace to binary drops (Event ID 4688).
- **Expert Tip**: Disable RDP or use MFA. Realistic: Unattended machines; hunt off-hours.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.002): Malicious File
Executed binaries on compromised machines to inject into builds.
- **Hypothesis**: "RDP access enables execution of injection tools."
- **Data Sources**: Sysmon ID 1 (process from RDP), Event ID 4688.
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=endpoint EventID=1 | search ParentImage="*mstsc.exe*" Image="*injector*" | table _time, host, CommandLine`.
  2. Sigma Rule:
     ```
     title: RDP-Triggered Execution
     logsource:
       category: process_creation
     detection:
       selection:
         ParentImage: '*mstsc.exe*'
         Image: '*.exe' AND OriginalFileName: 'backdoor*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw procdump -p pid` (dump RDP sessions).
  4. Pivoting: Correlate with build job anomalies.
- **Expert Tip**: AppLocker on servers. Realistic: Binary drops; hunt RDP children.

#### Step 4: Hunt for Persistence (TA0003) - Create Account (T1136)
Created backdoor accounts on internal systems.
- **Hypothesis**: "Adversary persists via rogue accounts on build servers."
- **Data Sources**: Event ID 4720 (user create), Sysmon ID 13 (registry).
- **Step-by-Step**:
  1. Query Accounts: Splunk: `index=ad EventCode=4720 | search AccountName NOT IN ("known") | stats count by creator_host`.
  2. Sigma Rule:
     ```
     title: Rogue Account Creation
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4720
         CreatorHost: 'build_server'
       condition: selection
     ```
  3. Scan: Net user for hidden accounts.
  4. Pivoting: Link to RDP logons.
- **Expert Tip**: Account auditing. Realistic: Backdoor for injection; hunt new users.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134)
Escalated via token theft on compromised hosts.
- **Hypothesis**: "Initial access escalated to build admin."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4673.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" SubjectUserName="rdp_user" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Token Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe'
         GrantedAccess: '0x1410'
       condition: selection
     ```
  3. Analyze: Mimikatz YARA.
  4. Pivoting: To build access.
- **Expert Tip**: Protected LSASS. Realistic: Enabled injection; hunt unusual privs.

#### Step 6: Hunt for Defense Evasion (TA0005) - Obfuscated Files or Information (T1027)
Obfuscated backdoor with base64 (Axiom signature); signed binaries.
- **Hypothesis**: "Injected code evades via obfuscation/signing."
- **Data Sources**: Sysmon ID 11 (obfuscated files), AV bypasses.
- **Step-by-Step**:
  1. Query Obfuscation: Splunk: `index=endpoint FileCreate="*.exe" entropy > 7 | search content="base64" | stats count by hash`.
  2. Sigma Rule:
     ```
     title: Obfuscated Injection
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.exe'
         Entropy: '>7'
         Signed: true
       condition: selection
     ```
  3. Binary: Detect base64 decoders.
  4. Pivoting: To updates.
- **Expert Tip**: Code signing verification. Realistic: Axiom base64; hunt high-entropy.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552)
Accessed build creds (e.g., signing keys) on servers.
- **Hypothesis**: "Build server creds stolen for signing."
- **Data Sources**: Sysmon ID 10 (cred stores), Event ID 4688.
- **Step-by-Step**:
  1. Query Access: Splunk: `index=endpoint TargetProcess="*credman*" | search host="build" | stats dc(host)`.
  2. Sigma Rule:
     ```
     title: Build Cred Theft
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*vault* OR *keyring*'
         Host: 'build_server'
       condition: selection
     ```
  3. Forensics: ProcDump for cred processes.
  4. Pivoting: To discovery.
- **Expert Tip**: HSM for keys. Realistic: Enabled signing; hunt vault.

#### Step 8: Hunt for Discovery (TA0007) - Software Discovery (T1518)
Discovered build tools (e.g., compilers) for injection.
- **Hypothesis**: "Recon on servers for supply chain points."
- **Data Sources**: Sysmon ID 1 (wmic.exe), Event ID 4688.
- **Step-by-Step**:
  1. Query Discovery: Splunk: `index=endpoint Image="wmic.exe" CommandLine="*process*" host="build" | stats count by _time`.
  2. Sigma Rule:
     ```
     title: Build Server Recon
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*wmic.exe* OR *tasklist*'
         Host: 'ci_cd*'
       condition: selection
     ```
  3. Analyze: Enum of compilers.
  4. Pivoting: To injection.
- **Expert Tip**: Server hardening. Realistic: Mapped pipeline; hunt enum.

#### Step 9: Hunt for Lateral Movement (TA0008) - Remote Services (T1021.001: RDP)
Moved via RDP between build machines.
- **Hypothesis**: "Lateral to inject into multiple builds."
- **Data Sources**: Event ID 5145, Sysmon ID 3 (3389).
- **Step-by-Step**:
  1. Query RDP: Splunk: `index=network protocol=rdp dest_port=3389 host="build" | stats count by src, dest`.
  2. Sigma Rule:
     ```
     title: Build Lateral RDP
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 3389
         Src: 'internal_server'
       condition: selection
     ```
  3. Traffic: Anomalous RDP chains.
  4. Pivoting: To tainted builds.
- **Expert Tip**: RDP bastions. Realistic: Network spread; hunt internal.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected targeted data post-infection (e.g., files from Akamai).
- **Hypothesis**: "Second-stage collects IP from targets."
- **Data Sources**: Sysmon ID 11 (ShadowPad staging), EDR on victims.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=edr FileName="shadowpad*" Size > 10MB | stats sum(Size) by host_domain="akamai.com"`.
  2. Sigma Rule:
     ```
     title: Targeted Collection
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.dat' Process: '*loader*'
         HostDomain: 'tech_target*'
       condition: selection
     ```
  3. Victim: Domain-specific payloads.
  4. Pivoting: To exfil.
- **Expert Tip**: Endpoint DLP. Realistic: 20 targets; hunt geo-fenced.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
Loader downloaded second-stage from C2.
- **Hypothesis**: "Backdoor C2 for payload delivery."
- **Data Sources**: Sysmon ID 3 (downloads), Zeek HTTP.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="c2.com" http_method=GET payload="shadowpad" | stats dc(dest)`.
  2. Sigma Rule:
     ```
     title: Supply Chain C2
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '80'
         URI: '*loader*'
       condition: selection
     ```
  3. Traffic: Beacon to Chinese C2.
  4. Pivoting: To keylogger.
- **Expert Tip**: C2 hunting. Realistic: HTTP; hunt loaders.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated data from targets via ShadowPad.
- **Hypothesis**: "Collected IP exfil to attackers."
- **Data Sources**: Network (POSTs from victims), EDR.
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=edr http_method=POST bytes_out > 1MB host_domain="sony.com" | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: Targeted Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_length: '>500KB'
         host: 'tech_domain*'
       condition: selection
     ```
  3. PCAP: Encoded payloads.
  4. Pivoting: Dark web IP dumps.
- **Expert Tip**: Outbound DLP. Realistic: Espionage; hunt targeted.

#### Step 13: Hunt for Impact (TA0040) - No Direct Destruction
No encryption/wipe; impact via espionage (data theft).
- **Hypothesis**: "Theft leads to IP compromise."
- **Data Sources**: EDR (keylogger output), leak monitoring.
- **Step-by-Step**:
  1. Query Theft: Splunk: `index=edr Process="keylogger" | stats count by victim_domain`.
  2. Sigma Rule:
     ```
     title: Espionage Impact
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*shadowpad*'
         Behavior: 'keylog OR screenshot'
       condition: selection
     ```
  3. Monitor: Breaches.cloud for CCleaner dumps.
  4. Pivoting: Attribution to Axiom.
- **Expert Tip**: Threat intel feeds. Realistic: Silent theft; hunt behaviors.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (quarantine builds), eradicate (revoke certs, scan endpoints), recover (reissue updates, notify users). Like Avast, notify FBI; revoke signatures.
- **Lessons**: Per Talos, secure build pipelines, monitor updates, scan repos. Iterate weekly; simulate with tainted builds in labs.
- **Expert Tip**: ATT&CK Navigator for devops; evolve for 2025 (e.g., AI code injection detection).
