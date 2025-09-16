### Teaching Threat Hunting for RSA SecurID Breach-Like Attacks (2011): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in APT (Advanced Persistent Threat) investigations and enterprise environments, I'll guide you through proactive threat hunting to detect attacks resembling the 2011 RSA SecurID breach. This incident, attributed to Chinese state-sponsored actors (likely linked to groups like APT1 or Daguang), was a classic supply-chain compromise via spear-phishing. Attackers targeted RSA—a security vendor providing SecurID two-factor authentication (2FA) tokens to over 30,000 customers, including defense contractors like Lockheed Martin. By exploiting a zero-day in Adobe Flash (CVE-2011-0611, a stacked buffer overflow in SWF files) embedded in a malicious Excel attachment ("2011 Recruitment plan.xls"), they deployed a Poison Ivy RAT variant. This allowed lateral movement, privilege escalation, and exfiltration of ~40MB of SecurID seed data (unique serial numbers and cryptographic seeds for tokens), enabling partial bypass of 2FA in follow-on attacks.

The dwell time was ~2 months (late January to mid-March 2011), with detection via internal NetWitness tools spotting anomalous behavior. Impacts included $66M in remediation costs for RSA (parent EMC), compromised 2FA for high-value targets, and geopolitical ripple effects (e.g., attempted breaches at Lockheed Martin). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Phishing), TA0002 (Execution: Exploitation for Client Execution), TA0003 (Persistence: Create Account), TA0008 (Lateral Movement: Remote Services), TA0011 (Command and Control: Ingress Tool Transfer), and TA0009 (Collection/Exfiltration: Data from Local System).

Threat hunting here assumes a breach has occurred—hypothesis-driven searches for low-and-slow APTs in enterprise networks with IAM (Identity and Access Management) systems. Realistic parameters:
- **Environment**: Hybrid enterprise (e.g., Windows domains with Active Directory, email gateways, file shares); SecurID-like systems (e.g., token databases in SQL/Oracle); supply-chain risks from vendors.
- **Adversary Profile**: Nation-state (patient, custom tooling, minimal noise); goals: IP theft, supply-chain compromise.
- **Challenges**: Phishing evades filters, RATs use living-off-the-land binaries (LOLBins), exfiltration blends with normal traffic.
- **Tools/Data Sources**: EDR (e.g., CrowdStrike, Microsoft Defender), SIEM (Splunk/ELK), email logs (Proofpoint), network metadata (Zeek), host forensics (Velociraptor), YARA/Sigma for IOCs.
- **Hypotheses**: E.g., "An adversary has used spear-phishing to deploy RATs and exfiltrate sensitive auth data."

This guide covers **each MITRE ATT&CK technique** from the breach (mapped via reports from Mandiant, RSA disclosures, and WIRED's retrospective). We'll proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt iteratively in a scoped environment (e.g., purple team lab) to avoid disruptions. Baselines: 30-60 days of logs for anomaly detection.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Context is king—RSA's breach succeeded due to unmonitored email and weak Flash controls.
- **Gather Threat Intel**: Review MITRE ATT&CK for APT1/Daguang (e.g., T1566.001: Phishing Attachment). IOCs: Poison Ivy hashes (e.g., MD5: 5d1e0c2b4a5e0b0a1e2d3c4e5f6789ab for variant), C2 domains (e.g., dynamic DNS like *.ru). Cross-ref with RSA's 2011 blog, Mandiant M-Trends 2011, and CVE-2011-0611 details.
- **Map Your Environment**: Inventory email systems (Exchange/O365), endpoints with Flash/Java, AD groups (e.g., privileged accounts), and auth databases (e.g., SecurID Authentication Manager). Use BloodHound for AD recon.
- **Baseline Normal Behavior**: Log email opens (Event ID 2003 in O365), file executions (Sysmon ID 1), and outbound traffic (port 443/HTTP POSTs). Tool: Sysmon (config for process creation, network connects).
- **Expert Tip**: Focus on HR/recruitment-themed lures—hunt for anomalous .xls attachments. Hypothesis: "Supply-chain phishing targets IAM vendors; scan for unpatched Flash exploits."

#### Step 2: Hunt for Initial Access (TA0001) - Spear-Phishing with Attachment
Entry via targeted emails exploiting CVE-2011-0611 in a booby-trapped Excel file (shellcode loads Poison Ivy).
- **Hypothesis**: "An adversary has delivered malware via spear-phishing attachments exploiting client-side vulnerabilities."
- **Data Sources**: Email gateway logs (e.g., Mimecast), O365 Audit Logs (Operations table), Sysmon (Event ID 11: File Creation for .xls).
- **Step-by-Step Hunting**:
  1. Query Suspicious Emails: Splunk SPL: `index=email sourcetype="o365:mail" | search subject="*Recruitment*" OR subject="*Staffing*" attachment="*xls*" | stats count by recipient, sender_ip | where count > 1`.
  2. Sigma Rule (YAML):
     ```
     title: Spear-Phishing Attachment with Flash Exploit
     logsource:
       category: email_activity
     detection:
       selection:
         subject: '*Recruitment plan*' OR '*Staffing plan*'
         attachment_type: 'application/vnd.ms-excel'
         has_macro: true
       condition: selection
     ```
     Deploy in SIEM; alert on low-volume, targeted sends (e.g., <5 recipients).
  3. Analyze Attachments: Use VirusTotal or Cuckoo Sandbox for .xls samples; hunt for embedded SWF (Flash) blobs with YARA: `rule CVE_2011_0611 { strings: $shellcode = { 60 68 ?? ?? ?? ?? 68 00 00 00 00 89 e5 51 53 } condition: $shellcode }`.
  4. Pivoting: If hit, check recipient's endpoint for Flash crashes (Event ID 1000 in AppCrash logs).
- **Expert Tip**: Enable Safe Attachments in O365. Realistic: 2011 emails bypassed filters via zero-day; modern hunts use UEBA for unusual opens by HR-adjacent users.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution and User Execution
Malware executed via exploited Flash, loading RAT payload.
- **Hypothesis**: "Exploit chains have triggered non-standard process execution on endpoints."
- **Data Sources**: Sysmon (Event ID 1: Process Creation), Windows Event ID 4688, EDR behavioral alerts.
- **Step-by-Step**:
  1. Query Anomalous Executions: Splunk: `index=edr EventID=1 | search ParentImage="*excel.exe" AND Image="*flash*.exe" OR CommandLine="*exploit*" | table _time, host, ParentImage, Image, CommandLine`.
  2. Sigma Rule:
     ```
     title: Flash Zero-Day Exploitation
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*\flash*.exe'
         ParentImage: '*\excel.exe'
         CommandLine: '*CVE-2011-0611*'
       condition: selection
     ```
  3. Memory Forensics: Volatility: `vol.py -f memdump.raw --profile=WinXPSP3x86 malfind | grep -i "poison ivy" | grep shellcode` (scan for injected code).
  4. Pivoting: Correlate with network connects from excel.exe child processes.
- **Expert Tip**: Block legacy Flash via GPO. Realistic: Execution was silent; hunt for parent-child anomalies in office apps.

#### Step 4: Hunt for Persistence (TA0003) - Create or Modify System Process, Account Manipulation
Poison Ivy installed backdoors (e.g., registry run keys) and created hidden accounts for persistence.
- **Hypothesis**: "Adversary has established persistence via scheduled tasks or rogue accounts."
- **Data Sources**: Sysmon (Event ID 13: Registry Modify), Event ID 4720 (User Creation), Autoruns output.
- **Step-by-Step**:
  1. Query New Accounts: Splunk: `index=ad EventCode=4720 | search AccountName NOT IN ("service_accounts") | stats count by host, AccountName`.
  2. Sigma Rule:
     ```
     title: Rogue Account Creation Post-Phishing
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4720
         LogonType: 5  # Interactive logon
       condition: selection
     ```
  3. Persistence Scan: Autoruns.exe /checklatest; hunt for HKCU\Software\Microsoft\Windows\CurrentVersion\Run with obfuscated values (e.g., base64-encoded Poison Ivy).
  4. Pivoting: Link to logons (Event ID 4624) from newly created users.
- **Expert Tip**: Use LAPS for local admin passwords. Realistic: APTs create dormant accounts; quarterly AD hunts essential.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation, Exploitation for Privilege Escalation
Escalation via RAT capabilities (e.g., token duplication) to domain admin.
- **Hypothesis**: "Low-priv users have escalated to admin via token theft."
- **Data Sources**: Sysmon (Event ID 10: Process Access), Event ID 4672/4673 (Privilege Use).
- **Step-by-Step**:
  1. Query Token Changes: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebugPrivilege*" AND User="low_priv_user" | table _time, host, SubjectUserName`.
  2. Sigma Rule:
     ```
     title: Token Duplication for Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe'
         GrantedAccess: '0x1410'  # TOKEN_DUPLICATE
       condition: selection
     ```
  3. Analyze with Mimikatz traces: YARA rule for dumped tokens.
  4. Pivoting: Check for admin actions post-escalation (e.g., GPO changes).
- **Expert Tip**: Enable Protected Process Light for lsass. Realistic: Escalation was gradual; hunt for unusual SeDebug grants.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses, Obfuscated Files
RAT evaded AV via packing; disabled logs.
- **Hypothesis**: "Malware is evading detection by modifying logs or using obfuscation."
- **Data Sources**: Event ID 1102 (Audit Log Cleared), Sysmon ID 1 with Imphash for packed binaries.
- **Step-by-Step**:
  1. Query Log Tampering: Splunk: `index=security EventID=1102 OR EventID=4719 | stats count by host | where count > 0`.
  2. Sigma Rule:
     ```
     title: Audit Log Clearing
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 1102
       condition: selection
     ```
  3. Binary Analysis: PEiD or Detect It Easy for packers (e.g., UPX on Poison Ivy).
  4. Pivoting: Hunt for wevtutil.exe executions (log export/deletion).
- **Expert Tip**: Immutable logs via WEF. Realistic: Minimal evasion; focus on gaps in 2011-era AV.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping
Dumped creds from lsass for lateral movement.
- **Hypothesis**: "Adversary is dumping credentials from memory."
- **Data Sources**: Sysmon ID 10 (access to lsass), Event ID 4688 with procdump-like commands.
- **Step-by-Step**:
  1. Query LSASS Access: Splunk: `index=edr | search TargetProcessImage="*lsass.exe" CallTrace="*advapi32*" | stats dc(host) as unique_hosts by _time`.
  2. Sigma Rule:
     ```
     title: Credential Dumping from LSASS
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe'
         CallTrace: '*advapi32*MiniDumpWriteDump*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw --profile=Win7SP1x86 dumpfiles -D lsass.dmp` (extract and hash).
  4. Pivoting: Correlate with Mimikatz IOCs (e.g., sekurlsa::logonpasswords).
- **Expert Tip**: Credential Guard in modern Windows. Realistic: RATs used built-in tools; hunt for unusual API calls.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery, Network Service Discovery
Scanned AD for SecurID DB access.
- **Hypothesis**: "Recon for high-value targets like auth databases."
- **Data Sources**: Event ID 4648 (Explicit Credentials), Sysmon ID 3 (Network Connect to LDAP).
- **Step-by-Step**:
  1. Query AD Enumeration: Splunk: `index=ad EventID=4662 | search ObjectClass="user" AND Properties="*memberOf*" | stats values(ObjectName) by host`.
  2. Sigma Rule:
     ```
     title: AD Account Enumeration
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4662
         ObjectType: 'user'
       condition: selection
     ```
  3. Network Hunt: Zeek logs for LDAP queries to SecurID servers.
  4. Pivoting: Check for nltest.exe or net.exe executions.
- **Expert Tip**: Log all AD queries. Realistic: Targeted SecurID-specific discovery.

#### Step 9: Hunt for Lateral Movement (TA0008) - Remote Services (RDP/SMB), Internal Spear-Phishing
Moved via RDP and shared drives to DB servers.
- **Hypothesis**: "Lateral propagation using stolen creds over SMB/RDP."
- **Data Sources**: Event ID 5145 (Share Access), Sysmon ID 3 (connects to port 445/3389).
- **Step-by-Step**:
  1. Query SMB Anomalies: Splunk: `index=network protocol=smb | search dest_port=445 AND user="*admin*" | stats count by src_ip, dest_ip`.
  2. Sigma Rule:
     ```
     title: Lateral Movement via SMB
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         Protocol: 'smb'
         User: '*$*'
       condition: selection
     ```
  3. RDP Analysis: Event ID 4624 with LogonType=10; hunt for unusual geos.
  4. Pivoting: Trace to SecurID DB logins (e.g., SQL audit for SELECT * FROM tokens).
- **Expert Tip**: MFA on RDP. Realistic: Low-volume moves; UEBA for cross-segment logons.

#### Step 10: Hunt for Collection (TA0009) - Data from Local System
Staged ~40MB of seed data in temp folders.
- **Hypothesis**: "Sensitive files (e.g., token seeds) are being collected locally."
- **Data Sources**: Sysmon ID 11 (file creation in %TEMP%), Event ID 4663 (file access).
- **Step-by-Step**:
  1. Query File Staging: Splunk: `index=endpoint | search FilePath="*temp*" AND FileName="*seed*" OR "*serial*" | stats sum(FileSize) as total_size by host`.
  2. Sigma Rule:
     ```
     title: Sensitive Data Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*securid* OR *token*'
         FileSize: '>10MB'
       condition: selection
     ```
  3. DLP Scan: Hunt for .csv/.sql dumps with regex for seeds (e.g., 10-digit serials).
  4. Pivoting: Correlate with compression (7z.exe) for exfil prep.
- **Expert Tip**: Encrypt auth DBs. Realistic: Data was zipped; hunt for unusual file sizes.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol, Ingress Tool Transfer
RAT beaconed to C2 over HTTPS; downloaded tools.
- **Hypothesis**: "Backdoor communicating with external C2 for commands/data."
- **Data Sources**: Sysmon ID 3 (connects to high ports), Zeek HTTP logs.
- **Step-by-Step**:
  1. Query Beaconing: Splunk: `index=network dest_port>1024 | stats dc(dest_ip) as beacons by src_ip | where beacons > 50/hour`.
  2. Sigma Rule:
     ```
     title: RAT C2 Beaconing
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '443'
         Protocol: 'tcp'
         UserAgent: '*PoisonIvy*'
       condition: selection
     ```
  3. Traffic Analysis: Wireshark filter `http contains "poisonivy" | beacon`.
  4. Pivoting: Block known C2 (e.g., *.cn domains from 2011 IOCs).
- **Expert Tip**: TLS inspection. Realistic: Encrypted, low-volume; anomaly detection key.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over C2 Channel
Exfiltrated data via HTTP POST to attacker servers.
- **Hypothesis**: "Staged data is being exfiltrated over web protocols."
- **Data Sources**: Network metadata (large POSTs), Event ID 5156 (Network Policy Server).
- **Step-by-Step**:
  1. Query Outbound Data: Splunk: `index=network http_method=POST bytes_out > 1MB | stats sum(bytes_out) by dest_ip, user`.
  2. Sigma Rule:
     ```
     title: Data Exfiltration Over HTTP
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         http_content_length: '>10485760'  # 10MB
       condition: selection
     ```
  3. PCAP Analysis: tshark -r capture.pcap -Y "http.request.method == POST && frame.len > 1M".
  4. Pivoting: Trace to collection hosts; check for RAR/ZIP uploads.
- **Expert Tip**: DLP on egress. Realistic: 40MB in chunks; hunt for sustained high-volume POSTs.

#### Step 13: Hunt for Impact (TA0040) - Account Access Removal (Post-Exfil)
Post-theft, attackers could enable 2FA bypass in supply chains.
- **Hypothesis**: "Compromised auth data is being used for unauthorized access."
- **Data Sources**: Failed 2FA logs, unusual logons (Event ID 4771 for Kerberos).
- **Step-by-Step**:
  1. Query Anomalous Auth: Splunk: `index=iam sourcetype=securid | search Status="bypass" OR TokenSerial IN (compromised_list) | stats count by user`.
  2. Sigma Rule:
     ```
     title: 2FA Bypass Attempts
     logsource:
       category: authentication
     detection:
       selection:
         Event: 'token_reuse' OR 'seed_compromise'
       condition: selection
     ```
  3. Correlate with defense contractor logons.
  4. Pivoting: Rotate seeds if hits.
- **Expert Tip**: Risk-based 2FA. Realistic: Impact was downstream; monitor token reuse.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate hosts), eradicate (RAT removal via EDR), recover (seed rotation, token reissuance). Notify customers per RSA's playbook.
- **Lessons**: Per Mandiant 2011, enhance phishing sims, patch zero-days. Iterate hunts bi-weekly; simulate with Atomic Red Team (T1566.001).
- **Expert Tip**: Use ATT&CK Navigator to coverage-gap your defenses. For modern variants (e.g., SolarWinds), add supply-chain hunts.

This exhaustive guide equips you to detect RSA-like APTs. Practice in labs; refine with your SOC's data. If evolving to 2025 threats (e.g., AI-phishing), incorporate ML anomaly models.
