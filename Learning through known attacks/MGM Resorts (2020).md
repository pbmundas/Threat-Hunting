### Teaching Threat Hunting for MGM Resorts Cyberattack-Like Attacks (2023): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in social engineering and ransomware operations targeting critical infrastructure like hospitality and gaming, I'll guide you through proactive threat hunting to detect attacks resembling the 2023 MGM Resorts International cyberattack. This incident was a ransomware operation attributed to the ALPHV/BlackCat ransomware group (also known as Scattered Spider, UNC3944, or Storm-0875, a loose collective of English-speaking cybercriminals with U.S./U.K. ties), who used advanced social engineering (vishing/phishing) to gain initial access. On September 10, 2023, attackers impersonated an employee via a 10-minute call to MGM's IT help desk, obtaining Okta and Azure credentials. They deployed ransomware, encrypting systems and disrupting operations for 10 days (September 11-21, 2023), affecting 29 properties worldwide. This caused slot machines to go offline, digital keys to fail, and reservation apps to crash, leading to manual processes (e.g., handwritten receipts) and $100M in lost revenue. Data from ~10.6 million guests (PII like names, contacts, loyalty info) was stolen and leaked on dark web forums after MGM refused ransom. The attack highlighted vishing risks, with Scattered Spider using LinkedIn for employee intel and AI for voice cloning.

Dwell time: ~1 day for detection (September 10 access to September 11 disruption), but preparation involved weeks (social engineering recon). Undetected initially due to no vishing training, weak help desk verification, and over-reliance on MFA bypass via social proof. Detection: MGM's security tools flagged encryption; Mandiant investigated, confirming ALPHV. Impacts: $100M revenue loss, £20M potential ICO fine (under investigation), class-action lawsuits, and industry-wide vishing alerts (e.g., CISA advisories). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts T1078.002 via social engineering), TA0002 (Execution: User Execution T1204.001 via ransomware), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.004 via MFA bypass), TA0006 (Credential Access: Steal Web Session Cookie T1539), TA0008 (Lateral Movement: Remote Services T1021.001), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0040 (Impact: Data Encrypted for Impact T1486).

Threat hunting assumes compromise: Hypothesis-driven searches for social engineering leading to ransomware in high-value sectors like gaming/hospitality. Realistic parameters:
- **Environment**: Hybrid cloud/on-prem (e.g., Okta/Azure for IAM, flat networks); help desk as weak link.
- **Adversary Profile**: Cybercriminals (vishing for creds, ransomware deployment; extortion via leaks).
- **Challenges**: Human-targeted attacks bypass tech, rapid encryption, leak sites for impact.
- **Tools/Data Sources**: EDR (CrowdStrike for behaviors), SIEM (Splunk for auth/help desk logs), vishing sim tools, YARA/Sigma for ALPHV IOCs (e.g., SHA256: ransomware binaries from leaks).
- **Hypotheses**: E.g., "Scattered Spider uses vishing to steal IAM creds; hunt anomalous help desk calls leading to encryption."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Mandiant's analysis, CISA alerts, and RiskIQ reports). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., help desk sims) to avoid operational risks. Baselines: 30-60 days of auth/call logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the attack—MGM's help desk vishing enabled rapid ransomware; prioritize social engineering monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for UNC3944 (e.g., T1078 for creds). IOCs: Vishing scripts (LinkedIn intel), ALPHV ransomware notes, Okta bypasses. Cross-ref Mandiant report, CISA alert, Vox analysis, and Netwrix timeline.
- **Map Your Environment**: Inventory help desk (e.g., ServiceNow), IAM (Okta/Azure), endpoints. Use BloodHound for cred paths; sim vishing with tools like GoPhish.
- **Baseline Normal Behavior**: Log help desk calls (verified only), IAM logons (MFA). Tool: Sysmon (auth config); enable Okta logs.
- **Expert Tip**: Vishing training. Hypothesis: "Scattered Spider vish for IAM creds; hunt anomalous help desk interactions leading to ransomware."

#### Step 2: Hunt for Initial Access (TA0001) - Valid Accounts (T1078.002 via Social Engineering)
Vishing to help desk for Okta/Azure creds.
- **Hypothesis**: "An adversary uses social engineering to obtain initial creds."
- **Data Sources**: Help desk logs (tickets/calls), auth failures (Event ID 4771).
- **Step-by-Step Hunting**:
  1. Query Vishing: Splunk SPL: `index=helpdesk ticket_type="password_reset" user_agent="phone" | search description="*impersonation*" | stats count by agent, caller_ip`.
  2. Sigma Rule (YAML):
     ```
     title: Vishing Help Desk Abuse
     logsource:
       category: application
     detection:
       selection:
         ticket: '*password help* OR *locked out*'
         caller: external OR unknown
       condition: selection
     ```
     Deploy in SIEM; alert on unverified calls.
  3. Analyze: Hunt LinkedIn-sourced employee details in tickets; cross-ref with sudden MFA bypasses.
  4. Pivoting: Trace to IAM logons (Okta events).
- **Expert Tip**: Call verification protocols. Realistic: 10-min call; hunt urgent resets.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.001): Command and Scripting Interpreter
Deployed ransomware via PowerShell post-cred theft.
- **Hypothesis**: "Stolen creds execute ransomware scripts."
- **Data Sources**: Sysmon ID 1 (powershell.exe), Event ID 4688.
- **Step-by-step**:
  1. Query Scripts: Splunk: `index=endpoint EventID=1 | search Image="*powershell.exe*" CommandLine="*ransomware*" | table _time, host, ParentImage`.
  2. Sigma Rule:
     ```
     title: Ransomware Script Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*powershell.exe*'
         CommandLine: '*Invoke-WebRequest* OR *download*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw pslist | grep powershell` (injected scripts).
  4. Pivoting: To encryption.
- **Expert Tip**: Constrained PowerShell. Realistic: ALPHV scripts; hunt downloads.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Reused stolen IAM creds for dwell.
- **Hypothesis**: "Creds persist for ransomware deployment."
- **Data Sources**: Event ID 4624 (repeated logons), Okta sessions.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=okta EventID=4624 | search AccountName="helpdesk_granted" | stats count by src_ip, _time | where count > 5/hour`.
  2. Sigma Rule:
     ```
     title: IAM Cred Persistence
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'okta*'
         Frequency: '>3/hour'
       condition: selection
     ```
  3. Scan: Long sessions in Okta.
  4. Pivoting: To escalation.
- **Expert Tip**: Session revocation. Realistic: Post-vish reuse; hunt frequencies.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Escalated via Okta/Azure over-priv roles.
- **Hypothesis**: "Help desk creds escalate to admin."
- **Data Sources**: Event ID 4673, Okta role assumptions.
- **Step-by-Step**:
  1. Query Escalations: Splunk: `index=okta EventID=4673 | search PrivilegeList="*Admin*" Account="user" | table _time, host`.
  2. Sigma Rule:
     ```
     title: IAM Escalation
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Privileges: '*Admin*'
         Account: 'helpdesk*'
       condition: selection
     ```
  3. Analyze: Role chaining in Azure.
  4. Pivoting: To discovery.
- **Expert Tip**: Least-priv roles. Realistic: Okta bypass; hunt grants.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.004: Hide Artifacts)
Bypassed MFA via social engineering; hid ransomware.
- **Hypothesis**: "Vish evades MFA; ransomware hides."
- **Data Sources**: Event ID 1102 (no clears), Sysmon ID 1 (hidden processes).
- **Step-by-Step**:
  1. Query Bypasses: Splunk: `index=okta mfa_bypass=true | search method="social_engineering" | stats count by user`.
  2. Sigma Rule:
     ```
     title: MFA Bypass Evasion
     logsource:
       category: authentication
     detection:
       selection:
         Event: 'mfa_bypass'
         Method: 'vish OR social*'
       condition: selection
     ```
  3. Analyze: Hunt hidden ransomware (e.g., process hollowing).
  4. Pivoting: To collection.
- **Expert Tip**: Vishing sims. Realistic: Human bypass; hunt exceptions.

#### Step 7: Hunt for Credential Access (TA0006) - Steal Web Session Cookie (T1539)
Stole Okta/Azure session tokens via vish.
- **Hypothesis**: "Social engineering steals session creds."
- **Data Sources**: Okta logs (token theft), Event ID 4778.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=okta EventID=4778 | search TokenType="session" | stats count by ip`.
  2. Sigma Rule:
     ```
     title: Session Token Theft
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4778
         Token: 'session*'
       condition: selection
     ```
  3. Forensics: Hunt reused tokens.
  4. Pivoting: To discovery.
- **Expert Tip**: Token binding. Realistic: Vish harvest; hunt anomalies.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087)
Enumerated systems post-access (e.g., net view).
- **Hypothesis**: "Creds used to discover assets."
- **Data Sources**: Event ID 4662, Sysmon ID 3 (LDAP).
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=ad EventID=4662 ObjectClass="user" | stats values(ObjectName) by host`.
  2. Sigma Rule:
     ```
     title: Asset Discovery
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4662
         ObjectType: 'user OR computer'
       condition: selection
     ```
  3. Analyze: net.exe spikes.
  4. Pivoting: To collection.
- **Expert Tip**: Query limits. Realistic: Pre-ransom recon; hunt LDAP.

#### Step 9: Hunt for Lateral Movement (TA0008) - Remote Services (T1021.001)
Moved via RDP/Okta to endpoints.
- **Hypothesis**: "Stolen creds pivot to encrypt systems."
- **Data Sources**: Event ID 5145, Sysmon ID 3 (3389).
- **Step-by-Step**:
  1. Query RDP: Splunk: `index=network protocol=rdp dest_port=3389 user="stolen" | stats count by src, dest`.
  2. Sigma Rule:
     ```
     title: Lateral RDP
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 3389
         User: 'okta*'
       condition: selection
     ```
  3. Traffic: Anomalous RDP.
  4. Pivoting: To encryption.
- **Expert Tip**: RDP monitoring. Realistic: To slots; hunt chains.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected guest PII before encryption.
- **Hypothesis**: "Ransomware stages data for leak."
- **Data Sources**: Sysmon ID 11 (copies), DB exports.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FileName="guest_data*" Size > 10MB | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: PII Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.csv OR *.sql' Size: '>5MB'
       condition: selection
     ```
  3. Volume: High PII copies.
  4. Pivoting: To exfil.
- **Expert Tip**: DLP on PII. Realistic: 10.6M leaked; hunt exports.

#### Step 11: Hunt for Command and Control (TA0011) - Application Layer Protocol (T1071)
Ransomware C2 for encryption commands.
- **Hypothesis**: "Backdoor C2 for ransomware."
- **Data Sources**: Sysmon ID 3 (HTTP), Zeek.
- **Step-by-Step**:
  1. Query C2: Splunk: `index=network dest_domain="alphv_c2" | stats dc(dest) by src_ip`.
  2. Sigma Rule:
     ```
     title: Ransomware C2
     logsource:
       category: network_connection
     detection:
       selection:
         Domain: '*alphv* OR *blackcat*'
       condition: selection
     ```
  3. Traffic: Beacon to leak sites.
  4. Pivoting: To impact.
- **Expert Tip**: C2 blocks. Realistic: ALPHV; hunt domains.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated PII to dark web before encryption.
- **Hypothesis**: "Staged data exfil for double-extortion."
- **Data Sources**: Network (POSTs), leak forums.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 50MB dest="darkweb" | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: PII Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         length: '>10MB'
       condition: selection
     ```
  3. PCAP: PII payloads.
  4. Pivoting: To leaks.
- **Expert Tip**: Egress DLP. Realistic: Leaked post-refusal; hunt large.

#### Step 13: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486)
Encrypted systems, disrupting ops.
- **Hypothesis**: "Ransomware encrypts for downtime."
- **Data Sources**: EDR (encryption), OT logs.
- **Step-by-Step**:
  1. Query Encryption: Splunk: `index=ot Event="file_encrypted" | stats count by device`.
  2. Sigma Rule:
     ```
     title: Ransomware Impact
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.encrypted*'
       condition: selection
     ```
  3. Physical: Slot outages.
  4. Pivoting: Revenue loss.
- **Expert Tip**: Immutable backups. Realistic: 10-day; hunt encrypts.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate IAM), eradicate (cred reset, ransomware removal), recover (manual ops, notify ICO). Like MGM, refuse ransom; engage Mandiant.
- **Lessons**: Per Mandiant, train vishing, verify help desk, monitor IAM. Iterate monthly; simulate with ALPHV in labs.
- **Expert Tip**: ATT&CK Navigator for hospitality; evolve for 2025 (e.g., AI vishing detection).
