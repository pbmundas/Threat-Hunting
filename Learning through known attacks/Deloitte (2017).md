### Teaching Threat Hunting for Deloitte Breach-Like Attacks (2017): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in professional services and cloud-adjacent compromises, I'll guide you through proactive threat hunting to detect attacks resembling the 2017 Deloitte data breach. This incident involved unauthorized access to Deloitte's global email platform, likely by nation-state or advanced cybercriminals (attribution unclear, but suspected state-sponsored due to targeted client data). Attackers compromised an admin account without multi-factor authentication (MFA), accessing the entire email database for months (discovered March 2017, but access possibly from late 2016). Stolen data included confidential emails, usernames, passwords, IP addresses, business plans, architectural diagrams, health information, intellectual property, product specifications, manufacturing techniques, and PII from up to 350 clients (e.g., FIFA, global banks, airlines, car manufacturers, energy firms, pharma, and U.S. government entities). The breach affected all company email and admin accounts, but Deloitte downplayed it as impacting "very few" clients. No malware details publicized; focus was on credential compromise and data exfiltration.

Dwell time: ~6-9 months (late 2016 to March 2017 detection via internal review), undetected due to no MFA on admin accounts, poor logging, and delayed investigation. Detection: Internal audit in March 2017; disclosed September 2017 after Guardian reporting. Impacts: Embarrassment for Deloitte (world's top cybersecurity consultant), FTC/SEC scrutiny (part of broader non-disclosure issues), client notifications (only 6 admitted, but sources claim 350), and enhanced email security mandates. From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001 via weak auth), TA0007 (Discovery: Account Discovery T1087), TA0006 (Credential Access: Unsecured Credentials T1552.001), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0003 (Persistence: Valid Accounts T1078).

Threat hunting assumes compromise: Hypothesis-driven searches for admin credential abuse in email systems for professional services firms. Realistic parameters:
- **Environment**: Enterprise email platforms (e.g., Exchange/Office 365), AD-integrated admin accounts; high-value client data in emails.
- **Adversary Profile**: Advanced (credential stuffing or phishing for admins; targeted exfil of client intel, low noise).
- **Challenges**: Email volume masks anomalies, no MFA on legacy admins, delayed disclosure risks.
- **Tools/Data Sources**: EDR (Microsoft Defender for email), SIEM (Splunk for auth/email logs), email security (Proofpoint), YARA/Sigma for IOCs (e.g., anomalous admin logons).
- **Hypotheses**: E.g., "An adversary has compromised admin creds to access client emails."

This guide covers **each relevant MITRE ATT&CK technique** (inferred from Guardian reporting, Krebs analysis, and Deloitte statements). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., email labs) to avoid compliance issues (e.g., GDPR). Baselines: 60-90 days of email/auth logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—Deloitte's weak admin auth enabled email access; prioritize MFA and logging.
- **Gather Threat Intel**: Review MITRE ATT&CK for credential abuse (e.g., T1078 for admins). IOCs: Anomalous admin logons (e.g., non-U.S. IPs), client email patterns (e.g., FIFA/banks). Cross-ref Guardian reporting, Krebs analysis, BBC coverage, and Deloitte factsheet.
- **Map Your Environment**: Inventory email admins (Exchange/AD), client inboxes (shared folders). Use BloodHound for paths from admins to client data; Microsoft Purview for email auditing.
- **Baseline Normal Behavior**: Log admin logons (Event ID 4624, internal only), email searches (low-volume on client folders). Tool: Sysmon (email config for process/auth); enable O365 Audit Logs.
- **Expert Tip**: Audit admin accounts quarterly. Hypothesis: "Attackers target weak admin creds for email access; hunt anomalous logons leading to client data exfil."

#### Step 2: Hunt for Initial Access (TA0001) - Valid Accounts (T1078.002)
Compromised admin account without MFA.
- **Hypothesis**: "An adversary has abused weak admin credentials for email access."
- **Data Sources**: Auth logs (Event ID 4624/4771), O365 sign-ins (failed successes).
- **Step-by-Step Hunting**:
  1. Query Admin Logons: Splunk SPL: `index=auth EventID=4624 | search AccountName="admin*" LogonType=3 | stats count by src_ip, geo | where geo!="US" OR count > baseline`.
  2. Sigma Rule (YAML):
     ```
     title: Anomalous Admin Access
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'admin* OR *service'
         LogonType: 3
         SrcGeo: NOT 'corporate'
       condition: selection
     ```
     Deploy in SIEM; alert on external admin logons.
  3. Analyze: Cross-ref with dark web dumps (e.g., Have I Been Pwned for Deloitte admins); hunt brute-force (Event ID 4625).
  4. Pivoting: Trace to email queries (e.g., O365 Search-UnifiedAuditLog).
- **Expert Tip**: Enforce MFA on all admins. Realistic: No 2FA; hunt non-interactive logons.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.002): Valid Accounts
Executed admin actions (e.g., email searches/downloads).
- **Hypothesis**: "Stolen creds enable execution of data access commands."
- **Data Sources**: O365 Audit (Search-AdminMailbox), Sysmon ID 1 (powershell for queries).
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=o365 Workload="Exchange" Operation="Search-Mailbox" UserId="admin" | table _time, ResultCount | where ResultCount > 1000`.
  2. Sigma Rule:
     ```
     title: Admin Email Execution
     logsource:
       category: cloud_api
     detection:
       selection:
         Operation: 'Search-Mailbox OR Export-Mailbox'
         User: 'admin*'
         ItemsReturned: '>500'
       condition: selection
     ```
  3. Forensics: Purview eDiscovery for unusual searches (e.g., client keywords like "FIFA").
  4. Pivoting: Correlate with data exports.
- **Expert Tip**: Log all admin queries. Realistic: Silent searches; hunt high-volume.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078)
Reused admin creds for ongoing access.
- **Hypothesis**: "Adversary maintains access via persistent admin use."
- **Data Sources**: Event ID 4624 (repeated logons), O365 sign-in risks.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=auth AccountName="suspect_admin" | stats count by src_ip, _time | where count > 10/day`.
  2. Sigma Rule:
     ```
     title: Persistent Admin Reuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'admin*'
         Frequency: '>5/hour'
       condition: selection
     ```
  3. Scan: O365 risky sign-ins (e.g., impossible travel).
  4. Pivoting: To discovery.
- **Expert Tip**: Session timeouts. Realistic: Months of access; hunt patterns.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Admin account already privileged; no further escalation needed.
- **Hypothesis**: "Over-privileged admin enables broad access."
- **Data Sources**: Event ID 4673 (priv assignments), IAM audits.
- **Step-by-Step**:
  1. Query Privs: Splunk: `index=ad EventID=4673 | search PrivilegeList="*FullControl*" Account="admin" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Admin Privilege Abuse
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Privileges: '*SeDebug* OR *Full*'
         Account: 'service_admin'
       condition: selection
     ```
  3. Audit: AD group membership for admins.
  4. Pivoting: To email collection.
- **Expert Tip**: Role-based access. Realistic: Single admin key; hunt over-priv.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
No direct impairment; evasion via low-noise access and delayed disclosure.
- **Hypothesis**: "Access evades via stealthy admin actions."
- **Data Sources**: Event ID 1102 (no clears, but gaps), unusual patterns.
- **Step-by-Step**:
  1. Query Gaps: Splunk: `index=auth | stats dc(EventID) by host | where dc < baseline` (missing logs).
  2. Sigma Rule:
     ```
     title: Stealthy Admin Evasion
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 1102  # Log clear
         OR LogGaps: true
       condition: selection
     ```
  3. Analyze: Hunt for suppressed alerts (e.g., O365 risk ignored).
  4. Pivoting: To collection.
- **Expert Tip**: Anomaly baselines. Realistic: No tampering; hunt quiet access.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552.001)
Accessed via weak/unprotected admin creds.
- **Hypothesis**: "Weak admin creds enable email compromise."
- **Data Sources**: Failed logons (4771), dark web scans.
- **Step-by-Step**:
  1. Query Access: Splunk: `index=auth EventID=4771 Account="admin" | stats count by src_ip | where count > 5`.
  2. Sigma Rule:
     ```
     title: Admin Cred Abuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4771
         Account: 'admin*'
         Status: 'failure' then 'success'
       condition: selection
     ```
  3. Forensics: Check for cred dumps (e.g., lsass if escalated).
  4. Pivoting: To discovery.
- **Expert Tip**: Passwordless auth. Realistic: No MFA; hunt stuffing.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087)
Enumerated client emails/accounts in system.
- **Hypothesis**: "Admin access used to discover client data."
- **Data Sources**: O365 Audit (Get-Mailbox), Event ID 4662.
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=o365 Operation="Get-Mailbox" UserId="admin" | stats dc(Mailbox) by _time | where dc > 100`.
  2. Sigma Rule:
     ```
     title: Email Account Discovery
     logsource:
       category: cloud_api
     detection:
       selection:
         Operation: 'Get-Mailbox OR Search*'
         User: 'admin*'
         Items: '>50'
       condition: selection
     ```
  3. Analyze: Keyword searches (e.g., "FIFA").
  4. Pivoting: To collection.
- **Expert Tip**: Query limits. Realistic: Broad searches; hunt volume.

#### Step 9: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected emails/PII from client inboxes.
- **Hypothesis**: "Client data aggregated from emails."
- **Data Sources**: O365 Export-Mailbox, Sysmon ID 11 (PST exports).
- **Step-by-Step**:
  1. Query Collection: Splunk: `index=o365 Operation="Export-Mailbox" MailboxOwner="client*" | stats sum(Items) by UserId`.
  2. Sigma Rule:
     ```
     title: Email Data Collection
     logsource:
       category: cloud_api
     detection:
       selection:
         Operation: 'Export* OR Copy-Mailbox'
         ItemsExported: '>1000'
       condition: selection
     ```
  3. Forensics: PST file sizes.
  4. Pivoting: To exfil.
- **Expert Tip**: Retention policies. Realistic: Confidential emails; hunt exports.

#### Step 10: Hunt for Command and Control (TA0011) - Minimal (Direct Access)
No C2; direct email platform use.
- **Hypothesis**: "Access via direct API without beacons."
- **Data Sources**: O365 sign-ins, network (no outbound).
- **Step-by-Step**:
  1. Query Direct: Splunk: `index=o365 UserId="admin" Location="external" | stats count by IP`.
  2. Sigma Rule:
     ```
     title: Direct Email Access
     logsource:
       category: authentication
     detection:
       selection:
         Location: external
         User: 'admin*'
       condition: selection
     ```
  3. Geoloc: Non-corporate IPs.
  4. Pivoting: To exfil.
- **Expert Tip**: Conditional access. Realistic: No malware; hunt sessions.

#### Step 11: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated emails via O365 exports or downloads.
- **Hypothesis**: "Client data exfil via email APIs."
- **Data Sources**: O365 Audit (Export to PST), network egress.
- **Step-by-Step**:
  1. Query Exfil: Splunk: `index=o365 Operation="Export-Mailbox" bytes_out > 1GB | stats sum(bytes) by Mailbox`.
  2. Sigma Rule:
     ```
     title: Email Exfil
     logsource:
       category: cloud_api
     detection:
       selection:
         Operation: 'Export*'
         bytes: '>500MB'
       condition: selection
     ```
  3. PCAP: If VPN, hunt large transfers.
  4. Pivoting: Dark web client dumps.
- **Expert Tip**: Export limits. Realistic: Bulk; hunt volumes.

#### Step 12: Hunt for Impact (TA0040) - No Destruction
Impact via data theft; secondary risks (phishing from emails).
- **Hypothesis**: "Theft enables client targeting."
- **Data Sources**: Client notifications, leak monitoring.
- **Step-by-Step**:
  1. Query Impact: Splunk: `index=external_dump domain="deloitte.com" | search keyword="client_email"`.
  2. Sigma Rule:
     ```
     title: Post-Breach Client Risk
     logsource:
       category: external
     detection:
       selection:
         event: 'email_leak'
         source: 'darkweb'
       condition: selection
     ```
  3. Monitor: HIBP for client PII.
  4. Pivoting: Phishing spikes.
- **Expert Tip**: Client alerts. Realistic: Intel theft; hunt reuse.

#### Step 13: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate admins), eradicate (MFA rollout, log review), recover (notify clients, encrypt emails). Like Deloitte, inform regulators; avoid downplaying.
- **Lessons**: Per Guardian, enforce MFA, audit admins, disclose promptly. Iterate monthly; simulate with admin abuse tests.
- **Expert Tip**: ATT&CK Navigator for services; evolve for 2025 (e.g., AI email anomalies).
