### Teaching Threat Hunting for Marriott Data Breach-Like Attacks (2018): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in long-dwell credential compromise and database-focused APTs, I'll guide you through proactive threat hunting to detect attacks resembling the 2018 Marriott International data breach (affecting its Starwood acquisition). This was a sophisticated operation (suspected Chinese state-sponsored actors, per U.S. intelligence and Mandiant analysis), where attackers compromised a Starwood reservation database starting in July 2014 (discovered September 2018). Using stolen admin credentials (likely via phishing or malware), they accessed an unencrypted database, enumerated schemas, and exfiltrated PII from ~500 million guests (names, addresses, emails, phone numbers, passport numbers, encrypted payment card details, and travel history). The breach persisted for ~4 years, undetected due to no MFA on admin accounts, poor database auditing, and inadequate segmentation between legacy Starwood systems and Marriott's network. Detection: An internal security tool flagged suspicious access in September 2018; full forensic review revealed the 2014 origin. Impacts: £18.4M ICO fine (2020, reduced from £99M under GDPR), $52M U.S. class-action settlement (2019), CEO testimony to Congress, and enhanced PCI-DSS compliance for Marriott. From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts T1078.002), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001 via weak auth), TA0007 (Discovery: Account Discovery T1087 and Database Services T1525), TA0006 (Credential Access: Unsecured Credentials T1552.001), TA0009 (Collection: Data from Information Repositories T1213), and TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002).

Threat hunting assumes compromise: Hypothesis-driven searches for credential abuse leading to DB theft in hospitality/finance. Realistic parameters:
- **Environment**: Legacy databases (e.g., SQL Server connected to web apps), AD-integrated admins; high-volume PII.
- **Adversary Profile**: State-sponsored (low-and-slow with stolen creds; espionage/fraud goals).
- **Challenges**: Long-dwell in legacy systems, unencrypted PII, no real-time auditing.
- **Tools/Data Sources**: EDR (Defender for endpoints), SIEM (Splunk for DB/auth logs), DB auditors (SQL Profiler), YARA/Sigma for IOCs (e.g., anomalous admin queries).
- **Hypotheses**: E.g., "An adversary has abused admin creds to enumerate and dump DB schemas."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Mandiant's post-breach analysis and ICO report). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., DB labs) to avoid PCI/GDPR issues. Baselines: 60-90 days of DB/auth logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—Starwood's legacy DB enabled undetected access; prioritize admin auditing.
- **Gather Threat Intel**: Review MITRE ATT&CK for T1078 (e.g., admin abuse). IOCs: Anomalous DB queries (e.g., SELECT * FROM guests), stolen admin patterns. Cross-ref Mandiant analysis (suspected China), ICO fine notice, Wikipedia timeline, and StrongDM case study.
- **Map Your Environment**: Inventory DB admins (SQL Server/AD), reservation schemas (guests table). Use BloodHound for admin paths to DB; SQL Profiler for query baselines.
- **Baseline Normal Behavior**: Log admin logons (internal only), DB queries (low-volume SELECTs). Tool: Sysmon (DB config for process/auth); enable SQL audit traces.
- **Expert Tip**: MFA for all DB admins. Hypothesis: "Attackers steal admin creds for long-dwell DB access; hunt anomalous logons leading to schema dumps."

#### Step 2: Hunt for Initial Access (TA0001) - Valid Accounts (T1078.002)
Compromised admin account via phishing/malware.
- **Hypothesis**: "An adversary has abused stolen admin credentials for DB entry."
- **Data Sources**: Auth logs (Event ID 4624), SQL login audits.
- **Step-by-Step Hunting**:
  1. Query Admin Logons: Splunk SPL: `index=auth EventID=4624 | search AccountName="db_admin*" LogonType=3 | stats count by src_ip, geo | where geo!="US" OR count > baseline`.
  2. Sigma Rule (YAML):
     ```
     title: Anomalous DB Admin Access
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'db_admin*'
         LogonType: 3
         SrcGeo: NOT 'corporate'
       condition: selection
     ```
     Deploy in SIEM; alert on external admin logons.
  3. Analyze: Cross-ref dark web dumps for Marriott admins; hunt brute-force (Event ID 4625).
  4. Pivoting: Trace to DB queries (SQL audit for SELECT on guests).
- **Expert Tip**: Rotate admin creds quarterly. Realistic: 2014 phishing; hunt non-interactive logons.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.002): Valid Accounts
Executed admin commands (e.g., SQL queries) post-access.
- **Hypothesis**: "Stolen creds enable DB command execution."
- **Data Sources**: SQL audit (query events), Sysmon ID 1 (sqlcmd.exe).
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=db Operation="Execute SQL" UserId="admin" | search query="*guests*" | table _time, ResultCount | where ResultCount > 1000`.
  2. Sigma Rule:
     ```
     title: Admin DB Execution
     logsource:
       category: database
     detection:
       selection:
         Operation: 'Execute'
         User: 'admin*'
         Query: '*SELECT * FROM guests*'
       condition: selection
     ```
  3. Forensics: SQL Profiler traces for unusual commands.
  4. Pivoting: Correlate with schema enum.
- **Expert Tip**: Query whitelisting. Realistic: Silent queries; hunt high-result.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Reused admin creds for ongoing access over years.
- **Hypothesis**: "Adversary persists via repeated admin use."
- **Data Sources**: Event ID 4624 (long sessions), SQL login frequency.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=auth AccountName="suspect_admin" | stats count by src_ip, _time | where count > 10/week`.
  2. Sigma Rule:
     ```
     title: Persistent Admin Reuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'db_admin*'
         Frequency: '>5/week'
       condition: selection
     ```
  3. Scan: O365/SQL risky sign-ins.
  4. Pivoting: To discovery.
- **Expert Tip**: Session limits. Realistic: 4-year dwell; hunt patterns.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Admin account already privileged; no further needed.
- **Hypothesis**: "Over-privileged admin enables full DB access."
- **Data Sources**: Event ID 4673 (priv lists), IAM audits.
- **Step-by-Step**:
  1. Query Privs: Splunk: `index=ad EventID=4673 | search PrivilegeList="*FullControl*" Account="admin" | table _time, host`.
  2. Sigma Rule:
     ```
     title: DB Admin Privilege Abuse
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Privileges: '*Full* OR *SeDebug*'
         Account: 'service_admin'
       condition: selection
     ```
  3. Audit: SQL roles (e.g., db_owner).
  4. Pivoting: To collection.
- **Expert Tip**: DB roles limit. Realistic: Broad access; hunt over-priv.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
No direct impairment; evasion via low-noise queries and legacy gaps.
- **Hypothesis**: "Access evades via stealthy DB actions."
- **Data Sources**: Audit gaps, unusual patterns.
- **Step-by-Step**:
  1. Query Gaps: Splunk: `index=db | stats dc(Operation) by session | where dc < baseline` (missing audits).
  2. Sigma Rule:
     ```
     title: DB Evasion Gaps
     logsource:
       category: database
     detection:
       selection:
         AuditGap: true
         OR LogLevel: 'low'
       condition: selection
     ```
  3. Analyze: Hunt suppressed alerts.
  4. Pivoting: To discovery.
- **Expert Tip**: Full DB auditing. Realistic: No tampering; hunt quiet.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552.001)
Accessed via weak/unprotected admin creds.
- **Hypothesis**: "Weak DB creds enable compromise."
- **Data Sources**: Failed logons (4771), config files.
- **Step-by-Step**:
  1. Query Access: Splunk: `index=auth EventID=4771 Account="db_admin" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: DB Cred Abuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4771
         Account: 'db_admin*'
       condition: selection
     ```
  3. Forensics: Scan configs for plain-text pwds.
  4. Pivoting: To discovery.
- **Expert Tip**: Encrypted creds. Realistic: Phishing; hunt stuffing.

#### Step 8: Hunt for Discovery (TA0007) - Database Services (T1525)
Enumerated DB schemas/tables (e.g., guests).
- **Hypothesis**: "Admin access discovers PII tables."
- **Data Sources**: SQL audit (information_schema), Event ID 4662.
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=db query="information_schema" OR "SHOW TABLES" | stats count by session`.
  2. Sigma Rule:
     ```
     title: DB Schema Discovery
     logsource:
       category: database
     detection:
       selection:
         query: '*information_schema* OR *DESCRIBE guests*'
       condition: selection
     ```
  3. Analyze: Table names like "reservations".
  4. Pivoting: To collection.
- **Expert Tip**: Schema restrictions. Realistic: Targeted; hunt schema.

#### Step 9: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Dumped 500M records to files.
- **Hypothesis**: "Bulk PII collected from reservation DB."
- **Data Sources**: SQL audit (SELECT *), temp files.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=db query="SELECT * FROM guests" rows > 1M | stats sum(rows) by session`.
  2. Sigma Rule:
     ```
     title: Mass PII Dump
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM *guests OR *reservations*'
         rows_returned: '>100K'
       condition: selection
     ```
  3. Volume: Temp .csv sizes.
  4. Pivoting: To exfil.
- **Expert Tip**: Row limits. Realistic: Legacy dump; hunt large SELECTs.

#### Step 10: Hunt for Command and Control (TA0011) - Minimal (Direct DB)
No C2; direct access.
- **Hypothesis**: "Persistent sessions for ongoing dumps."
- **Data Sources**: DB session logs.
- **Step-by-Step**:
  1. Query Sessions: Splunk: `index=db session_duration > 1h | stats avg(duration) by ip`.
  2. Sigma Rule:
     ```
     title: Long DB Sessions
     logsource:
       category: database
     detection:
       selection:
         session_time: '>3600s'
       condition: selection
     ```
  3. Geoloc: External IPs.
  4. Pivoting: To exfil.
- **Expert Tip**: Idle timeouts. Realistic: No malware; hunt durations.

#### Step 11: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated dumps via web/email.
- **Hypothesis**: "DB data exfil over network."
- **Data Sources**: Network (large POSTs), DB exports.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 100MB | stats sum(bytes) by src_ip`.
  2. Sigma Rule:
     ```
     title: PII Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_length: '>50MB'
       condition: selection
     ```
  3. PCAP: Payloads with PII.
  4. Pivoting: Dark web.
- **Expert Tip**: Egress filtering. Realistic: Chunked; hunt volumes.

#### Step 12: Hunt for Impact (TA0040) - No Destruction
Impact via fraud; no wipe.
- **Hypothesis**: "Theft enables identity fraud."
- **Data Sources**: Fraud logs, HIBP.
- **Step-by-Step**:
  1. Query Fraud: Splunk: `index=external event="PII_fraud" source="marriott" | stats count by type`.
  2. Sigma Rule:
     ```
     title: Post-Breach Fraud
     logsource:
       category: external
     detection:
       selection:
         event: 'passport_theft OR *fraud*'
       condition: selection
     ```
  3. Monitor: SSN spikes.
  4. Pivoting: Victim alerts.
- **Expert Tip**: PII alerts. Realistic: Ongoing; hunt patterns.

#### Step 13: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate DB), eradicate (cred reset, audit), recover (notify ICO, encrypt). Like Marriott, settle fines; implement GDPR.
- **Lessons**: Per ICO, MFA admins, audit DBs, disclose. Iterate monthly; simulate with DB dumps.
- **Expert Tip**: ATT&CK Navigator for hospitality; evolve for 2025 (e.g., AI query anomalies).
