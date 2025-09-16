### Teaching Threat Hunting for Dropbox Sign Breach-Like Attacks (2024): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in supply-chain credential compromises and SaaS platform breaches, I'll guide you through proactive threat hunting to detect attacks resembling the 2024 Dropbox Sign (formerly HelloSign) breach. This incident involved an unidentified threat actor compromising a service account in Dropbox Sign's production environment on April 19, 2024 (discovered April 24, 2024), accessing customer data for all users, including emails, usernames, phone numbers, hashed passwords, general account settings, and authentication information (API keys, OAuth tokens, MFA details). The breach affected Dropbox Sign's automated system configuration tool, enabling unauthorized database access. No evidence of account content (e.g., documents) being compromised, but API/OAuth theft posed risks for connected apps. Dropbox responded by rotating keys, notifying regulators (Irish DPC, SEC filing May 1, 2024), and restricting functionality. Attribution remains unclear, but it highlights supply-chain risks in SaaS (e.g., non-human identities like service accounts).

Dwell time: ~5 days (April 19-24, 2024), undetected due to weak service account security (no MFA/rotation), inadequate logging for config tools, and isolated environments. Detection: Internal monitoring flagged unusual activity; SEC Form 8-K disclosed it. Impacts: Potential cascading breaches via stolen tokens (e.g., connected SaaS like Google Workspace), regulatory scrutiny (GDPR/SEC), and eroded trust (second Dropbox incident in 2 years, following 2022 code theft). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts T1078.004 via service account compromise), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001 via weak auth), TA0006 (Credential Access: Unsecured Credentials T1552.005 for tokens), TA0007 (Discovery: Account Discovery T1087), TA0009 (Collection: Data from Information Repositories T1213), and TA0010 (Exfiltration: Exfiltration Over C2 Channel T1041, minimal).

Threat hunting assumes compromise: Hypothesis-driven searches for service account abuse in SaaS environments. Realistic parameters:
- **Environment**: SaaS platforms (e.g., Dropbox Sign with API integrations), non-human accounts (service keys).
- **Adversary Profile**: Advanced (credential stuffing or insider-like access; token theft for lateral in connected apps).
- **Challenges**: Non-human identities hard to monitor, token reuse, isolated prod envs.
- **Tools/Data Sources**: EDR (CrowdStrike for behaviors), SIEM (Splunk for API logs), IAM auditors (Okta/Dropbox API), YARA/Sigma for IOCs (e.g., anomalous token usage).
- **Hypotheses**: E.g., "An adversary compromises service accounts to access customer data; hunt anomalous API calls leading to token theft."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Dropbox's SEC filing, The Hacker News analysis, and Varonis report). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., API sandboxes) to avoid GDPR risks. Baselines: 60-90 days of API/auth logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—compromised service accounts enabled customer data access; prioritize non-human identity monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for T1078.004 (non-human accounts). IOCs: Anomalous service account logons (April 19-24, 2024), API key patterns (compromised tokens). Cross-ref Dropbox SEC filing, The Hacker News disclosure, Varonis analysis, and Malwarebytes report.
- **Map Your Environment**: Inventory service accounts (e.g., Dropbox Sign API keys), connected apps (OAuth scopes). Use IAM tools like Okta for non-human auditing; Splunk for API baselines.
- **Baseline Normal Behavior**: Log service logons (internal only), API calls (low-volume). Tool: Sysmon (API config for process/auth); enable Dropbox API auditing.
- **Expert Tip**: Rotate service keys quarterly. Hypothesis: "Threat actors target service accounts for data access; hunt anomalous logons leading to API abuse."

#### Step 2: Hunt for Initial Access (TA0001) - Valid Accounts (T1078.004 via Service Account)
Compromised service account in production environment.
- **Hypothesis**: "An adversary abuses non-human service accounts for entry."
- **Data Sources**: Auth logs (Event ID 4624 for service), API access logs.
- **Step-by-Step Hunting**:
  1. Query Service Logons: Splunk SPL: `index=auth EventID=4624 | search AccountName="service_account*" LogonType=5 | stats count by src_ip, geo | where geo!="internal" OR count > baseline`.
  2. Sigma Rule (YAML):
     ```
     title: Service Account Abuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'service* OR *api*'
         LogonType: 5
         SrcGeo: NOT 'corporate'
       condition: selection
     ```
     Deploy in SIEM; alert on external service logons.
  3. Analyze: Hunt credential stuffing (Event ID 4771 failures); cross-ref dark web for Dropbox service keys.
  4. Pivoting: Trace to database queries (e.g., customer SELECTs).
- **Expert Tip**: MFA for service accounts (via API keys). Realistic: April 19 access; hunt non-interactive.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.002 via API Calls)
Executed API commands to access production database.
- **Hypothesis**: "Stolen service creds execute data queries."
- **Data Sources**: API logs (Dropbox Sign calls), Sysmon ID 1 (curl/postman for API).
- **Step-by-Step**:
  1. Query API Executions: Splunk: `index=api sourcetype=dropbox | search Operation="customer_query" UserId="service" | table _time, ResultCount | where ResultCount > 1000`.
  2. Sigma Rule:
     ```
     title: Service API Execution
     logsource:
       category: cloud_api
     detection:
       selection:
         Operation: 'query_customer OR access_db'
         User: 'service*'
         ItemsReturned: '>500'
       condition: selection
     ```
  3. Forensics: API traces for unusual scopes (e.g., full DB read).
  4. Pivoting: To persistence.
- **Expert Tip**: API rate limiting. Realistic: DB access; hunt high-result calls.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Reused service account for ongoing access.
- **Hypothesis**: "Service account persists for data theft."
- **Data Sources**: Event ID 4624 (repeated calls), token sessions.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=api Account="service" | stats count by src_ip, _time | where count > 5/hour`.
  2. Sigma Rule:
     ```
     title: Service Account Persistence
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Account: 'service*'
         Frequency: '>3/hour'
       condition: selection
     ```
  3. Scan: Long-lived OAuth tokens.
  4. Pivoting: To evasion.
- **Expert Tip**: Token expiry. Realistic: 5-day dwell; hunt frequencies.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Service account had broad prod access; no further escalation.
- **Hypothesis**: "Over-privileged service enables DB read."
- **Data Sources**: Event ID 4673, IAM audits.
- **Step-by-Step**:
  1. Query Privs: Splunk: `index=iam EventID=4673 | search PrivilegeList="*FullAccess*" Account="service" | table _time, scope`.
  2. Sigma Rule:
     ```
     title: Service Privilege Abuse
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Privileges: '*Full* OR *DBRead*'
         Account: 'service*'
       condition: selection
     ```
  3. Audit: Scope for prod DB.
  4. Pivoting: To discovery.
- **Expert Tip**: Least-priv services. Realistic: Broad scope; hunt over-priv.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001)
No direct impairment; evasion via low-noise API and weak logging.
- **Hypothesis**: "Access evades via stealthy service actions."
- **Data Sources**: Audit gaps, anomalous patterns.
- **Step-by-Step**:
  1. Query Gaps: Splunk: `index=api | stats dc(Operation) by session | where dc < baseline`.
  2. Sigma Rule:
     ```
     title: Service Evasion Gaps
     logsource:
       category: cloud_api
     detection:
       selection:
         AuditGap: true
         OR LogLevel: 'low'
       condition: selection
     ```
  3. Analyze: Suppressed alerts.
  4. Pivoting: To discovery.
- **Expert Tip**: Full API auditing. Realistic: No tampering; hunt quiet.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552.005)
Stole API keys/OAuth tokens from service account.
- **Hypothesis**: "Service compromise steals auth tokens."
- **Data Sources**: Token events (Event ID 4778), API logs.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=api EventID=4778 | search TokenType="OAuth" | stats count by ip`.
  2. Sigma Rule:
     ```
     title: Token Theft
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4778
         Token: 'OAuth OR API*'
       condition: selection
     ```
  3. Forensics: Reused tokens in connected apps.
  4. Pivoting: To discovery.
- **Expert Tip**: Token scoping. Realistic: Token theft; hunt anomalies.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087)
Enumerated customer accounts in DB.
- **Hypothesis**: "Service access discovers user data."
- **Data Sources**: DB audit (SELECT users), Event ID 4662.
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=db query="SELECT * FROM users" | stats count by session`.
  2. Sigma Rule:
     ```
     title: Customer Discovery
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM *users*'
       condition: selection
     ```
  3. Analyze: All-user queries.
  4. Pivoting: To collection.
- **Expert Tip**: Row limits. Realistic: Full DB; hunt SELECTs.

#### Step 9: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected emails/usernames/hashes from customer DB.
- **Hypothesis**: "Service queries collect PII."
- **Data Sources**: DB audit (bulk SELECTs), temp files.
- **Step-by-Step**:
  1. Query Collection: Splunk: `index=db query="SELECT email FROM customers" rows > 1M | stats sum(rows)`.
  2. Sigma Rule:
     ```
     title: PII Collection
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM *customers*'
         rows: '>100K'
       condition: selection
     ```
  3. Volume: High exports.
  4. Pivoting: To exfil.
- **Expert Tip**: Query auditing. Realistic: All users; hunt bulk.

#### Step 10: Hunt for Command and Control (TA0011) - Minimal (Direct API)
No C2; direct API/DB access.
- **Hypothesis**: "Persistent API for ongoing theft."
- **Data Sources**: API session logs.
- **Step-by-Step**:
  1. Query Sessions: Splunk: `index=api session_duration > 1h | stats avg(duration) by ip`.
  2. Sigma Rule:
     ```
     title: Long API Sessions
     logsource:
       category: cloud_api
     detection:
       selection:
         session_time: '>3600s'
       condition: selection
     ```
  3. Geoloc: External.
  4. Pivoting: To exfil.
- **Expert Tip**: API timeouts. Realistic: No malware; hunt durations.

#### Step 11: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated data via API calls.
- **Hypothesis**: "Collected data exfil via API."
- **Data Sources**: API logs (large responses), network.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=api Operation="export" bytes_out > 10MB | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: Data Exfil
     logsource:
       category: cloud_api
     detection:
       selection:
         Operation: 'export*'
         bytes: '>5MB'
       condition: selection
     ```
  3. PCAP: PII payloads.
  4. Pivoting: Dark web.
- **Expert Tip**: API DLP. Realistic: All users; hunt volumes.

#### Step 12: Hunt for Impact (TA0040) - No Destruction
Impact via data theft; secondary risks (phishing from emails).
- **Hypothesis**: "Theft enables fraud/phishing."
- **Data Sources**: Fraud logs, HIBP.
- **Step-by-Step**:
  1. Query Fraud: Splunk: `index=external event="email_phish" source="dropbox_sign" | stats count by type`.
  2. Sigma Rule:
     ```
     title: Post-Breach Risk
     logsource:
       category: external
     detection:
       selection:
         event: 'data_theft'
       condition: selection
     ```
  3. Monitor: Token abuse.
  4. Pivoting: Alerts.
- **Expert Tip**: Token monitoring. Realistic: API risks; hunt connected.

#### Step 13: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (rotate keys, isolate services), eradicate (audit accounts, scan), recover (notify DPC, restrict APIs). Like Dropbox, rotate tokens; engage regulators.
- **Lessons**: Per SEC filing, secure service accounts, audit APIs, notify promptly. Iterate monthly; simulate with token theft.
- **Expert Tip**: ATT&CK for SaaS; evolve for 2025 (e.g., AI token anomalies).
