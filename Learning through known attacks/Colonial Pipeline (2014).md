### Teaching Threat Hunting for Yahoo Breach-Like Attacks (2013-2014): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with extensive experience in large-scale state-sponsored intrusions and credential-focused APTs, I'll guide you through proactive threat hunting to detect attacks resembling the Yahoo data breaches of 2013 and 2014. These were two separate but massive incidents affecting Yahoo's user databases, making them the largest known breaches in history at the time. The 2013 breach (disclosed in December 2016, revised to all 3 billion accounts in October 2017) involved unauthorized access to Yahoo's servers, stealing names, email addresses, phone numbers, birthdates, hashed passwords (MD5 with bcrypt in some cases, but unsalted in others), and security questions (both encrypted and unencrypted). The 2014 breach (disclosed September 2016) impacted 500 million accounts with similar data, plus forged cookies for unauthorized access without passwords. Attackers used spear-phishing, SQL injection (SQLi), and exploited unpatched vulnerabilities to pivot to databases, staging and exfiltrating data over extended periods.

Attribution: The 2014 breach was conducted by Russian FSB officers (Dmitry Dokuchaev, Igor Sushchin) hiring Canadian-Russian hacker-for-hire Karim Baratov (indicted 2017, sentenced to 5 years) and Alexsey Belan (FBI Most Wanted, extradited 2021). Belan accessed accounts for espionage, voucher theft, and SEO manipulation from October 2014 to November 2016. The 2013 breach is attributed to a different unauthorized third party, possibly state-sponsored (Russian links suspected but unconfirmed). Dwell time: ~3 years undetected (2013 breach active until discovery in 2016), due to poor monitoring, underfunded security (e.g., CISO Alex Stamos denied resources), and no public disclosure until Verizon acquisition pressures. Impacts: $117.5M class-action settlement (2019), $35M SEC fine (2018) for non-disclosure, $350M Verizon acquisition discount, eroded trust, widespread credential stuffing (e.g., ATOs on linked services), and geopolitical fallout (e.g., U.S. indictments under CFAA/economic espionage laws).

From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Phishing T1566.001, Exploit Public-Facing Application T1190), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0007 (Discovery: Account Discovery T1087), TA0006 (Credential Access: OS Credential Dumping T1003), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), and TA0011 (Command and Control: Proxy T1090). Post-breach, Yahoo spent $70M on remediation; Verizon invested $306M (2019-2022).

Threat hunting assumes compromise: Hypothesis-driven searches for DB-targeted intrusions in web-scale services. Realistic parameters:
- **Environment**: Cloud/legacy hybrid (e.g., MySQL/Oracle DBs on Yahoo's infrastructure, web portals with auth endpoints); high-traffic masking anomalies.
- **Adversary Profile**: State-sponsored (patient, custom tools like SQLi kits; espionage/money motives, low noise via proxies).
- **Challenges**: Billions of records, weak hashing (MD5 unsalted, crackable offline), delayed disclosure, alert fatigue.
- **Tools/Data Sources**: SIEM (Splunk/ELK for DB/web logs), DB audits (MySQL general_log), EDR (CrowdStrike for endpoints), cloud trails (AWS/GCP), YARA/Sigma for IOCs (e.g., Belan's IPs, MD5 hashes), dark web monitoring (e.g., Recorded Future for dumps).
- **Hypotheses**: E.g., "An adversary has exploited web vulns to dump user DBs and forge auth cookies."

This guide covers **each relevant MITRE ATT&CK technique** (inferred from DOJ indictments, Yahoo disclosures, and Krebs/Mandiant reports). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., shadow DBs) to avoid prod disruption. Baselines: 60-90 days of auth/DB logs for anomaly detection.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Context is critical—Yahoos under-resourced security enabled long dwell; focus on DB monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for state-sponsored DB breaches (e.g., T1190 for SQLi). IOCs: Belan's tools (e.g., SQLMap variants, IPs like 91.219.236.170), forged cookie patterns (base64 MD5), dark web sales ("Peace" alias, $300K dumps). Cross-ref Wikipedia, DOJ indictment, Krebs/HIBP, and SEC report.
- **Map Your Environment**: Inventory auth DBs (e.g., users table with hashed pwds), web endpoints (login/SQLi-prone forms), access controls (e.g., dev/prod DB segregation). Use tools like AWS IAM Access Analyzer or SQL schema queries.
- **Baseline Normal Behavior**: Log DB queries (e.g., SELECT on users), cookie issuances, outbound volumes. Tool: Enable MySQL audit plugins; Sysmon for web server processes.
- **Expert Tip**: Audit unsalted MD5 (query: SELECT COUNT(*) FROM users WHERE hash LIKE '^[0-9a-f]{32}$'). Hypothesis: "State actors use SQLi/phishing for DB access; hunt anomalous queries and cookie forgeries."

#### Step 2: Hunt for Initial Access (TA0001) - Phishing: Spearphishing Link/Attachment (T1566.001), Exploit Public-Facing Application (T1190)
2014: Spear-phishing to steal creds; SQLi on web apps. 2013: Likely SQLi or unpatched server exploits.
- **Hypothesis**: "An adversary has phished for creds or injected SQL to access auth endpoints."
- **Data Sources**: Email logs (O365/Proofpoint), WAF/DB error logs (syntax errors), web access logs.
- **Step-by-Step Hunting**:
  1. Query Phishing/SQLi: Splunk SPL: `index=web sourcetype=access | regex _raw=".*(union|select|from|or 1=1).*users.*" OR index=email subject="*yahoo update*" | stats count by client_ip | where count > 5`.
  2. Sigma Rule (YAML):
     ```
     title: SQLi or Spear-Phishing for DB Access
     logsource:
       category: web
     detection:
       selection:
         request: '*union select * from users*' OR subject: '*account verification*'
         status_code: '200'  # Success
       condition: selection
     ```
     Deploy in SIEM; alert on targeted emails or UNION payloads.
  3. Analyze: Grep for injection errors ("SQL syntax"); check phished creds in failed logons (Event ID 4776).
  4. Pivoting: Trace IPs to Russia/Canada (Belov/Baratov geos); follow to DB sessions.
- **Expert Tip**: Parameterized queries/WAF rules. Realistic: 2013/14 SQLi evaded filters; hunt low-volume targeted phishing.

#### Step 3: Hunt for Execution (TA0002) - Command and Scripting Interpreter (T1059): SQL Commands
Executed SQL dumps (e.g., SELECT * FROM users); possible shell via RCE.
- **Hypothesis**: "Injected queries execute to extract user data."
- **Data Sources**: DB query logs (pg_stat_statements), slow query logs, Sysmon ID 1 (if endpoint pivot).
- **Step-by-Step**:
  1. Query DB Exec: Splunk: `index=db sourcetype=mysql | search query="*SELECT*email*password*" AND user!="app_svc" | stats values(query) by client_ip | where row_count > 1M`.
  2. Sigma Rule:
     ```
     title: Mass DB Query Execution
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM users password*'
         rows_returned: '>100K'
       condition: selection
     ```
  3. Analyze: Visualize query spikes outside peak hours; hunt for INTO OUTFILE.
  4. Pivoting: Correlate with web requests triggering dumps.
- **Expert Tip**: Query rate-limiting. Realistic: Single queries dumped billions; hunt high-row ops.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002), Account Manipulation (T1098)
Used stolen creds for ongoing access; forged cookies (2014) for passwordless entry; Belan created backdoors.
- **Hypothesis**: "Adversary persists via stolen creds or forged auth artifacts."
- **Data Sources**: Auth logs (Event ID 4624 for unusual logons), cookie audit trails.
- **Step-by-Step**:
  1. Query Anomalous Logons: Splunk: `index=auth EventID=4624 | search LogonType=3 AND AccountName IN (stolen_list) | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Forged Cookie Persistence
     logsource:
       category: web
     detection:
       selection:
         cookie: '*MD5* OR base64_encoded_session'
         user_agent: 'curl'  # Automated
       condition: selection
     ```
  3. Cookie Forensics: Decode samples for MD5 patterns; hunt session hijacks.
  4. Pivoting: Link to repeated DB accesses from same session.
- **Expert Tip**: Short-lived tokens/JWT. Realistic: Cookies enabled 2015-2016 access; hunt anomalous sessions.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078), Exploitation for Privilege Escalation (T1068)
Escalated via stolen admin creds or DB privilege grants (e.g., GRANT SELECT on users).
- **Hypothesis**: "Low-priv access escalated to full DB read."
- **Data Sources**: DB privilege logs (SHOW GRANTS audits), Event ID 4673.
- **Step-by-Step**:
  1. Query Priv Changes: Splunk: `index=db command="GRANT" OR "SET PASSWORD" | table _time, user, privileges`.
  2. Sigma Rule:
     ```
     title: DB Escalation
     logsource:
       category: database
     detection:
       selection:
         sql_command: 'GRANT SELECT ON users'
         from_user: 'phished_account'
       condition: selection
     ```
  3. Audit: Run SHOW GRANTS FOR 'suspect'@'%'; hunt unexpected ALL PRIVS.
  4. Pivoting: Follow to bulk queries.
- **Expert Tip**: Role-based DB access. Realistic: Dev creds over-priv'd; audit grants.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001), Obfuscated Files or Information (T1027)
Disabled logs; used proxies (2014); weak MD5 hashing evaded cracking defenses.
- **Hypothesis**: "Attackers tamper logs or use weak crypto for evasion."
- **Data Sources**: Event ID 1102 (log clear), hash patterns in DB.
- **Step-by-Step**:
  1. Query Tampering: Splunk: `index=security EventID=1102 OR 4719 | stats count by host`.
  2. Sigma Rule:
     ```
     title: Log Evasion Post-Access
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 1102
         Source: 'db_user'
       condition: selection
     ```
  3. Hash Audit: Query: SELECT password FROM users WHERE LENGTH(password)=32; crack with Hashcat (-m 0).
  4. Pivoting: Hunt proxy chains (e.g., TOR in logs).
- **Expert Tip**: Tamper-proof logs (e.g., blockchain append). Realistic: MD5 cracked 30-50%; baseline hash strength.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552), OS Credential Dumping (T1003)
Dumped hashed pwds/security questions; possible lsass dumps for pivots.
- **Hypothesis**: "Adversary accesses unsecured auth storage."
- **Data Sources**: DB logs for SELECT on passwords, Sysmon ID 10 (lsass).
- **Step-by-Step**:
  1. Query Access: Splunk: `index=db query="*password* OR *security_question*" | stats sum(rows) by session`.
  2. Sigma Rule:
     ```
     title: Auth DB Dump
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM users password*'
         rows: '>500M'
       condition: selection
     ```
  3. Forensics: Sample hashes for MD5; identify via hash-identifier.
  4. Pivoting: Check for cookie forges post-dump.
- **Expert Tip**: Encrypt at rest. Realistic: Questions aided cracking; hunt query volumes.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087), Permission Groups Discovery (T1069)
Enumerated schemas/users (e.g., SHOW TABLES; SELECT * FROM users LIMIT 1).
- **Hypothesis**: "Recon for auth tables and high-value accounts."
- **Data Sources**: DB logs for INFORMATION_SCHEMA, Event ID 4662.
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=db query="SHOW TABLES" OR "information_schema" | stats count by ip`.
  2. Sigma Rule:
     ```
     title: DB Recon
     logsource:
       category: database
     detection:
       selection:
         query: '*DESCRIBE users* OR *SELECT * FROM information_schema*'
       condition: selection
     ```
  3. Analyze: Grep for column enum (password fields).
  4. Pivoting: Follow to data dumps.
- **Expert Tip**: Restrict schema access. Realistic: SQLi started with recon.

#### Step 9: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Staged billions of records (e.g., CSV dumps in temp tables).
- **Hypothesis**: "Bulk collection from user DBs."
- **Data Sources**: Temp file creates, large SELECT INTO.
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=db "CREATE TEMP TABLE" OR "SELECT INTO OUTFILE" target=users | table query`.
  2. Sigma Rule:
     ```
     title: User Data Staging
     logsource:
       category: database
     detection:
       selection:
         sql_command: 'SELECT INTO *users*'
         rows: '>1B'
       condition: selection
     ```
  3. Volume: Monitor session row totals (>500M flags).
  4. Pivoting: Correlate with compression (gzip in logs).
- **Expert Tip**: Disable OUTFILE. Realistic: Staged for exfil; hunt exports.

#### Step 10: Hunt for Command and Control (TA0011) - Proxy (T1090), Application Layer Protocol (T1071)
Used proxies/VPNs (Belan); possible C2 for commands (2014).
- **Hypothesis**: "Access via proxies for ongoing control."
- **Data Sources**: Network logs (TOR/VPN), Sysmon ID 3 (high ports).
- **Step-by-Step**:
  1. Query Proxies: Splunk: `index=network src_ip IN (tor_list) dest_port=443 | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: Proxy C2 for DB Access
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: '443'
         ProxyChain: true
       condition: selection
     ```
  3. Traffic: Zeek for VPN anomalies.
  4. Pivoting: Geoloc to Russia.
- **Expert Tip**: Proxy logging. Realistic: Hid origins; hunt chain lengths.

#### Step 11: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated via HTTP POST or direct DB copies to attacker machines.
- **Hypothesis**: "DB dumps exfil over web."
- **Data Sources**: Egress logs, WAF for large POSTs.
- **Step-by-Step**:
  1. Query Outbound: Splunk: `index=network http_method=POST bytes_out > 1GB | stats sum(bytes) by dest_ip`.
  2. Sigma Rule:
     ```
     title: Massive DB Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_length: '>500MB'
         content_type: 'application/octet-stream'
       condition: selection
     ```
  3. PCAP: tshark -Y "http contains 'email:' OR 'password:'".
  4. Pivoting: Monitor dark web (e.g., $300K sales IOCs).
- **Expert Tip**: DLP on DB traffic. Realistic: Chunked over months; hunt volumes.

#### Step 12: Hunt for Impact (TA0040) - Account Access Removal (T1531, via ATOs), Data Destruction (Inferred from Cracking)
Enabled ATOs (e.g., Gmail breaches); no destruction but downstream fraud.
- **Hypothesis**: "Stolen data used for unauthorized access."
- **Data Sources**: Auth failures, HIBP alerts.
- **Step-by-Step**:
  1. Query ATOs: Splunk: `index=auth failed_login > 10 user IN (yahoo_breached) | stats count by ip`.
  2. Sigma Rule:
     ```
     title: Post-Breach Stuffing
     logsource:
       category: authentication
     detection:
       selection:
         event: 'failed login'
         source: 'darkweb_proxy'
       condition: selection
     ```
  3. Monitor: HIBP for domain dumps.
  4. Pivoting: Rotate creds if hits.
- **Expert Tip**: MFA enforcement. Realistic: Espionage/ATOs; hunt reuse.

#### Step 13: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate DBs), eradicate (cred rotation, patch SQLi), recover (notify per GDPR, hash migration). Like Yahoo, conduct internal audits (e.g., Mayer's bonus forfeiture).
- **Lessons**: Fund security (Yahoo under-spent 2013-2016); disclose promptly (SEC fine). Iterate monthly; simulate with SQLMap/Atomic Red Team (T1190, T1566).
- **Expert Tip**: ATT&CK Navigator for DB coverage; evolve for 2025 (e.g., quantum-resistant hashing).
