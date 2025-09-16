### Teaching Threat Hunting for LinkedIn Breach-Like Attacks (2012): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in cloud-scale enterprise breaches and credential-focused APTs, I'll guide you through proactive threat hunting to detect attacks resembling the 2012 LinkedIn breach. This incident involved Russian cybercriminal Yevgeniy Nikulin (born 1987, Moscow-based, convicted in 2021 and sentenced to 88 months in U.S. prison), who exploited poor password storage practices to steal unsalted SHA-1 hashed passwords and emails for ~167 million users (initially reported as 6.5M, expanded in 2016 to 117M+ with decrypted passwords). The breach occurred around March-May 2012, with public exposure on June 5, 2012, via a Russian forum post of 6.5M hashes. Likely via SQL injection or compromised internal access (e.g., a developer's credentials granting production DB access), attackers dumped the user database without salting, enabling rapid cracking (e.g., via rainbow tables; common passwords like "123456" comprised ~2.2M entries). Impacts: $66M+ in remediation for LinkedIn (now Microsoft-owned), widespread credential reuse leading to account takeovers (e.g., Biz Stone's Twitter via linked services), and secondary breaches (e.g., used creds hit Dropbox/Formspring). No evidence of advanced malware; it was opportunistic database compromise.

Dwell time: ~2-3 months (March-June 2012), undetected due to weak logging and no anomaly detection on DB queries. From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts or External Remote Services), TA0005 (Defense Evasion: Impair Defenses via weak hashing), TA0007 (Discovery: Account Discovery), TA0009 (Collection: Data from Information Repositories), TA0010 (Exfiltration: Exfiltration Over Web Service), and TA0040 (Impact: Data Destruction via forced resets). Post-breach, ~90% of hashes were cracked offline, highlighting credential stuffing risks.

Threat hunting assumes compromise: Hypothesis-driven searches for database tampering and credential leaks in large-scale web apps (e.g., social platforms, SaaS). Realistic parameters:
- **Environment**: Cloud/DB-heavy (e.g., MySQL/PostgreSQL on AWS/GCP), high-traffic web apps with user auth (e.g., unsalted/weak hashes), limited DB auditing.
- **Adversary Profile**: Cybercriminal (opportunistic, SQLi or insider access; low noise, focus on data monetization via dark web sales).
- **Challenges**: Massive scale (millions of users), weak hashing (SHA-1 unsalted), logs overwhelmed by legit traffic.
- **Tools/Data Sources**: SIEM (Splunk/ELK for DB queries), DB audit logs (e.g., MySQL general_log), EDR (CrowdStrike for endpoint if hybrid), cloud trails (AWS CloudTrail), credential scanners (Have I Been Pwned API), YARA/Sigma for IOCs (e.g., Nikulin's forum posts).
- **Hypotheses**: E.g., "An adversary has exploited a web vuln for DB access and is dumping user creds."

This guide covers **each relevant MITRE ATT&CK technique** (inferred from reports: SQLi for access, weak storage evasion, DB discovery/collection). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., test DBs) to avoid prod disruption. Baselines: 30-90 days of DB query logs for anomaly baselines.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Understand the breach vector—LinkedIn's unsalted SHA-1 enabled offline cracking post-dump.
- **Gather Threat Intel**: Review MITRE ATT&CK for credential access (T1552: Unsecured Credentials). IOCs: SHA-1 hashes (e.g., patterns like 5e884898da28047151d0e56f8dc6292773603d0d for "password"), dark web sales (e.g., "Peace" alias on The Real Deal forum, 2016 dump). Cross-ref Wikipedia, Krebs on Security, HIBP, and Nikulin's conviction (FBI-assisted probe).
- **Map Your Environment**: Inventory DBs (e.g., user tables with auth fields), web apps (e.g., login endpoints), access controls (e.g., dev/prod segregation). Use tools like AWS IAM analyzer or SQL queries for schema mapping.
- **Baseline Normal Behavior**: Log DB queries (e.g., SELECT * FROM users), hash patterns, outbound data volumes. Tool: Enable MySQL/PostgreSQL audit plugins; Sysmon for any endpoint ties.
- **Expert Tip**: Scan for unsalted SHA-1 in prod (query: SELECT COUNT(*) FROM users WHERE password LIKE '5e88%'). Hypothesis: "Attackers exploit web vulns for unauth DB access; hunt anomalous queries."

#### Step 2: Hunt for Initial Access (TA0001) - Exploit Public-Facing Application (T1190), Valid Accounts (T1078)
Likely SQL injection (SQLi) on a web form or compromised dev creds for DB access.
- **Hypothesis**: "An adversary has injected SQL via web inputs to query/dump user tables."
- **Data Sources**: Web app firewall (WAF) logs (e.g., ModSecurity), DB error logs (e.g., MySQL error_log for syntax errors), app server logs (e.g., Apache/Nginx access logs).
- **Step-by-Step Hunting**:
  1. Query Suspicious Web Requests: Splunk SPL: `index=web sourcetype=access_combined | regex _raw=".*(union|select|from|where).*users.*" | stats count by client_ip, uri_path | where count > 10`.
  2. Sigma Rule (YAML):
     ```
     title: SQL Injection Attempt
     logsource:
       category: web
     detection:
       selection:
         request: '*union select * from users*'
         status_code: '200'  # Successful injection
       condition: selection
     ```
     Deploy in SIEM; alert on UNION-based SQLi (common for dumps).
  3. Analyze DB Errors: Grep logs for "You have an error in your SQL syntax" or injection payloads (e.g., ' OR 1=1 --).
  4. Pivoting: If hits, trace client_ip to geoloc (Russia/Moscow for Nikulin-like); check for subsequent SELECT queries on auth tables.
- **Expert Tip**: Use OWASP ZAP for vuln scanning. Realistic: 2012 SQLi bypassed basic filters; modern hunts include parameterized query enforcement checks.

#### Step 3: Hunt for Execution (TA0002) - Command and Scripting Interpreter (T1059) if via RCE, but Primarily DB Query Execution
Execution via SQL commands to dump data (e.g., SELECT email, password_hash FROM members).
- **Hypothesis**: "Injected queries are executing to extract credential data."
- **Data Sources**: DB query logs (e.g., PostgreSQL pg_stat_statements), slow query logs.
- **Step-by-Step**:
  1. Query Anomalous DB Access: Splunk: `index=db sourcetype=mysql:query | search query="*SELECT*email*password*" AND user!="app_user" | stats values(query) by client_ip, _time | where query_count > 50`.
  2. Sigma Rule:
     ```
     title: Mass Credential Dump Query
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM users WHERE * password_hash*'
         rows_returned: '>1000'
       condition: selection
     ```
  3. Analyze Query Patterns: Use ELK to visualize query frequency; hunt for bulk SELECTs outside business hours.
  4. Pivoting: Correlate with web logs for the triggering request (e.g., login form SQLi).
- **Expert Tip**: Enable query whitelisting. Realistic: LinkedIn dump was a single large query; hunt for high-row-count ops.

#### Step 4: Hunt for Persistence (TA0003) - Limited in This Breach (Opportunistic, No Backdoor)
No known persistence; attackers dumped and exfiltrated quickly. But hunt for potential account creation or modified triggers.
- **Hypothesis**: "Post-access, adversary creates backdoor accounts or alters DB triggers for re-entry."
- **Data Sources**: DB audit for INSERT/UPDATE on users table, Event ID 4720 (if AD-integrated).
- **Step-by-Step**:
  1. Query New/Modified Accounts: Splunk: `index=db | search action=INSERT OR UPDATE table=users | stats count by user, timestamp | where count > baseline`.
  2. Sigma Rule:
     ```
     title: Unauthorized DB Account Creation
     logsource:
       category: database
     detection:
       selection:
         sql_command: 'INSERT INTO users'
         user: NOT IN ('legit_admins')
       condition: selection
     ```
  3. Schema Check: Query for rogue triggers (e.g., SELECT * FROM information_schema.triggers WHERE trigger_name LIKE '%backdoor%').
  4. Pivoting: If found, review commit timestamps for anomalies.
- **Expert Tip**: Immutable DB snapshots. Realistic: No persistence needed for data theft; focus on access logs.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Exploitation for Privilege Escalation (T1068) if via Vuln
If initial access was low-priv dev account, escalation to DB admin via SQL privileges.
- **Hypothesis**: "Low-priv access escalated to full DB read via privilege grants."
- **Data Sources**: DB privilege logs (e.g., MySQL SHOW GRANTS history via audit).
- **Step-by-Step**:
  1. Query Privilege Changes: Splunk: `index=db | search command="GRANT" OR "SET PASSWORD" | table _time, user, privileges_granted`.
  2. Sigma Rule:
     ```
     title: DB Privilege Escalation
     logsource:
       category: database
     detection:
         sql_command: 'GRANT ALL ON *.*'
         from_user: 'dev_account'
       condition: selection
     ```
  3. Audit Current Privs: Run SHOW GRANTS FOR 'suspect_user'@'%'; hunt for unexpected ALL PRIVILEGES.
  4. Pivoting: Link to initial access IP.
- **Expert Tip**: Principle of least privilege on DB users. Realistic: Dev creds often over-priv'd in 2012; hunt role anomalies.

#### Step 6: Hunt for Defense Evasion (TA0005) - Weak Hashing/Storage (T1552.001: Credentials in Files, but DB-Specific)
Un salted SHA-1 evaded no real "defense" but enabled cracking; hunt for insecure storage.
- **Hypothesis**: "Stored creds use weak hashing, vulnerable to offline attacks."
- **Data Sources**: DB schema inspection, sample hash analysis.
- **Step-by-Step**:
  1. Query Hash Patterns: Splunk/DB: `SELECT password FROM users LIMIT 1000 | WHERE LENGTH(password)=40 AND password LIKE '^[0-9a-f]{40}$'` (SHA-1 signature).
  2. Sigma Rule (Adapted):
     ```
     title: Unsalted SHA-1 Detection
     logsource:
       category: database
     detection:
       selection:
         field: 'password_hash'
         pattern: '^[0-9a-f]{40}$'
       condition: selection
     ```
  3. Crack Test: Sample hashes with Hashcat (e.g., hashcat -m 0 -a 0 hashes.txt rockyou.txt); alert if >50% crack rate.
  4. Pivoting: Scan all auth fields for SHA-1 (no salt check: UNIQUE hashes < expected).
- **Expert Tip**: Migrate to bcrypt/Argon2. Realistic: LinkedIn's SHA-1 cracked 90%; baseline crack rates quarterly.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003), Unsecured Credentials (T1552)
Direct DB dump of hashed creds.
- **Hypothesis**: "Adversary accessed unsecured credential storage in DB."
- **Data Sources**: DB access logs for SELECT on auth tables.
- **Step-by-Step**:
  1. Query Credential Access: Splunk: `index=db query="*password*" OR "*hash*" table=users | stats sum(rows_affected) by session_id`.
  2. Sigma Rule:
     ```
     title: Credential Table Dump
     logsource:
       category: database
     detection:
       selection:
         query: '*SELECT * FROM members OR users password*'
         rows_returned: '>1M'
       condition: selection
     ```
  3. Forensics: Dump table samples; hash identify (e.g., identify -k hash_id.txt).
  4. Pivoting: Check for UNION ALL in queries (multi-table dumps).
- **Expert Tip**: Encrypt creds at rest. Realistic: Single query dumped millions; hunt large exports.

#### Step 8: Hunt for Discovery (TA0007) - Database Discovery (T1523, Inferred), Account Discovery (T1087)
Queried schema to find user tables (e.g., SHOW TABLES; DESCRIBE users).
- **Hypothesis**: "Recon queries enumerate DB structure for credential tables."
- **Data Sources**: DB logs for INFORMATION_SCHEMA queries.
- **Step-by-Step**:
  1. Query Schema Enum: Splunk: `index=db | search query="SHOW TABLES" OR "INFORMATION_SCHEMA" | stats count by ip`.
  2. Sigma Rule:
     ```
     title: DB Schema Recon
     logsource:
       category: database
     detection:
       selection:
         query: '*SHOW TABLES* OR *DESCRIBE users*'
       condition: selection
     ```
  3. Analyze: Grep for "information_schema.columns" (column enum for password fields).
  4. Pivoting: Follow with data queries.
- **Expert Tip**: Block schema queries from web users. Realistic: SQLi often starts with schema recon.

#### Step 9: Hunt for Collection (TA0009) - Data from Information Repositories (T1213), Automated Collection (T1119)
Staged/dumped user data (emails + hashes) for exfil.
- **Hypothesis**: "Bulk data collection from auth repositories."
- **Data Sources**: Temp table creation or large SELECT INTO OUTFILE.
- **Step-by-Step**:
  1. Query Bulk Collection: Splunk: `index=db | search "CREATE TABLE temp_dump" OR "SELECT INTO OUTFILE" | table query, user`.
  2. Sigma Rule:
     ```
     title: Data Staging in DB
     logsource:
       category: database
     detection:
       selection:
         sql_command: 'SELECT INTO OUTFILE' OR 'CREATE TEMP TABLE'
         target: '*users*'
       condition: selection
     ```
  3. Volume Analysis: Monitor total rows queried per session (>1M flags dump).
  4. Pivoting: Check for file exports (if enabled).
- **Expert Tip**: Disable INTO OUTFILE. Realistic: LinkedIn dump was ~167M rows; alert on query volumes.

#### Step 10: Hunt for Command and Control (TA0011) - Minimal (Internal DB Access)
No external C2; direct DB session. But hunt if via compromised host.
- **Hypothesis**: "If pivoted from endpoint, look for DB client connects."
- **Data Sources**: Network logs for DB ports (3306), endpoint process (mysql.exe).
- **Step-by-Step**:
  1. Query DB Connects: Splunk: `index=network dest_port=3306 src_ip!="internal" | stats count by src_ip`.
  2. Sigma Rule:
     ```
     title: External DB Access
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 3306
         Protocol: 'tcp'
       condition: selection
     ```
  3. Endpoint Hunt: Sysmon ID 1 for mysql.exe spawns.
  4. Pivoting: Geoloc external IPs (e.g., Russia).
- **Expert Tip**: VPN-only DB access. Realistic: Likely internal; hunt anomalous sessions.

#### Step 11: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002), Alternative Protocols if File Transfer
Data exfiltrated via web (e.g., HTTP POST if SQLi) or direct download.
- **Hypothesis**: "Stolen creds exfiltrated over web channels."
- **Data Sources**: Network egress logs, WAF for large POSTs.
- **Step-by-Step**:
  1. Query Large Outbound: Splunk: `index=network http_method=POST bytes_out > 10MB | stats sum(bytes_out) by dest_ip`.
  2. Sigma Rule:
     ```
     title: DB Dump Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_type: 'application/octet-stream'  # Dump files
         bytes: '>5MB'
       condition: selection
     ```
  3. PCAP: tshark -r pcap -Y "http contains 'SHA1' OR 'email:'".
  4. Pivoting: Dark web monitoring (e.g., via HIBP for your domain).
- **Expert Tip**: DLP on DB exports. Realistic: 2012 dump sold on forums; hunt for similar sales IOCs.

#### Step 12: Hunt for Impact (TA0040) - Data Encrypted for Impact (T1486, Inferred from Cracking), Account Access Removal
Post-dump cracking led to ATOs; LinkedIn forced resets (impact on users).
- **Hypothesis**: "Compromised creds used for unauthorized access or sold."
- **Data Sources**: Auth logs for failed/successful logins with cracked pwds, dark web alerts.
- **Step-by-Step**:
  1. Query ATO Attempts: Splunk: `index=auth failed_login=true user IN (breached_list) | stats count by ip`.
  2. Sigma Rule:
     ```
     title: Credential Stuffing Post-Breach
     logsource:
       category: authentication
     detection:
       selection:
         event: 'failed login'
         user_agent: 'curl' OR 'wget'  # Automated
       condition: selection
     ```
  3. Monitor Sales: Use tools like Recorded Future for "LinkedIn dump" mentions.
  4. Pivoting: Rotate all pre-2012 pwds if hits.
- **Expert Tip**: Enable MFA everywhere. Realistic: Secondary impacts (e.g., Twitter ATOs); hunt reuse patterns.

#### Step 13: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate DB), eradicate (audit all access), recover (hash migration, notify users per GDPR). Like LinkedIn, force resets and add salting.
- **Lessons**: Adopt bcrypt; enable DB auditing. Iterate hunts monthly; simulate with SQLMap for SQLi.
- **Expert Tip**: Use ATT&CK Navigator for coverage; monitor HIBP for your domains.

This guide arms you against LinkedIn-like breaches. Practice in labs; evolve for 2025 threats (e.g., AI-cracking hashes).
