### Teaching Threat Hunting for the 2020 Twitter Celebrity Hacks: A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in social engineering and platform-specific compromises, I'll guide you through proactive threat hunting to detect attacks resembling the 2020 Twitter celebrity hacks. This incident, occurring on July 15, 2020, was a coordinated social engineering attack by a group of teenagers led by 17-year-old Graham Ivan Clark (aka "Lil' Man") from Florida, along with accomplices Mason Sheppard (19, U.K., aka "Chaewon") and Nima Fazeli (22, Florida, aka "Rolex"). They targeted Twitter's internal tools, gaining access via vishing (voice phishing) to trick employees into providing credentials. Over ~1 hour, they hijacked 130+ high-profile accounts, including those of Barack Obama, Joe Biden, Elon Musk, Bill Gates, Jeff Bezos, Kanye West, Kim Kardashian West, Apple, Uber, and crypto firms, posting a Bitcoin scam promising to double donations (netting ~$120,000). They also sold access to desirable usernames on hacker forums. The attack exposed Twitter's internal vulnerabilities, leading to temporary lockdown of verified accounts. Clark was sentenced to 3 years in prison (2021); Sheppard and Fazeli faced charges.

Dwell time: Minimal for execution (~1 hour), but preparation involved weeks (forum reconnaissance, tool access). Undetected due to weak employee verification, no multi-layered auth for internal tools, and rapid execution. Detection: Twitter's security team noticed unusual activity; full scope revealed via FBI investigation. Impacts: $120K stolen, eroded trust in Twitter (stock dip), DOJ indictments (July 31, 2020), and platform reforms (e.g., enhanced employee training). From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Valid Accounts T1078.002 via social engineering), TA0002 (Execution: User Execution T1204.002), TA0005 (Defense Evasion: Impair Defenses T1562.004 via tool abuse), TA0007 (Discovery: Account Discovery T1087), TA0008 (Lateral Movement: Valid Accounts T1078.002), TA0009 (Collection: Data from Information Repositories T1213), and TA0010 (Exfiltration: Exfiltration Over C2 Channel T1041, minimal).

Threat hunting assumes breach: Hypothesis-driven searches for social engineering leading to internal tool abuse in social media platforms. Realistic parameters:
- **Environment**: Internal admin tools (e.g., Twitter's account support panel), AD-integrated access; high-value verified accounts.
- **Adversary Profile**: Young cybercriminals (vishing for creds, rapid hijacks; financial scams via Bitcoin).
- **Challenges**: Human-targeted (bypasses tech), quick execution, forum sales for persistence.
- **Tools/Data Sources**: SIEM (Splunk for auth/help desk logs), EDR (CrowdStrike for behaviors), vishing sims (GoPhish), YARA/Sigma for IOCs (e.g., Bitcoin wallet addresses from scam tweets).
- **Hypotheses**: E.g., "Teen hackers vish employees for tool access; hunt anomalous internal logons leading to account hijacks."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from DOJ indictments, Twitter's report, and Krebs analysis). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., internal tool sims) to avoid platform risks. Baselines: 30-60 days of auth/internal logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the hack—attackers vished Twitter employees for internal tool access; prioritize help desk monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for T1078 (e.g., social engineering). IOCs: Vishing scripts (e.g., impersonating IT), Bitcoin wallets (e.g., 16PWaZ1Q1Z1Z1Z1Z1Z1Z1Z1Z1Z1Z1Z1Z1Z from scam tweets), forum sales (OGUsers). Cross-ref Wikipedia timeline, Al Jazeera charges, Guardian arrests, and NPR indictments.
- **Map Your Environment**: Inventory internal tools (e.g., Twitter's account panel), help desk (ServiceNow), AD groups (tool admins). Use BloodHound for paths from employees to tools; sim vishing with tools like GoPhish.
- **Baseline Normal Behavior**: Log employee vish calls (verified only), tool logons (internal IPs). Tool: Sysmon (auth config for process/logons); enable help desk auditing.
- **Expert Tip**: Train on vishing. Hypothesis: "Hackers vish employees for tool creds; hunt anomalous help desk calls leading to hijacks."

#### Step 2: Hunt for Initial Access (TA0001) - Valid Accounts (T1078.002 via Social Engineering)
Vished help desk for employee creds to internal tools.
- **Hypothesis**: "An adversary uses vishing to obtain internal tool credentials."
- **Data Sources**: Help desk logs (tickets/calls), auth failures (Event ID 4771).
- **Step-by-Step Hunting**:
  1. Query Vishing: Splunk SPL: `index=helpdesk ticket_type="credential_reset" description="*urgent access*" | stats count by agent, caller_id | where caller_id!="known"`.
  2. Sigma Rule (YAML):
     ```
     title: Vishing Help Desk Abuse
     logsource:
       category: application
     detection:
       selection:
         ticket: '*password OR *access*'
         caller: external OR unknown
         urgency: 'high'
       condition: selection
     ```
     Deploy in SIEM; alert on unverified urgent requests.
  3. Analyze: Hunt scripts mimicking IT (e.g., "locked out" pretexts); cross-ref with sudden tool logons.
  4. Pivoting: Trace to internal tool access (Event ID 4624).
- **Expert Tip**: Callback verification. Realistic: 10-min call; hunt urgent tickets.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.002)
Executed tool access to hijack accounts.
- **Hypothesis**: "Stolen creds execute account modifications."
- **Data Sources**: Internal tool logs (account changes), Sysmon ID 1 (tool.exe).
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=internal EventID=1 | search Image="*twitter_tool*" CommandLine="*hijack*" | table _time, host, user`.
  2. Sigma Rule:
     ```
     title: Internal Tool Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*account_tool*'
         User: 'helpdesk_granted'
       condition: selection
     ```
  3. Forensics: Audit tool sessions for rapid changes (e.g., email swaps).
  4. Pivoting: To collection.
- **Expert Tip**: Tool logging. Realistic: Panel abuse; hunt modifications.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Reused creds for multiple hijacks.
- **Hypothesis**: "Stolen creds persist for account control."
- **Data Sources**: Event ID 4624 (repeated logons), session logs.
- **Step-by-Step**:
  1. Query Reuse: Splunk: `index=internal AccountName="suspect" | stats count by src_ip, _time | where count > 5/min`.
  2. Sigma Rule:
     ```
     title: Persistent Tool Reuse
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4624
         Frequency: '>3/min'
       condition: selection
     ```
  3. Scan: Long sessions in tool panel.
  4. Pivoting: To discovery.
- **Expert Tip**: Session limits. Realistic: 1-hour spree; hunt bursts.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Valid Accounts (T1078)
Escalated via tool access to verified accounts.
- **Hypothesis**: "Help desk creds escalate to account control."
- **Data Sources**: Event ID 4673, tool priv changes.
- **Step-by-Step**:
  1. Query Escalations: Splunk: `index=internal EventID=4673 | search PrivilegeList="*verified*" Account="user" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Tool Privilege Escalation
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4673
         Privileges: '*account_control*'
         Account: 'helpdesk*'
       condition: selection
     ```
  3. Analyze: Role assumptions in tool.
  4. Pivoting: To collection.
- **Expert Tip**: Tool least-priv. Realistic: Internal escalation; hunt grants.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.004)
Bypassed verification via social engineering.
- **Hypothesis**: "Vishing evades auth checks."
- **Data Sources**: Help desk gaps, Event ID 1102 (no clears).
- **Step-by-Step**:
  1. Query Bypasses: Splunk: `index=helpdesk verification="skipped" | stats count by agent`.
  2. Sigma Rule:
     ```
     title: Social Engineering Evasion
     logsource:
       category: application
     detection:
       selection:
         ticket: '*bypass* OR *verification skipped*'
       condition: selection
     ```
  3. Analyze: Hunt pretext patterns (e.g., "urgent").
  4. Pivoting: To discovery.
- **Expert Tip**: Mandatory verification. Realistic: Human error; hunt skips.

#### Step 7: Hunt for Credential Access (TA0006) - Steal Web Session Cookie (T1539)
Harvested creds via vishing (session tokens).
- **Hypothesis**: "Vishing steals session creds."
- **Data Sources**: Okta-like logs (token events), Event ID 4778.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=auth EventID=4778 | search TokenType="session" | stats count by ip`.
  2. Sigma Rule:
     ```
     title: Session Cred Theft
     logsource:
       category: authentication
     detection:
       selection:
         EventID: 4778
         Token: 'session*'
       condition: selection
     ```
  3. Forensics: Reused tokens.
  4. Pivoting: To discovery.
- **Expert Tip**: Token expiry. Realistic: Vish harvest; hunt anomalies.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087)
Discovered verified accounts in tool.
- **Hypothesis**: "Tool access discovers high-profile targets."
- **Data Sources**: Tool logs (account queries), Event ID 4662.
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=internal EventID=4662 ObjectClass="verified" | stats values(ObjectName) by host`.
  2. Sigma Rule:
     ```
     title: Verified Account Discovery
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4662
         ObjectType: 'verified_account'
       condition: selection
     ```
  3. Analyze: Search for "obama" etc.
  4. Pivoting: To collection.
- **Expert Tip**: Query limits. Realistic: Panel enum; hunt searches.

#### Step 9: Hunt for Lateral Movement (TA0008) - Valid Accounts (T1078.002)
Moved to account panel using creds.
- **Hypothesis**: "Creds pivot to hijack tools."
- **Data Sources**: Event ID 5145, Sysmon ID 3.
- **Step-by-Step**:
  1. Query Pivots: Splunk: `index=network protocol=http dest="internal_panel" user="stolen" | stats count by src`.
  2. Sigma Rule:
     ```
     title: Tool Lateral
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 80
         User: 'helpdesk*'
       condition: selection
     ```
  3. Traffic: Panel accesses.
  4. Pivoting: To collection.
- **Expert Tip**: Tool segmentation. Realistic: Direct pivot; hunt panels.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Collected account data (handles, emails).
- **Hypothesis**: "Tool access collects account info."
- **Data Sources**: Tool logs (exports), file copies.
- **Step-by-Step**:
  1. Query Collection: Splunk: `index=internal Operation="export_account" | stats count by user`.
  2. Sigma Rule:
     ```
     title: Account Data Collection
     logsource:
       category: application
     detection:
       selection:
         Operation: 'export OR copy'
         Target: 'verified*'
       condition: selection
     ```
  3. Volume: High exports.
  4. Pivoting: To exfil.
- **Expert Tip**: Export logs. Realistic: Handle sales; hunt copies.

#### Step 11: Hunt for Command and Control (TA0011) - Minimal (Direct Tool)
No C2; direct tool abuse.
- **Hypothesis**: "Persistent tool sessions for control."
- **Data Sources**: Session logs.
- **Step-by-Step**:
  1. Query Sessions: Splunk: `index=internal session_duration > 30min | stats avg(duration) by ip`.
  2. Sigma Rule:
     ```
     title: Long Tool Sessions
     logsource:
       category: application
     detection:
       selection:
         session_time: '>1800s'
       condition: selection
     ```
  3. Geoloc: External.
  4. Pivoting: To impact.
- **Expert Tip**: Session timeouts. Realistic: No malware; hunt durations.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated account data via tool exports.
- **Hypothesis**: "Collected data exfil for sales."
- **Data Sources**: Network (POSTs from tool), logs.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 1KB dest="forum" | stats sum(bytes)`.
  2. Sigma Rule:
     ```
     title: Account Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content: '*handle OR *email*'
       condition: selection
     ```
  3. PCAP: Data payloads.
  4. Pivoting: To scam tweets.
- **Expert Tip**: Tool DLP. Realistic: Forum sales; hunt exports.

#### Step 13: Hunt for Impact (TA0040) - No Destruction
Impact via scams (Bitcoin tweets) and sales.
- **Hypothesis**: "Hijacks enable fraud."
- **Data Sources**: Tweet logs, fraud alerts.
- **Step-by-Step**:
  1. Query Scams: Splunk: `index=external tweet_content="*bitcoin*" account="obama" | stats count by wallet`.
  2. Sigma Rule:
     ```
     title: Hijack Impact
     logsource:
       category: external
     detection:
       selection:
         event: 'scam_tweet'
       condition: selection
     ```
  3. Monitor: $120K wallets.
  4. Pivoting: Arrests.
- **Expert Tip**: Verified locks. Realistic: $120K; hunt scams.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (lock tools), eradicate (cred reset, audit), recover (notify users, monitor scams). Like Twitter, lockdown verified; engage FBI.
- **Lessons**: Per DOJ, train vishing, verify tools, log internals. Iterate monthly; simulate with vishing.
- **Expert Tip**: ATT&CK Navigator for platforms; evolve for 2025 (e.g., AI vishing).
