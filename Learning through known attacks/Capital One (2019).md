### Teaching Threat Hunting for Capital One Breach-Like Attacks (2019): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter with expertise in cloud misconfigurations and SSRF (Server-Side Request Forgery) exploits, I'll guide you through proactive threat hunting to detect attacks resembling the 2019 Capital One data breach. This incident was perpetrated by Paige Thompson, a former AWS engineer (arrested July 29, 2019; pleaded guilty in 2022, sentenced to time served plus probation). Thompson exploited a misconfigured web application firewall (WAF) in Capital One's AWS environment, using an SSRF vulnerability in a customer dispute portal to access metadata services and assume an IAM role. This allowed her to enumerate S3 buckets and exfiltrate ~100 million customer records (106M total: names, addresses, DOBs, emails, phone numbers, SSNs for 14M, credit scores, balances, and 80K+ credit card apps with partial numbers). The attack was reconnaissance-heavy, with Thompson scanning ~30 organizations (e.g., government entities). No malware; it was a pure misconfig exploit.

Dwell time: ~2 months (March 2019 scanning to July 2019 access/exfil; discovered July 2019 via internal alert). Undetected due to over-privileged IAM roles, no WAF logging for SSRF, and unmonitored metadata access. Detection: AWS CloudTrail anomaly (unusual IAM role assumption); Thompson's GitHub posts (e.g., "marvelous" repo with scan code) aided attribution. Impacts: $190M settlement (2021, including $80M class-action), $80M FTC fine (2022), CEO resignation, and enhanced AWS IAM best practices. From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Exploitation of Public-Facing Application T1190 via SSRF), TA0002 (Execution: Exploitation for Client Execution T1203), TA0005 (Defense Evasion: Impair Defenses T1562.001 via misconfig), TA0007 (Discovery: Cloud Service Discovery T1526), TA0006 (Credential Access: Steal or Forge Authentication Certificates T1606.002 via IAM), TA0009 (Collection: Data from Cloud Storage T1530), and TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002).

Threat hunting assumes misconfig: Hypothesis-driven searches for SSRF and IAM abuse in cloud environments. Realistic parameters:
- **Environment**: AWS (EC2, S3, IAM, WAF); web apps with metadata access.
- **Adversary Profile**: Insider/former employee (recon tools, IAM role chaining; data theft for fraud/espionage).
- **Challenges**: CloudTrail volume, over-priv IAM, SSRF bypasses WAF.
- **Tools/Data Sources**: CloudTrail (API logs), GuardDuty (anomalies), SIEM (Splunk for IAM), IAM Access Analyzer, YARA/Sigma for SSRF IOCs (e.g., unusual metadata fetches).
- **Hypotheses**: E.g., "An adversary exploits SSRF to assume IAM roles and dump S3 data."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Exabeam MITRE analysis and ACM case study). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., AWS sandboxes) to avoid compliance (e.g., PCI). Baselines: 30-60 days of CloudTrail for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Contextualize the breach—Thompson's SSRF chained to IAM over-priv; prioritize metadata monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for T1190 (SSRF). IOCs: SSRF payloads (e.g., gopher://metadata), IAM role assumptions (e.g., CapitalOne-AWSRole). Cross-ref Exabeam MITRE mapping, ACM systematic analysis, Capital One facts, and Medium breakdown.
- **Map Your Environment**: Inventory web apps (WAF configs), IAM roles (e.g., over-priv for S3), metadata endpoints. Use IAM Access Analyzer for privs; GuardDuty for SSRF.
- **Baseline Normal Behavior**: Log IAM assumptions (internal), metadata fetches (none from apps). Tool: Sysmon (cloud config for API); CloudTrail for events.
- **Expert Tip**: Least-priv IAM. Hypothesis: "Ex-dev exploits SSRF to chain IAM roles; hunt anomalous metadata access leading to S3 dumps."

#### Step 2: Hunt for Initial Access (TA0001) - Exploitation of Public-Facing Application (T1190 via SSRF)
Exploited SSRF in WAF misconfig for metadata access.
- **Hypothesis**: "An adversary exploits web app SSRF to reach internal metadata."
- **Data Sources**: WAF logs (ModSecurity), CloudTrail (metadata fetches), app errors.
- **Step-by-Step Hunting**:
  1. Query SSRF: Splunk SPL: `index=waf sourcetype=modsec | search msg="SSRF" OR request_uri="*metadata*" | stats count by src_ip | where count > 1`.
  2. Sigma Rule (YAML):
     ```
     title: SSRF Exploitation
     logsource:
       category: web
     detection:
       selection:
         request_uri: '*metadata* OR *gopher://*'
         status: '200'
       condition: selection
     ```
     Deploy in SIEM; alert on internal redirects.
  3. Analyze: Hunt gopher:// or internal IP requests in app logs.
  4. Pivoting: Trace to IAM assumptions (CloudTrail AssumeRole).
- **Expert Tip**: WAF SSRF rules. Realistic: Misconfig bypass; hunt internal URIs.

#### Step 3: Hunt for Execution (TA0002) - Exploitation for Client Execution (T1203)
Executed SSRF to invoke AWS APIs (e.g., DescribeInstances).
- **Hypothesis**: "SSRF executes internal API calls."
- **Data Sources**: CloudTrail (API events), Sysmon ID 1 (awscli if local).
- **Step-by-Step**:
  1. Query APIs: Splunk: `index=cloudtrail eventName="DescribeInstances" sourceIPAddress="web_app_ip" | stats count by userAgent`.
  2. Sigma Rule:
     ```
     title: SSRF API Execution
     logsource:
       category: cloud_api
     detection:
       selection:
         eventName: 'Describe* OR List*'
         sourceIP: 'web_app'
       condition: selection
     ```
  3. Forensics: GuardDuty findings for SSRF.
  4. Pivoting: To role assumption.
- **Expert Tip**: API logging. Realistic: Chained to metadata; hunt web IPs.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002)
Assumed IAM role for ongoing access.
- **Hypothesis**: "SSRF enables persistent IAM role use."
- **Data Sources**: CloudTrail (AssumeRole), session tokens.
- **Step-by-Step**:
  1. Query Roles: Splunk: `index=cloudtrail eventName="AssumeRole" roleName="CapitalOne-AWSRole" | stats count by principalId`.
  2. Sigma Rule:
     ```
     title: IAM Role Persistence
     logsource:
       category: cloud_api
     detection:
       selection:
         eventName: 'AssumeRole'
         role: 'over_priv*'
       condition: selection
     ```
  3. Scan: IAM policies for over-priv (S3 full access).
  4. Pivoting: To discovery.
- **Expert Tip**: Role rotation. Realistic: Persistent assumption; hunt unusual principals.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Steal or Forge Authentication Certificates (T1606.002 via IAM)
Chained SSRF to assume over-priv IAM role.
- **Hypothesis**: "Metadata access escalates via IAM chaining."
- **Data Sources**: CloudTrail (role events), metadata fetches.
- **Step-by-Step**:
  1. Query Chaining: Splunk: `index=cloudtrail eventName="GetInstanceMetadata" followed_by "AssumeRole" | stats count by sourceIP`.
  2. Sigma Rule:
     ```
     title: IAM Escalation Chain
     logsource:
       category: cloud_api
     detection:
       selection:
         eventName: 'GetInstanceMetadata' then 'AssumeRole'
       condition: selection
     ```
  3. Analyze: Role policies (e.g., s3:GetObject on buckets).
  4. Pivoting: To S3 access.
- **Expert Tip**: Metadata service controls. Realistic: Role over-priv; hunt chains.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001 via Misconfig)
Bypassed WAF via misconfig; no direct impairment.
- **Hypothesis**: "Misconfigs evade WAF/monitoring."
- **Data Sources**: WAF logs (bypasses), CloudTrail gaps.
- **Step-by-Step**:
  1. Query Bypasses: Splunk: `index=waf action="allow" request_uri="*metadata*" | stats count by rule_id`.
  2. Sigma Rule:
     ```
     title: WAF Misconfig Evasion
     logsource:
       category: web
     detection:
       selection:
         action: 'allow'
         uri: '*internal* OR *metadata*'
       condition: selection
     ```
  3. Audit: WAF rules for SSRF.
  4. Pivoting: To discovery.
- **Expert Tip**: WAF tuning. Realistic: Misconfig; hunt allowed internals.

#### Step 7: Hunt for Credential Access (TA0006) - Unsecured Credentials (T1552.001)
Accessed IAM creds via metadata service.
- **Hypothesis**: "SSRF steals IAM creds from metadata."
- **Data Sources**: CloudTrail (metadata events), Sysmon ID 13.
- **Step-by-Step**:
  1. Query Metadata: Splunk: `index=cloudtrail eventName="GetInstanceMetadata" path="*iam/security-credentials*" | stats count by sourceIP`.
  2. Sigma Rule:
     ```
     title: IAM Cred Theft via Metadata
     logsource:
       category: cloud_api
     detection:
       selection:
         eventName: 'GetInstanceMetadata'
         path: '*iam*'
       condition: selection
     ```
  3. Forensics: GuardDuty for metadata abuse.
  4. Pivoting: To S3.
- **Expert Tip**: IMDSv2. Realistic: Metadata fetch; hunt paths.

#### Step 8: Hunt for Discovery (TA0007) - Cloud Service Discovery (T1526)
Enumerated S3 buckets via IAM role.
- **Hypothesis**: "Assumed role discovers storage resources."
- **Data Sources**: CloudTrail (ListBuckets), IAM calls.
- **Step-by-Step**:
  1. Query Buckets: Splunk: `index=cloudtrail eventName="ListBuckets" role="suspect" | stats dc(bucketName)`.
  2. Sigma Rule:
     ```
     title: S3 Discovery
     logsource:
       category: cloud_api
     detection:
       selection:
         eventName: 'ListBuckets OR ListObjects'
         role: 'assumed*'
       condition: selection
     ```
  3. Analyze: Bucket names like "capitalone-data".
  4. Pivoting: To collection.
- **Expert Tip**: Bucket policies. Realistic: 700+ enumerated; hunt lists.

#### Step 9: Hunt for Collection (TA0009) - Data from Cloud Storage (T1530)
Downloaded 100M records from S3.
- **Hypothesis**: "IAM role collects PII from buckets."
- **Data Sources**: CloudTrail (GetObject), S3 logs.
- **Step-by-Step**:
  1. Query Downloads: Splunk: `index=cloudtrail eventName="GetObject" bucket="customer-data" bytes > 1GB | stats sum(bytes) by role`.
  2. Sigma Rule:
     ```
     title: Bulk S3 Collection
     logsource:
       category: cloud_api
     detection:
       selection:
         eventName: 'GetObject'
         bucket: 'sensitive*'
         bytes: '>100MB'
       condition: selection
     ```
  3. Volume: High object counts.
  4. Pivoting: To exfil.
- **Expert Tip**: S3 versioning. Realistic: 30GB dumped; hunt large gets.

#### Step 10: Hunt for Command and Control (TA0011) - Minimal (Direct API)
No C2; direct AWS API calls.
- **Hypothesis**: "Persistent API access without beacons."
- **Data Sources**: CloudTrail (repeated calls).
- **Step-by-Step**:
  1. Query Sessions: Splunk: `index=cloudtrail role="suspect" | stats count by eventName | where count > 50`.
  2. Sigma Rule:
     ```
     title: Persistent API Access
     logsource:
       category: cloud_api
     detection:
       selection:
         frequency: '>20/hour'
         role: 'assumed'
       condition: selection
     ```
  3. Geoloc: External principals.
  4. Pivoting: To exfil.
- **Expert Tip**: API rate limits. Realistic: No malware; hunt volumes.

#### Step 11: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
Exfiltrated data via AWS APIs (downloaded to attacker's machine).
- **Hypothesis**: "S3 data exfil via direct downloads."
- **Data Sources**: CloudTrail (GetObject egress), network.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=cloudtrail eventName="GetObject" bytes_out > 500MB | stats sum(bytes) by principalId`.
  2. Sigma Rule:
     ```
     title: S3 Data Exfil
     logsource:
       category: cloud_api
     detection:
       selection:
         eventName: 'GetObject'
         bytes: '>100MB'
       condition: selection
     ```
  3. PCAP: If VPN, large transfers.
  4. Pivoting: Dark web dumps.
- **Expert Tip**: Egress monitoring. Realistic: 100M records; hunt bytes.

#### Step 12: Hunt for Impact (TA0040) - No Destruction
Impact via identity theft; no encryption.
- **Hypothesis**: "Theft enables fraud; monitor downstream."
- **Data Sources**: Fraud alerts, HIBP.
- **Step-by-Step**:
  1. Query Fraud: Splunk: `index=external event="SSN_fraud" source="capitalone" | stats count by type`.
  2. Sigma Rule:
     ```
     title: Post-Breach Fraud
     logsource:
       category: external
     detection:
       selection:
         event: 'identity_theft'
       condition: selection
     ```
  3. Monitor: Credit spikes.
  4. Pivoting: Victim support.
- **Expert Tip**: Fraud detection. Realistic: Ongoing; hunt patterns.

#### Step 13: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (revoke IAM, isolate apps), eradicate (WAF fix, role trim), recover (notify FTC, offer monitoring). Like Capital One, settle claims; audit IAM.
- **Lessons**: Per Exabeam, least-priv IAM, SSRF protection, CloudTrail monitoring. Iterate monthly; simulate with SSRF in labs.
- **Expert Tip**: ATT&CK Navigator for cloud; evolve for 2025 (e.g., AI IAM anomalies).
