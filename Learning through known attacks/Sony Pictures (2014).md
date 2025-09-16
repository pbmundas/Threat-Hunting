### Teaching Threat Hunting for Sony Pictures Breach-Like Attacks (2014): A Pro Threat Hunter's Step-by-Step Guide

As a professional threat hunter specializing in nation-state APTs and destructive malware campaigns, I'll guide you through proactive threat hunting to detect attacks resembling the 2014 Sony Pictures Entertainment (SPE) breach. This was a politically motivated cyber operation attributed to North Korean state-sponsored actors (Lazarus Group, per FBI analysis), targeting SPE in retaliation for the film *The Interview*, a comedy depicting the assassination of Kim Jong-un. Attackers (self-styled "Guardians of Peace" or GOP) gained initial access likely via spear-phishing or exploiting unpatched vulnerabilities, then conducted extensive reconnaissance, exfiltrated ~100TB of data (e.g., unreleased films like *Annie* and *Fury*, executive emails, 47,000 SSNs, salaries, scripts), and deployed destructive wiper malware (Shamoon-like, overwriting MBR and files with GOP imagery/skeleton screens). The attack disrupted operations (e.g., email outage for 6,600 employees), leaked data via torrent sites, and issued threats mimicking 9/11 to halt the film's release.

Dwell time: ~2-3 months (estimated September-November 2014 for infiltration/exfil; wiper executed November 24, 2014), undetected due to poor segmentation, outdated security (e.g., weak AV, no SIEM), and under-resourced IT (e.g., 2011 PwC audit flagged issues). Detection: November 24, 2014, via on-screen warnings; FBI confirmed North Korea on December 19, 2014, via malware TTPs (e.g., Korean strings, IP overlaps with prior NK ops). Impacts: $15M immediate costs, $100M+ in lawsuits/settlements, $35M SEC fine for non-disclosure, reputational damage (e.g., Amy Pascal resignation), and precedent for state-sponsored corporate attacks. From a MITRE ATT&CK Enterprise perspective, key tactics include TA0001 (Initial Access: Phishing T1566.001, Exploit Public-Facing Application T1190), TA0003 (Persistence: Valid Accounts T1078.002), TA0005 (Defense Evasion: Impair Defenses T1562.001), TA0007 (Discovery: Account Discovery T1087), TA0006 (Credential Access: OS Credential Dumping T1003), TA0009 (Collection: Data from Information Repositories T1213), TA0010 (Exfiltration: Exfiltration Over Web Service T1567.002), TA0040 (Impact: Data Destruction T1485 via wiper), and TA0011 (Command and Control: Proxy T1090).

Threat hunting assumes breach: Hypothesis-driven searches for long-dwell APTs with destructive payloads in media/entertainment sectors. Realistic parameters:
- **Environment**: Flat enterprise networks (e.g., Windows AD, email servers, file shares with IP like scripts/films); high-value data (PII, IP).
- **Adversary Profile**: Nation-state (patient exfil, custom wipers; political motives, proxy use for deniability).
- **Challenges**: Massive data volumes masking exfil, weak logging (no EDR), insider-like access (e.g., admin creds).
- **Tools/Data Sources**: EDR (Carbon Black for endpoint), SIEM (Splunk/ELK for email/file logs), network metadata (Zeek for proxies), file integrity (Tripwire), YARA/Sigma for wiper IOCs (e.g., MD5: e0f5b2a0e5f6a7b8c9d0e1f2a3b4c5d6 for Destover variant).
- **Hypotheses**: E.g., "An adversary has phished for creds to exfil IP and deploy wipers."

This guide covers **each relevant MITRE ATT&CK technique** (mapped from Operation Blockbuster by Novetta, FBI reports, and Mandiant analysis). Proceed tactic-by-tactic with sub-steps: hypothesis, data collection, analysis, pivoting. Includes realistic queries, Sigma rules, and expert tips. Hunt in scoped envs (e.g., media labs) to avoid leaks. Baselines: 60-90 days of file/email logs for anomalies.

#### Step 1: Preparation - Intelligence Gathering and Environment Mapping
Understand the breach—Sony's flat network and poor patching enabled deep access; focus on email/IP monitoring.
- **Gather Threat Intel**: Review MITRE ATT&CK for Lazarus (e.g., T1485 for wipers). IOCs: Wiper strings ("GOD IS YOUR SAVIOR", GOP skull wallpaper), C2 IPs (e.g., NK proxies), malware hashes (SHA256: 0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b). Cross-ref Wikipedia , Novetta's Operation Blockbuster , FBI attribution , and Krebs .
- **Map Your Environment**: Inventory email gateways (Exchange), file shares (e.g., for scripts/films), AD groups (exec admins). Use BloodHound for paths from phishing users to shares; Shodan for exposed ports.
- **Baseline Normal Behavior**: Log email attachments (Event ID 2003), file accesses (4663), outbound (large torrents). Tool: Sysmon (config for process/file/network); enable file auditing on shares.
- **Expert Tip**: Scan for weak hashing (e.g., NTLMv1). Hypothesis: "Lazarus uses phishing for foothold; hunt anomalous email opens leading to exfil."

#### Step 2: Hunt for Initial Access (TA0001) - Phishing: Spearphishing Attachment/Link (T1566.001), Exploit Public-Facing Application (T1190)
Likely spear-phishing with malware (e.g., backdoor dropper) or unpatched web vulns for foothold.
- **Hypothesis**: "An adversary has delivered malware via targeted phishing to gain network access."
- **Data Sources**: Email logs (Proofpoint), web proxy (suspicious URLs), Sysmon ID 11 (malicious .exe).
- **Step-by-Step Hunting**:
  1. Query Phishing: Splunk SPL: `index=email sourcetype=exchange | search attachment="*scr*" OR subject="*sony update*" | stats count by sender_ip, recipient | where count > 1 AND sender_domain NOT "trusted"`.
  2. Sigma Rule (YAML):
     ```
     title: Lazarus Spear-Phishing
     logsource:
       category: email_activity
     detection:
       selection:
         subject: '*interview* OR *script*'
         attachment: '*.scr OR *.exe'
         sender: NOT IN ('internal')
       condition: selection
     ```
     Deploy in SIEM; alert on exec-targeted sends.
  3. Analyze: VirusTotal attachments for Lazarus droppers; hunt URL clicks (Event ID 2004).
  4. Pivoting: Trace to first logon (Event ID 4624 from external IP).
- **Expert Tip**: Safe Links/Attachments. Realistic: Political lures (e.g., *The Interview* related); hunt low-volume to execs.

#### Step 3: Hunt for Execution (TA0002) - User Execution (T1204.002): Malicious File
Executed backdoor/wiper via user-opened attachments.
- **Hypothesis**: "Phished files execute to establish foothold."
- **Data Sources**: Sysmon ID 1 (process from .scr), Event ID 4688.
- **Step-by-Step**:
  1. Query Executions: Splunk: `index=endpoint EventID=1 | search ParentImage="*outlook.exe*" AND Image="*backdoor.exe*" | table _time, host, CommandLine`.
  2. Sigma Rule:
     ```
     title: Backdoor Execution
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*.scr'
         ParentImage: '*winword.exe* OR *outlook.exe*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py -f mem.raw --profile=Win7SP1x86 malfind | grep shellcode` (scan injections).
  4. Pivoting: Correlate with registry mods (persistence).
- **Expert Tip**: AppLocker for .scr. Realistic: Silent exec; hunt office app children.

#### Step 4: Hunt for Persistence (TA0003) - Valid Accounts (T1078.002), Create Account (T1136)
Used stolen creds; created backdoors (e.g., scheduled tasks).
- **Hypothesis**: "Adversary persists via rogue accounts post-phishing."
- **Data Sources**: Event ID 4720 (user create), Sysmon ID 13 (Run keys).
- **Step-by-Step**:
  1. Query Accounts: Splunk: `index=ad EventCode=4720 | search AccountName LIKE "*gop*" | stats count by creator`.
  2. Sigma Rule:
     ```
     title: Rogue Account Persistence
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4720
         LogonType: 5
       condition: selection
     ```
  3. Scan: Autoruns for HKCU\Run with obfuscated paths.
  4. Pivoting: Link to repeated logons.
- **Expert Tip**: Just-in-time privs. Realistic: Admin creds stolen; audit service accounts.

#### Step 5: Hunt for Privilege Escalation (TA0004) - Access Token Manipulation (T1134), Exploitation for Privilege Escalation (T1068)
Escalated via token theft or unpatched vulns (e.g., EternalBlue precursors).
- **Hypothesis**: "Low-priv foothold escalated to domain admin."
- **Data Sources**: Sysmon ID 10 (token access), Event ID 4673.
- **Step-by-Step**:
  1. Query Tokens: Splunk: `index=windows EventID=4673 | search PrivilegeList="*SeDebug*" AND User="user" | table _time, host`.
  2. Sigma Rule:
     ```
     title: Token Theft Escalation
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe'
         GrantedAccess: '0x1410'
       condition: selection
     ```
  3. Analyze: Mimikatz YARA for dumps.
  4. Pivoting: To file share access.
- **Expert Tip**: Protected processes. Realistic: Gradual escalation; hunt unusual SeDebug.

#### Step 6: Hunt for Defense Evasion (TA0005) - Impair Defenses (T1562.001), Obfuscated Files (T1027)
Disabled AV; packed wiper (Destover) evaded detection.
- **Hypothesis**: "Malware evades via tool impairment and packing."
- **Data Sources**: Event ID 1102 (log clear), Sysmon ID 1 (packers like UPX).
- **Step-by-Step**:
  1. Query Impairment: Splunk: `index=security EventID=1102 OR Image="taskkill.exe" CommandLine="*avp*" | stats count by host`.
  2. Sigma Rule:
     ```
     title: AV Evasion
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*taskkill.exe*'
         CommandLine: '*symantec* OR *mcafee*'
       condition: selection
     ```
  3. Binary: PEiD for packers on suspicious .exe.
  4. Pivoting: Precedes wiper.
- **Expert Tip**: Behavioral EDR. Realistic: Wiper overwrote logs; hunt disables.

#### Step 7: Hunt for Credential Access (TA0006) - OS Credential Dumping (T1003)
Dumped creds from lsass for lateral movement.
- **Hypothesis**: "Adversary dumps creds for network traversal."
- **Data Sources**: Sysmon ID 10 (lsass), Event ID 4688.
- **Step-by-Step**:
  1. Query Dumps: Splunk: `index=edr TargetProcess="*lsass.exe*" CallTrace="*MiniDump*" | stats dc(host) by _time`.
  2. Sigma Rule:
     ```
     title: LSASS Dumping
     logsource:
       category: process_access
     detection:
       selection:
         TargetImage: '*lsass.exe'
         CallTrace: '*advapi32*MiniDump*'
       condition: selection
     ```
  3. Forensics: Volatility: `vol.py dumpfiles -D lsass.dmp`.
  4. Pivoting: To share accesses.
- **Expert Tip**: Credential Guard. Realistic: Enabled IP access; hunt API.

#### Step 8: Hunt for Discovery (TA0007) - Account Discovery (T1087), Network Service Discovery (T1046)
Enumerated AD/users, scanned for shares (e.g., net view).
- **Hypothesis**: "Recon for high-value IP/PII."
- **Data Sources**: Event ID 4662 (object access), Sysmon ID 3 (scans).
- **Step-by-Step**:
  1. Query Enum: Splunk: `index=ad EventID=4662 ObjectClass="user" | stats values(ObjectName) by host`.
  2. Sigma Rule:
     ```
     title: AD Discovery
     logsource:
       category: security_event
     detection:
       selection:
         EventID: 4662
         ObjectType: 'user'
       condition: selection
     ```
  3. Network: Zeek for port 445 probes.
  4. Pivoting: To collection.
- **Expert Tip**: Log AD queries. Realistic: Targeted exec shares.

#### Step 9: Hunt for Lateral Movement (TA0008) - Remote Services (T1021.001: SMB), Valid Accounts (T1078.002)
Pivoted via SMB/RDP using dumped creds to file servers.
- **Hypothesis**: "Movement to IP repositories via shares."
- **Data Sources**: Event ID 5145 (SMB), Sysmon ID 3 (445).
- **Step-by-Step**:
  1. Query SMB: Splunk: `index=network protocol=smb dest_port=445 user="admin" | stats count by src, dest`.
  2. Sigma Rule:
     ```
     title: Lateral SMB
     logsource:
       category: network_connection
     detection:
       selection:
         DestinationPort: 445
         User: '*$'
       condition: selection
     ```
  3. RDP: Event ID 4624 LogonType=10.
  4. Pivoting: To file exfil.
- **Expert Tip**: Disable SMBv1. Realistic: Flat net; UEBA crosses.

#### Step 10: Hunt for Collection (TA0009) - Data from Information Repositories (T1213)
Staged ~100TB (films, emails) on shares.
- **Hypothesis**: "Bulk IP/PII collection for leaks."
- **Data Sources**: Sysmon ID 11 (staging), Event ID 4663 (accesses).
- **Step-by-Step**:
  1. Query Staging: Splunk: `index=endpoint FilePath="\\share\staged*" Size > 1GB | stats sum(Size) by host`.
  2. Sigma Rule:
     ```
     title: IP Staging
     logsource:
       category: file_event
     detection:
       selection:
         TargetFilename: '*.torrent OR *.zip' Size: '>50GB'
       condition: selection
     ```
  3. DLP: Regex for SSNs in copies.
  4. Pivoting: To exfil.
- **Expert Tip**: Encrypt shares. Realistic: Torrents prepped; hunt volumes.

#### Step 11: Hunt for Command and Control (TA0011) - Proxy (T1090)
Used NK proxies for exfil/commands.
- **Hypothesis**: "Backdoor proxies for sustained access."
- **Data Sources**: Sysmon ID 3 (proxy chains), Zeek DNS.
- **Step-by-Step**:
  1. Query Proxies: Splunk: `index=network proxy=true dest_port=80 | stats dc(dest_ip) by src_ip`.
  2. Sigma Rule:
     ```
     title: Proxy C2
     logsource:
       category: network_connection
     detection:
       selection:
         Proxy: true
         DestPort: '80 OR 443'
       condition: selection
     ```
  3. DNS: Hunt NK domains.
  4. Pivoting: To data transfers.
- **Expert Tip**: Proxy inspection. Realistic: Deniability; hunt chains.

#### Step 12: Hunt for Exfiltration (TA0010) - Exfiltration Over Web Service (T1567.002)
~100TB via HTTP/torrents to leak sites.
- **Hypothesis**: "Staged data exfil for public leaks."
- **Data Sources**: Network (large POSTs), torrent trackers.
- **Step-by-Step**:
  1. Query Egress: Splunk: `index=network http_method=POST bytes_out > 10GB | stats sum(bytes) by dest`.
  2. Sigma Rule:
     ```
     title: Mass Exfil
     logsource:
       category: web
     detection:
       selection:
         http_method: 'POST'
         content_length: '>1GB'
       condition: selection
     ```
  3. PCAP: tshark -Y "http contains 'torrent'".
  4. Pivoting: Dark web scans.
- **Expert Tip**: DLP egress. Realistic: Chunked leaks; hunt spikes.

#### Step 13: Hunt for Impact (TA0040) - Data Destruction (T1485): Disk Wipe
Wiper overwrote data/MBR, displayed threats.
- **Hypothesis**: "Destructive payload wipes post-exfil."
- **Data Sources**: Event ID 7045 (wiper service), file mods.
- **Step-by-Step**:
  1. Query Wipes: Splunk: `index=endpoint Image="*wiper*" OR Event="MBR overwrite" | stats count by host`.
  2. Sigma Rule:
     ```
     title: Wiper Impact
     logsource:
       category: process_creation
     detection:
       selection:
         Image: '*destover.exe*'
         CommandLine: '*overwrite*'
       condition: selection
     ```
  3. Forensics: Check MBR hashes.
  4. Pivoting: Post-leak threats.
- **Expert Tip**: Backups offline. Realistic: Psychological; hunt overwrites.

#### Step 14: Post-Hunt - Response, Remediation, and Iteration
- **If Found**: Contain (isolate shares), eradicate (wiper removal, cred reset), recover (data restore, notify). Like Sony, engage forensics (Mandiant); disclose per SEC.
- **Lessons**: Per Novetta , segment networks, patch promptly, train phishing. Iterate monthly; simulate with Shamoon Atomic Red Team.
- **Expert Tip**: ATT&CK Navigator for media; evolve for 2025 (e.g., AI wipers).
