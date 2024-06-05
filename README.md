# Mitre-Based-Usecases
This repository is established as part of my personal projects and cybersecurity research endeavors.

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/02e1219d-08b8-4c03-a4b6-77ec011078fa)

# Working of use-cases:

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/dee8e7b8-5aeb-4c02-b2b9-3e0973a8e7bb)

Alerts in cybersecurity serve as notifications or warnings about potential security incidents or vulnerabilities within a network or system. They play a critical role in helping security teams quickly identify, investigate, and respond to threats, thus maintaining the integrity, confidentiality, and availability of information.

### Use Cases of Alerts in Cybersecurity:

1. **Intrusion Detection:**
   - **Use Case:** Alerts notify security teams of unauthorized access attempts or suspicious activities.
   - **Example:** An alert triggers when an unknown IP address attempts multiple failed logins on a server.

2. **Malware Detection:**
   - **Use Case:** Alerts indicate the presence of malicious software such as viruses, ransomware, or spyware.
   - **Example:** An alert is generated when a file matching the signature of known malware is downloaded or executed.

3. **Phishing Attacks:**
   - **Use Case:** Alerts inform users and administrators about potential phishing emails or websites.
   - **Example:** An alert is sent when an email with suspicious links or attachments is detected.

4. **Data Exfiltration:**
   - **Use Case:** Alerts detect unusual data transfer activities that may indicate data theft.
   - **Example:** An alert occurs when a large amount of sensitive data is transferred outside the network during off-hours.

5. **Vulnerability Management:**
   - **Use Case:** Alerts notify about newly discovered vulnerabilities and necessary patches.
   - **Example:** An alert is issued when a critical security patch is available for a widely-used software application.

6. **Configuration Changes:**
   - **Use Case:** Alerts detect unauthorized or unexpected changes in system configurations.
   - **Example:** An alert triggers when firewall rules are altered without proper authorization.

7. **Behavioral Anomalies:**
   - **Use Case:** Alerts identify deviations from normal user or system behavior that could indicate a compromise.
   - **Example:** An alert is generated when a user accesses resources they typically do not access.

8. **Compliance Monitoring:**
   - **Use Case:** Alerts help ensure that systems comply with regulatory and policy requirements.
   - **Example:** An alert notifies when a system configuration deviates from compliance standards like GDPR or HIPAA.

### Working of Alerts in Cybersecurity:

1. **Data Collection:**
   - **Sources:** Security Information and Event Management (SIEM) systems, Intrusion Detection Systems (IDS), firewalls, antivirus software, and other security tools collect data from various network components and endpoints.
   - **Logs and Events:** These systems gather logs, events, and network traffic data.

2. **Analysis:**
   - **Correlation:** The collected data is analyzed and correlated to identify patterns or signatures associated with known threats.
   - **Behavioral Analysis:** Machine learning and AI algorithms are used to detect anomalies and unusual behaviors that deviate from the baseline.

3. **Detection:**
   - **Rule-based Detection:** Predefined rules and signatures trigger alerts when certain conditions are met (e.g., multiple failed login attempts).
   - **Anomaly Detection:** Advanced systems use statistical models and machine learning to identify deviations from normal behavior, which can indicate new or unknown threats.

4. **Alert Generation:**
   - **Severity Levels:** Alerts are categorized based on severity (e.g., informational, warning, critical) to prioritize response.
   - **Notification:** Alerts are sent to security teams via dashboards, emails, SMS, or integration with other incident response tools.

5. **Response:**
   - **Investigation:** Security analysts investigate the alerts to determine the validity and scope of the potential threat.
   - **Mitigation:** If a threat is confirmed, appropriate actions are taken to mitigate the risk, such as isolating affected systems, applying patches, or blocking malicious IP addresses.
   - **Reporting:** Incidents are documented, and reports are generated for compliance and further analysis.

6. **Feedback and Improvement:**
   - **Tuning:** Based on the investigation outcomes, rules and detection mechanisms are refined to reduce false positives and improve detection accuracy.
   - **Learning:** Continuous learning from past incidents helps in enhancing the overall security posture and readiness against future threats.

By using alerts effectively, organizations can proactively manage and mitigate risks, ensuring a robust defense against cyber threats.

Creating use case alerts based on the MITRE ATT&CK framework involves defining and implementing specific alerts that map to tactics, techniques, and procedures (TTPs) identified in the MITRE ATT&CK matrix. These use cases help in detecting potential threats by recognizing behaviors and activities associated with known adversarial tactics. Here's a step-by-step guide to creating MITRE-based use case alerts:

## MITRE MAPPING

<div>
    <img src="https://img.shields.io/badge/-Reconnaissance-ff4d94?&style=for-the-badge&logo=Suricata&logoColor=white" />
    <img src="https://img.shields.io/badge/-Resource Development-b3ffb3?&style=for-the-badge&logo=Suricata&logoColor=white" />
    <img src="https://img.shields.io/badge/-Initial Access-cc0000?&style=for-the-badge&logo=Elastic&logoColor=white" />
    <img src="https://img.shields.io/badge/-Execution-3333ff?&style=for-the-badge&logo=ProAct&logoColor=white" />
    <img src="https://img.shields.io/badge/-Persistence & Event Management-adad85?&style=for-the-badge&logo=ProAct&logoColor=white" />
    <img src="https://img.shields.io/badge/-Privilege Escalation-0066cc?&style=for-the-badge&logo=ProAct&logoColor=white" />
    <img src="https://img.shields.io/badge/-Defense Evasion-ff0080?&style=for-the-badge&logo=ProAct&logoColor=white" />
    <img src="https://img.shields.io/badge/-Credential Access-ff0080?&style=for-the-badge&logo=ProAct&logoColor=white" />
    <img src="https://img.shields.io/badge/-Discovery-e69900?&style=for-the-badge&logo=ProAct&logoColor=white" />
    <img src="https://img.shields.io/badge/-Lateral Movement-40bf40?&style=for-the-badge&logo=ProAct&logoColor=white" />    
    <img src="https://img.shields.io/badge/-Collection-ff4d94?&style=for-the-badge&logo=Suricata&logoColor=white" />
    <img src="https://img.shields.io/badge/-Command and Control-b3ffb3?&style=for-the-badge&logo=Suricata&logoColor=white" />
    <img src="https://img.shields.io/badge/-Exfiltration-cc0000?&style=for-the-badge&logo=Elastic&logoColor=white" />
    <img src="https://img.shields.io/badge/-Impact-3333ff?&style=for-the-badge&logo=ProAct&logoColor=white" />
</div>

## Step 1: Understand the MITRE ATT&CK Framework
The MITRE ATT&CK framework is a comprehensive matrix of tactics and techniques used by adversaries. It is divided into:

Tactics: The "why" of an attack (e.g., Initial Access, Execution, Persistence).
Techniques: The "how" of an attack (e.g., Phishing, PowerShell, Scheduled Task).

## Step 2: Identify Relevant TTPs
Based on your organization's threat model and environment, identify which TTPs are most relevant. For example, if your organization uses Windows, you might focus on techniques frequently used against Windows systems.

## Step 3: Gather Logs and Data Sources
Ensure that you have access to necessary logs and data sources such as:

Endpoint detection and response (EDR) logs
Network traffic logs
Authentication logs
Application logs

## Step 4: Define Use Cases
Translate the identified TTPs into specific use cases. Each use case should describe the following:

Objective: What you aim to detect.
Tactic and Technique: Corresponding MITRE ATT&CK tactic and technique.
Data Sources: Logs and data required.
Detection Logic: How to identify the suspicious activity.

## Step 5: Implement Detection Logic
Create the actual detection rules using your SIEM or EDR tool. The detection logic can vary based on the platform, but generally involves:

Indicators of Compromise (IoCs): Specific artifacts like file hashes or IP addresses.
Behavioral Indicators: Patterns of behavior such as unusual login times, execution of certain scripts, etc.

## Step 6: Test and Tune
Before deploying the use cases into production, test them thoroughly to ensure they work as expected and do not generate false positives. Fine-tune the logic as necessary.

## Step 7: Deploy and Monitor
Deploy the alerts in your production environment and continuously monitor their effectiveness. Update the use cases as new TTPs emerge or as your environment changes.

Example Use Case: Detecting PowerShell Execution (T1059.001)
Objective: Detect malicious PowerShell execution.

Tactic: Execution

Technique: PowerShell (T1059.001)

Data Sources:

Windows Event Logs (Event ID 4104 for PowerShell Script Block Logging)
EDR logs

## Detection Logic:

Look for suspicious PowerShell commands that are commonly used by attackers, such as those that:
Encode scripts (powershell.exe -EncodedCommand)
Download content from the internet (e.g., Invoke-WebRequest, wget)
Access WMI objects

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/327f6c9c-8d05-4ebc-a8c5-312eb1c1af97)


Example Use Case: Detecting Unusual RDP Activity (T1076)
Objective: Detect unusual Remote Desktop Protocol (RDP) activity that might indicate lateral movement or unauthorized access.

Tactic: Lateral Movement

Technique: Remote Desktop Protocol (T1076)

Data Sources:

Windows Security Event Logs (Event ID 4624 for logon events)
Network traffic logs
RDP session logs
Detection Logic:

Identify RDP sessions initiated from unusual IP addresses.
Detect multiple RDP login attempts from a single IP in a short time frame.
Alert on RDP logins outside of normal business hours.

Example SIEM Rule:

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/e24e69c5-bf95-4116-99db-c75ba68c02eb)

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/db4a1871-56ef-40e4-9dde-89efc4f78e83)

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/605ed5d3-9816-420f-bcf8-b7bea9a17bf5)

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/5c316462-11c0-42e9-af4b-a889f990a325)

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/da3030fb-7ed4-4104-826c-32f644ab0736)

# Index

| Rule Name                                        | Associated Project      |  
|-----------------------------------------------|----------------------------|
| AADInternals PowerShell Cmdlet Execution | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AADInternals%20PowerShell%20Cmdlet%20Execution">AADInternals PowerShell Cmdlet Execution </a>|
| AD Object WriteDAC Access Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AD%20Object%20WriteDAC%20Access%20Detected">AD Object WriteDAC Access Detected </a>|
| AD Privileged Users or Groups Reconnaissance Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AD%20Privileged%20Users%20or%20Groups%20Reconnaissance%20Detected">AD Privileged Users or Groups Reconnaissance Detected</a>|
| Accessibility Features-Registry | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Accessibility%20Features-Registry">Accessibility Features-Registry</a>|
| Accessibility features - Process | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Accessibility%20features%20-%20Process">Accessibility features - Process </a>|
| Account Discovery Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Account%20Discovery%20Detected">Account Discovery Detected</a>|
| Active Directory DLLs Loaded By Office Applications | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Active%20Directory%20DLLs%20Loaded%20By%20Office%20Applications">Active Directory DLLs Loaded By Office Applications</a>|
| Active Directory Replication User Backdoor | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Active%20Directory%20Replication%20User%20Backdoor">Active Directory Replication User Backdoor</a>|
| Active Directory Schema Change Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Active%20Directory%20Schema%20Change%20Detected">Active Directory Schema Change Detected</a>|
| Activity Related to NTDS Domain Hash Retrieval    | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Activity%20Related%20to%20NTDS%20Domain%20Hash%20Retrieval">Activity Related to NTDS Domain Hash Retrieval</a>|
| Addition of SID History to Active Directory Object | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Addition%20of%20SID%20History%20to%20Active%20Directory%20Object">Addition of SID History to Active Directory Object</a>|
| Adobe Flash Use-After-Free Vulnerability Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Adobe%20Flash%20Use-After-Free%20Vulnerability%20Detected">Adobe Flash Use-After-Free Vulnerability Detected</a>|
|Adwind RAT JRAT Detected  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Adwind%20RAT%20JRAT%20Detected">Adwind RAT JRAT Detected </a>|
| Antivirus Exploitation Framework Detection        | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Antivirus%20Exploitation%20Framework%20Detection">Antivirus Exploitation Framework Detection</a>|
| Antivirus Password Dumper Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Antivirus%20Password%20Dumper%20Detected">Antivirus Password Dumper Detected</a>|
| Antivirus Web Shell Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Antivirus%20Web%20Shell%20Detected">Antivirus Web Shell Detected</a>|
| Apache Struts 2 Remote Code Execution Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Apache%20Struts%202%20Remote%20Code%20Execution%20Detected">Apache Struts 2 Remote Code Execution Detected</a>|
| AppCert DLLs Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AppCert%20DLLs%20Detected">AppCert DLLs Detected</a>|
| Application Shimming - File Access Detected        | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Shimming%20-%20File%20Access%20Detected">Application Shimming - File Access Detected</a>|
| Application Whitelisting Bypass via Bginfo Detected    | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20Bginfo%20Detected">Application Whitelisting Bypass via Bginfo Detected</a>|
| Application Whitelisting Bypass via DLL Loaded by odbcconf Detected     | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20DLL%20Loaded%20by%20odbcconf%20Detected">Application Whitelisting Bypass via DLL Loaded by odbcconf Detected </a>|
| Application Whitelisting Bypass via Dnx Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20Dnx%20Detected">Application Whitelisting Bypass via Dnx Detected</a>|
| Application Whitelisting Bypass via Dxcap Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20Dxcap%20Detected">Application Whitelisting Bypass via Dxcap Detected</a>|
| Audio Capture Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Audio%20Capture%20Detected">Audio Capture Detected </a>|
| Authentication Package Detected  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Authentication%20Package%20Detected">Authentication Package Detected</a>|
| Autorun Keys Modification Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Autorun%20Keys%20Modification%20Detected">Autorun Keys Modification Detected</a>|
| BITS Jobs - Network Detected  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/BITS%20Jobs%20-%20Network%20Detected">BITS Jobs - Network Detected</a>|
| BITS Jobs - Process Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/BITS%20Jobs%20-%20Process%20Detected">BITS Jobs - Process Detected</a>|
| Batch Scripting Detected| <a href="https://google.com">Batch Scripting Detected</a>|
| SIEM Implementation and Log Analysis | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Batch%20Scripting%20Detected">Detection Lab</a>|
| Bloodhound and Sharphound Hack Tool Detected  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Bloodhound%20and%20Sharphound%20Hack%20Tool%20Detected">Bloodhound and Sharphound Hack Tool Detected</a>|
| BlueMashroom DLL Load Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/BlueMashroom%20DLL%20Load%20Detected">BlueMashroom DLL Load Detected</a>|
| Browser Bookmark Discovery | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Browser%20Bookmark%20DiscoveryBrowser Bookmark Discovery"> Browser Bookmark Discovery</a>|
|Bypass UAC via CMSTP Detected  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Bypass%20UAC%20via%20CMSTP%20Detected">Bypass UAC via CMSTP Detected</a>|
| Bypass User Account Control using Registry | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Bypass%20User%20Account%20Control%20using%20RegistryBypass User Account Control using Registry">Bypass User Account Control using Registry </a>|
| C-Sharp Code Compilation Using Ilasm Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/C-Sharp%20Code%20Compilation%20Using%20Ilasm%20Detected>C-Sharp Code Compilation Using Ilasm Detected">C-Sharp Code Compilation Using Ilasm Detected</a>|
| CACTUSTORCH Remote Thread Creation Detected    | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CACTUSTORCH%20Remote%20Thread%20Creation%20Detected">CACTUSTORCH Remote Thread Creation Detected</a>|
| CEO Fraud - Possible Fraudulent Email Behavior     | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CEO%20Fraud%20-%20Possible%20Fraudulent%20Email%20Behavior">CEO Fraud - Possible Fraudulent Email Behavior</a>|
| CMSTP Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CMSTP%20Detected">CMSTP Detected </a>|
| CMSTP Execution Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CMSTP%20Execution%20Detected">CMSTP Execution Detected</a>|
| CMSTP UAC Bypass via COM Object Access | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CMSTP%20UAC%20Bypass%20via%20COM%20Object%20Access">CMSTP UAC Bypass via COM Object Access</a>|
| CVE-2019-0708 RDP RCE Vulnerability Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CVE-2019-0708%20RDP%20RCE%20Vulnerability%20Detected">CVE-2019-0708 RDP RCE Vulnerability Detected</a>|
| Capture a Network Trace with netsh | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Capture%20a%20Network%20Trace%20with%20netsh">Capture a Network Trace with netsh</a>|
| Certutil Encode Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Certutil%20Encode%20Detected">Certutil Encode Detected</a>|
| Chafer Activity Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Chafer%20Activity%20Detected">Chafer Activity Detected</a>|
| Change of Default File Association Detected  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Change%20of%20Default%20File%20Association%20Detected">Change of Default File Association Detected</a>|
| Citrix ADC VPN Directory Traversal Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">Citrix ADC VPN Directory Traversal Detected</a>| 
| Clearing of PowerShell Logs Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">Clearing of PowerShell Logs Detected/a>|
| Clipboard Data Access Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Clipboard%20Data%20Access%20Detected">Clipboard Data Access Detected</a>|
| Clop Ransomware Emails Sent to Attacker | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Clop%20Ransomware%20Emails%20Sent%20to%20Attacker">Clop Ransomware Emails Sent to Attacker </a>|
| Incident Response Planning and Execution | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Clop%20Ransomware%20Emails%20Sent%20to%20Attacker">Incident Response Planning and Execution </a>|
| Clop Ransomware Infected Host Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Clop%20Ransomware%20Infected%20Host%20Detected">Clop Ransomware Infected Host Detected</a>|
| Scripting and Automation for Threat Mitigation | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Clop%20Ransomware%20Infected%20Host%20Detected">Scripting and Automation for Threat Mitigation</a>|
| Cmdkey Cached Credentials Recon Detected   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Cmdkey%20Cached%20Credentials%20Recon%20Detected">Cmdkey Cached Credentials Recon Detected</a>|
| CobaltStrike Process Injection Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CobaltStrike%20Process%20Injection%20Detected">CobaltStrike Process Injection Detected</a>|
| Command Obfuscation in Command Prompt| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Command%20Obfuscation%20in%20Command%20Prompt">Command Obfuscation in Command Prompt</a>|
| Command Obfuscation via Character Insertion  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Command%20Obfuscation%20via%20Character%20Insertion">Command Obfuscation via Character Insertion</a>|
| Command Obfuscation via Environment Variable Concatenation Reassembly  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Command%20Obfuscation%20via%20Environment%20Variable%20Concatenation%20Reassembly">Command Obfuscation via Environment Variable Concatenation Reassembly</a>|
| Compiled HTML File Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Compiled%20HTML%20File%20Detected">Compiled HTML File Detected</a>|
| Component Object Model Hijacking Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Component%20Object%20Model%20Hijacking%20Detected">Component Object Model Hijacking Detected</a>|
| Connection to Hidden Cobra Source  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Connection%20to%20Hidden%20Cobra%20Source">Connection to Hidden Cobra Source</a>|
| Console History Discovery Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Console%20History%20Discovery%20Detected">Console History Discovery Detected</a>|
| Control Panel Items - Process Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Control%20Panel%20Items%20-%20Process%20Detected">Control Panel Items - Process Detected</a>|
| Control Panel Items - Registry Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Control%20Panel%20Items%20-%20Registry%20Detected">Control Panel Items - Registry Detected</a>|
| Control Panel Items Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Control%20Panel%20Items%20Detected">Control Panel Items Detected</a>|
| Copy from Admin Share Detected  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Copy%20from%20Admin%20Share%20Detected">Copy from Admin Share Detected</a>|
| Copying Sensitive Files with Credential Data | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Copying%20Sensitive%20Files%20with%20Credential%20Data">Copying Sensitive Files with Credential Data </a>|
| Copyright Violation Email | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Copyright%20Violation%20Email">Copyright Violation Email</a>|
| CrackMapExecWin Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CrackMapExecWin%20Detected">CrackMapExecWin Detected</a>|
| CreateMiniDump Hacktool Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CreateMiniDump%20Hacktool%20Detected">CreateMiniDump Hacktool Detected</a>|
| CreateRemoteThread API and LoadLibrary | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CreateRemoteThread%20API%20and%20LoadLibrary">CreateRemoteThread API and LoadLibrary</a>|
| Credential Access via Input Prompt Detected    | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credential%20Access%20via%20Input%20Prompt%20Detected">Credential Access via Input Prompt Detected </a>|
| Credential Dump Tools Dropped Files Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credential%20Dump%20Tools%20Dropped%20Files%20Detected">Credential Dump Tools Dropped Files Detected </a>|
| Credential Dumping - Process Access | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credential%20Dumping%20-%20Process%20Access">Credential Dumping - Process Access </a>|
| Credential Dumping - Process Creation   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credential%20Dumping%20-%20Process%20Creation">Credential Dumping - Process Creation </a>|
| Credential Dumping - Registry Save | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credential%20Dumping%20-%20Registry%20Save">Credential Dumping - Registry Save </a>|
| Credential Dumping with ImageLoad Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credential%20Dumping%20with%20ImageLoad%20Detected">Credential Dumping with ImageLoad Detected </a>|
| Credentials Access in Files Detected | <a href="Credentials Access in Files Detected">Credentials Access in Files Detected </a>|
| Credentials Capture via Rpcping Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credentials%20Capture%20via%20Rpcping%20Detected">Credentials Capture via Rpcping Detected</a>|
| Credentials in Registry Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Credentials%20in%20Registry%20Detected">Credentials in Registry Detected/a>|
| Curl Start Combination Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Curl%20Start%20Combination%20Detected">Curl Start Combination Detected</a>|
| DCSync detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/DCSync%20detected">DCSync detected</a>|\
| DLL Side Loading Via Microsoft Defender | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/DLL%20Side%20Loading%20Via%20Microsoft%20Defender">DLL Side Loading Via Microsoft Defender</a>|
| Data Compression Detected in Windows | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Data%20Compression%20Detected%20in%20Windows">Data Compression Detected in Windows</a>|
| DenyAllWAF SQL Injection Attack | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/DenyAllWAF%20SQL%20Injection%20Attack">DenyAllWAF SQL Injection Attack</a>|
| Execution of Trojanized 3CX Application | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Execution%20of%20Trojanized%203CX%20Application">Execution of Trojanized 3CX Application</a>|
| Javascript conversion to executable Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Javascript%20conversion%20to%20executable%20Detected">Javascript conversion to executable Detected</a>|
| LSASS Process Access by Mimikatz | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/LSASS%20Process%20Access%20by%20Mimikatz">LSASS Process Access by Mimikatz</a>|
| Malicious use of Scriptrunner Detected| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Malicious%20use%20of%20Scriptrunner%20Detected">Malicious use of Scriptrunner Detected</a>|
| Microsoft SharePoint Remote Code Execution Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Microsoft%20SharePoint%20Remote%20Code%20Execution%20Detected">Microsoft SharePoint Remote Code Execution Detected</a>|
| Mitre - Initial Access - Valid Account - Unauthorized IP Access | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Mitre%20-%20Initial%20Access%20-%20Valid%20Account%20-%20Unauthorized%20IP%20Access">Mitre - Initial Access - Valid Account - Unauthorized IP Access</a>|
| Msbuild Spawned by Unusual Parent Process | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Msbuild%20Spawned%20by%20Unusual%20Parent%20Process">Msbuild Spawned by Unusual Parent Process</a>|
| Process Dump via Resource Leak Diagnostic Tool| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Process%20Dump%20via%20Resource%20Leak%20Diagnostic%20Tool">Process Dump via Resource Leak Diagnostic Tool</a>|
| Proxy Execution via Desktop Setting Control Panel | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Proxy%20Execution%20via%20Desktop%20Setting%20Control%20Panel">Proxy Execution via Desktop Setting Control Panel</a>|
| Regsvr32 Anomalous Activity Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Regsvr32%20Anomalous%20Activity%20Detected">Regsvr32 Anomalous Activity Detected</a>|
| Remote File Execution via MSIEXEC | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Remote%20File%20Execution%20via%20MSIEXEC"> Remote File Execution via MSIEXEC</a>|
| ScreenSaver Registry Key Set Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/ScreenSaver%20Registry%20Key%20Set%20Detected"> ScreenSaver Registry Key Set Detected</a>|
| Suspicious ConfigSecurityPolicy Execution Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20ConfigSecurityPolicy%20Execution%20Detected">Suspicious ConfigSecurityPolicy Execution Detected</a>|
| Suspicious DLL execution via Register-Cimprovider | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20DLL%20execution%20via%20Register-Cimprovider">Suspicious DLL execution via Register-Cimprovider</a>|
| Suspicious Driver Loaded | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20Driver%20Loaded">Suspicious Driver Loaded</a>|
| Suspicious Execution of Gpscript Detected| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20Execution%20of%20Gpscript%20Detected">Suspicious Execution of Gpscript Detected</a>|
| Suspicious File Execution via MSHTA | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20File%20Execution%20via%20MSHTA">Suspicious File Execution via MSHTA</a>|
| SSuspicious Files Designated as System Files Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20Files%20Designated%20as%20System%20Files%20Detected">Suspicious Files Designated as System Files Detected</a>|
| Suspicious Microsoft Equation Editor Child Process | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20Microsoft%20Equation%20Editor%20Child%20Process">Suspicious Microsoft Equation Editor Child Process</a>|
| Suspicious Named Pipe Connection to Azure AD Connect Database | <a href="Suspicious Named Pipe Connection to Azure AD Connect Database">Suspicious Named Pipe Connection to Azure AD Connect Database</a>|
| Suspicious Scheduled Task Creation via Masqueraded XML File | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20Scheduled%20Task%20Creation%20via%20Masqueraded%20XML%20File">Suspicious Scheduled Task Creation via Masqueraded XML File</a>|
| Suspicious WMIC XSL Script Execution | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20WMIC%20XSL%20Script%20Execution">Suspicious WMIC XSL Script Execution</a>|
| Suspicious process related to Rundll32 Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Suspicious%20process%20related%20to%20Rundll32%20Detected">Suspicious process related to Rundll32 Detected</a>|
| SUAC Bypass Attempt via Windows Directory Masquerading| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/UAC%20Bypass%20Attempt%20via%20Windows%20Directory%20Masquerading">DUAC Bypass Attempt via Windows Directory Masquerading</a>|
| UAC Bypass via Sdclt Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/UAC%20Bypass%20via%20Sdclt%20Detected">UAC Bypass via Sdclt Detected </a>|
| Unsigned Image Loaded Into LSASS Process | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Unsigned%20Image%20Loaded%20Into%20LSASS%20Process">Unsigned Image Loaded Into LSASS Process</a>|
| Usage of Sysinternals Tools Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Usage%20of%20Sysinternals%20Tools%20Detected">Usage of Sysinternals Tools Detected</a>|
| Usage of Sysinternals Tools Detected| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Usage%20of%20Sysinternals%20Tools%20Detected">Usage of Sysinternals Tools Detected</a>|
| Windows Command Line Execution with Suspicious URL and AppData Strings| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Windows%20Command%20Line%20Execution%20with%20Suspicious%20URL%20and%20AppData%20Strings">Windows Command Line Execution with Suspicious URL and AppData Strings</a>|
| Windows CryptoAPI Spoofing Vulnerability Detected | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Windows%20CryptoAPI%20Spoofing%20Vulnerability%20Detected">Windows CryptoAPI Spoofing Vulnerability Detected</a>|
| Windows Error Process Masquerading| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Windows%20Error%20Process%20Masquerading">Windows Error Process Masquerading</a>|
| Xwizard DLL Side Loading Detected| <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Xwizard%20DLL%20Side%20Loading%20Detected">Xwizard DLL Side Loading Detected</a>|
| ZIP File Creation or Extraction via Printer Migration CLI Tool | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/ZIP%20File%20Creation%20or%20Extraction%20via%20Printer%20Migration%20CLI%20Tool">ZIP File Creation or Extraction via Printer Migration CLI Tool</a>|
| Data Staging Process Detected in Windows | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Data%20Staging%20Process%20Detected%20in%20Windows">Data Staging Process Detected in Windows|


