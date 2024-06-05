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

# Index

| Rule Name                                        | Associated Project         |
|-----------------------------------------------|----------------------------|
| AADInternals PowerShell Cmdlet Execution |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AADInternals%20PowerShell%20Cmdlet%20Execution">AADInternals PowerShell Cmdlet Execution</a> |
| AD Object WriteDAC Access Detected | | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AD%20Object%20WriteDAC%20Access%20Detected">AADInternals PowerShell Cmdlet Execution</a> |
| AD Privileged Users or Groups Reconnaissance Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AD%20Privileged%20Users%20or%20Groups%20Reconnaissance%20Detected">AADInternals PowerShell Cmdlet Execution</a> |
| Accessibility Features-Registry | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Accessibility%20Features-Registry">AADInternals PowerShell Cmdlet Execution</a> |
| Accessibility features - Process | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Accessibility%20features%20-%20Process">AADInternals PowerShell Cmdlet Execution</a> |
| Account Discovery Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Account%20Discovery%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Active Directory DLLs Loaded By Office Applications | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Active%20Directory%20DLLs%20Loaded%20By%20Office%20Applications">AADInternals PowerShell Cmdlet Execution</a>|
| Active Directory Replication User Backdoor |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Active%20Directory%20Replication%20User%20Backdoor">AADInternals PowerShell Cmdlet Execution</a>|
| Active Directory Schema Change Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Active%20Directory%20Schema%20Change%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Activity Related to NTDS Domain Hash Retrieval |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Activity%20Related%20to%20NTDS%20Domain%20Hash%20Retrieval">AADInternals PowerShell Cmdlet Execution</a>|
| Addition of SID History to Active Directory Object |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Addition%20of%20SID%20History%20to%20Active%20Directory%20Object">AADInternals PowerShell Cmdlet Execution</a>|
| Admin User Remote Logon Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Admin%20User%20Remote%20Logon%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Adobe Flash Use-After-Free Vulnerability Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Adobe%20Flash%20Use-After-Free%20Vulnerability%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Adwind RAT JRAT Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Adwind%20RAT%20JRAT%20Detected">AADInternals 
| PowerShell Cmdlet Execution</a>| | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Antivirus%20Exploitation%20Framework%20Detection">AADInternals PowerShell Cmdlet Execution</a>|
| Antivirus Exploitation Framework Detection | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Antivirus%20Password%20Dumper%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Antivirus Password Dumper Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Antivirus%20Web%20Shell%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Antivirus Web Shell Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Apache%20Struts%202%20Remote%20Code%20Execution%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Apache Struts 2 Remote Code Execution Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/AppCert%20DLLs%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| AppCert DLLs Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Shimming%20-%20File%20Access%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Application Shimming - File Access Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20Bginfo%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Application Whitelisting Bypass via Bginfo Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20Bginfo%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Application Whitelisting Bypass via DLL Loaded by odbcconf Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20DLL%20Loaded%20by%20odbcconf%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Application Whitelisting Bypass via Dnx Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20Dnx%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Application Whitelisting Bypass via Dxcap Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Application%20Whitelisting%20Bypass%20via%20Dxcap%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Audio Capture Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Audio%20Capture%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Authentication Package Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Authentication%20Package%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Autorun Keys Modification Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Autorun%20Keys%20Modification%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| BITS Jobs - Network Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/BITS%20Jobs%20-%20Network%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| BITS Jobs - Process Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/BITS%20Jobs%20-%20Process%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Batch Scripting Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Batch%20Scripting%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Bloodhound and Sharphound Hack Tool Detected |   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Bloodhound%20and%20Sharphound%20Hack%20Tool%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| BlueMashroom DLL Load Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/BlueMashroom%20DLL%20Load%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Browser Bookmark Discovery |   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Browser%20Bookmark%20Discovery">AADInternals PowerShell Cmdlet Execution</a>|
| Bypass UAC via CMSTP Detected |   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Bypass%20UAC%20via%20CMSTP%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Bypass User Account Control using Registry |   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Bypass%20User%20Account%20Control%20using%20Registry">AADInternals PowerShell Cmdlet Execution</a>|
| C-Sharp Code Compilation Using Ilasm Detected |   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/C-Sharp%20Code%20Compilation%20Using%20Ilasm%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| CACTUSTORCH Remote Thread Creation Detected |   | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CACTUSTORCH%20Remote%20Thread%20Creation%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| CEO Fraud - Possible Fraudulent Email Behavior |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CEO%20Fraud%20-%20Possible%20Fraudulent%20Email%20Behavior">AADInternals PowerShell Cmdlet Execution</a>|
| CMSTP Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CMSTP%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| CMSTP Execution Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CMSTP%20Execution%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| CMSTP UAC Bypass via COM Object Access |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CMSTP%20UAC%20Bypass%20via%20COM%20Object%20Access">AADInternals PowerShell Cmdlet Execution</a>|
| CVE-2019-0708 RDP RCE Vulnerability Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/CVE-2019-0708%20RDP%20RCE%20Vulnerability%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Call to a Privileged Service Failed |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Call%20to%20a%20Privileged%20Service%20Failed">AADInternals PowerShell Cmdlet Execution</a>|
| Capture a Network Trace with netsh |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Capture%20a%20Network%20Trace%20with%20netsh">AADInternals PowerShell Cmdlet Execution</a>|
| Certutil Encode Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Certutil%20Encode%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Chafer Activity Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Chafer%20Activity%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Change of Default File Association Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Change%20of%20Default%20File%20Association%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Citrix ADC VPN Directory Traversal Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|













| Clearing of PowerShell Logs Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals 
 PowerShell Cmdlet Execution</a>|  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Clipboard Data Access Detected | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Clop Ransomware Emails Sent to Attacker | | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Clop Ransomware Infected Host Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Cmdkey Cached Credentials Recon Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| CobaltStrike Process Injection Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Command Obfuscation in Command Prompt |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Command Obfuscation via Character Insertion |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Command Obfuscation via Environment Variable Concatenation Reassembly |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Compiled HTML File Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|
| Component Object Model Hijacking Detected |  | <a href="https://github.com/rajeevranjancom/Mitre-Based-Usecases/blob/main/Citrix%20ADC%20VPN%20Directory%20Traversal%20Detected">AADInternals PowerShell Cmdlet Execution</a>|


| Connection to Hidden Cobra Source |
| Console History Discovery Detected |
| Control Panel Items - Process Detected |
| Control Panel Items - Registry Detected |
| Control Panel Items Detected |
| Copy from Admin Share Detected |
| Copying Sensitive Files with Credential Data |
| Copyright Violation Email |
| CrackMapExecWin Detected |
| CreateMiniDump Hacktool Detected |
| CreateRemoteThread API and LoadLibrary |
| Credential Access via Input Prompt Detected |
| Credential Dump Tools Dropped Files Detected |
| Credential Dumping - Process Access |
| Credential Dumping - Process Creation |
| Credential Dumping - Registry Save |
| Credential Dumping with ImageLoad Detected |
| Credentials Access in Files Detected |
| Credentials Capture via Rpcping Detected |
| Credentials in Registry Detected |
| Curl Start Combination Detected |
| DCSync detected |
| DLL Side Loading Via Microsoft Defender |
| Data Compression Detected in Windows |
| DenyAllWAF SQL Injection Attack |
| Execution of Trojanized 3CX Application |
| Javascript conversion to executable Detected |
| LSASS Process Access by Mimikatz |
| Malicious use of Scriptrunner Detected |
| Microsoft SharePoint Remote Code Execution Detected |
| Mitre - Initial Access - Valid Account - Unauthorized IP Access |
| Msbuild Spawned by Unusual Parent Process |
| Process Dump via Resource Leak Diagnostic Tool |
| Proxy Execution via Desktop Setting Control Panel |
| Regsvr32 Anomalous Activity Detected |
| Remote File Execution via MSIEXEC |
| ScreenSaver Registry Key Set Detected |
| Suspicious ConfigSecurityPolicy Execution Detected |
| Suspicious DLL execution via Register-Cimprovider |
| Suspicious Driver Loaded |
| Suspicious Execution of Gpscript Detected |
| Suspicious File Execution via MSHTA |
| Suspicious Files Designated as System Files Detected |
| Suspicious Microsoft Equation Editor Child Process |
| Suspicious Named Pipe Connection to Azure AD Connect Database |
| Suspicious Scheduled Task Creation via Masqueraded XML File |
| Suspicious WMIC XSL Script Execution |
| Suspicious process related to Rundll32 Detected |
| UAC Bypass Attempt via Windows Directory Masquerading |
| UAC Bypass via Sdclt Detected |
| Unsigned Image Loaded Into LSASS Process |
| Usage of Sysinternals Tools Detected |
| Windows Command Line Execution with Suspicious URL and AppData Strings |
| Windows CryptoAPI Spoofing Vulnerability Detected |
| Windows Error Process Masquerading |
| Xwizard DLL Side Loading Detected | 
| ZIP File Creation or Extraction via Print |

