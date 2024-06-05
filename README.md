# Mitre-Based-Usecases
This repository is established as part of my personal projects and cybersecurity research endeavors.

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/02e1219d-08b8-4c03-a4b6-77ec011078fa)

# Working of use-cases:

![image](https://github.com/rajeevranjancom/Mitre-Based-Usecases/assets/50344183/dee8e7b8-5aeb-4c02-b2b9-3e0973a8e7bb)



Creating use case alerts based on the MITRE ATT&CK framework involves defining and implementing specific alerts that map to tactics, techniques, and procedures (TTPs) identified in the MITRE ATT&CK matrix. These use cases help in detecting potential threats by recognizing behaviors and activities associated with known adversarial tactics. Here's a step-by-step guide to creating MITRE-based use case alerts:

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

