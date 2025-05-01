# Threat Hunt Lab: PowerShell Suspicious Web Request

<img width="850" alt="Screen Shot 2025-04-29 at 10 24 03 PM" src="https://github.com/user-attachments/assets/29b01993-7f4e-4efc-ab67-cc18348c8b47" />

**Author:** James Moore  
**Date:** April 29, 2025  
**Lab Type:** Threat Hunting / Incident Response / Malicious Script Detection

---

## Scenario Overview

This lab focuses on detecting and investigating suspicious PowerShell activity on a Windows 10 virtual machine. The scenario simulated a user unknowingly executing PowerShell commands that downloaded and ran multiple `.ps1` scripts from GitHub, mimicking common attacker behavior like ransomware, exfiltration, and network scanning.

Detection was based on identifying the use of `Invoke-WebRequest` in PowerShell, and verifying the execution of the downloaded scripts using Microsoft Sentinel and Microsoft Defender for Endpoint (MDE).

---

### Step 1: PowerShell Web Request Detection Query

**KQL Query Used:**

```kql
let TargetHostname = "win10vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated desc
```

**Purpose:**
Detect usage of PowerShell to download remote content using Invoke-WebRequest.

**Query results showing suspicious PowerShell downloads.**

<img width="800" alt="Screen Shot 2025-04-29 at 7 50 12 PM" src="https://github.com/user-attachments/assets/3394fc97-0412-4ffa-8f49-29490214e452" />

---

### Step 2: Sentinel Alert Creation
Created a Scheduled Query Rule in Microsoft Sentinel:
Rule Name: PowerShell Suspicious Web Request

- Severity: Medium
- Trigger: Any use of Invoke-WebRequest
- Entity mapping: DeviceName, AccountName, ProcessCommandLine
- Action: Automatically create an incident when triggered

**Sentinel rule configuration and alert setup.**

<img width="800" alt="Screen Shot 2025-04-29 at 7 49 37 PM" src="https://github.com/user-attachments/assets/54e1f23b-df3a-4b38-86cc-c6cf8a03fd4e" />


---

### Step 3: Confirm Execution of Downloaded Scripts
KQL Query Used:

```kql 

let TargetHostname = "win10vm"; 
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname 
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

**Result:**
Confirmed execution of all four .ps1 scripts on the win10vm.

**Showing script execution from MDE logs.**

<img width="800" alt="Screen Shot 2025-04-29 at 7 53 36 PM" src="https://github.com/user-attachments/assets/7377cf25-3426-4c75-8338-973de8317d31" />

---

## Step 4: Script Behavior Analysis

## Script	Description
- pwncrypt.ps1	Simulates file encryption / ransomware behavior
- exfiltratedata.ps1	Simulates data exfiltration
- portscan.ps1	Performs a basic network port scan
- eicar.ps1	Contains the EICAR test string to trigger antivirus without causing harm

---

### Step 5: Containment and Remediation Actions
- Isolated win10vm using Microsoft Defender for Endpoint
- Ran a full anti-malware scan via MDE
- Removed device from isolation after verification
- Assigned user to enhanced security awareness training
- Drafted policy to restrict PowerShell usage for non-essential users

**Device isolation**

<img width="800" alt="Screen Shot 2025-04-29 at 7 55 01 PM" src="https://github.com/user-attachments/assets/fc4819a2-fa6e-405b-8802-12703e107018" />

**Anti-Virus Scan**

<img width="800" alt="Screen Shot 2025-04-29 at 7 55 24 PM" src="https://github.com/user-attachments/assets/0f4c9138-e68d-4925-903c-6e1e07ab1c6c" />

---
## Framework Mapping

**🧠 MITRE ATT&CK**
- T1059.001 – PowerShell
- T1105 – Ingress Tool Transfer
- T1562.001 – Impair Defenses: Execution Policy Bypass
- T1036 – Masquerading

**🔁 Cyber Kill Chain**

- Delivery – Scripts downloaded via PowerShell from GitHub
- Exploitation – Execution of .ps1 scripts
- Installation – Scripts dropped in C:\\ProgramData
- Command & Control – Simulated exfil behavior
- Actions on Objectives – Port scanning, ransomware simulation

**🔐 NIST 800-61**

- Detection & Analysis – Logs detected via Sentinel Analytics Rule
- Containment – Device isolated in MDE
- Eradication & Recovery – Scanned and cleared for reentry
- Post-Incident Activity – Policy updates, user training

**Status**

- Incident was classified as a True Positive.
- Scripts were confirmed executed.
- System was contained, cleaned, and user re-educated.
- Preventive measures and improved policy were implemented.
