# 🛡️ Threat Hunt Report: CrossCheck

**Unauthorized Year-End Compensation Data Access & Staging**

---

## 📌 Overview

- **Hunt Name:** CrossCheck
- **Detection Platform:** Microsoft Defender for Endpoint
- **Query Language:** Kusto Query Language (KQL)
- **Operating Systems Observed:** Windows 10 / Windows Server
- **Timeframe Investigated:** December 1–31, 2025

---

## 🎯 Executive Summary

During routine monitoring of year-end financial activity, abnormal access patterns were detected involving compensation and performance review data. What initially appeared as legitimate administrative access evolved into a multi-stage intrusion chain involving:

- Remote session misuse
- PowerShell-based tooling execution
- System reconnaissance
- Sensitive HR document access
- Data staging into compressed archives
- Persistence via registry and scheduled tasks
- Outbound connectivity attempts
- Expansion to a second endpoint

The activity demonstrates intentional discovery, preparation, and attempted exfiltration of sensitive compensation data, affecting multiple systems and user contexts.

---

## 🧩 Environment & Tooling

### Platforms
- Microsoft Defender for Endpoint
- Windows endpoints and servers

### Telemetry Sources
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceNetworkEvents`

---

## 🧠 Investigation Methodology

This hunt followed a hypothesis-driven approach, correlating:

- Remote session metadata
- Process execution chains
- File access patterns
- Persistence mechanisms
- Network telemetry

Each finding builds logically on the previous one, forming a complete intrusion narrative.

---

## 🔍 Findings & Analysis

### 🚩 Flag 01: Initial Endpoint Association

**Objective:** Identify the first endpoint associated with suspicious user activity.

**Finding:** The local account `5y51-d3p7` first appeared on endpoint `sys1-dept`.

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where AccountName =~ "5y51-d3p7"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 01 - Initial Endpoint Association](../screenshots/flag01.png)

---

### 🚩 Flag 02: Remote Session Source Attribution

**Objective:** Identify the remote source initiating access.

**Finding:** Remote session originated from:
- **Source IP:** `192.168.0.110`
- **Remote Device:** `M1-ADMIN`

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where AccountName =~ "5y51-d3p7"
| where IsProcessRemoteSession == true
| project Timestamp, DeviceName, AccountName, ProcessRemoteSessionIP, ProcessRemoteSessionDeviceName
| order by Timestamp asc
```

**Screenshot:**

![Flag 02 - Remote Session Source Attribution](../screenshots/flag02.png)

---

### 🚩 Flag 03: Support-Themed Script Execution

**Objective:** Detect execution of a suspicious PowerShell script.

**Finding:** A payroll-themed PowerShell script executed from a user-writable directory.

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where AccountName contains "5y51-d3p7"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has ".ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 03 - Support-Themed Script Execution](../screenshots/flag03.png)

---

### 🚩 Flag 04: Reconnaissance Activity

**Objective:** Confirm early-stage system enumeration.

**Finding:** Initial reconnaissance executed via identity enumeration.

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where FileName in~ ("whoami.exe","query.exe","tasklist.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 04 - Reconnaissance Activity](../screenshots/flag04.png)

---

### 🚩 Flag 05: Sensitive Bonus File Discovery

**Objective:** Identify access to sensitive compensation data.

**Finding:** Draft bonus matrix file accessed during discovery phase.

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where FileName contains "Bonus"
| project Timestamp, FileName, FolderPath, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

**Screenshot:**

![Flag 05 - Sensitive Bonus File Discovery](../screenshots/flag05.png)

---

### 🚩 Flag 06: Data Staging via Archive Creation

**Objective:** Confirm preparation of data for movement.

**Finding:** A ZIP archive was created shortly after sensitive file access.

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, InitiatingProcessUniqueId
| order by Timestamp asc
```

**Screenshot:**

![Flag 06 - Data Staging via Archive Creation](../screenshots/flag06.png)

---

### 🚩 Flag 07: Outbound Connectivity Test

**Objective:** Validate attempted external connectivity.

**Finding:** Outbound connection attempted to a benign test endpoint.

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-03) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Screenshot:**

![Flag 07 - Outbound Connectivity Test](../screenshots/flag07.png)

---

### 🚩 Flag 08: Registry-Based Persistence

**Objective:** Identify persistence mechanisms.

**Finding:** Persistence established via HKCU Run key.

**KQL:**
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-12-03) .. datetime(2025-12-04))
| where RegistryKey has "CurrentVersion\\Run"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

**Screenshot:**

![Flag 08 - Registry-Based Persistence](../screenshots/flag08.png)

---

### 🚩 Flag 09: Scheduled Task Persistence

**Objective:** Confirm secondary persistence method.

**Finding:** Scheduled task created to maintain execution.

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-03) .. datetime(2025-12-04))
| where ProcessCommandLine has "schtasks"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 09 - Scheduled Task Persistence](../screenshots/flag09.png)

---

## 🚩 Flag 10: Secondary Access to Employee Scorecard Artifact

**Objective:** Identify evidence that a different remote session context accessed employee-related scorecard material.

**Finding:** File telemetry revealed that employee scorecard–related artifacts were accessed under a different remote session context, originating from the remote device:

- **Remote Session Device:** `YE-HELPDESKTECH`

This access occurred shortly after persistence mechanisms were established, indicating continued exploration of sensitive HR data beyond the initial bonus artifacts.

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-03) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where FileName has_any ("Review", "Scorecard")
| project Timestamp, FileName, FolderPath,
         InitiatingProcessRemoteSessionDeviceName, DeviceName
| order by Timestamp asc
```

**Screenshot:**

![Flag 10 - Secondary Access to Employee Scorecard Artifact](../screenshots/flag10.png)

---

## 🚩 Flag 11: Bonus Matrix Activity by a New Remote Session Context

**Objective:** Determine whether additional departments interacted with sensitive bonus payout files.

**Finding:** Subsequent access to bonus-related artifacts was associated with another remote session context:

- **Remote Session Device:** `YE-HRPLANNER`

This activity suggests lateral exposure of compensation data across multiple departments rather than isolated access.

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-03) .. datetime(2025-12-10))
| where DeviceName == "sys1-dept"
| where FileName has ".zip"
| project Timestamp, FileName,
         InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

**Screenshot:**

![Flag 11 - Bonus Matrix Activity by a New Remote Session Context](../screenshots/flag11.png)

---

## 🚩 Flag 12: Performance Review Access Validation

**Objective:** Confirm access to employee performance review materials through user-level tooling.

**Finding:** Process telemetry showed user-level access to performance review documents from a different directory, indicating broader data discovery beyond bonus artifacts.

- **Access Timestamp:** `2025-12-03T07:25:15.6288106Z`

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-03T07:20:00Z) .. datetime(2025-12-03T07:30:00Z))
| where DeviceName == "sys1-dept"
| where ProcessCommandLine has_any ("Review", "Performance")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 12 - Performance Review Access Validation](../screenshots/flag12.png)

---

## 🚩 Flag 13: Approved / Final Bonus Artifact Access

**Objective:** Confirm unauthorized access to a finalized year-end bonus artifact.

**Finding:** Telemetry confirmed access to an approved/final version of a bonus matrix file shortly after earlier draft access, indicating escalation to higher-risk data.

- **Unauthorized Access Timestamp:** `2025-12-03T07:25:39.1653621Z`

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-03T07:20:00Z) .. datetime(2025-12-03T07:30:00Z))
| where DeviceName == "sys1-dept"
| where FileName has "BonusMatrix"
| project Timestamp, FileName, FolderPath,
         InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

**Screenshot:**

![Flag 13 - Approved / Final Bonus Artifact Access](../screenshots/flag13.png)

---

## 🚩 Flag 14: Candidate Archive Creation Location

**Objective:** Identify where a suspicious archive containing candidate-related material was created.

**Finding:** A compressed archive containing candidate data was created in a user-accessible documents directory, consistent with data staging behavior.

- **Archive Path:** `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip`

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-03) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, InitiatingProcessUniqueId
| order by Timestamp asc
```

**Screenshot:**

![Flag 14 - Candidate Archive Creation Location](../screenshots/flag14.png)

---

## 🚩 Flag 15: Outbound Transfer Attempt Timestamp

**Objective:** Confirm whether an outbound transfer attempt occurred after staging.

**Finding:** Network telemetry showed an outbound connection attempt shortly after archive creation, consistent with exfiltration testing.

- **Outbound Attempt Timestamp:** `2025-12-03T07:26:28.5959592Z`

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-03T07:25:00Z) .. datetime(2025-12-03T07:30:00Z))
| where DeviceName == "sys1-dept"
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Screenshot:**

![Flag 15 - Outbound Transfer Attempt Timestamp](../screenshots/flag15.png)

---

## 🚩 Flag 16: Local Log Clearing Attempt Evidence

**Objective:** Identify evidence of attempted log clearing to reduce forensic visibility.

**Finding:** Process creation events showed execution of a system utility commonly used to clear logs.

- **Command Observed:** `"wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational`

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-03) .. datetime(2025-12-04))
| where FileName == "wevtutil.exe"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 16 - Local Log Clearing Attempt Evidence](../screenshots/flag16.png)

---

## 🚩 Flag 17: Second Endpoint Scope Confirmation

**Objective:** Identify additional endpoints involved in the activity chain.

**Finding:** Similar telemetry patterns were observed on a second endpoint:

- **Second Compromised Device:** `main1-srvr`

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-04) .. datetime(2025-12-05))
| where DeviceName != "sys1-dept"
| where ProcessCommandLine has_any ("Bonus", "Review")
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 17 - Second Endpoint Scope Confirmation](../screenshots/flag17.png)

---

## 🚩 Flag 18: Approved Bonus Artifact Access on Second Endpoint

**Objective:** Confirm access to approved bonus artifacts on the second endpoint.

**Finding:** Approved bonus data was accessed again on the second system.

- **Initiating Process Creation Time:** `2025-12-04T03:11:58.6027696Z`

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-04T03:00:00Z) .. datetime(2025-12-04T03:30:00Z))
| where DeviceName == "main1-srvr"
| where ProcessCommandLine has "Bonus"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 18 - Approved Bonus Artifact Access on Second Endpoint](../screenshots/flag18.png)

---

## 🚩 Flag 19: Employee Scorecard Access on Second Endpoint

**Objective:** Confirm repeated employee scorecard access and identify remote session context.

**Finding:** Scorecard files were accessed on the second endpoint via a different remote session device.

- **Remote Session Device:** `YE-FINANCEREVIE`

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-04) .. datetime(2025-12-05))
| where DeviceName == "main1-srvr"
| where FileName has "Scorecard"
| project Timestamp, FileName,
         InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

**Screenshot:**

![Flag 19 - Employee Scorecard Access on Second Endpoint](../screenshots/flag19.png)

---

## 🚩 Flag 20: Staging Directory Identification on Second Endpoint

**Objective:** Identify the directory used for final data consolidation.

**Finding:** Archived review materials were staged in an internal references directory.

- **Staging Path:** `C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip`

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-04) .. datetime(2025-12-05))
| where DeviceName == "main1-srvr"
| where FolderPath has "InternalReferences"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
```

**Screenshot:**

![Flag 20 - Staging Directory Identification on Second Endpoint](../screenshots/flag20.png)

---

## 🚩 Flag 21: Staging Activity Timing on Second Endpoint

**Objective:** Determine when final staging activity occurred.

**Finding:** Final staging activity occurred at:

- **Timestamp:** `2025-12-04T03:15:29.2597235Z`

**KQL:**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-04T03:10:00Z) .. datetime(2025-12-04T03:20:00Z))
| where DeviceName == "main1-srvr"
| where FolderPath has "ArchiveBundles"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
```

**Screenshot:**

![Flag 21 - Staging Activity Timing on Second Endpoint](../screenshots/flag21.png)

---

## 🚩 Flag 22: Outbound Connection Remote IP (Final Phase)

**Objective:** Identify the external destination associated with the final outbound connection attempt.

**Finding:** Network telemetry confirmed a final outbound connection attempt to:

- **Remote IP:** `54.83.21.156`

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-04) .. datetime(2025-12-05))
| where DeviceName == "main1-srvr"
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Screenshot:**

![Flag 22 - Outbound Connection Remote IP (Final Phase)](../screenshots/flag22.png)

---

## 📝 Summary of Continued Findings

This phase of the investigation revealed:

- **Lateral Movement:** Multiple remote session contexts from different organizational units (Helpdesk, HR, Finance)
- **Data Escalation:** Progression from draft documents to approved/final compensation materials
- **Multi-Endpoint Activity:** Expansion to a second system (`main1-srvr`)
- **Anti-Forensics:** Attempted log clearing using `wevtutil.exe`
- **Exfiltration Attempts:** Multiple outbound connection attempts following data staging

The activity demonstrates a coordinated, multi-stage operation with clear intent to access, consolidate, and exfiltrate sensitive year-end compensation and performance review data.

---

**Report Generated:** February 2026  
**Classification:** Internal Use Only

## 📝 Conclusion

This investigation uncovered a sophisticated multi-stage intrusion focused on unauthorized access to sensitive compensation data. The attacker demonstrated knowledge of the environment, employed multiple persistence mechanisms, and attempted to exfiltrate data through staged archives and outbound connections.

---

**Report Generated:** February 2026  
**Classification:** Internal Use Only
