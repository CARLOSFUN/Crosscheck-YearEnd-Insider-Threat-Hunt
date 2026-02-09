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

![Flag 01 - Initial Endpoint Association](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag01.png)

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

![Flag 02 - Remote Session Source Attribution](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag02.png)

---

### 🚩 Flag 03: Support-Themed Script Execution

**Objective:** Detect execution of a suspicious PowerShell script.

**Finding:** A payroll-themed PowerShell script executed from a user-writable directory.

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has ".ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 03 - Support-Themed Script Execution](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag03.png)

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

![Flag 04 - Reconnaissance Activity](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag04.png)

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

![Flag 05 - Sensitive Bonus File Discovery](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag05.png)

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

![Flag 06 - Data Staging via Archive Creation](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag06.png)

---

### 🚩 Flag 07: Outbound Connectivity Test

**Objective:** Validate attempted external connectivity.

**Finding:** Outbound connection attempted to a benign test endpoint.

**KQL:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-04))
| where DeviceName == "sys1-dept"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Screenshot:**

![Flag 07 - Outbound Connectivity Test](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag07.png)

---

### 🚩 Flag 08: Registry-Based Persistence

**Objective:** Identify persistence mechanisms.

**Finding:** Persistence established via HKCU Run key.

**KQL:**
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where RegistryKey has "CurrentVersion\Run"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

**Screenshot:**

![Flag 08 - Registry-Based Persistence](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag08.png)

---

### 🚩 Flag 09: Scheduled Task Persistence

**Objective:** Confirm secondary persistence method.

**Finding:** Scheduled task created to maintain execution.

**KQL:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2025-12-04))
| where ProcessCommandLine has "schtasks"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Screenshot:**

![Flag 09 - Scheduled Task Persistence](Crosscheck-YearEnd-Insider-Threat-Hunt/screenshots/flag09.png)

---

## 📝 Conclusion

This investigation uncovered a sophisticated multi-stage intrusion focused on unauthorized access to sensitive compensation data. The attacker demonstrated knowledge of the environment, employed multiple persistence mechanisms, and attempted to exfiltrate data through staged archives and outbound connections.

---

**Report Generated:** February 2026  
**Classification:** Internal Use Only
