# Crosscheck  
## SOC Threat Hunt Report: Year End Compensation and Performance Data

**Analyst:** Carlos Funez  
**Platform:** Microsoft Defender for Endpoint Advanced Hunting  
**Timeframe Investigated:** December 1 to December 31, 2025  
**Primary Endpoints:** sys1-dept, main1-srvr  

---

## Executive Summary

Routine monitoring during year end compensation and performance review activity revealed abnormal access patterns that initially resembled legitimate administrative behavior. Investigation confirmed a multi stage sequence including unauthorized PowerShell execution, reconnaissance, sensitive HR data access, data staging into archives, persistence mechanisms, outbound transfer testing, attempted log clearing, and expansion to a second endpoint. The activity is consistent with hands on keyboard misuse of access and preparation for data exfiltration.

---

## Scenario

At the onset of December, routine monitoring detected irregular access patterns during year end compensation and performance review activities. What initially appeared as legitimate administrative and departmental behavior revealed a multi stage sequence involving unauthorized script execution, sensitive file access, data staging, persistence mechanisms, and outbound communication attempts. The investigation correlated endpoint telemetry across multiple user contexts and systems to reconstruct the access chain and determine how year end bonus and performance data was accessed, prepared, and transmitted.

---

## Scope

### Endpoints
- Initial endpoint: `sys1-dept`
- Second endpoint: `main1-srvr`

### Accounts and remote session context
- Local account observed: `5y51-d3p7`
- Remote session IP: `192.168.0.110`
- Remote session devices observed: `YE-HELPDESKTECH`, `YE-HRPLANNER`, `YE-FINANCEREVIE`

### Sensitive artifacts involved
- Draft bonus file: `BonusMatrix_Draft_v3.xlsx`
- Approved bonus file: `BonusMatrix_Q4_Approved.xlsx`
- Candidate archive: `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip`
- Final staging archive: `C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip`
- Final outbound destination IP: `54.83.21.156`

---

## Findings Summary

| Flag | What was confirmed | Key value |
|---|---|---|
| 01 | Initial endpoint association | sys1-dept |
| 02 | Remote session source IP | 192.168.0.110 |
| 03 | Support themed PowerShell execution | "powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1 |
| 04 | First recon command | "whoami.exe" /all |
| 05 | First sensitive bonus file accessed | BonusMatrix_Draft_v3.xlsx |
| 06 | Staging archive process unique ID | 2533274790396713 |
| 07 | First outbound connectivity test | 2025-12-03T06:27:31.1857946Z |
| 08 | Run key persistence path | HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| 09 | Scheduled task persistence | BonusReviewAssist |
| 10 | Scorecard access other remote session | YE-HELPDESKTECH |
| 11 | Bonus activity other remote session | YE-HRPLANNER |
| 12 | Performance review access timestamp | 2025-12-03T07:25:15.6288106Z |
| 13 | Sensitive read of approved bonus artifact | 2025-12-03T07:25:39.1653621Z |
| 14 | Candidate archive location | C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip |
| 15 | Outbound POST transfer attempt timestamp | 2025-12-03T07:26:28.5959592Z |
| 16 | Log clearing attempt | "wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational |
| 17 | Second endpoint scope confirmation | main1-srvr |
| 18 | Approved bonus access on second endpoint process creation time | 2025-12-04T03:11:58.6027696Z |
| 19 | Scorecard access second endpoint remote device | YE-FINANCEREVIE |
| 20 | Staging directory and archive path on second endpoint | C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip |
| 21 | Staging activity timestamp on second endpoint | 2025-12-04T03:15:29.2597235Z |
| 22 | Final outbound remote IP | 54.83.21.156 |

---

## Evidence and KQL Library

All queries used to reproduce each flag are stored in the `kql/` folder. Each findings section below references the exact KQL file and the screenshot that should be captured.

Next section will include Flag by Flag detail with KQL blocks and screenshot placeholders.

---
## Flag by Flag Findings and Evidence

This section documents each confirmed finding from the Crosscheck threat hunt.  
Each flag includes the objective, confirmed finding, KQL used to reproduce evidence, and a placeholder for screenshots.

All queries use the following timeframe unless otherwise stated:

Time range: 2025-12-01 through 2026-01-01

---

## Flag 01: Initial Endpoint Association

### Objective
Determine which endpoint first shows activity tied to the user context involved in the chain.

### Confirmed Finding
The local account `5y51-d3p7` was first observed executing processes on endpoint `sys1-dept`.

### KQL
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where AccountName =~ "5y51-d3p7"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
````

### Evidence

![Flag 01](../screenshots/flag01_initial_endpoint.png)

---

## Flag 02: Remote Session Source Attribution

### Objective

Identify the remote session source IP tied to the initiating access on the first endpoint.

### Confirmed Finding

Remote session source IP: `192.168.0.110`

### KQL

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where DeviceName == "sys1-dept"
| where AccountName =~ "5y51-d3p7"
| where IsProcessRemoteSession == true or IsInitiatingProcessRemoteSession == true
| project Timestamp, DeviceName, AccountName,
          ProcessRemoteSessionIP, ProcessRemoteSessionDeviceName,
          InitiatingProcessRemoteSessionIP, InitiatingProcessRemoteSessionDeviceName,
          FileName, ProcessCommandLine
| order by Timestamp asc
```

### Evidence

![Flag 02](../screenshots/flag02_remote_session_ip.png)

---

## Flag 03: Support Script Execution Confirmation

### Objective

Confirm execution of a support-themed PowerShell script from a user-accessible directory.

### Confirmed Finding

```text
"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1
```

### KQL

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where DeviceName == "sys1-dept"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "PayrollSupportTool.ps1"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### Evidence

![Flag 03](../screenshots/flag03_payroll_support_script_exec.png)

---

## Flag 04: System Reconnaissance Initiation

### Objective

Identify the first reconnaissance action used to gather host and user context.

### Confirmed Finding

```text
"whoami.exe" /all
```

### KQL

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where DeviceName == "sys1-dept"
| where FileName == "whoami.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

### Evidence

![Flag 04](../screenshots/flag04_first_recon_command.png)

---

## Flag 05: Sensitive Bonus File Discovery

### Objective

Identify the first sensitive year-end bonus-related file accessed.

### Confirmed Finding

Sensitive file accessed: `BonusMatrix_Draft_v3.xlsx`

### KQL

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where DeviceName == "sys1-dept"
| where FileName == "BonusMatrix_Draft_v3.xlsx"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

### Evidence

![Flag 05](../screenshots/flag05_sensitive_bonus_file.png)

---

## Flag 06: Data Staging Activity

### Objective

Confirm sensitive data was staged into an archive.

### Confirmed Finding

InitiatingProcessUniqueId: `2533274790396713`

### KQL

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where DeviceName == "sys1-dept"
| where FileName endswith ".zip"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessUniqueId
| order by Timestamp asc
```

### Evidence

![Flag 06](../screenshots/flag06_data_staging.png)

---

## Flag 07: Outbound Connectivity Test

### Objective

Confirm outbound connectivity was tested prior to data transfer.

### Confirmed Finding

First outbound attempt: `2025-12-03T06:27:31.1857946Z`

### KQL

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2026-01-01))
| where DeviceName == "sys1-dept"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### Evidence

![Flag 07](../screenshots/flag07_outbound_test.png)

---

## Flag 08: Registry-Based Persistence

### Objective

Identify persistence established via a user Run key.

### Confirmed Finding

```text
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### KQL

```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where RegistryKey has "CurrentVersion\\Run"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

### Evidence

![Flag 08](../screenshots/flag08_registry_persistence.png)

---

## Flag 09: Scheduled Task Persistence

### Objective

Confirm scheduled task persistence was used.

### Confirmed Finding

Task name: `BonusReviewAssist`

### KQL

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-12-01) .. datetime(2026-01-01))
| where ProcessCommandLine has "BonusReviewAssist"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

### Evidence

![Flag 09](../screenshots/flag09_scheduled_task.png)

---

## Flag 10: Secondary Scorecard Access

### Objective

Identify scorecard access from a different remote session.

### Confirmed Finding

Remote session device: `YE-HELPDESKTECH`

### KQL

```kql
DeviceFileEvents
| where FileName has "Scorecard"
| project Timestamp, FileName, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```

### Evidence

![Flag 10](../screenshots/flag10_scorecard_access.png)

```

---

## Next steps (recommended)
1. Paste this block into GitHub  
2. Re-run each KQL query  
3. Capture screenshots and drop them into `/screenshots`  
4. I’ll finish **Flags 11–22 in the same exact format**, then:
   - MITRE ATT&CK mapping  
   - IOC table  
   - Analyst recommendations  
   - Lessons learned  
   - LinkedIn post draft  

When ready, say:  
**“Write Flags 11–22 in the same GitHub format”**
```
