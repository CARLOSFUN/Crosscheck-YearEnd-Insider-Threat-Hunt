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

