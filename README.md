# 🛡️ Crosscheck

## Multi-Stage Year-End Compensation & Performance Data Exfiltration Investigation

<div align="center">

![Threat Hunting](https://img.shields.io/badge/Type-Threat%20Hunting-red?style=for-the-badge)
![Microsoft Defender](https://img.shields.io/badge/Platform-Microsoft%20Defender-blue?style=for-the-badge)
![KQL](https://img.shields.io/badge/Language-KQL-orange?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-success?style=for-the-badge)

**A comprehensive SOC-style threat hunt investigating unauthorized access to sensitive year-end compensation and performance review data across multiple endpoints.**

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [What's Inside](#whats-inside)
- [Investigation Summary](#investigation-summary)
- [Key Findings](#key-findings)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Detection Rules](#detection-rules)
- [Repository Structure](#repository-structure)
- [Skills Demonstrated](#skills-demonstrated)
- [Disclaimer](#disclaimer)

---

## 🎯 Overview

**Crosscheck** is a professional-grade threat hunting investigation that documents the detection, analysis, and remediation of a sophisticated multi-stage intrusion targeting sensitive HR compensation data. This repository showcases advanced SOC analyst capabilities including hypothesis-driven threat hunting, multi-source telemetry correlation, and actionable detection engineering.

### Investigation Scope

| **Attribute** | **Details** |
|---------------|-------------|
| **Hunt Name** | CrossCheck |
| **Investigation Period** | December 1–31, 2025 |
| **Detection Platform** | Microsoft Defender for Endpoint |
| **Query Language** | Kusto Query Language (KQL) |
| **Affected Systems** | 2 endpoints across IT and server infrastructure |
| **Remote Session Sources** | 4 distinct devices (IT, Helpdesk, HR, Finance) |
| **MITRE ATT&CK Techniques** | 10 techniques across 7 tactics |

### What Makes This Investigation Unique?

✅ **Enterprise-Grade Documentation** - SOC II/IR-ready threat hunt report  
✅ **Complete Attack Chain** - Full lifecycle from initial access to exfiltration  
✅ **Production-Ready Detections** - 8 KQL rules deployable in production  
✅ **Multi-Endpoint Scope** - Tracks lateral movement across systems  
✅ **Business Impact Analysis** - Translates technical findings into executive risk language  
✅ **Visual Timeline** - Reconstructed attack progression with timestamps

---

## 📦 What's Inside

### 📄 SOC Threat Hunt Report
**Location:** [`report/Threat_Hunt_Report.md`](report/Threat_Hunt_Report.md)

A comprehensive 22-flag investigation documenting:
- Detailed findings for each indicator of compromise
- KQL queries used for detection and hunting
- Evidence screenshots for each discovery
- Complete attack timeline with timestamps
- MITRE ATT&CK technique mapping
- Business impact assessment
- Detection and hardening recommendations
- Analyst reflection and methodology

### 📸 Evidence Screenshots
**Location:** [`screenshots/`](screenshots/)

Visual evidence supporting all 22 investigation flags:
- Flag 01-09: Initial endpoint activity (sys1-dept)
- Flag 10-16: Data escalation and persistence
- Flag 17-22: Lateral movement to second endpoint (main1-srvr)

All screenshots are referenced in the main threat hunt report with contextual analysis.

---

## 🔍 Investigation Summary

During routine monitoring of year-end financial activity, the Security Operations Center detected abnormal access patterns involving compensation and performance review data. The investigation uncovered a sophisticated, multi-stage intrusion chain:

### Attack Progression

```
Initial Access (Dec 1)
    ↓
PowerShell Execution (Dec 3)
    ↓
System Reconnaissance
    ↓
Sensitive Data Discovery
    ↓
Data Staging (ZIP Archives)
    ↓
Persistence Mechanisms
    ↓
Anti-Forensic Measures
    ↓
Lateral Movement (Dec 4)
    ↓
Attempted Exfiltration
```

### Adversary Behavior

- **Remote Session Misuse** from multiple organizational contexts
- **PowerShell-Based Tooling** for reconnaissance and data manipulation
- **Systematic Data Collection** targeting bonus matrices, performance reviews, scorecards
- **Dual Persistence** via registry Run keys and scheduled tasks
- **Log Clearing Attempts** using wevtutil.exe
- **Multi-Endpoint Activity** affecting workstation and server infrastructure
- **Exfiltration Attempts** through outbound connections to external IPs

---

## 🚨 Key Findings

### Compromised Assets

**Endpoints:**
- `sys1-dept` (Initial target - workstation)
- `main1-srvr` (Secondary target - server infrastructure)

**Account:**
- `5y51-d3p7` (Suspicious local account with abnormal remote session activity)

**Remote Session Sources:**
- `M1-ADMIN` (192.168.0.110) - IT Administration
- `YE-HELPDESKTECH` - Helpdesk
- `YE-HRPLANNER` - HR Planning
- `YE-FINANCEREVIE` - Finance Review

### Data at Risk

- Year-end bonus matrices (draft and approved versions)
- Employee performance reviews
- Employee scorecards and evaluations
- Candidate evaluation packages
- Compensation planning documents

### Indicators of Compromise (IOCs)

```
Source IP:           192.168.0.110
Exfiltration IP:     54.83.21.156

Staging Locations:
- C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip
- C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip

Registry Persistence:
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Anti-Forensics:
- wevtutil.exe cl Microsoft-Windows-PowerShell/Operational
```

---

## 🗺️ MITRE ATT&CK Coverage

This investigation mapped adversary behavior to **10 techniques** across **7 tactics**:

| **Tactic** | **Technique** | **ID** | **Evidence** |
|------------|---------------|--------|--------------|
| **Initial Access** | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Remote session from 192.168.0.110 |
| **Execution** | PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Payroll-themed .ps1 script |
| **Discovery** | Account Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | whoami.exe execution |
| **Discovery** | System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | query.exe, tasklist.exe |
| **Persistence** | Registry Run Keys | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | HKCU Run key modification |
| **Persistence** | Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | schtasks.exe task creation |
| **Defense Evasion** | Clear Windows Event Logs | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | wevtutil.exe log clearing |
| **Collection** | Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | HR file access |
| **Collection** | Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | ZIP archive creation |
| **Exfiltration** | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | Outbound connections |
| **Lateral Movement** | Remote Services | [T1021](https://attack.mitre.org/techniques/T1021/) | Expansion to main1-srvr |

---

## 🔎 Detection Rules

This investigation produced **8 production-ready KQL detection rules** that can be deployed in Microsoft Defender for Endpoint or Azure Sentinel:

### 1. PowerShell from User Directories
Detects script execution from non-standard, user-writable locations

### 2. HKCU Run Key Persistence
Identifies user-level persistence mechanisms via registry

### 3. Scheduled Task Creation
Monitors scheduled task-based persistence establishment

### 4. Suspicious Archive Creation
Detects data staging through rapid ZIP file creation

### 5. Remote Session Context Changes
Identifies anomalous remote session patterns

### 6. PowerShell Log Clearing
Detects anti-forensic log clearing attempts

### 7. Post-Archive Network Activity
Correlates data staging with exfiltration attempts

### 8. HR Directory Remote Access
Monitors sensitive directory access from remote sessions

All detection rules are documented in the main threat hunt report with full KQL queries and tuning guidance.

---

## 📁 Repository Structure

```
Crosscheck/
│
├── README.md                    # This file - Project overview
│
├── report/                      # Main investigation documentation
│   └── Threat_Hunt_Report.md    # Complete SOC-style threat hunt report
│                                 # (22 flags, timeline, KQL queries, MITRE mapping)
│
├── screenshots/                 # Evidence supporting investigation findings
│   ├── flag01.png               # Initial endpoint association
│   ├── flag02.png               # Remote session source
│   ├── flag03.png               # Script execution
│   ├── ...                      # Flags 04-21
│   └── flag22.png               # Final exfiltration attempt
│
└── LICENSE                      # MIT License
```

### File Descriptions

- **`report/Threat_Hunt_Report.md`** - Complete investigation with findings, timeline, analysis, detections, and recommendations
- **`screenshots/`** - Visual evidence referenced throughout the report (22 flags)
- **`README.md`** - This overview document
- **`LICENSE`** - Repository license information

---

## 💼 Skills Demonstrated

This investigation showcases professional competencies in:

### Technical Skills
✅ **Microsoft Defender for Endpoint** - Advanced hunting and EDR analysis  
✅ **Kusto Query Language (KQL)** - Complex query development and optimization  
✅ **Threat Hunting** - Hypothesis-driven methodology and pattern detection  
✅ **Lateral Movement Detection** - Cross-device activity correlation  
✅ **Data Exfiltration Analysis** - Complete attack chain validation  
✅ **Persistence Analysis** - Registry and scheduled task forensics  
✅ **Anti-Forensics Detection** - Log clearing identification  
✅ **Windows Event Log Analysis** - PowerShell operational logging  
✅ **Remote Session Analysis** - Context-based access patterns  
✅ **Network Traffic Analysis** - Outbound connection monitoring

### Analytical Capabilities
✅ **Multi-Source Telemetry Correlation** - Process, file, registry, network events  
✅ **Temporal Pattern Analysis** - Timeline reconstruction and operational tempo  
✅ **Behavioral Analytics** - Anomaly detection and baseline deviation  
✅ **Root Cause Analysis** - Attack chain reconstruction  
✅ **IOC Development** - Indicator identification and documentation

### Frameworks & Methodologies
✅ **MITRE ATT&CK Framework** - Technique mapping and coverage analysis  
✅ **Cyber Kill Chain** - Attack phase identification  
✅ **Incident Response** - Detection, analysis, containment, eradication  
✅ **Detection Engineering** - Production-ready rule development

### Communication
✅ **Technical Report Writing** - SOC-grade documentation  
✅ **Executive Summary Development** - Business risk translation  
✅ **Business Impact Assessment** - Financial and regulatory implications  
✅ **Visual Documentation** - Evidence presentation and timeline graphics

---

## ⚠️ Disclaimer

**Important:** All data, indicators, and scenarios in this repository are from a **lab/simulated training environment**.

- ❌ No real organization data is included
- ❌ No actual security incidents are documented
- ❌ All IPs, usernames, hostnames, and file paths are fictitious

**Purpose:** This repository is created for:
- Educational demonstrations
- Portfolio showcasing
- Security training scenarios
- Threat hunting methodology examples

All findings represent simulated adversary behavior in a controlled lab environment designed for security analysis training.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **MITRE ATT&CK** - Framework for adversary behavior mapping
- **Microsoft Security Team** - Excellent EDR platform and documentation
- **Security Community** - Continuous knowledge sharing and collaboration

---

<div align="center">

### 🛡️ Defense Through Detection

---

![GitHub last commit](https://img.shields.io/github/last-commit/carlosfun/crosscheck?style=flat-square)
![GitHub repo size](https://img.shields.io/github/repo-size/carlosfun/crosscheck?style=flat-square)
![GitHub](https://img.shields.io/github/license/carlosfun/crosscheck?style=flat-square)

**[⬆ Back to Top](#-crosscheck)**

</div>
