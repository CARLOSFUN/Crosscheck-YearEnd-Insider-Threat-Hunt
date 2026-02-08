
# Crosscheck  
## Year End Compensation and Performance Data Threat Hunt

This repository contains a complete SOC style threat hunt write up for a simulated environment investigation involving suspicious access to year end compensation and performance review data.

## What is included
- SOC Threat Hunt Report: `report/Threat_Hunt_Report.md`
- KQL Library: `kql/` (queries per flag so you can re run and capture screenshots)
- Timeline: `timeline/attack_timeline.md`
- Screenshots: `screenshots/` (evidence images used in the report)

## How to use this repo
1. Open `kql/` and run each query in Microsoft Defender for Endpoint Advanced Hunting
2. Capture screenshots of the results for each flag
3. Save screenshots in `screenshots/` using the naming guide in `screenshots/README.md`
4. Update the report sections with your screenshot links as you go

## Disclaimer
All data in this repository is from a lab or simulated environment. No real organization data is included. IPs, usernames, hostnames, and file paths are part of the training scenario.
