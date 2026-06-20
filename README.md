# Wazuh Windows Network Detection Lab

A home lab project built to detect suspicious network activity on a Windows endpoint using Wazuh, Syscollector, and Sysmon.

## Overview

This project demonstrates custom Wazuh detection engineering for Windows endpoint monitoring. The lab detects when a host opens a new listening port and when a host connects to suspicious ports commonly associated with command and control activity.

## Tools Used

- Wazuh Manager, Indexer, and Dashboard
- Windows 10 endpoint
- Wazuh Agent
- Sysmon
- Python HTTP server for port testing
- VirtualBox / VMware

## Detection Rules

| Rule ID | Description | MITRE ATT&CK |
|---|---|---|
| 100201 | Host opened a new listening port | Discovery / Network Activity |
| 100202 | Suspicious listening port opened | T1071 |
| 100203 | Outbound connection to suspicious port | T1071 |

## Results

All rules were successfully tested in the Wazuh dashboard. Syscollector detected newly opened listening ports, while Sysmon provided process-level telemetry for outbound network connections.

##

<img width="1915" height="93" alt="100201-new-listening-port" src="https://github.com/user-attachments/assets/b4c2a91a-c44d-4728-9871-d96811f39f7b" />

## 

<img width="2197" height="716" alt="100202-suspicious-listening-port" src="https://github.com/user-attachments/assets/e3965343-4d34-488c-af68-129b643368fb" />

##

<img width="2114" height="744" alt="100203-outbound-suspicious-port" src="https://github.com/user-attachments/assets/fb5388a1-9464-4f4b-8194-4176d4f529be" />

