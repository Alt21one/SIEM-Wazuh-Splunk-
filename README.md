# SIEM-Wazuh-Splunk Home Lab

A cybersecurity home lab project built to simulate endpoint monitoring, custom detection engineering, and SIEM alerting using Wazuh, Sysmon, and Windows telemetry.

This project focuses on detecting suspicious endpoint behavior such as newly opened listening ports, outbound connections to suspicious ports, process activity, and PowerShell-based command execution.

## Overview

This lab demonstrates how a Windows endpoint can be monitored using Wazuh and Sysmon, with custom detection rules written to identify activity that may indicate attacker behavior or command-and-control activity.

The project includes:

- Wazuh Manager, Indexer, and Dashboard
- Windows endpoint monitoring
- Sysmon event collection
- Syscollector inventory monitoring
- Custom Wazuh rules
- Detection write-ups
- Screenshots of triggered alerts

## Lab Architecture

```text
Host Machine
│
├── Ubuntu Server VM
│   └── Wazuh Manager + Indexer + Dashboard
│
└── Windows 10/11 VM
    ├── Wazuh Agent
    ├── Sysmon
    └── Syscollector
```
