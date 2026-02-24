# Linux Endpoint Detection Engineering – Nmap Recon Execution

## Overview

This lab was conducted in an Azure-hosted enterprise simulation environment to demonstrate end-to-end detection engineering using Microsoft Defender for Endpoint (Linux) and Microsoft Sentinel.

The objective was to simulate network reconnaissance activity on a monitored Linux endpoint and build a custom analytics rule capable of generating a fully enriched incident within Microsoft Sentinel.

This project validates:

* Linux EDR telemetry ingestion
* Advanced hunting validation
* Custom KQL detection engineering
* Scheduled analytics rule creation
* Entity mapping (Host, Account, Process)
* MITRE ATT&CK alignment
* Incident lifecycle management
* Investigation graph correlation

---

## Lab Environment

| Component      | Details                                 |
| -------------- | --------------------------------------- |
| VM Name        | kali                                    |
| OS             | Kali Linux (Debian-based)               |
| EDR            | Microsoft Defender for Endpoint (Linux) |
| SIEM           | Microsoft Sentinel                      |
| Log Workspace  | law-cyber-range                         |
| Cloud Platform | Microsoft Azure                         |

---

## Phase 1 – EDR Validation

Microsoft Defender for Endpoint was installed and verified healthy on the Linux endpoint.

<p align="left">
  <img src="assets/Screenshot 2026-02-23 113115.png" width="600">
  <img src="assets/Screenshot 2026-02-23 113336.png" width="600">
  <img src="assets/Screenshot 2026-02-23 113616.png" width="600">
  <img src="assets/Screenshot 2026-02-23 113908.png" width="600">
  <img src="assets/Screenshot 2026-02-23 113925.png" width="600">
  <img src="assets/Screenshot 2026-02-23 114923.png" width="600">  
</p>

Telemetry ingestion was validated using Advanced Hunting queries in Microsoft Sentinel.

### Screenshot – Advanced Hunting Query Results

<p align="left">
  <img src="assets/Screenshot 2026-02-23 115611.png" width="600">
  <img src="assets/Screenshot 2026-02-23 115929.png" width="600">  
</p>

---

## Phase 2 – Adversary Simulation

To simulate discovery behavior aligned with MITRE ATT&CK T1046 (Network Service Scanning), the following command was executed:

```
nmap 8.8.8.8
```

This generated process telemetry captured by Defender and forwarded into Sentinel.

<p align="left">
  <img src="assets/Screenshot 2026-02-23 120707.png" width="600">
</p>

---

## Phase 3 – Detection Engineering

A custom scheduled analytics rule was created using KQL:

```kql
DeviceProcessEvents
| where DeviceName contains "kali"
| where ProcessCommandLine has "nmap"
| extend HostCustomEntity = DeviceName
| extend AccountCustomEntity = AccountName
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

Detection configuration:

* Table: `DeviceProcessEvents`
* Severity: Medium
* MITRE ATT&CK: Discovery – T1046
* Rule Type: Scheduled Analytics Rule

<p align="left">
  <img src="assets/Screenshot 2026-02-24 135050.png" width="600">
  <img src="assets/Screenshot 2026-02-23 121120.png" width="600">  
</p>

---

## Phase 4 – Entity Mapping

Proper entity enrichment was configured to enable investigation graph correlation.

Mapped Entities:

* Host → DeviceName
* Account → AccountName
* Process → ProcessCommandLine

<p align="left">
  <img src="assets/Screenshot 2026-02-23 122103.png" width="600">
</p>

---

## Phase 5 – Incident Generation

After execution of the reconnaissance command, Microsoft Sentinel generated an incident.

<p align="left">
  <img src="assets/Screenshot 2026-02-23 121203.png" width="600">
  <img src="assets/Screenshot 2026-02-23 153527.png" width="600">  
</p>

The incident included:

* Proper severity classification
* MITRE ATT&CK mapping
* Alert enrichment
* Associated entities

---

## Phase 6 – Investigation Workflow

The investigation graph validated entity relationships and alert correlation.

<p align="left">
  <img src="assets/Screenshot 2026-02-23 153621.png" width="600">
  <img src="assets/Screenshot 2026-02-23 153645.png" width="600">  
</p>

The investigation graph correctly correlated:

* Host (kali)
* Account (kali)
* Process (nmap 8.8.8.8)
* Alert object

This replicates real SOC triage workflow.

---

## Phase 7 – Incident Lifecycle Management

The incident was:

* Assigned to analyst
* Marked Active
* Investigated and documented
* Classified as True Positive (Security Testing)
* Closed with documentation

<p align="left">
  <img src="assets/Screenshot 2026-02-23 164818.png" width="600">
  <img src="assets/Screenshot 2026-02-23 164858.png" width="600">  
</p>

This demonstrates operational SOC process maturity beyond detection creation.
