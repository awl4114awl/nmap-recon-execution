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

`![Advanced Hunting Results](images/advanced-hunting-validation.png)`

---

## Phase 2 – Adversary Simulation

To simulate discovery behavior aligned with MITRE ATT&CK T1046 (Network Service Scanning), the following command was executed:

```
nmap 8.8.8.8
```

This generated process telemetry captured by Defender and forwarded into Sentinel.

### Screenshot – Nmap Execution on Kali

`![Nmap Execution](images/nmap-execution-terminal.png)`

---

## Phase 3 – Detection Engineering

A custom scheduled analytics rule was created using KQL:

```kql
DeviceProcessEvents
| where DeviceName contains "kali"
| where ProcessFileName =~ "nmap"
| extend HostCustomEntity = DeviceName
| extend AccountCustomEntity = AccountName
| extend ProcessCustomEntity = ProcessCommandLine
| project TimeGenerated, DeviceName, AccountName, ProcessFileName, ProcessCommandLine, InitiatingProcessCommandLine
```

Detection configuration:

* Table: `DeviceProcessEvents`
* Severity: Medium
* MITRE ATT&CK: Discovery – T1046
* Rule Type: Scheduled Analytics Rule

### Screenshot – Analytics Rule Configuration

`![Analytics Rule Config](images/analytics-rule-config.png)`

---

## Phase 4 – Entity Mapping

Proper entity enrichment was configured to enable investigation graph correlation.

Mapped Entities:

* Host → DeviceName
* Account → AccountName
* Process → ProcessCommandLine

### Screenshot – Entity Mapping Configuration

`![Entity Mapping](images/entity-mapping.png)`

---

## Phase 5 – Incident Generation

After execution of the reconnaissance command, Microsoft Sentinel generated an incident.

### Screenshot – Incident Created in Sentinel

`![Incident Created](images/sentinel-incident-created.png)`

The incident included:

* Proper severity classification
* MITRE ATT&CK mapping
* Alert enrichment
* Associated entities

---

## Phase 6 – Investigation Workflow

The investigation graph validated entity relationships and alert correlation.

### Screenshot – Incident Overview Panel

`![Incident Overview](images/incident-overview.png)`

### Screenshot – Entities Panel

`![Entities Panel](images/entities-panel.png)`

### Screenshot – Investigation Graph

`![Investigation Graph](images/investigation-graph.png)`

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

### Screenshot – Incident Assignment

`![Incident Assigned](images/incident-assigned.png)`

### Screenshot – Incident Closure

`![Incident Closed](images/incident-closed.png)`

This demonstrates operational SOC process maturity beyond detection creation.

---

## Skills Demonstrated

* Linux EDR deployment validation
* KQL-based detection engineering
* Scheduled analytics rule configuration
* MITRE ATT&CK alignment
* Entity enrichment configuration
* SOC investigation workflow
* Incident triage and lifecycle management
* Azure + Microsoft Sentinel operations

---

## Conclusion

This lab demonstrates a complete detection engineering and SOC investigation lifecycle:

1. Simulate adversary behavior
2. Validate endpoint telemetry
3. Engineer targeted detection logic
4. Map entities for investigation enrichment
5. Generate and investigate a SIEM incident
6. Document and close incident properly

The environment successfully replicated an enterprise-grade reconnaissance detection scenario aligned with real-world SOC operations.

---
