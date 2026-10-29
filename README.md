# SOC-Lab
### Description 
This is a documentation of an incident response report that was done in a controlled environment to replicate a real life scenario incident. Made a homelab where I used Microsoft Defender XDR for alerts and incidents report in a controlled environment for my Azure VMs. I used Atomic red teams tests and Eicar test file to simulate an in real life security threat which would allow me to know how to prepare for the threat, detection of the threat, analysis of the threat if it's a false alarm or a legit threat, contain the threat, eradication of the threat and recovery of the system to it's normal state. And then the Post Incident Activity by documenting the whole process

# Table of Contents
- [Incident Response Report](#Incident-Response-Report)
  - [Document Control](#Document-Control)
  - [Executive Summary](#Executive-Summary)
- [Preparation](#Preparation)
  - [Environment and Tooling](#Environment-and-Tooling)
  - [Roles and Access](#Roles-and-Access)
  - [Readiness Checklist](#Readiness-Checklist)
- [Detection and Analysis](#Detection-and-Analysis)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
- [Containment, Eradication and Recovery](#Containment-Eradication-and-Recovery)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
- [Post-Incident Activity](#Post-Incident-Activity)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
  - [Root Cause](#Root-Cause)
- [Appendix A](#Appendix-A)
- [Appendix B: References](#Appendix-B-References)

# Incident Response Report

### Document Control 
| Incident ID | 2 |
|:-------- |:-------- |
| **Title**     | Compromised account conducting hands-on-keyboard attack  |
| **Status**     | Closed |
| **Severity**    | High (Defender Severity: High; Adjusted after triage, see 2.2)   |
| **Classification**    | True positive - simulated activity   |
| **Detection source**    | EDR   |
| **Affected asset**     | test-Vm : Windows 11 Enterpise VM, onboarded to Defender for Endpoint   |
| **Affected account(s)**     | test_user1 (local account)  |
| **Detected / Closed**     | [2026-10-29 00:38 UTC-8] / [2026-10-30 1:00 UTC-8, after 24 h monitoring   |
| **Analyst / Reviewer**     | Abir, SOC Analyst / Self-reviewed (lab)   |
| **Framework**     | NIST SP 800-61; MITRE ATT&CK  |

### Executive Summary
On [29 Oct 2026 at 00:38 UTC-8], Microsoft Defender XDR raised an incident after detecting repeated PowerShell script execution on the endpoint test-Vm following a successful logon by the local account "test_user1". The commands collected network configuration details and tested which outbound ports were open, consistent with the discovery stage of an attack (MITRE ATT&CK T1016). The activity came from an authorized lab simulation but was handled as a real credential compromise. No sensitive data was accessed and no other assets were affected; the only change was one new text file listing the open ports. The root cause was that valid credentials could be used to log on and run PowerShell unchallenged, because the account had a weak password and no logon restrictions. Response actions were to reset the password, remove the generated file, and block the source address in the network security group, after which the endpoint was monitored for [duration] with no further suspicious activity and declared clean.

### Key Facts at a Glance
| **Time to Detect**| **Time to Contain**| **Time to Recover**| **Assets affected**| **Data Impact**|
|:-------- |:-------- |:-------- |:-------- |:-------- |
| [12 mins] | [23 mins] | [76 mins] | 1 endpoint, 1 account | None identified |
# Preparation
### Environment and Tooling
### Roles and Access
### Readiness Checklist

# Detection and Analysis
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling

# Containment, Eradication and Recovery
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling
### Environment and Tooling

# Post-Incident Activity
### Root Cause
### What Went Well and What Did Not
### Lessons Learned and Recommendations
### Metrics
### Closure

## Appendix A

## Appendix B: References
- NIST SP 800-61
- MITRE ATT&CK Enterprise Matrix: T1016, T1059.001
- Microsoft Learn: Defender XDR incident response and advanced hunting.
