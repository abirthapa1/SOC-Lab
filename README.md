# SOC-Lab
### Description 
This is a documentation of an incident response report that was done in a controlled environment to replicate a real life scenario incident. Made a homelab where I used Microsoft Defender XDR for alerts and incidents report in a controlled environment for my Azure VMs. I used Atomic red teams tests and Eicar test file to simulate an in real life security threat which would allow me to know how to prepare for the threat, detection of the threat, analysis of the threat if it's a false alarm or a legit threat, contain the threat, eradication of the threat and recovery of the system to it's normal state. And then the Post Incident Activity by documenting the whole process

## Table of Contents
- [Incident Response Report](#Incident-Response-Report)
  - [Document Control](#Document-Control)
  - [Executive Summary](#Executive-Summary)
1. [Preparation](#Preparation)
  1.1 [Environment and Tooling](#Environment-and-Tooling)
  1.2
- [Section 3](#section-3)

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
| **Framework**     | NIST SP 800-61; MITRE ATT&CK;  |

### Executive Summary

### Key Facts at a Glance

# 1. Preparation
### 1.1 Environment and Tooling
### 1.2 Roles and Access
### 1.3 Readiness Checklist

# 2. Detection and Analysis

# 3. Containment, Eradication and Recovery

# 4. Post-Incident Activity

## Appendix A

## Appendix B: References
- 
