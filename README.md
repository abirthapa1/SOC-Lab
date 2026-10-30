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
  - [Detection](#Detection)
  - [Inital Triage and Prioritization](#Initial-Triage-and-Prioritization)
  - [Investigation Timeline (UTC-8)](#Investigation-Timeline)
  - [Evidence and Queries](#Evidence-and-Queries)
  - [Scope and Impact](#Scope-and-Impact)
  - [MITRE ATT&CK Mapping](#MITRE-ATT&CK-Mapping)
  - [Indicators of Compromise](#Indicators-of-Compromise)
  - [Verdict](#Verdict)
- [Containment, Eradication and Recovery](#Containment-Eradication-and-Recovery)
  - [Containment](#Containment)
  - [Eradication](#Eradication)
  - [Recovery](#Recovery)
  - [Validation](#Validation)
- [Post-Incident Activity](#Post-Incident-Activity)
  - [Root Cause](#Root-Cause)
  - [What Went Well and What Did Not](#What-Went-Well-and-What-Did-Not)
  - [Lessons Learned and Recommendations](#Lessons-Learned-and-Recommendation)
  - [Metrics](#Metrics)
  - [Closure](#Closure)
- [Appendix A: Evidence Checklist](#Appendix-A-Evidence-Checklist)
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
This section records the controls and readiness in place before the incident, which determines how quickly it can be detected and handled.

### Environment and Tooling
| **Component**| **Configuration**| **Purpose**|
|:-------- |:-------- |:-------- |
| Microsoft Defender XDR | Microsoft 365 E5 trial tenant, incidents and alerts enabled | Unified detection, investigation and response|
| Defender for Endpoint | test-Vm on-boarded via local script, sensor reporting | Endpoint telemetry, device isolation, Live response |
| Microsoft Sentinel | Log Analytics workspace with Defender XDR and Entra ID connectors | SIEM correlation, long-term log retention |
| Microsoft Entra ID | Diagnostic settings, send sign-in and audit logs to Sentinel | Identity telemetry |
| Notifications | Defender email notification rule for Medium+ incidents | Analyst alerting |

### Roles and Access
| **Role**| **Person/Account**| **Responsibility**|
|:-------- |:-------- |:-------- |
| Incident Handler| Jean Arc (Security Administrator) | Triage, investigate and contain|
| Tenant Owner | Global Admin Account | Tenant level changes only, not used for daily work |
| System Owner | Abir | Approves containment of the lab VM |
| Azure account | azureuser | Used to login to test-Vm |
| Local account | test_user1 | Used to login to test-VM as a local account |

### Readiness Checklist
| **Control**| **Status**| **Notes**|
|:-------- |:-------- |:-------- |
| Endpoint onboarded and reporting | Yes | Device visible in Assets > Devices |
| Sign-in and device logs reaching Sentinel | Yes | Verified with SigninLogs and DeviceLogOnEvents queries |
| Alert notifications tested | Yes | Test alert delivered by email |
| Custom detection for repeated | Yes (need to redo) | Identity telemetry |
| Account lockout policy | Yes (need to redo) | Analyst alerting |
| RDP restricted to trusted IP in the NSG | Partial | Open to a wide range, narrowed after this incident |
| Incident response procedure documented | Yes | This report follows NIST SP 800-61 |

# Detection and Analysis
### Detection
The alert was created on [29 Oct 2026 at 00:38 UTC-8] with two alerts one for Compromised account conducting hands-on-keyboard attack and the other one for Suspicious DNS server discovery. Defender grouped the two alerts into incident [Incident ID 2]. An email notification reached the analyst within [4] minutes of the incident being created.

##### Image 1: Incident Page
<img width="1433" height="591" alt="Incident-page" src="https://github.com/user-attachments/assets/9830f34b-f8be-422c-9c96-da920034ea1d" />

##### Image 2: Alert Page
<img width="1471" height="328" alt="image" src="https://github.com/user-attachments/assets/118abb6f-76bc-4778-bf5b-ef17600c39fd" />

##### Image 3: Timeline
<img width="1735" height="870" alt="image" src="https://github.com/user-attachments/assets/fc291939-0cff-43f8-a595-f82cd955931e" />


### Initial Triage and Prioritization
- **Asset Criticality**: Medium (No production data), but internet-exposed through RDP
- **Pattern**: [49] powershell.exe scripts ran in a span of 10 minutes, from a local account with a creation of open-ports.txt.
- **Severity decision**: raised it to High, after the user started running more PowerShell scripts with the intention of knowing the network configuration of the system and saving the all the open ports in a text file.

### Investigation Timeline (UTC-8)
| **Time**| **Event**| **Source**|
|:-------- |:-------- |:-------- |
| 2026-10-28 23:36:37 | Interactive logon for test_user1: userinit.exe (PID 6572) started, which sets up the user session. | Device timeline: process creation |
| 2026-10-28 23:36:38 | explorer.exe (PID 6608) started in the session. The session was opened remotely from cachyos-x8664 / 192.168.0.103 (remote logon). | Device timeline: process creation |
| 2026-10-28 23:41:47 | powershell.exe (PID 11980) launched interactively by test_user1. | Device timeline: process creation |
| 2026-10-28 23:42:11 | powershell.exe -exec bypass (PID 1936) launched, bypassing the PowerShell execution policy. | Device timeline: process creation |
| 2026-10-29 00:24:41 to 00:30:42 | whoami.exe and HOSTNAME.EXE ran each time Invoke-AtomicTest was called. This is likely the framework recording the executing user and host, not separate manual discovery. | Device timeline: process creation |
| 2026-10-29 00:30:42 | Invoke-AtomicTest T1566.002 executed. It created a child powershell.exe (PID 3900) running an inline script. Defender mapped it to T1059.001 (PowerShell) and T1620 (Reflective Code Loading). | PowerShell script block log and Defender alert |
| 2026-10-29 00:30:43 | Inline script behavior: defines a keybd_event call from user32.dll, simulates Win+R to open the Run dialog, then types cmd /c powershell -ec <Base64>. The Base64 decodes to calc.exe, so the end result is a calculator launched through an encoded PowerShell command. | PowerShell script block log |
| 2026-10-29 00:30:43 | powershell.exe loaded a .NET assembly in memory. This is likely the Add-Type compile of the helper class, and it contributed to the T1620 tag. | Defender alert / device timeline |
| 2026-10-29 00:30:46 | Defender XDR raised the incident. | Defender XDR incident |
| 2026-10-29 00:38:02 | The T1016 PowerShell script (PID 1040) that reads top-128.txt and sets up open-ports.txt on the Desktop. | 	Device timeline: process creation |
| 2026-10-29 00:38:18 | cmd.exe running qakbot.bat (PID 9540) from the same T1016 folder. | 	Device timeline: process creation |
| 2026-10-29 00:38:18 | Defender XDR raised the incident. | 	Defender XDR incident |


### Evidence and Queries

``
DeviceProcessEvents
| where DeviceName =~ "test-Vm" and Timestamp > ago(24h)
| where ProcessCommandLine has_any ("open-ports.txt")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
``
##### Image : Output for the above KQL query
<img width="1160" height="875" alt="image" src="https://github.com/user-attachments/assets/ac9048d0-5965-42ec-815a-c47789dd21cb" />


### Scope and Impact

### MITRE ATT&CK Mapping

### Indicators of Compromise

### Verdict
True positive (simulated). The detection correctly identified a bunch of commands and scripts being executed on PowerShell with a known credential. The source was an authorized lab test, so no real compromise occurred. The response was still carried out as if the activity were real.

# Containment, Eradication and Recovery
### Containment
Short-term containment limited the attacker's ability to act while evidence was preserved.
| **Time**| **Action**| **By**| **Result** |
|:-------- |:-------- |:-------- | :------ |
| 2026-10-29 00:39 | Isolated test-Vm from the network using Defender 'Isolate Device' | Jean Arc (Security Admin) |  Device isolated, sensor still reporting |
| 2026-10-29 00:42 | Removed the account test_user1 in local users (Entra account not involved) | Jean Arc (Security Admin) |  Account removed |
| 2026-10-29 00:45 | Quarantined the open-ports.txt using Live response | Jean Arc (Security Admin) |  Quarantined the text file  |
| 2026-10-29 00:48 | Collected investigation package from the device for evidence | Jean Arc (Security Admin) |  Package saved to the case folder |


### Eradication
- Removed the compromised local account test_user1.
- Quarantined the open-ports.txt file.
- Ran a full Microsoft Defender Antivirus scan on test-Vm. Result: no threats found.
- Reviewed local users, services, scheduled tasks and startup items for persistence. Result: nothing new.
- Confirmed no other accounts showed any spikes in execution of multiple PowerShell scripts from the same IP (hunting query across all devices).

### Recovery
- Released the device from isolation at [01:30] after the antivirus scan and checks were clean.
- Monitored the device for 24 hours: no repeat alerts or new failed-logon spikes.

### Validation
| **Check**| **Result** |
|:-------- |:-------- |
| Device reporting to Defender and healthy | Pass |
| No remaining alerts on the device |  Pass |
| Not being able to login from the local account test_user1 |  Pass |
| Incident closed with classification and comments |  Pass (True positive, classification noted as a lab test) |

# Post-Incident Activity
### Root Cause

### What Went Well and What Did Not



### Lessons Learned and Recommendations
| **#**| **Recommendation**| **Priority**| **Owner** | **Status** |
|:-------- |:-------- |:-------- | :------- | :------- |
| 1 | Move to Entra-joined accounts with MFA | High | System Owner  | Done |
| 2 | Add detections for ``powershell -exec bypass`` and PowerShell launched from a remote session |  High | Security Admin | Done|
| 3 | Keep PowerShell script block logging enabled, and consider Sysmon for process termination events | Medium |  System Owner | Done |
| 4 | Write a playbook for this scenario: isolate the device, disable the account, block the source and collect the investigation package | Low |  Security Admin  | Planned |

### Metrics
| **Metric**| **Value** | **Definition** |
|:-------- |:-------- |:-------- |
| 1 | Move to Entra-joined accounts with MFA | High | System Owner  | Done |
| 2 | Add detections for ``powershell -exec bypass`` and PowerShell launched from a remote session |  High | Security Admin | Done|
| 3 | Keep PowerShell script block logging enabled, and consider Sysmon for process termination events | Medium |  System Owner | Done |
| 4 | Write a playbook for this scenario: isolate the device, disable the account, block the source and collect the investigation package | Low |  Security Admin  | Planned |

### Closure (rewrite)
The incident was closed in Defender as True positive with a comment summarizing the findings and a link to this report. Recommendations 4 and 5 are tracked as follow-up tasks.

## Appendix A: Evidence Checklist

## Appendix B: References
- NIST SP 800-61 Rev.2, Computer Security Incident Handling Guide (four-phase lifecycle used here).
- MITRE ATT&CK Enterprise Matrix: T1016, T1059, T1059.001
- Microsoft Learn: Defender XDR incident response and advanced hunting.
- Manage your live response library directly in Microsoft Defender https://www.modernsecurity.nl/live-response-library-in-microsoft-defender/
