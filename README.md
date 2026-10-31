# SOC-Lab
### Description 
This is a documentation of an incident response report that was done in a controlled environment to replicate a real life scenario incident. Made a homelab where I used Microsoft Defender XDR for alerts and incidents report in a controlled environment for my Azure VMs. I used Atomic red teams tests to simulate an in real life security threat which would allow me to know how to prepare for the threat, detection of the threat, analysis of the threat if it's a false alarm or a legit threat, contain the threat, eradication of the threat and recovery of the system to it's normal state. And then the Post Incident Activity by documenting the whole process

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
  - [Lessons Learned and Recommendations](#Lessons-Learned-and-Recommendations)
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
| **Severity**    | High (Defender Severity: High; Adjusted after triage)   |
| **Classification**    | True positive - simulated activity   |
| **Detection source**    | EDR   |
| **Affected asset**     | test-Vm : Windows 11 Enterpise VM, onboarded to Defender for Endpoint   |
| **Affected account(s)**     | test_user1 (local account)  |
| **Detected / Closed**     | [2026-10-29 00:38 UTC-8] / [2026-10-30 1:00 UTC-8, after 24 h monitoring   |
| **Analyst / Reviewer**     | Abir, SOC Analyst / Self-reviewed (lab)   |
| **Framework**     | NIST SP 800-61; MITRE ATT&CK  |

### Executive Summary
On [29 Oct 2026 at 00:38 UTC-8], Microsoft Defender XDR raised an incident after detecting repeated PowerShell script execution on the endpoint test-Vm following a successful logon by the local account "test_user1". The commands collected network configuration details and tested which outbound ports were open, consistent with the discovery stage of an attack (MITRE ATT&CK T1016, T1059). The activity came from an authorized lab simulation but was handled as a real credential compromise. No sensitive data was accessed and no other assets were affected; the only change was one new text file listing the open ports. The root cause was that valid credentials could be used to log on and run PowerShell unchallenged, because the account had a weak password and no logon restrictions. Response actions were to reset the password, remove the generated file, and block the source address in the network security group, after which the endpoint was monitored for 24 hours with no further suspicious activity and declared clean.

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
The alert was created on [29 Oct 2026 at 00:38 UTC-8] with two alerts[Image 1](#Image-1) one for Compromised account conducting hands-on-keyboard attack and the other one for Suspicious DNS server discovery. Defender grouped the two alerts into incident [Incident ID 2].[Image 2](#Image-2) An email notification reached the analyst within [4] minutes of the incident being created.

##### Image 1: Incident Page


##### Image 2: Alert Page


##### Image 3: Timeline



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
- KQL for checking the logon users [Image 4](#Image-4)
``
let StartT = datetime(2026-10-28T08:00:00Z);
let EndT   = datetime(2026-10-29T09:00:00Z);
DeviceLogonEvents
| where Timestamp between (StartT .. EndT)
| where DeviceName startswith "test-vm"
| project Timestamp, ActionType, AccountName, LogonType, RemoteIP, RemoteDeviceName, IsLocalAdmin
| order by Timestamp asc
``

- KQL for checking the text file created (open-ports.txt) [Image 5](#Image-5)
``
let StartT = datetime(2026-10-28T08:00:00Z);
let EndT   = datetime(2026-10-29T09:00:00Z);
DeviceProcessEvents
| where Timestamp between (StartT .. EndT)
| where DeviceName startswith "test-vm"
| where ProcessCommandLine has_any ("open-ports.txt")
| project Timestamp, AccountName, FileName, ProcessId, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
``


- Query to see the ``PowerShell.exe`` and ``cmd.exe`` was ran [Image 6](#Image-6)
``
let StartT = datetime(2026-10-28T08:00:00Z);
let EndT   = datetime(2026-10-29T09:00:00Z);
DeviceProcessEvents
| where Timestamp between (StartT .. EndT)
| where DeviceName startswith "test-vm"
| where FileName in~ ("powershell.exe","cmd.exe")
| project Timestamp, AccountName, FileName, ProcessId, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessId, ProcessTokenElevation, ProcessIntegrityLevel
| order by Timestamp asc
``
- Brought the device into isolation.[Image 7](#Image-7)
- Remediated the text file(open-ports.txt).[Image 8](#Image-8)
- Uploaded a powershell script to remove the local account from the device.[Image 9](#Image-9)


### Scope and Impact
| **Question**| **Finding** | 
|:-------- |:-------- |
| How many systems were affected? | One: test-Vm. No evidence of other devices in the timeline. |
| What accounts were involved?  | One: test_user1 (local account). No Entra or domain accounts involved. |
| What was the privilege level? | No privilege escalation observed |
| Was data accessed or exfiltrated? | Nothing sensitive. Network configuration was shown but no outbound network activity.  |
| Was data modified? | Minor. ``open-ports.txt`` was setup on the Desktop. |
| Was there any lateral movement? | None observed |
| Was persistence established ? | None found. Check for new accounts, scheduled tasks, services and startup items. |


### MITRE ATT&CK Mapping
| **Tactic**| **Technique** | **Observed evidence** |
|:-------- |:-------- |:-------- |
| Initial Access | T1078.003 Valid Accounts: Local Accounts | Successful remote logon as ``test-Vm\test_user1``  |
| Execution | T1059.001 PowerShell |  Interactive PowerShell, ``-exec bypass``, inline scripts (Defender tag) |
| Discovery | T1016 System Network Configuration Discovery | open-ports script and ``qakbot.bat`` |

### Indicators of Compromise
| **Type**| **Indicator** |
|:-------- |:-------- |
| Ip address | 192.168.0.103 |
| Hostname | cachyos-x8664 |
| Account | test_user1 |
| Device | test-Vm |
| Command Line | ``powershell.exe -exec bypass`` |
| File path | ``%USERPROFILE%\Desktop\open-ports.txt`` |

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
The root cause was weak access controls on the endpoint test-Vm. The local account test_user1 could be used for a remote logon with only username and password, with no MFA, no account lockout and no restrictions on which IP addresses could connect. Because it is a local account, it also fell outside the Entra ID Protection and Conditional Access, so nothing challenged or flagged the sign-in. Once logged on, the account could run PowerShell freely with the execution policy bypassed, which allowed the Atomic Red Team discovery tests (T1016, T1059) to run unrestricted. Detection depended on behavior-based rules which took a little bit of time to showup as an alert in the Defender Portal.

### What Went Well and What Did Not
| **Went Well**| **Needs improvement** |
|:-------- |:-------- |
| Defender caught the activity and tagged it with MITRE techniques (T1016, T1059) and a "Remote execution" label which made the source of the session easy to see| A local account with valid credentials was enough to log on remotely and run PowerShell with no challenge. MFA, Entra ID and conditional access needs to be in place. |
| Device timeline and script block logs gave a clear record of the exact commands that was ran on PowerShell | ``powershell.exe`` and ``cmd.exe`` being MS-signed made it harder to detect and depended on behavior and command lines.  |
| Isolation preserved Defender connectivity, so evidence could be collected |   |



### Lessons Learned and Recommendations
| **#**| **Recommendation**| **Priority**| **Owner** | **Status** |
|:-------- |:-------- |:-------- | :------- | :------- |
| 1 | Move to Entra-joined accounts with MFA | High | System Owner  | Done |
| 2 | Add detections for ``powershell -exec bypass`` and PowerShell launched from a remote session |  High | Security Admin | Done|
| 3 | Keep PowerShell script block logging enabled, and consider Sysmon for process termination events | Medium |  System Owner | Planned |
| 4 | Write a playbook for this scenario: isolate the device, disable the account, block the source and collect the investigation package | Low |  Security Admin  | Planned |

### Metrics
| **Metric**| **Value** | **Definition** |
|:-------- |:-------- |:-------- |
| Mean Time to Detect (MTTD) | 12 mins | Suspicious commands run on PowerShell  |
| Mean Time to Respond (MTTR) | 23 mins |  Incident Creation to containment start |
| Mean Time to Recover | 76 mins | Medium | Incident Creation to device restored |
| Alerts / Incidents involved | 2 alerts, 1 incident | Correlated in Defender XDR |

### Closure (rewrite)
The incident was closed in Defender as **True positive** with a comment summarizing the findings and a link to this report. Recommendations 3 and 4 are tracked as follow-up tasks.

## Appendix A: Evidence Checklist
##### Image 1: Alert page
<img width="1433" height="591" alt="Incident-page" src="https://github.com/user-attachments/assets/9830f34b-f8be-422c-9c96-da920034ea1d" />

##### Image 2: Incident page
<img width="1471" height="328" alt="image" src="https://github.com/user-attachments/assets/118abb6f-76bc-4778-bf5b-ef17600c39fd" />

##### Image 3: Timeline
<img width="1735" height="870" alt="image" src="https://github.com/user-attachments/assets/fc291939-0cff-43f8-a595-f82cd955931e" />

##### Image 4
<img width="1435" height="772" alt="image" src="https://github.com/user-attachments/assets/65faa86b-0fdb-46d8-9158-883a8d3bbbe7" />

##### Image 5
<img width="1446" height="766" alt="image" src="https://github.com/user-attachments/assets/e4c782b2-5160-4fca-924c-207c9c3e562d" />

##### Image 6
<img width="1446" height="766" alt="image" src="https://github.com/user-attachments/assets/78abdcfa-c371-4039-bc66-dc6ae76df4a0" />

##### Image 7
<img width="1036" height="378" alt="image" src="https://github.com/user-attachments/assets/2a5c6742-5d71-498d-a9a1-fb4f6c1b9c39" />

##### Image 8
<img width="984" height="375" alt="image" src="https://github.com/user-attachments/assets/22aa8939-a825-42ea-b47a-6af72582a225" />

##### Image 9
<img width="999" height="297" alt="image" src="https://github.com/user-attachments/assets/e212aca0-dbd1-4865-9cb5-914493d0510f" />


## Appendix B: References
- NIST SP 800-61 Rev.2, Computer Security Incident Handling Guide (four-phase lifecycle used here). https://doi.org/10.6028/NIST.SP.800-61r2 
- MITRE ATT&CK Enterprise Matrix:
  -  T1016 https://attack.mitre.org/techniques/T1016/
  -  T1059 https://attack.mitre.org/techniques/T1059/
  -  T1059.001 https://attack.mitre.org/techniques/T1059/001/
  -  T1078.003 https://attack.mitre.org/techniques/T1078/003/
- Microsoft Learn: Defender XDR incident response and advanced hunting.
- Manage your live response library directly in Microsoft Defender. https://www.modernsecurity.nl/live-response-library-in-microsoft-defender/
