# MITRE ATT&CK — SOC Analyst Study Notes

> Goal: use ATT&CK as a **shared vocabulary for behaviour**, to map detections, measure coverage, and communicate about intrusions — not to memorise 200 technique IDs.
> Attack patterns → `Common-Attacks.md`; detection engineering → section 05/06; threat intel → section 07.

---

## 0. How to use this note

1. §1–§2: what ATT&CK is and why SOCs use it.
2. §3–§5: matrices, tactics, techniques, sub-techniques, procedures.
3. §6–§8: key techniques per tactic; data sources; Navigator.
4. §9–§12: mapping detections, coverage assessment, triage, threat intel.
5. §13–§15: limitations, purple teaming, workflow.
6. §16–§19: commands/tools, labs, self-test, revision.

---

## 1. What ATT&CK is

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is a **curated knowledge base of adversary behaviour**, based on real-world observations.

- Organised as **matrices** (Enterprise, Mobile, ICS).
- Columns = **tactics** ("why" — the goal).
- Cells = **techniques** ("how" — the behaviour).
- Sub-techniques add specificity (`T1059.001` PowerShell).
- Each technique page contains: description, procedure examples (groups/software), detection guidance, data sources, mitigations, references.

**What it is not:**
- Not a vulnerability list (that's CVE/CWE/CAPEC).
- Not a compliance checklist.
- Not exhaustive or perfectly mutually exclusive.
- Not a substitute for local context.

---

## 2. Why SOCs use ATT&CK

| Use | Benefit |
|---|---|
| **Common language** | "T1059.001" means the same to detection, IR, intel, and leadership. |
| **Detection mapping** | Each rule maps to technique(s) → coverage visibility. |
| **Coverage gaps** | Navigator heatmap shows what you cannot detect. |
| **Triage context** | Alerts say *what*; ATT&CK says *where in the campaign*. |
| **Threat intel translation** | Reports map to techniques → hunt hypotheses. |
| **Purple teaming** | Test techniques, measure detection, improve. |
| **Reporting** | Shows sophistication and progression, not just "malware". |
| **Prioritisation** | Focus on techniques used by relevant adversaries. |

**Value chain:** intel → technique → data source → detection → alert → triage → response → coverage update.

---

## 3. Matrices

| Matrix | Scope | Examples |
|---|---|---|
| **Enterprise** | Windows, macOS, Linux, cloud (AWS/Azure/GCP), containers, network, Office Suite, SaaS. | Most SOC work. |
| **Mobile** | Android, iOS. | MDM, mobile threats. |
| **ICS** | Industrial control systems. | OT/SCADA. |

Enterprise platforms: **Windows, macOS, Linux, Cloud, Containers, Network, Office Suite, SaaS, Identity Provider**.

> A technique may exist on multiple platforms; detection differs by platform.

---

## 4. The 14 Enterprise tactics

| # | Tactic | ID | Goal |
|---|---|---|---|
| 1 | **Reconnaissance** | TA0043 | Gather information to plan. |
| 2 | **Resource Development** | TA0042 | Build infrastructure/capabilities. |
| 3 | **Initial Access** | TA0001 | Get into the network. |
| 4 | **Execution** | TA0002 | Run malicious code. |
| 5 | **Persistence** | TA0003 | Maintain foothold. |
| 6 | **Privilege Escalation** | TA0004 | Gain higher permissions. |
| 7 | **Defense Evasion** | TA0005 | Avoid detection. |
| 8 | **Credential Access** | TA0006 | Steal credentials. |
| 9 | **Discovery** | TA0007 | Learn the environment. |
| 10 | **Lateral Movement** | TA0008 | Move to other systems. |
| 11 | **Collection** | TA0009 | Gather target data. |
| 12 | **Command and Control** | TA0011 | Communicate with implants. |
| 13 | **Exfiltration** | TA0010 | Steal data out. |
| 14 | **Impact** | TA0040 | Disrupt/destroy/extort. |

**Mnemonic:** *Really Risky Intruders Execute Persistent Privileged Evasion, Credential Discovery Leads Collection, Control, Exfil, Impact.*

> ATT&CK tactics are **not strictly sequential** — attackers loop (persistence after lateral movement, discovery throughout).

---

## 5. Techniques, sub-techniques, procedures

| Level | Example |
|---|---|
| **Tactic** | Execution (TA0002) |
| **Technique** | Command and Scripting Interpreter (T1059) |
| **Sub-technique** | PowerShell (T1059.001) |
| **Procedure** | `powershell.exe -enc <base64>` downloaded via macro in a phishing document |

- **Technique ID** format: `T####` / `T####.###`.
- **Procedure** = specific implementation (what you actually detect).
- **Group** = threat actor (e.g. APT29).
- **Software** = tool/malware (e.g. Cobalt Strike).
- **Mitigation** = defensive control (`M####`).
- **Data Source / Component** = telemetry needed (e.g. `Process: Process Creation`).

> **Detection happens at the procedure level.** The technique tells you what to look for; the procedure tells you what it looks like in your logs.

---

## 6. Key techniques by tactic (SOC-relevant)

### Reconnaissance (TA0043)
- T1595 Active Scanning, T1592 Gather Victim Host Info, T1589 Gather Victim Identity Info, T1598 Phishing for Information, T1590 Gather Victim Network Info.

### Resource Development (TA0042)
- T1583 Acquire Infrastructure, T1587 Develop Capabilities, T1608 Stage Capabilities, T1588 Obtain Capabilities (tools/malware/certs).

### Initial Access (TA0001)
- **T1566 Phishing** (.001 attachment, .002 link, .003 service, .004 spearphishing voice)
- **T1190 Exploit Public-Facing Application**
- **T1078 Valid Accounts** (.001 default, .002 domain, .003 local, .004 cloud)
- **T1133 External Remote Services**
- T1189 Drive-by Compromise
- T1195 Supply Chain Compromise
- T1199 Trusted Relationship
- T1200 Hardware Additions

### Execution (TA0002)
- **T1059 Command and Scripting Interpreter** (.001 PowerShell, .002 AppleScript, .003 Windows Command Shell, .004 Unix Shell, .005 VBScript, .006 Python, .007 JavaScript, .008 Network Device CLI)
- **T1204 User Execution** (.001 malicious link, .002 malicious file, .003 malicious image)
- **T1203 Exploitation for Client Execution**
- **T1053 Scheduled Task/Job** (.003 Cron, .005 Scheduled Task)
- **T1569 System Services** (.002 Service Execution)
- **T1047 WMI**
- **T1218 System Binary Proxy Execution** (.005 mshta, .010 regsvr32, .011 rundll32, .014 mmc)
- **T1106 Native API**
- T1202 Indirect Command Execution
- T1569.002 Service Execution

### Persistence (TA0003)
- **T1547 Boot or Logon Autostart** (.001 Registry Run Keys, .002 Startup Folder, .014 Active Setup)
- **T1543 Create or Modify System Process** (.002 Windows Service, .003 Windows Service? — .003 is Windows Service; .004 Launch Agent)
- **T1053 Scheduled Task/Job**
- **T1546 Event Triggered Execution** (.003 WMI Event Subscription, .004 Unix Shell Configuration, .008 Accessibility Features, .012 Image File Execution Options, .015 Component Object Model Hijacking)
- **T1136 Create Account**
- **T1505 Server Software Component** (.003 Web Shell, .005 Terminal Services DLL)
- **T1574 Hijack Execution Flow** (.001 DLL Search Order, .002 DLL Side-Loading, .008 Path Interception)
- **T1542 Pre-OS Boot**
- **T1554 Compromise Host Software Binary**
- **T1098 Account Manipulation** (.001 Additional Cloud Credentials, .004 SSH Authorized Keys, .005 Device Registration)

### Privilege Escalation (TA0004)
- **T1068 Exploitation for Privilege Escalation**
- **T1548 Abuse Elevation Control Mechanism** (.001 Setuid/Setgid, .002 Bypass UAC, .003 Sudo and Sudo Caching, .004 ElevateControl, .005 Temporary Elevated Cloud Access)
- **T1134 Access Token Manipulation**
- **T1055 Process Injection**
- **T1574 Hijack Execution Flow**
- **T1543.003 Windows Service**
- **T1078 Valid Accounts**

### Defense Evasion (TA0005)
- **T1070 Indicator Removal** (.001 Clear Windows Event Logs, .002 Clear Linux/macOS Logs, .004 File Deletion, .005 Timestomp)
- **T1562 Impair Defenses** (.001 Disable/Modify Tools, .005 Indicator Blocking, .008 Disable Cloud Logs)
- **T1027 Obfuscated Files or Information** (.001 Binary Padding, .002 Software Packing, .003 Steganography, .005 Indicator Removal from Tools, .010 Command Obfuscation, .012 LNK, .013 Encrypted/Encoded File)
- **T1055 Process Injection** (.001 DLL, .002 PE, .003 Thread Execution Hijacking, .004 APC, .005 Thread Local Storage, .007 .NET? — variants, .012 Process Hollowing, .013 Process Doppelgänging)
- **T1218 System Binary Proxy Execution**
- **T1036 Masquerading** (.004 Rename System Utilities, .005 Match Legitimate Name or Location)
- **T1112 Modify Registry**
- **T1497 Virtualization/Sandbox Evasion**
- **T1620 Reflective Code Loading**
- **T1564 Hide Artifacts** (.001 Hidden Files, .003 Hidden Window, .006 Run Virtual Instance)
- **T1574.001 DLL Search Order Hijacking**
- **T1014 Rootkit**
- **T1205 Traffic Signaling**
- **T1090 Proxy** (C2)

### Credential Access (TA0006)
- **T1003 OS Credential Dumping** (.001 LSASS, .002 SAM, .003 NTDS, .004 LSA Secrets, .005 Cached Domain Creds, .006 DCSync, .007 Proc Filesystem)
- **T1110 Brute Force** (.001 Password Guessing, .002 Password Cracking, .003 Password Spraying, .004 Credential Stuffing)
- **T1555 Credentials from Password Stores** (.003 Windows Credential Manager, .001 Keychain, .005 Password Managers)
- **T1558 Steal or Forge Kerberos Tickets** (.001 Golden, .002 Silver, .003 Kerberoasting, .004 AS-REP Roasting)
- **T1550 Use Alternate Authentication Material** (.001 Application Access Token, .002 Pass the Hash, .003 Pass the Ticket, .004 Web Session Cookie)
- **T1056 Input Capture** (.001 Keylogging, .003 Web Portal Capture)
- **T1539 Steal Web Session Cookie**
- **T1528 Steal Application Access Token**
- **T1621 MFA Request Generation**
- **T1111 MFA Interception**
- **T1556 Modify Authentication Process** (.005 MFA, .006 Multi-Factor? — variants, .001 Domain Trust Modification)

### Discovery (TA0007)
- T1087 Account Discovery (.001 Local, .002 Domain, .004 Cloud)
- T1018 Remote System Discovery
- T1046 Network Service Discovery
- T1069 Permission Groups Discovery
- T1082 System Information Discovery
- T1083 File and Directory Discovery
- T1057 Process Discovery
- T1012 Query Registry
- T1518 Software Discovery (.001 Security Software)
- T1482 Domain Trust Discovery
- T1615 Group Policy Discovery
- T1526 Cloud Service Discovery
- T1580 Cloud Infrastructure Discovery

### Lateral Movement (TA0008)
- **T1021 Remote Services** (.001 RDP, .002 SMB/Windows Admin Shares, .003 DCOM, .004 SSH, .005 VNC, .006 WinRM)
- **T1210 Exploitation of Remote Services**
- **T1550 Use Alternate Authentication Material** (PTH/PTT)
- **T1570 Lateral Tool Transfer**
- **T1563 Remote Service Session Hijacking**
- **T1080 Taint Shared Content**
- **T1546.003 WMI Event Subscription** (also persistence)

### Collection (TA0009)
- T1005 Data from Local System
- T1039 Data from Network Shared Drive
- T1025 Data from Removable Media
- T1114 Email Collection (.001 Local, .002 Remote, .003 Email Forwarding Rule)
- T1115 Clipboard Data
- T1113 Screen Capture
- T1125 Video Capture
- T1560 Archive Collected Data (.001 Archive via Utility, .002 Archive via Library, .003 Archive via Custom Method)
- T1074 Data Staged (.001 Local, .002 Remote)
- T1213 Data from Information Repositories
- T1530 Data from Cloud Storage

### Command and Control (TA0011)
- **T1071 Application Layer Protocol** (.001 Web, .002 DNS, .003 Mail, .004 FTP)
- **T1090 Proxy** (.001 Internal, .002 External, .003 Multi-hop)
- **T1095 Non-Application Layer Protocol**
- **T1105 Ingress Tool Transfer**
- **T1571 Non-Standard Port**
- **T1572 Protocol Tunneling**
- **T1008 Fallback Channels**
- **T1001 Data Obfuscation** (.001 Jitter, .002 Steganography, .003 Protocol Impersonation)
- **T1568 Dynamic Resolution** (.001 Fast Flux, .002 Domain Generation Algorithms, .003 DNS Calculation)
- **T1665 Hide Infrastructure** (newer)
- T1219 Remote Access Software (Anydesk, TeamViewer)
- T1102 Web Service (legit cloud services as C2)

### Exfiltration (TA0010)
- **T1041 Exfiltration Over C2 Channel**
- **T1048 Exfiltration Over Alternative Protocol** (.001 FTP, .002 DNS, .003 Mail, .005 ICMP)
- **T1567 Exfiltration Over Web Service** (.001 Webhook, .002 Cloud Storage, .003 Code Repo, .004 Text Sharing)
- **T1029 Scheduled Transfer**
- **T1030 Data Transfer Size Limits**
- **T1052 Exfiltration Over Physical Medium**
- **T1011 Exfiltration Over Other Network Medium**

### Impact (TA0040)
- **T1486 Data Encrypted for Impact**
- **T1485 Data Destruction**
- **T1490 Inhibit System Recovery**
- **T1489 Service Stop**
- **T1498 Network Denial of Service** (.001 Direct, .002 Reflected)
- **T1499 Endpoint Denial of Service**
- **T1565 Data Manipulation** (.001 Stored, .002 Transmitted, .003 Runtime)
- **T1491 Defacement** (.001 Internal, .002 External)
- **T1529 System Shutdown/Restart**
- **T1531 Account Access Removal**
- **T1657 Financial Theft**
- **T1496 Resource Hijacking** (crypto-mining)
- **T1561 Disk Wipe** (.001, .002)

---

## 7. Data sources and components

ATT&CK maps techniques to **data sources** (v18 restructured these):

| Data source | Examples |
|---|---|
| **Process** | Creation, termination, injection, access. |
| **Command** | Command execution. |
| **File** | Creation, modification, deletion, metadata. |
| **Network Traffic** | Flow, connection, DNS, HTTP, C2. |
| **Logon Session** | Creation, authentication. |
| **User Account** | Creation, modification, credential change. |
| **Service** | Creation, modification, start. |
| **Scheduled Job** | Creation, modification. |
| **Registry** | Key/value modification. |
| **Module** | Image/DLL load. |
| **Driver** | Load. |
| **Script** | Execution, content. |
| **Cloud Storage/Control Plane/Auth** | API calls, IAM. |
| **Container** | Create/start/exec. |
| **Application Log** | App-specific. |
| **Firewall** | Allow/deny. |

**Use:** pick the data source → confirm you collect it → write the detection → map to technique.

---

## 8. ATT&CK Navigator

- Web tool (`mitre-attack.github.io/attack-navigator`) to visualise/annotate matrices.
- Layers (JSON) overlay scores, detection coverage, group usage, software.
- **SOC uses:**
  - Coverage heatmap (green detected, yellow partial, red gap).
  - Threat-informed prioritisation (overlay a relevant group).
  - Purple-team results.
  - Gap analysis for leadership.

**Workflow:** export layer per quarter → compare → show improvement → justify tooling.

---

## 9. Mapping detections to ATT&CK

### 9.1 Method

1. **Identify the observable** in your rule (process, logon, network, registry…).
2. **Ask what adversary behaviour** produces it.
3. **Choose the most specific technique** (sub-technique preferred).
4. **Record the data source** and log/event used.
5. **Note false positives and confidence**.
6. **Store in a detection catalogue** (ID, name, query, technique, source, status, owner).

### 9.2 Example mapping table

| Detection | Technique | Data source | Event |
|---|---|---|---|
| Office spawns PowerShell | T1566.001 → T1204.002 → T1059.001 | Process | Sysmon 1 / 4688 |
| Encoded PowerShell | T1059.001, T1027.010 | Script/Process | 4104 / 4688 |
| LSASS access | T1003.001 | Process access | Sysmon 10 |
| New service from temp | T1543.003 | Service | 7045 |
| Run key persistence | T1547.001 | Registry | Sysmon 13 |
| Scheduled task creation | T1053.005 | Scheduled job | 4698 |
| WMI subscription | T1546.003 | WMI | WMI-Activity 5861 |
| Kerberoasting | T1558.003 | Logon/DC | 4769 RC4 |
| Pass-the-hash | T1550.002 | Logon | 4624 type 3 NTLM |
| Shadow copy deletion | T1490 | Process | 4688 |
| Ransomware encryption | T1486 | File | EDR file events |
| DNS tunneling | T1071.002 / T1048.003 | Network | DNS logs |
| Cloud role attach | T1098.003 / T1078.004 | Cloud | CloudTrail |
| Public bucket | T1530 | Cloud storage | S3 API logs |
| MFA fatigue | T1621 | IdP | Sign-in logs |

### 9.3 Detection catalogue fields

```
id, name, description, technique(s), tactic(s), platform,
data_source, log_channel/event_id, query, threshold,
false_positives, severity, owner, status, last_tested, test_case
```

---

## 10. Coverage assessment

### 10.1 Levels

| Level | Meaning |
|---|---|
| **0 — None** | No telemetry or no rule. |
| **1 — Telemetry** | Logs collected but no detection. |
| **2 — Partial** | Rule exists, noisy or narrow. |
| **3 — Good** | Reliable rule, tuned, tested. |
| **4 — Validated** | Purple-team/emulation verified end-to-end. |

### 10.2 Prioritisation

- Techniques used by **threats relevant to your sector**.
- Techniques with **high impact** (credential access, lateral movement, ransomware).
- Techniques with **cheap, high-fidelity telemetry** (process creation, auth logs).
- Techniques at **choke points** (identity, egress, execution).

### 10.3 Common coverage gaps

- Cloud control plane (IAM, storage, K8s audit).
- SaaS/IdP (consent, token theft).
- macOS/Linux.
- Encrypted C2 (need proxy/EDR).
- In-memory/fileless (need memory/AMSI/ETW).
- Insider/data collection (need DLP/UEBA).
- OT/ICS.

---

## 11. Triage with ATT&CK

### Step 1 — Map the alert
Which technique(s) does this event represent?

### Step 2 — Place it in the campaign
Is this initial access, execution, persistence, credential access, lateral movement?

### Step 3 — Predict the next step
If T1003 succeeded, expect T1550/T1021. If T1543.003 succeeded, expect T1059/T1105.

### Step 4 — Choose telemetry
Query the data source ATT&CK lists for that technique.

### Step 5 — Scope by technique
Hunt the **behaviour**, not just the hash (`schtasks` creations, NTLM type 3, LSASS access).

### Step 6 — Report with IDs
"T1566.001 → T1204.002 → T1059.001 → T1547.001 → T1071.001".

> ATT&CK turns a single alert into a **hypothesis about the intrusion**.

---

## 12. Threat intel and hunting

- **CTI reports** → extract techniques → map to ATT&CK → build hunts.
- **Groups** (APT29, FIN7, Lazarus) have technique profiles → prioritise.
- **Software** (Cobalt Strike, Mimikatz) → technique footprint.
- **Hunt hypothesis template:**
  > "If <group> is present, we would see <technique> in <data source>. Query: <KQL/SPL>. Expected: <baseline>. Anomaly: <threshold>."

**Example:** "If APT29 used T1098.001, we would see new cloud credentials added to service principals. Query CloudTrail `CreateAccessKey`/`AddServicePrincipalCredentials`. Anomaly: non-CI principal or unusual source IP."

---

## 13. Limitations and pitfalls

| Pitfall | Reality |
|---|---|
| Treating ATT&CK as a checklist | It is a model; coverage ≠ security. |
| Over-mapping to tactics | Tactic is too coarse; map to sub-technique. |
| One detection = one technique | Many detections cover several; be honest. |
| Ignoring platform differences | Same technique, different telemetry. |
| Assuming sequence | Attackers loop and skip. |
| Ignoring procedures | Technique-level detection is too broad. |
| Chasing 100% coverage | Prioritise by threat relevance. |
| No test evidence | Untested detections are claims, not coverage. |

---

## 14. Purple teaming with ATT&CK

1. Select techniques relevant to your threat model.
2. Define **emulation plan** (Atomic Red Team, CALDERA, manual).
3. Execute in a controlled scope.
4. Record **telemetry generated** and **alerts fired**.
5. Score coverage level.
6. Fix detections/telemetry.
7. Re-test and update the Navigator layer.

**Atomic Red Team** maps each atomic test to a technique ID — ideal for validation.

---

## 15. Workflow summary

```
Threat intel / incident
        │
        ▼
Map to ATT&CK technique(s) ──► Data source needed
        │                          │
        ▼                          ▼
Hunt hypothesis  ◄──── Confirm telemetry collected
        │
        ▼
Detection rule (SPL/KQL/Sigma/YARA)
        │
        ▼
Test (atomic/purple) → tune → catalogue → Navigator layer
        │
        ▼
Alert → triage with technique context → response
```

---

## 16. Tools and commands

| Tool | Use |
|---|---|
| **ATT&CK Navigator** | Layers, coverage maps. |
| **ATT&CK website** | Technique pages, groups, software. |
| **Atomic Red Team** | Technique-based tests. |
| **CALDERA** | Automated adversary emulation. |
| **Sigma** | Vendor-neutral detection rules (mapped to ATT&CK). |
| **MITRE Engenuity Evaluations** | Vendor detection results by technique. |
| **Threat Intelligence (MISP/OpenCTI)** | Map reports to techniques. |
| **Detection catalogue** | Internal mapping (spreadsheet/DB). |

**Sigma example with ATT&CK tag:**
```yaml
title: Suspicious PowerShell Encoded Command
id: 1c3f9a2e-...
status: experimental
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027.010
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
  condition: selection
level: high
```

**Navigator layer skeleton:**
```json
{
  "name": "SOC Coverage Q4",
  "versions": { "attack": "16", "navigator": "5.1.0", "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [
    { "techniqueID": "T1059.001", "score": 3, "comment": "4104 + Sysmon 1" },
    { "techniqueID": "T1003.001", "score": 3, "comment": "Sysmon 10 + EDR" }
  ],
  "gradient": { "colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 3 }
}
```

---

## 17. Labs

1. Browse the Enterprise matrix; pick 10 techniques relevant to your sector.
2. Map 20 existing detections to techniques; note gaps.
3. Build a Navigator layer for your lab coverage.
4. Run 5 Atomic Red Team tests; record telemetry and alerts.
5. Write Sigma rules for 5 techniques with `attack.*` tags.
6. Take a public CTI report; extract techniques and write 3 hunts.
7. Trace an incident timeline and label each step with technique IDs.
8. Compare a technique's Windows vs Linux telemetry.
9. Score your coverage 0–4 and justify.
10. Present a one-page coverage improvement plan.

---

## 18. Self-test questions

1. What do the columns and cells of an ATT&CK matrix represent?
2. Name the 14 Enterprise tactics in order.
3. Difference between technique, sub-technique, and procedure?
4. Which technique covers PowerShell execution?
5. Which technique covers LSASS dumping?
6. Which technique covers scheduled task persistence?
7. Which technique IDs map to Kerberoasting and AS-REP roasting?
8. What is the technique for shadow copy deletion?
9. Which data source would you need for T1059.001?
10. What is a Navigator layer used for?
11. Why is coverage ≠ security?
12. How do you use ATT&CK in triage?
13. What is Atomic Red Team?
14. How do you prioritise which techniques to detect?
15. What are three common coverage gaps?

---

## 19. One-page revision checklist

- [ ] ATT&CK = behaviour knowledge base; matrices Enterprise/Mobile/ICS; tactics (why), techniques (how), sub-techniques, procedures (specific).
- [ ] 14 tactics: Recon, Resource Dev, Initial Access, Execution, Persistence, PrivEsc, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact.
- [ ] Key techniques: T1566, T1190, T1078, T1133; T1059.001/.003/.004, T1204, T1053, T1047, T1218, T1569.002; T1547.001, T1543.003, T1546.003, T1505.003, T1574, T1136; T1068, T1548, T1134, T1055; T1070, T1562, T1027, T1036, T1620, T1014; T1003, T1110, T1558, T1550, T1555, T1539, T1621; T1087, T1018, T1046, T1082, T1482; T1021, T1210, T1570; T1005, T1114, T1560, T1074; T1071, T1090, T1105, T1572, T1568, T1219, T1102; T1041, T1048, T1567; T1486, T1485, T1490, T1489, T1498, T1491, T1496, T1561.
- [ ] Data sources: process, command, file, network, logon, account, service, scheduled job, registry, module, driver, script, cloud, container, firewall.
- [ ] Navigator: layers, heatmap, threat overlay, purple-team results, gap analysis.
- [ ] Detection mapping: observable → behaviour → most specific technique → data source/event → catalogue fields.
- [ ] Coverage levels 0–4; prioritise by threat relevance, impact, cheap fidelity, choke points; gaps (cloud, SaaS/IdP, macOS/Linux, encrypted C2, fileless, insider, OT).
- [ ] Triage: map → campaign position → predict next → telemetry → scope by behaviour → report with IDs.
- [ ] CTI: extract techniques, group/software profiles, hunt hypothesis template.
- [ ] Limitations: not checklist/vuln DB, map to sub-techniques, platform differences, non-linear, procedures matter, no 100%, test evidence.
- [ ] Purple team: select → emulate (Atomic/CALDERA) → record → score → fix → retest → layer.
- [ ] Workflow: intel/incident → technique → data source → telemetry → hunt → rule → test → catalogue → alert → triage.
