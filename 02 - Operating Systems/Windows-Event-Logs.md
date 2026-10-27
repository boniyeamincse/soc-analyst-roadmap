# Windows Event Logs — SOC Analyst Study Notes

> Goal: read, query, and reason about Windows event logs well enough to **detect and reconstruct attacks**, and to know which audit settings must be enabled for that to be possible.
> Host internals → `Windows.md`; process behaviour → `Processes.md`; permissions/object auditing → `Permissions.md`.

---

## 0. How to use this note

1. §1–§3: why logs matter; architecture; anatomy of an event.
2. §4–§6: logon events, account/group events, process/object events.
3. §7–§9: persistence/lateral/malware events; PowerShell/Defender/Sysmon; channels.
4. §10–§13: audit policy, forwarding/retention, detection mapping, investigation.
5. §14–§16: triage, queries, false positives.
6. §17–§19: labs, self-test, revision.

---

## 1. Why Windows event logs matter

- They are the **primary audit trail** for authentication, privilege use, process creation, object access, persistence, and policy changes.
- Most **MITRE ATT&CK techniques on Windows leave an event** — but only if auditing is enabled.
- They provide **timeline evidence** after an incident and support **SIEM detection** at scale.
- They are the **most common interview topic** for SOC L1/L2 Windows roles.
- Weakness: **default logging is insufficient** — many high-value events are off unless explicitly enabled.

**SOC outcomes:** given an alert you can answer:
- Which event IDs prove the behaviour?
- Which log/channel are they in?
- What fields distinguish benign from malicious?
- What prerequisite auditing must exist?
- How do I correlate across logon sessions and hosts?

---

## 2. Architecture

### 2.1 Components

| Component | Role |
|---|---|
| **Event Log service** (`EventLog`) | Writes/reads `.evtx` files, applies channels. |
| **Event providers** | Components that emit events (Security, System, app, Sysmon). |
| **Channels** | Named streams: `Security`, `System`, `Application`, `Microsoft-Windows-*/Operational`, `Microsoft-Windows-*/Admin`. |
| **`.evtx` files** | Binary log storage in `C:\Windows\System32\winevt\Logs`. |
| **ETW** | Kernel/user tracing framework underlying many providers. |
| **Windows Event Forwarding (WEF)** | Central collection via WinRM/HTTP. |
| **SIEM agent** | Universal Forwarder, Azure Monitor Agent, MDE, etc. |
| **Audit policy** | Determines which security events are generated. |
| **SACL** | Per-object auditing (file/registry access). |

### 2.2 Log locations

```
C:\Windows\System32\winevt\Logs\
├── Security.evtx
├── System.evtx
├── Application.evtx
├── Microsoft-Windows-Sysmon%4Operational.evtx
├── Microsoft-Windows-PowerShell%4Operational.evtx
├── Windows PowerShell.evtx
├── Microsoft-Windows-TaskScheduler%4Operational.evtx
├── Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
├── Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
├── Microsoft-Windows-WMI-Activity%4Operational.evtx
├── Microsoft-Windows-Windows Defender%4Operational.evtx
├── Microsoft-Windows-SMBClient%4Security.evtx
├── Microsoft-Windows-SMBServer%4Security.evtx
└── ...
```

### 2.3 Log types

- **Admin** — problems requiring action.
- **Operational** — routine operations (most useful for SOC).
- **Analytic/Debug** — verbose, usually disabled.
- **Classic** — legacy Application/System/Security.

---

## 3. Anatomy of an event

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{...}"/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-27T10:00:00.000Z"/>
    <EventRecordID>123456</EventRecordID>
    <Correlation/>
    <Execution ProcessID="700" ThreadID="800"/>
    <Channel>Security</Channel>
    <Computer>HOST01.corp.local</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
    ...
  </EventData>
</Event>
```

| Field | Meaning |
|---|---|
| **Provider** | Who emitted the event. |
| **EventID** | Event type within the provider. |
| **Level** | 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose. |
| **Task/Opcode** | Subcategory/operation. |
| **Keywords** | Audit success/failure bitmask for Security events (`0x8020000000000000` success, `0x8010000000000000` failure). |
| **TimeCreated** | UTC timestamp (always convert to UTC for analysis). |
| **EventRecordID** | Monotonic per-log record number — useful for ordering. |
| **Channel** | Log name. |
| **Computer** | Host FQDN. |
| **Security UserID** | SID of the account writing the event (often SYSTEM). |
| **EventData** | Event-specific named fields. |
| **UserData** | Alternative structured payload. |

> **Common mistake:** reading `SubjectUserName` as "the attacker". It is usually the account performing the action, but for service events it may be `SYSTEM` or the service account. Always read the field definitions.

---

## 4. Logon and authentication events

### 4.1 Core logon event IDs

| ID | Meaning |
|---|---|
| **4624** | Successful logon. |
| **4625** | Failed logon. |
| **4634** | Logoff. |
| **4647** | User-initiated logoff. |
| **4648** | Logon with explicit credentials (`runas`). |
| **4672** | Special privileges assigned (admin logon). |
| **4778** | Session reconnected. |
| **4779** | Session disconnected. |
| **4800/4801** | Workstation locked/unlocked. |
| **4802/4803** | Screensaver invoked/dismissed. |

### 4.2 Logon types (critical table)

| Type | Name | Where seen |
|---|---|---|
| **2** | Interactive | Console logon. |
| **3** | Network | SMB, IIS, mapped drives. |
| **4** | Batch | Scheduled tasks. |
| **5** | Service | Service startup. |
| **7** | Unlock | Workstation unlock. |
| **8** | NetworkCleartext | IIS basic auth, `runas /netonly`-like. |
| **9** | NewCredentials | `runas /netonly`. |
| **10** | RemoteInteractive | **RDP**. |
| **11** | CachedInteractive | Cached domain creds (offline). |
| **12** | CachedRemoteInteractive | RDP cached. |
| **13** | CachedUnlock | Unlock cached. |

> `4624` type 3 with an admin account from a workstation to a server is normal for admins and suspicious for a non-admin account.

### 4.3 4624 key fields

| Field | Use |
|---|---|
| `TargetUserName`, `TargetDomainName` | Who. |
| `LogonType` | How. |
| `IpAddress`, `IpPort` | From where (blank/`-`/`127.0.0.1` for local). |
| `WorkstationName` | Source host name. |
| `LogonProcessName` | `Kerberos`, `NtLmSsp`, `Advapi`, `User32`, `MicrosoftEntra`. |
| `AuthenticationPackageName` | `Kerberos`, `NTLM`, `Negotiate`. |
| `ImpersonationLevel` | `%%1832`/`%%1833` etc. |
| `ElevatedToken` | `%%1842` = yes. |
| `TargetLogonId` | Link to other events. |

### 4.4 4625 key fields

`Status`/`SubStatus` explain failure:

| Status | Meaning |
|---|---|
| `0xC000006D` | Bad username or password. |
| `0xC000006A` | Correct username, bad password. |
| `0xC0000064` | Username does not exist. |
| `0xC0000234` | Account locked out. |
| `0xC0000072` | Account disabled. |
| `0xC000006F` | Time restriction. |
| `0xC0000070` | Workstation restriction. |
| `0xC0000193` | Account expired. |
| `0xC0000071` | Password expired. |
| `0xC0000133` | Clock skew (Kerberos). |
| `0xC000015B` | Logon type not granted. |

> `0xC000006A` vs `0xC0000064` is a **username enumeration** signal.

### 4.5 Domain authentication events (DCs)

| ID | Meaning |
|---|---|
| **4768** | Kerberos TGT requested (AS-REQ). |
| **4769** | Kerberos service ticket requested (TGS-REQ). |
| **4770** | Kerberos ticket renewed. |
| **4771** | Kerberos pre-auth failed. |
| **4776** | NTLM credential validation. |
| **4769 + RC4 (`0x17`)** | Possible Kerberoasting. |
| **4768 + pre-auth disabled** | AS-REP roasting. |
| **4740** | Account locked out. |
| **4771 failures burst** | Password spray. |

### 4.6 Credential and privilege events

| ID | Meaning |
|---|---|
| **4672** | Special privileges assigned (admin-equivalent logon). |
| **4673** | Privileged service called. |
| **4674** | Operation on privileged object. |
| **4703** | Token right adjusted. |
| **4704** | User right assigned. |
| **4648** | Explicit credential use. |
| **4688** | Process creation (with command line if enabled). |
| **4689** | Process exit. |
| **4656** | Handle to object requested (SACL). |
| **4663** | Object access attempt (SACL). |
| **4670** | Object permissions changed. |

---

## 5. Account and group events

| ID | Meaning |
|---|---|
| **4720** | User account created. |
| **4722** | Account enabled. |
| **4723** | Password change attempt (self). |
| **4724** | Password reset (by admin). |
| **4725** | Account disabled. |
| **4726** | Account deleted. |
| **4727** | Global security group created. |
| **4728** | Member added to global group. |
| **4729** | Member removed from global group. |
| **4730** | Global group deleted. |
| **4731** | Local security group created. |
| **4732** | Member added to local group. |
| **4733** | Member removed from local group. |
| **4734** | Local group deleted. |
| **4735** | Local group changed. |
| **4737** | Global group changed. |
| **4738** | User account changed. |
| **4739** | Domain policy changed. |
| **4740** | Account locked out. |
| **4741** | Computer account created. |
| **4742** | Computer account changed. |
| **4743** | Computer account deleted. |
| **4756** | Member added to universal group. |
| **4757** | Member removed from universal group. |
| **4764** | Group type changed. |
| **4781** | Account name changed. |

**High-signal:** 4720 (new account), 4732 (added to Administrators), 4728/4756 (added to privileged global/universal group), 4738 (account changed), 4724 (admin password reset), 4740 (lockout).

---

## 6. Process, object, and share events

| ID | Meaning | Notes |
|---|---|---|
| **4688** | Process created | Command line requires *Include command line in process creation events* policy. |
| **4689** | Process exited | Pairs with 4688. |
| **4656** | Handle requested | Requires SACL. |
| **4663** | Object access | Requires SACL; includes access mask. |
| **4670** | Permissions changed | Object ACL change. |
| **4907** | Auditing settings changed | Object SACL change. |
| **5140** | Network share accessed | Includes share name and source. |
| **5145** | Detailed file share access | Includes file path. |
| **5156** | WFP connection allowed | Requires filter auditing. |
| **5157** | WFP connection blocked | Firewall. |
| **5152/5153** | WFP packet blocked/allowed | Verbose. |
| **4697** | Service installed (Security) | Security log version. |
| **7045** | Service installed (System) | System log version; often more reliable. |
| **7040** | Service start type changed. |
| **4698** | Scheduled task created | |
| **4699** | Task deleted. | |
| **4700** | Task enabled. | |
| **4702** | Task updated. | |
| **4701** | Task disabled. | |
| **1102** | Security log cleared | Critical defense-evasion signal. |
| **104** | Event log cleared (System) | |
| **4719** | Audit policy changed | |
| **4902** | Per-user audit policy table created. | |
| **4912** | Per-user audit policy changed. | |

> `4688` **without command line is nearly useless** for triage. Enable the policy via GPO: *Administrative Templates → System → Audit Process Creation → Include command line in process creation events*.

---

## 7. Persistence, lateral movement, and malware events

### 7.1 Persistence

| Evidence | Event |
|---|---|
| New service | **7045** (System), 4697 (Security). |
| Service config change | 7040, registry change (Sysmon 13). |
| Scheduled task | **4698/4702**, TaskScheduler operational (106/200/201). |
| Registry autorun | Sysmon 12/13, 4688 (`reg add`). |
| WMI subscription | WMI-Activity operational (5861), Sysmon 19/20/21. |
| Startup folder | Sysmon 11, 4688, FIM. |
| Winlogon/IFEO/COM | Registry change, Sysmon 13. |
| Accessibility backdoor | File replace (Sysmon 11), 4688. |
| BITS job | BITS-Client operational (3, 59, 60). |

### 7.2 Lateral movement

| Technique | Evidence |
|---|---|
| SMB admin share | 5140/5145, `ADMIN$`/`C$` access. |
| PsExec | Service 7045 (`PSEXESVC`), pipe creation (Sysmon 17/18). |
| WMI | WMI-Activity 5857/5860/5861, 4624 type 3. |
| WinRM | WinRM operational 91/168, 4624 type 3/8. |
| RDP | 4624 type 10, 4778/4779, TerminalServices logs. |
| Remote task | 4698 with remote subject. |
| Pass-the-hash | 4624 type 3 + NTLM + anomalous account/source. |
| Explicit creds | 4648 (`runas`, `Enter-PSSession -Credential`). |

### 7.3 Malware / defense evasion

| Evidence | Event |
|---|---|
| AV detection | Defender 1116, 1117, 1006, 1007. |
| Defender disabled | 5001, 5004, 5010, 5012. |
| Config changed | 5007. |
| Engine failure | 5008. |
| AMSI detection | 1116/1117. |
| Log cleared | **1102**, 104. |
| Audit policy changed | 4719. |
| PowerShell abuse | 4103/4104, 400/403. |
| Process injection | Sysmon 8, 10, 25. |
| Driver load | Sysmon 6, 7045 (driver service). |
| Timestomping | Sysmon 2 (file creation time changed). |
| Ransomware prep | 4688 `vssadmin delete shadows`, `bcdedit`, `wbadmin`. |

---

## 8. PowerShell, Sysmon, and Defender logs

### 8.1 PowerShell

| Log | Events |
|---|---|
| `Windows PowerShell` (classic) | 400 (engine start), 403 (engine stop), 600 (provider start), 800 (pipeline). |
| `Microsoft-Windows-PowerShell/Operational` | **4104 script block**, **4103 module logging**, 4100, 4101, 4102, 4105, 4106. |
| Transcription | Files in configured directory. |
| `Microsoft-Windows-PowerShell/Admin` | 100, 101. |

**Enable:** *Turn on PowerShell Script Block Logging* (4104) and *Module Logging* (4103) via GPO/registry.

### 8.2 Sysmon event IDs (essential)

| ID | Event |
|---|---|
| **1** | Process created (image, command line, parent, hashes, user). |
| **2** | File creation time changed (timestomping). |
| **3** | Network connection. |
| **4** | Sysmon service state changed. |
| **5** | Process terminated. |
| **6** | Driver loaded. |
| **7** | Image/DLL loaded. |
| **8** | CreateRemoteThread (injection). |
| **9** | RawAccessRead (disk). |
| **10** | ProcessAccess (LSASS access). |
| **11** | FileCreate. |
| **12** | Registry object create/delete. |
| **13** | Registry value set. |
| **14** | Registry key/value rename. |
| **15** | FileCreateStreamHash (ADS). |
| **17** | Pipe created. |
| **18** | Pipe connected. |
| **19/20/21** | WMI filter/consumer/binding. |
| **22** | DNS query. |
| **23** | FileDelete (archived). |
| **25** | ProcessTampering. |
| **26** | FileDeleteDetected. |
| **27** | FileBlockExecutable. |
| **28** | FileBlockShredding. |
| **255** | Sysmon error. |

### 8.3 Defender (Windows Defender/Operational)

| ID | Meaning |
|---|---|
| 1006/1007 | Malware detected/action taken (older). |
| 1116 | Malware detected. |
| 1117 | Action taken. |
| 1118/1119 | Remediation success/failure. |
| 5001 | Real-time protection disabled. |
| 5004 | Real-time protection configuration changed. |
| 5007 | Configuration changed (exclusions, ASR). |
| 5008 | Engine failure. |
| 5010 | Scanning disabled. |
| 5012 | Tamper protection event. |

---

## 9. Key channels quick reference

| Channel | Use |
|---|---|
| `Security` | Auth, accounts, privileges, process, object access, shares. |
| `System` | Services (7045), drivers, crashes, time, boot. |
| `Application` | App crashes/errors. |
| `Microsoft-Windows-Sysmon/Operational` | Deep endpoint telemetry. |
| `Microsoft-Windows-PowerShell/Operational` | Script blocks, modules. |
| `Windows PowerShell` | Engine/pipeline. |
| `Microsoft-Windows-TaskScheduler/Operational` | Task creation/run. |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | RDP sessions (21/22/25/39/40). |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | RDP connections (1149). |
| `Microsoft-Windows-WMI-Activity/Operational` | WMI operations/persistence. |
| `Microsoft-Windows-Windows Defender/Operational` | AV. |
| `Microsoft-Windows-SMBServer/Security` | SMB access. |
| `Microsoft-Windows-SMBClient/Security` | SMB client. |
| `Microsoft-Windows-WinRM/Operational` | WinRM sessions. |
| `Microsoft-Windows-Bits-Client/Operational` | BITS jobs. |
| `Microsoft-Windows-DNS-Server/Analytical` | DNS server (verbose). |
| `Microsoft-Windows-Eventlog/Operational` | Log service changes. |
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | Rule changes. |

---

## 10. Audit policy (prerequisite for everything)

### 10.1 Advanced audit subcategories (high value)

| Category → Subcategory | Enables |
|---|---|
| Logon/Logoff → Logon | 4624/4625 |
| Logon/Logoff → Logoff | 4634/4647 |
| Logon/Logoff → Special Logon | 4672 |
| Logon/Logoff → Other Logon/Logoff | 4648, 4778/4779 |
| Account Logon → Kerberos Authentication Service | 4768/4771 |
| Account Logon → Kerberos Service Ticket Operations | 4769/4770 |
| Account Logon → Credential Validation | 4776 |
| Account Management → * | 4720–4781 |
| Detailed Tracking → Process Creation | 4688 |
| Detailed Tracking → Process Termination | 4689 |
| Object Access → File System | 4656/4663 |
| Object Access → Registry | 4656/4663 |
| Object Access → Handle Manipulation | 4656 |
| Object Access → Share | 5140/5145 |
| Policy Change → Audit Policy Change | 4719/4907 |
| Policy Change → Authentication Policy Change | 4739 |
| Privilege Use → Sensitive Privilege Use | 4672/4673/4674 |
| System → Security State Change | 4608/4609 |
| System → Security System Extension | 4610/4611/4614 |
| System → System Integrity | 4612/4614/4616 |
| System → IPsec Driver | 4960–4963 |

### 10.2 Enabling

```cmd
auditpol /get /category:*
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Or GPO: *Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration*.

### 10.3 Command-line auditing

GPO: *Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events* = Enabled.

Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`.

### 10.4 PowerShell logging GPO

*Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell*:
- Turn on Module Logging
- Turn on PowerShell Script Block Logging
- Turn on PowerShell Transcription

### 10.5 SACL for object access

Without a **System Access Control List** entry, 4656/4663 never fire. Enable auditing on the object:

```powershell
$acl = Get-Acl C:\Sensitive
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","ReadData","Success")
$acl.AddAuditRule($rule)
Set-Acl C:\Sensitive $acl
```

---

## 11. Forwarding, retention, and integrity

- **WEF (Windows Event Forwarding)** — native, subscription-based, uses WinRM; good for servers.
- **SIEM agents** — Splunk UF, Azure Monitor Agent, Elastic, Sentinel MDE.
- **MDE/EDR** — cloud telemetry, no local log dependency for many events.
- **Retention** — size/rotation per channel; Security defaults are small. Increase and forward.
- **Log integrity** — restrict access, forward centrally, monitor 1102, use immutable storage.
- **Time sync** — NTP on all hosts; UTC in SIEM; clock skew breaks correlation.
- **Parsing** — field extraction (XML or regex); normalise usernames/SIDs, IPs, hashes.
- **Noise control** — filter known-good high-volume events at the **source** (WEF) or in SIEM, but avoid blind filters that hide lateral movement.

---

## 12. Detection mapping (ATT&CK → events)

| Technique | Key events |
|---|---|
| **Valid Accounts (T1078)** | 4624 (odd type/source), 4672, 4648. |
| **Brute Force (T1110)** | 4625 burst, 4771, 4740, 4776 failures. |
| **Password Spray** | 4625/4771 across many accounts, low rate. |
| **Kerberoasting (T1558.003)** | 4769 with RC4 `0x17`, many SPNs. |
| **AS-REP Roasting (T1558.004)** | 4768 without pre-auth. |
| **Pass-the-Hash (T1550.002)** | 4624 type 3 + NTLM + admin account. |
| **Pass-the-Ticket** | 4768/4769 anomalies, 4624 without 4768. |
| **DCSync (T1003.006)** | 4662 on domain object (replicating changes). |
| **LSASS Dump (T1003.001)** | Sysmon 10 on lsass, 4656/4663. |
| **SAM/NTDS (T1003.002/.003)** | `reg save`, `esentutl`, VSS, 4688 command lines. |
| **Process Injection (T1055)** | Sysmon 8/10/25. |
| **Scheduled Task (T1053.005)** | 4698/4702, TaskScheduler logs. |
| **Service (T1543.003)** | 7045, 4697. |
| **Registry Run (T1547.001)** | Sysmon 13, 4688. |
| **WMI Event Subscription (T1546.003)** | WMI-Activity 5861, Sysmon 19-21. |
| **Account Creation (T1136)** | 4720, 4728/4732. |
| **Indicator Removal (T1070)** | 1102, 104, Sysmon 23/26, timestomping (Sysmon 2). |
| **Impair Defenses (T1562)** | Defender 5001/5007, 4719. |
| **Remote Services (T1021)** | 5140/5145, 4624 type 3/10, WMI/WinRM logs. |
| **Ransomware (T1486)** | 4688 `vssadmin`, mass file writes, 524. |
| **Data Staging/Exfil** | Large SMB/HTTP, BITS, archive creation. |

---

## 13. Investigation workflow with logs

### Step 1 — Anchor the time
- Alert timestamp → UTC; identify timezone of logs; confirm NTP.

### Step 2 — Establish identity
- 4624 + 4672 + 4648; logon type, source IP, workstation, LogonId.
- Account creation/change (4720/4738/4724) if unexpected.

### Step 3 — Establish execution
- 4688 with command line; Sysmon 1; PowerShell 4104.
- Parent chain and hashes.

### Step 4 — Establish behaviour
- Sysmon 3/22 (network), 11 (files), 12-14 (registry), 8/10 (injection/cred access).
- 4663 for sensitive object access.

### Step 5 — Find persistence
- 7045, 4698, Sysmon 13/19-21, startup folder.

### Step 6 — Detect lateral movement
- 5140/5145, 4624 type 3/10, remote task/service, WMI/WinRM.

### Step 7 — Check anti-forensics
- 1102/104, 4719, Defender 5001/5007, Sysmon 2/25.

### Step 8 — Build the timeline
- Merge events by `EventRecordID` within channel and by UTC across channels/hosts.
- Note gaps (log cleared, agent offline).

### Step 9 — Scope and respond
- Hunt same account/hash/IP across estate; contain; preserve logs.

---

## 14. Triage playbooks

### A. Failed logon burst (4625)
1. Single account or many? Internal or external IP?
2. Status codes (`0xC000006A` vs `0xC0000064`) → spray vs brute force.
3. Success after failures? (4624).
4. Lockouts (4740), source diversity.
5. Block source, enforce MFA/lockout, notify user.

### B. Admin logon (4672) from unexpected host
1. Which account, source, logon type?
2. Is that host a PAW/jump host?
3. What did the account do next?
4. If anomalous → reset credentials, review privilege use.

### C. New service (7045)
1. Service name, image path, account, signature.
2. Creator process/user (4688 correlation).
3. Did it run? Network/children?
4. Remove if unauthorized.

### D. Scheduled task (4698)
1. Task name, action, trigger, author.
2. Binary path/signature.
3. Legit automation or persistence?

### E. 1102 log cleared
1. Subject user/domain/logon ID.
2. Events immediately prior (from forwarded copy).
3. Treat as high severity; state may be compromised.

### F. Kerberoasting (4769 RC4)
1. Which account requested, how many SPNs, source host.
2. Service account password age/privilege.
3. Rotate service account passwords (managed accounts), hunt follow-on.

### G. RDP session anomaly
1. 4624 type 10, source IP, account, time.
2. 4778/4779 reconnects; 1149 connection.
3. What happened in-session? Data access, tooling.

### H. Object access (4663) on sensitive file
1. Who, what object, what access mask (read/write/delete/ACL).
2. Approved process or unknown?
3. Data classification and exfil risk.

### Severity guide

| Scenario | Typical severity |
|---|---|
| Failed logons, no success | Low–Medium |
| Successful logon after spray | High |
| New service/task (unapproved) | High |
| LSASS access | Critical |
| Domain admin / DCSync | Critical |
| Log cleared / Defender disabled | High–Critical |
| Sensitive file mass access | High |
| Kerberoasting pattern | High |
| RDP from anomalous geo | High |

---

## 15. Queries and commands

### 15.1 PowerShell

```powershell
# Recent failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='Type';e={$_.Properties[10].Value}}, @{n='IP';e={$_.Properties[19].Value}}, @{n='Status';e={$_.Properties[7].Value}}

# Successful logons by type
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 |
  Group-Object {$_.Properties[8].Value} | Sort-Object Count -Descending

# Process creation with command line
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[1].Value}}, @{n='Image';e={$_.Properties[5].Value}}, @{n='Cmd';e={$_.Properties[8].Value}}

# Service installs
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50

# Log clear
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 10

# Sysmon network
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 50

# PowerShell script blocks
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 20 |
  Select-Object TimeCreated, @{n='Script';e={$_.Properties[2].Value}}

# XML query (server-side filtering)
$q = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]</Select></Query></QueryList>
"@
Get-WinEvent -FilterXml $q -MaxEvents 50
```

### 15.2 wevtutil

```cmd
wevtutil el
wevtutil gl Security
wevtutil qe Security /c:20 /rd:true /f:text
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:20 /f:text
wevtutil sl Security /ms:1073741824
```

### 15.3 Splunk

```spl
index=wineventlog EventCode=4625
| stats count by src_ip, user, status
| where count > 20
```

```spl
index=wineventlog EventCode=4624 LogonType=3
| stats dc(src_ip) as sources values(ComputerName) as hosts by user
| where sources > 5
```

```spl
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| stats count values(ServiceName) as spns by user, src_ip
| where count > 10
```

```spl
index=wineventlog sourcetype="WinEventLog:Security"
| eval user=coalesce(TargetUserName, SubjectUserName)
| transaction user maxspan=30m
| where eventcount > 50
```

### 15.4 KQL

```kusto
SecurityEvent
| where EventID == 4625
| summarize Failures = count(), IPs = make_set(IpAddress) by Account, bin(TimeGenerated, 1h)
| where Failures > 20
```

```kusto
SecurityEvent
| where EventID == 4688
| where Process has_any ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName
```

```kusto
SecurityEvent
| where EventID in (1102, 104)
| project TimeGenerated, Computer, Account, Activity
```

### 15.5 Forensic parsers

- **EvtxECmd** (Eric Zimmerman) — bulk CSV/JSON export.
- **Chainsaw** — Sigma-based hunting over EVTX.
- **Hayabusa** — timeline + Sigma detection.
- **python-evtx**, **EvtxParser**.
- **Timeline Explorer** — review CSV output.

---

## 16. False positives and gotchas

| Issue | Explanation |
|---|---|
| 4625 from services | Cached/expired service creds retry constantly. |
| 4625 from scanners | Vulnerability scanners authenticate-and-fail. |
| 4672 for SYSTEM | SYSTEM logon always has privileges — filter carefully. |
| 4688 missing command line | Policy not enabled. |
| 4663 missing | No SACL on the object. |
| Logon type 3 from `127.0.0.1` | Local service/IIS; not remote. |
| `ANONYMOUS LOGON` | Null sessions, some legacy apps. |
| Machine account logons (`HOST$`) | Normal Kerberos/NTLM computer auth. |
| 4769 noise | All Kerberos service access generates these — filter on RC4 + volume. |
| 5145 volume | File server auditing can be enormous — scope SACL. |
| 7045 patching | Windows Update/software installs create services. |
| 1102 by support | Some tools clear logs; verify source. |
| Duplicate events | Multiple collectors/forwarders; dedupe by `EventRecordID` + host. |
| Timezone | Local time in viewer vs UTC in SIEM — always verify. |
| Truncated fields | Long command lines may be truncated — correlate with 4104/Sysmon. |
| Log rollover | Small max size causes loss; check `wevtutil gl`. |

---

## 17. Lab practice plan

1. Enable advanced audit + command line + PowerShell logging + Sysmon in a lab VM.
2. Generate 4624/4625 with different logon types (console, SMB, RDP, `runas`).
3. Trigger account events (create user, add to Administrators, lock out).
4. Create a service and a scheduled task; compare 7045/4698 evidence.
5. Dump LSASS with a benign lab tool; correlate Sysmon 10 + 4656/4663.
6. Run encoded PowerShell; compare 4688, 4104, Sysmon 1.
7. Set a SACL on a folder; read/modify it; observe 4656/4663.
8. Clear the Security log in the lab; observe 1102 and the gap.
9. Use EvtxECmd/Chainsaw to parse and hunt the collected logs.
10. Build a 24-hour timeline for a simulated intrusion across two hosts.

---

## 18. Self-test questions

1. What are the five most important event IDs for a logon investigation?
2. Which logon type is RDP, and which is SMB?
3. What is the difference between `4625` status `0xC000006A` and `0xC0000064`?
4. Which event IDs show a new service, and in which log?
5. What must be enabled to see command lines in 4688?
6. What must be configured to see 4663?
7. Which event indicates the Security log was cleared?
8. Which PowerShell event contains the script text?
9. Which Sysmon event shows LSASS access?
10. Which event IDs indicate Kerberoasting?
11. What does `4672` mean, and why is it noisy?
12. Which events show lateral movement over SMB?
13. How do you correlate events from one logon session?
14. What is WEF, and why use it?
15. What are three signs that logging was tampered with?

---

## 19. One-page revision checklist

- [ ] Why: primary audit trail; only as good as audit policy; timeline + SIEM.
- [ ] Architecture: EventLog service, providers, channels, `.evtx`, ETW, WEF, SIEM agent, audit policy, SACL.
- [ ] Event anatomy: provider, ID, level, task, keywords, TimeCreated (UTC), EventRecordID, channel, computer, SID, EventData.
- [ ] Logons: 4624/4625/4634/4647/4648/4672/4778/4779; logon types 2/3/4/5/7/8/9/10/11/12/13; 4624 fields; 4625 status codes; DC events 4768/4769/4770/4771/4776/4740.
- [ ] Accounts: 4720/4722/4723/4724/4725/4726/4728/4732/4738/4740/4756/4781.
- [ ] Process/object: 4688/4689/4656/4663/4670/4907/5140/5145/5156/5157/4697/7045/7040.
- [ ] Persistence: 7045/4697/4698/4702, Sysmon 12/13/19-21, WMI 5861, BITS.
- [ ] Evasion: 1102/104/4719, Defender 5001/5007, Sysmon 2/25.
- [ ] PowerShell: 4103/4104/400/403/transcription; Sysmon IDs 1-28; Defender 1116/1117/5001/5007.
- [ ] Channels: Security, System, Application, Sysmon, PowerShell, TaskScheduler, TerminalServices, WMI, Defender, SMB, WinRM, BITS, Firewall.
- [ ] Audit policy: subcategories, `auditpol`, command-line policy, PowerShell GPO, SACL.
- [ ] Ops: WEF, retention, integrity, NTP/UTC, parsing, noise filtering.
- [ ] ATT&CK mapping: valid accounts, brute force/spray, Kerberoasting, AS-REP, PTH/PTT, DCSync, LSASS, SAM/NTDS, injection, tasks, services, run keys, WMI, account creation, indicator removal, impair defenses, remote services, ransomware, exfil.
- [ ] Investigation: time → identity → execution → behaviour → persistence → lateral → anti-forensics → timeline → scope/respond.
- [ ] Triage: 4625 burst, 4672 anomaly, 7045, 4698, 1102, 4769 RC4, RDP anomaly, 4663 sensitive.
- [ ] Queries: `Get-WinEvent -FilterHashtable/-FilterXml`, `wevtutil qe`, Splunk `EventCode`, KQL `SecurityEvent`, EvtxECmd/Chainsaw/Hayabusa.
- [ ] Gotchas: service 4625 noise, SYSTEM 4672, missing cmdline/SACL, 127.0.0.1 type 3, machine accounts, 4769/5145 volume, patching 7045, duplicates, timezone, truncation, rollover.
