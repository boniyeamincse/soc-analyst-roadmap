# Windows — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Windows Event Logs](Windows-Event-Logs.md) · [Linux Logging →](linuxlog.md)

> Goal: understand Windows internals, identity, persistence surfaces, and forensic artifacts well enough to **detect, investigate, and scope intrusions on Windows endpoints and servers**.
> Event IDs in depth → [Windows-Event-Logs.md](Windows-Event-Logs.md); process behaviour → [Processes.md](Processes.md); ACLs → [Permissions.md](Permissions.md); AD/domain attacks → the AD skill.

---

## 0. How to use this note

1. §1–§2: why Windows matters; architecture map.
2. §3–§5: identity/auth, registry, services & persistence.
4. §6–§8: PowerShell/Defender/Sysmon, common attacks, artifacts.
5. §9–§12: telemetry, detection, investigation, triage.
6. §13–§15: commands, false positives, hardening.
7. §16–§18: labs, self-test, revision.

---

## 1. Why Windows matters to a SOC analyst

- The majority of enterprise endpoints and a large share of servers run Windows.
- Most **ransomware, commodity malware, and phishing payloads** target Windows.
- **Active Directory** (the dominant enterprise identity system) is Windows-centric.
- Windows produces **rich but fragmented telemetry** — knowing which log/artifact answers which question is the core skill.
- Windows is where **credential theft, lateral movement, and persistence** are most standardised, so attacker patterns are learnable.

**SOC outcomes:** given a Windows alert you can answer:
- What user/session/privilege was involved?
- What executed, from where, and what did it do?
- What persistence was created?
- Were credentials accessed or moved?
- What artifacts prove it after the fact?
- What is the containment scope?

---

## 2. Architecture map

| Layer | Components | SOC relevance |
|---|---|---|
| **Kernel** | NT kernel, HAL, drivers, object manager | Rootkits, BYOVD, driver abuse. |
| **Executive** | Object/security/process/memory/I/O managers | Tokens, handles, privileges. |
| **User mode** | Win32, NT native, .NET, UWP | Application behaviour. |
| **Services** | SCM, `services.exe`, `svchost.exe` | Persistence, privileges, lateral movement. |
| **Registry** | Hives, keys, values | Config, persistence, forensics. |
| **WMI/CIM** | Repository, providers, subscriptions | Persistence, lateral movement, recon. |
| **COM/DCOM** | CLSIDs, servers | Hijacking, lateral movement. |
| **Networking** | Winsock, SMB, RPC, WinRM, RDP | Lateral movement, C2. |
| **Identity** | SAM, LSASS, Kerberos, NTLM, DPAPI | Credential theft, auth abuse. |
| **Logging** | EventLog, ETW, Sysmon, Defender | Detection. |

**Editions:** Workstation (Pro/Enterprise/Education) vs Server (Standard/Datacenter, Core vs Desktop Experience). **Server Core** has no GUI — many detections rely on logs only.

---

## 3. Identity, authentication, and credentials

### 3.1 Accounts and SIDs

- **Local accounts** in SAM; **domain accounts** in AD.
- **Built-in**: Administrator (RID 500), Guest (501), `SYSTEM` (`S-1-5-18`), `LOCAL SERVICE`, `NETWORK SERVICE`.
- **Service accounts**: LocalSystem, LocalService, NetworkService, domain service accounts, **gMSA**, **virtual accounts**.
- **SIDs** are the real identity; names are display.

### 3.2 Logon and tokens

- **Interactive** (console/RDP), **network** (SMB), **batch**, **service**, **network cleartext**, **new credentials** (`runas /netonly`).
- **Access token** = user SID + groups + privileges + integrity + logon session.
- **UAC** produces a filtered token for admins; elevation yields a full token.
- **Logon session** (`LogonId`) links events across the logon lifetime.

### 3.3 Credential storage

| Store | Contents | Theft method |
|---|---|---|
| **LSASS** | Interactive creds, hashes, Kerberos tickets | `procdump`, `comsvcs.dll`, Mimikatz, `sekurlsa`. |
| **SAM** | Local account hashes | `reg save`, `esentutl`, Volume Shadow Copy. |
| **NTDS.dit** | Domain hashes | DCSync (AD), VSS copy on DC. |
| **DPAPI** | App/browser/credential secrets | Master key + user context. |
| **Credential Manager** | Saved creds | `cmdkey`, DPAPI. |
| **Browser stores** | Passwords/cookies | File + DPAPI. |
| **LSA secrets** | Service account creds | Registry `SECURITY`. |

> **Defensive controls:** LSA protection (`RunAsPPL`), Credential Guard, Protected Users, disable WDigest, restrict `SeDebugPrivilege`, EDR LSASS protection, tiered admin.

### 3.4 Authentication protocols

- **NTLM** — challenge/response; relay and pass-the-hash targets. Restrict/disable where possible.
- **Kerberos** — tickets (TGT/TGS); Kerberoasting, AS-REP roasting, pass-the-ticket, Golden/Silver tickets (AD skill).
- **Negotiate** — picks Kerberos then NTLM.
- **Web/cloud** — OAuth/OIDC/SAML to Entra ID; token theft and consent phishing.

---

## 4. Registry

### 4.1 Structure

`HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`. Hives on disk: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `NTUSER.DAT`, `UsrClass.dat`.

### 4.2 High-value keys for SOC

| Key | Why |
|---|---|
| `HKLM\...\CurrentVersion\Run`, `RunOnce` | Autostart. |
| `HKCU\...\CurrentVersion\Run`, `RunOnce` | Per-user autostart. |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Services, drivers, ImagePath. |
| `HKLM\...\Winlogon` (`Shell`, `Userinit`, `Notify`) | Logon persistence. |
| `HKLM\...\Image File Execution Options` | Debugger hijack, mitigations. |
| `HKLM\...\AppInit_DLLs`, `AppCertDlls` | DLL injection. |
| `HKLM\...\Explorer\Browser Helper Objects` | IE/explorer plugins. |
| `HKLM\...\Shell Extensions\Approved` | Shell extension. |
| `HKLM\...\Policies\Explorer\Run` | Policy-based autostart. |
| `HKLM\SYSTEM\...\NetworkProvider` | Credential capture. |
| `HKLM\...\Print\Monitors` | Print nightmare-style abuse. |
| `HKLM\...\COM` / `HKCR\CLSID` | COM hijacking. |
| `HKLM\SYSTEM\...\Services\...\Parameters` | Service config, DLLs. |
| `HKLM\...\CurrentVersion\Uninstall` | Installed software. |
| `HKU\...\Software\Microsoft\Windows\CurrentVersion\Explorer\*` | User activity (UserAssist, TypedPaths, RunMRU, RecentDocs). |
| `HKLM\SYSTEM\...\USBSTOR` | USB history. |
| `HKLM\SYSTEM\...\MountedDevices` | Drive history. |
| `HKLM\...\Terminal Server Client\Servers` | RDP history. |

### 4.3 Registry forensics

- **AmCache** (`Amcache.hve`) — executed/installed program metadata.
- **ShimCache/AppCompatCache** — executables that existed/ran.
- **SRUM** (`SRUDB.dat`) — network/app usage per process.
- **BAM/DAM** — background activity.
- **UserAssist** — GUI program execution counts/times (ROT13 names).
- **ShellBags** — folder navigation.
- **RecentDocs / JumpLists / LNK** — file access.
- **MUI cache** — application display names.

---

## 5. Services, tasks, and persistence

### 5.1 Services

- Managed by **SCM** (`services.exe`); registry config; `ImagePath`, `ServiceDll`, `ObjectName`.
- **svchost** hosts service DLLs via `ServiceDll` under `HKLM\SYSTEM\...\Services\<svc>\Parameters`.
- Persistence: new service (7045), modified `ImagePath`, DLL service, `sc create`, `New-Service`.
- Privilege escalation: weak ACLs, unquoted path, writable binary, `SeImpersonate`.

### 5.2 Scheduled tasks

- Task Scheduler (`TaskScheduler/Operational` log), XML in `C:\Windows\System32\Tasks`.
- Persistence/lateral movement: `schtasks /create`, remote `/s`, SYSTEM-run tasks.
- Detect `4698/4699/4700/4702` and task XML changes.

### 5.3 Other persistence

| Mechanism | Artifact |
|---|---|
| Startup folders | Files in `Startup`. |
| WMI event subscription | `__EventFilter`, `__EventConsumer`, binding; WMI repo. |
| Winlogon | `Shell`/`Userinit` values. |
| IFEO | Debugger key. |
| COM hijack | CLSID in HKCU. |
| DLL side-loading | Writable dir + missing DLL. |
| Accessibility backdoor | `sethc`, `utilman`, `osk`, `magnify` replaced/IFEO. |
| Screensaver | `SCRNSAVE.EXE`. |
| Print processors/monitors | Spooler abuse. |
| BITS | `bitsadmin /addfile`, jobs DB. |
| WinRM/SSH | Remote shells. |
| RDP | `fDenyTSConnections`, shadowing. |
| Boot/logon scripts | GPO/registry. |
| AppInit/AppCert | DLL injection. |
| Time providers | `W32Time` DLL. |
| Netsh helper DLL | `netsh add helper`. |
| Office add-ins | Registry/templates. |

### 5.4 Lateral movement techniques

| Technique | Evidence |
|---|---|
| **SMB/Admin shares** | 5140/5145, `ADMIN$` writes, service creation. |
| **PsExec** | Service `PSEXESVC`, named pipe `psexesvc`. |
| **WMI** | `wmic /node:`, `Win32_Process.Create`, WMI-Activity log. |
| **WinRM/PowerShell Remoting** | 4624 type 3/8, WinRM operational logs. |
| **RDP** | 4624 type 10, 4778/4779, TerminalServices logs. |
| **Scheduled task remote** | 4698 with remote context. |
| **Pass-the-hash/ticket** | NTLM/Kerberos anomalies, 4624 type 3. |
| **DCOM** | `MMC20.Application`, `ShellWindows` execution. |
| **SSH/WinRM over cloud** | Network + auth logs. |

---

## 6. PowerShell, Defender, Sysmon

### 6.1 PowerShell logging

| Log | Event | Content |
|---|---|---|
| **Script Block** | 4104 | Deobfuscated script text. |
| **Module** | 4103 | Pipeline/module execution. |
| **Transcription** | files | Full session transcript. |
| **Engine** | 400/403/600 | Start/stop/state. |
| **Operational** | 4100-4104 | Host/script events. |

Enable via GPO: *Turn on Module Logging*, *Turn on PowerShell Script Block Logging*, *Turn on PowerShell Transcription*, *Include invocation headers*.

> Script block logging is the **single highest-value PowerShell control** for SOC.

### 6.2 AMSI

- Scans scripts/content at runtime; logs to `Microsoft-Windows-Windows Defender/Operational` (1116/1117) when detected.
- Bypasses exist; `amsi.dll` patching and `AMSI_PROVIDER` tampering are red flags.

### 6.3 Defender / MDE

| Event / Action | Meaning |
|---|---|
| 1116 | Malware detected. |
| 1117 | Action taken. |
| 5001 | Real-time protection disabled. |
| 5007 | Configuration changed. |
| 5008 | Engine failure. |
| ASR rules | Behaviour blocking (Office child process, LSASS access, etc.). |
| Tamper protection | Blocks disabling. |

**MDE** adds process/network/file/registry telemetry (`DeviceProcessEvents`, `DeviceNetworkEvents`, etc.).

### 6.4 Sysmon

Deploy with a tuned config. Key IDs: 1 process create, 3 network, 5 process exit, 6 driver load, 7 image load, 8 remote thread, 9 raw access, 10 process access, 11 file create, 12-14 registry, 15-16 file stream, 17-18 pipe, 19-21 WMI, 22 DNS, 23 file delete, 25 process tampering, 26 file delete logged.

---

## 7. Common Windows attacks

### 7.1 Initial access

- Phishing (macro, LNK, ISO/IMG, HTML smuggling, OneNote), malicious ads, USB.
- Exposed RDP/VPN, vulnerable edge services (Exchange, Citrix, Fortinet, etc.).
- Credential stuffing / password spray against VPN, RDP, OWA, Entra ID.

### 7.2 Execution

- `rundll32`, `regsvr32`, `mshta`, `certutil`, `wmic`, `bitsadmin`, `installutil`, `msbuild`.
- PowerShell encoded/`IEX`/download cradles.
- Malicious LNK/HTA/JS/VBS; `wscript`/`cscript`.
- Signed binary proxy execution; DLL side-loading.
- Office macros/add-ins/COM.

### 7.3 Privilege escalation

- Service misconfig (weak ACLs, unquoted path, writable binary).
- `SeImpersonatePrivilege` (Potato family), `SeBackup`/`SeRestore`, `SeDebug`.
- UAC bypass (`fodhelper`, `computerdefaults`, `sdclt`, `eventvwr`).
- AlwaysInstallElevated, weak permissions on tasks/registry.
- Credential theft → admin reuse.
- Kernel/driver exploits (BYOVD).

### 7.4 Credential access

- LSASS dump (`procdump`, `comsvcs.dll`, Mimikatz).
- SAM/SECURITY registry save; VSS copy.
- DPAPI master keys; browser credential theft.
- Kerberoasting/AS-REP (AD skill), password spraying.
- Token theft/impersonation.

### 7.5 Lateral movement

- SMB admin shares, PsExec, WMI, WinRM, RDP, DCOM, scheduled tasks.
- Pass-the-hash/ticket, over-pass-the-hash.
- RDP hijacking, shadowing.

### 7.6 Persistence

See §5. Plus: registry Run keys, startup folder, services, tasks, WMI, COM, IFEO, accessibility, BITS, Winlogon, DLL search order, browser extensions, Office templates.

### 7.7 Defense evasion

- AMSI/ETW bypass, AV exclusion (`Add-MpPreference`), Defender disable (5001/5007).
- Log clearing (**1102**, 104), event log service stop.
- Timestomping, indicator removal, masquerading, process injection.
- Rootkits/BYOVD, disabling LSA protection.
- Living off the land; signed binaries; cloud services for C2.

### 7.8 Impact

- Ransomware (shadow copy deletion `vssadmin delete shadows`, mass encryption, ransom notes).
- Data staging/exfil, wipers, business email compromise.

---

## 8. Forensic artifacts (where to look)

| Artifact | Path | Answers |
|---|---|---|
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | What executed, run count, last run. |
| **AmCache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Installed/executed programs, hashes. |
| **ShimCache** | `SYSTEM` hive | Executables present (execution proxy). |
| **SRUM** | `C:\Windows\System32\sru\SRUDB.dat` | Per-process network/app usage. |
| **BAM/DAM** | `SYSTEM` hive | Background activity, last execution. |
| **UserAssist** | `NTUSER.DAT` | GUI program usage. |
| **LNK/JumpLists** | `Recent`, `AutomaticDestinations` | Files/folders opened. |
| **ShellBags** | `UsrClass.dat` | Folder navigation. |
| **MFT/USN** | `$MFT`, `$UsnJrnl` | File creation/deletion timeline. |
| **Event logs** | `C:\Windows\System32\winevt\Logs` | What happened. |
| **WMI repo** | `C:\Windows\System32\wbem\Repository` | WMI persistence. |
| **PowerShell logs** | Event logs / transcription | Script content. |
| **Defender logs** | Event log / MDE | Detections/actions. |
| **Browser data** | Profile dirs | History/downloads/creds. |
| **Memory** | RAM image | Injected code, creds, keys. |
| **Pagefile/hiberfil** | `pagefile.sys`, `hiberfil.sys` | Residual data. |
| **Recycle Bin** | `$Recycle.Bin` | Deleted files. |
| **Volume Shadow Copies** | `vssadmin list shadows` | Prior file versions. |
| **USB history** | `USBSTOR`, setupapi logs | Device insertion. |
| **RDP artifacts** | `Terminal Server Client`, event logs | Remote sessions. |

**Order of volatility:** memory → network state → running processes → temp files → disk artifacts → backups.

---

## 9. Telemetry map

| Question | Source |
|---|---|
| Who logged on? | 4624/4625/4634/4647/4648, 4778/4779. |
| What ran? | 4688 (+command line), Sysmon 1, EDR. |
| What did it touch? | Sysmon 11, 4663, EDR file events. |
| Network? | Sysmon 3/22, firewall, proxy, DNS, EDR. |
| Persistence? | 7045, 4698, Sysmon 12/13/19-21, registry. |
| Privilege use? | 4672/4673/4674, 4703, `whoami /priv`. |
| Credential access? | Sysmon 10, 4656/4663 on LSASS, Defender. |
| Lateral movement? | 5140/5145, 4624 types, WMI/WinRM/RDP logs. |
| Defense evasion? | 1102, 5001/5007, 4104, Sysmon 25. |
| Ransomware? | 4688 (`vssadmin`, `bcdedit`), file writes, shadow copy events. |

---

## 10. Detection engineering

### 10.1 High-signal ideas

1. Office/browser → shell (see [Processes.md](Processes.md)).
2. LSASS access/dump.
3. New service with suspicious binary path.
4. Scheduled task created by unusual user/process.
5. WMI event subscription created.
6. Registry autorun created/modified.
7. Defender disabled / exclusions added.
8. Event log cleared (1102/104).
9. Security-relevant PowerShell (encoded/download/AMSI).
10. Admin share access + service creation (lateral movement).
11. RDP from unusual source / off-hours.
12. Kerberoasting/AS-REP/spray patterns (AD skill).
13. Pass-the-hash indicators (NTLM, 4624 type 3, anomalous account).
14. Shadow copy deletion / backup tampering.
15. Mass file rename/encryption.
16. New local admin / privileged group change.
17. UAC bypass binaries.
18. Accessibility binary replaced.
19. `netsh` helper / time provider / print monitor persistence.
20. Unsigned driver load (BYOVD).

### 10.2 Splunk SPL

**LSASS access:**
```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| where match(lower(TargetImage), "lsass\.exe$")
| where GrantedAccess IN ("0x1010","0x1038","0x1fffff","0x1410","0x1438","0x143a","0x40")
| table _time, ComputerName, SourceImage, TargetImage, GrantedAccess, CallTrace
```

**Defender disabled / exclusion:**
```spl
index=wineventlog (sourcetype="WinEventLog:Microsoft-Windows-Windows Defender/Operational")
| where EventCode IN (5001,5004,5007,5010,5012)
| table _time, ComputerName, EventCode, _raw
```

**Event log cleared:**
```spl
index=wineventlog EventCode IN (1102,104)
| table _time, ComputerName, SubjectUserName, _raw
```

**New service:**
```spl
index=wineventlog EventCode=7045
| where NOT match(ImagePath, "(?i)(system32|syswow64|program files)")
| table _time, ComputerName, ServiceName, ImagePath, AccountName
```

**Scheduled task created:**
```spl
index=wineventlog EventCode=4698
| table _time, ComputerName, SubjectUserName, TaskName, TaskContent
```

**Ransomware precursor (shadow copy deletion):**
```spl
index=wineventlog EventCode=4688
| where match(lower(CommandLine), "(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete.*backup)")
| table _time, ComputerName, User, CommandLine
```

**Suspicious service + admin share:**
```spl
index=wineventlog (EventCode=7045 OR EventCode=5140)
| stats values(EventCode) as ev by ComputerName, ServiceName, SubjectUserName
```

**WMI subscription:**
```spl
index=wineventlog (sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational")
| where match(_raw, "(?i)(__EventFilter|__EventConsumer|__FilterToConsumerBinding)")
| table _time, ComputerName, User, _raw
```

### 10.3 KQL (Sentinel/Defender)

**LSASS access:**
```kusto
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, AdditionalFields
```

**Defender disabled:**
```kusto
DeviceEvents
| where ActionType in ("AntivirusDisabled","AntivirusExclusionsAdded","TamperProtectionDisabled")
| project TimeGenerated, DeviceName, AccountName, ActionType, AdditionalFields
```

**New service from non-standard path:**
```kusto
DeviceProcessEvents
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

**Shadow copy deletion:**
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin","wmic shadowcopy","bcdedit","wbadmin")
| where ProcessCommandLine has_any ("delete","shadows","recoveryenabled")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

**RDP logon from rare IP:**
```kusto
SecurityEvent
| where EventID == 4624 and LogonType == 10
| summarize Logons = count(), IPs = make_set(IpAddress) by Account, Computer
| where array_length(IPs) > 5
```

**Kerberoasting pattern:**
```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| summarize Count = count() by Account, IpAddress, bin(TimeGenerated, 10m)
| where Count > 20
```

### 10.4 Sigma sketch

```yaml
title: Suspicious Service Image Path
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ImagePath|contains:
      - '\Temp\'
      - '\Users\Public\'
      - '\ProgramData\'
      - '\AppData\'
  condition: selection
level: high
```

---

## 11. Investigation workflow

### Step 1 — Triage the alert
- Host, user, time, detection, severity, initial evidence.

### Step 2 — Establish the session
- 4624/4634, logon type, source IP, account, LogonId.
- Was it expected (VPN/RDP/business hours)?

### Step 3 — Build execution chain
- Parent/child processes, command lines, hashes/signatures.
- Was it user-driven or service/automation?

### Step 4 — Find persistence
- Services, tasks, registry autoruns, WMI, startup, COM, IFEO, accessibility.

### Step 5 — Check credential access
- LSASS access, SAM/NTDS copies, DPAPI, browser stores, Kerberos anomalies.

### Step 6 — Network and lateral movement
- C2, downloads, SMB/RDP/WinRM connections, admin shares, remote service creation.

### Step 7 — Scope
- Same hash/command/task across estate; related accounts; domain controller activity.

### Step 8 — Contain and eradicate
- Isolate host, disable accounts, reset passwords (krbtgt if DC compromise), remove persistence, block IOCs.

### Step 9 — Preserve and document
- Memory + key artifacts, timeline, verdict, gaps, recommendations.

---

## 12. Triage playbooks

### A. "Malware detected by Defender"
1. Detection name, file path, hash, action taken.
2. Did it execute? What did it spawn/connect to?
3. Was it quarantined or did it persist?
4. Hunt hash/path on other hosts.

### B. "LSASS access"
1. Source process, user, granted access, call trace.
2. Approved security tool or unknown?
3. If unknown → assume credential compromise; reset creds, isolate, hunt.

### C. "New service / scheduled task"
1. Binary path, signature, account, creator.
2. Approved deployment or persistence?
3. Check execution, network, and lateral use.

### D. "Encoded PowerShell"
1. Decode; understand action.
2. Parent process and user.
3. Follow network/files/children.

### E. "RDP logon anomaly"
1. Source IP/geo, account, time, MFA.
2. Success after failures? Spray?
3. Check session activity and data access.

### F. "Event log cleared"
1. Who/what cleared it (1102 subject).
2. What else happened just before?
3. Treat as high-severity defense evasion.

### G. "Defender disabled / exclusions"
1. Who changed, via what (GPO, CLI, registry)?
2. Approved management or attacker?
3. Re-enable, hunt for malware that followed.

### H. "Ransomware indicators"
1. Shadow copy deletion, backup tampering, mass encryption.
2. Identify patient zero and lateral spread.
3. Isolate, preserve, engage IR/leadership; do not reboot blindly.

### Severity guide

| Scenario | Typical severity |
|---|---|
| Commodity malware quarantined, no execution | Low–Medium |
| Confirmed malicious execution, contained | High |
| LSASS dump / credential theft | Critical |
| Domain admin compromise / DCSync | Critical |
| Ransomware / wiper | Critical |
| Persistence on server | High |
| Defender tampering | High |
| Unapproved admin login | High |
| Phishing email blocked | Low |

---

## 13. Commands

```powershell
# Identity / privileges
whoami /all
whoami /priv
Get-LocalUser; Get-LocalGroupMember Administrators
Get-CimInstance Win32_LoggedOnUser

# Sessions / logons
query user
quser
Get-CimInstance Win32_LogonSession

# Processes / network
Get-Process | Sort-Object CPU -Descending | Select -First 20
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection -State Established
netstat -ano

# Services / tasks / autoruns
Get-Service | Where Status -eq Running
sc qc ServiceName
Get-ScheduledTask
Get-CimInstance Win32_StartupCommand
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

# Registry / persistence
reg query HKLM\SYSTEM\CurrentControlSet\Services /s /f ImagePath
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter

# Logs
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text

# Hashes / signatures
Get-FileHash file.exe -Algorithm SHA256
Get-AuthenticodeSignature file.exe
sigcheck -a -h file.exe

# Defender
Get-MpComputerStatus
Get-MpPreference
Get-MpThreatDetection

# Firewall / shares
Get-NetFirewallRule | Where Enabled -eq True
Get-SmbShare; Get-SmbShareAccess -Name Share

# Audit policy
auditpol /get /category:*

# RDP / sessions
qwinsta
Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' fDenyTSConnections

# Shadow copies / backups
vssadmin list shadows
Get-CimInstance Win32_ShadowCopy
```

```cmd
tasklist /v
systeminfo
net user
net localgroup administrators
net share
net session
schtasks /query /fo LIST /v
wmic process get name,processid,parentprocessid,commandline
reg save HKLM\SAM sam.hiv
```

> `reg save`/LSASS capture is evidence collection — follow legal/chain-of-custody rules.

---

## 14. Common false positives

| Alert | Often actually |
|---|---|
| LSASS access | EDR, backup, password managers, admin tools. |
| New service | Software deployment, patching, monitoring agents. |
| Scheduled task | IT automation, updaters, backup. |
| Encoded PowerShell | SCCM/Intune, monitoring, vendor scripts. |
| Registry autorun | Legitimate installers/updaters. |
| Admin share access | Backup, inventory, admin workflows. |
| RDP from unusual IP | Travelling user, VPN pool, jump host. |
| Defender changes | Central management, GPO, troubleshooting. |
| Event log clear | Support procedures, log rotation tools. |
| WMI activity | Management tools, SCCM, monitoring. |
| Unsigned binary | In-house software, open source. |
| Shadow copy commands | Backup software, storage admin. |

**Validate with:** change management, deployment tooling, user confirmation, hash reputation, prevalence, and whether follow-on malicious behaviour exists.

---

## 15. Hardening

- **Patch** OS and edge apps (Exchange, VPN, browsers, Office, Java).
- **Tiered administration**; no domain admin on workstations; LAPS; JIT/PIM; PAWs.
- **Credential protections:** Credential Guard, LSA protection, Protected Users, disable WDigest, restrict `SeDebug`.
- **App control:** WDAC/AppLocker; block macros from internet; ASR rules; SmartScreen.
- **PowerShell:** script-block/module logging, transcription, Constrained Language, remove v2.
- **Attack surface reduction:** disable SMBv1, LLMNR/NBT-NS, restrict admin shares, SMB signing/encryption, disable unused services (spooler on servers), restrict RDP (NLA, gateway, MFA), firewall egress.
- **Logging:** advanced audit policy, Sysmon, WEF to SIEM, Defender/MDE, PowerShell logs, command-line auditing.
- **EDR** with tamper protection and LSASS protection.
- **Backups:** offline/immutable, tested restores, protect backup infrastructure.
- **Email:** attachment filtering, link detonation, DMARC.
- **Least privilege** for services/tasks/shares (see [Permissions.md](Permissions.md)).
- **Baselines** per host role; alert on drift.
- **Incident readiness:** isolation tooling, evidence kits, runbooks.

---

## 16. Lab practice plan

1. Stand up a Windows VM + domain (or standalone) and enable advanced auditing + Sysmon.
2. Simulate macro → PowerShell → download; trace 4688/1/3/11 + 4104.
3. Dump LSASS with a benign tool in the lab; detect via Sysmon 10.
4. Create persistence (service, task, Run key, WMI); detect each.
5. Use PsExec/WMI/WinRM between lab hosts; compare telemetry.
6. Perform a password spray against a lab account; detect 4625/4771 patterns.
7. Delete shadow copies in the lab; build a ransomware-precursor detection.
8. Disable Defender in the lab; detect 5001/5007.
9. Parse Prefetch/Amcache/ShimCache/SRUM and build an execution timeline.
10. Capture memory, extract a process list, compare with disk artifacts.

---

## 17. Self-test questions

1. What is the difference between a SID and a username?
2. What does an access token contain?
3. Which logon type represents RDP, and which represents SMB?
4. Where are local password hashes stored?
5. Why is LSASS a high-value target?
6. What are three high-value registry persistence keys?
7. How does `svchost.exe` load service code?
8. What event ID indicates a new service, and in which log?
9. Which PowerShell event contains deobfuscated script text?
10. What does Defender event 5007 indicate?
11. What is the difference between AmCache and ShimCache?
12. What does SRUM record?
13. Name four lateral movement techniques and their evidence.
14. How would you detect ransomware staging?
15. What is the order of volatility during Windows forensics?

---

## 18. One-page revision checklist

- [ ] Why Windows: enterprise dominance, AD, ransomware, fragmented-but-rich telemetry.
- [ ] Architecture: kernel/executive/user mode, services/SCM, registry, WMI/COM, networking, identity, logging; editions/Core.
- [ ] Identity: local vs domain, built-in accounts, service accounts/gMSA, SIDs, logon types, tokens, UAC filtering, logon sessions.
- [ ] Credentials: LSASS, SAM, NTDS, DPAPI, Credential Manager, browsers, LSA secrets; NTLM/Kerberos/Negotiate/OAuth.
- [ ] Registry: hives, Run/RunOnce, Services, Winlogon, IFEO, AppInit, BHO, NetworkProvider, Print Monitors, COM, USBSTOR, RDP history.
- [ ] Registry artifacts: AmCache, ShimCache, SRUM, BAM, UserAssist, ShellBags, RecentDocs/JumpLists/LNK, MUICache.
- [ ] Persistence: services, tasks, startup, WMI subscriptions, Winlogon, IFEO, COM, DLL side-load, accessibility, screensaver, print, BITS, WinRM/SSH, RDP, scripts, time providers, netsh, Office add-ins.
- [ ] Lateral movement: SMB, PsExec, WMI, WinRM, RDP, tasks, PTH/PTT, DCOM.
- [ ] Logging: PowerShell 4103/4104/transcription, AMSI, Defender 1116/1117/5001/5007, Sysmon IDs, MDE.
- [ ] Attacks: initial access, execution/LOLBins, privesc, credential access, lateral, persistence, evasion, impact.
- [ ] Artifacts: Prefetch, AmCache, ShimCache, SRUM, BAM, UserAssist, LNK, ShellBags, MFT/USN, logs, WMI repo, memory, pagefile, recycle bin, VSS, USB, RDP.
- [ ] Telemetry map: logon, execution, file, network, persistence, privilege, credential, lateral, evasion, ransomware.
- [ ] Detections: Office→shell, LSASS, new service, task, WMI, autorun, Defender disable, log clear, PS abuse, admin share, RDP anomaly, Kerberoasting, PTH, shadow deletion, mass encryption, new admin, UAC bypass, accessibility, netsh/time/print, BYOVD.
- [ ] Investigation: triage → session → execution chain → persistence → credentials → network/lateral → scope → contain → document.
- [ ] Triage: malware, LSASS, service/task, encoded PS, RDP anomaly, log clear, Defender tamper, ransomware.
- [ ] Commands: `whoami /all`, `Get-CimInstance Win32_Process`, `sc`, `schtasks`, `reg`, `Get-WinEvent`, `wevtutil`, `Get-MpComputerStatus`, `vssadmin`, `reg save`, Sysinternals.
- [ ] Hardening: patching, tiering/LAPS/JIT, Credential Guard/LSA/Protected Users, WDAC/AppLocker/ASR, PowerShell logging, SMB/LLMNR/RDP restrictions, audit + WEF + Sysmon + EDR, immutable backups, email security, least privilege, baselines.

---

> **Navigation:** [Roadmap index](../README.md) · [← Windows Event Logs](Windows-Event-Logs.md) · [Linux Logging →](linuxlog.md)
