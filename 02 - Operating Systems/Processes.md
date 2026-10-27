# Processes — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Permissions](Permissions.md) · [Windows Event Logs →](Windows-Event-Logs.md)

> Goal: understand how processes are created, identified, and abused on Windows, Linux, and macOS, so you can **recognise malicious execution, process injection, living-off-the-land abuse, and hidden persistence** from telemetry.
> Windows host → [Windows.md](Windows.md); Linux host → [Linux.md](Linux.md); permissions → [Permissions.md](Permissions.md); logs → [Windows-Event-Logs.md](Windows-Event-Logs.md).

---

## 0. How to use this note

1. §1–§2: why processes matter; the universal process model.
2. §3–§5: Windows, Linux, macOS process internals.
3. §6–§7: execution abuse and injection/evasion techniques.
4. §8–§11: telemetry, detections, investigation, triage.
5. §12–§14: commands, false positives, hardening.
6. §15–§17: labs, self-test, revision.

---

## 1. Why processes matter to a SOC analyst

- **Execution is the heartbeat of an intrusion.** Every attack eventually runs code — a shell, a loader, a script, a service.
- **Process telemetry is the most reliable source** of attacker behaviour: what ran, by whom, from where, with what parent, and with what arguments.
- **Process trees expose intent.** Office → PowerShell, web server → `sh`, `services.exe` → unknown binary are high-signal.
- **LOLBins** (legitimate binaries) hide in plain sight; the *context* (parent, command line, path, user) is the detection.
- **Injection and hollowing** mean the visible process name lies — you must inspect modules, memory, and handles.
- **Process attributes (hash, signature, path, parent)** drive triage and scoping.

**SOC outcomes:** given a process event you can answer:
- Is this binary expected on this host, in this path, signed by this publisher?
- Is the parent-child relationship plausible?
- Is the command line consistent with normal use?
- Is the user/token appropriate (SYSTEM spawning a browser? a service spawning `cmd`?)
- Are there network connections, file writes, or child processes?
- Does it match known attack tooling or LOLBin patterns?

---

## 2. The universal process model

A process is a **running instance of a program** with:

| Attribute | Meaning |
|---|---|
| **PID** | Process identifier (unique while alive; reused after exit). |
| **Parent PID (PPID)** | Creator. Chain forms a tree. |
| **Image/path** | Executable on disk (can be deleted/replaced). |
| **Command line** | Arguments, scripts, URLs, encoded blobs. |
| **User/token** | Security context (UID/GID, SID, token, integrity). |
| **Session** | Interactive/console vs service session. |
| **Environment** | Variables, working directory, handles. |
| **Modules** | Loaded libraries/DLLs (injection evidence). |
| **Handles/fds** | Open files, sockets, registry keys. |
| **Threads** | Execution units inside the process. |
| **Start time** | When it began (compare with file timestamps). |
| **Hash/signature** | Identity and trust. |
| **Integrity/protection** | PPL, protected process, capabilities. |

**Lifecycle:** create → run → (spawn children / load modules / open resources) → exit. **Orphans** (parent exited) get re-parented, which can hide the original chain — but the **creation event** still captured the real parent.

> **Core detective insight:** parent-child relationships and command lines are harder for attackers to fake than filenames. `PID 4`/`System` can never be a real parent of a user shell in a healthy system.

---

## 3. Windows processes

### 3.1 Internals

- **EPROCESS** kernel object; **PEB** user-mode structure; **handles** reference kernel objects.
- **Tokens** carry identity/privileges; impersonation tokens allow acting as another user.
- **Sessions**: Session 0 = services (isolation), Session 1+ = interactive users.
- **Integrity levels**: Low, Medium, High, System, Protected.
- **WOW64**: 32-bit process on 64-bit OS; `SysWOW64` vs `System32` confusion is a common masquerade.
- **Subsystems**: Win32, POSIX, .NET CLR, WSL.

### 3.2 Creation and lineage

- `CreateProcess` (and `CreateProcessAsUser`) is the normal path.
- Parent recorded at creation; **PPID spoofing** possible via handle manipulation.
- Services are started by **`services.exe`** (SCM); scheduled tasks by **`taskeng.exe`/`svchost.exe` (Schedule)**; WMI by **`WmiPrvSE.exe`**.
- **`svchost.exe -k`** hosts many services; a `svchost` with a weird path or no `-k` is suspicious.
- **`RuntimeBroker`, `dllhost`, `conhost`, `WerFault`, `smartscreen`** are common system processes; masquerading uses their names.

### 3.3 Key system processes and expected parents

| Process | Normal parent | Notes |
|---|---|---|
| `System` (PID 4) | none | Kernel; never spawns user shells. |
| `smss.exe` | System | Session manager; spawns `csrss`/`wininit`/`winlogon`. |
| `csrss.exe` | smss | Critical; one per session. |
| `wininit.exe` | smss | Spawns `services.exe`, `lsass.exe`. |
| `services.exe` | wininit | Service control manager. |
| `lsass.exe` | wininit | Credential store; dumping target. |
| `svchost.exe` | services | Many services; check `-k` and path. |
| `explorer.exe` | userinit | Shell; parent of user apps. |
| `winlogon.exe` | smss | Logon UI. |
| `spoolsv.exe` | services | Print spooler; abuse target. |
| `taskhostw.exe` | svchost | Task host. |

> A `cmd.exe` whose parent is `winword.exe`, or `powershell.exe` whose parent is `w3wp.exe`, is worth investigating immediately.

### 3.4 Windows execution mechanisms

| Mechanism | Artifact | Detection |
|---|---|---|
| Services | `7045`, service registry keys, binary path | `sc`, `Get-Service`, Sysmon 1. |
| Scheduled tasks | Task XML, `4698/4699/4700/4702`, TaskScheduler log | `schtasks`, `Get-ScheduledTask`. |
| WMI subscriptions | `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` | WMI-Activity log, repo files. |
| Run/RunOnce keys | Registry | Autoruns, 4688. |
| Startup folder | Files | FIM, 4688. |
| Winlogon shell/userinit | Registry | Unusual values. |
| IFEO | Registry `Image File Execution Options` | Debugger hijack. |
| COM hijack | Registry CLSID | Missing/redirected CLSID. |
| DLL search order | Writable dirs | Side-loading. |
| BITS jobs | `bitsadmin`, BITS log | Transfer persistence. |
| WSL | `wsl.exe` | Rare in servers. |

### 3.5 PowerShell and scripting

- **ScriptBlock logging (4104)**, **Module logging (4103)**, **Transcription**, **AMSI**.
- Look for `-enc`/`-EncodedCommand`, `-w hidden`, `-nop`, `-ep bypass`, `IEX`, `DownloadString`, `FromBase64String`, `Invoke-WebRequest`.
- **Constrained Language Mode** breaks many attacks; attackers try to escape.
- `wmic`, `mshta`, `regsvr32` (Squiblydoo), `rundll32`, `installutil`, `csc`, `msbuild` are common LOLBins.

### 3.6 Injection and evasion

| Technique | What happens | Evidence |
|---|---|---|
| **Classic DLL injection** | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` | Remote thread in another process (Sysmon 8), unusual modules. |
| **Process hollowing** | Create suspended, unmap, write payload, resume | Mismatched image path vs memory, parent/child oddities. |
| **APC injection** | Queue APC to thread | Remote thread/APC telemetry (limited). |
| **Reflective DLL loading** | Manual mapping, no disk file | Unsigned modules, no file on disk. |
| **Process doppelgänging / herpaderping** | Transaction/section manipulation | Memory-only image, file mismatch. |
| **Token theft/impersonation** | Steal token from privileged process | `SeImpersonate`, token events, unusual user context. |
| **PPID spoofing** | Fake parent | Parent/child timestamp inconsistency. |
| **Masquerading** | Name/path mimicry | Path not System32, wrong signature. |
| **Parent PID + name combo** | `svchost.exe` from `C:\Temp` | Path + signature checks. |
| **Timestomping** | Modify timestamps | Creation time vs Prefetch/Amcache mismatch. |

---

## 4. Linux processes

### 4.1 Internals

- **`task_struct`** in kernel; `fork()` duplicates, `execve()` replaces image.
- **PID 1** = init/systemd; **kernel threads** `[kthreadd]`, `[kswapd]` in brackets, PPID 2.
- **Namespaces** (pid, net, mnt, user, uts, ipc, cgroup) — containers hide processes.
- **cgroups** limit/attribute resources; useful for container forensics.
- **Signals** (`SIGKILL`, `SIGTERM`, `SIGSTOP`) — attackers may ignore/block.
- **Zombies** (exited, not reaped) and **orphans** (re-parented to PID 1).

### 4.2 Creation and lineage

- Shell → command; `systemd` → service; `cron`/`atd` → scheduled; `sshd` → login shell; web server → CGI/PHP.
- **Daemonisation**: fork, setsid, fork, close fds — parent often PID 1.
- **`/proc/<pid>/`** exposes `cmdline`, `exe`, `cwd`, `environ`, `maps`, `fd`, `status`, `net`.
- **Deleted binaries** show as `exe -> /path (deleted)` — common for malware that unlinks itself.

### 4.3 Common Linux execution locations

| Location | Typical content | Suspicious if |
|---|---|---|
| `/usr/bin`, `/bin` | System tools | Unexpected new binaries. |
| `/usr/local/bin` | Admin-installed | Unsigned/unknown. |
| `/tmp`, `/var/tmp`, `/dev/shm` | Scratch, noexec often | Executables, scripts. |
| `/home/*` | User files | Executables run as service. |
| `/var/www` | Web content | Shells, uploads. |
| `/run`, `/var/run` | Runtime | Persistence scripts. |

### 4.4 Linux execution abuse

- **Reverse/bind shells**: `bash -i >& /dev/tcp/IP/PORT`, `nc -e`, `socat`, `python -c`.
- **Curl-pipe-shell**: `curl ... | bash`.
- **Base64/obfuscation**: `echo ... | base64 -d | sh`.
- **Cron/systemd persistence**: user crontab, `/etc/cron.*`, `.service` units, timers.
- **.bashrc/.profile** modifications.
- **LD_PRELOAD** library injection (setuid ignored for security, but root-run scripts).
- **Process masquerading**: copy `sshd` name, hide in `/tmp`.
- **Rootkits**: kernel modules, `LD_PRELOAD` userland, `ptrace` hiding.
- **Crypto-miners**: high CPU, pool connections, unusual binary names.
- **Containers**: `docker run --privileged`, host mounts, `nsenter`.

### 4.5 Linux process telemetry

- `auditd` `execve` (with `-a always,exit -F arch=b64 -S execve`), `fork`, `clone`.
- **eBPF** tools (Falco, Tetragon, Tracee) for process/network/file behaviour.
- `osquery` process tables and `process_events`.
- `ps`, `top`, `htop`, `pstree`, `atop`.
- `journald`/`syslog` for service starts, cron, sudo.

---

## 5. macOS processes

- **launchd** (PID 1) starts daemons/agents; `LaunchDaemons`/`LaunchAgents` are persistence.
- **XPC** inter-process communication; abused for privilege escalation.
- **Gatekeeper/Notarization** gate execution; `spctl`.
- **SIP** protects system binaries; disabling is suspicious.
- **`task_for_pid`** and `ptrace` restrictions; injection possible with entitlements.
- **`com.apple.quarantine`** xattr on downloads.
- Unified logging (`log show`), `EndpointSecurity` framework (EDR), `OpenBSM` audit.
- Common abuse: `osascript`, `curl | sh`, `launchctl`, `tccutil`, dylib hijacking.

---

## 6. Execution technique catalogue (attacker view)

| Technique | Example | Detection angle |
|---|---|---|
| **LOLBins** | `certutil -urlcache`, `rundll32`, `mshta`, `regsvr32 /i:http` | Parent/user/path/args, network from LOLBin. |
| **Script interpreters** | `powershell -enc`, `wscript`, `cscript` | Encoded args, script from temp. |
| **Signed binary proxy** | `msbuild`, `installutil`, `csc` | Compilation/exec from unusual paths. |
| **Service creation** | `sc create`, `New-Service` | 7045 + binary path. |
| **Task/cron** | `schtasks /create`, `crontab -e` | 4698/cron logs. |
| **WMI** | `wmic process call create` | WMI-Activity + process. |
| **WMIC lateral** | `/node:` | Remote WMI. |
| **PsExec** | Service + `PSEXESVC` | Service creation, named pipe. |
| **WinRM** | `Enter-PSSession` | 4624 type 3/8, WinRM logs. |
| **SSH** | `ssh user@host` | Auth logs, unusual source. |
| **Container exec** | `docker exec`, `kubectl exec` | Audit logs. |
| **Cloud run/exec** | Lambda, Cloud Run, VM agent | Provider audit. |
| **Scheduled container** | K8s CronJob | Audit logs. |

---

## 7. Injection / evasion deep dive

1. **Allocate** memory in remote process (`VirtualAllocEx`, `mmap`).
2. **Write** payload (`WriteProcessMemory`, `process_vm_writev`).
3. **Execute** (`CreateRemoteThread`, `NtQueueApcThread`, `ptrace`).
4. **Hide** (unlink file, clear logs, rename, masquerade).
5. **Persist** (service, task, registry, cron, systemd, launchd).

**Detection reality:** user-mode API hooks and ETW can be bypassed; **kernel telemetry, memory scanning, and behavioural correlations** (process + network + file) are more resilient.

---

## 8. Telemetry sources

| Source | Windows | Linux | macOS |
|---|---|---|---|
| **Native** | Security 4688/4689, 4624/4634, 4672, 7045 | auditd, syslog, journald | OpenBSM, unified log |
| **Sysmon** | 1 (create), 3 (net), 5 (exit), 7 (image load), 8 (remote thread), 10 (access), 11 (file), 12/13/14 (registry), 17/18 (pipe), 22 (DNS), 25 (process tampering) | Sysmon for Linux 1/3/11 | limited |
| **EDR** | Process tree, memory, script content, network, file | same | same |
| **ETW** | Kernel providers (`Microsoft-Windows-Kernel-Process`) | eBPF | EndpointSecurity |
| **PowerShell** | 4103/4104/Transcription | — | — |
| **OS query** | `processes`, `process_events` | same | same |
| **Network** | Proxy/DNS/firewall + process attribution | same | same |

**Enable:** command-line auditing (4688 `ProcessCommandLine`), PowerShell script-block logging, Sysmon with a solid config, auditd `execve` rules, EDR full telemetry.

---

## 9. Detection engineering

### 9.1 High-signal ideas

1. **Office/browser spawning shells** (`winword.exe` → `cmd`/`powershell`/`wscript`).
2. **Web server spawning shells** (`w3wp.exe`, `httpd`, `nginx`, `php-fpm` → `cmd`/`sh`).
3. **Service host spawning unusual binaries** or `svchost` from non-System32.
4. **Encoded/obfuscated PowerShell** (`-enc`, `-e`, base64, `IEX`, `DownloadString`).
5. **LOLBin making network connections** (`certutil`, `rundll32`, `regsvr32`, `mshta`).
6. **Execution from temp/user-writable paths**.
7. **Unsigned or invalid-signature binaries** in sensitive context.
8. **Parent PID spoofing** (creation time paradox / missing parent).
9. **Process injection** (remote thread creation, image load anomalies).
10. **Rare process** on host (frequency baseline).
11. **Masquerading names** (`scvhost`, `lsasss`, `explorer` in temp).
12. **Shells spawning shells** (`sh -i`, `bash -i`, `nc -e`, `python -c`).
13. **Crypto-miner patterns** (high CPU, stratum pools, known miner names).
14. **Credential dumping** (`procdump lsass`, `comsvcs.dll MiniDump`, `mimikatz`, `sekurlsa`).
15. **Recon tooling** (`whoami`, `net user`, `nltest`, `adfind`, `bloodhound`, `seatbelt`) in sequence.
16. **Deletion of binaries after execution** (Linux `(deleted)`, Windows missing image).
17. **Process tampering** (Sysmon 25).
18. **Container escape** (`nsenter`, `--privileged`, host mounts).
19. **New service/task with suspicious binary**.
20. **Long command lines with secrets/URLs**.

### 9.2 Splunk SPL examples

**Office spawning shell:**
```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval parent=lower(ParentImage), child=lower(Image)
| where (match(parent,"(winword|excel|powerpnt|outlook|onenote)\.exe$") AND match(child,"(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe$"))
| table _time, ComputerName, User, parent, child, CommandLine
```

**Web server spawning shell:**
```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval p=lower(ParentImage), c=lower(Image)
| where (match(p,"(w3wp|httpd|nginx|php-cgi|tomcat|java)") AND match(c,"(cmd|powershell|sh|bash|whoami|net|curl|wget)\.exe$"))
| table _time, ComputerName, User, ParentImage, Image, CommandLine
```

**Encoded PowerShell:**
```spl
index=wineventlog (EventCode=4104 OR EventCode=4688)
| where match(_raw, "(?i)(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring|iex\s*\(|invoke-expression)")
| table _time, ComputerName, User, EventCode, CommandLine, ScriptBlockText
```

**LOLBin with network:**
```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| eval img=lower(Image)
| where match(img,"(certutil|rundll32|regsvr32|mshta|installutil|msbuild|bitsadmin|wmic)\.exe$")
| table _time, ComputerName, User, Image, DestinationIp, DestinationPort, DestinationHostname
```

**Execution from temp:**
```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(Image), "(\\temp\\|\\appdata\\|\\downloads\\|\\programdata\\|\\users\\public\\|/tmp/|/var/tmp/|/dev/shm/)")
| table _time, ComputerName, User, Image, CommandLine
```

**Remote thread / injection (Sysmon 8):**
```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| eval src=lower(SourceImage), tgt=lower(TargetImage)
| where NOT (match(src,"(csrss|lsass|svchost|services|wininit|wmiprvse)\.exe$") AND match(tgt,"(csrss|lsass|svchost|services|wininit|wmiprvse)\.exe$"))
| table _time, ComputerName, User, SourceImage, TargetImage, StartAddress, StartModule
```

**Linux execution from temp:**
```spl
index=linux sourcetype=linux:audit type=EXECVE
| where match(_raw, "(?i)(/tmp/|/var/tmp/|/dev/shm/|/home/[^/]+/\.cache/)")
| table _time, host, uid, auid, _raw
```

**Linux reverse shell indicators:**
```spl
index=linux sourcetype=linux:audit
| where match(_raw, "(?i)(/dev/tcp/|nc -e|ncat -e|socat .*exec|bash -i|sh -i|python[0-9.]* -c|perl -e|php -r)")
| table _time, host, uid, _raw
```

**Crypto-miner:**
```spl
index=* (sourcetype=linux:audit OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")
| where match(_raw, "(?i)(xmrig|minerd|cpuminer|stratum\+tcp|nicehash|monero|coinhive)")
| stats count by host, user, _raw
```

### 9.3 Microsoft Sentinel / Defender KQL

**Office → shell:**
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","powerpnt.exe","onenote.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**Encoded PowerShell:**
```kusto
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring)"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

**Web server child processes:**
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","tomcat.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","sh","bash","whoami.exe","net.exe","curl.exe","wget.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**Rare process (frequency):**
```kusto
let baseline = DeviceProcessEvents
| where TimeGenerated between (ago(30d) .. ago(1d))
| summarize Hosts = dcount(DeviceName) by FileName;
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| join kind=leftouter baseline on FileName
| where isempty(Hosts) or Hosts <= 2
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

**Injection (remote thread):**
```kusto
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, AccountName
```

**LSASS access:**
```kusto
DeviceEvents
| where ActionType has "Lsass"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, AccountName
```

**Linux temp execution (Syslog/audit connector):**
```kusto
Syslog
| where SyslogMessage has_any ("/tmp/","/dev/shm/","/var/tmp/")
| where SyslogMessage has_any ("execve","EXECVE")
| project TimeGenerated, HostName, ProcessName, SyslogMessage
```

### 9.4 Sigma sketch

```yaml
title: Office Application Spawning Shell
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
  child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\mshta.exe'
  condition: parent and child
level: high
```

---

## 10. Investigation workflow

### Step 1 — Establish facts
- Host, user, time (UTC), PID/PPID, image path, command line, hash, signature.
- Parent chain (3+ levels), session, integrity level.

### Step 2 — Validate plausibility
- Does this parent normally create this child?
- Is the path expected for this binary?
- Is the signature valid and publisher expected?
- Is the command line consistent with the product?

### Step 3 — Inspect process context
- Loaded modules/DLLs, handles, network connections, child processes.
- File writes/registry changes, scheduled tasks/services created.
- Token identity/privileges (`whoami /priv` equivalent from telemetry).

### Step 4 — Check reputation and prevalence
- Hash on VT/EDR; first-seen; prevalence across estate.
- Is the binary known-good or a renamed legitimate tool?

### Step 5 — Follow the chain
- What launched it? What did it launch?
- Network destinations, downloaded payloads, persistence.

### Step 6 — Scope
- Same hash/command line on other hosts.
- Same parent-child pattern across the estate.
- Related accounts and credentials.

### Step 7 — Respond
- Contain (isolate), kill process, remove persistence, rotate creds, block IOCs.
- Preserve memory before reboot when feasible.
- Escalate to IR if SYSTEM/admin, lateral movement, or data access.

### Step 8 — Document
Timeline, process tree, evidence, verdict, actions, gaps.

---

## 11. Triage playbooks

### A. "Suspicious process spawned by Office"
1. Confirm child and command line.
2. Check macro/document origin and whether it was opened by the user.
3. Look for downloads, child processes, persistence.
4. Contain, remove document, hunt for the same file/hash.

### B. "PowerShell with encoded command"
1. Decode the command (CyberChef/`base64 -d`/PowerShell).
2. Identify the script's actions (download, persist, exfil).
3. Check parent and user; was it a script/tool (SCCM, monitoring)?
4. Hunt for 4104 content and related network.

### C. "Web server spawned a shell"
1. Identify the request/upload that led to it (web logs).
2. Check child process, network, files written.
3. Assume web shell; remove, patch, review access logs.

### D. "svchost.exe running from wrong path"
1. Verify path, signature, `-k` argument, service association.
2. If invalid → likely malware; isolate and investigate.
3. Check for service creation (7045) and persistence.

### E. "Linux process from /tmp or deleted binary"
1. Inspect `/proc/<pid>/exe`, `cmdline`, `cwd`, `maps`, `environ`.
2. Check parent, user, network, and files.
3. Preserve memory/binary (copy `/proc/<pid>/exe`), then kill and hunt.

### F. "Remote thread / injection alert"
1. Identify source and target processes; are they expected to interact?
2. Check target sensitivity (lsass, browser, security product).
3. Look for credential access, C2, and follow-on behaviour.
4. Treat as high severity; isolate and escalate.

### G. "Crypto-mining"
1. Confirm high CPU and pool connections.
2. Identify initial access (exposed service, weak creds, vulnerable app).
3. Remove miner/persistence, patch entry point, rotate creds.

### H. "Process masquerading"
1. Compare name/path/signature/publisher.
2. Check creation time vs file time (timestomping).
3. Hunt the same hash/name across hosts.

### Severity guide

| Scenario | Typical severity |
|---|---|
| Unknown unsigned binary in temp (no follow-on) | Medium–High |
| Office → shell / encoded PowerShell | High |
| Web server → shell | Critical |
| LSASS access / dump | Critical |
| Remote thread into security process | Critical |
| Miner on server | High |
| Masqueraded system process | High |
| LOLBin used for admin automation (verified) | Informational |

---

## 12. Commands

### Windows

```powershell
# Live processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine /format:list
tasklist /v /fo table

# Tree / lineage
Get-CimInstance Win32_Process | Sort-Object ParentProcessId | Format-Table ProcessId,ParentProcessId,Name

# Modules / handles / network
Get-Process -Id PID -Module
handle.exe -p PID
tcpview.exe
Get-NetTCPConnection -OwningProcess PID

# Signature / hash
Get-AuthenticodeSignature C:\path\file.exe
Get-FileHash C:\path\file.exe -Algorithm SHA256
sigcheck.exe -a -h C:\path\file.exe

# Memory capture
procdump.exe -accepteula -ma PID out.dmp
Get-Process -Id PID | Out-Minidump

# Services / tasks
Get-Service | Where-Object Status -eq Running
Get-ScheduledTask | Get-ScheduledTaskInfo

# Logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 50
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /c:20 /f:text
```

### Linux

```bash
ps auxf
pstree -ap
top -b -n1 | head -30
pgrep -a -f pattern

# /proc deep dive
cat /proc/PID/cmdline | tr '\0' ' '
ls -l /proc/PID/exe /proc/PID/cwd
cat /proc/PID/environ | tr '\0' '\n'
cat /proc/PID/maps
ls -l /proc/PID/fd
cat /proc/PID/status

# Network attribution
ss -tulpenp
lsof -p PID
lsof -i

# Trace
strace -p PID -f -s 200
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s %s\n", comm, str(args->filename)); }'

# Hash / copy binary
sha256sum /proc/PID/exe
cp /proc/PID/exe /tmp/evidence/PID.exe

# Audit
ausearch -m EXECVE -ts recent
ausearch -m EXECVE -p PID
```

### macOS

```bash
ps -axo pid,ppid,user,command
lsof -p PID
log show --predicate 'process == "ProcessName"' --last 1h
launchctl list
codesign -dv --verbose=4 /path/app
spctl -a -vv /path/app
```

> `procdump`/memory capture may expose credentials — handle per policy and preserve chain of custody.

---

## 13. Common false positives

| Alert | Often actually |
|---|---|
| Office spawning shell | Macros/add-ins, legitimate document automation, vendor tools. |
| Web server spawning process | Image processing, PDF generation, health checks, cron. |
| Encoded PowerShell | SCCM/Intune, monitoring, vendor installers, scheduled scripts. |
| svchost variants | Windows updates, third-party services. |
| Execution from temp | Installers, updaters, self-extracting packages. |
| Unsigned binary | In-house tools, open-source utilities. |
| Rare process | One-off admin tool, new software deployment. |
| Remote thread | Debuggers, security products, .NET/JIT, accessibility tools. |
| Crypto-miner strings | Monitoring/benchmark tools, browser features. |
| Deleted binary | Package updates, containerised builds, Java/Go self-updates. |
| Parent mismatch | Service restarts, orphan re-parenting, WMI/SCM behaviour. |
| Credential access alerts | Backup software, EDR, password managers, admin tools. |

**Validate with:** change records, deployment tools, baseline prevalence, signer reputation, and the process's actual behaviour (network/files/children).

---

## 14. Hardening

- **Application control** (AppLocker/WDAC, Allowlisting) blocks most untrusted execution.
- **Disable Office macros** from the internet; block OLE/ActiveX.
- **PowerShell**: script-block + module logging + transcription; Constrained Language for non-admins; remove v2.
- **Credential protection**: LSA protection, Credential Guard, Protected Users, disable WDigest, restrict debug privilege.
- **Service/task hygiene**: non-writable paths, quoted paths, least privilege, gMSA.
- **Remove unnecessary tools** (`wmic`, `mshta` where possible), restrict LOLBins by policy.
- **Linux**: `noexec` on `/tmp`, `/dev/shm`; restrict compilers/interpreters; auditd execve; minimal packages; SELinux/AppArmor.
- **Containers**: no privileged, drop capabilities, read-only rootfs, seccomp/AppArmor, restrict `exec`.
- **EDR with tamper protection**; alert on sensor disable/uninstall.
- **Network**: egress filtering blocks C2; DNS monitoring.
- **Baselines**: approved-process inventory per host role; alert on deviations.
- **Patch** widely exploited apps (browsers, Office, Java, VPN, edge services).

---

## 15. Lab practice plan

1. Enable Sysmon; generate Office→PowerShell (macro) and observe 1/3/11 events.
2. Run an encoded PowerShell command; decode it; compare 4104 vs 4688 visibility.
3. Create a service with a suspicious binary path; observe 7045 + Sysmon 1.
4. Use `certutil` to download a file; detect LOLBin network activity.
5. Inject a benign DLL into a test process; observe Sysmon 8 and module loads.
6. Build a Linux reverse-shell lab; detect via auditd `execve`.
7. Run a process from `/tmp`, delete the binary, inspect `/proc/<pid>/exe (deleted)`.
8. Create a cron/systemd persistence; detect via auditd/journal.
9. Correlate process + network + file events to reconstruct an attack chain.
10. Write an incident report from §10/§11.

---

## 16. Self-test questions

1. What is the difference between a process, a thread, and a program?
2. Which Windows process is the parent of services, and why does it matter?
3. Why is `svchost.exe -k` significant?
4. What are three indicators of process masquerading?
5. How does process hollowing differ from DLL injection?
6. What does Sysmon Event ID 8 indicate?
7. Why is parent PID spoofing detectable?
8. Which Linux file reveals a process's original binary and working directory?
9. What does `(deleted)` next to `/proc/<pid>/exe` mean?
10. Why are LOLBins effective for attackers?
11. Which PowerShell logs show script content?
12. What is the difference between `4688` and Sysmon Event 1?
13. How would you detect a reverse shell on Linux?
14. What process behaviour suggests crypto-mining?
15. How do you preserve a running process for forensics?

---

## 17. One-page revision checklist

- [ ] Process model: PID/PPID, image, command line, user/token, session, modules, handles, integrity, hash/signature, start time.
- [ ] Lifecycle: create → spawn → load → exit; orphans/re-parenting; creation event retains real parent.
- [ ] Windows: EPROCESS/PEB/token/handles, sessions, WOW64, CreateProcess, services/tasks/WMI, svchost `-k`, expected parents, LOLBins, PowerShell logging, injection (DLL/hollowing/APC/reflective/doppelgänging), PPID spoofing, masquerading, timestomping.
- [ ] Linux: task_struct, fork/exec, PID 1, kernel threads, namespaces/cgroups, daemonisation, `/proc/<pid>/*`, deleted binaries, shell/reverse shells, cron/systemd persistence, LD_PRELOAD, rootkits, miners, containers.
- [ ] macOS: launchd, XPC, Gatekeeper, SIP, task_for_pid, quarantine, unified log, EndpointSecurity.
- [ ] Execution catalogue: LOLBins, interpreters, signed-binary proxy, services, tasks, WMI, PsExec, WinRM/SSH, containers, cloud exec.
- [ ] Telemetry: Sysmon 1/3/5/7/8/10/11/12-14/17-18/22/25, 4688/4689/4624/4634/4672/7045, 4103/4104, auditd execve, eBPF/Falco, osquery, EDR, ETW.
- [ ] Detections: Office/browser→shell, web server→shell, service host anomalies, encoded PowerShell, LOLBin network, temp execution, unsigned binaries, PPID spoofing, injection, rare process, masquerading, shell-spawning-shell, miners, credential dumping, recon chains, deleted binaries, process tampering, container escape, new service/task, long/secret command lines.
- [ ] Investigation: facts → plausibility → context → reputation/prevalence → chain → scope → respond → document.
- [ ] Triage: Office spawn, encoded PS, web shell, bad svchost, Linux temp/deleted, injection, miner, masquerade.
- [ ] Commands: `Get-Process/Get-CimInstance Win32_Process/wmic/tasklist/Get-AuthenticodeSignature/sigcheck/procdump/handle/tcpview`, `ps/pstree/top//proc/<pid>/*/ss/lsof/strace/ausearch`, `ps/lsof/log show/codesign/spctl`.
- [ ] Hardening: AppLocker/WDAC, macro blocking, PowerShell logging + CLM, credential protections, service/task hygiene, LOLBin restrictions, noexec/auditd/least packages, container hardening, EDR tamper protection, egress filtering, baselines, patching.

---

> **Navigation:** [Roadmap index](../README.md) · [← Permissions](Permissions.md) · [Windows Event Logs →](Windows-Event-Logs.md)
