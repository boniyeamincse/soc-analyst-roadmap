# Suspicious Processes — SOC Analyst Study Notes

> Goal: look at a process and decide — fast — whether it is normal for this host, this user, and this time.
> OS mechanics → `02 - Operating Systems/Processes.md`; EDR telemetry → `04 - Security Monitoring/EDR.md`; malware triage → `Malware.md`.

---

## 0. How to use this note

1. §1–§3: why processes are the core unit of endpoint detection.
2. §4–§7: the five questions; lineage; command lines; binaries.
3. §8–§10: behaviour signals — network, files, registry, injection, tokens.
4. §11–§13: LOLBins, common abuse patterns, triage workflow.
5. §14–§16: tooling, false positives, labs.
6. §17–§18: self-test, revision.

---

## 1. Why processes matter

- Every execution is a **process** (or a thread inside one).
- Attackers must run code — even fileless attacks create processes or inject into them.
- Process data provides **parent, command line, user, hash, path, network** — rich context.
- Most EDR/AV detections are ultimately about process behaviour.

**Core skill:** given a process, determine if it is **expected** for that host/user/time — and if not, what it did.

---

## 2. The five questions

For any suspicious process:

1. **Who is the parent?** (lineage)
2. **What is the command line?**
3. **Where is the binary?** (path, signer, hash)
4. **Who is running it?** (user, integrity, session)
5. **What has it done?** (children, network, files, registry, memory)

Answer all five before deciding.

---

## 3. Process lineage

### 3.1 Normal lineage examples

| Child | Expected parent(s) |
|---|---|
| `explorer.exe` | `userinit.exe` |
| `cmd.exe` | `explorer.exe`, `services.exe`, admin tools |
| `powershell.exe` | `explorer.exe`, `cmd.exe`, admin tools, SCCM |
| `svchost.exe` | `services.exe` |
| `lsass.exe` | `wininit.exe` |
| `winlogon.exe` | `smss.exe` |
| `taskhostw.exe` | `svchost.exe` |
| `conhost.exe` | console apps |
| `RuntimeBroker.exe` | `svchost.exe` |
| Chrome/Edge children | browser parent |

### 3.2 High-signal anomalies

| Anomaly | Why |
|---|---|
| **Office → shell** | Macro/exploit execution. |
| **Browser → shell** | Drive-by/download. |
| **Web server (w3wp) → shell** | Webshell. |
| **`svchost.exe` not from `services.exe`** | Masquerading. |
| **`lsass.exe` not from `wininit.exe`** | Fake LSASS. |
| **`explorer.exe` spawning services** | Unusual. |
| **Email client → script host** | Phishing. |
| **Database → shell** | SQLi/xp_cmdshell. |
| **`services.exe` → powershell** | Service-based execution. |
| **Orphaned process (parent exited)** | Common for droppers. |

### 3.3 Sysmon Event 1 fields

```
UtcTime, ProcessGuid, ProcessId, Image, FileVersion, Description,
CommandLine, CurrentDirectory, User, LogonId, IntegrityLevel,
Hashes, ParentProcessId, ParentImage, ParentCommandLine
```

**`ParentImage` + `CommandLine` + `User`** are the fastest trio.

---

## 4. Command-line analysis

### 4.1 Red flags

| Pattern | Meaning |
|---|---|
| `-enc`, `-encodedcommand`, long base64 | Obfuscation. |
| `-w hidden`, `-nop`, `-ep bypass` | Evasion. |
| `IEX`, `Invoke-Expression` | Dynamic execution. |
| `DownloadString`, `WebClient`, `Invoke-WebRequest` | Download cradle. |
| `FromBase64String` | Decoding payload. |
| `mshta http://` | Remote HTA. |
| `regsvr32 /s /u /i:http... scrobj.dll` | Squiblydoo. |
| `rundll32` with URL/export | Proxy execution. |
| `certutil -urlcache -f` | Download. |
| `bitsadmin /transfer` | Download. |
| `wmic process call create` | Remote exec. |
| `schtasks /create ... /ru SYSTEM` | Persistence as SYSTEM. |
| `vssadmin delete shadows` | Ransomware precursor. |
| `net user ... /add`, `net localgroup administrators ... /add` | Account creation. |
| `whoami /priv`, `net group "domain admins" /domain` | Recon. |
| `bitsadmin`, `curl`, `wget` to temp | Staging. |
| `cmd /c` chains with `&&` | Obfuscated sequence. |
| `%COMSPEC%`, `^` escapes | Evasion. |

### 4.2 Decoding

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<b64>"))
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("<b64>"))
```

```bash
echo '<b64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

**Always decode before judging.** Encoded ≠ malicious, but it demands explanation.

### 4.3 Command-line logging

- **4688** with "Include command line in process creation events" enabled.
- **Sysmon 1**.
- **PowerShell 4104** (script block).
- **EDR** (always).

Without command-line logging, you are half-blind.

---

## 5. Binary analysis

| Attribute | Normal | Suspicious |
|---|---|---|
| **Path** | `System32`, `Program Files`, `Windows` | `Temp`, `AppData`, `ProgramData`, `Public`, `Downloads`, `Recycle` |
| **Name** | Known | Random, system-lookalike (`scvhost.exe`, `lsasss.exe`) |
| **Signer** | Microsoft/vendor valid | Unsigned, invalid, revoked, mismatched |
| **Hash prevalence** | Common | First-seen, one host |
| **Version info** | Present/consistent | Missing/generic |
| **Size** | Expected | Tiny dropper / huge packed |
| **Compile time** | Reasonable | Future/absent |

### 5.1 Masquerading

- Same name as system binary but different path.
- Unicode lookalikes (`ѕvchost` with Cyrillic).
- Right-to-left override characters.
- Trailing spaces/dots (`svchost.exe `).

**Verify by path + hash + signer, never name alone.**

### 5.2 Unsigned binaries

- Many legitimate tools are unsigned (admin tools, open source).
- Context decides: unsigned binary in `Temp` making network connections = bad.
- Unsigned binary in `Program Files` shipped by IT = likely benign.

---

## 6. User and privilege context

| Context | Meaning |
|---|---|
| **User** | Standard vs admin vs service account. |
| **Integrity** | Low/Medium/High/System. |
| **Elevation** | UAC-elevated? |
| **Session** | Interactive/RDP/service. |
| **Logon ID** | Correlate with 4624. |

**Red flags:**
- Standard user running admin-only tools.
- Service account launching interactive shells.
- SYSTEM process spawned by user-writable path.
- Process running in a session where the user isn't logged in.

---

## 7. Children and behaviour

### 7.1 Children

- `cmd` → `powershell` → `rundll32` chains.
- Shell → `whoami`, `ipconfig`, `net`, `nltest` (recon).
- Shell → `certutil`, `bitsadmin` (download).
- Shell → `schtasks`, `sc`, `reg add` (persistence).
- Shell → `vssadmin`, `wbadmin` (impact).
- Office → `mshta`/`wscript`/`powershell`.

### 7.2 Network

| Signal | Meaning |
|---|---|
| Connection from `Temp` binary | Malware. |
| Beacon periodicity | C2. |
| Rare external IP/domain | C2/exfil. |
| High upload | Exfil. |
| Connection on odd port | Tunnel. |
| DNS from unexpected process | Tunnelling/DGA. |

### 7.3 Files and registry

- Writes to `Startup`, `Run`, `Services`, `Winlogon`, `IFEO`.
- Drops in `Temp`/`AppData`.
- Modifies security tools/config.
- Creates archives.

### 7.4 Injection / tampering

| Technique | Signal |
|---|---|
| **CreateRemoteThread** | Sysmon 8. |
| **Process access** | Sysmon 10 (`GrantedAccess`). |
| **Process hollowing** | Sysmon 25 process tampering. |
| **Reflective load** | Memory-only module. |
| **Token theft** | Process access to privileged process. |

---

## 8. Masquerading and persistence launchers

| Technique | Example |
|---|---|
| **Masquerade name** | `svch0st.exe` in `%TEMP%`. |
| **Masquerade path** | `C:\Windows\Temp\svchost.exe`. |
| **Service** | `sc create` with random name. |
| **Scheduled task** | `schtasks /create /tn \Microsoft\...`. |
| **Run key** | `HKCU\...\Run`. |
| **WMI subscription** | `__EventFilter`. |
| **Startup folder** | `.lnk` dropped. |
| **DLL side-loading** | Legit EXE + malicious DLL in same dir. |

---

## 9. LOLBins (living-off-the-land binaries)

| Binary | Abuse |
|---|---|
| **powershell** | Download/execute, encode. |
| **cmd** | Chaining, recon. |
| **mshta** | Remote HTA execution. |
| **rundll32** | Proxy execution, JS/VBS. |
| **regsvr32** | Squiblydoo. |
| **wmic** | Remote exec, persistence. |
| **certutil** | Download, decode, hash. |
| **bitsadmin** | Download. |
| **msiexec** | Remote MSI. |
| **installutil** | .NET execution. |
| **regasm/regsvcs** | .NET execution. |
| **msbuild** | Inline task execution. |
| **cscript/wscript** | Script execution. |
| **forfiles** | Command execution. |
| **pcalua** | Proxy execution. |
| **explorer** | Execution via shell. |
| **schtasks** | Persistence. |
| **sc** | Service persistence. |
| **netsh** | Firewall/proxy changes. |
| **curl/wget** | Download. |

**LOLBins are legitimate** — detection requires **arguments and context**, not names.

---

## 10. High-signal process patterns

| Pattern | Likely meaning |
|---|---|
| `WINWORD.EXE` → `cmd.exe`/`powershell.exe` | Macro/exploit. |
| `w3wp.exe` → `cmd.exe`/`powershell.exe` | Webshell. |
| `sqlservr.exe` → `cmd.exe` | SQLi/xp_cmdshell. |
| `services.exe` → `powershell.exe -enc` | Service-based loader. |
| `explorer.exe` → `rundll32` with URL | Proxy execution. |
| `outlook.exe` → `wscript.exe` | Phishing. |
| `chrome.exe` → `cmd.exe` | Drive-by/download. |
| `wmiprvse.exe` → `cmd.exe` | WMI exec. |
| `taskeng.exe`/`svchost` → script in Temp | Task persistence. |
| `lsass.exe` access by unknown | Credential dumping. |
| Process in `Temp` with network | Malware. |
| Unsigned binary with high entropy | Packed malware. |

---

## 11. Triage workflow

### Step 1 — Capture
Image, PID, parent, command line, user, integrity, hash, path, signer, start time.

### Step 2 — Establish expectedness
Is this binary/path normal for this host role? Baseline/EDR prevalence. First seen?

### Step 3 — Check lineage
Parent legitimate? Sibling processes normal?

### Step 4 — Check children
Recon/download/persistence/impact commands?

### Step 5 — Check network
External connections, beaconing, rare domains, uploads.

### Step 6 — Check file/registry
Drops, persistence, tampering.

### Step 7 — Check memory/injection
Injected modules, unsigned memory, hollowing.

### Step 8 — Decide
Malicious / suspicious / benign / FP.

### Step 9 — Act
Kill tree, isolate, collect, scope.

---

## 12. Killing and collection

- **Collect before kill** if memory artefacts matter.
- Kill the **tree** (children too).
- Watch for **watchdog respawn** — remove persistence first or isolate.
- Verify termination; check for renamed restarts.
- Preserve binary (hash + copy) for analysis.

**Killing the parent alone often leaves the payload running.**

---

## 13. Tooling

| Tool | Use |
|---|---|
| **Process Explorer** | Tree, handles, DLLs, strings, VirusTotal. |
| **Process Monitor** | Real-time file/registry/network. |
| **Autoruns** | Persistence inventory. |
| **Sysinternals Suite** | `pslist`, `pssuspend`, `procdump`, `sigcheck`, `handle`. |
| **TCPView** | Connections per process. |
| **Sysmon** | Structured telemetry. |
| **EDR console** | Search, pivot, respond. |
| **Volatility** | Memory forensics. |
| **PE-bear / pestudio** | Static PE analysis. |

```powershell
Get-Process | Sort-Object CPU -Desc | Select-Object -First 20 Name,Id,CPU,Path
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine
Get-Process -Id <pid> | Select-Object -ExpandProperty Modules
Get-NetTCPConnection -OwningProcess <pid>
```

```bash
ps -eo pid,ppid,user,etime,cmd --sort=-%cpu | head -30
lsof -p <pid>
ls -l /proc/<pid>/exe
cat /proc/<pid>/cmdline | tr '\0' ' '
```

---

## 14. False positives

| Legit cause | Why it looks bad |
|---|---|
| **IT admin scripts** | PowerShell encoded, remote exec. |
| **SCCM/Intune** | SYSTEM processes, scripts. |
| **Backup software** | Mass file access, VSS. |
| **Vulnerability scanners** | Credential access, network scan. |
| **Developer tools** | Compilers, debuggers, unsigned binaries. |
| **Software installers** | Temp extraction, child processes. |
| **Monitoring agents** | Network connections, WMI. |
| **Legacy apps** | Unsigned, odd paths. |

**Verify with the owner.** Document allowlists with expiry.

---

## 15. Labs

1. Build a Sysmon lab; generate Office→PowerShell; analyse Sysmon 1.
2. Inspect a process tree with Process Explorer; spot masquerading.
3. Decode a base64 PowerShell command line.
4. Detect a Temp-path binary with network via EDR query.
5. Compare signed vs unsigned binaries with `sigcheck`.
6. Trigger CreateRemoteThread in a lab; observe Sysmon 8.
7. Hunt LOLBin usage with suspicious arguments.
8. Build a detection for `w3wp.exe → cmd.exe`.
9. Practise collect → kill tree → verify.
10. Write a process triage report with all five questions answered.

---

## 16. Self-test questions

1. What are the five questions for a suspicious process?
2. Why is parent-child lineage high-signal?
3. What does Office→PowerShell indicate?
4. Why is command-line logging essential?
5. How do you decode an encoded PowerShell command?
6. Why is path+hash+signer better than filename?
7. What is masquerading?
8. Which Sysmon events show injection?
9. What are LOLBins, and how do you detect abuse?
10. Why is killing the parent insufficient?
11. What does a Temp-path binary with network suggest?
12. What is process hollowing?
13. What are three benign causes of Suspicious-Process alerts?
14. What must you collect before killing?
15. How do you baseline process behaviour?

---

## 17. One-page revision checklist

- [ ] Processes are the core endpoint unit; execution always leaves a process or injection.
- [ ] Five questions: parent, command line, path/signer/hash, user/integrity, behaviour.
- [ ] Normal lineage table; anomalies (Office/browser/web server/DB → shell, fake lsass/svchost, orphan).
- [ ] Sysmon 1 fields.
- [ ] Command-line red flags (encode, hidden, IEX, download, mshta, regsvr32, certutil, wmic, schtasks, vssadmin, net user, whoami, LOLBins); decoding methods; logging sources 4688/4104/Sysmon1/EDR.
- [ ] Binary attributes: path, name, signer, prevalence, version, size, compile time; masquerading variants.
- [ ] Context: user, integrity, elevation, session, logon ID.
- [ ] Behaviour: children chains, network, files/registry, injection (Sysmon 8/10/25).
- [ ] Persistence launchers: service, task, Run, WMI, startup, side-loading.
- [ ] LOLBin table; detection requires arguments/context.
- [ ] High-signal patterns table recalled.
- [ ] Triage 9 steps; collect-before-kill, kill tree, watchdog, verify.
- [ ] Tooling: Process Explorer/Monitor, Autoruns, Sysinternals, TCPView, Sysmon, EDR, Volatility, PE tools; commands.
- [ ] False positives: admin scripts, SCCM, backup, scanners, dev tools, installers, monitoring, legacy.
- [ ] Labs and self-test recalled.
