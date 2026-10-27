# PowerShell — SOC Automation Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Bash](Bash.md) · [Python →](Python.md)

> Goal: investigate Windows at scale — event logs, endpoints, and APIs — using objects rather than text.
> Bash equivalent → [Bash.md](Bash.md); API mechanics → [APIs.md](APIs.md); Windows logs → [02 - Operating Systems/Windows-Event-Logs.md](../02%20-%20Operating%20Systems/Windows-Event-Logs.md).

---

## 0. How to use this note

1. §1–§3: objects, pipeline, discovery.
2. §4–§7: filtering, selecting, sorting, exporting.
3. §8–§11: event logs, processes, files, persistence.
4. §12–§15: JSON/REST, remoting, Graph, logging/safety.
5. §16–§18: SOC recipes, pitfalls, labs.
6. §19–§20: self-test, revision.

---

## 1. Why PowerShell

| Feature | Benefit |
|---|---|
| **Objects, not text** | Filter on properties, no parsing |
| **Pipeline** | Compose small commands |
| **Native Windows access** | WMI/CIM, registry, event log |
| **REST support** | `Invoke-RestMethod` |
| **Remoting** | `Invoke-Command` across hosts |

**Stop parsing text. Start filtering objects.**

---

## 2. Basics

```powershell
Get-Service
Get-Process | Where-Object CPU -gt 100
Get-ChildItem C:\Windows\Temp -Recurse | Measure-Object Length -Sum
```

| Cmdlet | Use |
|---|---|
| `Get-Help <cmd> -Examples` | Discovery |
| `Get-Command *event*` | Find cmdlets |
| `Get-Member` | Object properties |
| `Select-Object` | Choose properties |
| `Where-Object` | Filter |
| `Sort-Object` | Order |
| `Group-Object` | Aggregate |
| `Measure-Object` | Counts/sums |
| `ForEach-Object` | Iterate |
| `Export-Csv` | Save |
| `ConvertTo-Json` | Serialise |

### 2.1 Discovery habit

```powershell
Get-Process | Get-Member
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount
```

**Discover the object shape before you filter it.**

---

## 3. Pipeline

```powershell
Get-Process
| Where-Object { $_.Company -eq $null }
| Sort-Object WS -Descending
| Select-Object -First 10 Name, Id, WS
```

| Symbol | Meaning |
|---|---|
| `$_` | Current item (in script block) |
| `$_.Property` | Property access |
| `|` | Pipe |
| `?` | Alias for `Where-Object` |
| `%` | Alias for `ForEach-Object` |
| `ft`, `fl`, `ft -auto` | Format table/list |

**Aliases are fine interactively — use full names in scripts.**

---

## 4. Where-Object

```powershell
Get-Process | Where-Object { $_.Name -like 'chrome*' }
Get-Service | Where-Object Status -eq 'Running'
Get-ChildItem | Where-Object { $_.Length -gt 10MB }

# multiple conditions
Get-Process | Where-Object {
  $_.Name -in @('powershell','pwsh') -and $_.StartTime -gt (Get-Date).AddHours(-2)
}
```

| Operator | Use |
|---|---|
| `-eq/-ne` | Equality |
| `-like/-notlike` | Wildcards |
| `-match/-notmatch` | Regex |
| `-contains` | Collection contains |
| `-in` | Item in collection |
| `-gt/-lt` | Numeric/date |
| `-and/-or/-not` | Logic |

**`-contains` vs `-in`:** `$list -contains $item` vs `$item -in $list`.

---

## 5. Select, sort, group

```powershell
Get-Process | Select-Object Name, Id, CPU, WS
Get-Process | Select-Object -First 5
Get-Process | Select-Object -ExpandProperty Name
Get-Process | Sort-Object CPU -Descending
Get-Process | Group-Object Company | Sort-Object Count -Descending
```

### 5.1 Calculated properties

```powershell
Get-ChildItem *.log | Select-Object Name,
  @{Name='MB'; Expression={ [math]::Round($_.Length/1MB,2) } }
```

Useful for normalising output for reports.

---

## 6. Export and format

```powershell
Get-Process | Export-Csv procs.csv -NoTypeInformation
Get-Process | ConvertTo-Json -Depth 4 | Set-Content procs.json
Get-Content procs.json | ConvertFrom-Json
Get-Process | Format-Table -AutoSize
```

| Format | Use |
|---|---|
| CSV | Excel/report |
| JSON | API/automation |
| `Out-File` | Raw text |
| `Tee-Object` | Show + save |

**CSV for humans, JSON for machines.**

---

## 7. Variables and types

```powershell
$cutoff = (Get-Date).AddDays(-1)
$hosts  = @('WS-01','WS-02')
$hash   = @{}
$hash['WS-01'] = 3

[int]$count = 0
[datetime]$when = Get-Date
```

| Type | Use |
|---|---|
| `@()` | Array |
| `@{}` | Hashtable |
| `[PSCustomObject]@{}` | Structured record |

```powershell
[PSCustomObject]@{
  Host  = $env:COMPUTERNAME
  Time  = (Get-Date).ToUniversalTime()
  Event = 'triage-start'
}
```

---

## 8. Event logs

```powershell
Get-WinEvent -LogName Security -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)}
```

### 8.1 Fast filtering

`-FilterHashtable` is **much faster** than piping to `Where-Object` because filtering happens in the log service.

```powershell
$since = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4625, 4624, 4672
  StartTime = $since
} | Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}},
                    @{n='IP';e={$_.Properties[19].Value}}
```

### 8.2 Sysmon

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 20
```

### 8.3 Event XML

```powershell
$e = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1
$xml = [xml]$e.ToXml()
$xml.Event.EventData.Data | Select-Object Name, '#text'
```

**Property indexes differ by event — parse XML for reliability.**

---

## 9. Processes and network

```powershell
Get-Process | Sort-Object StartTime -Descending | Select-Object -First 10
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine
Get-NetTCPConnection -State Established |
  Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess
```

### 9.1 Process tree

```powershell
$procs = Get-CimInstance Win32_Process
$byPid = @{}; $procs | ForEach-Object { $byPid[$_.ProcessId] = $_ }
foreach ($p in $procs) {
  $parent = $byPid[$p.ParentProcessId]
  [PSCustomObject]@{
    Child = $p.Name; ChildPid = $p.ProcessId
    Parent = $parent.Name; ParentPid = $p.ParentProcessId
    Cmd = $p.CommandLine
  }
}
```

**Lineage is often the whole detection.**

---

## 10. Files and hashing

```powershell
Get-ChildItem C:\Users -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.Length -gt 5MB } |
  Select-Object FullName, Length, LastWriteTime

Get-FileHash .\sample.exe -Algorithm SHA256
Get-AuthenticodeSignature .\sample.exe | Select-Object Status, SignerCertificate
```

### 10.1 Find recently created executables

```powershell
Get-ChildItem C:\Users, C:\ProgramData, C:\Windows\Temp -Recurse -Include *.exe,*.dll,*.ps1 `
  -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-3) } |
  Select-Object FullName, CreationTime, Length
```

---

## 11. Persistence checks

```powershell
# Run keys
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# Services
Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName

# Scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State

# Startup folders
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
              "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# WMI subscriptions (often overlooked)
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
```

**WMI persistence is a classic miss — check it explicitly.**

---

## 12. JSON and REST

```powershell
$headers = @{ Authorization = "Bearer $env:SOC_TOKEN" }
$alerts = Invoke-RestMethod -Uri "$env:SIEM/api/v3/alerts?limit=100" `
                            -Headers $headers -Method Get

$alerts.items | Where-Object severity -eq 'high' |
  Select-Object id, host, user
```

### 12.1 POST

```powershell
$body = @{ host = 'WS-01'; reason = 'incident 1023' } | ConvertTo-Json
Invoke-RestMethod -Uri "$env:EDR/api/isolate" -Method Post `
  -Headers $headers -ContentType 'application/json' -Body $body
```

### 12.2 Error handling

```powershell
try {
  Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 30
} catch {
  Write-Error "API failed: $($_.Exception.Message)"
  throw
}
```

**Always set `-TimeoutSec`.**

---

## 13. Remoting

```powershell
Invoke-Command -ComputerName WS-01 -ScriptBlock {
  Get-Process | Where-Object { $_.Name -eq 'powershell' }
}
```

| Requirement | Note |
|---|---|
| WinRM enabled | Port 5985/5986 |
| Credentials | `-Credential` |
| Privilege | Local admin for most |
| Output | Deserialised objects |

### 13.1 Fan-out

```powershell
$hosts = Get-Content hosts.txt
Invoke-Command -ComputerName $hosts -ThrottleLimit 20 -ScriptBlock {
  Get-Service WinDefend | Select-Object Status
} -ErrorAction SilentlyContinue
```

**Throttle to avoid knocking over the network.**

---

## 14. Microsoft Graph

```powershell
Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All'
Get-MgUser -Top 10 | Select-Object DisplayName, UserPrincipalName
Get-MgAuditLogSignIn -Top 20 | Select-Object CreatedDateTime, UserPrincipalName, Status
```

| Rule | Detail |
|---|---|
| Use least scopes | Not `Directory.ReadWrite.All` |
| Use app registration for automation | Client credentials |
| Never store secrets in scripts | Vault/env |
| Respect throttling | Backoff |

**Graph is read-write to your tenant — treat tokens as crown jewels.**

---

## 15. Logging and safety

### 15.1 Transcript

```powershell
Start-Transcript -Path .\triage.log -Append
try   { ... }
finally { Stop-Transcript }
```

### 15.2 Safety rules

| Rule | Why |
|---|---|
| `-WhatIf` for destructive cmdlets | Preview |
| `-Confirm` | Intent |
| Validate input | Injection |
| Scope paths | Accidental deletion |
| `-ErrorAction Stop` | Catch failures |
| Never `Remove-Item -Recurse -Force` on vars | Catastrophe |
| Constrained Language Mode | Restrict execution |
| Signed scripts + AllSigned policy | Integrity |

### 15.3 Execution policy is not security

Bypass is trivial; treat it as a guardrail only. Use AppLocker/WDAC for real control.

---

## 16. SOC recipes

### 16.1 Successful logons from new IPs

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-7)} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time = $_.TimeCreated
      User = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
      IP   = ($x.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
      Type = ($x.Event.EventData.Data | Where-Object Name -eq 'LogonType').'#text'
    }
  } | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 10
```

### 16.2 Unsigned executables in temp

```powershell
Get-ChildItem $env:TEMP -Recurse -Include *.exe -ErrorAction SilentlyContinue |
  ForEach-Object {
    [PSCustomObject]@{
      Path   = $_.FullName
      Signed = (Get-AuthenticodeSignature $_.FullName).Status
    }
  } | Where-Object Signed -ne 'Valid'
```

### 16.3 Suspicious service paths

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match '(?i)(temp|appdata|public|programdata)' } |
  Select-Object Name, PathName, StartMode
```

### 16.4 Bulk hashing

```powershell
Get-ChildItem C:\Samples -File |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Hash, Path | Export-Csv hashes.csv -NoTypeInformation
```

### 16.5 Compare autoruns

```powershell
$before = Get-ItemProperty HKLM:\...\Run | Out-String
# ... change ...
$after  = Get-ItemProperty HKLM:\...\Run | Out-String
Compare-Object ($before -split "`n") ($after -split "`n")
```

---

## 17. Pitfalls

| Pitfall | Consequence |
|---|---|
| Piping all events to `Where-Object` | Very slow |
| Trusting property indexes | Wrong fields |
| Aliases in scripts | Unreadable |
| No `-TimeoutSec` | Hung automation |
| `-ErrorAction SilentlyContinue` everywhere | Silent failures |
| Unquoted paths | Breakage |
| Over-broad remoting | Network impact |
| Secrets in scripts | Breach |
| `Remove-Item` on computed path | Data loss |
| Assuming policy = security | Bypass |

---

## 18. Labs

1. List top 10 processes by memory with company null.
2. Query 4625 for 24 h with `-FilterHashtable`.
3. Parse 4688 XML and extract command lines.
4. Build a process tree for a given PID.
5. Find unsigned EXEs in temp.
6. Enumerate all persistence locations.
7. Call a REST API and filter results.
8. Remote-query 5 hosts with throttling.
9. Query Graph sign-ins with least scopes.
10. Write a transcript-logged triage script.

---

## 19. Testing and style

| Practice | Why |
|---|---|
| `PSScriptAnalyzer` | Lint |
| `-WhatIf` | Safety |
| Full cmdlet names | Readability |
| Comment-based help | Usability |
| Pester tests | Regression |

```powershell
Invoke-ScriptAnalyzer -Path .\triage.ps1 -Severity Warning,Error
```

---

## 20. Self-test questions

1. What does "objects not text" mean?
2. What is `$_`?
3. `-contains` vs `-in`?
4. Why is `-FilterHashtable` faster?
5. How do you parse event XML reliably?
6. How do you build a process tree?
7. How do you check a file signature?
8. Name five persistence locations.
9. How do you call a REST API safely?
10. What does `-ThrottleLimit` do?
11. Which Graph scopes would you request for read-only?
12. What is `Start-Transcript` for?
13. Why isn't execution policy security?
14. What are the risks of `-ErrorAction SilentlyContinue`?
15. What does `PSScriptAnalyzer` do?

---

## 21. One-page revision checklist

- [ ] Objects and pipeline; `$_`, `Get-Member`.
- [ ] Cmdlets: Select/Where/Sort/Group/Measure/ForEach.
- [ ] Operators incl. `-like`, `-match`, `-in`.
- [ ] Calculated properties.
- [ ] Export CSV/JSON; `ConvertFrom-Json`.
- [ ] Variables, arrays, hashtables, PSCustomObject, types.
- [ ] `Get-WinEvent` with `-FilterHashtable`; Sysmon; XML parsing.
- [ ] Processes: `Win32_Process`, TCP connections, tree building.
- [ ] Files: hashing, signatures, recent executables.
- [ ] Persistence: Run, services, tasks, startup, WMI.
- [ ] REST: `Invoke-RestMethod`, POST body, try/catch, timeout.
- [ ] Remoting with throttling.
- [ ] Graph with least scopes.
- [ ] Transcript logging and safety rules.
- [ ] SOC recipes.
- [ ] Pitfalls memorised.
- [ ] PSScriptAnalyzer.

---

> **Navigation:** [Roadmap index](../README.md) · [← Bash](Bash.md) · [Python →](Python.md)
