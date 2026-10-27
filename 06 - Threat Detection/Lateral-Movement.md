# Lateral Movement — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Credential Attacks](Credential-Attacks.md) · [Malware →](Malware.md)

> Goal: detect an attacker moving from the first compromised host to others — and stop the spread before it reaches the crown jewels.
> Credential theft feeds this → [Credential-Attacks.md](Credential-Attacks.md); AD structure → [03 - Cybersecurity Fundamentals/Common-Attacks.md](../03%20-%20Cybersecurity%20Fundamentals/Common-Attacks.md); network view → [04 - Security Monitoring/Network-Traffic.md](../04%20-%20Security%20Monitoring/Network-Traffic.md).

---

## 0. How to use this note

1. §1–§3: what lateral movement is; why it matters; the telemetry.
2. §4–§7: techniques and their artefacts — SMB/services/tasks/WMI/WinRM/RDP/remote registry.
3. §8–§10: detection logic and queries; fan-out and fan-in.
4. §11–§13: triage, scope, response.
5. §14–§16: hardening, labs, self-test/revision.

---

## 1. What lateral movement is

> **Lateral movement (ATT&CK TA0008)** = using access on host A to gain access on host B, typically reusing valid accounts, remote services, or admin tooling.

It is the bridge between **initial access/privilege escalation** and **impact** (ransomware deployment, data theft, domain dominance).

**Why SOC cares:**
- It is the highest-signal phase — legitimate users rarely authenticate to 40 hosts in 10 minutes.
- It is where **containment** has the most leverage.
- It often produces the **cleanest detection** in an otherwise noisy intrusion.

---

## 2. Prerequisites attackers need

| Requirement | Why |
|---|---|
| **Valid credential** (password/hash/ticket) | Authenticate to the remote host. |
| **Admin rights** on target | Create service/task, access admin share. |
| **Reachable service** | SMB, RPC, WinRM, RDP, SSH. |
| **Firewall path** | Flat networks make this trivial. |

**Detection insight:** the credential is often already compromised, so focus on **where it is used**, not just how it was stolen.

---

## 3. Telemetry that matters

| Source | Signal |
|---|---|
| **4624** | Logon success — type 3 (network), 10 (RDP), 9 (runas). |
| **4625** | Failed logon to remote host. |
| **4648** | Explicit credentials used. |
| **4672** | Special privileges assigned (admin logon). |
| **4688** | Process creation (with command line if enabled). |
| **4697** | Service installed (security log). |
| **7045** | Service installed (system log). |
| **4698/4699/4700/4702** | Scheduled task created/changed. |
| **5140/5145** | Network share accessed / detailed file share. |
| **5141/5142/5143/5144** | Share add/change/delete. |
| **4768/4769** | Kerberos TGT/TGS (which service from where). |
| **4776** | NTLM validation. |
| **Sysmon 1** | Process creation with parent/hash. |
| **Sysmon 3** | Network connection + process. |
| **Sysmon 10** | Process access (credential theft). |
| **Sysmon 11** | File create (tools/dumps). |
| **Sysmon 17/18** | Pipe create/connect (PsExec, Cobalt Strike). |
| **Firewall/flow** | 445/135/5985/3389 fan-out. |
| **EDR** | Remote execution, service creation, lateral behaviour. |
| **PowerShell 4103/4104** | Remote management commands. |

**Logon type mapping is essential:**

| Type | Meaning |
|---|---|
| 2 | Interactive console. |
| 3 | Network (SMB, WMI, WinRM over HTTP). |
| 4 | Batch (scheduled task). |
| 5 | Service. |
| 7 | Unlock. |
| 8 | Network cleartext. |
| 9 | New credentials (`runas /netonly`). |
| 10 | RemoteInteractive (RDP). |
| 11 | Cached interactive. |

---

## 4. Technique: SMB / admin shares

### 4.1 What

Copy a binary to `\\target\ADMIN$` or `C$`, then execute via service or task.

### 4.2 Artefacts

- **5140/5145** — access to `\\*\ADMIN$` or `C$`.
- **4624 type 3** from source host.
- **7045** service creation pointing at the copied file.
- **Sysmon 11** — file written to `ADMIN$`/`C$`.
- **Sysmon 17/18** — named pipes (`\PSEXESVC`, `\srvsvc`).

```spl
index=windows EventCode=5140
| where Share_Name IN ("\\\\*\\ADMIN$","\\\\*\\C$")
| stats count dc(Subject_Account_Name) AS users BY src_ip
| where users > 3
```

### 4.3 PsExec family

- Service `PSEXESVC` created/started/deleted quickly.
- Named pipe `\PSEXESVC`.
- Binary `psexec.exe`, `paexec.exe`, renamed variants.
- `7045` with `ImagePath` containing `PSEXESVC` or `%SystemRoot%\Temp`.

**Modern variants:** `smbexec`, `wmiexec`, `atexec`, Impacket scripts — service names vary.

---

## 5. Technique: services, tasks, WMI, WinRM

### 5.1 Service creation (T1543.003)

**7045/4697** is one of the highest-value events.

```spl
index=windows EventCode=7045
| stats count BY Service_Name, Service_File_Name, host
| where count > 0
```

**Triage questions:**
- Is the binary signed/known?
- Is it in `System32` or `Temp`/`ProgramData`/`Users`?
- Was it created in a change window?
- Who created it? (4697 has subject; 7045 may not)
- Does the service persist or delete quickly (PsExec pattern)?

### 5.2 Scheduled tasks (T1053.005)

- **4698** created, **4699** deleted, **4700/4701** enabled/disabled, **4702** updated.
- **106** (TaskScheduler operational) — task registered.
- **200/201** — action started/completed.

```spl
index=windows EventCode=4698
| stats count BY Task_Name, Subject_Account_Name, host
```

**Red flags:** task runs `powershell`, `cmd`, script from `Temp`, SYSTEM context, created remotely.

### 5.3 WMI (T1047)

- `wmic /node:target process call create`.
- `Invoke-WmiMethod`, `Win32_Process.Create`.
- WMI persistence: `__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`.

**Telemetry:** 4688 for `wmic.exe` with `/node:`; Sysmon 19/20/21 (WMI events); EDR WMI monitoring; `Microsoft-Windows-WMI-Activity/Operational` (5857/5860/5861).

```spl
index=windows EventCode=4688
| where match(lower(CommandLine), "wmic.*/node:")
| table _time, host, user, CommandLine
```

### 5.4 WinRM / PowerShell Remoting (T1021.006)

- **5985/5986** traffic.
- 4624 type 3 with `AuthenticationPackage: Negotiate` from admin host.
- `wsman`/`wsmprovhost.exe` process on target.
- PowerShell 4103/4104 `Invoke-Command`, `Enter-PSSession`.
- `WinRM` operational log 91/168.

```spl
index=windows EventCode=4688
| where Process_Name IN ("wsmprovhost.exe")
| stats count BY host, user, src_ip
```

### 5.5 DCOM (T1021.003)

- `MMC20.Application`, `ShellWindows`, `ShellBrowserWindow` abuse.
- Sysmon 3/1: `mmc.exe`/`explorer.exe` spawning odd children.
- Network 135 + dynamic RPC ports.

**Noisy; needs baseline.**

---

## 6. Technique: RDP (T1021.001)

### 6.1 Artefacts

- **4624 type 10** on target + **4624 type 2/10** on source (logoff).
- **4778/4779** reconnect/disconnect.
- **1149** (TerminalServices) auth.
- `mstsc.exe` on source, `RDP` client artefacts.
- **4648** if explicit creds.
- RDP gateway logs.

```spl
index=windows EventCode=4624 Logon_Type=10
| stats count dc(dest) AS targets BY src_ip, user
| where targets > 2
```

### 6.2 RDP hijacking / session theft

- `tscon` to steal another user's session (needs SYSTEM).
- **4778/4779** anomalies; no new logon.
- Detect `tscon.exe` execution.

### 6.3 Reverse RDP / tunneling

- RDP over non-standard ports, SSH tunnels.
- Flow to 3389 from internal host to external.

---

## 7. Technique: other paths

| Path | Telemetry |
|---|---|
| **Remote registry** | `reg.exe` + `\\host`; RemoteRegistry service start. |
| **SSH (Linux)** | `sshd` accepts from internal host, `Accepted publickey`. |
| **VNC** | 5900 flows, `winvnc` process. |
| **SNMP/DHCP/AD** | Rogue configs, delegation abuse. |
| **Admin tools** | `net use`, `sc`, `schtasks /s`, `psexec`, `wmic /node`. |
| **File transfer** | SMB reads/writes, `bitsadmin`, `curl`, `certutil`. |
| **PowerShell remoting** | 5985/5986, `Invoke-Command`. |
| **Cloud jump hosts** | Bastion logs, SSM sessions. |

---

## 8. Detection design

### 8.1 The core logic: fan-out and fan-in

**Fan-out:** one source host authenticates to many targets.

```spl
index=windows EventCode=4624 Logon_Type=3 earliest=-1h
| stats dc(dest) AS targets values(dest) AS dests BY src_ip, user
| where targets >= 10
```

**Fan-in:** many sources authenticate to one target (less common for LM; more for spray).

### 8.2 Rare user↔host pairs

```kusto
let baseline = SecurityEvent
| where TimeGenerated between (ago(30d)..ago(1d))
| where EventID == 4624 and LogonType == 3
| summarize by Account, Computer;
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4624 and LogonType == 3
| join kind=leftanti baseline on Account, Computer
```

### 8.3 Service/task creation with suspicious paths

```spl
index=windows EventCode=7045
| where match(lower(Service_File_Name), "(\\\\temp\\\\|\\\\users\\\\|\\\\programdata\\\\|\\\\appdata\\\\)")
```

### 8.4 Sequence: credential access → lateral

```spl
index=windows
| eval stage=case(
    EventCode=10 AND TargetImage="*lsass.exe", "cred_access",
    EventCode=4624 AND Logon_Type=3, "network_logon",
    EventCode=7045, "service_install",
    true(), null())
| stats values(stage) AS stages BY host
| where mvcount(stages) >= 2
```

(Correlate within a time window and by host/account in practice.)

### 8.5 Tool-name detection (weak alone)

- `psexec`, `paexec`, `wmiexec`, `smbexec`, `atexec`, `crackmapexec`, `impacket`, `cobaltstrike`.
- Renaming defeats this — pair with behaviour.

### 8.6 Baseline legitimate admin behaviour

- SCCM/Intune, backup, monitoring, vulnerability scanners.
- Jump hosts/PAWs.
- Service accounts with fixed source hosts.
- **Exclude these explicitly, with owners and expiry.**

---

## 9. Detection coverage map

| Technique | Primary signal | Secondary |
|---|---|---|
| SMB/admin share | 5140/5145 ADMIN$/C$ | 4624 type 3, Sysmon 11 |
| PsExec | 7045 PSEXESVC | pipe 17/18, file in ADMIN$ |
| Service create | 7045/4697 | suspicious path |
| Scheduled task | 4698 | powershell/cmd action |
| WMI | 4688 wmic /node | WMI-Activity 5857-5861 |
| WinRM | 5985/5986, wsmprovhost | PS 4103/4104 |
| DCOM | 135/RPC, mmc/explorer children | Sysmon 1/3 |
| RDP | 4624 type 10, 4778/4779 | mstsc, 1149 |
| Remote registry | RemoteRegistry start, reg \\host | 4688 |
| SSH | sshd Accepted from internal | flow 22 |
| File transfer | SMB reads, certutil/bitsadmin | proxy uploads |
| Credential reuse | 4624 type 3 NTLM | 4776 |

---

## 10. Distinguishing attack from administration

| Legitimate | Suspicious |
|---|---|
| Known admin host/PAW | Workstation-to-workstation |
| Change window | Off-hours / weekend |
| Documented tooling | Renamed binaries |
| Service accounts with fixed sources | User account fan-out |
| SCCM/backup/monitoring | Temp/ProgramData binaries |
| Few targets | Many targets quickly |
| Signed tools | Unsigned, low prevalence |
| Ticket exists | No change record |

**Context is everything.** Build the allowlist from reality, not guesses.

---

## 11. Triage playbook

### Step 1 — Characterise
- Source host, destination host(s), account, logon type, service/tool.
- How many targets? How fast?

### Step 2 — Validate legitimacy
- Is the source an admin/jump host?
- Is the account expected to do this?
- Is there a change ticket?
- Is the tool approved?

### Step 3 — Check the source host
- Is it compromised? (credential access, malware, unusual processes)
- Who is logged in?
- Recent alerts?

### Step 4 — Check the target
- Did execution succeed? (service started, task ran, process spawned)
- What ran? Command line, hash, network.
- Persistence created?

### Step 5 — Scope
- All targets from this source.
- All sources using this account.
- All hosts with the same artefact.

### Step 6 — Decide
| Verdict | Criteria |
|---|---|
| **Malicious** | Unapproved tooling + compromised source + suspicious payload. |
| **Suspicious** | Anomalous but inconclusive. |
| **Benign** | Documented admin activity. |
| **FP** | Detection logic/threshold issue. |

### Step 7 — Contain
- Isolate source and confirmed targets.
- Disable/reset the account (and any reused credentials).
- Block C2/tooling hashes.
- Preserve evidence.

### Step 8 — Escalate
Lateral movement = likely **High/Critical**; escalate to IR immediately if multiple hosts or privileged accounts.

---

## 12. Severity guidance

| Condition | Severity |
|---|---|
| Single host, unapproved tool, no payload | Medium |
| Multiple hosts, compromised source | High |
| Privileged account used | High/Critical |
| Domain controller targeted | Critical |
| Ransomware tooling staged | Critical |
| Admin activity, documented | Informational/closed benign |

---

## 13. Response and hardening

### 13.1 Immediate

- Isolate affected hosts.
- Reset credentials used (assume compromised).
- Revoke sessions/tickets.
- Block tool hashes/domains.
- Hunt estate-wide for artefacts.
- Preserve memory/logs.

### 13.2 Strategic

| Control | Effect |
|---|---|
| **Network segmentation** | Blocks workstation-to-workstation SMB/RDP. |
| **Host firewall rules** | Restrict 445/135/3389/5985 between tiers. |
| **Tiered administration** | Admin creds only on admin hosts. |
| **PAW/jump hosts** | Centralised, monitored admin path. |
| **LAPS** | Unique local admin passwords. |
| **Disable SMBv1** | Removes legacy paths. |
| **SMB signing** | Blocks relay. |
| **Restrict admin shares** | Reduce exposure. |
| **Disable NTLM** | Blocks PtH. |
| **Credential Guard** | Protects secrets. |
| **Service account hygiene** | gMSA, least privilege. |
| **EDR + Sysmon** | Telemetry and blocking. |
| **Attack path management** | Remove AD paths to Tier 0. |
| **Honeytokens** | Early warning. |

### 13.3 Detection hardening

- Baseline admin fan-out per role.
- Alert on workstation→workstation 445/3389.
- Alert on new service from temp paths.
- Alert on remote task creation by non-admin.
- Correlate credential access + lateral in one entity score.

---

## 14. Labs

1. Build a 2-VM AD lab; run PsExec; capture 7045 + 5140 + pipe.
2. Create a remote scheduled task; detect 4698.
3. Run `wmic /node:`; detect 4688.
4. Enable WinRM; detect 5985 + wsmprovhost.
5. RDP between hosts; detect 4624 type 10.
6. Build fan-out detection; tune against admin host.
7. Add allowlist for SCCM/backup; verify no false negatives.
8. Simulate service creation from `C:\Temp`; detect.
9. Write the lateral-movement triage runbook.
10. Map detections to ATT&CK TA0008 techniques.

---

## 15. Self-test questions

1. What is lateral movement, and why is it high-signal?
2. What prerequisites does an attacker need?
3. Which logon type indicates SMB vs RDP?
4. Which event shows service creation?
5. What artefacts does PsExec leave?
6. How do you detect remote scheduled tasks?
7. What telemetry covers WMI execution?
8. How do you detect WinRM?
9. What is fan-out, and how do you baseline it?
10. How do you distinguish admin activity from attack?
11. What is the difference between 5140 and 5145?
12. Which techniques avoid new logons entirely?
13. What should you reset after confirmed LM?
14. What segmentation control matters most?
15. Why is tool-name detection insufficient?

---

## 16. One-page revision checklist

- [ ] Definition TA0008; bridge from access to impact; highest-signal phase.
- [ ] Prereqs: credential, admin rights, reachable service, firewall path.
- [ ] Telemetry: 4624/4625/4648/4672/4688/4697/7045/4698/5140/5145/4768/4769/4776; Sysmon 1/3/10/11/17/18; flow; EDR; PS logs.
- [ ] Logon types 2/3/4/5/7/8/9/10/11.
- [ ] SMB/admin shares: 5140/5145, ADMIN$/C$, 7045, Sysmon 11, pipes.
- [ ] PsExec family artefacts: PSEXESVC, pipe, temp service.
- [ ] Services: 7045/4697, suspicious paths, quick create/delete.
- [ ] Tasks: 4698/4699/4700/4702, 106/200/201, suspicious actions.
- [ ] WMI: wmic /node, Win32_Process.Create, persistence triad, 5857-5861.
- [ ] WinRM: 5985/5986, wsmprovhost, 4103/4104, 91/168.
- [ ] DCOM: MMC20/ShellWindows, 135, children baseline.
- [ ] RDP: 4624 type 10, 4778/4779, 1149, mstsc; tscon hijack.
- [ ] Other: remote registry, SSH, VNC, admin tools, file transfer, cloud bastion.
- [ ] Detection design: fan-out/fan-in, rare user↔host, suspicious service paths, sequence cred→lateral, tool names weak, baseline admins.
- [ ] Coverage map table recalled.
- [ ] Legit vs suspicious table.
- [ ] Triage 8 steps; severity; response (isolate, reset, revoke, block, hunt, preserve).
- [ ] Hardening: segmentation, host firewall, tiering, PAW, LAPS, SMBv1 off, signing, admin shares, NTLM off, Credential Guard, gMSA, EDR/Sysmon, attack-path mgmt, honeytokens.

---

> **Navigation:** [Roadmap index](../README.md) · [← Credential Attacks](Credential-Attacks.md) · [Malware →](Malware.md)
