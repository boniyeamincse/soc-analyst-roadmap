# Credential Attacks — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Brute Force](Brute-Force.md) · [Lateral Movement →](Lateral-Movement.md)

> Goal: detect the theft, extraction, and abuse of credentials and tickets — the step that turns "a foothold" into "domain admin".
> Password guessing → [Brute-Force.md](Brute-Force.md); AD mechanics → [03 - Cybersecurity Fundamentals/Authentication.md](../03%20-%20Cybersecurity%20Fundamentals/Authentication.md); events → [02 - Operating Systems/Windows-Event-Logs.md](../02%20-%20Operating%20Systems/Windows-Event-Logs.md); deep AD attacks → [Active-Directory-Attacks.md](Active-Directory-Attacks.md); cloud identity → [Cloud-Detection.md](Cloud-Detection.md).

---

## 0. How to use this note

1. §1–§2: the credential attack map; why it dominates intrusions.
2. §3–§5: theft from memory/disk; ticket attacks; relay/PtH.
3. §6–§8: cloud/session token theft; DCSync; golden/silver.
4. §9–§11: detection queries; triage; response.
5. §12–§14: hardening; labs; self-test/revision.

---

## 1. The credential attack map

```
Initial access
   ↓
Credential access  ← THIS NOTE
   ├── Memory: LSASS dump, handle theft
   ├── Disk: SAM, NTDS.dit, browser stores, config files
   ├── Tickets: Kerberoast, AS-REP, PtT, Golden/Silver
   ├── Network: NTLM relay, coercion
   ├── Session: token/PRT theft, cookie theft
   └── Cloud: app secrets, managed identity, device code
   ↓
Privilege escalation → Lateral movement → Impact
```

**Why it matters:** almost every serious intrusion involves credential abuse. Detecting it early breaks the chain before domain-wide impact.

---

## 2. Windows credential stores (what attackers want)

| Store | Content | Access |
|---|---|---|
| **LSASS memory** | Plaintext (WDigest/SSP), NTLM hashes, Kerberos tickets. | Admin/SYSTEM + SeDebug. |
| **SAM** | Local account NTLM hashes. | SYSTEM + registry. |
| **SECURITY hive** | LSA secrets, cached domain creds (DCC2). | SYSTEM. |
| **NTDS.dit** | All domain hashes. | DC + SYSTEM. |
| **DPAPI** | User/machine secrets, browser creds. | User/domain backup key. |
| **Credential Manager** | Saved creds. | User context. |
| **Kerberos ticket cache** | TGT/TGS. | User context. |
| **Browser stores** | Passwords, cookies. | User files + DPAPI. |
| **GPP/cScripts/configs** | Embedded passwords. | File read. |

---

## 3. Memory and disk credential theft

### 3.1 LSASS dumping techniques

| Technique | Artefact |
|---|---|
| **Mimikatz** `sekurlsa::logonpasswords` | LSASS handle, driver, named pipe. |
| **procdump** `-ma lsass.exe` | `procdump.exe` execution, dump file. |
| **comsvcs.dll MiniDump** | `rundll32 comsvcs.dll, MiniDump <pid>`. |
| **Task Manager dump** | `taskmgr.exe` creating `lsass.DMP`. |
| **nanodump / silent** | Direct syscalls, less telemetry. |
| **Dump via Defender/EDR** | Legitimate tool misuse. |

**Detection hooks:**

- **Sysmon Event 10** — `ProcessAccess` with `TargetImage=lsass.exe` and `GrantedAccess` (e.g., `0x1010`, `0x1410`, `0x143a`).
- **Windows 4656/4663** — handle to LSASS (if SACL enabled).
- **EDR** — "credential dumping" behavioural rule.
- **File creation** — `*.dmp`, `lsass.dmp`, `debug*.tmp`.
- **Process** — `rundll32` + `comsvcs`, `procdump`, unknown binaries with SeDebug.

```kusto
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","csrss.exe","services.exe","wininit.exe","svchost.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

### 3.2 SAM / hive dumping

```cmd
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive
```

- Detect `reg.exe save` targeting SAM/SYSTEM/SECURITY.
- Detect `esentutl`, `ntdsutil`, `vssadmin`/`diskshadow` + copy of `ntds.dit`.
- Volume Shadow Copy creation followed by file copy.

```spl
index=windows EventCode=4688
| where match(lower(CommandLine), "(reg\.exe\s+save|ntdsutil|esentutl|diskshadow|vssadmin.*create)")
```

### 3.3 NTDS.dit extraction

- `ntdsutil "ac i ntds" "ifm" "create full c:\temp"`.
- `diskshadow` + copy `ntds.dit` + SYSTEM hive.
- `vssadmin create shadow` + copy.

**Alert on any of these on a DC outside change windows.**

### 3.4 Browser and config harvesting

- Chromium `Login Data`, `Cookies`, `Local State`.
- Firefox `logins.json`, `key4.db`.
- `findstr /si password *.txt *.xml *.config`.
- `Get-ChildItem -Recurse | Select-String password`.
- Unattend.xml, web.config, `.env`, `wp-config.php`.

**Detection:** mass file reads by non-browser process; `findstr` with credential terms; archive creation of browser profile dirs.

---

## 4. Kerberos attacks

### 4.1 Kerberoasting (T1558.003)

**What:** request a service ticket (TGS) for an SPN, extract it, crack offline.

**Telemetry:**
- **4769** — service ticket requested.
- `TicketEncryptionType = 0x17` (RC4) is the classic signal (modern cracking on RC4).
- Many SPNs from one user in short time.
- `TicketOptions` anomalies.
- Account with SPN and weak password.

```spl
index=windows EventCode=4769
| where Ticket_Encryption_Type="0x17"
| stats count dc(Service_Name) AS spns BY Target_User_Name
| where spns > 10
```

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| summarize SPNs=dcount(ServiceName), Count=count() by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where SPNs > 10
```

**Caveats:** legacy apps still use RC4 — baseline first. 4769 is extremely high volume; filter by select accounts/IPs.

### 4.2 AS-REP Roasting (T1558.004)

**What:** accounts with **Kerberos pre-authentication disabled** return an AS-REP encrypted with the user's password hash → crack offline.

**Telemetry:**
- **4768** with `PreAuthType = 0` (no pre-auth).
- Requests from unusual hosts for many accounts.

```spl
index=windows EventCode=4768 Pre_Authentication_Type=0
| stats count BY Target_User_Name, src_ip
```

**Prevention:** remove "Do not require Kerberos preauthentication" from all accounts.

### 4.3 Pass-the-Ticket (T1550.003)

**What:** inject a stolen TGT/TGS into a session.

**Telemetry:**
- 4768/4769 from a host where the user never logs in.
- Ticket lifetime anomalies (long-lived).
- Service ticket used from different IP than issued.
- `4624` type 3 without prior 4768 on that host.

**Detection needs baselines:** user↔host↔service relationships.

### 4.4 Overpass-the-Hash (T1550.002)

- Use NTLM hash to request a Kerberos TGT.
- 4768 with `PreAuthType` 2 (encrypted timestamp) + RC4 + unusual host.
- Followed by 4769 to many services.

### 4.5 Golden Ticket (T1558.001)

**What:** forge a TGT using the **krbtgt** hash.

**Telemetry:**
- 4769 for services without a preceding 4768.
- TGT lifetime far beyond domain policy (e.g., 10 years).
- Encryption type downgrade.
- Account that doesn't exist in AD.
- 4624 with anomalous `LogonGuid`/SID history.

**Detection is hard** — relies on baselines and unusual ticket properties.

### 4.6 Silver Ticket (T1558.002)

**What:** forge a TGS for a specific service using the service account hash.

**Telemetry:**
- 4624 type 3 to the service **without** 4769 (no TGS request).
- Service-specific (e.g., CIFS, HTTP, MSSQL) access from unexpected hosts.

### 4.7 Skeleton Key / DCSync (see §7)

- Skeleton key patches LSASS to accept a master password.
- DCSync replicates hashes using DRSUAPI.

---

## 5. Network credential attacks

### 5.1 Pass-the-Hash (T1550.002)

**What:** authenticate with an NTLM hash instead of a password.

**Telemetry:**
- **4624 type 3** with NTLM (`AuthenticationPackage: NTLM`) from unusual host.
- **4776** validation success.
- No 4768/4769 (Kerberos) for that session.
- Lateral SMB/RDP/WinRM immediately after credential access.

```spl
index=windows EventCode=4624 Logon_Type=3
| where Authentication_Package="NTLM"
| stats count BY src_ip, user, dest
```

### 5.2 NTLM Relay (T1557.001)

**What:** relay NTLM auth to another service (SMB/LDAP/HTTP) to impersonate.

**Telemetry:**
- **4776** on the relay target.
- **4624 type 3** with NTLM from a host that isn't the user's.
- **Responder/ntlmrelayx** artefacts (LLMNR/NBNS traffic spikes, SMB signing off).
- LDAP binds with NTLM from unusual hosts.

**Prerequisites:** LLMNR/NBNS/mDNS enabled, SMB signing off, LDAP signing/channel binding off.

### 5.3 Coercion (PetitPotam, PrinterBug)

- Force a machine account to authenticate to attacker (e.g., `EfsRpcOpenFileRaw`, `RpcRemoteFindFirstPrinterChangeNotification`).
- Telemetry: 4624 type 3 from a machine account (`HOST$`) to an unusual destination; SMB to attacker; RPC calls (if logged).

### 5.4 Credential dumping over SMB

- Copying `ntds.dit` / hives across the network.
- Large SMB reads from DC by non-backup host.

---

## 6. Cloud and session credential theft

| Technique | Signal |
|---|---|
| **Token/PRT theft** | Sign-in with stolen refresh token; impossible travel; new device. |
| **Device code phishing** | User consents to attacker's device code. |
| **OAuth illicit consent** | New app consent with mail/file scopes. |
| **App secret theft** | New credentials added to app registration/service principal. |
| **Managed identity abuse** | IMDS token requests from unexpected process. |
| **Cookie theft** | Session hijack without MFA prompt. |
| **Password spray + MFA fatigue** | Repeated push notifications. |

```kusto
AuditLogs
| where OperationName in ("Add service principal credentials","Add app role assignment grant to user","Consent to application")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

```kusto
AADSignInEventsBeta
| where ErrorCode == 0
| summarize by AccountUpn, IPAddress, Country, DeviceDetail
```

**Key insight:** cloud credential theft often produces **no failed logins** — detect via new device, new location, anomalous token use.

---

## 7. DCSync (T1003.006)

**What:** attacker with replication rights (`DS-Replication-Get-Changes`, `-All`) requests password hashes directly from a DC.

**Telemetry:**

- **4662** — directory service access with `Control Access Right` = `Replicating Directory Changes` / `All`.
- Source account is **not** a DC (compare to known DCs).
- **DRSUAPI** network traffic to DC (RPC).
- Often preceded by privilege escalation.

```spl
index=windows EventCode=4662
| where match(Properties, "(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)")
| stats count BY Subject_Account_Name, src_ip
```

**Exclude known DCs and Azure AD Connect accounts** — otherwise noisy.

---

## 8. Detection coverage map

| Attack | Primary event | Secondary |
|---|---|---|
| LSASS dump | Sysmon 10 / EDR | dump file, procdump/rundll32 |
| SAM dump | 4688 reg save | file write to hive |
| NTDS extraction | 4688 ntdsutil/diskshadow | large file copy, VSS |
| Kerberoasting | 4769 RC4 many SPNs | cracking host network |
| AS-REP roasting | 4768 PreAuth=0 | many accounts |
| Pass-the-ticket | 4768/4769 mismatch | host baseline |
| Overpass-the-hash | 4768 RC4 unusual host | 4769 fan-out |
| Golden ticket | 4769 without 4768 | long lifetime |
| Silver ticket | 4624 without 4769 | service access |
| Pass-the-hash | 4624 type 3 NTLM | lateral SMB |
| NTLM relay | 4776 + 4624 type 3 | LLMNR/NBNS, no signing |
| DCSync | 4662 replication | non-DC source |
| Cloud token theft | sign-in new device/geo | no MFA event |
| OAuth consent | AuditLogs consent | new app |

---

## 9. Triage playbook

### Step 1 — Identify the technique
Which credential store/attack is indicated? Which telemetry fired?

### Step 2 — Identify the actor host
Source host, user, process, command line, parent.

### Step 3 — Determine success
- Was the credential actually extracted? (dump file exists, tool exit, network exfil)
- Were stolen creds used? (subsequent logons)
- Did privilege change?

### Step 4 — Determine privilege of target
- Local admin? Domain admin? krbtgt? Service account with SPN?
- What could the attacker now do?

### Step 5 — Scope
- Same tool/hash across estate.
- All hosts the compromised account touched.
- Lateral movement from those hosts.

### Step 6 — Escalate
Credential access on a DC or privileged account = **critical, immediate escalation**.

### Step 7 — Contain
- Isolate host (preserve memory first if dumping in progress).
- Reset passwords (affected + privileged), twice for krbtgt if golden ticket.
- Revoke Kerberos tickets (`klist purge`, reset krbtgt).
- Revoke cloud sessions/tokens.
- Block IOCs.

### Step 8 — Eradicate
Remove tooling/persistence; hunt for the initial access; reimage if uncertain.

---

## 10. Response specifics

| Attack | Response |
|---|---|
| LSASS dump | Isolate, capture memory, reset all creds on host, hunt hash use, reimage. |
| Kerberoasting | Reset SPN account passwords (long, random), rotate, check cracking host. |
| AS-REP roasting | Enable pre-auth, reset password. |
| Pass-the-hash | Reset NTLM hash (password), disable NTLM where possible, find source host. |
| Golden ticket | **Reset krbtgt twice** (with replication wait), reset DA creds, rebuild trust if needed. |
| DCSync | Remove replication rights, reset exposed accounts, audit ACLs. |
| Cloud token theft | Revoke sessions, reset password, re-register MFA, review OAuth grants. |

**Resetting a password does not invalidate existing Kerberos tickets** — purge/invalidate.

---

## 11. Hardening

| Control | Effect |
|---|---|
| **Credential Guard** | Protects LSASS secrets. |
| **LSA protection (RunAsPPL)** | Blocks non-PPL LSASS access. |
| **Disable WDigest** | No plaintext in memory. |
| **Protected Users group** | No NTLM/cached creds/RC4 for admins. |
| **Tiered admin model** | Limits credential exposure. |
| **PAW/red forest** | Admin creds never on user hosts. |
| **Disable NTLM** | Removes PtH/relay surface. |
| **SMB/LDAP signing + channel binding** | Blocks relay. |
| **Disable LLMNR/NBNS** | Blocks poisoning. |
| **gMSA** | No static service passwords. |
| **Long random SPN passwords** | Kerberoast-resistant. |
| **Remove pre-auth exemption** | AS-REP resistant. |
| **krbtgt rotation** | Limits golden-ticket lifetime. |
| **EDR + Sysmon 10** | Detection. |
| **MFA + Conditional Access** | Cloud token abuse limits. |
| **App consent restrictions** | Blocks illicit consent. |

---

## 12. Labs

1. Enable Sysmon; run a benign LSASS read; detect event 10.
2. Run `procdump` in a lab; detect process + file.
3. Generate 4769 RC4 events; build Kerberoasting query.
4. Configure an account with no pre-auth; detect 4768 PreAuth=0.
5. Simulate DCSync with `mimikatz` in an isolated lab; detect 4662.
6. Test pass-the-hash with a lab tool; detect 4624 type 3 NTLM.
7. Build a `4662` baseline excluding DCs.
8. Simulate OAuth consent in a test tenant; detect in AuditLogs.
9. Write the credential-attack triage runbook.
10. Measure FP rate of Kerberoasting detection over a week.

---

## 13. Self-test questions

1. What does LSASS contain, and what access is needed to dump it?
2. Which Sysmon event detects LSASS access?
3. Difference between Kerberoasting and AS-REP roasting?
4. Which event IDs indicate each?
5. What is a golden ticket, and how is it detected?
6. Why is silver-ticket detection hard?
7. What telemetry indicates pass-the-hash?
8. What prerequisites enable NTLM relay?
9. What is DCSync, and which event shows it?
10. Why doesn't password reset stop a golden ticket?
11. How does cloud token theft differ from password guessing?
12. What post-theft activity do you look for?
13. What are the top three hardening controls?
14. Why is 4769 high volume, and how do you filter?
15. What is the correct response to a golden ticket?

---

## 14. One-page revision checklist

- [ ] Credential attack map: memory, disk, tickets, network, session, cloud.
- [ ] Stores: LSASS, SAM, SECURITY, NTDS, DPAPI, Credential Manager, ticket cache, browser, configs.
- [ ] LSASS dumping: mimikatz, procdump, comsvcs, taskmgr, nanodump; Sysmon 10, 4656/4663, EDR, dump files.
- [ ] SAM/hive: `reg save`, esentutl, ntdsutil, diskshadow, vssadmin.
- [ ] NTDS extraction paths; alert on DC.
- [ ] Kerberos: 4769 RC4 many SPNs (Kerberoast), 4768 PreAuth=0 (AS-REP), PtT/Overpass, golden (4769 without 4768, long lifetime), silver (4624 without 4769).
- [ ] Network: PtH (4624 type 3 NTLM + 4776), relay (signing/LLMNR), coercion (machine account auth), SMB dumping.
- [ ] Cloud: token/PRT, device code, OAuth consent, app secrets, managed identity, cookie theft, MFA fatigue; AuditLogs/SigninLogs.
- [ ] DCSync 4662 replication rights; exclude DCs/AAD Connect.
- [ ] Coverage map table recalled.
- [ ] Triage 8 steps; escalation rules; response per attack (krbtgt twice for golden).
- [ ] Hardening: Credential Guard, RunAsPPL, WDigest off, Protected Users, tiering/PAW, NTLM off, signing, LLMNR off, gMSA, long SPN passwords, pre-auth on, krbtgt rotation, EDR/Sysmon, MFA/CA, consent restrictions.
- [ ] Queries recalled: LSASS access, Kerberoast, AS-REP, DCSync, PtH.

---

> **Navigation:** [Roadmap index](../README.md) · [← Brute Force](Brute-Force.md) · [Lateral Movement →](Lateral-Movement.md)
