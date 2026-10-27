# Common Attacks — SOC Analyst Study Notes

> Goal: recognise the **attack patterns you will actually see in alerts**, know what telemetry each produces, and triage them in order of consequence.
> Technique IDs → `MITRE-ATTACK.md`; payloads → `Malware.md`; auth-focused attacks → `Authentication.md`; web vuln mechanics → `Vulnerabilities.md`.

---

## 0. How to use this note

1. §1–§2: why pattern knowledge matters; the attack lifecycle.
2. §3–§9: initial access, execution, credential, web, network, privilege/lateral, impact.
3. §10–§12: cloud/identity, supply chain, social engineering/insider.
4. §13–§16: detection matrix, investigation, triage, severity.
5. §17–§20: commands, false positives, labs, self-test, revision.

---

## 1. Why common attacks matter to a SOC analyst

- You will triage the **same 15–20 patterns** repeatedly; recognising them fast is the job.
- Each attack leaves a **characteristic telemetry fingerprint** — knowing it lets you pick the right log.
- Alert names are vendor-specific; **mapping to a pattern** lets you reason independently.
- Patterns compose into **chains** (phishing → execution → creds → lateral → ransomware); you must see the chain, not the alert.
- Interviewers test pattern recognition more than tool knowledge.

**SOC outcomes:** given an alert you can answer:
- Which attack pattern is this?
- What is the expected next step if it succeeds?
- Which logs confirm or refute it?
- What is the blast radius?
- What is the fastest safe containment?

---

## 2. Attack lifecycle models

### 2.1 Cyber Kill Chain (Lockheed Martin)

1. **Reconnaissance** — target selection, OSINT, scanning.
2. **Weaponisation** — build payload/document.
3. **Delivery** — email, web, USB, exploit.
4. **Exploitation** — code execution / auth abuse.
5. **Installation** — persistence.
6. **Command & Control (C2)** — remote control.
7. **Actions on Objectives** — theft, encryption, disruption.

**Use:** communicate to leadership, identify where to break the chain; weaker for cloud/identity-only attacks.

### 2.2 MITRE ATT&CK

Tactics → techniques → sub-techniques, with real-world procedure examples. **Use:** detection mapping and coverage analysis. See `MITRE-ATTACK.md`.

### 2.3 Unified Kill Chain

Combines kill chain + ATT&CK for modern (including identity/cloud) attacks.

### 2.4 Diamond Model

Adversary ↔ Infrastructure ↔ Capability ↔ Victim, with social-political context. **Use:** pivot analysis and attribution.

> **SOC rule:** detect at the **earliest reliable point** (delivery, execution, credential use), not only at impact.

---

## 3. Initial access patterns

| Pattern | Examples | Telemetry |
|---|---|---|
| **Phishing** | Malicious attachment, link, QR, OAuth consent, thread hijack | Mail gateway, proxy, DNS, EDR, sign-in logs. |
| **Exploit public-facing app** | VPN, Exchange, Citrix, web CMS, API | WAF, web logs, EDR, crash/child process. |
| **Valid accounts** | Stolen creds, purchased access, MFA fatigue | Sign-in logs, VPN, 4624. |
| **External remote services** | RDP, SSH, WinRM exposed | Firewall, 4624 type 10, sshd. |
| **Drive-by compromise** | Malvertising, compromised site | Proxy, DNS, EDR. |
| **Removable media** | USB drop | 4688, USBSTOR, EDR. |
| **Supply chain** | Compromised vendor/update, dependency | Vendor logs, code signing, EDR. |
| **Trusted relationship** | MSP/partner access | IdP logs, cross-tenant access. |
| **Hardware** | Rogue device, BMC | Network inventory, NAC. |

**Fast triage questions:** delivered or blocked? executed? credentials used? from where?

---

## 4. Execution patterns

| Pattern | Indicators |
|---|---|
| **Office macro** | `winword.exe` → `cmd`/`powershell`, VBA, `AutoOpen`. |
| **LNK/HTA/ISO/IMG** | `explorer.exe` → `cmd`, mounted image, `.lnk` in temp. |
| **Script interpreters** | `wscript`, `cscript`, `mshta`, `powershell -enc`. |
| **LOLBins** | `certutil`, `rundll32`, `regsvr32`, `installutil`, `msbuild`, `wmic`, `bitsadmin`. |
| **Signed binary proxy** | Trusted binary loads attacker DLL. |
| **DLL side-loading** | Missing DLL in writable dir. |
| **Web shell** | `w3wp`/`httpd` → `cmd`/`sh`, file in webroot. |
| **Container exec** | `docker exec`, `kubectl exec`, privileged pod. |
| **Cloud function/run** | New function, unusual invocation. |
| **Scheduled task/cron** | New task/unit/script. |

**Detection anchor:** parent-child plausibility + command line + path + signature.

---

## 5. Credential and identity attacks

| Pattern | Indicators |
|---|---|
| **Password spray/brute force** | 4625/4771 spread, low-and-slow, success after. |
| **Credential stuffing** | Distributed IPs, breach passwords. |
| **Phishing for creds** | Lookalike domain, proxy phishing, MFA prompts. |
| **MFA fatigue** | Push denials then approval. |
| **Token theft** | Session use from new IP without login. |
| **Pass-the-hash/ticket** | NTLM type 3, no 4768, anomalous account. |
| **Kerberoasting/AS-REP** | 4769 RC4 volume, 4768 without pre-auth. |
| **DCSync** | 4662 replication rights on domain object. |
| **LSASS dump** | Sysmon 10, `procdump`, `comsvcs`. |
| **SAM/NTDS copy** | `reg save`, `esentutl`, VSS. |
| **Golden/Silver ticket** | KRBTGT/service key abuse, long ticket lifetime. |
| **Consent phishing** | New OAuth grant with mail/file scopes. |

**Blast radius:** credential compromise usually means **everything that account can reach**, plus reuse elsewhere.

---

## 6. Web application attacks (what SOC sees)

| Attack | Signal in logs | Notes |
|---|---|---|
| **SQL injection** | `' OR 1=1`, `UNION SELECT`, error floods | WAF, DB errors, unusual queries. |
| **XSS** | `<script>`, `onerror=`, encoded payloads | Reflected/stored; may need browser telemetry. |
| **CSRF** | State-changing request without token | Hard to see in logs; correlate origin. |
| **SSRF** | Requests to internal IPs/metadata | `169.254.169.254`, `localhost`, internal hostnames. |
| **Path traversal / LFI** | `../`, `%2e%2e`, `/etc/passwd`, `php://` | Web logs, file access. |
| **File upload abuse** | `.php`, `.jsp`, double extensions, polyglot | Upload endpoint + execution. |
| **Command injection** | `;`, `|`, `$()`, backticks in params | Web logs + child process. |
| **Deserialization** | Base64 blobs, gadget chains | Java/PHP/.NET apps. |
| **XXE** | `<!DOCTYPE`, `SYSTEM`, `file://` | XML endpoints, OOB callbacks. |
| **SSTI** | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` | Template engines. |
| **API abuse** | BOLA/BFLA, mass assignment, rate abuse | API gateway logs, 401/403 patterns. |
| **Auth bypass** | Forced browsing, JWT tampering | 200 on protected path, token anomalies. |
| **Web shell** | New file in webroot, `cmd` child | FIM + process + web logs. |
| **Scanner activity** | High 404/403, common paths | Noise; look for follow-up. |

**SOC pattern:** scan noise → a 200 on an unusual path → POST with payload → child process → shell. Detect the **chain**, not the 404s.

---

## 7. Network attacks

| Pattern | Indicators |
|---|---|
| **Port scanning** | Many destinations/ports, SYN scans, short duration. |
| **Brute force on services** | SSH/RDP/VPN/SMB auth failures. |
| **MITM / ARP spoofing** | Duplicate ARP, gateway MAC change, TLS anomalies. |
| **DNS tunneling** | Long/high-entropy subdomains, TXT/NULL queries, volume. |
| **DNS hijacking** | Resolver change, rogue DHCP DNS. |
| **C2 beaconing** | Periodic connections, jitter, rare domains. |
| **Data exfiltration** | Large outbound, unusual destinations, cloud storage. |
| **Lateral SMB/RPC** | 5140/5145, admin shares, named pipes. |
| **SMB relay** | NTLM auth to unexpected host, signing disabled. |
| **LLMNR/NBT-NS poisoning** | Responder traffic, name resolution anomalies. |
| **DDoS** | Volumetric, SYN flood, HTTP flood, amplification. |
| **Wi-Fi attacks** | Rogue AP, deauth, evil twin. |
| **VPN abuse** | Impossible travel, new device, concurrent sessions. |

**Detection sources:** firewall, IDS/IPS, NetFlow, DNS logs, proxy, Zeek, PCAP.

---

## 8. Privilege escalation patterns

### Windows
- Weak service ACL/unquoted path/writable binary.
- `SeImpersonate` (Potato), `SeBackup`/`SeRestore`, `SeDebug`.
- UAC bypass (`fodhelper`, `computerdefaults`, `sdclt`).
- AlwaysInstallElevated, weak task/registry perms.
- Credential reuse from local admin.
- Kernel/driver exploit, BYOVD.

### Linux
- SUID/SGID, capabilities, sudo NOPASSWD, writable cron/systemd.
- Kernel exploit, container escape, docker/lxd group.
- Writable `/etc/passwd`, PATH hijack, LD_PRELOAD.

### Cloud/identity
- Over-broad role, `iam:PassRole`, role chaining, managed identity abuse.
- App secret/key exposure, CI/CD token abuse.

**Detection:** process lineage to SYSTEM/root, new admin group membership, service/task creation, credential access, unusual token privileges.

---

## 9. Lateral movement and impact

### 9.1 Lateral movement

| Technique | Evidence |
|---|---|
| SMB/admin shares | 5140/5145, `ADMIN$`, file writes. |
| PsExec | `PSEXESVC`, pipe, service 7045. |
| WMI | WMI-Activity, 4624 type 3, `Win32_Process`. |
| WinRM | WinRM logs, 4624 type 3/8. |
| RDP | 4624 type 10, 4778/4779. |
| Scheduled task remote | 4698, remote creation. |
| Pass-the-hash/ticket | NTLM/Kerberos anomalies. |
| DCOM | `MMC20.Application`, `ShellWindows`. |
| SSH/cloud exec | sshd, cloud audit. |

### 9.2 Collection and exfiltration

- Staging: archives (`zip`, `rar`, `7z`), temp directories, cloud sync.
- Exfil channels: HTTPS, DNS, cloud storage, email, USB, FTP, C2.
- Evidence: large outbound, archive creation, unusual destinations, DLP.

### 9.3 Impact

- **Ransomware**: shadow copy deletion, mass encryption, ransom notes, backup tampering.
- **Wiper**: MBR/boot destruction, mass deletion.
- **BEC/fraud**: mailbox rules, payment detail changes.
- **Data breach**: exfil + public leak/extortion.
- **Defacement**: web content change.
- **DDoS**: availability loss.

---

## 10. Cloud and identity attacks

| Pattern | Indicators |
|---|---|
| **Credential/key leak** | New key use from unusual IP, code repo leak. |
| **Console login anomaly** | New geo/device, MFA changes, root login. |
| **Role escalation** | `AttachRolePolicy`, `CreatePolicyVersion`, `AddMember`. |
| **Public storage** | Bucket ACL/public access changes. |
| **Metadata SSRF** | Requests to `169.254.169.254`, `metadata.google.internal`. |
| **Consent grant** | OAuth app with mail/file scopes. |
| **Token theft** | Refresh token reuse, impossible travel. |
| **CI/CD abuse** | New workflow, secret exfil, runner registration. |
| **Kubernetes** | `cluster-admin` binding, privileged pod, SA token use. |
| **Cloud resource abuse** | Crypto-mining instances, new regions. |

**Detection sources:** CloudTrail, Azure Activity/Sign-in, GCP Audit, K8s audit, CASB, IdP logs.

---

## 11. Supply chain and trusted relationship

- Compromised software update (SolarWinds-style), malicious dependency, trojanised installer.
- Vendor/MSP remote access abuse; cross-tenant access.
- Code-signing abuse; stolen certificates.
- Detection: unusual vendor process behaviour, new outbound destinations, unexpected code changes, SBOM/dependency alerts, signed-but-anomalous binaries.

> **Hard problem:** trusted binaries and vendors bypass allowlists. Behavioural baselines and egress monitoring matter more than signatures.

---

## 12. Social engineering and insider threats

| Pattern | Indicators |
|---|---|
| **Phishing/vishing/pretexting** | User reports, lookalike domains, urgency. |
| **BEC** | Mailbox rules, reply-to changes, payment change requests. |
| **Helpdesk impersonation** | MFA reset, password reset, new device. |
| **Insider data theft** | Bulk access before resignation, USB, cloud upload. |
| **Sabotage** | Permission changes, deletions, account abuse. |
| **Credential sharing** | Same account, multiple devices/locations. |

**Insider detection** is largely **behavioural baselining** + HR/legal process; avoid over-alerting on normal work.

---

## 13. Detection matrix (pattern → telemetry → query focus)

| Pattern | Primary telemetry | Query focus |
|---|---|---|
| Phishing | Mail, proxy, DNS | Sender/domain, attachment hash, clicked URL. |
| Execution | EDR/Sysmon/4688 | Parent, command line, path, hash. |
| Credential attacks | Auth logs | Volume, spread, success, source. |
| Web attack | Web/WAF | Payload, status, child process. |
| Lateral | 4624/5140/WMI | Account + source + destination. |
| C2 | Proxy/DNS/NetFlow | Periodicity, rarity, reputation. |
| Exfil | Proxy/DLP/NetFlow | Volume, destination, data type. |
| Ransomware | EDR/file/4688 | Shadow deletion, encryption rate, notes. |
| Cloud abuse | Cloud audit/IdP | IAM changes, public access, new keys. |

### Splunk examples

**Phishing click then execution:**
```spl
index=proxy url=*
| join type=left src_ip [search index=edr EventCode=1]
| where isnotnull(Image)
| table _time, user, url, Image, CommandLine
```

**Scan then exploit:**
```spl
index=web status IN (401,403,404)
| stats count by src_ip, uri_path
| where count > 100
| join src_ip [search index=web status=200 method=POST uri_path=*]
```

**Lateral movement burst:**
```spl
index=wineventlog EventCode=4624 LogonType=3
| stats dc(ComputerName) as targets by TargetUserName, src_ip
| where targets > 3
```

**C2 beaconing (regularity):**
```spl
index=proxy
| streamstats current=f window=1 last(_time) as prev by dest
| eval delta=_time-prev
| stats stdev(delta) as jitter avg(delta) as avg_delta count by dest
| where count > 20 AND jitter < avg_delta*0.2
```

### KQL examples

**Execution after phishing click:**
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "outlook.exe"
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
```

**Lateral movement:**
```kusto
SecurityEvent
| where EventID == 4624 and LogonType == 3
| summarize Targets = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 30m)
| where Targets > 3
```

**Cloud IAM escalation:**
```kusto
AWSCloudTrail
| where EventName in ("AttachUserPolicy","AttachRolePolicy","CreateAccessKey","CreatePolicyVersion","PutRolePolicy")
| project TimeGenerated, UserIdentityArn, EventName, SourceIpAddress
```

---

## 14. Investigation workflow

### Step 1 — Name the pattern
What class of attack is this? Which tactic?

### Step 2 — Determine success
Attempted vs executed vs persisted vs moved vs exfiltrated.

### Step 3 — Identify the earliest reliable evidence
Was it delivered? executed? authenticated? Which log proves it?

### Step 4 — Establish the chain
Build timeline: delivery → execution → persistence → credentials → lateral → impact.

### Step 5 — Scope
Same artefact across estate; same account across services; same infrastructure.

### Step 6 — Contain
Block at the earliest choke point: mail, DNS, proxy, identity, endpoint isolation.

### Step 7 — Eradicate and recover
Remove persistence, reset creds, patch, restore, verify.

### Step 8 — Document pattern, technique IDs, evidence, gaps.

---

## 15. Triage playbooks (pattern-based)

### A. Phishing campaign
1. Sender/domain/URL/attachment hash.
2. Delivered to whom? Clicked? Credentials entered? Executed?
3. Purge, block, reset affected creds, hunt.

### B. Malware execution
1. Hash/path/parent/command line.
2. Behaviours: persistence, network, injection.
3. Isolate, remove, hunt.

### C. Ransomware
1. Scope (hosts/shares), patient zero, backups.
2. Contain, preserve, engage IR; do not reboot.
3. Determine exfil/double extortion.

### D. Web shell / web attack
1. Request that created it; file path/hash.
2. Child processes, network.
3. Remove, patch, review logs.

### E. Credential attack
See `Authentication.md` playbooks.

### F. Lateral movement
1. Source host, account, technique.
2. Blast radius; compromised creds.
3. Isolate source, reset creds, hunt destination hosts.

### G. C2 / beaconing
1. Destination reputation, periodicity, process.
2. Data volume, other hosts.
3. Block, isolate, memory capture.

### H. Data exfiltration
1. What/how much/where.
2. Authorised transfer?
3. Block, preserve, privacy/legal.

### I. Cloud abuse
1. Principal, action, resource, source.
2. Legit automation or attacker?
3. Revoke, rotate, right-size, audit.

### Severity guide

| Scenario | Typical severity |
|---|---|
| Blocked phishing, no clicks | Low |
| Click, no creds/execution | Medium |
| Credential compromise | High |
| Malware executed, contained | High |
| Lateral movement | Critical |
| Ransomware/wiper | Critical |
| Sensitive data exfil | Critical |
| Public bucket, limited data | Medium–High |
| Scan noise | Informational |

---

## 16. ATT&CK quick mapping

| Pattern | Technique examples |
|---|---|
| Phishing | T1566 |
| Exploit public app | T1190 |
| Valid accounts | T1078 |
| Command interpreter | T1059 |
| LOLBins | T1218 |
| OS credential dumping | T1003 |
| Kerberoasting | T1558.003 |
| Pass-the-hash | T1550.002 |
| Scheduled task | T1053 |
| Service | T1543.003 |
| Run key | T1547.001 |
| Web shell | T1505.003 |
| Lateral SMB | T1021.002 |
| RDP | T1021.001 |
| C2 | T1071, T1571, T1090 |
| Exfil | T1041, T1048, T1567 |
| Ransomware | T1486 |
| Inhibit recovery | T1490 |
| Impair defenses | T1562 |
| Clear logs | T1070.001 |
| Account creation | T1136 |

---

## 17. Commands useful during triage

```bash
# Network / C2
ss -tunp; netstat -anop
tcpdump -i any -nn port 443
dig +short suspicious.domain
whois suspicious.domain

# Web logs
grep "POST" access.log | awk '{print $1,$7,$9}' | sort | uniq -c | sort -rn | head
grep -E "(\?|%3F).*(union|select|script|\.\./)" access.log

# Files / hashes
sha256sum suspicious.bin
strings -a suspicious.bin | head -50

# Windows
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 100
Get-NetTCPConnection -State Established | Sort RemotePort
```

```powershell
# DNS/proxy from logs via SIEM is preferred; endpoint quick checks:
Resolve-DnsName suspicious.domain
Get-DnsClientCache | Where-Object Entry -like "*suspicious*"
```

---

## 18. Common false positives

| Alert | Often actually |
|---|---|
| Port scan | Vulnerability scanner, monitoring, inventory. |
| Brute force | Misconfigured app/service, cached creds. |
| C2 beacon | Software updater, telemetry, health check. |
| DNS tunneling | CDN/AV/telemetry, long but legitimate names. |
| Lateral movement | Admin tools, backup, SCCM, monitoring. |
| Web attack | Security scanner, fuzzing tests, WAF test. |
| Data exfil | Backup, cloud sync, authorised transfer. |
| Phishing | Marketing mail, newsletter, internal campaign. |
| Ransomware | Encryption software, backup compression. |
| Credential dumping | EDR/backup/admin tooling. |

**Validate with:** asset ownership, change records, baseline, reputation, and whether the behaviour continues or escalates.

---

## 19. Labs

1. Simulate phishing → macro → PowerShell in a lab; build the full timeline.
2. Run a web scanner against a lab app; separate noise from exploitation.
3. Perform spray and brute force; write detections for both.
4. Use PsExec/WMI/RDP between lab hosts; compare telemetry.
5. Create a web shell; detect via FIM + process + logs.
6. Beacon with a benign C2 simulator; detect periodicity.
7. Exfiltrate test data over HTTPS/DNS; compare detection coverage.
8. Run a ransomware simulator; practise containment.
9. Enumerate cloud IAM escalation in a sandbox; detect.
10. Map each lab action to ATT&CK IDs and write a coverage note.

---

## 20. Self-test questions

1. Name the seven kill chain phases.
2. Why is ATT&CK better for detection mapping than the kill chain?
3. What distinguishes spray from brute force in logs?
4. What are three signs of a web shell?
5. Which log proves lateral movement over SMB?
6. What does periodic beaconing look like statistically?
7. Which technique deletes shadow copies, and why?
8. How does consent phishing differ from credential phishing?
9. What is the fastest choke point for a phishing campaign?
10. Which events indicate DCSync?
11. What is BYOVD, and why is it used?
12. How do you distinguish scanner noise from exploitation?
13. Which cloud API calls indicate privilege escalation?
14. What is double extortion?
15. How do you scope a credential compromise?

---

## 21. One-page revision checklist

- [ ] Kill chain: recon, weaponise, deliver, exploit, install, C2, actions. ATT&CK tactics/techniques/sub-techniques. Diamond model.
- [ ] Initial access: phishing, public app exploit, valid accounts, remote services, drive-by, USB, supply chain, trusted relationship, hardware.
- [ ] Execution: macros, LNK/HTA/ISO, interpreters, LOLBins, signed binary proxy, side-loading, web shell, container/cloud exec, tasks/cron.
- [ ] Credential: spray, brute force, stuffing, phishing, MFA fatigue, token theft, PTH/PTT, roasting, DCSync, LSASS/SAM/NTDS, golden/silver, consent.
- [ ] Web: SQLi, XSS, CSRF, SSRF, traversal/LFI, upload, command injection, deserialization, XXE, SSTI, API abuse, auth bypass, web shell, scanners.
- [ ] Network: scanning, service brute force, MITM/ARP, DNS tunneling/hijack, C2, exfil, SMB/RPC lateral, relay, LLMNR poisoning, DDoS, Wi-Fi, VPN abuse.
- [ ] PrivEsc: Windows service/impersonation/UAC/AlwaysInstallElevated/BYOVD; Linux SUID/caps/sudo/cron/container; cloud roles/PassRole/managed identity.
- [ ] Lateral: SMB, PsExec, WMI, WinRM, RDP, tasks, PTH/PTT, DCOM, SSH/cloud exec.
- [ ] Impact: ransomware, wiper, BEC, breach, defacement, DDoS; staging/archive/exfil channels.
- [ ] Cloud/identity: key leak, console anomaly, role escalation, public storage, metadata SSRF, consent, token theft, CI/CD, K8s, resource abuse.
- [ ] Supply chain/trusted relationship: update compromise, dependency, MSP, signing abuse.
- [ ] Social/insider: phishing variants, BEC, helpdesk, data theft, sabotage, sharing.
- [ ] Detection matrix + SPL/KQL patterns: phishing→exec, scan→exploit, lateral burst, beacon periodicity, cloud IAM.
- [ ] Investigation: name → success? → earliest evidence → chain → scope → contain → eradicate → document.
- [ ] Triage: phishing, malware, ransomware, web shell, credential, lateral, C2, exfil, cloud; severity table.
- [ ] ATT&CK mapping table memorised for top 20 patterns.
