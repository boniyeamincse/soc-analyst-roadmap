# Eradication — Incident Response Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Containment](Containment.md) · [Identification →](Identification.md)

> Goal: remove the attacker's presence *and* the vulnerability that let them in — then prove it.
> Containment → [Containment.md](Containment.md); restore → [Recovery.md](Recovery.md); cause analysis → [07 - Investigation/Root-Cause-Analysis.md](../07%20-%20Investigation/Root-Cause-Analysis.md).

---

## 0. How to use this note

1. §1–§3: eradication scope; rebuild vs clean; prerequisites.
2. §4–§7: persistence inventory and removal across OS, AD, cloud, email.
3. §8–§11: credential reset strategy, vulnerability remediation, eviction of an active actor, verification.
4. §12–§16: monitoring window, re-infection prevention, validation, documentation, pitfalls.
5. §17–§19: playbooks, labs.
6. §20–§21: self-test, revision.

---

## 1. What eradication includes

| Element | Question |
|---|---|
| **Malware** | All files, processes, memory artefacts removed? |
| **Persistence** | Every autostart mechanism removed? |
| **Credentials** | Every credential the attacker touched rotated? |
| **Access paths** | The vulnerability/entry point fixed? |
| **Accounts** | Rogue accounts, keys, tokens removed? |
| **Config** | Attacker changes reverted? |
| **Data** | Stolen data accounted for (cannot be un-stolen)? |

**Eradication without fixing the entry point = guaranteed recurrence.**

---

## 2. Rebuild vs clean

| | **Clean in place** | **Rebuild** |
|---|---|---|
| **Speed** | Faster | Slower |
| **Confidence** | Low — hidden persistence | High |
| **Cost** | Low | Medium |
| **Use when** | Simple, well-understood, low privilege | Root/admin compromise, malware, uncertainty |
| **Risk** | Re-infection | Downtime |

### 2.1 Rule of thumb

| Compromise level | Action |
|---|---|
| User-level, no admin, known malware | Clean + verify |
| Local admin | Rebuild recommended |
| Domain admin / Tier-0 | Rebuild + domain-wide reset |
| Firmware/bootkit suspected | Replace/reflash |
| Ransomware | Rebuild from known-good |

**If you cannot enumerate the persistence, you cannot clean it.**

---

## 3. Prerequisites

- [ ] Scope established (which hosts/accounts).
- [ ] Evidence acquired and preserved.
- [ ] Containment verified.
- [ ] Recovery path (backups/images) validated.
- [ ] Change approval and business window.
- [ ] Credential reset plan.
- [ ] Monitoring in place for re-infection.

---

## 4. Persistence inventory

### 4.1 Windows

| Mechanism | Where |
|---|---|
| Run/RunOnce | `HKLM/HKCU ...\CurrentVersion\Run*` |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services` |
| Scheduled tasks | `C:\Windows\System32\Tasks`, Task Scheduler |
| WMI subscription | `__EventFilter`, `CommandLineEventConsumer` |
| Startup folder | `%APPDATA%\...\Startup`, ProgramData |
| DLL search order / AppInit | `AppInit_DLLs`, `KnownDLLs` |
| COM hijack | `HKCU\Software\Classes\CLSID` |
| Image File Execution Options | Debugger keys |
| Winlogon | `Shell`, `Userinit`, `Notify` |
| LSA packages | `HKLM\SYSTEM\...\LSA` |
| BITS jobs | `bitsadmin /list` |
| Print processors / port monitors | Spooler |
| Netsh helper DLLs | `netsh add helper` |
| Accessibility features | `sethc.exe`, `utilman.exe` |
| Screensaver | `.scr` |
| Drivers | `System32\drivers`, kernel services |
| Bootkit / MBR | Boot sector, UEFI |
| Browser extensions | Chrome/Edge profiles |
| Office add-ins | `%APPDATA%\Microsoft\AddIns` |
| PowerShell profiles | `$PROFILE` |

### 4.2 Linux

| Mechanism | Where |
|---|---|
| cron / anacron | `/etc/cron*`, `/var/spool/cron` |
| systemd units | `/etc/systemd/system`, user units |
| init scripts | `/etc/init.d`, rc.local |
| SSH keys | `authorized_keys`, `sshd_config` |
| `LD_PRELOAD` | `/etc/ld.so.preload`, env |
| PAM modules | `/etc/pam.d`, `/lib/security` |
| Kernel modules | `/etc/modules`, `modprobe.d` |
| Shell profiles | `.bashrc`, `.profile`, `/etc/profile.d` |
| Web shells | web roots |
| SUID backdoors | unusual SUID binaries |
| at jobs | `atq` |
| Git hooks | repos |

### 4.3 Active Directory / identity

| Mechanism | Check |
|---|---|
| Rogue accounts | New/changed users, computers |
| Group membership | Domain/Enterprise/Schema Admins |
| AdminSDHolder | ACL |
| ACL backdoors | `GenericAll`, `WriteDACL`, `DCSync` rights |
| SID history | Injected SIDs |
| Golden ticket | `krbtgt` compromise |
| Silver ticket | Service account hashes |
| DCSync rights | Replication permissions |
| GPO | Malicious policy/scripts |
| Skeleton key | LSA patch |
| DCShadow | Rogue DC registration |
| Delegation | Unconstrained/constrained/RBCD |
| Certificate templates | ESC abuse |
| `msDS-KeyCredentialLink` | Shadow credentials |

### 4.4 Cloud

| Mechanism | Check |
|---|---|
| IAM users/keys | New users, access keys |
| Role trust policies | Cross-account trust |
| OAuth apps / consent | Illicit grants |
| Service principals | New enterprise apps |
| Conditional access | Weakened policies |
| Mailbox rules/forwarding | BEC persistence |
| Inbox delegates | Mail access |
| Storage policies | Public/exfil |
| Lambda/functions | Backdoors |
| Resource policies | Cross-account access |
| SSO/SAML | Rogue IdP |
| Secrets | Rotate all |

### 4.5 Email

| Mechanism | Check |
|---|---|
| Forwarding rules | Hidden auto-forward |
| Inbox rules | Delete/move rules |
| Delegates | Mailbox access |
| OAuth grants | Mail.Read, Send |
| Transport rules | Tenant-level |
| Connectors | Inbound/outbound |
| Safe-lists | Attacker-added allow entries |
| Signature | Malicious links |

---

## 5. Removal

### 5.1 Order

```
1. Preserve evidence
2. Remove persistence (so it can't come back during the process)
3. Remove payload/malware
4. Kill processes (after suspend/collect)
5. Clean registry/config
6. Reset credentials
7. Patch the entry point
8. Verify
```

**If you remove the payload first, persistence will simply re-drop it.**

### 5.2 Removal cautions

- Some malware **wipes on kill** — suspend first.
- Some persistence is **watchdogged** — remove all together.
- Some has **multiple stages** — removing stage 1 leaves stage 2 dormant.
- Some is in **firmware** — OS cleaning is futile.

### 5.3 Rebuild workflow

```
verify clean image → rebuild → patch to baseline
→ re-enrol management/EDR → restore data (not binaries)
→ verify no persistence → return to service
```

**Restore data, not applications or configuration, from compromised systems.**

---

## 6. Active Directory cleanup

If privileged compromise is suspected:

| Step | Detail |
|---|---|
| Reset `krbtgt` **twice** | Invalidates Golden Tickets; wait replication between. |
| Reset all privileged accounts | Twice for Tier-0 if needed. |
| Reset service account passwords | Coordinate with app owners. |
| Rotate certificates | If CA compromise suspected. |
| Remove rogue accounts | Including computers. |
| Clean ACLs / AdminSDHolder | Revert unauthorised changes. |
| Remove SID history | |
| Audit delegation | |
| Reset DSRM password | If DC compromised. |
| Rebuild compromised DCs | Preferred for Tier-0. |
| Verify replication | |

**Domain-wide compromise invalidates the assumption that any credential is safe.**

---

## 7. Cloud cleanup

- Disable/delete rogue identities and keys.
- Revoke all sessions and refresh tokens.
- Remove OAuth consents.
- Revert trust policies.
- Remove backdoor functions/roles.
- Restore restrictive CA policies.
- Remove mailbox rules/forwarding.
- Rotate all secrets the principal could read.
- Review audit logs for what was created.

**Check for cross-account trust — attackers persist outside the account they compromised.**

---

## 8. Credential reset strategy

### 8.1 Which credentials

| Credential | Reset if |
|---|---|
| User password | Compromised or reused |
| Admin password | Any privileged host touched |
| Service account | Used on compromised host |
| Kerberos `krbtgt` | DC/DA compromise |
| Machine account | Host compromised |
| API keys/secrets | Readable by attacker |
| Certificates | CA/private key exposure |
| SSH keys | Present on compromised host |
| Session tokens | Any token theft |

### 8.2 Order

```
revoke sessions → reset → verify old creds fail → re-enrol MFA
```

### 8.3 Double reset

For `krbtgt` and highly privileged accounts, reset **twice** with a replication interval between, to invalidate tickets minted with the old key.

---

## 9. Vulnerability remediation

| Root cause | Fix |
|---|---|
| Unpatched software | Patch/upgrade |
| Misconfiguration | Harden + config management |
| Weak MFA | Enforce phishing-resistant MFA |
| Excessive privilege | Least privilege, tiering |
| Flat network | Segmentation |
| Missing detection | Add rule + test |
| Process gap | Change process + owner |
| Vendor risk | Contract/controls |

**Eradication is incomplete until the entry point is closed.**

---

## 10. Evicting an active actor

Sometimes you must eradicate while the attacker is present. Considerations:

| Concern | Approach |
|---|---|
| Attacker watches your comms | Out-of-band channels. |
| Attacker has multiple footholds | Simultaneous removal. |
| Attacker may trigger destructive action | Prepare backups and IR surge. |
| Attacker may re-enter via unknown path | Reset everything at once. |
| Identity unknown | Assume domain-wide. |

### 10.1 Coordinated eviction

```
T-0:  all teams ready, backups verified
T+0:  isolate + disable + reset simultaneously
T+1h: verify, monitor, hunt remnants
T+24h: confirm no re-entry
```

**Partial eviction teaches the attacker which paths still work.**

---

## 11. Verification of eradication

| Check | Method |
|---|---|
| No malware on disk | Hash scan, YARA sweep |
| No malicious process | EDR live response |
| No persistence | Autoruns baseline diff |
| No rogue accounts | AD/cloud audit diff |
| No mailbox rules | Mail audit |
| No C2 traffic | NDR/firewall monitoring |
| Old creds fail | Auth tests |
| No beaconing | Traffic analysis 24–72 h |
| Entry point closed | Patch/config verification |

**Eradication is a claim requiring evidence.**

---

## 12. Monitoring window

| Duration | Rationale |
|---|---|
| 24 h | Catches immediate re-infection |
| 72 h | Catches delayed beacons |
| 7–30 days | Catches dormant persistence/actor return |

### 12.1 What to watch

- Beacon-like periodicity.
- Re-creation of removed accounts/rules.
- Re-appearance of hashes/domains.
- New persistence on cleaned hosts.
- Unusual auth from cleaned identities.

---

## 13. Preventing re-infection

| Control | Effect |
|---|---|
| Patch entry point | Removes path |
| Credential reset | Removes access |
| Remove persistence | Removes restart |
| Segmentation | Limits spread |
| Egress filtering | Blocks C2 |
| Immutable backups | Enables recovery |
| MFA everywhere | Blocks reuse |
| Detection coverage | Catches return |

---

## 14. Documentation

```
What was found (per host/account)
What was removed (with hashes/paths)
What was reset (accounts, keys, certs)
What was patched/changed
Verification performed + results
Residual risk
Monitoring plan
Owner sign-off
```

---

## 15. Pitfalls

| Pitfall | Consequence |
|---|---|
| Removing payload before persistence | Re-infection. |
| Single `krbtgt` reset | Golden ticket still valid. |
| Password reset without session revoke | Token still works. |
| Cleaning a rootkit in place | Hidden persistence. |
| Forgetting mailbox rules | BEC continues. |
| Ignoring cross-account trust | Attacker persists elsewhere. |
| Not patching entry point | Repeat incident. |
| Declaring done without monitoring | Silent return. |
| Restoring data with binaries | Re-introduces malware. |
| Partial eviction | Attacker adapts. |

---

## 16. Playbook: malware with persistence

```
1. Inventory persistence (autoruns, tasks, services, WMI)
2. Preserve evidence
3. Remove persistence entries
4. Suspend → collect → kill process
5. Delete payload (record hash/path)
6. Reset credentials used
7. Patch entry vector
8. Verify (sweep + autoruns diff)
9. Monitor 72 h
10. Sign off
```

---

## 17. Playbook: suspected domain compromise

```
1. Declare critical, engage IR/legal
2. Contain Tier-0 (isolate DCs as needed)
3. Reset krbtgt twice (replication interval)
4. Reset privileged accounts twice
5. Remove rogue accounts/ACLs/SID history
6. Audit delegation, AdminSDHolder, GPO
7. Rebuild compromised DCs
8. Rotate certificates if CA touched
9. Hunt estate-wide for persistence
10. Monitor 30 days
```

---

## 18. Labs

1. Enumerate autoruns on a lab host and baseline-diff.
2. Find WMI persistence with PowerShell.
3. Remove a scheduled task persistence chain.
4. Practise a double `krbtgt` reset in a lab domain.
5. Audit mailbox rules in a test tenant.
6. YARA sweep a sample image.
7. Verify old credentials fail after reset.
8. Build an eradication checklist for a Linux host.
9. Draft a rebuild workflow.
10. Monitor 24 h for beaconing after cleanup.

---

## 19. Verification checklist

- [ ] Persistence inventoried and removed.
- [ ] Payload removed (hashes recorded).
- [ ] Credentials reset (sessions revoked).
- [ ] Rogue accounts/keys/tokens removed.
- [ ] Entry point patched.
- [ ] Estate sweep complete.
- [ ] Verification tests passed.
- [ ] Monitoring window active.
- [ ] Documentation complete.
- [ ] Owner sign-off.

---

## 20. Self-test questions

1. What does eradication include beyond removing malware?
2. Rebuild vs clean — when each?
3. Why remove persistence before payload?
4. Name eight Windows persistence mechanisms.
5. Name five Linux mechanisms.
6. What is a Golden Ticket and how do you invalidate it?
7. Why reset `krbtgt` twice?
8. Why revoke sessions before resetting a password?
9. What is partial eviction and why is it dangerous?
10. How do you verify eradication?
11. How long do you monitor and why?
12. What must you never restore from a compromised host?
13. What cross-account risk exists in cloud?
14. What is the relationship between eradication and root cause?
15. When is a host not cleanable?

---

## 21. One-page revision checklist

- [ ] Eradication = malware + persistence + credentials + access path + accounts + config.
- [ ] Rebuild vs clean matrix; rebuild for admin/Tier-0/ransomware/uncertainty.
- [ ] Prerequisites incl. evidence and recovery path.
- [ ] Persistence inventories: Windows, Linux, AD, cloud, email.
- [ ] Removal order: persistence → payload → processes → config → creds → patch → verify.
- [ ] AD cleanup: double krbtgt, privileged resets, ACLs, SID history, delegation, rebuild DCs.
- [ ] Cloud cleanup incl. cross-account trust and OAuth.
- [ ] Credential reset table + revoke-then-reset order + double reset.
- [ ] Vulnerability remediation closes the entry point.
- [ ] Coordinated eviction when actor is active.
- [ ] Verification evidence list.
- [ ] Monitoring windows 24h/72h/7–30d.
- [ ] Re-infection controls.
- [ ] Documentation fields.
- [ ] Pitfalls memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Containment](Containment.md) · [Identification →](Identification.md)
