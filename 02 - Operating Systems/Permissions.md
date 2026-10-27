# Permissions — SOC Analyst Study Notes

> Goal: understand how Linux, Windows, macOS, and cloud permissions actually work, so you can **spot privilege-escalation paths, over-permissioned accounts, exposed shares, and ACL abuse**, and explain them in an incident.
> File-system internals → `File-Systems.md`; Linux host → `Linux.md`; Windows host → `Windows.md`; Active Directory ACL abuse → the AD skill.

---

## 0. How to use this note

1. §1–§2: why permissions matter and the universal model.
2. §3–§5: Linux, Windows, macOS permissions.
3. §6–§7: cloud/IAM and common misconfigurations.
4. §8–§11: telemetry, detections, investigation, triage.
5. §12–§14: commands, false positives, hardening.
6. §15–§17: labs, self-test, revision.

---

## 1. Why permissions matter to a SOC analyst

- Nearly every privilege-escalation finding is a **permission bug**: writable service binary, SUID binary, weak sudo rule, over-broad role, mis-scoped ACL.
- Permissions decide **blast radius** after initial access: what data can be read, what can be modified, where lateral movement is possible.
- Permission changes are **high-signal telemetry**: a new admin, a changed ACL, a new service account, a role assignment.
- Over-permissioned **service accounts, CI runners, and cloud roles** are frequent root causes of large breaches.
- Permissions are where **policy meets reality** — the gap is what attackers exploit.

**SOC outcomes:** given an access event you can answer:
- Who is the principal (user/group/service/role)?
- What resource and what operation?
- Was it allowed, denied, or changed?
- Is that expected for the role? Least privilege?
- Does it enable escalation or data access?
- What should be reviewed, revoked, or contained?

---

## 2. The universal access-control model

Every modern system answers four questions:

1. **Who** is asking? (identity: user, group, service principal, role, token)
2. **What** are they asking for? (resource + operation)
3. **Under what context**? (session, device, network, time, MFA, integrity level)
4. **What does policy say?** (allow/deny rules, inheritance, explicit vs implicit)

| Concept | Meaning |
|---|---|
| **Principal** | Identity requesting access (SID, UID, role ARN, service account). |
| **Resource** | File, folder, share, registry key, service, API, bucket, record. |
| **Permission/right** | Read, write, execute, delete, change-permissions, take-ownership, admin. |
| **Policy/ACL** | Rules mapping principals → permissions on resources. |
| **Inheritance** | Child objects inherit parent rules (can be broken/overridden). |
| **Explicit deny** | Usually overrides allow (Windows DACL, some cloud policies). |
| **Effective access** | The result after groups, inheritance, denies, and conditions. |
| **Least privilege** | Only the access required, only when required. |

**Evaluation mindset:** attackers don't need "admin" — they need **one path** from their current principal to a more powerful one. Look for **transitive** permissions (group membership, role chains, delegation, impersonation).

---

## 3. Linux permissions

### 3.1 Mode bits

`-rwxr-xr--  1 alice dev  4096 Oct 27 12:00 file.sh`

| Position | Meaning |
|---|---|
| `-` / `d` / `l` | file / directory / symlink |
| `rwx` (owner) | read/write/execute for owner |
| `r-x` (group) | read/execute for group |
| `r--` (other) | read for others |

Octal: `r=4, w=2, x=1` → `755` = `rwxr-xr-x`, `644` = `rw-r--r--`, `600` = `rw-------`, `777` = everyone everything.

**Directory semantics differ:** `r` = list names, `w` = create/delete entries, `x` = traverse/enter. A directory with `wx` but no `r` lets you access known paths without listing.

### 3.2 Ownership and umask

- `chown user:group file`, `chgrp group file`.
- `umask` controls default permissions for new files/dirs (e.g. `022` → files `644`, dirs `755`; `077` → private).
- **Sticky bit** on directories (`+t`, e.g. `/tmp`) — only owner can delete their files.
- **Setgid** on directories — new files inherit the directory's group.
- **Setuid** on executables — runs with the file owner's UID (root setuid = privilege escalation target).

### 3.3 Special bits

| Bit | Symbol | Effect | Risk |
|---|---|---|---|
| **SUID** | `s` in owner execute | Run as file owner | Root SUID binaries → privesc (GTFOBins). |
| **SGID** | `s` in group execute | Run with file group; dir inheritance | Group privilege abuse. |
| **Sticky** | `t` in other execute | Only owner deletes in dir | Protects shared dirs. |

Find them:

```bash
find / -xdev -perm -4000 -type f 2>/dev/null   # SUID
find / -xdev -perm -2000 -type f 2>/dev/null   # SGID
find / -xdev -perm -1000 -type d 2>/dev/null   # sticky
```

### 3.4 POSIX ACLs

```bash
getfacl file
setfacl -m u:bob:rw file
setfacl -m g:dev:r file
setfacl -x u:bob file
setfacl -b file                  # remove all ACLs
```

ACLs add named users/groups beyond owner/group/other. Check for **unexpected ACL grants** on sensitive files — `+` in `ls -l` indicates an ACL.

### 3.5 Extended attributes, capabilities, and MAC

- **xattr** — `getfattr -d file`, `setfattr`; `security.selinux`, `security.capability`, `user.*`.
- **Capabilities** — split root privileges: `cap_setuid`, `cap_setgid`, `cap_net_raw`, `cap_sys_admin`, `cap_dac_read_search`.

```bash
getcap -r / 2>/dev/null
setcap cap_net_raw+ep /usr/bin/ping
```

Unusual capabilities on user-writable binaries = privesc.

- **SELinux** — labels/contexts (`ls -Z`, `ps -Z`), enforcing/permissive; `semanage`, `restorecon`.
- **AppArmor** — profiles in `/etc/apparmor.d/`; `aa-status`.
- **chattr** — immutable (`+i`) and append-only (`+a`) attributes; attackers use them to protect payloads.

### 3.6 File-mode risk patterns

| Pattern | Risk |
|---|---|
| World-writable files in `/etc` | Direct tampering. |
| World-writable scripts run by root (cron/systemd) | Privesc. |
| SUID on custom/user-writable binary | Privesc. |
| Sudo NOPASSWD on shell-capable binary | Privesc (GTFOBins). |
| `PATH` includes `.` or writable dirs for root scripts | Hijack. |
| Writable `/etc/passwd` or `/etc/shadow` | Direct root. |
| Group membership in `docker`/`lxd`/`disk`/`shadow` | Root-equivalent. |

### 3.7 Sudo and PAM

- `/etc/sudoers` (edit with `visudo`) and `/etc/sudoers.d/*`.
- `sudo -l` shows your rights; look for `NOPASSWD`, wildcards, `ALL`, and shell-spawning binaries.
- `Defaults env_keep += LD_PRELOAD` is dangerous.
- PAM stack (`/etc/pam.d/`) controls auth; modifications are backdoors.

---

## 4. Windows permissions

### 4.1 The security model

- **SID** (Security Identifier) — unique principal ID; well-known SIDs (`S-1-5-18` SYSTEM, `S-1-5-19` LOCAL SERVICE, `S-1-5-20` NETWORK SERVICE, `S-1-5-32-544` Administrators, `S-1-5-32-545` Users).
- **Access token** — created at logon; contains user SID, group SIDs, privileges, integrity level, logon session.
- **Security descriptor** — owner, group, **DACL** (who is allowed/denied what), **SACL** (auditing).
- **ACE** (Access Control Entry) — one rule: principal + access mask + allow/deny + inheritance flags.
- **Access mask** — `Read`, `Write`, `Execute`, `Delete`, `ChangePermissions`, `TakeOwnership`, `FullControl`.
- **Inheritance** — explicit vs inherited ACEs; `(OI)(CI)` object/container inherit.
- **Integrity levels** — Low/Medium/High/System; UAC relates but is not the same.
- **Privileges** — rights assigned to accounts/tokens (e.g. `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeTcbPrivilege`).

### 4.2 DACL evaluation

1. If no DACL → full access.
2. Explicit **Deny** ACEs are evaluated before Allow.
3. Allow ACEs accumulate across the token's SIDs (user + groups).
4. Inheritance adds parent ACEs unless disabled.
5. If nothing allows → access denied.

> **Effective access** is what matters; `icacls` output alone may not show group-derived or inherited rights. Use `AccessChk` (`-e`) or PowerShell to compute.

### 4.3 Common Windows permission targets

| Target | Tool | Notes |
|---|---|---|
| Files/folders | `icacls`, `Get-Acl`, `Set-Acl` | Watch `Everyone`, `Users`, `Authenticated Users` with write. |
| Shares | `Get-SmbShare`, `Get-SmbShareAccess` | Share + NTFS both apply (most restrictive wins). |
| Registry keys | `reg`, `Get-Acl` | Autoruns, services, policies. |
| Services | `sc sdshow`, `sc sdset`, `AccessChk` | Weak service ACLs = privesc. |
| Scheduled tasks | `schtasks`, `Get-ScheduledTask`, `Get-Acl` | Writable task = code execution. |
| AD objects | `dsacls`, AD tools | GenericAll/WriteDACL/WriteOwner abuse (see AD skill). |
| WMI | `Get-CimInstance`, ACL tools | Event subscription persistence. |

### 4.4 Share vs NTFS permissions

- **Share permissions** apply only over the network; **NTFS** applies locally and over the network.
- Effective network access = **most restrictive** of share and NTFS.
- `Everyone`/`Authenticated Users` full share + permissive NTFS = data exposure.
- **Administrative shares** (`C$`, `ADMIN$`, `IPC$`) accessible to admins; abuse is lateral movement.

### 4.5 UAC and tokens

- **UAC** gates elevation; admin users run with a filtered (medium) token until elevated.
- **Auto-elevation**, `fodhelper`/`computerdefaults` style bypasses, and `AlwaysNotify` settings matter.
- **UAC is not a security boundary** (Microsoft's stance) — treat admin accounts as powerful regardless.
- **Protected Users** group, **LSA protection** (RunAsPPL), **Credential Guard** harden credential theft.

### 4.6 Service and task permissions

- A service binary or its directory writable by a non-admin → **replace binary → SYSTEM execution**.
- **Unquoted service path** with spaces → path hijack.
- Writable service **config** (`sc config`) → change binary path.
- Writable scheduled task file/action → code execution.

### 4.7 Integrity, AppLocker, WDAC

- **AppLocker/WDAC** restrict what can execute; bypasses (LOLBins, signed binaries) are common.
- **SACL auditing** enables 4663/4656 object access; without it you have no file-level audit.

---

## 5. macOS permissions (brief)

- **POSIX** mode bits + **ACLs** (`ls -le`, `chmod +a`).
- **SIP (System Integrity Protection)** protects system paths; disabling it is a red flag.
- **TCC (Transparency, Consent, Control)** — per-app access to files, camera, mic, screen; TCC.db is a key artifact.
- **Entitlements** — signed capabilities (e.g. `com.apple.security.cs.disable-library-validation`).
- **Quarantine xattr** — `com.apple.quarantine` on downloaded files.
- **launchd** — services/agents (`/Library/LaunchDaemons`, `~/Library/LaunchAgents`) = persistence.
- **Keychain** — credential storage.

---

## 6. Cloud and IAM permissions (concepts)

| Cloud | Identity | Policy model | Key risks |
|---|---|---|---|
| **AWS** | IAM user/role, STS | JSON policies (identity/resource), SCPs, permission boundaries | `*:*`, `iam:PassRole`, `sts:AssumeRole` chains, public buckets. |
| **Azure** | Entra ID user/app/managed identity | RBAC roles + assignments, conditional access | Owner/Contributor at subscription, app secrets, guest access. |
| **GCP** | Google account/service account | IAM roles (basic/predefined/custom), org policies | `roles/owner`, `iam.serviceAccounts.actAs`, public buckets. |
| **Kubernetes** | User/SA + RBAC | Roles/ClusterRoles + bindings | `cluster-admin`, wildcard verbs, SA token abuse. |

**Principles:** least privilege, separation of duties, short-lived credentials, no long-lived keys, permission boundaries/SCPs, regular access reviews.

**Detection:** CloudTrail/Activity Log/Audit Logs for `AttachRolePolicy`, `CreateAccessKey`, `SetIamPolicy`, `AddMember`, role assignments, public bucket ACL changes, and new identity providers.

---

## 7. Common misconfigurations and attack paths

| # | Misconfiguration | Escalation |
|---|---|---|
| 1 | World-writable config/script run by root/SYSTEM | Replace content → elevated execution. |
| 2 | SUID root binary (custom or GTFOBin) | Execute as root. |
| 3 | Sudo NOPASSWD on shell/editor/find/awk | Spawn root shell. |
| 4 | Writable service binary/path (Windows) | Replace → SYSTEM. |
| 5 | Unquoted service path | Plant binary in earlier path. |
| 6 | Weak service ACL | Reconfigure service. |
| 7 | Writable scheduled task/cron | Code execution as task owner. |
| 8 | Weak registry key ACL (autorun/service) | Persistence/privesc. |
| 9 | Over-broad group membership (`docker`, `lxd`, `disk`, `shadow`, `Administrators`, `Backup Operators`) | Root/SYSTEM equivalent. |
| 10 | Permissive share (`Everyone` write) | Data tampering/lateral. |
| 11 | `SeImpersonatePrivilege` on service account | Potato-style SYSTEM escalation. |
| 12 | `SeBackupPrivilege` / `SeRestorePrivilege` | Read/copy protected files (SAM/NTDS). |
| 13 | Weak AD ACL (GenericAll, WriteDACL, WriteOwner, ForceChangePassword) | Domain escalation (AD skill). |
| 14 | Over-privileged cloud role (`*:*`, Owner) | Full account takeover. |
| 15 | Long-lived cloud keys / app secrets | Persistent access. |
| 16 | Public bucket/container | Data exposure. |
| 17 | Unquoted/Writable PATH | Hijack root/admin process. |
| 18 | Misconfigured sudo `env_keep=LD_PRELOAD` | Library injection as root. |
| 19 | Weak file/dir permissions on SSH keys, `.env`, configs | Credential theft. |
| 20 | Default/unchanged permissions on backups, DB dumps | Data exposure. |

> **Escalation is a chain.** A writable file only matters if something privileged reads/executes it; a group membership only matters if the group has rights.

---

## 8. Telemetry for permission events

| Source | What it records |
|---|---|
| **Linux auditd** | `chmod`, `chown`, `setxattr`, `setfacl`, `execve`, `open` on watched paths. |
| **Linux auth logs** | `sudo`, `su`, PAM, user/group changes. |
| **Sysmon for Linux** | Process/file events. |
| **Windows Security 4663** | Object access (needs SACL). |
| **Windows Security 4656** | Handle request (object access). |
| **Windows Security 4670** | Permissions on an object changed. |
| **Windows Security 4703/4704** | Token/privilege adjustment. |
| **Windows Security 4720–4738** | Account/group changes. |
| **Windows Security 4719** | Audit policy change. |
| **Windows Security 4907** | Auditing settings on object changed. |
| **Windows Security 5140/5145** | Share access. |
| **Windows Security 4688** | Process creation (command line if enabled). |
| **Windows 7045** | New service installed (System log). |
| **EDR** | File/registry/service/process changes with actor. |
| **FIM** | File permission/integrity changes. |
| **Cloud audit** | IAM/policy/ACL changes (CloudTrail, Activity Log, GCP Audit). |
| **Kubernetes audit** | RBAC/role binding changes. |

**Prerequisite:** object access auditing (SACL) and command-line auditing must be enabled — otherwise you cannot see 4663/4688 details.

---

## 9. Detection engineering

### 9.1 High-signal ideas

1. **World-writable sensitive paths** or permission loosening (`777`, `Everyone:Full`).
2. **SUID/SGID created or modified**.
3. **Capabilities added** to binaries.
4. **Sudoers changed** or NOPASSWD added.
5. **New admin/privileged group membership**.
6. **New account** or UID/SID 0/500-equivalent.
7. **Service binary/permission changed** (Windows 7045 + file writes).
8. **Scheduled task/cron created** by unusual user.
9. **Registry autorun ACL changed**.
10. **Share permission loosened** or new `Everyone` access.
11. **Sensitive file ACL changed** (SAM, NTDS, keys, configs).
12. **Privilege assigned** (`SeDebug`, `SeImpersonate`, `SeBackup`) unexpectedly.
13. **Cloud role/policy attached** to a principal (especially admin).
14. **Access key created** or long-lived secret minted.
15. **Public bucket/ACL change**.
16. **Kubernetes role binding** to `cluster-admin` or wildcard.
17. **Bulk permission changes** (mass ACL rewrite — possible ransomware prep).
18. **Ownership takeover** (`takeown`, `SetOwner`).
19. **Failed access spikes** (401/403, 4625, EACCES) — probing.
20. **Access to sensitive resources by service accounts** outside baseline.

### 9.2 Splunk SPL examples

**Linux permission changes on sensitive paths (auditd):**
```spl
index=linux sourcetype=linux:audit
| search "chmod" OR "chown" OR "setfacl" OR "setxattr"
| where match(_raw, "(?i)(/etc/(passwd|shadow|sudoers|ssh)|/root/|/var/spool/cron|/etc/systemd)")
| table _time, host, user, _raw
```

**Sudoers change:**
```spl
index=linux (sourcetype=linux:audit OR sourcetype=linux_secure)
| where match(_raw, "(?i)(/etc/sudoers|visudo|NOPASSWD)")
| table _time, host, user, _raw
```

**SUID/capability change:**
```spl
index=linux sourcetype=linux:audit
| where match(_raw, "(?i)(chmod .*[46][0-7][0-7][0-7]|setcap|setuid|setgid)")
| table _time, host, user, _raw
```

**New privileged group membership:**
```spl
index=linux (sourcetype=linux:audit OR sourcetype=linux_secure)
| where match(_raw, "(?i)(usermod .*-aG?.*(sudo|wheel|docker|lxd|disk|shadow)|gpasswd .*(sudo|wheel|docker))")
| table _time, host, user, _raw
```

**Windows object permission change (4670):**
```spl
index=wineventlog EventCode=4670
| table _time, ComputerName, SubjectUserName, ObjectName, ObjectType, AccessList, ProcessName
```

**Windows privilege/account changes:**
```spl
index=wineventlog EventCode IN (4720,4722,4724,4728,4732,4738,4756,4672)
| stats count values(EventCode) as events by SubjectUserName, TargetUserName, ComputerName
| sort -count
```

**Service installed (7045):**
```spl
index=wineventlog EventCode=7045
| table _time, ComputerName, ServiceName, ImagePath, ServiceType, StartType, AccountName
```

**Share permission change:**
```spl
index=wineventlog EventCode IN (5140,5145)
| stats count by SubjectUserName, ShareName, RelativeTargetName, ComputerName
| sort -count
```

**Cloud role/policy change (AWS CloudTrail example):**
```spl
index=aws sourcetype=aws:cloudtrail
| where eventName IN ("AttachRolePolicy","PutRolePolicy","CreateAccessKey","CreatePolicyVersion","SetIamPolicy","AddMember")
| table _time, userIdentity.arn, eventName, requestParameters, sourceIPAddress
```

### 9.3 Microsoft Sentinel / Defender KQL examples

**New local admin group member (SecurityEvent):**
```kusto
SecurityEvent
| where EventID == 4732
| where TargetUserName has "Administrators" or GroupName has "Administrators"
| project TimeGenerated, Computer, SubjectAccount, MemberName, GroupName
```

**Explicit logon / privilege use:**
```kusto
SecurityEvent
| where EventID in (4672, 4673, 4674)
| summarize Count = count() by Account, Activity, Computer, bin(TimeGenerated, 1h)
| where Count > 10
```

**File ACL change (4663 with ChangePermissions):**
```kusto
SecurityEvent
| where EventID == 4663
| where AccessList has "ChangePermissions" or AccessList has "WRITE_DAC"
| project TimeGenerated, Computer, SubjectAccount, ObjectName, ProcessName, AccessList
```

**Cloud role assignment (Azure Activity):**
```kusto
AzureActivity
| where OperationNameValue has "roleAssignments/write"
| project TimeGenerated, Caller, OperationNameValue, Resource, Properties
```

**New access key (AWS CloudTrail via connector):**
```kusto
AWSCloudTrail
| where EventName == "CreateAccessKey"
| project TimeGenerated, UserIdentityArn, EventName, SourceIpAddress
```

**Kubernetes RBAC binding:**
```kusto
KubeAuditLogs
| where Verb in ("create","update","patch")
| where ObjectRefResource has "rolebindings" or ObjectRefResource has "clusterrolebindings"
| project TimeGenerated, User, ObjectRefName, RequestURI, ResponseStatus
```

### 9.4 Sigma-style skeleton

```yaml
title: Linux SUID Bit Set on Binary
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: SYSCALL
    syscall: chmod
  filter_known:
    exe|startswith:
      - /usr/bin/
      - /bin/
  condition: selection and not filter_known
level: high
```

---

## 10. Investigation workflow (step by step)

### Step 1 — Facts
- Time (UTC), principal, resource, operation, result, source host/IP.
- Which detection fired.

### Step 2 — Identify the principal
- Linux: UID/GID, groups, sudo rights, capabilities.
- Windows: SID, groups, token privileges, integrity level, logon session.
- Cloud: role/ARN/app, policy attachments, conditions.
- Is it a human, service, machine, or automation identity?

### Step 3 — Determine effective access
- Direct + inherited + group-derived + conditional.
- Explicit denies, boundaries, SCPs.
- Is the access expected for the role?

### Step 4 — Check the change
- Who changed what, when, from where, and was it approved?
- Change ticket / maintenance window / automation identity.

### Step 5 — Assess escalation potential
- Does this grant a path to root/SYSTEM/admin/owner?
- Combine with writable files, services, tasks, or credentials.

### Step 6 — Scope
- Same change/principal across hosts/accounts/cloud.
- Other resources affected.
- Data exposure.

### Step 7 — Respond
- Revert unauthorized changes.
- Revoke access, rotate credentials/keys, remove persistence.
- Isolate if compromise suspected.
- Preserve evidence.

### Step 8 — Document
Timeline, principals, policy diff, effective access, impact, actions, recommendations.

---

## 11. Triage playbooks

### A. "Permission change on sensitive file"
1. What changed, by whom, from where?
2. Was it approved (change ticket/automation)?
3. Does it expose credentials or allow execution?
4. Revert; check for follow-on access; rotate secrets if exposed.

### B. "New admin / privileged group member"
1. Verify with the requester/HR/change record.
2. Check the account's creation time, source, and other changes.
3. If unauthorized → remove, reset credentials, hunt for actions taken.
4. Review group nesting and indirect rights.

### C. "SUID / capability / sudoers change"
1. Identify the binary/rule and who changed it.
2. Test whether it grants root (GTFOBins logic) — in a lab, not production.
3. If malicious → remove, hunt persistence, rebuild if rootkit risk.

### D. "Weak service/task permissions (Windows)"
1. Confirm writable path/binary/config.
2. Check who can write and whether the service runs as SYSTEM.
3. Treat as privesc: patch ACLs, rebuild if exploited.
4. Hunt for replaced binaries and new services.

### E. "Over-permissioned cloud role/key"
1. Enumerate permissions and blast radius.
2. Check usage (CloudTrail/Audit) for abuse.
3. Right-size policy, rotate keys, revoke sessions.
4. Review all principals with similar access.

### F. "Share exposure"
1. Identify share, permissions, and data classification.
2. Who accessed it? Any external/anonymous access?
3. Restrict permissions, audit access, notify data owners.

### G. "Mass ACL/permission changes"
1. Identify the actor and tooling.
2. Distinguish migration/automation from ransomware prep.
3. Halt, preserve, and assess integrity of security controls.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| World-writable non-sensitive file | Low–Medium |
| Writable service binary/SUID on sensitive host | High |
| New admin membership (unapproved) | High |
| Sudoers/NOPASSWD escalation path | High |
| Cloud Owner/`*:*` assignment | High–Critical |
| Public bucket with sensitive data | Critical |
| Confirmed privesc exploitation | Critical |
| Bulk permission changes | High |

---

## 12. Commands

### Linux

```bash
# Mode bits / ownership / ACLs
ls -l
stat file
chmod 750 file
chown user:group file
getfacl file
setfacl -m u:bob:rw file
getfattr -d file
getcap -r / 2>/dev/null

# Find risky permissions
find / -xdev -perm -4000 -type f 2>/dev/null
find / -xdev -perm -2000 -type f 2>/dev/null
find / -xdev -perm -0002 -type f 2>/dev/null      # world-writable files
find / -xdev -perm -0002 -type d 2>/dev/null      # world-writable dirs
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# Sudo / identity
sudo -l
id
getent group sudo wheel docker lxd disk shadow
grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# MAC
getenforce; sestatus; ls -Z
aa-status
lsattr file

# Audit
ausearch -m SYSCALL -ts today
ausearch -k perm_change
```

### Windows

```powershell
# ACLs
Get-Acl C:\Path | Format-List
icacls C:\Path
icacls C:\Path /grant "DOMAIN\user:(OI)(CI)M"
icacls C:\Path /remove "DOMAIN\user"
Get-Acl HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Shares
Get-SmbShare
Get-SmbShareAccess -Name Share
Grant-SmbShareAccess -Name Share -AccountName user -AccessRight Read

# Services / tasks
sc sdshow MyService
sc qc MyService
Get-ScheduledTask | Get-ScheduledTaskInfo
Get-ScheduledTask -TaskName X | Get-Acl

# Identity / privileges
whoami /all
whoami /priv
whoami /groups
Get-LocalGroupMember -Group Administrators
Get-LocalUser

# Effective access (Sysinternals)
AccessChk.exe -accepteula -uwcqv "Everyone" *
AccessChk.exe -accepteula -uwdqs "Users" C:\Path

# Audit policy
auditpol /get /category:*
auditpol /set /category:"Object Access" /success:enable /failure:enable
```

### macOS

```bash
ls -le
chmod +a "user allow read" file
ls -l@
xattr -l file
csrutil status
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db 'select * from access;'
```

### Cloud

```bash
# AWS
aws iam list-attached-role-policies --role-name ROLE
aws iam get-policy-version --policy-arn ARN --version-id v1
aws s3api get-bucket-acl --bucket BUCKET
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy

# Azure
az role assignment list --all
az role definition list --name Owner
az storage container show-permissions --name C --account-name A

# GCP
gcloud projects get-iam-policy PROJECT
gcloud storage buckets get-iam-policy gs://BUCKET
```

> Use read-only commands during investigations; changes require authorisation and change control.

---

## 13. Common false positives

| Alert | Often actually |
|---|---|
| Permission changes | Package installs, config management, migrations, admin fixes. |
| New admin | Onboarding, role change, break-glass, approved automation. |
| SUID changes | Package updates, vendor installers, admin tooling. |
| Sudo usage | Legitimate administration/automation. |
| Cloud role changes | IaC (Terraform/CloudFormation), CI/CD, approved access reviews. |
| Access key creation | Application deployment, rotation. |
| Shared folder access | Business workflow, backup, indexing. |
| Mass ACL changes | Migration, DR, storage restructuring. |
| Capability/tool hits | Custom binaries, legitimate privileged utilities. |
| Failed access spikes | Misconfigured app, expired credentials, scanner. |

**Rule of thumb:** confirm **change provenance** (ticket, automation identity, timestamp) before escalating. Most permission alerts are misconfigured automation.

---

## 14. Hardening and recommendations

- **Least privilege everywhere**; role-based access with periodic reviews.
- **Remove standing admin**; use just-in-time elevation (PAM, `sudo` with approval, Entra PIM).
- **Linux:** `077` umask for sensitive dirs, no world-writable paths, audit SUID/caps, restrict sudo, SELinux/AppArmor enforcing, protect `/etc/passwd|shadow|sudoers`, disable unused accounts.
- **Windows:** tiered admin model, Protected Users, LSA protection, Credential Guard, no shared admin accounts, restrict `SeImpersonate`/`SeDebug`/`SeBackup`, AppLocker/WDAC, LAPS for local admin, patch ACL misconfigs, disable SMBv1, restrict admin shares.
- **Services/tasks:** install to non-writable paths, quote paths, restrict ACLs, use gMSA, audit changes.
- **Shares:** least privilege, remove `Everyone`, enable access-based enumeration, audit access, SMB signing/encryption.
- **Cloud:** permission boundaries/SCPs, no long-lived keys, rotate secrets, block public buckets, review role assignments, enable audit logs, alert on IAM changes.
- **Kubernetes:** RBAC least privilege, no wildcard verbs, disable automount SA tokens, admission policies (OPA/Kyverno), Pod Security Standards.
- **Logging:** SACL/object auditing, command-line auditing, auditd rules, cloud trail, retention, centralisation.
- **FIM/EDR** on permission metadata and privileged paths.
- **Access reviews** quarterly for privileged roles and service accounts.
- **Break-glass** accounts documented, monitored, rotated.

---

## 15. Lab practice plan

1. Create Linux users/groups; practice `chmod`, `chown`, ACLs, capabilities, SUID; find risky permissions.
2. Write a root cron job reading a world-writable script; demonstrate and fix the privesc.
3. Configure sudo NOPASSWD on a GTFOBin; demonstrate and remediate.
4. Set up auditd rules for `chmod`/`setfacl`/`sudoers`; generate and query events.
5. On Windows, create a service in a writable directory; demonstrate replacement; fix ACL.
6. Configure SACL/4663 on a file; change permissions; observe events.
7. Create an over-privileged AWS IAM role in a sandbox; inspect with `iam` CLI; right-size.
8. Set a public S3 bucket in a sandbox; detect via config/CloudTrail.
9. Build a Kubernetes RoleBinding to `cluster-admin`; detect with audit logs.
10. Write an incident report from §10/§11 with policy diffs and evidence.

---

## 16. Self-test questions

1. What do `r`, `w`, `x` mean on a directory vs a file?
2. What is the difference between SUID, SGID, and the sticky bit?
3. How do POSIX ACLs differ from mode bits?
4. What are Linux capabilities, and why are they safer than SUID root?
5. What is the difference between DACL and SACL?
6. How does Windows evaluate an access request with allow/deny ACEs?
7. What is the difference between share and NTFS permissions?
8. What does `SeImpersonatePrivilege` enable?
9. Why is a writable service binary a privilege escalation?
10. What is an unquoted service path attack?
11. What is the difference between `icacls` and effective access?
12. Which AWS permissions are especially dangerous, and why?
13. What does `cluster-admin` allow in Kubernetes?
14. Which event IDs show object access and permission changes on Windows?
15. How would you investigate an unexpected new local administrator?

---

## 17. One-page revision checklist

- [ ] Universal model: principal, resource, permission, ACL, inheritance, explicit deny, effective access, least privilege.
- [ ] Linux: mode bits/octal, umask, ownership, SUID/SGID/sticky, ACLs, xattr, capabilities, SELinux/AppArmor, chattr, sudo/PAM.
- [ ] Linux risky patterns: world-writable, SUID, sudo NOPASSWD, PATH, writable passwd/shadow, docker/lxd/disk/shadow groups.
- [ ] Windows: SID, token, security descriptor, DACL/SACL, ACE, access mask, inheritance, integrity levels, privileges (SeDebug/SeImpersonate/SeBackup/SeRestore/SeTakeOwnership/SeLoadDriver).
- [ ] Windows targets: files, shares, registry, services, tasks, AD objects, WMI.
- [ ] Share vs NTFS; UAC/token filtering; AppLocker/WDAC.
- [ ] macOS: POSIX+ACL, SIP, TCC, entitlements, quarantine, launchd, Keychain.
- [ ] Cloud IAM: AWS policies/roles/SCPs, Azure RBAC, GCP roles, Kubernetes RBAC; dangerous permissions.
- [ ] Misconfigurations: writable scripts/binaries/configs, SUID, sudo, unquoted paths, weak service ACLs, group membership, share exposure, over-broad roles, long-lived keys, public buckets.
- [ ] Telemetry: auditd, auth logs, 4663/4656/4670/4907, 4688, 4720–4738, 7045, 5140/5145, EDR, FIM, cloud audit, K8s audit.
- [ ] Detections: permission loosening, SUID/caps, sudoers, admin membership, new accounts, service/task changes, share changes, privilege assignment, cloud role/key changes, public buckets, RBAC bindings, mass ACL changes, ownership takeover, failed access spikes, sensitive access by services.
- [ ] Investigation: facts → principal → effective access → change provenance → escalation potential → scope → respond → document.
- [ ] Triage: sensitive permission change, new admin, SUID/sudoers, weak service/task, over-privileged cloud, share exposure, mass ACL changes.
- [ ] Commands: `chmod/chown/getfacl/setfacl/getcap/find -perm/sudo -l/getenforce/ausearch`, `icacls/Get-Acl/AccessChk/sc sdshow/Get-SmbShare/whoami /priv/auditpol`, `ls -le/csrutil/TCC`, cloud CLIs.
- [ ] Hardening: least privilege/JIT, Linux tightening, Windows tiering/protections, service/task ACLs, share least privilege, cloud boundaries/rotation/no public, K8s RBAC/PSS, auditing/FIM, access reviews, break-glass.
