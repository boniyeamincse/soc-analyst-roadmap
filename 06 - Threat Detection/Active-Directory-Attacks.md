# Active Directory Attacks — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Credential Attacks](Credential-Attacks.md) · [Lateral Movement →](Lateral-Movement.md)

> Goal: Master the detection, triage, and investigation of Active Directory (AD) and identity-based attacks — the primary attack surface of enterprise Windows environments.
> Related notes: [Credential-Attacks.md](Credential-Attacks.md); [Lateral-Movement.md](Lateral-Movement.md); [02 - Operating Systems/Windows-Event-Logs.md](../02%20-%20Operating%20Systems/Windows-Event-Logs.md); [03 - Cybersecurity Fundamentals/Authentication.md](../03%20-%20Cybersecurity%20Fundamentals/Authentication.md).

---

## 0. How to use this note

1. §1–§2: The AD attack lifecycle and core architecture (Domains, Forests, Trusts, DCs, KDC, LDAP).
2. §3–§6: Reconnaissance (BloodHound/SharpHound), Kerberos attacks (Kerberoasting, AS-REP Roasting, Golden/Silver tickets), and DCSync.
3. §7–§8: AD Certificate Services (AD CS) abuse and Persistence (GPO, AdminSDHolder, ACL backdoors).
4. §9–§11: Essential Windows Event IDs, SIEM detection queries (SPL, KQL, Sigma), and triage workflows.
5. §12–§14: Enterprise hardening, hands-on lab exercises, self-test questions, and revision checklist.

---

## 1. The Active Directory attack lifecycle

```
Initial Foothold (Workstation compromised)
   ↓
AD Reconnaissance (BloodHound, SharpHound, PowerView, AD PowerShell)
   ├── Enumerate users, groups, computer objects, Domain Admins
   └── Map attack paths (unconstrained delegation, misconfigured ACLs, Kerberoasting targets)
   ↓
Credential Access & Privilege Escalation
   ├── AS-REP Roasting (pre-authentication disabled)
   ├── Kerberoasting (Service Principal Names with weak passwords)
   ├── AD CS ESC1–ESC8 (misconfigured certificate templates)
   └── NTLM Relay & Coercion (PetitPotam, PrinterBug, ShadowCoerce)
   ↓
Lateral Movement & Domain Dominance
   ├── Overpass-the-Hash / Pass-the-Ticket (PtT)
   ├── DCSync (Directory Service Replication abuse - DsGetNCChanges)
   └── Golden Ticket / Silver Ticket creation
   ↓
Persistence & Control
   └── GPO abuse, AdminSDHolder modification, DSRM password sync, Skeleton Key
```

---

## 2. Core AD architecture & mechanics for defenders

| Component | Role in AD | Security Significance |
|---|---|---|
| **Domain Controller (DC)** | Hosts Active Directory Database (`ntds.dit`), authenticates users, enforces policy. | The crown jewel. Compromise of a DC is total domain compromise. |
| **KDC (Key Distribution Center)** | Kerberos service running on DCs (handles AS-REQ/REP and TGS-REQ/REP). | Issues TGTs and service tickets; logs event IDs 4768, 4769, 4771. |
| **Global Catalog (GC)** | Distributed data repository containing a searchable subset of all objects in the forest. | Used for forest-wide queries and Universal Group membership checks. |
| **LDAP / LDAPS** | Lightweight Directory Access Protocol (ports 389 / 636). | Protocol used by attackers to query users, computers, permissions, and SPNs. |
| **NTDS.dit** | The database file containing all Active Directory objects and password hashes. | Attackers attempt to extract this via VSS, `ntdsutil`, or DCSync. |
| **`krbtgt` Account** | Built-in service account whose password hash encrypts all Ticket Granting Tickets (TGTs). | Stolen `krbtgt` hash enables the forging of Golden Tickets. |

---

## 3. AD Reconnaissance & BloodHound detection

Attackers rarely attack blindly; they map graph-based shortest paths to Domain Admin using tools like **BloodHound / SharpHound** and **PowerView**.

### 3.1 SharpHound telemetry & footprints
SharpHound queries LDAP, SMB, and RPC across hundreds of endpoints in minutes:
- High volume of LDAP queries over port 389/636 in a short time frame from a standard workstation.
- SMB connections (port 445) to multiple workstations requesting session enumerations (`NetSessionEnum`, `NetWkstaUserEnum`).
- Access to `\PIPE\srvsvc` and `\PIPE\samr` across the network.

### 3.2 Detection queries

```spl
# Splunk: Detect Rapid SMB Session Enumeration across multiple hosts (SharpHound indicator)
index=windows EventCode=5140 ShareName="\\\\*\\IPC$"
| stats dc(Computer) as TargetHosts, count by SourceAddress, user
| where TargetHosts > 20
```

```kusto
// Sentinel / MDE: High volume of distinct LDAP queries from non-DC workstation
DeviceEvents
| where ActionType == "LdapSearch"
| where not(DeviceName has "DC" or DeviceName has "DomainController")
| summarize UniqueQueries = dc(AdditionalFields) by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 10m)
| where UniqueQueries > 50
```

---

## 4. Kerberos attacks: In-depth

### 4.1 Kerberoasting (T1558.003)
- **Concept:** Any authenticated domain user can request a Kerberos service ticket (TGS) for any service account with a registered `ServicePrincipalName` (SPN). The ticket is encrypted with the service account's password hash. The attacker dumps the ticket from memory and cracks it offline.
- **Log Source:** Security Event ID **4769** (A Kerberos service ticket was requested).
- **Indicators:**
  - `TicketOptions`: `0x40810000` (or standard request flags).
  - `TicketEncryptionType`: `0x17` (RC4-HMAC-MD5 — attackers intentionally downgrade to RC4 for faster cracking).
  - High volume of 4769 requests for unusual service accounts within seconds from a single IP/user.

```kusto
// KQL: Detect potential Kerberoasting (RC4 ticket requests)
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName !in ("krbtgt", "kadmin")
| summarize RequestedServices = make_set(ServiceName), RequestCount = count() by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where RequestCount >= 5
```

### 4.2 AS-REP Roasting (T1558.004)
- **Concept:** If a user account has the "Do not require Kerberos preauthentication" attribute set (`DONT_REQ_PREAUTH`), any attacker can send an AS-REQ without credentials. The KDC returns an AS-REP containing an encrypted blob with the user's password hash, which can be cracked offline.
- **Log Source:** Security Event ID **4768** (A Kerberos authentication ticket was requested) where `PreAuthType == 0` (or `PreAuthType == -`).
- **Failure Code:** Event ID **4771** with `Status == 0x0` or `PreAuthType == 0`.

```spl
# Splunk: AS-REP Roasting detection
index=windows EventCode=4768 PreAuthType=0 TargetUserName!="*$"
| table _time, TargetUserName, IpAddress, TicketOptions, TicketEncryptionType
```

### 4.3 Golden Ticket & Silver Ticket (T1558.001 / T1558.002)

| Feature | Golden Ticket (T1558.001) | Silver Ticket (T1558.002) |
|---|---|---|
| **What is forged?** | Ticket Granting Ticket (TGT). | Service Ticket (TGS). |
| **Secret required** | `krbtgt` NTLM or AES hash. | Target Service Account NTLM/AES hash (e.g., CIFS, MSSQL, HTTP). |
| **Scope** | Complete domain persistence and access to any service/system. | Access restricted only to the specific service on that target host. |
| **Contact with DC?** | No contact needed with KDC to forge TGT; DC contacted only when requesting TGS. | Never contacts the DC. Completely direct to the target server. |
| **Detection anomaly** | - 4769 request without a preceding 4768 (TGS requested without issuing TGT).<br>- TGT lifetime abnormal (default is 10 hours; forged tickets often set to 10 years).<br>- Encryption type mismatch. | - Target server event 4624 (Logon Type 3) without corresponding event 4769 on any DC.<br>- Anomalous PAC validation failures. |

---

## 5. DCSync (T1003.006)

- **Concept:** Exploits the Directory Replication Service (DRS) Remote Protocol (`drsuapi`). An attacker with replication rights (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) impersonates a Domain Controller to pull password hashes (including `krbtgt`) directly from the active DC using `mimikatz lsadump::dcsync`.
- **Telemetry:** Event ID **4662** (An operation was performed on an object).
- **Key Object Properties:**
  - Object Server: `DS`
  - Object Type: `domainDNS`
  - Properties containing DRS GUIDs:
    - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes`)
    - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes-All`)
    - `89e95b76-444d-4c62-991a-0205a5e2f168` (`DS-Replication-Get-Changes-In-Filtered-Set`)

```kusto
// KQL: DCSync detection on Domain Controllers
SecurityEvent
| where EventID == 4662
| where ObjectServer == "DS"
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
// Exclude legitimate DCs and Azure AD Connect / Entra Connect Sync service accounts
| where SubjectUserName !endswith "$" and SubjectUserName !has "MSOL_" and SubjectUserName !has "AAD_"
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, SubjectUserSid, Properties
```

---

## 6. Active Directory Certificate Services (AD CS) Abuse

Misconfigured certificate templates allow low-privileged domain users to request certificates with arbitrary `Subject Alternative Names` (SAN), enabling instant privilege escalation to Domain Admin.

### 6.1 Common ESC misconfigurations
- **ESC1:** Template allows enrollee to supply a SAN (`ENROLLEE_SUPPLIES_SAN`) and has Client Authentication EKU. Attacker requests a cert as `Administrator`.
- **ESC8:** AD CS Web Enrollment HTTP endpoints vulnerable to NTLM Relay (PetitPotam / PrinterBug coercing DC authentication to the CA).

### 6.2 Key Telemetry & Events
- **Event ID 4886:** Certificate Services received a certificate request.
- **Event ID 4887:** Certificate Services approved and issued a certificate.
- Look for:
  - Low-privileged requester username requesting a certificate with `SubjectAlternativeName` containing an administrative identity.
  - Unusual templates specified in `CertificateTemplate` field.

```spl
# Splunk: Suspicious SAN in Issued Certificates (AD CS ESC1 Indicator)
index=windows EventCode=4887
| eval Requester=lower(Requester), SAN=lower(SubjectAlternativeName)
| where isnotnull(SAN) AND NOT match(SAN, Requester)
| table _time, Requester, SubjectAlternativeName, CertificateTemplate
```

---

## 7. Persistence & Domain Backdoors

| Technique | Description | Detection Telemetry |
|---|---|---|
| **AdminSDHolder Abuse** | SDProp updates ACLs of protected groups every 60 min. Adding an attacker to AdminSDHolder gives persistent domain admin. | Event ID **5136** (Directory object modified) targeting `CN=AdminSDHolder,CN=System`. |
| **GPO Modification** | Malicious GPO deployed across OUs to execute scheduled tasks, deploy malware, or add local admins. | Event ID **5136** / **5137** on `groupPolicyContainer` objects, or sysvol file modifications. |
| **DSRM Password Sync** | Syncing the Directory Services Restore Mode admin password to allow local DC logon. | Event ID **4794** (Attempt to set Directory Services Restore Mode password) & registry `HKLM\System\CCS\Control\Lsa\DsrmAdminLogonBehavior`. |
| **SID History Injection** | Injecting `Domain Admins` SID into a regular user's `sIDHistory` attribute. | Event ID **4765** (SID History was added to an account) or **4766** (Attempt failed). |

---

## 8. Essential Active Directory Event IDs Reference

| Event ID | Log Name | Description | TTP / Attack Association |
|---|---|---|---|
| **4768** | Security | Kerberos TGT requested | AS-REP Roasting (`PreAuthType=0`), Golden Ticket validation |
| **4769** | Security | Kerberos Service Ticket (TGS) requested | Kerberoasting (RC4 `0x17`, high volume) |
| **4771** | Security | Kerberos pre-authentication failed | Password spraying, brute force |
| **4624** | Security | Successful logon | Type 3 (Network), Type 9 (NewCredentials/Mimikatz), Pass-the-Hash |
| **4672** | Security | Special privileges assigned to new logon | `SeDebugPrivilege`, admin logon monitoring |
| **4662** | Security | Operation performed on directory object | DCSync replication rights abuse |
| **4720** | Security | User account created | Rogue backdoor account creation |
| **4728 / 4732 / 4756** | Security | Member added to security group | Privilege escalation (added to Domain Admins, Enterprise Admins) |
| **5136** | Security | Directory Service object modified | AdminSDHolder, GPO backdoors, SPN manipulation |
| **4887** | Security | Certificate Services approved request | AD CS certificate abuse (ESC1–ESC8) |

---

## 9. Investigation & Triage Playbook

### Step-by-step AD Incident Triage

```
Alert Triggered (e.g., Kerberoasting / DCSync / Suspicious Group Member Added)
   │
   ├─ 1. Identify the Actor & Host
   │     • Extract SubjectUserName, SubjectUserSid, and IpAddress / WorkstationName.
   │     • Verify: Is the source IP a known DC, backup server, or standard workstation?
   │
   ├─ 2. Validate Authorization
   │     • Check ticketing system: Was there an approved change request or admin action?
   │     • If DCSync from non-DC: Immediate True Positive (P1 incident).
   │
   ├─ 3. Scope Account & Machine Compromise
   │     • Check recent logon events (4624) and EDR telemetry on the source host.
   │     • Look for Cobalt Strike, PowerShell Empire, mimikatz, or SharpHound executions.
   │
   ├─ 4. Check for Impact & Lateral Spread
   │     • Did the actor successfully crack or request high-privilege credentials?
   │     • Query downstream logons from the compromised account across other Tier 0/1 assets.
   │
   └─ 5. Containment Actions
         • Immediately disable/isolate the compromised source host from network.
         • Disable compromised user accounts.
         • If DCSync or Golden Ticket confirmed: Trigger emergency two-step `krbtgt` password reset!
```

---

## 10. Enterprise Hardening & Mitigation

1. **Active Directory Tiering:** Strictly enforce Tier 0 (DCs, PKI, Identity), Tier 1 (Servers), Tier 2 (Workstations). Never allow Tier 0 accounts to log into Tier 1 or 2 assets.
2. **Protected Users Security Group:** Add all sensitive admins to the `Protected Users` group (disables NTLM, cached credentials, and RC4 Kerberos encryption).
3. **Group Managed Service Accounts (gMSA):** Replace user accounts running services with gMSAs (automatic 120-character random passwords rotated automatically, immune to Kerberoasting).
4. **Enforce Kerberos AES Encryption:** Disable RC4 in Kerberos domain policy (`msDS-SupportedEncryptionTypes`).
5. **Double `krbtgt` Password Reset:** Regularly or post-compromise rotate the `krbtgt` account password twice (with 24-48 hours gap to prevent domain disruption while invalidating Golden Tickets).
6. **Restrict DC Replication Rights:** Audit and remove `DS-Replication-Get-Changes-All` permissions from any non-DC account.

---

## 11. Hands-on Labs

1. **SharpHound Detection:** Run SharpHound in a lab domain and capture Sysmon / Windows 5140 logs; write a rule alerting on rapid SMB/LDAP enumeration.
2. **Kerberoasting Lab:** Configure an SPN on a test user (`setspn -a HTTP/app.corp.local testsvc`), request ticket using Rubeus or PowerShell, and detect Event 4769 with RC4 encryption.
3. **AS-REP Roasting Lab:** Disable Kerberos pre-authentication on a test account, request hash with `GetNPUsers.py`, and inspect Event 4768 (`PreAuthType=0`).
4. **DCSync Simulation:** Execute `lsadump::dcsync /domain:lab.local /user:krbtgt` from a non-DC admin host and write a KQL query for Event 4662.
5. **AD CS ESC1 Lab:** Set up an AD CS lab template with `ENROLLEE_SUPPLIES_SAN`, issue a certificate requesting Domain Admin identity, and analyze Event 4887.

---

## 12. Self-test questions

1. What is the fundamental difference between Kerberoasting and AS-REP Roasting?
2. Why do attackers intentionally request RC4 encryption (`0x17`) during a Kerberoasting attack?
3. What Windows Event ID and property GUIDs indicate a DCSync attack?
4. What is a Golden Ticket, which account hash does it require, and why doesn't a standard user password reset invalidate it?
5. What are the key log indicators of an AD CS ESC1 exploit?
6. How does the `Protected Users` security group mitigate credential-based AD attacks?
7. Why must the `krbtgt` password be reset **twice** following a domain compromise?
8. Which event ID indicates that a user was added to the `Domain Admins` group?

---

## 13. One-page revision checklist

- [ ] Kerberos flow: AS-REQ (4768) → AS-REP → TGS-REQ (4769) → TGS-REP → AP-REQ (4624).
- [ ] Kerberoasting: Event 4769, `TicketEncryptionType == 0x17`, high volume, non-machine SPNs.
- [ ] AS-REP Roasting: Event 4768, `PreAuthType == 0`, accounts without pre-auth requirement.
- [ ] Golden Ticket: Forged TGT using `krbtgt` hash, 10-year lifetime, 4769 without preceding 4768.
- [ ] Silver Ticket: Forged TGS using service password hash, bypasses DC entirely, targets single service.
- [ ] DCSync: Event 4662 on DC, GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` and `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, non-DC caller.
- [ ] AD CS (ESC1): Event 4887, `ENROLLEE_SUPPLIES_SAN`, SubjectAlternativeName mismatch with requester.
- [ ] SharpHound footprint: Burst of LDAP (389/636) and SMB IPC$ (5140) queries from non-admin endpoint.
- [ ] Persistence checks: AdminSDHolder (5136), GPO mods (5136/5137), DSRM (4794), SID History (4765).
- [ ] Remediation: Tiered admin model, gMSA, Protected Users group, double `krbtgt` reset.

---

> **Navigation:** [Roadmap index](../README.md) · [← Credential Attacks](Credential-Attacks.md) · [Lateral Movement →](Lateral-Movement.md)
