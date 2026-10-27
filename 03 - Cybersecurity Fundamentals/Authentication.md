# Authentication — SOC Analyst Study Notes

> Goal: understand how identity is **proven**, how that proof fails, and how to detect and triage authentication attacks across Windows/AD, Linux, web, and cloud.
> Related: `Permissions.md` (authorisation), `Windows-Event-Logs.md` (logon events), `Common-Attacks.md`, `Credential-Attacks` in section 06.

---

## 0. How to use this note

1. §1–§2: why authentication matters; the identity vocabulary.
2. §3–§5: factors, password mechanisms, credential storage.
3. §6–§8: protocols (NTLM/Kerberos), web/SSO (SAML/OAuth/OIDC), tokens/sessions.
4. §9–§10: passwordless, adaptive auth, and MFA bypass.
5. §11–§15: attacks, telemetry, detections, investigation, triage.
6. §16–§19: commands, false positives, hardening, labs, self-test, revision.

---

## 1. Why authentication matters to a SOC analyst

- **Credential compromise is the most common initial access** in breaches.
- Most "impossible" attacks (lateral movement, cloud takeover, ransomware) begin with a **valid account**.
- Authentication logs are **high-volume but high-signal** — failures, successes, MFA denials, token issuance.
- Attackers rarely "hack in"; they **log in**. Detection must focus on *how* and *from where*.
- Authentication is where **privacy, compliance, and user experience** collide.

**SOC outcomes:** given an auth alert you can answer:
- Which identity, factor, protocol, and source?
- Failure pattern: typo, spray, stuffing, or brute force?
- Was MFA satisfied? Which factor?
- Is the token/session valid, and where else was it used?
- Is the account privileged or service?
- What response: lock, reset, revoke, or monitor?

---

## 2. Identity vocabulary

| Term | Meaning |
|---|---|
| **Identification** | Claiming an identity (username, email). |
| **Authentication (AuthN)** | Proving the claim. |
| **Authorisation (AuthZ)** | What the identity may do (see `Permissions.md`). |
| **Accounting/Auditing** | Recording who did what. |
| **Principal** | User, service, device, or application identity. |
| **Credential** | Secret or artefact used to prove identity. |
| **Factor** | Category of proof (know/have/are). |
| **MFA** | Two or more *different* factor categories. |
| **SSO** | One authentication for many applications. |
| **Federation** | Trust between identity providers/domains. |
| **Session** | Authenticated state over time (cookie/token/ticket). |
| **Assertion** | Signed statement of identity/attributes (SAML). |
| **Token** | Bearer/credential artefact (JWT, OAuth, refresh). |
| **Step-up** | Re-authentication for sensitive actions. |

> **MFA ≠ authorisation.** MFA proves identity at login; it does not limit what that identity can do afterwards.

---

## 3. Authentication factors

| Category | Examples | Weaknesses |
|---|---|---|
| **Something you know** | Password, PIN, security question | Phishing, reuse, guessing, spraying. |
| **Something you have** | Phone, OTP app, hardware key, smartcard, certificate | Theft, cloning, relay, push fatigue. |
| **Something you are** | Fingerprint, face, iris | Spoofing, irrevocability, privacy. |
| **Somewhere you are** | Geo/IP/network | VPN/proxy spoofing, travel. |
| **Something you do** | Behaviour/typing/keystroke | False positives, limited adoption. |

### 3.1 MFA strength

| Method | Phishing-resistant? | Notes |
|---|---|---|
| SMS OTP | No | SIM swap, interception, SS7. |
| Email OTP | No | Mailbox compromise. |
| TOTP app | No | Real-time phishing proxies steal codes. |
| Push notification | Partly | MFA fatigue, push bombing; number matching helps. |
| Hardware OTP (YubiKey OTP) | No | Code can be relayed. |
| **FIDO2/WebAuthn/passkey** | **Yes** | Origin-bound, cryptographic. |
| Certificate/smartcard | Yes (with PIN) | Strong but operationally heavy. |

> **Phishing-resistant MFA** (FIDO2) is the only category that breaks real-time proxy phishing (Evilginx-style), because the credential is bound to the origin.

---

## 4. Password authentication mechanics

### 4.1 Storage (never plaintext)

- **Hash** the password (one-way), ideally with a **slow KDF**: bcrypt, scrypt, Argon2, PBKDF2.
- **Salt** per user (defeats rainbow tables); **pepper** as an application-wide secret.
- Fast hashes (MD5/SHA-1/SHA-256 raw) are inadequate for passwords.

### 4.2 Windows specifics

- **NTLM hash** = MD4(UTF-16LE(password)) — unsalted, fast; used for pass-the-hash.
- **LM hash** — legacy, disabled by default (and should remain so).
- **Cached domain credentials** (DCC2) for offline logon.
- **Kerberos** stores long-term key derived from password.
- **Credential Guard** protects derived secrets; **LSA protection** protects LSASS.

### 4.3 Linux specifics

- `/etc/shadow` stores `$id$salt$hash`:
  - `$1$` MD5 (bad), `$2b$` bcrypt, `$5$` SHA-256, `$6$` SHA-512, `$y$` yescrypt (modern default).
- `/etc/passwd` has `x` placeholder.
- PAM modules enforce policy (`pam_pwquality`, `pam_faillock`, `pam_tally2`).
- `sudo`, `su`, SSH keys (`authorized_keys`, `known_hosts`).

### 4.4 Password policy trade-offs

- Length > complexity; block breached passwords; rate limit; MFA.
- **NIST guidance:** no forced rotation without evidence of compromise, no composition rules, screen against breached lists, support long passphrases.
- Lockout thresholds must balance brute-force protection vs DoS (lockout as attack).

---

## 5. Password attacks

| Attack | Description | Detection |
|---|---|---|
| **Brute force** | Many guesses for one account | 4625 burst per account, 4771. |
| **Password spray** | One/few passwords across many accounts | Low rate, many accounts, 4625/4771 spread. |
| **Credential stuffing** | Breach lists across services | Distributed IPs, high failure rate, known breaches. |
| **Password guessing** | Contextual guesses (Season2026!) | Targeted failures then success. |
| **Kerberoasting** | Request service tickets, crack offline | 4769 RC4 `0x17`, many SPNs. |
| **AS-REP roasting** | Request AS-REP for no-preauth accounts | 4768 without pre-auth, offline crack. |
| **Pass-the-hash** | Reuse NTLM hash | 4624 type 3, NTLM, no 4768. |
| **Pass-the-ticket** | Reuse Kerberos ticket | 4624 without fresh 4768/4769. |
| **Relay** | NTLM relay to other service | NTLM auth to unexpected target, coercion. |
| **Credential dumping** | LSASS/SAM/NTDS/DPAPI | Sysmon 10, `procdump`, `comsvcs`. |
| **Phishing** | Fake login/proxy | Lookalike domains, MFA prompts, token theft. |
| **MFA fatigue** | Repeated push until approve | Many push denials then success. |
| **Session/token theft** | Steal cookie/token | Token use from new IP/device, no login event. |
| **Password reset abuse** | Weak reset flow | Reset then immediate login from new location. |

**Rate-limit awareness:** attackers use **low-and-slow** sprays (1 attempt per account per hour) to evade thresholds. Detection must use **account spread**, not just volume.

---

## 6. Windows/AD protocols

### 6.1 NTLM

- Challenge/response; used when Kerberos is unavailable.
- **Pass-the-hash**, **relay**, and **NTLM downgrade** are the main risks.
- Detect via 4624 with `AuthenticationPackageName=NTLM`, 4776.
- Mitigate: disable NTLM where possible, SMB signing, EPA, channel binding, block outbound NTLM.

### 6.2 Kerberos

- **AS-REQ/AS-REP** → TGT (4768).
- **TGS-REQ/TGS-REP** → service ticket (4769).
- **Pre-authentication** prevents AS-REP roasting; **AES** avoids RC4 weakness.
- **SPNs** enable Kerberoasting; service accounts with weak passwords are targets.
- **KRBTGT** compromise → Golden Ticket (reset twice).
- **Delegation** (unconstrained/constrained/RBCD) enables impersonation.

### 6.3 Windows logon types (see `Windows-Event-Logs.md`)

Interactive 2, Network 3, Batch 4, Service 5, Unlock 7, NetworkCleartext 8, NewCredentials 9, **RemoteInteractive 10**, CachedInteractive 11.

### 6.4 Other Windows auth

- **Credential Manager / DPAPI** for saved credentials.
- **Windows Hello** (PIN/biometric, TPM-bound).
- **Certificate services / smartcards** (PKINIT).
- **Web Account Manager (WAM)** for Entra ID.

---

## 7. Web, SSO, and federation

### 7.1 SAML

- IdP issues signed **Assertion** to SP via browser POST.
- Risks: **XSW** (signature wrapping), signature stripping, comment injection in NameID, audience/recipient not validated, replay, XXE.
- Detect: anomalous IdP, modified assertions, unusual SP, replay.

### 7.2 OAuth 2.0 / OIDC

- Flows: authorization code (+PKCE), client credentials, device code, implicit (legacy).
- **Tokens:** access, refresh, ID (JWT).
- Risks: **redirect_uri** manipulation, **consent phishing** (illicit grant), token theft, weak client secrets, **device code phishing**, scope escalation.
- Detect: new consent grants, unusual app registrations, token replay, impossible travel, refresh-token abuse.

### 7.3 JWT

- Header.payload.signature; algorithms HS/RS/ES/PS/none.
- Risks: `alg:none`, **key confusion** (RS→HS), weak secret, `kid` injection, unverified claims, no expiry, missing audience/issuer checks.
- Detect: token anomalies, forged claims, signature failures, mass token reuse.

### 7.4 Session management

- Cookie attributes: `Secure`, `HttpOnly`, `SameSite`, `__Host-` prefix.
- **Session fixation** (no rotation on login), **no invalidation** on logout/password change, long-lived refresh tokens.
- Detect: session use from new ASN/device, concurrent sessions, token reuse after logout.

### 7.5 Passwordless

- **FIDO2/WebAuthn/passkeys** — origin-bound public-key credentials; strongest.
- **Windows Hello for Business** — TPM-bound.
- **Magic links** — email possession; treat like email compromise.
- Risks shift to **device/authenticator compromise**, account recovery, and enrollment.

---

## 8. Adaptive / risk-based authentication

Signals: device fingerprint, IP reputation, geo-velocity, ASN, behaviour, time, MFA method, threat intel.

Outcomes: allow, step-up MFA, block, require password reset, restrict session.

**Detection value:** risk scores and step-up events are high-signal; a burst of step-ups or blocks indicates attack.

---

## 9. MFA bypass techniques

| Technique | How | Detection |
|---|---|---|
| **Push fatigue** | Spam approvals | Many denials then success. |
| **Real-time phishing proxy** | Relay session + OTP | Lookalike domain, unusual ASN, session reuse. |
| **OTP interception** | SMS/email compromise | SIM swap, mailbox rules. |
| **MFA downgrade** | Force weaker factor | Policy change, legacy protocol. |
| **Legacy protocol bypass** | IMAP/SMTP/EWS without MFA | Legacy auth sign-ins. |
| **Token theft** | Steal cookies/tokens | Token from new IP, no auth event. |
| **Session hijack** | Adversary-in-the-middle | Concurrent session, device change. |
| **Recovery abuse** | Weak recovery flow | Reset + new device. |
| **Device code phishing** | User enters code at real IdP | Device code grant, unusual app. |
| **Helpdesk social engineering** | Reset MFA | Support ticket correlation. |

**Mitigations:** phishing-resistant MFA, number matching, conditional access, block legacy auth, device compliance, token protection (binding), short sessions, user reporting.

---

## 10. Account lifecycle and service identities

- **Joiner/mover/leaver** processes; stale accounts are attack surface.
- **Privileged accounts**: separate admin accounts, JIT/PIM, PAWs, break-glass.
- **Service accounts**: gMSA/virtual accounts, no interactive logon, long random passwords, rotation.
- **Shared accounts**: avoid; if unavoidable, attribute via source host.
- **Guest/external accounts**: expiry, review, conditional access.
- **API keys/service principals**: scoped, rotated, monitored.
- **Dormant accounts** re-enabled by attackers — detect enablement + logon.

---

## 11. Telemetry for authentication

| Source | Events |
|---|---|
| **Windows Security** | 4624/4625/4634/4647/4648/4672/4740, 4768/4769/4771/4776, 4720-4738. |
| **AD FS** | 4624/4625, 1200/1202/1203, token issuance. |
| **Entra ID sign-in logs** | Success/failure, MFA, conditional access, risk, app, IP, device. |
| **Entra audit logs** | User/app/role changes, consent grants. |
| **Okta system log** | `user.session.start`, `policy.evaluate_sign_on`, MFA events. |
| **Linux** | `auth.log`/`secure`, `sshd`, `sudo`, `pam`, `faillock`. |
| **Web/app** | Login success/failure, lockout, password reset, MFA challenge. |
| **VPN** | Auth success/failure, source IP, device posture. |
| **Cloud** | CloudTrail `ConsoleLogin`, `AssumeRole`, `GetSessionToken`; Azure sign-in. |
| **Email** | OWA/IMAP/SMTP auth, forwarding rules. |
| **EDR** | Credential access, token theft, LSASS. |

**Correlation keys:** username, source IP, ASN, device ID, user agent, session/token ID, LogonId, request ID.

---

## 12. Detection engineering

### 12.1 High-signal ideas

1. **Spray pattern**: many accounts, few attempts each, same source/subnet.
2. **Brute force**: many failures, one account, short window.
3. **Success after threshold failures**.
4. **Impossible travel** / geo-velocity.
5. **New ASN/country** for privileged account.
6. **MFA denial burst** then success (fatigue).
7. **Legacy auth** (IMAP/POP/SMTP/EWS) success.
8. **MFA method change** then login.
9. **Password reset** then immediate login from new location.
10. **Account enabled** then logon (dormant reactivation).
11. **Token use without login** (session theft).
12. **Consent grant** to new/unverified app.
13. **New device + privileged role**.
14. **Service account interactive logon**.
15. **Kerberoasting** (4769 RC4 volume).
16. **AS-REP roasting** (4768 no pre-auth).
17. **Pass-the-hash** (NTLM type 3, admin account).
18. **Password never expires + privileged** (hygiene).
19. **Multiple accounts from one host** (credential testing).
20. **Authentication from hosting/VPN/Tor ASN**.

### 12.2 Splunk SPL

**Spray (many accounts, few attempts):**
```spl
index=wineventlog EventCode=4625
| bin _time span=10m
| stats dc(TargetUserName) as accounts count as failures by src_ip, _time
| where accounts > 15 and failures < accounts * 3
```

**Brute force (one account):**
```spl
index=wineventlog EventCode=4625
| stats count by TargetUserName, src_ip, bin(_time,5m)
| where count > 20
```

**Success after failures:**
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as fails, count(eval(EventCode=4624)) as success by TargetUserName, src_ip
| where fails > 10 AND success > 0
```

**MFA fatigue (Entra sign-in via connector):**
```spl
index=azure sourcetype="azure:aad:signin"
| where status.errorCode=50074 OR status.errorCode=50076
| stats count by userPrincipalName, ipAddress, bin(_time,15m)
| where count > 10
```

**Legacy auth success:**
```spl
index=azure sourcetype="azure:aad:signin"
| where clientAppUsed IN ("IMAP","POP","SMTP","Other clients","Exchange ActiveSync")
| where status.errorCode=0
| table _time, userPrincipalName, clientAppUsed, ipAddress, appDisplayName
```

**Impossible travel (simplified):**
```spl
index=azure sourcetype="azure:aad:signin" status.errorCode=0
| iplocation ipAddress | eval country=Country
| sort 0 userPrincipalName _time
| streamstats current=f window=1 values(country) as prev_country values(_time) as prev_time by userPrincipalName
| where country!=prev_country AND (_time - prev_time) < 3600
```

**Kerberoasting:**
```spl
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| stats count values(ServiceName) as spns by TargetUserName, IpAddress
| where count > 15
```

**Password reset then login:**
```spl
index=azure sourcetype="azure:aad:audit" activityDisplayName="Reset password (by admin)"
| join userPrincipalName [search index=azure sourcetype="azure:aad:signin" status.errorCode=0]
| table _time, userPrincipalName, ipAddress
```

**Linux auth failures:**
```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src>\S+)"
| stats count by src, user, host
| where count > 10
```

### 12.3 KQL

**Spray:**
```kusto
SigninLogs
| where ResultType == 50126
| summarize Accounts = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 15m)
| where Accounts > 15 and Attempts < Accounts * 3
```

**Impossible travel:**
```kusto
SigninLogs
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevCountry = prev(Country, 1), PrevTime = prev(TimeGenerated, 1), PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser and Country != PrevCountry
| extend Minutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where Minutes < 60
```

**MFA fatigue:**
```kusto
AADSignInEventsBeta
| where ErrorCode in (50074, 50076, 500121)
| summarize Denials = count() by AccountUpn, IPAddress, bin(Timestamp, 15m)
| where Denials > 10
```

**Legacy auth:**
```kusto
SigninLogs
| where ClientAppUsed in ("IMAP","POP","SMTP","Other clients","Exchange ActiveSync")
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, AppDisplayName
```

**Service account interactive logon (Windows):**
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType in (2,10)
| where Account endswith "$" or Account has_any ("svc_","sa_")
| project TimeGenerated, Computer, Account, LogonType, IpAddress
```

### 12.4 Sigma sketch

```yaml
title: Multiple Failed Logons Followed by Success
logsource:
  product: windows
  service: security
detection:
  failure:
    EventID: 4625
  success:
    EventID: 4624
  timeframe: 15m
  condition: failure | count() by TargetUserName > 10 and success
level: high
```

---

## 13. Investigation workflow

### Step 1 — Identify the identity
Human, service, device, app? Privileged? Dormant? New?

### Step 2 — Characterise the attempt
Failures → success? Protocol? Logon type? MFA satisfied? Conditional access result?

### Step 3 — Source
IP, ASN, geo, device, user agent, VPN/proxy/Tor, known-bad reputation.

### Step 4 — Determine legitimacy
User confirmation, travel, change ticket, expected automation, baseline.

### Step 5 — Check what the session did
Post-login activity: mailbox rules, file access, role changes, new tokens, lateral movement.

### Step 6 — Scope
Other accounts from same source; same account from other sources; token reuse.

### Step 7 — Respond
Lock/disable, revoke sessions/tokens, reset password, reset MFA, block source, force re-auth.

### Step 8 — Document
Timeline, factor, protocol, source, evidence, actions, residual risk.

---

## 14. Triage playbooks

### A. Brute force against one account
1. Volume, window, source.
2. Any success? If yes → treat as compromise.
3. Lockout policy engaged? User notified.
4. Block source, enforce MFA, monitor.

### B. Password spray
1. Accounts targeted, source diversity, attempts per account.
2. Any success (especially privileged)?
3. Block IPs/ASN, notify affected users, check for follow-on.

### C. MFA fatigue
1. Count of pushes, times, user response.
2. Any approval from unusual location?
3. Revoke sessions, re-register MFA, educate, enable number matching.

### D. Impossible travel
1. Verify with user (VPN? mobile? travel?).
2. Check device and app.
3. If anomalous → revoke sessions, reset credentials.

### E. Legacy auth success
1. Which protocol, app, user?
2. Expected (old device/app)?
3. Block legacy auth, require modern auth, investigate mailbox.

### F. Token/session theft
1. Token used without corresponding login.
2. Source/device change.
3. Revoke tokens, reset password, check app consents.

### G. Suspicious consent grant
1. App name, publisher, scopes, granting user.
2. Verified publisher? Business justification?
3. Revoke grant, remove app, notify.

### H. Kerberoasting / AS-REP
1. Account, SPN/pre-auth setting, source.
2. Password strength/age of service account.
3. Rotate to gMSA/strong random, monitor use.

### Severity guide

| Scenario | Severity |
|---|---|
| Failures only, no success | Low–Medium |
| Spray with success (non-privileged) | High |
| Privileged account compromise | Critical |
| MFA bypass / token theft | Critical |
| Consent grant with mail/file scopes | High–Critical |
| Legacy auth success | Medium–High |
| Impossible travel (verified benign) | Informational |
| Dormant account reactivation | High |

---

## 15. Authentication controls (defensive summary)

- **Phishing-resistant MFA** (FIDO2/passkeys) for all privileged and high-risk users.
- **Conditional access**: device compliance, location, risk, app sensitivity.
- **Block legacy authentication**.
- **Password policy**: length, breached-password screening, no forced rotation, rate limiting, lockout tuned.
- **Privileged access**: separate admin accounts, JIT/PIM, PAWs, break-glass monitoring.
- **Service accounts**: gMSA, no interactive logon, rotation, SPN hygiene.
- **Session security**: short lifetimes, rotation on privilege change, revocation on logout, token binding.
- **Monitoring**: sign-in logs to SIEM, alert on spray/fatigue/impossible travel/legacy/consent.
- **User reporting** of unexpected MFA prompts.
- **Account hygiene**: disable dormant, review access, expire guests.

---

## 16. Commands

```bash
# Linux
last -ai
lastb
faillock --user alice
grep "Failed password" /var/log/auth.log | tail
grep "Accepted" /var/log/auth.log | tail
passwd -S alice
chage -l alice
awk -F: '($2==""){print $1}' /etc/shadow    # empty passwords
```

```powershell
# Windows
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50
Get-ADUser -Filter * -Properties PasswordLastSet, PasswordNeverExpires, Enabled |
  Where-Object { $_.PasswordNeverExpires -and $_.Enabled }
Get-ADUser -Filter * -Properties DoesNotRequirePreAuth |
  Where-Object { $_.DoesNotRequirePreAuth -eq $true }
net accounts
Get-MpComputerStatus   # (not auth, but endpoint context)
```

```bash
# Entra/Graph (read-only)
az ad user list --query "[].{upn:userPrincipalName,enabled:accountEnabled}"
# Sign-in logs via Log Analytics
```

```bash
# AWS
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin
aws iam list-users
aws iam get-account-password-policy
```

---

## 17. Common false positives

| Alert | Often actually |
|---|---|
| Failed logons | Expired cached creds, mapped drives, services, scanners. |
| Spray pattern | NAT/proxy egress, SSO retries, mobile clients. |
| Impossible travel | VPN, mobile network switching, cloud egress, ISP geo errors. |
| MFA denials | User errors, time sync, app issues, push not received. |
| Legacy auth | Old mail clients, printers/scanners, line-of-business apps. |
| Token reuse | Load-balanced app, multiple tabs, API integrations. |
| Password reset + login | Support workflow, user forgot password. |
| Dormant account login | Seasonal worker, automation, re-enabled for project. |
| Service account interactive | Misconfigured app, admin troubleshooting. |
| Multiple accounts one host | Shared workstation, kiosk, admin jump host. |

**Validate with:** user confirmation, device/geo context, change records, baseline behaviour, and post-login activity.

---

## 18. Labs

1. Build a lab AD domain; run spray and brute force; write detections.
2. Enable Entra ID sign-in logs; simulate impossible travel with a VPN.
3. Configure MFA; simulate push fatigue; write a detection.
4. Test legacy auth against a lab mailbox; block and verify.
5. Create a JWT demo app; test `alg:none` and key confusion; detect.
6. Configure SAML with a test IdP; attempt XSW in a lab; log and detect.
7. Set up Linux `pam_faillock`; test lockout; analyse logs.
8. Compare 4624 logon types across console/SMB/RDP.
9. Audit a lab tenant for dormant/privileged accounts.
10. Write an auth incident report with timeline and response.

---

## 19. Self-test questions

1. Differentiate identification, authentication, authorisation, accounting.
2. What makes MFA "phishing-resistant"?
3. Why is NTLM hash reuse (pass-the-hash) possible?
4. Which Kerberos event IDs indicate roasting, and how do you tell them apart?
5. What is the difference between brute force and password spray?
6. Why is low-and-slow spraying hard to detect?
7. What is session fixation, and how is it prevented?
8. What are three JWT weaknesses?
9. How does consent phishing work?
10. Which sign-in signals indicate MFA fatigue?
11. Why is blocking legacy auth important?
12. What should happen to sessions after a password reset?
13. Why are service accounts risky, and how should they be managed?
14. Which detection catches token theft without a login event?
15. How would you triage an impossible-travel alert?

---

## 20. One-page revision checklist

- [ ] Vocabulary: identification/AuthN/AuthZ/accounting, principal, credential, factor, MFA, SSO, federation, session, assertion, token, step-up.
- [ ] Factors: know/have/are/somewhere/do; MFA strength; phishing-resistant = FIDO2/WebAuthn.
- [ ] Passwords: hashing + salt + KDF (bcrypt/scrypt/Argon2/PBKDF2); Windows NTLM/LM/DCC2; Linux `$y$`/`$6$`, PAM; policy trade-offs (length > complexity, no forced rotation, breached screening, lockout balance).
- [ ] Attacks: brute force, spray, stuffing, guessing, Kerberoasting, AS-REP, PTH, PTT, relay, dumping, phishing, MFA fatigue, token theft, reset abuse.
- [ ] Windows/AD: NTLM (PTH/relay), Kerberos (TGT/TGS, pre-auth, SPN, KRBTGT, delegation), logon types, Windows Hello, smartcards.
- [ ] Web/SSO: SAML (XSW/strip/comment/replay/XXE), OAuth/OIDC (redirect_uri, consent, device code, scopes), JWT (alg none/key confusion/kid/claims), session (fixation/invalidation/cookie flags), passwordless.
- [ ] Adaptive auth: risk signals and outcomes.
- [ ] MFA bypass: fatigue, proxy phishing, OTP interception, downgrade, legacy, token theft, session hijack, recovery abuse, device code, helpdesk.
- [ ] Lifecycle: JML, privileged accounts/JIT, service accounts/gMSA, shared, guest, API keys, dormant.
- [ ] Telemetry: 4624/4625/4634/4648/4672/4740/4768/4769/4771/4776/4720-4738, AD FS, Entra sign-in/audit, Okta, Linux auth.log/sshd/sudo/pam, web, VPN, cloud, email, EDR.
- [ ] Detections: spray, brute force, success-after-failure, impossible travel, new ASN, MFA fatigue, legacy auth, MFA method change, reset+login, dormant reactivation, token without login, consent grant, new device+privilege, service interactive, Kerberoasting, AS-REP, PTH, never-expires, multi-account host, hosting/Tor ASN.
- [ ] Investigation: identity → attempt → source → legitimacy → session activity → scope → respond → document.
- [ ] Triage: brute force, spray, fatigue, impossible travel, legacy, token theft, consent, roasting.
- [ ] Controls: phishing-resistant MFA, conditional access, block legacy, password policy, privileged access, service accounts, session security, monitoring, user reporting, hygiene.
