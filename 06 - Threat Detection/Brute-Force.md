# Brute Force — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Wazuh](../05%20-%20SIEM/wazuh.md) · [Credential Attacks →](Credential-Attacks.md)

> Goal: detect and triage password-guessing at scale — brute force, password spray, credential stuffing — across on-prem, remote access, and cloud identity.
> Stealing/replaying credentials → [Credential-Attacks.md](Credential-Attacks.md); identity fundamentals → [03 - Cybersecurity Fundamentals/Authentication.md](../03%20-%20Cybersecurity%20Fundamentals/Authentication.md).

---

## 0. How to use this note

1. §1–§3: definitions; why it matters; the log sources that matter.
2. §4–§6: detection logic; queries; what success looks like.
3. §7–§9: triage playbook; severity; false positives.
4. §10–§12: response; hardening; labs.
5. §13–§14: self-test, revision.

---

## 1. Definitions

| Term | Pattern | Goal |
|---|---|---|
| **Brute force** | Many passwords, **one** account. | Crack one account. |
| **Password spray** | **One/few** passwords, **many** accounts. | Avoid lockout, find weak password. |
| **Credential stuffing** | Known breach username/password pairs. | Reuse across services. |
| **Reverse brute force** | One common password, many usernames. | Same as spray. |
| **Distributed attack** | Many source IPs. | Evade IP-based blocking. |
| **Low-and-slow** | Few attempts over long period. | Evade thresholds. |
| **Credential stuffing via API** | Automated against login endpoints. | Bypass UI protections. |

**Key distinction:** brute force locks accounts; **spray avoids lockout by trying each account once or twice.**

---

## 2. Why it matters to a SOC

- One of the **most common initial access** techniques (ATT&CK **T1110**).
- Successful guessing = **valid account**, so no malware needed.
- Often the first stage before **BEC, ransomware, or data theft**.
- Cloud/SSO makes it cheaper (no network position needed).
- Detection is **high-signal when tuned** — success after failure is rarely benign.

**What a "win" looks like for the attacker:**
```
spray → 1 valid credential → MFA prompt? → if no MFA → mailbox/cloud access
```

---

## 3. Log sources

### 3.1 Windows / AD

| Event | Meaning |
|---|---|
| **4625** | Failed logon (has `Failure Reason`, `Logon Type`, `Workstation`). |
| **4624** | Successful logon (Logon Type 2/3/10). |
| **4648** | Explicit credential use. |
| **4740** | Account lockout. |
| **4771** | Kerberos pre-auth failed (bad password/expired). |
| **4776** | NTLM credential validation. |
| **4768** | TGT requested (success). |
| **4769** | Service ticket requested. |
| **4647/4634** | Logoff. |
| **3075 / 1203** | NTLM/other auth failures (varies). |

**Logon types:** 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 8 network-cleartext, 9 runas, 10 RDP, 11 cached.

- **Logon type 3 + 4625** = SMB/network guessing.
- **Logon type 10 + 4625** = RDP guessing.
- **Logon type 8** = cleartext (rare, suspicious).

### 3.2 Linux / Unix

| Source | Content |
|---|---|
| `/var/log/auth.log` (Debian) | `sshd`, `sudo`, PAM. |
| `/var/log/secure` (RHEL) | Same. |
| `journald` | Structured. |
| `faillock`/`pam_tally2` | Lockouts. |

Pattern:
```
Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2
Failed password for root from 1.2.3.4 port 5556 ssh2
Accepted password for deploy from 1.2.3.4 port 5557 ssh2
```

### 3.3 Remote access / VPN

- VPN auth logs (user, source IP, result, MFA).
- RDP Gateway, Citrix, Zscaler, GlobalProtect, FortiClient.

### 3.4 Cloud / SaaS

| Platform | Signal |
|---|---|
| **Entra ID** | `SigninLogs`: 50126 (bad password), 50053 (locked), 50055 (expired), 50074 (MFA required), 50140 (keep me signed in). |
| **M365** | Unified Audit Log, `UserLoginFailed`. |
| **Okta** | `user.session.start`, `user.authentication.auth_via_mfa`, `policy.evaluate_sign_on` (DENY). |
| **AWS** | CloudTrail `ConsoleLogin` failures, `AssumeRole` failures. |
| **Google** | Admin audit login failures. |

### 3.5 Application

- Web login endpoints (401/403), API auth failures.
- Proxy logs for POSTs to `/login`.

---

## 4. Detection logic

### 4.1 Dimensions to correlate

| Dimension | Why |
|---|---|
| **Source IP** | Single vs distributed. |
| **Account** | Many accounts = spray; one account = brute. |
| **Time window** | Short burst vs low-and-slow. |
| **Failure reason** | Bad password vs nonexistent user (enumeration). |
| **Logon type/service** | SMB, RDP, SSH, cloud. |
| **User-agent / device** | Stuffing tools vs browsers. |
| **Geo/ASN** | Hosting/VPN/Tor sources. |
| **Success afterwards** | The decisive signal. |

### 4.2 Baselines before thresholds

- Normal failed-login volume per hour/day.
- Normal failure rate per account.
- Normal source IP distribution.
- Normal service-account behaviour (usually fixed source).

**Threshold without baseline = noise or blindness.**

### 4.3 Spray vs brute classifier

```
distinct_accounts / attempts  → high ratio = spray
attempts / distinct_accounts  → high ratio = brute force
```

### 4.4 Brute force (one account)

```spl
index=windows EventCode=4625 earliest=-1h
| stats count AS fails dc(src_ip) AS sources values(Failure_Reason) AS reasons BY user
| where fails >= 20
| sort -fails
```

### 4.5 Password spray (many accounts, one/few passwords)

```spl
index=windows EventCode=4625 earliest=-1h
| stats count AS attempts dc(user) AS accounts BY src_ip
| where accounts >= 10 AND attempts <= accounts*3
| sort -accounts
```

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 50126
| summarize Attempts=count(), Accounts=dcount(UserPrincipalName), Apps=dcount(AppDisplayName) by IPAddress
| where Accounts >= 10
```

### 4.6 Distributed spray

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 50126
| summarize Attempts=count(), IPs=dcount(IPAddress), Countries=dcount(Location) by UserPrincipalName, bin(TimeGenerated, 1h)
| where IPs >= 10
```

### 4.7 Success after failure (highest value)

```spl
index=windows (EventCode=4625 OR EventCode=4624) earliest=-2h
| eval ok=if(EventCode=4624,1,0)
| stats sum(eval(if(EventCode=4625,1,0))) AS fails,
        max(ok) AS success,
        values(src_ip) AS srcs,
        min(_time) AS first,
        max(_time) AS last BY user
| where fails >= 10 AND success = 1
```

```kusto
let fails = SigninLogs
  | where TimeGenerated > ago(24h) and ResultType == 50126
  | summarize F=count(), FirstFail=min(TimeGenerated), LastFail=max(TimeGenerated) by UserPrincipalName, IPAddress;
SigninLogs
| where TimeGenerated > ago(24h) and ResultType == 0
| join kind=inner fails on UserPrincipalName, IPAddress
| where TimeGenerated between (LastFail .. LastFail + 30m)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, F
```

### 4.8 Enumeration signal

Different responses for valid vs invalid usernames leaks accounts.

- 4625 failure reason `%%2313` (unknown user) vs `%%2313` variants.
- Entra `50034` (user does not exist) vs `50126` (bad password).
- Response-time differences on web login.

```kusto
SigninLogs
| where ResultType in (50034, 50126)
| summarize Unknown=countif(ResultType==50034), BadPw=countif(ResultType==50126) by IPAddress
| where Unknown > 10
```

### 4.9 Lockout monitoring

```spl
index=windows EventCode=4740
| stats count AS lockouts values(Caller_Computer_Name) AS sources BY Target_User_Name
| sort -lockouts
```

**Lockouts across many accounts = spray in progress.**

---

## 5. Detection coverage map

| Scenario | Primary signal | Secondary |
|---|---|---|
| SSH brute force | auth.log failures by IP | success from same IP |
| RDP brute force | 4625 type 10 | 4624 type 10 |
| SMB guessing | 4625 type 3 | 4776 failures |
| Kerberos guessing | 4771 | 4768 success |
| Domain spray | 4625 many users, few IPs | 4740 lockouts |
| Entra spray | 50126 many users | 50053 lockouts |
| Okta spray | policy.evaluate_sign_on | session.start |
| VPN spray | VPN auth failures | VPN success |
| API stuffing | 401 by IP/ASN | success + token issue |
| Credential stuffing | breach-list user agents | new device + success |

---

## 6. What "successful compromise" looks like

After a successful guess, look for:

- New MFA method registered.
- Inbox rule created (BEC).
- Mailbox forwarding/export.
- New OAuth consent / app.
- New device registration.
- VPN session then lateral SMB.
- Cloud resource enumeration (CloudTrail/Azure Activity).
- Password change (persistence).
- Session token reuse.

**The failure alert is only the beginning.** The success is the incident.

---

## 7. Triage playbook

### Step 1 — Characterise the activity
- Volume, window, accounts, sources.
- One account or many?
- Internal or external source?
- Which service (SSH/RDP/VPN/cloud/API)?

### Step 2 — Determine if it succeeded
- Any 4624 / ResultType 0 / `Accepted password` from the same source?
- Within the window and shortly after?
- Same account(s)?
- Check MFA result.

### Step 3 — Check the account
- Privilege (admin? service? VIP?).
- Recent password change.
- MFA status.
- Recent activity anomalies.

### Step 4 — Check the source
- Reputation (hosting, Tor, VPN, bulletproof).
- Geo/ASN.
- Other accounts targeted from same IP.
- Other customers/tenants (if MSSP).

### Step 5 — Scope
- Other accounts from same IP.
- Same account from other IPs.
- Successful logins estate-wide.

### Step 6 — Classify
| Verdict | Criteria |
|---|---|
| **Malicious** | Success after failure, or ongoing high-volume guessing. |
| **Suspicious** | High volume, no success, hostile source. |
| **Benign** | User typo storm, misconfigured app/service account. |
| **FP** | Monitoring false positive (e.g., health check). |

### Step 7 — Respond
- Block source (firewall/proxy/conditional access).
- Force password reset + revoke sessions.
- Enforce/verify MFA.
- Disable account if compromised.
- Hunt for post-compromise activity.

### Step 8 — Document
Queries, counts, timeline, accounts, source IPs, verdict, actions.

---

## 8. Severity guidance

| Condition | Severity |
|---|---|
| High-volume guessing, no success, external | Medium |
| Success after failure, standard user | High |
| Success after failure, privileged account | Critical |
| Spray across many accounts | High |
| Lockouts disrupting business | High |
| Internal source guessing (compromised host) | Critical |
| Cloud spray with MFA success | Critical |

---

## 9. False positives

| Source | Why | How to confirm |
|---|---|---|
| **User typos** | Human error bursts. | Single user, few sources, resolves. |
| **Cached credentials** | Old password after change. | Repeated from one device. |
| **Service accounts** | Hardcoded old password. | Fixed source, periodic. |
| **Scanners** | Auth checks. | Known scanner IP. |
| **Load balancers/health checks** | Probe endpoints. | Known infra. |
| **MFA re-prompts** | Not failures, but logged. | Check result code. |
| **Password manager sync** | Multiple attempts. | User confirms. |
| **Penetration test** | Authorised. | Change ticket. |
| **SSO misconfig** | Wrong client secret. | App-specific pattern. |

**Always verify with the user before "benign".**

---

## 10. Response and hardening

### 10.1 Immediate

- Block/rate-limit source at edge.
- Force reset + revoke refresh tokens/sessions.
- Require MFA re-registration if MFA changed.
- Disable account if active compromise.
- Review and revert malicious mailbox/cloud changes.

### 10.2 Strategic

| Control | Effect |
|---|---|
| **MFA everywhere** | Kills most guessing value. |
| **Conditional Access** | Block legacy auth, geo, risky sign-ins. |
| **Smart lockout** | Slow attackers without DoS. |
| **Password policy/length** | Raise guessing cost. |
| **Banned password lists** | Block common passwords. |
| **Passwordless/FIDO2** | Remove password attack surface. |
| **Rate limiting at edge** | Blunt automation. |
| **Disable legacy protocols** | NTLM, basic auth, IMAP/POP. |
| **Honeytoken accounts** | High-signal alerts. |
| **Alert on lockouts** | Early spray signal. |
| **Service account hygiene** | Managed identities/gMSA. |

### 10.3 Detection hardening

- Baseline per source.
- Entity-based thresholds.
- Distributed-spray logic (many IPs, few attempts each).
- Success-after-failure always on.
- Alert on MFA method registration.
- Alert on legacy-auth success.

---

## 11. Labs

1. Deploy a lab AD + Windows client; generate 4625s; build the detection.
2. Run a spray with a small user list in a lab; tune threshold.
3. Simulate SSH failures with a loop; detect in auth.log.
4. Create a success-after-failure rule and test it.
5. Generate Entra-style sign-in failures (or use sample data) and write KQL.
6. Test distributed spray logic with rotating source IPs.
7. Add a honeytoken account and alert on any use.
8. Build a lockout dashboard.
9. Write the triage runbook end to end.
10. Measure FP rate over a week and tune.

---

## 12. Self-test questions

1. Difference between brute force and password spray?
2. Why does spray avoid lockouts?
3. Which Windows event IDs matter?
4. What does logon type 3 vs 10 tell you?
5. How do you distinguish spray from brute force mathematically?
6. Why is success-after-failure the key signal?
7. What does a lockout spike indicate?
8. How do you detect distributed spray?
9. Which cloud result codes indicate failure types?
10. What post-compromise activity should you check?
11. What are three benign causes of failure spikes?
12. When is spraying "critical"?
13. How do you block without breaking the business?
14. What control most reduces risk?
15. How do you detect username enumeration?

---

## 13. One-page revision checklist

- [ ] Definitions: brute, spray, stuffing, reverse, distributed, low-and-slow, API stuffing.
- [ ] ATT&CK T1110; initial access → BEC/ransomware/data theft; success = valid account.
- [ ] Windows: 4625/4624/4648/4740/4771/4776/4768/4769; logon types 2/3/8/10.
- [ ] Linux: auth.log/secure/journald; `Failed password`, `Accepted password`.
- [ ] Remote/cloud: VPN logs; Entra 50126/50053/50055/50034; Okta session/policy; CloudTrail ConsoleLogin.
- [ ] Dimensions: IP, account, window, failure reason, logon type, UA/device, geo/ASN, success.
- [ ] Baseline first; spray vs brute ratio; enumeration; lockouts.
- [ ] Queries: brute (one account), spray (many accounts/few IPs), distributed, success-after-failure, enumeration, lockouts.
- [ ] Coverage map across SSH/RDP/SMB/Kerberos/domain/Entra/Okta/VPN/API.
- [ ] Post-success indicators: MFA registration, inbox rule, forwarding, OAuth, device, VPN+lateral, enumeration, password change.
- [ ] Triage 8 steps; severity table; FP table.
- [ ] Response: block, reset, revoke, MFA, disable, revert changes; strategic controls (MFA, CA, lockout, passwordless, rate limit, legacy auth off, honeytokens).
- [ ] Detection hardening: baseline, entity thresholds, distributed logic, success-after-failure, MFA registration, legacy auth.
- [ ] Pitfalls/FP list memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Wazuh](../05%20-%20SIEM/wazuh.md) · [Credential Attacks →](Credential-Attacks.md)
