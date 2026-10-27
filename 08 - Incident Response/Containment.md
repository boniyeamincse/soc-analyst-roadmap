# Containment — Incident Response Study Notes

> Goal: stop the spread and the bleeding without destroying evidence or the business.
> Declaration/severity → `Identification.md`; removal of the cause → `Eradication.md`.

---

## 0. How to use this note

1. §1–§3: containment goals; short vs long term; the trade-off triangle.
2. §4–§8: decision framework; containment by layer — network, endpoint, identity, cloud, data, email.
3. §9–§12: ransomware, lateral movement, verification, monitoring while contained.
4. §13–§16: evidence tension, comms, legal/investigation holds, pitfalls.
5. §17–§19: playbooks, labs.
6. §20–§21: self-test, revision.

---

## 1. What containment is

> **Containment** = limiting the incident's scope and impact while preserving the ability to investigate and recover.

It is **not** eradication. Contained ≠ fixed.

| Containment does | Containment does not |
|---|---|
| Stop spread | Remove persistence |
| Stop exfil (partially) | Prove the attacker is gone |
| Protect critical services | Restore trust |
| Buy time | Answer root cause |

---

## 2. Short-term vs long-term

| | **Short-term** | **Long-term** |
|---|---|---|
| **Timing** | Immediately, within minutes–hours | After assessment |
| **Goal** | Stop active harm | Sustainable isolation |
| **Examples** | Isolate host, disable account, block IP | Segment VLAN, rebuild, new controls |
| **Risk** | Business disruption | Attacker adaptation |

**Apply short-term containment first, then design long-term containment deliberately.**

### 2.1 Short-term containment checklist

- [ ] Isolate active hosts.
- [ ] Disable/revoke compromised identity.
- [ ] Block confirmed C2 infrastructure.
- [ ] Preserve volatile evidence.
- [ ] Notify IC and asset owners.
- [ ] Start containment log.

---

## 3. The trade-off triangle

```
        Stop the attack
            /      \
   Preserve        Keep business
   evidence           running
```

You cannot maximise all three. The IC decides the priority and records it.

| Situation | Priority |
|---|---|
| Active ransomware | Stop the attack |
| Suspected insider | Preserve evidence |
| Critical service | Keep business running (with monitoring) |
| Regulatory case | Preserve evidence + legal |

---

## 4. Decision framework

### 4.1 Questions

1. Is the attacker active right now?
2. What is the blast radius if we wait 1 hour?
3. What is the business impact of isolating?
4. Can we isolate without tipping off the attacker?
5. Is evidence preserved if we act?
6. Do we have authority (IC/legal/business)?
7. How will we verify containment?

### 4.2 Containment options ladder

| Level | Action | Reversible | Disruption |
|---|---|---|---|
| 1 | Monitor + block IOC | Yes | None |
| 2 | Conditional access / step-up | Yes | Low |
| 3 | Disable session / revoke token | Yes | Low |
| 4 | Block egress destination | Yes | Low-medium |
| 5 | Network isolate host (EDR) | Yes | Medium |
| 6 | Disable account | Yes | Medium-high |
| 7 | Quarantine VLAN | Yes | High |
| 8 | Shut down service | Maybe | Very high |
| 9 | Power off host | No (volatile loss) | High |

**Choose the lowest level that actually stops the activity.**

### 4.3 OODA tempo

Containment is a race. Decide, act, observe the attacker's reaction, adapt. Do not wait for certainty.

---

## 5. Network containment

| Technique | Use | Caveat |
|---|---|---|
| **EDR network isolation** | Single host | Keeps EDR channel open. |
| **Switch port shutdown** | Hard isolation | Loses remote forensics. |
| **VLAN quarantine** | Groups of hosts | Requires pre-built design. |
| **Firewall block** | IP/port/domain | Attacker may rotate. |
| **DNS sinkhole** | Domain C2 | Only DNS-based. |
| **Proxy block** | URL/category | Encrypted SNI caveats. |
| **Egress deny-all + allowlist** | Strong containment | Business impact. |
| **802.1X re-auth** | NAC-based quarantine | Architecture-dependent. |

### 5.1 Isolation design principles

- Contain but keep **management/EDR connectivity** for investigation.
- Pre-define **quarantine VLANs** before you need them.
- Document allowed exceptions (updates, AV, logging).
- Verify the host is actually isolated (test).

### 5.2 Blocking infrastructure

| Indicator | Block at | Note |
|---|---|---|
| IP | Firewall/proxy | Shared hosting risk. |
| Domain | DNS/proxy | Cheap to rotate. |
| URL path | Proxy | Specific. |
| TLS SNI | Proxy | Encrypted hello visible. |
| JA3/JA4 | NDR | Client fingerprint. |
| Certificate | Proxy/NDR | Infrastructure. |

**Blocking is temporary containment, not eradication.**

---

## 6. Endpoint containment

| Action | Effect | Evidence impact |
|---|---|---|
| **EDR isolate** | No network except EDR | Good |
| **Disable NIC** | No network | Loses remote access |
| **Suspend process** | Stops execution | Memory preserved |
| **Kill process** | Stops now | May trigger wiper |
| **Terminate session** | Cuts interactive access | Loses session artefacts |
| **Power off** | Stops everything | Loses memory |

### 6.1 Order

```
capture memory → isolate network → suspend suspicious process
→ collect artefacts → decide on eradication
```

**Never power off a suspected ransomware host before deciding — encryption keys may live in memory.**

### 6.2 Verification

- Ping/EDR heartbeat blocked?
- Can the host reach the internet?
- Is EDR still reporting?
- Does the attacker's C2 show failure?

---

## 7. Identity containment

| Action | Use | Effect |
|---|---|---|
| **Disable account** | Confirmed compromise | Blocks all auth |
| **Reset password** | Credential theft | Invalidates password |
| **Revoke sessions/tokens** | Token theft | Kills active sessions |
| **Revoke refresh tokens** | OAuth abuse | Forces re-auth |
| **Remove MFA device** | Attacker-added MFA | Restores control |
| **Block sign-in** | Conditional access | Policy-level |
| **Require compliant device** | Reduce reuse | Preventative |
| **Rotate API keys/secrets** | Key exposure | Stops programmatic access |

### 7.1 Order matters

```
revoke sessions → reset password → re-enrol MFA → verify no new methods
```

Resetting a password without revoking sessions may leave the attacker logged in.

### 7.2 Service accounts

- Rotate secret.
- Check where it authenticated from.
- Review permissions granted during compromise.
- Search for scheduled tasks/services using it.

### 7.3 Verification

- Sign-in logs show failures for old sessions.
- No new MFA methods.
- No mailbox rules/forwarding left.
- No new OAuth grants.

---

## 8. Cloud, data, and email containment

### 8.1 Cloud

| Action | Use |
|---|---|
| Disable/contain identity | Compromised principal. |
| Revoke access keys | Leaked keys. |
| Snapshot + quarantine instance | Compromised VM. |
| Restrict security group | Open exposure. |
| Block public storage | Data exposure. |
| Revoke OAuth consent | Malicious app. |
| Enable/force CA policy | Prevent recurrence. |
| Rotate secrets in vault | Lateral risk. |

**Snapshot before destroying — cloud evidence disappears fast.**

### 8.2 Data

| Action | Use |
|---|---|
| Remove public access | Exposure |
| Revoke share links | Oversharing |
| Legal hold | Litigation |
| Restore from clean backup | Integrity |
| DLP block | Ongoing exfil |

### 8.3 Email

| Action | Use |
|---|---|
| Purge campaign messages | Phishing |
| Block sender/domain | Repeat |
| Reset mailbox rules/forwarding | BEC |
| Revoke OAuth app | Persistence |
| Disable compromised mailbox | Active BEC |
| Notify recipients | Awareness |

---

## 9. Ransomware containment

### 9.1 Immediate

1. Isolate affected hosts (EDR).
2. Disable compromised accounts.
3. Block C2 and exfil destinations.
4. Protect/verify backups (immutable, offline).
5. Segment remaining network.
6. Identify patient zero and spread vector.
7. Preserve memory/notes/keys where possible.
8. Engage legal/exec/insurer.

### 9.2 Do not

- Pay without legal/exec decision.
- Delete encrypted files before forensics.
- Reconnect isolated hosts to "check".
- Assume backups are clean.
- Broadcast details to all staff (attacker may read).

### 9.3 Ransomware-specific risks

| Risk | Control |
|---|---|
| Re-infection from backups | Scan/restore to clean segment. |
| Credential reuse | Rotate all privileged creds. |
| Persistence in GPO/AD | Audit AD changes. |
| Double extortion | Assume data taken; notify per law. |
| Attacker monitoring email | Use out-of-band comms. |

---

## 10. Lateral movement containment

| Control | Effect |
|---|---|
| Disable NTLM where possible | Blocks pass-the-hash. |
| Block SMB between workstations | Stops spread. |
| Tier admin accounts | Limits credential reuse. |
| LAPS | Unique local admin passwords. |
| Credential Guard | Protects secrets. |
| Restrict RDP | Reduces pivot paths. |
| Network segmentation | Limits blast radius. |

**Containment during an active intrusion often means cutting admin pathways, not just hosts.**

---

## 11. Verification

| Check | Method |
|---|---|
| Host isolated | Ping/EDR/probe |
| Account disabled | Test auth |
| Sessions revoked | Sign-in logs |
| C2 blocked | Firewall/NDR logs |
| Attacker inactive | Absence of new events |
| No new hosts | Re-sweep IOCs |
| Business functional | Service checks |

**Containment must be proven, not assumed.**

---

## 12. Monitoring while contained

Containment changes the environment — expect new alerts and gaps:

- Isolated hosts stop logging normally (agent queue).
- Accounts disabled generate failures (attacker retries).
- Blocks generate deny logs (attacker probing).
- Users work around controls (shadow IT).

**Watch for attacker adaptation:** new infrastructure, new accounts, new protocols.

---

## 13. Evidence tension

| Tension | Resolution |
|---|---|
| Isolation stops exfil but also forensics | Capture memory/disk first where feasible. |
| Killing process destroys memory | Suspend, then acquire. |
| Powering off preserves disk but loses memory | Prefer isolate over power-off. |
| Disabling account tips off attacker | Consider monitoring first if scope unknown. |
| Purging email destroys evidence | Export first. |

**Record the trade-off you chose and why.**

---

## 14. Communication during containment

- State what is contained, what is not.
- Give the business a service impact statement.
- Set expectations for duration.
- Do not declare "contained" until verified.

### 14.1 Wording

| Bad | Better |
|---|---|
| "We stopped them." | "We have isolated 3 hosts and disabled 1 account; verification ongoing." |
| "It's contained." | "Containment applied at 14:05; monitoring for 24 h." |

---

## 15. Legal and investigation holds

- Notify legal before destroying anything.
- Preserve logs beyond retention if litigation likely.
- Do not delete malware without hashing.
- Keep an evidence register.
- Restrict access to the incident channel.

---

## 16. Pitfalls

| Pitfall | Consequence |
|---|---|
| Powering off first | Memory lost. |
| Isolating without EDR path | No remote forensics. |
| Password reset without session revoke | Attacker stays in. |
| Blocking single IP only | Attacker rotates. |
| Declaring contained too early | Re-infection. |
| Over-isolation | Business outage. |
| No verification | False confidence. |
| Purging mail before export | Evidence lost. |
| Reconnecting hosts to test | Re-infection. |
| Ignoring backups | Recovery fails later. |

---

## 17. Playbook: suspected compromised host

```
1. Acknowledge, assign IC
2. Capture memory (if possible) + volatile data
3. EDR network isolate (keep management channel)
4. Collect: process tree, autoruns, network, hashes
5. Block C2 at egress
6. Hunt same IOCs estate-wide
7. Identify credential use → containment for identity
8. Verify isolation
9. Decide eradication path (see Eradication.md)
10. Document all actions + timestamps
```

---

## 18. Labs

1. Practise EDR isolation and verify.
2. Build a quarantine VLAN design.
3. Write an identity containment runbook.
4. Time a session-revocation sequence.
5. Simulate ransomware containment decisions in a tabletop.
6. Verify C2 blocking with a test domain.
7. Draft containment communications.
8. Test backup immutability.
9. Document a containment trade-off decision.
10. Re-sweep IOCs and confirm zero new hosts.

---

## 19. Containment log template

```
time_utc | action | target | performed_by | authorisation
| result | verification | evidence_ref | rollback_plan
```

---

## 20. Self-test questions

1. Containment vs eradication.
2. Short-term vs long-term.
3. What is the trade-off triangle?
4. What is the containment ladder?
5. How do you isolate a host and still investigate it?
6. Why is blocking one IP insufficient?
7. Correct order for identity containment?
8. What must you do before purging phishing email?
9. Why might powering off be wrong?
10. How do you verify containment?
11. What attacker adaptation do you watch for?
12. What are ransomware containment priorities?
13. How do you contain lateral movement?
14. What evidence trade-offs exist?
15. When may you declare "contained"?

---

## 21. One-page revision checklist

- [ ] Containment limits scope/impact; not eradication.
- [ ] Short-term (minutes) → long-term (sustainable).
- [ ] Triangle: stop attack / preserve evidence / keep business.
- [ ] Decision questions + containment ladder 1–9.
- [ ] Network: EDR isolate, VLAN, firewall, sinkhole, egress allowlist, keep mgmt path.
- [ ] Endpoint: capture memory → isolate → suspend → collect; avoid power-off.
- [ ] Identity: revoke sessions → reset → MFA → verify; service accounts rotate + audit.
- [ ] Cloud: disable identity, revoke keys, snapshot, block public, revoke OAuth.
- [ ] Data/email containment actions.
- [ ] Ransomware priorities and "do not" list.
- [ ] Lateral movement controls (NTLM, SMB, tiering, LAPS, segmentation).
- [ ] Verification checks; monitoring while contained; attacker adaptation.
- [ ] Evidence tensions and recorded trade-offs.
- [ ] Comms wording; legal hold.
- [ ] Pitfalls memorised.
- [ ] Containment log fields.
