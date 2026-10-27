# Alert Triage — SOC Analyst Study Notes

> Goal: turn an alert into a defensible verdict fast — without over-investigating noise or under-investigating a breach.
> Alert design/metrics → `04 - Security Monitoring/Alerting.md`; IOCs → `IOC-Analysis.md`; timelines → `Timeline-Analysis.md`.

---

## 0. How to use this note

1. §1–§3: what triage is; roles; verdicts.
2. §4–§7: the framework; evidence; questioning; time-boxing.
3. §8–§12: triage by domain — identity, endpoint, network, cloud, email.
4. §13–§16: decision trees, documentation, escalation/handover.
5. §17–§19: pitfalls, metrics, labs.
6. §20–§21: self-test, revision.

---

## 1. What triage is

> **Triage** = a bounded investigation that answers: *is this real, how bad, and who needs to act now?*

It is **not** full incident response. It is the gate between the queue and the IR process.

| Stage | Question | Owner |
|---|---|---|
| **Acknowledge** | Has someone taken it? | L1 |
| **Triage** | Real? Impact? Escalate? | L1/L2 |
| **Investigate** | Full scope and story. | L2/IR |
| **Respond** | Contain, eradicate, recover. | IR |

**Goal of triage:** correct verdict + evidence + next action, within SLA.

---

## 2. Roles

| Role | Triage responsibility |
|---|---|
| **L1** | Validate, enrich, classify obvious FP/benign, escalate real. |
| **L2** | Deep-dive, scope, correlate, recommend containment. |
| **IR** | Own confirmed incidents; containment strategy. |
| **Detection engineering** | Fix rules based on triage feedback. |
| **Threat hunting** | Proactive search beyond alerts. |

**The boundary matters:** L1 should not burn an hour on a phish that needs IR, and IR should not be paged for every scanner hit.

---

## 3. Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| **True positive — malicious** | Attack confirmed. | Escalate/contain. |
| **True positive — benign** | Rule right, activity legitimate. | Document, tune context. |
| **False positive — rule** | Logic wrong. | Tune rule. |
| **False positive — data** | Parsing/schema wrong. | Fix pipeline. |
| **Duplicate** | Covered by another alert/case. | Link, close. |
| **Inconclusive** | Not enough data. | Collect more, escalate, or time-box. |
| **Test/authorised** | Red team, scanner, change. | Verify authorisation, close. |

**Never close as "FP" when you mean "benign TP"** — the fixes are different.

---

## 4. The triage framework

```
1. READ        title, severity, entities, rule, evidence
2. VALIDATE    is the data real and correctly parsed?
3. CONTEXT     asset, user, baseline, change window
4. CORROBORATE other sources agree?
5. DECIDE      verdict + confidence
6. ACT         close / enrich / escalate / contain
7. DOCUMENT    evidence, reasoning, verdict
8. FEEDBACK    tune rule/playbook
```

### 4.1 Time budget (guideline)

| Severity | Triage target |
|---|---|
| Critical | 15–30 min |
| High | 30–60 min |
| Medium | 1–2 h |
| Low | Batch, 5–10 min each |

**If you exceed the budget without a verdict, escalate with what you have.**

---

## 5. Evidence gathering

### 5.1 Evidence hierarchy

| Tier | Example | Trust |
|---|---|---|
| **Direct** | Process tree, PCAP, raw log | High |
| **Corroborating** | Two independent sources | High |
| **Contextual** | Asset inventory, TI | Medium |
| **Circumstantial** | Timing, geography | Low |

**Prefer direct evidence.** Contextual data can be wrong or stale.

### 5.2 Minimum evidence set

- Exact event(s) and timestamps.
- Entity (user/host/IP/process).
- Preceding and following events (±15 min).
- Related alerts.
- Asset criticality and user role.
- Change/maintenance status.

### 5.3 Evidence discipline

- Save queries and results.
- Screenshot/hash where needed.
- Do not alter source systems.
- Note timezone and data source.
- Distinguish observed vs inferred.

---

## 6. Questioning the alert

### 6.1 Twelve questions

1. What exactly does the rule detect?
2. Is the event real, or a parsing artefact?
3. Who/what is the entity, and is it expected?
4. Is the timing normal (business hours/shift)?
5. Is this the first time, or recurring?
6. Does another source corroborate?
7. What happened immediately before?
8. What happened immediately after?
9. Could this be legitimate admin/automation?
10. What would an attacker do next if real?
11. What is the worst-case impact?
12. What is the cheapest test that distinguishes benign from malicious?

### 6.2 The "so what?" test

For every finding ask: **"What does this let the attacker do?"**

- A failed login from a scanner: nothing.
- A failed login followed by success on a DC: everything.

---

## 7. Time-boxing and escalation triggers

### 7.1 Escalate immediately when

- Privileged account or Tier-0 asset.
- Confirmed execution/C2.
- Multiple hosts affected.
- Data access/exfiltration.
- Ransomware indicators.
- You are uncertain but impact could be high.
- SLA breach approaching.

### 7.2 Escalation package

```
Summary:        one paragraph
Evidence:       events, queries, screenshots, hashes
Entities:       user, host, IP, process
Impact:         CIA, scope, asset criticality
Actions taken:  blocks, isolates, resets
Open questions: what you couldn't determine
Recommendation
```

**Escalate early with partial info; do not sit on a critical finding.**

---

## 8. Identity triage

| Alert | First checks |
|---|---|
| **Brute force/spray** | Success after failure? MFA? Source reputation? Account privilege? |
| **Impossible travel** | VPN? Mobile? New device? MFA method? |
| **New MFA method** | Was it the user? Any preceding risky sign-in? |
| **Password reset** | Requester identity? Helpdesk ticket? |
| **Risky sign-in** | Risk reason, IP/ASN, app, conditional access result. |
| **New admin** | Who created, approval, what has it done? |
| **Token anomaly** | New device/geo, no MFA, app scopes. |

**Pivot:** user → all sign-ins 24h → MFA events → mailbox rules → OAuth grants → endpoint logons.

---

## 9. Endpoint triage

| Alert | First checks |
|---|---|
| **Malware detected** | Executed? Path, hash, parent, children, network. |
| **Suspicious process** | Lineage, command line, signer, prevalence. |
| **LSASS access** | Process, user, granted access, dump file. |
| **Persistence** | Service/task/Run key content, creator, path. |
| **Ransomware behaviour** | Shadow deletion, mass writes, note files. |
| **Defence evasion** | Defender/EDR tampering, AMSI bypass. |

**Pivot:** process → parent/children → network → files → registry → other hosts with same hash.

---

## 10. Network triage

| Alert | First checks |
|---|---|
| **IDS signature** | Flow, direction, action (blocked?), target service. |
| **Beaconing** | Periodicity, destination reputation, process. |
| **DNS tunnelling** | Label length, volume, record type, client process. |
| **Exfil volume** | Bytes out, destination, user/host baseline. |
| **Lateral SMB** | Source/dest, account, share, fan-out. |
| **Scan** | Internal vs external source, follow-up exploitation. |

**Pivot:** IP → DNS → proxy → EDR network → auth logs.

---

## 11. Cloud triage

| Alert | First checks |
|---|---|
| **IAM change** | Principal, action, target, source (IaC vs console vs API). |
| **New access key** | Who, when, used from where. |
| **Public storage** | Data sensitivity, exposure duration, access logs. |
| **Risky OAuth consent** | App, scopes, publisher, user count. |
| **Cloud sign-in anomaly** | Device, geo, conditional access, token type. |
| **Resource deletion** | Principal, snapshot/backup existence. |

**Pivot:** principal → all activity 24h → IP/ASN → resource access → data egress.

---

## 12. Email triage

| Alert | First checks |
|---|---|
| **Phishing reported** | Auth results, links, attachments, recipients. |
| **Malicious attachment** | Hash, sandbox, execution on endpoints. |
| **BEC** | Sender legitimacy, reply-to, bank details, rules. |
| **Mass mail** | Sender reputation, volume, internal vs external. |
| **Account compromise** | Rules, forwarding, OAuth, sent items. |

**Pivot:** message → all recipients → clicks → auth → endpoint execution.

> Detail → `06 - Threat Detection/Phishing.md`.

---

## 13. Decision trees

### 13.1 Generic

```
Is the data valid? ──no──> FP-D (fix pipeline)
        │yes
Is the behaviour expected for this entity/environment? ──yes──> TP-B (verify, tune context)
        │no
Is there corroboration? ──no──> enrich more / inconclusive (time-box)
        │yes
Is impact plausible? ──no──> close low-confidence (document)
        │yes
ESCALATE / CONTAIN
```

### 13.2 Credential alert

```
Failures only? ──yes──> volume/source/privilege → block/monitor
        │no (success after failure)
MFA satisfied? ──no──> assume compromise → reset+revoke
        │yes
Is the success from the same source/geo? ──no──> suspicious → verify with user
        │yes
Post-auth anomalies (rules/OAuth/new device)? ──yes──> escalate
        │no
TP-B or close with monitoring
```

### 13.3 Malware alert

```
Action taken = blocked? ──yes──> verify no residue → close
        │no
Process executed? ──no──> file-only → check persistence/download
        │yes
Network/persistence/credential access? ──yes──> isolate + escalate
        │no
Scope by hash → decide
```

---

## 14. Documentation

### 14.1 Minimum note

```
Alert:        id, title, severity
Time:         event + detection (UTC)
Entities:     user, host, IP, process
What happened: factual timeline
Evidence:     queries/screenshots/hashes
Analysis:     why benign/malicious
Verdict:      disposition code
Actions:      blocks/resets/escalation
Follow-up:    tuning/hunting tasks
```

### 14.2 Writing rules

- Facts vs inference labelled.
- No "probably" without stating why.
- Include the query used (reproducibility).
- Record what you did **not** check (limits).
- Write for the next analyst, not for yourself.

---

## 15. Handover and escalation

### 15.1 Shift handover

- Open critical/high alerts and their state.
- Pending user verifications.
- Escalated cases and owners.
- Known noisy rules/outages.
- Upcoming changes/maintenance.

### 15.2 Escalation quality

A good escalation lets IR act **without redoing triage**:

- Timeline.
- Scope estimate.
- Evidence locations.
- Actions already taken.
- Recommended next step.

---

## 16. Common triage mistakes

| Mistake | Consequence |
|---|---|
| Trusting the rule title | Wrong verdict. |
| Stopping at first hit | Miss scope. |
| Not checking success after failure | Miss compromise. |
| Closing as FP because noisy | Miss real attack in noise. |
| Over-investigating low severity | SLA breach elsewhere. |
| Under-investigating privileged accounts | Miss domain compromise. |
| No documentation | No learning, no audit. |
| Not verifying with user | Wrong "benign". |
| Ignoring timezone | Wrong timeline. |
| Escalating without evidence | IR rework. |
| Sitting on critical findings | Worse impact. |

---

## 17. Metrics

| Metric | Meaning |
|---|---|
| **MTTA** | Acknowledge speed. |
| **Triage time** | Time to verdict. |
| **Escalation rate** | % escalated. |
| **Conversion rate** | Incidents per alert. |
| **Reopen rate** | Wrong verdicts. |
| **SLA compliance** | By severity. |
| **FP share** | Quality signal. |

Track per rule and per analyst (for coaching, not punishment).

---

## 18. Labs

1. Triage 10 mixed alerts on a sample dataset; assign dispositions.
2. Write the evidence note for a brute-force alert.
3. Build a decision tree for a cloud IAM alert.
4. Practise a 15-minute time-box on a critical alert.
5. Escalate a simulated incident with a full package.
6. Review a peer's triage note for reproducibility.
7. Measure your triage time across 20 alerts.
8. Find the FP in a batch of 20 and justify the tuning.
9. Take a benign TP and write the context rule.
10. Do a shift handover from notes only.

---

## 19. Pitfalls recap

- Verdict without evidence.
- No scope check.
- No post-event check.
- Ignoring privilege/asset.
- Silent time-box overrun.
- Bad escalation package.
- No tuning feedback.
- Closing "inconclusive" without a follow-up.

---

## 20. Self-test questions

1. What question does triage answer?
2. Triage vs investigation vs IR?
3. What are the seven dispositions?
4. Why distinguish FP from benign TP?
5. What is the minimum evidence set?
6. What are the twelve triage questions?
7. When do you escalate immediately?
8. What belongs in an escalation package?
9. How do you triage success-after-failure?
10. What is the "so what?" test?
11. How do you handle an inconclusive alert?
12. Why time-box?
13. What should a triage note contain?
14. Which metrics reveal bad triage?
15. What is the biggest triage mistake?

---

## 21. One-page revision checklist

- [ ] Triage = bounded investigation: real? impact? who acts?
- [ ] Stages: acknowledge → triage → investigate → respond; roles L1/L2/IR/DE/hunting.
- [ ] Verdicts: TP-malicious, TP-benign, FP-rule, FP-data, duplicate, inconclusive, authorised.
- [ ] Framework 8 steps; time budgets by severity; escalate at overrun.
- [ ] Evidence hierarchy and minimum set; evidence discipline.
- [ ] Twelve questions; "so what?" test.
- [ ] Escalation triggers and package contents.
- [ ] Domain triage checklists: identity, endpoint, network, cloud, email + pivots.
- [ ] Decision trees: generic, credential, malware.
- [ ] Documentation minimum note and writing rules.
- [ ] Handover contents; escalation quality.
- [ ] Mistakes table memorised.
- [ ] Metrics: MTTA, triage time, escalation/conversion, reopen, SLA, FP share.
