# Identification — Incident Response Study Notes

> Goal: decide *fast and correctly* whether this is an incident, how severe, who owns it, and what must happen in the first hour.
> Triage mechanics → `07 - Investigation/Alert-Triage.md`; lifecycle → this and following files.

---

## 0. How to use this note

1. §1–§3: IR frameworks; event vs incident; the five phases.
2. §4–§7: declaration criteria, severity, scoping, roles.
3. §8–§12: first-hour actions, evidence preservation, notification, comms, documentation.
4. §13–§16: legal/regulatory, escalation, metrics, readiness.
5. §17–§19: pitfalls, labs, templates.
6. §20–§21: self-test, revision.

---

## 1. Frameworks

| Framework | Phases |
|---|---|
| **NIST SP 800-61** | Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity |
| **SANS PICERL** | Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned |
| **ISO 27035** | Plan → Detect → Assess → Respond → Learn |

**PICERL is the working vocabulary in most SOCs.** They are compatible — use one and be consistent.

---

## 2. Event vs incident

| Term | Definition | Example |
|---|---|---|
| **Event** | Observable occurrence | Failed login |
| **Alert** | Detection match | 50 failures |
| **Incident** | Confirmed or suspected harm requiring response | Successful login after spray |
| **Crisis** | Incident with major business/legal impact | Ransomware on prod |

### 2.1 Incident criteria

Declare when **any** of:

- Confirmed unauthorised access.
- Malware execution with persistence/C2.
- Data exposure or exfiltration.
- Privileged account compromise.
- Multiple hosts affected.
- Business service degradation from attack.
- Regulatory notification likely.
- Uncertainty + high potential impact.

**When in doubt about a critical asset — declare.** False alarms are cheaper than delay.

---

## 3. The phases

```
Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned
                  ↑______________________________________________|
                              (iteration / re-scope)
```

### 3.1 Non-linear reality

- New evidence → back to identification.
- Containment incomplete → re-contain.
- Eradication finds more → re-scope.
- Recovery reveals persistence → back to eradication.

**The model is a checklist, not a waterfall.**

---

## 4. Detection sources

| Source | Signal |
|---|---|
| SIEM alerts | Rules |
| EDR | Behavioural detections |
| User reports | Phishing, odd behaviour |
| Helpdesk | Account lockouts, "slow PC" |
| Third party | Customer, vendor, CERT, law enforcement |
| Threat intel | Actor targeting you |
| Audit/compliance | Control failure |
| Backups | Integrity failure |
| Physical security | Badge anomalies |

**User reports are a top source — make reporting easy.**

---

## 5. Initial assessment

### 5.1 Questions in the first 15 minutes

1. What is confirmed vs suspected?
2. Which assets, accounts, data?
3. Is the attacker still active?
4. What is the business impact?
5. Is this contained by existing controls?
6. Do we need to declare?
7. Who must be told now?

### 5.2 Facts to capture

```
Detection time (UTC)
Reporter/source
Observed behaviour
Affected entities
Evidence locations
Actions already taken
Current status (active/contained/unknown)
```

---

## 6. Severity

| Severity | Criteria | Response |
|---|---|---|
| **Critical (P1)** | Crown jewels, ransomware, mass outage, active exfil | Full IR, exec/legal, 24×7 |
| **High (P2)** | Privileged compromise, multiple hosts, sensitive data risk | IR team, immediate |
| **Medium (P3)** | Single host malware contained, limited data | IR during hours |
| **Low (P4)** | Policy violation, unsuccessful attempt | Ticketed |
| **Info** | Suspicious but no impact | Monitor |

### 6.1 Scoring inputs

| Factor | Weight |
|---|---|
| Asset criticality | High |
| Data sensitivity | High |
| Scope (hosts/users) | High |
| Privilege level | High |
| Attacker activity (active?) | High |
| Regulatory exposure | High |
| Business disruption | Medium |
| Public visibility | Medium |

### 6.2 Severity can change

Re-score at every phase gate. Most incidents are reclassified at least once.

---

## 7. Roles

| Role | Responsibility |
|---|---|
| **Incident Commander (IC)** | Owns decisions and tempo. |
| **Lead investigator** | Technical direction. |
| **SOC analysts** | Monitoring, triage, evidence. |
| **IR/forensics** | Deep analysis, acquisition. |
| **IT ops** | Isolation, restore, patching. |
| **Legal/compliance** | Notification, privilege, evidence. |
| **Comms/PR** | External messaging. |
| **HR** | Insider cases. |
| **Executive sponsor** | Business decisions, budget. |
| **Scribe** | Timeline and decisions. |

### 7.1 Small-team reality

One person may hold several roles — but **write down who is IC**. Ambiguity is the enemy in the first hour.

### 7.2 IC principles

- One decision-maker.
- Communicate on a cadence, not constantly.
- Decide with incomplete information.
- Record every decision and why.

---

## 8. Scoping

### 8.1 Scope questions

- Which hosts, users, accounts, cloud resources?
- Which data was accessed?
- How far back does activity go?
- Are there other entry points?
- Are backups affected?

### 8.2 Scoping techniques

| Technique | Use |
|---|---|
| IOC sweep | Hash/domain/IP across estate |
| Entity pivot | User → hosts → services |
| Timeline window | Events before first alert |
| Control-plane audit | Cloud/IAM changes |
| Network flow analysis | C2/exfil destination |
| Endpoint sweep | Persistence artefacts |

### 8.3 Scope statement

```
Confirmed: 3 hosts, 1 service account
Suspected: 2 hosts (pending triage)
Excluded: 40 hosts checked by hash, none present
Unknown: mailbox access scope
```

**Explicitly state what you ruled out.**

---

## 9. First-hour actions

| Priority | Action |
|---|---|
| 1 | Confirm the incident and assign IC |
| 2 | Preserve volatile evidence |
| 3 | Stop active attacker access (if safe) |
| 4 | Notify per matrix |
| 5 | Establish comms channel |
| 6 | Start the incident log |
| 7 | Begin scoping |
| 8 | Set next update time |

### 9.1 Do not

- Reimage before acquisition.
- Reset accounts before understanding access.
- Delete malware without hashing.
- Broadcast speculation.
- Contact the attacker.
- Work in an unlogged ad-hoc chat.

---

## 10. Evidence preservation

### 10.1 Order of volatility

```
CPU/registers → memory → network state → processes
→ disk → remote logs → backups → archival
```

### 10.2 Acquisition rules

| Rule | Why |
|---|---|
| Hash every artefact | Integrity. |
| Record collector, time, tool | Chain of custody. |
| Prefer forensic copy | Preserve origin. |
| Capture memory before reboot | Volatile. |
| Export logs before retention expiry | Loss. |
| Store read-only | Tamper evidence. |

### 10.3 Chain of custody

```
Item ID | description | source | collected by | time | hash | storage | transfers
```

**If it may go to court or a regulator, treat it as evidence from minute one.**

---

## 11. Notification

### 11.1 Internal matrix

| Severity | Notify | When |
|---|---|---|
| Critical | IC, CISO, CTO, Legal, Comms, Exec | Immediately |
| High | IC, SOC lead, IT ops, CISO | 30 min |
| Medium | SOC lead, asset owner | 2 h |
| Low | Queue/ticket | Daily |

### 11.2 External

| Party | When |
|---|---|
| Regulator | Per law (e.g. 72 h GDPR) |
| Law enforcement | Per policy/legal advice |
| Customers | Per contract/law |
| Insurer | Per policy |
| CERT/ISAC | Voluntary/required |
| Vendors | If their product involved |

**Legal decides external notification — not the SOC.**

---

## 12. Communication

### 12.1 Principles

- Single source of truth (incident log).
- Scheduled updates ("next update 14:00").
- Facts, impact, actions, next steps.
- No speculation about attribution.
- No blame.

### 12.2 Update template

```
Status: investigating / contained / eradicating / recovering
Confirmed: ...
Impact: ...
Actions since last update: ...
Next steps: ...
Next update: <time>
```

### 12.3 External messaging

Legal/comms owns wording. Technical staff should not speak publicly.

---

## 13. Documentation

### 13.1 Incident log

| Field | Content |
|---|---|
| Timestamp (UTC) | Every entry |
| Author | Who |
| Type | Observation/decision/action/comms |
| Content | Fact and rationale |
| Evidence ref | Link/ID |

### 13.2 Why it matters

- Continuity across shifts.
- Legal defensibility.
- Lessons learned input.
- Metrics.

**If it isn't written, it didn't happen.**

---

## 14. Legal and regulatory

| Regime | Trigger | Clock |
|---|---|---|
| GDPR | Personal data breach | 72 h to authority |
| HIPAA | PHI breach | 60 days to individuals |
| PCI DSS | Cardholder data | Per acquirer |
| NIS2 | Essential services | 24 h early warning |
| SEC | Material cyber incident (US public co.) | 4 business days |
| Sector rules | Finance/health/energy | Varies |

### 14.1 Actions

- Engage legal early.
- Preserve evidence for regulators.
- Document decisions and timing.
- Do not delay notification to "finish investigating" if the law requires prompt notice.

---

## 15. Escalation

### 15.1 Escalate when

- Scope exceeds initial estimate.
- Attacker is active and evading.
- Crown jewels involved.
- Legal/regulatory thresholds met.
- Response capacity exhausted.
- Insider suspected.
- Media attention.

### 15.2 External support

| Option | Use |
|---|---|
| Retained IR firm | Major incidents. |
| Cyber insurer panel | Per policy. |
| Law enforcement | Criminal/legal. |
| Cloud provider IR | Cloud-native incidents. |
| Malware lab | Novel samples. |

**Activate early — retainers have onboarding time.**

---

## 16. Metrics

| Metric | Definition |
|---|---|
| Time to detect | Event → detection |
| Time to declare | Detection → declaration |
| Time to contain | Declaration → containment |
| Dwell time | Initial access → detection |
| Scope accuracy | Initial vs final |
| Notification timeliness | Within legal window |
| Reopen rate | Incidents returning |
| Cost | Hours, fines, downtime |

---

## 17. Pitfalls

| Pitfall | Consequence |
|---|---|
| Delaying declaration | Attacker freedom. |
| No IC | Conflicting actions. |
| Reimaging too early | Evidence lost. |
| Resetting before scoping | Attacker re-enters. |
| Siloed comms | Inconsistent messages. |
| Speculating publicly | Legal/reputational harm. |
| Ignoring legal clock | Fines. |
| No log | Unverifiable response. |
| Under-scoping | Recurrence. |
| Hero culture | Burnout, mistakes. |

---

## 18. Labs

1. Write declaration criteria for your org.
2. Score 5 scenarios with the severity matrix.
3. Fill the first-hour checklist for a ransomware alert.
4. Draft an internal notification for P1.
5. Build an evidence chain-of-custody form.
6. Write a scope statement with confirmed/excluded/unknown.
7. Practise an IC decision log for 30 minutes.
8. Map your legal notification obligations.
9. Run a tabletop exercise to declaration.
10. Measure time-to-declare on a drill.

---

## 19. Templates

### 19.1 Incident declaration

```
Incident ID:
Title:
Declared by / IC:
Time declared (UTC):
Detection source:
Severity / priority:
Confirmed facts:
Affected entities:
Current status:
Immediate actions:
Notifications sent:
Next update:
```

### 19.2 Scope statement

```
Confirmed:
Suspected:
Excluded:
Unknown:
Method:
Last updated:
```

---

## 20. Self-test questions

1. Event vs alert vs incident vs crisis.
2. Name the PICERL phases.
3. When do you declare an incident?
4. What are the first 15-minute questions?
5. What inputs drive severity?
6. Who is the IC and what do they do?
7. How do you scope an incident?
8. What is order of volatility?
9. What belongs in chain of custody?
10. Who decides external notification?
11. What belongs in the incident log?
12. Name three regulatory clocks.
13. When do you escalate?
14. Which metrics matter?
15. Why is early declaration usually right?

---

## 21. One-page revision checklist

- [ ] Frameworks: NIST 800-61, PICERL, ISO 27035.
- [ ] Event → alert → incident → crisis.
- [ ] Declaration criteria; declare when impact is high or uncertain.
- [ ] Phases are iterative, not waterfall.
- [ ] Detection sources incl. user reports.
- [ ] First 15-minute questions; facts to capture.
- [ ] Severity P1–P4 + inputs; re-score at gates.
- [ ] Roles incl. IC, scribe, legal, comms; one decision-maker.
- [ ] Scoping techniques and scope statement format.
- [ ] First-hour actions and "do not" list.
- [ ] Order of volatility, acquisition rules, chain of custody.
- [ ] Internal/external notification matrix; legal owns external.
- [ ] Comms principles and update template.
- [ ] Incident log fields; "not written = not happened".
- [ ] Regulatory clocks (GDPR 72h, HIPAA 60d, NIS2 24h, SEC 4d).
- [ ] Escalation triggers and external support.
- [ ] Metrics: detect/declare/contain, dwell, scope accuracy.
- [ ] Pitfalls memorised.
