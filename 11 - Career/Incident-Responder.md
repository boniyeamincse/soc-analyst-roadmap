# Incident Responder — Career Study Notes

> Goal: understand the IR role — the decisions, the pressure, the evidence, and the writing that follows.
> IR phases → `08 - Incident Response/`; forensics practice → `10 - Practice/CyberDefenders.md`.

---

## 0. How to use this note

1. §1–§3: the role; how it differs; responsibilities.
2. §4–§7: skills; incident leadership; evidence; communication.
3. §8–§11: work rhythm; tools; certs; metrics.
4. §12–§15: interview, portfolio, 90-day plan, mistakes.
5. §16–§18: self-test, revision.

---

## 1. What an incident responder is

> **Incident responder** = the person who leads an organisation through a confirmed security incident — scoping it, stopping it, removing it, and restoring safely.

| SOC analyst | Incident responder |
|---|---|
| Detects and triages | Owns the incident |
| Escalates | Decides |
| Follows playbook | Adapts playbook |
| Documents alerts | Writes the record |
| Single queue | Whole organisation |

**The job is judgement under uncertainty, not just tools.**

---

## 2. Responsibilities

1. Lead or support incident command.
2. Scope the compromise.
3. Decide containment strategy.
4. Preserve evidence and chain of custody.
5. Coordinate IT, identity, legal, comms.
6. Drive eradication and recovery.
7. Communicate status on a cadence.
8. Produce the incident report and RCA.
9. Run lessons learned.
10. Improve readiness (playbooks, drills).

---

## 3. Types of work

| Type | Character |
|---|---|
| **Retainer/consulting** | Travel, varied clients, fast context-switching |
| **In-house IR** | Deep environment knowledge, on-call |
| **MSSP IR** | Many clients, process-heavy |
| **DFIR lab** | Deep forensics, legal cases |
| **Cloud IR** | Identity/control-plane focus |

### 3.1 Reality check

- Long hours during incidents.
- On-call rotations.
- High-stakes communication.
- Legal and executive exposure.
- Emotionally heavy cases (ransomware, insider, data breach).

---

## 4. Skills

| Skill | Depth |
|---|---|
| IR process (PICERL) | Expert |
| Forensics (memory/disk) | Strong |
| Windows/Linux internals | Strong |
| Network analysis | Strong |
| Cloud (Entra/AWS/Azure) | Working → strong |
| Malware triage | Working |
| Log analysis | Expert |
| Threat intel | Working |
| Containment tooling | Expert |
| Legal/regulatory basics | Working |

### 4.1 Non-technical skills

| Skill | Why |
|---|---|
| Decision-making under uncertainty | Core of the role |
| Clear writing | Reports, regulator |
| Executive communication | Business impact |
| Negotiation | Containment vs uptime |
| Calm | Everyone looks to you |
| Facilitation | Lessons learned |

---

## 5. Incident leadership

### 5.1 Incident command

| Function | Owner |
|---|---|
| Decisions | IC |
| Technical direction | Lead investigator |
| Comms | Comms lead |
| Documentation | Scribe |
| Liaison | Legal/business |

### 5.2 Decision principles

- Decide with incomplete information.
- Prefer reversible actions.
- Document the trade-off.
- Communicate the *why*, not just the *what*.
- Re-evaluate as evidence changes.

### 5.3 Tempo

```
assess → act → observe → adapt
```

Set update cadence (e.g. every 60 min) and stick to it.

---

## 6. Evidence

| Requirement | Practice |
|---|---|
| Integrity | Hash on acquisition |
| Chain of custody | Document transfers |
| Order of volatility | Memory before disk |
| Preservation vs containment | Record choice |
| Legal hold | Notify legal early |
| Retention | Beyond investigation |

**If it may reach a regulator or court, treat it as evidence from minute one.**

---

## 7. Communication

| Audience | Content |
|---|---|
| Exec | Impact, risk, timeline, decisions needed |
| IT | Technical actions, dependencies |
| Legal | Facts, scope, notification triggers |
| Comms/PR | Approved statements only |
| Customers | Per legal |
| Regulator | Per law |

### 7.1 Writing rules

- Facts vs inference.
- No speculation on attribution.
- No blame.
- Time-stamped.
- Plain language for executives.

---

## 8. Work rhythm

### 8.1 During an incident

| Phase | Hours |
|---|---|
| First 24 h | Intense, continuous |
| Days 2–7 | Sustained, shift-based |
| Weeks 2–4 | Recovery, reporting |
| Post | Lessons learned |

### 8.2 Sustainment

- Rotate responders.
- Sleep and food are operational requirements.
- Scribe reduces IC load.
- Escalate to outside IR when capacity is exceeded.

---

## 9. Tools

| Category | Tools |
|---|---|
| Forensics | Volatility, KAPE, AXIOM, EnCase, FTK |
| Timeline | Timesketch, Plaso |
| EDR | CrowdStrike, Defender, SentinelOne |
| Network | Wireshark, Zeek, NetFlow |
| Cloud | CloudTrail, Entra logs, GCP audit |
| Malware | Sandboxes, YARA, capa |
| Case | TheHive, Cortex, spreadsheets |
| Comms | Out-of-band channels |

---

## 10. Certifications

| Cert | Value |
|---|---|
| GCIH | IR fundamentals |
| GCFA | Forensics |
| GNFA | Network forensics |
| GCFE | Windows forensics |
| EnCE | Enterprise forensics |
| CCFP | Cyber forensics |
| Cloud certs (SC-200, AWS Sec) | Cloud IR |

**Pair certs with real case writeups.**

---

## 11. Metrics

| Metric | Meaning |
|---|---|
| Time to contain | Response speed |
| Dwell time | Detection gap |
| Scope accuracy | Investigation quality |
| Recovery time vs RTO | Resilience |
| Notification timeliness | Compliance |
| Recurrence | Effectiveness |
| Client/exec satisfaction | Trust |

---

## 12. Interview

1. Walk me through your last incident end to end.
2. How do you decide to isolate vs monitor?
3. What do you do when the attacker is active and you lack scope?
4. How do you handle a ransomware negotiation decision?
5. How do you preserve evidence under pressure?
6. How do you communicate bad news to executives?
7. Tell me about a decision you got wrong.
8. How do you run a lessons-learned session?
9. What would you do if backups were also encrypted?
10. How do you handle legal notification deadlines?

### 12.1 What they assess

- Structured thinking.
- Ownership.
- Communication.
- Judgement, not just tools.
- Humility about uncertainty.

---

## 13. Portfolio

| Artefact | Value |
|---|---|
| Anonymised case study | Core evidence |
| Timeline + control-failure table | Analysis skill |
| RCA excerpt | Reasoning |
| Playbook you wrote | Readiness |
| Tabletop design | Leadership |

---

## 14. First 90 days

| Days | Focus |
|---|---|
| 1–14 | Environment, crown jewels, contacts, playbooks |
| 15–30 | Shadow incidents, learn tooling |
| 31–60 | Lead containment on a small case |
| 61–90 | Run a tabletop; update a playbook |

### 14.1 Questions to ask

- What incidents went badly, and why?
- Where is telemetry missing?
- Who decides external notification?
- What are the legal deadlines?
- Which vendors are retained?

---

## 15. Mistakes

| Mistake | Fix |
|---|---|
| Acting before scoping | Scope while containing |
| Destroying evidence | Preserve first |
| Hero mode | Rotate, delegate |
| Speculating publicly | Legal-approved comms |
| Ignoring legal clock | Engage early |
| Over-isolating | Least disruption |
| No scribe | Assign one |
| Declaring victory early | Monitor window |
| Skipping lessons learned | Schedule it |
| No residual-risk statement | State it |

---

## 16. Growth

| Direction | Next |
|---|---|
| DFIR | Deeper forensics |
| IR management | Program building |
| Threat intel | Actor tracking |
| Cloud IR | Cloud-native specialisation |
| Consulting | Client-facing leadership |

---

## 17. Self-test

1. How does IR differ from SOC?
2. List six responsibilities.
3. What is incident command?
4. What are the decision principles?
5. What is order of volatility?
6. How do you communicate with executives?
7. How do you sustain a multi-day response?
8. Which certs support IR?
9. Which metrics matter?
10. What makes a strong interview answer?

---

## 18. Revision checklist

- [ ] Role: owns incident, decides, communicates.
- [ ] Responsibilities 1–10.
- [ ] Work types and reality check.
- [ ] Technical + non-technical skills.
- [ ] Incident command functions.
- [ ] Decision principles + tempo.
- [ ] Evidence requirements.
- [ ] Communication by audience + writing rules.
- [ ] Work rhythm and sustainment.
- [ ] Tools.
- [ ] Certs.
- [ ] Metrics.
- [ ] Interview questions/assessment.
- [ ] Portfolio.
- [ ] 90-day plan.
- [ ] Mistakes memorised.
