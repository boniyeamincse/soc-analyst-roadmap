# SOC Analyst L2 — Career Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← SOC Analyst L1](SOC-Analyst-L1.md) · [Threat Hunter →](Threat-Hunter.md)

> Goal: move from *verdicts* to *scope and stories* — and from individual contributor to force multiplier.
> Entry role → [SOC-Analyst-L1.md](SOC-Analyst-L1.md); specialisation → [Incident-Responder.md](Incident-Responder.md), [Threat-Hunter.md](Threat-Hunter.md), [Detection-Engineer.md](Detection-Engineer.md).

---

## 0. How to use this note

1. §1–§3: what changes at L2; responsibilities; a day in the life.
2. §4–§7: skills, investigation depth, mentoring, KPIs.
3. §8–§11: certs, interview, 90-day plan, growth.
4. §12–§14: mistakes, self-test, revision.

---

## 1. What changes at L2

| L1 | L2 |
|---|---|
| Verdict on an alert | Scope of an incident |
| Single event | Entity and estate |
| Follows playbook | Improves playbook |
| Escalates | Leads investigation |
| Documents | Writes the narrative |
| Learns tools | Teaches tools |

**L2 answers: "How far did this go, and what does it mean?"**

---

## 2. Responsibilities

1. Investigate complex/multi-stage alerts.
2. Scope incidents across hosts, identities, cloud.
3. Lead triage during critical events until IR arrives.
4. Mentor L1 and review their escalations.
5. Tune rules and reduce false positives.
6. Write and maintain playbooks.
7. Support threat hunts with data and context.
8. Produce incident narratives and timelines.
9. Coordinate with IT/IR/identity teams.
10. Report trends to SOC leadership.

---

## 3. A day in the life

| Activity | Share |
|---|---|
| Complex investigations | High |
| L1 support/review | Medium |
| Tuning and playbooks | Medium |
| Meetings/handover | Low-medium |
| Critical response | Intermittent |

### 3.1 The shift in mindset

L1 asks *"is this alert real?"*
L2 asks *"what else is true if this is real?"*

---

## 4. Skills

| Skill | Expectation |
|---|---|
| SIEM querying | Advanced (SPL/KQL) |
| Log correlation | Multi-source |
| Endpoint analysis | Process lineage, persistence |
| Identity analysis | Auth flows, tokens, MFA |
| Network | Flows, DNS, proxy, PCAP basics |
| Cloud | Control-plane audit |
| Forensics basics | Memory/disk triage |
| Detection | Sigma, rule tuning |
| Scripting | Automate repetitive work |
| Communication | Narratives + stakeholder updates |

### 4.1 Scoping skill

```
Entity → related entities → time window → corroborating sources
→ expand until no new hosts/accounts → state exclusions
```

**Scoping is the defining L2 skill.**

---

## 5. Investigation depth

| Question | L2 action |
|---|---|
| Was it executed? | Process tree + EDR |
| By whom? | Parent, user, service |
| How did it arrive? | Mail/proxy/USB/download |
| What did it touch? | Files, registry, network |
| Did it spread? | Auth logs, SMB, remote services |
| Is it still active? | Current connections, persistence |
| What data? | Access logs, volume, staging |
| Who else? | Estate sweep |

### 5.1 Narrative structure

```
1. Summary
2. Initial access
3. Execution and persistence
4. Discovery/lateral (if any)
5. Impact/data
6. Current status
7. Open questions
```

---

## 6. Mentoring

| Practice | Effect |
|---|---|
| Review escalations with feedback | Quality |
| Pair on complex alerts | Skill transfer |
| Share queries/shortcuts | Efficiency |
| Explain the "why" | Understanding |
| Encourage questions | Safety |
| Document decisions | Consistency |

**A good L2 makes the whole queue faster.**

---

## 7. KPIs

| KPI | Meaning |
|---|---|
| Scope accuracy | Initial vs final |
| Escalation quality | IR rework |
| Detection improvements | Rules tuned/added |
| Playbook coverage | Alerts with runbooks |
| Mentoring outcomes | L1 progression |
| MTTR contribution | Investigation speed |
| Narrative quality | Report acceptance |

---

## 8. Certifications

| Cert | Value |
|---|---|
| CySA+ | Analyst depth |
| Microsoft SC-200 | Sentinel/Defender |
| Splunk Power User | SPL |
| BTL2 / practical blue-team | Hands-on |
| GCIH | IR credibility |
| GCFA | Forensics (if heading IR) |

---

## 9. Interview

### 9.1 Questions

1. Walk me through scoping a compromised host.
2. How do you decide a host must be rebuilt?
3. Describe a multi-stage intrusion you reconstructed.
4. How do you tune a noisy rule safely?
5. How do you mentor a struggling L1?
6. How do you handle disagreement with IR?
7. What do you do when telemetry is missing?
8. How do you communicate uncertainty to leadership?
9. Show me a detection you improved and its impact.
10. How do you prioritise during an active incident?

### 9.2 What they assess

- Depth of reasoning.
- Scoping discipline.
- Quality of writing.
- Collaboration.
- Impact beyond own queue.

---

## 10. First 90 days

| Days | Focus |
|---|---|
| 1–14 | Learn environment, crown jewels, gaps |
| 15–30 | Take complex alerts, review with senior |
| 31–60 | Own scoping; propose 2 tunings |
| 61–90 | Write a playbook; mentor an L1 |

### 10.1 Questions to ask

- What are our top detection gaps?
- Which incidents went badly and why?
- Where is telemetry missing?
- Who owns each data source?
- How is IR handoff supposed to work?

---

## 11. Growth

| Direction | Next step |
|---|---|
| IR | Forensics, containment leadership |
| Hunting | Hypothesis design, ATT&CK |
| Detection | Rule engineering, CI |
| Cloud | IAM, cloud-native detection |
| Leadership | Shift lead, SOC manager |

---

## 12. Mistakes

| Mistake | Fix |
|---|---|
| Stopping at first host | Sweep the estate |
| Accepting L1 verdict blindly | Verify evidence |
| Tuning to silence noise | Fix the logic |
| Writing vague narratives | Timestamps + evidence |
| Doing all the work alone | Delegate/mentor |
| Ignoring business context | Ask asset owner |
| Over-escalating everything | Scope first |
| Under-escalating privileged cases | Escalate early |
| No follow-up on gaps | Track actions |
| Avoiding documentation | Template |

---

## 13. Self-test

1. What defines the L1→L2 shift?
2. What is scoping, and when do you stop?
3. List five L2 responsibilities.
4. What belongs in a narrative?
5. How do you tune without hiding attacks?
6. How do you mentor effectively?
7. Which KPIs matter at L2?
8. Which certs support L2?
9. What do interviewers test?
10. Where can an L2 specialise?

---

## 14. Revision checklist

- [ ] L2 = scope + narrative + improvement.
- [ ] Ten responsibilities.
- [ ] Mindset shift from alert to implication.
- [ ] Skill table incl. scoping.
- [ ] Investigation depth questions.
- [ ] Narrative structure.
- [ ] Mentoring practices.
- [ ] KPIs.
- [ ] Certifications.
- [ ] Interview questions/assessment.
- [ ] 90-day plan.
- [ ] Growth directions.
- [ ] Mistakes memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← SOC Analyst L1](SOC-Analyst-L1.md) · [Threat Hunter →](Threat-Hunter.md)
