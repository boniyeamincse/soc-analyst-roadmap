# Lessons Learned — Incident Response Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Identification](Identification.md) · [Recovery →](Recovery.md)

> Goal: convert an incident into durable improvement — better detections, faster response, fewer repeats.
> Causal analysis → [07 - Investigation/Root-Cause-Analysis.md](../07%20-%20Investigation/Root-Cause-Analysis.md); the response phases → earlier files in this folder.

---

## 0. How to use this note

1. §1–§3: purpose; timing; participants.
2. §4–§6: the review meeting; what to examine; detection and response performance.
3. §7–§10: action tracking; knowledge capture; communicating lessons; maturity.
4. §11–§14: templates, metrics, pitfalls, anti-patterns.
5. §15–§17: labs, self-test, revision.

---

## 1. Purpose

> **Lessons learned** = a structured review that turns incident experience into verified improvements.

### 1.1 It is not

| Not | Why |
|---|---|
| Blame session | Destroys reporting. |
| A timeline read-out | That's documentation. |
| The RCA document | RCA explains cause; LL drives change. |
| Optional | Incidents repeat without it. |
| A complaint list | Needs owned actions. |

### 1.2 Outputs

1. What happened (shared understanding).
2. What worked.
3. What didn't.
4. Root causes (linked).
5. Actions with owners and dates.
6. Detection/response improvements.
7. Updated runbooks and knowledge base.

---

## 2. Timing

| Window | Rationale |
|---|---|
| **Within 5 days** | Memory fresh. |
| **After containment** | Team not firefighting. |
| **Before closure** | While authority exists. |
| **Separate from RCA** | RCA may take longer. |

**Do not wait weeks — details and goodwill evaporate.**

---

## 3. Participants

| Role | Contribution |
|---|---|
| IC | Decisions and trade-offs. |
| Responders | What they saw and did. |
| Detection engineer | Rule performance. |
| IT ops | System behaviour. |
| Business owner | Impact reality. |
| Legal/compliance | Obligations. |
| Facilitator | Process, not blame. |
| Scribe | Actions and notes. |

### 3.1 Facilitation

- Neutral facilitator (not the IC).
- Everyone speaks.
- Facts before opinions.
- No hierarchy in the room.
- Time-boxed agenda.

---

## 4. The review meeting

### 4.1 Agenda (60–90 min)

```
1. Ground rules + blameless statement       5 min
2. Timeline walkthrough                    15 min
3. What worked                             10 min
4. What didn't                             20 min
5. Detection performance                   10 min
6. Response performance                    10 min
7. Actions and owners                      15 min
8. Close + next steps                       5 min
```

### 4.2 Ground rules

- We assume good intent.
- We discuss systems, not people.
- We separate "what happened" from "what should happen".
- Disagreement is welcome; evidence decides.
- Everything said stays constructive.

---

## 5. What to examine

### 5.1 Detection

| Question | Evidence |
|---|---|
| How was it detected? | Alert, report, third party |
| How long after initial access? | Dwell time |
| Which rule fired? | Rule ID |
| Did any rule miss it? | Gap analysis |
| Was the alert actionable? | Triage time |
| Was it noisy? | FP rate |
| Was the data available? | Telemetry check |

### 5.2 Response

| Question | Evidence |
|---|---|
| Time to acknowledge? | MTTA |
| Time to declare? | Log |
| Time to contain? | Log |
| Correct severity? | Re-score |
| Right people involved? | Roster |
| Comms effective? | Feedback |
| Evidence preserved? | Custody log |
| Decisions documented? | IC log |

### 5.3 Controls

| Question | Evidence |
|---|---|
| Which controls should have stopped it? | Control map |
| Why didn't each? | RCA |
| Which worked? | Evidence |
| What was missing? | Gap list |

### 5.4 Business

| Question |
|---|
| What was the real impact? |
| What did the business need? |
| Were workarounds adequate? |
| Was communication timely and accurate? |

---

## 6. Metrics to review

| Metric | Compare to |
|---|---|
| Dwell time | Baseline/target |
| Time to detect | SLO |
| Time to declare | Target |
| Time to contain | SLA |
| Time to recover | RTO |
| Scope accuracy | Initial vs final |
| Escalation accuracy | Correct team? |
| False-positive cost | Baseline |
| Reopen/recurrence | Zero goal |

**One incident is an anecdote; trend across incidents is evidence.**

---

## 7. Action tracking

### 7.1 Action quality

| Good action | Bad action |
|---|---|
| "Add Sigma rule X by 15 May, owner DE" | "Improve detection" |
| "Close legacy auth by 30 June, owner IAM" | "Enforce MFA" |
| "Test restore quarterly, owner IT" | "Test backups" |

### 7.2 Categories

| Category | Example |
|---|---|
| Detection | New/tuned rule |
| Prevention | Patch, config, policy |
| Response | Playbook, tooling, access |
| Process | Approval, review cadence |
| Training | Specific skill gap |
| Communication | Notification matrix |

### 7.3 Tracking rules

- Owner named (person, not team).
- Due date.
- Measurable completion.
- Verified effective.
- Reviewed in a standing meeting.
- Escalated if overdue.

**Actions without owners and dates are wishes.**

---

## 8. Knowledge capture

| Artefact | Update |
|---|---|
| Runbooks | Steps that were missing. |
| Detection rules | New logic, tuning. |
| Playbooks | Decision points. |
| Asset inventory | Unknown assets found. |
| Contact lists | Who was needed. |
| Tool docs | Workarounds. |
| Training material | Case study. |

### 8.1 Case library

Store anonymised incidents for training:

```
Scenario | what happened | signals | decisions | outcome | lessons
```

**Use them in onboarding and tabletops.**

---

## 9. Communicating lessons

| Audience | Format |
|---|---|
| SOC team | Detailed debrief |
| IT | Technical summary + actions |
| Exec | 1-page impact + improvements |
| Organisation | Awareness note (if useful) |
| Regulator | Per obligation |

### 9.1 Sharing balance

Share enough to prevent repeats; redact enough to protect systems and people.

---

## 10. Maturity

| Level | Practice |
|---|---|
| 1 | No reviews |
| 2 | Ad-hoc after major incidents |
| 3 | Scheduled for all P1/P2 |
| 4 | All incidents; tracked actions |
| 5 | Trend analysis; proactive improvement |

**Level 5 uses incident data to drive roadmap and detection investment.**

---

## 11. Templates

### 11.1 Review record

```
Incident ID / date / severity
Participants
Timeline summary (link)
What worked:
What didn't:
Root causes (link to RCA):
Detection performance:
Response performance:
Actions:
  ID | action | owner | due | type | validation
Follow-up review date:
```

### 11.2 Executive summary

```
What happened (2 lines)
Impact (1 line)
How we found it (1 line)
What we fixed (2–3 bullets)
What remains (1–2 bullets)
```

---

## 12. Metrics programme

| Measure | Purpose |
|---|---|
| % incidents reviewed | Coverage |
| Actions closed on time | Follow-through |
| Recurrence rate | Effectiveness |
| Median time to close actions | Tempo |
| Detection rules added/tuned | Improvement |
| Repeat FP after tuning | Quality |

---

## 13. Pitfalls

| Pitfall | Consequence |
|---|---|
| Blame | Hidden incidents |
| No facilitator | Dominated discussion |
| Too many actions | None done |
| No owners/dates | No progress |
| No validation | False closure |
| Review skipped | Repeat incident |
| Only technical view | Business gaps missed |
| No trend analysis | Systemic issues invisible |
| Lessons not shared | Others repeat |
| Actions not prioritised | Trivial wins over risk |

---

## 14. Anti-patterns

| Anti-pattern | Fix |
|---|---|
| "User error, retrain" | System/control fix |
| "Add to watchlist" | Real control |
| 40 actions | Top 5 by risk |
| Review 6 months later | Within 5 days |
| Only managers attend | Include responders |
| Report filed, never read | Standing agenda item |

---

## 15. Labs

1. Facilitate a mock review for a phishing incident.
2. Write 5 actions with owners, dates, validation.
3. Convert a bad action into a good one.
4. Build a case-library entry.
5. Draft an executive summary.
6. Trend 5 incidents and find a systemic theme.
7. Update a runbook from a review.
8. Design an action-tracking board.
9. Measure recurrence across 3 incidents.
10. Present lessons to a non-technical audience.

---

## 16. Self-test questions

1. What is lessons learned, and what is it not?
2. Who facilitates and why not the IC?
3. When should it happen?
4. What belongs in the agenda?
5. What detection questions do you ask?
6. What response questions do you ask?
7. What makes a good action?
8. How do you track actions?
9. What artefacts get updated?
10. How do you share lessons safely?
11. What are the maturity levels?
12. How do you measure programme effectiveness?
13. Name three pitfalls and fixes.
14. Why is "retrain users" usually a bad action?
15. What is a case library for?

---

## 17. One-page revision checklist

- [ ] Lessons learned = structured, blameless review → verified change.
- [ ] Within 5 days; after containment; before closure.
- [ ] Participants and neutral facilitator.
- [ ] 60–90 min agenda with ground rules.
- [ ] Examine detection, response, controls, business.
- [ ] Metrics: dwell, detect/declare/contain/recover, scope accuracy, recurrence.
- [ ] Actions: owner, date, measurable, validated, tracked.
- [ ] Update runbooks, rules, playbooks, inventory, contacts, training.
- [ ] Case library for onboarding/tabletop.
- [ ] Communication by audience.
- [ ] Maturity 1–5.
- [ ] Programme metrics.
- [ ] Pitfalls and anti-patterns memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Identification](Identification.md) · [Recovery →](Recovery.md)
