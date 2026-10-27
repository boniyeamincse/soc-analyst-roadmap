# Root Cause Analysis — SOC Analyst Study Notes

> Goal: move from *what happened* to *why it was possible* — and produce fixes that actually prevent recurrence.
> Timeline construction → `Timeline-Analysis.md`; post-incident process → `08 - Incident Response/Lessons-Learned.md`.

---

## 0. How to use this note

1. §1–§3: what RCA is; proximate vs root; causal models.
2. §4–§8: methods — 5 Whys, fishbone, fault tree, Kepner-Tregoe, causal chain.
3. §9–§12: human/organisational factors; evidence; hypothesis testing.
4. §13–§16: corrective actions; validation; report template; blameless practice.
5. §17–§19: examples, pitfalls, labs.
6. §20–§21: self-test, revision.

---

## 1. What RCA is

> **Root Cause Analysis** = a structured method to determine *why* an incident occurred, distinguish causes from symptoms, and identify changes that prevent recurrence.

### 1.1 RCA is not

| Not this | Because |
|---|---|
| Blame assignment | People are part of the system. |
| A narrative of the incident | That's the timeline. |
| "User clicked the link" | That's a proximate cause. |
| A single fix guess | Needs verification. |
| A checklist | Needs reasoning. |

### 1.2 RCA outputs

1. Causal chain with evidence.
2. Root cause(s) and contributing factors.
3. Corrective actions, owners, dates.
4. Detection/prevention improvements.
5. Residual risk statement.

---

## 2. Proximate vs root cause

| Level | Example (ransomware) |
|---|---|
| **Symptom** | Files encrypted. |
| **Proximate cause** | Ransomware executed on workstation. |
| **Intermediate** | User opened a malicious attachment. |
| **Deeper** | Macro execution enabled; no attachment sandboxing. |
| **Root** | Email security control was not applied to that sender class; change process never validated the gap. |
| **Systemic** | No control-effectiveness testing programme; risk accepted without owner. |

### 2.1 Rule

**Stop when the next "why" is outside your ability to change — or when changing it would have prevented this class of incident, not just this instance.**

### 2.2 Class vs instance

| Fix scope | Example |
|---|---|
| Instance | Block that one domain. |
| Class | Block executable macro attachments from external senders. |
| Systemic | Quarterly control-effectiveness testing. |

**Instance fixes are not RCA outcomes.**

---

## 3. Causal models

### 3.1 Linear chain

```
A → B → C → incident
```

Useful for simple incidents; hides alternatives.

### 3.2 Branching tree

```
            incident
           /        \
      path 1        path 2
     /     \       /     \
   cause  cause  cause  cause
```

Better for "why did the control fail?"

### 3.3 Swiss cheese

Each layer has holes; the incident occurred because holes aligned.

| Layer | Hole |
|---|---|
| Email filter | Missed attachment type |
| Endpoint AV | Signature not updated |
| EDR | Rule not tuned |
| User training | Unreported |
| Network | Egress allowed |
| Detection | No rule for behaviour |

**Fix the alignment, not one slice.**

### 3.4 Defence-in-depth reasoning

Ask: *which controls should have stopped this, and why didn't each one?*

---

## 4. 5 Whys

### 4.1 Method

```
1. Why were files encrypted?      → ransomware ran on WS-014.
2. Why did it run?                → user opened invoice.docm.
3. Why did the macro execute?     → macros allowed for internet files.
4. Why were they allowed?         → GPO exception from 2023 never reviewed.
5. Why was it never reviewed?     → no owner for macro policy; no review cadence.
```

### 4.2 Rules

- One cause per answer.
- Ground each answer in evidence.
- Branch when there are multiple plausible causes.
- Don't stop at "human error".
- Verify the chain top-down and bottom-up.

### 4.3 Failure modes

| Failure | Result |
|---|---|
| Single chain only | Misses contributing factors. |
| Stopping at person | No systemic fix. |
| Guessing | Wrong corrective action. |
| Going too deep | Unactionable philosophy. |

---

## 5. Fishbone (Ishikawa)

### 5.1 Categories for security incidents

| Branch | Questions |
|---|---|
| **People** | Training, phishing susceptibility, staffing, handover. |
| **Process** | Change control, approvals, review cadence, runbooks. |
| **Technology** | Controls, configuration, coverage, patching. |
| **Tooling** | Detection rules, alerting, logging. |
| **Environment** | Architecture, segmentation, legacy systems. |
| **External** | Vendor, threat actor, supply chain. |

### 5.2 Use

List all candidate causes per branch, then test each against evidence. Fishbone is for **breadth**, not proof.

---

## 6. Fault tree analysis

### 6.1 Structure

```
        Incident
           AND
     /             \
 Control A       Control B
   failed          failed
     OR              OR
  /    \           /   \
misconf  off    no rule  untuned
```

Use AND/OR gates to express how failures combine.

### 6.2 When to use

- Complex control failures.
- Safety/compliance-relevant incidents.
- Recurring incidents with the same shape.

### 6.3 Quantification (optional)

Assign probabilities to leaves to estimate likelihood and prioritise fixes. **Even rough estimates beat intuition.**

---

## 7. Kepner-Tregoe

### 7.1 Four dimensions

| Dimension | Question |
|---|---|
| **What** | Object and defect. |
| **Where** | Location, geographically/technically. |
| **When** | First/last seen, pattern, cycle. |
| **Extent** | How many, how much, how severe. |

### 7.2 Is / Is Not

| | Is | Is not | Distinction |
|---|---|---|---|
| What | WS-014 encrypted | Other hosts | What's unique about WS-014? |
| Where | Finance subnet | Other subnets | Segmentation? |
| When | 02:10 UTC | Business hours | Scheduled job? |
| Extent | 1 host | 400 hosts | Why only one? |

**Distinctions and changes point to cause.**

### 7.3 Change analysis

"What changed?" — patch, config, new tool, new hire, new vendor, new rule.

---

## 8. Causal chain for security incidents

### 8.1 Standard chain

```
Exposure (attacker access path)
 → Initial access (how)
 → Execution (payload)
 → Persistence
 → Privilege escalation
 → Lateral movement
 → Collection/exfiltration
 → Impact
```

At each step ask: **which control should have stopped it, and why didn't it?**

### 8.2 Control-failure table

| Stage | Expected control | Actual | Why it failed |
|---|---|---|---|
| Initial access | Email filtering | Partial | `docm` not blocked |
| Execution | Macro policy | Disabled | GPO exception |
| Detection | EDR rule | Alerted late | Not tuned |
| Containment | Isolation SLA | 6 h | No automation |
| Recovery | Backups | Available | Restore untested |

**This table is the heart of a security RCA.**

### 8.3 Time-to-X analysis

| Measure | Finding |
|---|---|
| Time to first evidence | 6 days |
| Time to detection | 8 days |
| Time to triage | 2 h |
| Time to contain | 6 h |
| Time to recover | 3 days |

**Detection delays usually dwarf response delays.** Fix detection first.

---

## 9. Human and organisational factors

### 9.1 Avoid "human error"

"Human error" is a starting point, not a conclusion. Ask:

- Was the interface confusing?
- Was the policy known?
- Was there time pressure?
- Was the alerting overwhelming?
- Was the process designed for the real workload?

### 9.2 Contributing factors

| Factor | Example |
|---|---|
| Workload | 400 alerts/analyst/day |
| Tooling | No one-click isolation |
| Knowledge | New analyst, no playbook |
| Communication | Shift handover missed |
| Incentives | Speed over accuracy |
| Culture | Fear of reporting mistakes |

### 9.3 Just culture

- Distinguish error, at-risk behaviour, reckless behaviour.
- Punishing error destroys reporting.
- Report openly → learn → improve.

---

## 10. Evidence for RCA

| Evidence | Source |
|---|---|
| Timeline | `Timeline-Analysis.md` |
| Logs | SIEM/EDR/cloud |
| Config state | GPO, firewall, IAM, agent |
| Change records | ITSM |
| Interviews | Users, admins, analysts |
| Detection performance | Rule metrics |
| Control test results | Prior audits/purple team |

### 10.1 Evidence standards

- Cite the specific record.
- Separate observation from interpretation.
- Note unavailable evidence as a limitation.
- Preserve artefacts before remediation.

---

## 11. Hypothesis testing

```
Hypothesis → prediction → test → result → update
```

| Hypothesis | Prediction | Test |
|---|---|---|
| Macro policy exception caused execution | GPO shows exception | Query GPO |
| Detection was late because rule tuned out | Rule history shows suppression | Review changes |
| Only one host affected | No other hosts with hash | Estate search |

**RCA is falsification, not storytelling.**

### 11.1 Competing hypotheses

Always hold at least two. If you can't articulate an alternative, you haven't investigated.

---

## 12. Correlation vs causation

| Trap | Example |
|---|---|
| Coincidence | Patch deployed same day as incident |
| Reverse causation | Alert caused panic, not breach |
| Confounder | Both caused by a change window |
| Selection bias | Only looked at infected hosts |

**Test the counterfactual:** if we remove this cause, would the incident still occur?

---

## 13. Corrective actions

### 13.1 Types

| Type | Example | Strength |
|---|---|---|
| **Eliminate** | Remove risky feature | Strongest |
| **Prevent** | Block macro attachments | Strong |
| **Detect** | New EDR rule | Medium |
| **Contain** | Auto-isolate | Medium |
| **Recover** | Faster restore | Weak for prevention |
| **Accept** | Documented risk | Explicit |

### 13.2 Action quality criteria

- Addresses a **root/contributing** cause, not a symptom.
- Specific and testable.
- Owner and due date.
- Measurable completion.
- Verified effective after implementation.

### 13.3 Common bad actions

- "Retrain users" with no measurement.
- "Be more careful".
- "Add to watchlist" (not a control).
- Blocking one IOC.
- Buying a tool with no use case.

---

## 14. Validating fixes

| Validation | Method |
|---|---|
| Control works | Test with safe simulation. |
| Detection fires | Purple-team replay. |
| No new FP | Monitor 2 weeks. |
| Coverage closed | ATT&CK mapping update. |
| Process followed | Audit sample. |

**An unverified corrective action is a wish.**

---

## 15. RCA report template

```
1. Executive summary (5 lines)
2. Incident overview: what, when, impact, scope
3. Timeline (reference)
4. Causal chain with evidence
5. Root cause(s)
6. Contributing factors
7. Control-failure table
8. What worked well
9. Detection/response performance
10. Corrective actions (owner, date, type, validation)
11. Residual risk
12. Lessons and follow-ups
13. Appendices: queries, artefacts, evidence index
```

### 15.1 Quality checks

- [ ] Claims traceable to evidence.
- [ ] At least one alternative hypothesis tested.
- [ ] Root causes are changeable.
- [ ] Actions are class-level where possible.
- [ ] Owners and dates assigned.
- [ ] Residual risk stated.

---

## 16. Blameless practice

| Principle | Practice |
|---|---|
| Focus on systems | "What allowed this?" |
| Assume good intent | No naming-and-shaming. |
| Encourage reporting | Reward early disclosure. |
| Separate accountability | Process owner owns fix. |
| Share broadly | Others learn. |

---

## 17. Worked examples

### 17.1 Phishing → execution

| Question | Answer |
|---|---|
| Proximate | Macro executed. |
| Why allowed | GPO exception. |
| Why exception | 2023 compatibility issue. |
| Why unreviewed | No policy owner. |
| Systemic | No control-ownership register. |
| Class fix | Remove exception + owner + quarterly review. |

### 17.2 Credential compromise

| Question | Answer |
|---|---|
| Proximate | Valid account used from new IP. |
| Why valid creds | Password reused after breach. |
| Why not blocked | No impossible-travel/CA policy. |
| Why no MFA | Legacy protocol exemption. |
| Systemic | MFA exceptions unmanaged. |
| Class fix | Close legacy auth; enforce CA; review exceptions. |

### 17.3 Missed detection

| Question | Answer |
|---|---|
| Proximate | No alert for LSASS access. |
| Why | Rule existed but disabled. |
| Why disabled | Noisy in 2024. |
| Why not fixed | No owner, no backlog item. |
| Systemic | No detection lifecycle. |
| Class fix | Detection ownership + tuning backlog + review cadence. |

---

## 18. Pitfalls

| Pitfall | Consequence |
|---|---|
| Stopping at human error | No systemic fix. |
| Single-cause thinking | Recurrence. |
| Confirmation bias | Wrong conclusion. |
| Anecdote over evidence | Unreliable. |
| Fixing symptoms | Repeat incident. |
| No verification | False assurance. |
| Too many actions | None completed. |
| Blame culture | Hidden incidents. |
| Ignoring detection delay | Response tuned, detection not. |
| Report with no owner | Shelfware. |

---

## 19. Labs

1. Run 5 Whys on a simulated phishing incident.
2. Build a fishbone for a ransomware case.
3. Draw a fault tree for "detection failed".
4. Apply Kepner-Tregoe Is/Is Not to a scope question.
5. Fill a control-failure table for a 5-stage intrusion.
6. Write three competing hypotheses and a test for each.
7. Convert a symptom fix into a class fix.
8. Draft corrective actions with owners and validation.
9. Review a public incident report and extract root causes.
10. Critique a bad RCA (blame-based) and rewrite it.

---

## 20. Self-test questions

1. Define RCA in one sentence.
2. Proximate vs root cause — example.
3. When do you stop asking "why"?
4. Instance vs class vs systemic fix.
5. What does Swiss cheese explain?
6. Give the 5 Whys rules.
7. What are fishbone categories for security?
8. What is a fault tree gate?
9. Kepner-Tregoe's four dimensions?
10. Why is Is/Is Not powerful?
11. What is the control-failure table?
12. Why is "human error" a bad conclusion?
13. What is a contributing factor?
14. How do you test a hypothesis?
15. Why hold competing hypotheses?
16. What makes a corrective action good?
17. How do you validate a fix?
18. What belongs in an RCA report?
19. What is blameless practice?
20. Why does detection delay matter more than response speed?

---

## 21. One-page revision checklist

- [ ] RCA = why it was possible + class-level prevention.
- [ ] Symptom → proximate → intermediate → root → systemic.
- [ ] Stop rule: unchangeable or class-preventing.
- [ ] Models: linear, branching, Swiss cheese, defence-in-depth.
- [ ] 5 Whys rules and failure modes.
- [ ] Fishbone categories.
- [ ] Fault tree AND/OR.
- [ ] Kepner-Tregoe What/Where/When/Extent + Is/Is Not + change analysis.
- [ ] Standard attack chain + control-failure table + time-to-X.
- [ ] Human factors and just culture.
- [ ] Evidence standards and hypothesis testing (falsification).
- [ ] Correlation vs causation traps + counterfactual.
- [ ] Corrective action types and quality criteria.
- [ ] Validation methods.
- [ ] Report template and quality checks.
- [ ] Worked examples: phishing, credential, missed detection.
- [ ] Pitfalls memorised.
