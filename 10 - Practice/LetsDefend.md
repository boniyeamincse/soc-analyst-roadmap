# LetsDefend — Practice Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← CyberDefenders](CyberDefenders.md) · [Splunk Labs →](Splunk-Labs.md)

> Goal: practise the *daily SOC loop* — queue, triage, escalate, write the case — in a simulated SOC.
> Realistic artefacts → [CyberDefenders.md](CyberDefenders.md); SIEM querying → [Splunk-Labs.md](Splunk-Labs.md).

---

## 0. How to use this note

1. §1–§3: what LetsDefend is; fit; setup.
2. §4–§7: the simulated SOC loop; alert types; investigation; case writing.
3. §8–§11: scoring, progression, pitfalls, portfolio.
4. §12–§14: plan, self-test, revision.

---

## 1. What LetsDefend is

**LetsDefend** is a SOC simulation platform: a queue of alerts with a simulated SIEM, endpoint data, email analysis, and case management.

| Property | Detail |
|---|---|
| Focus | SOC analyst L1/L2 workflow |
| Format | Browser-based simulated SOC |
| Strength | End-to-end triage + case writing |
| Weakness | Less raw-evidence depth than DFIR platforms |
| Cost | Free tier + subscription |

> Verify current pricing/certification tracks on the site.

---

## 2. Where it fits

| Roadmap section | Use |
|---|---|
| 04 Monitoring | Alert types and responses |
| 05 SIEM | Log search practice |
| 06 Threat Detection | Recognising techniques |
| 07 Investigation | Triage and scoping |
| 08 IR | Escalation and containment |
| 11 Career | Interview-like experience |

**Best for:** the repeatable analyst loop and case documentation.

---

## 3. Setup

- Create account; explore free tier.
- Keep a log per alert: ID, type, time, verdict, actions.
- Have a notes template ready (see §7).
- Do not use employer data anywhere.

---

## 4. The simulated SOC loop

```
Queue → Open alert → Investigate → Decide → Take action → Close with reason → Next
```

| Stage | What you do |
|---|---|
| **Queue** | Prioritise by severity/age |
| **Open** | Read rule, entities, evidence |
| **Investigate** | Search logs, endpoint, email |
| **Decide** | TP / FP / benign |
| **Act** | Escalate, contain, or close |
| **Close** | Reason + notes |
| **Reflect** | What rule/step helped |

### 4.1 Queue discipline

- Don't cherry-pick easy alerts.
- Work by priority, not preference.
- Batch similar alerts only after individual validation.
- Time-box like a real shift.

---

## 5. Alert types you will see

| Type | Investigation angle |
|---|---|
| **Brute force** | Success after failures? Source? Privilege? |
| **Phishing** | Headers, URLs, attachment, clicks |
| **Malware** | Execution, hash, network, persistence |
| **Suspicious process** | Lineage, command line, signer |
| **PowerShell** | Encoded, parent, network |
| **Web attack** | Request payload, response, follow-up |
| **Data exfil** | Volume, destination, user |
| **C2/beacon** | Periodicity, destination, process |
| **Insider** | Access pattern, timing, volume |
| **Cloud/IAM** | Principal, action, source |

**Every type maps to a checklist in [07 - Investigation/Alert-Triage.md](../07%20-%20Investigation/Alert-Triage.md).**

---

## 6. Investigation sources in-platform

| Source | Use |
|---|---|
| **SIEM search** | Correlate events |
| **Endpoint** | Process, file, network, terminal |
| **Email** | Headers, attachments, URLs |
| **Threat intel** | Reputation lookups |
| **Log browser** | Raw events |

### 6.1 Search strategy

```
1. Start from the alert entity (user/host/IP)
2. Widen time ±30 min
3. Add the second entity to correlate
4. Look for success after failure
5. Check for follow-on activity
6. Pivot to other sources
```

---

## 7. Case-writing template

```
Alert ID / type / severity / time (UTC)

Summary (2–3 lines)

Entities: user, host, IP, process

Evidence:
- query + result
- event timestamps
- hashes/URLs

Analysis:
- what happened
- why it is malicious/benign
- what was ruled out

Verdict: TP / FP / benign TP / inconclusive

Actions:
- escalated / contained / blocked / closed

Follow-up:
- rule tuning
- hunt task
- user contact
```

**The close reason is graded and matters. Write it well.**

---

## 8. Scoring and progression

Most platforms score on:

| Dimension | Good practice |
|---|---|
| Correct verdict | Investigate, don't guess |
| Correct action | Proportionate |
| Case quality | Clear, evidence-based |
| Speed | Within time budget |
| False actions | Avoid |

### 8.1 Progression

| Stage | Goal |
|---|---|
| 1 | Finish alerts with correct verdicts |
| 2 | Improve case quality |
| 3 | Reduce time per alert |
| 4 | Handle multi-stage cases |
| 5 | Write detections from findings |

---

## 9. Pitfalls

| Pitfall | Consequence |
|---|---|
| Guess verdict to move on | No learning |
| Ignore endpoint data | Miss execution |
| Skip email headers | Miss phishing |
| Close as FP without evidence | Bad habit |
| No notes | No improvement |
| Only easy alerts | Weak coverage |
| Copy community answers | Useless |
| Over-contain | Wrong reflex |
| Never escalate | Miss real incidents |
| Ignore time | Unrealistic pace |

---

## 10. Portfolio

| Artefact | Value |
|---|---|
| Anonymised case notes | Shows reasoning |
| Query patterns | Shows tooling |
| Detection ideas | Shows engineering |
| Completion record | Shows consistency |

**Do not publish platform answer keys.**

---

## 11. Real-world transfer

| Platform habit | Real SOC habit |
|---|---|
| Prioritise queue | Same |
| Time-box | Same |
| Document evidence | Same |
| Escalate with package | Same |
| Close with disposition | Same |

### 11.1 What the platform cannot teach

- Politics and business pressure.
- Messy, incomplete telemetry.
- Multi-team coordination.
- Long-running incidents.
- Tool outages.

**Compensate with reading incident reports and tabletop exercises.**

---

## 12. Six-week plan

| Week | Focus | Output |
|---|---|---|
| 1 | Phishing + brute force | 10 cases |
| 2 | Malware + PowerShell | 10 cases |
| 3 | Web + C2 | 10 cases |
| 4 | Cloud/IAM + insider | 8 cases |
| 5 | Multi-stage incidents | 5 cases |
| 6 | Speed pass + write 2 detections | 15 cases |

---

## 13. Self-test

1. What does LetsDefend simulate?
2. What is the daily SOC loop?
3. Why investigate before closing?
4. What belongs in a close reason?
5. How do you handle success-after-failure?
6. Which sources do you pivot between?
7. What is proportionate action?
8. Why avoid only easy alerts?
9. What can't the platform teach?
10. How do you convert a case into a detection?

---

## 14. Revision checklist

- [ ] Platform focus: simulated SOC workflow.
- [ ] Loop: queue → open → investigate → decide → act → close → reflect.
- [ ] Queue discipline and time-boxing.
- [ ] Alert types and their checklists.
- [ ] Investigation sources and search strategy.
- [ ] Case template with evidence and verdict codes.
- [ ] Scoring dimensions.
- [ ] Progression stages.
- [ ] Pitfalls memorised.
- [ ] Portfolio rules.
- [ ] Real-world transfer and gaps.
- [ ] 6-week plan.

---

> **Navigation:** [Roadmap index](../README.md) · [← CyberDefenders](CyberDefenders.md) · [Splunk Labs →](Splunk-Labs.md)
