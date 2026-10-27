# SOC Analyst L1 — Career Study Notes

> Goal: know exactly what an L1 does, what is expected in the first 90 days, and how to prove you can do it.

---

## 0. How to use this note

1. §1–§3: the role; responsibilities; a day in the life.
2. §4–§7: skills; tools; KPIs; how you are judged.
3. §8–§11: certifications; resume/portfolio; interview; 90-day plan.
4. §12–§14: mistakes, growth, self-test.

---

## 1. What an L1 is

> **L1** is the first line of defence: monitor the queue, validate alerts, enrich, and escalate real incidents with evidence.

| L1 owns | L1 does not own |
|---|---|
| Acknowledge and triage | Deep forensics |
| Evidence gathering | Containment strategy |
| Verdict on routine alerts | Detection engineering |
| Clean escalation | Root cause analysis |
| Documentation | Remediation |

**Your value is speed + accuracy + clean handoffs.**

---

## 2. Responsibilities

1. Monitor SIEM/EDR/queue continuously.
2. Triage alerts against playbooks within SLA.
3. Enrich with TI, asset, identity context.
4. Classify: TP-malicious, TP-benign, FP, duplicate, inconclusive.
5. Escalate with a complete package.
6. Notify users/asset owners where policy allows.
7. Document every action.
8. Flag noisy rules to detection engineering.
9. Follow shift handover.
10. Stay current on campaigns.

---

## 3. A day in the life

| Time | Activity |
|---|---|
| Shift start | Handover, read open cases, check outages |
| Morning | Work queue by priority, triage |
| Midday | Escalations, user follow-ups |
| Afternoon | Batch low-severity, tuning feedback |
| Shift end | Document, handover open items |

### 3.1 Realistic rhythm

- Most alerts are noise or benign — that is normal.
- A few require deep work.
- Occasional critical interrupts everything.
- Documentation is a large share of the job.

**If you dislike documenting, you will dislike the role.**

---

## 4. Technical skills

| Skill | Level needed |
|---|---|
| Networking (TCP/IP, DNS, HTTP) | Solid |
| Windows/Linux fundamentals | Solid |
| Log reading (event IDs, syslog) | Solid |
| SIEM querying (SPL/KQL) | Working |
| EDR triage | Working |
| Phishing/email header analysis | Working |
| IOC enrichment | Working |
| MITRE ATT&CK basics | Familiar |
| Scripting (one language) | Basic |
| Cloud basics (M365/Entra/AWS) | Familiar |

### 4.1 Soft skills

| Skill | Why |
|---|---|
| Clear writing | Escalations and cases |
| Prioritisation | Queue pressure |
| Curiosity | Finding scope |
| Calm under pressure | Critical alerts |
| Asking for help early | Avoid mistakes |
| Shift reliability | 24×7 operations |

---

## 5. Tools you should recognise

| Category | Examples |
|---|---|
| SIEM | Splunk, Sentinel, Elastic, QRadar, Wazuh |
| EDR | Defender, CrowdStrike, SentinelOne, Carbon Black |
| Email | M365 Defender, Proofpoint |
| TI | VirusTotal, AbuseIPDB, MISP |
| Ticketing | ServiceNow, Jira, TheHive |
| Sandbox | Any.run, Joe Sandbox |
| Network | Wireshark, Zeek |
| Identity | Entra ID, AD, Okta |

**You don't need mastery of all — you need one of each category.**

---

## 6. KPIs

| KPI | Typical focus |
|---|---|
| MTTA | Acknowledge speed |
| Triage time | Time to verdict |
| SLA compliance | By severity |
| Escalation quality | Re-work rate |
| FP rate | Accuracy |
| Reopen rate | Verdict quality |
| Documentation quality | Audit |

**Speed without accuracy is worse than slow and correct.**

---

## 7. How you are judged

| Signal | What it says |
|---|---|
| Alerts closed with evidence | Competence |
| Escalations that hold up | Judgement |
| Low rework | Quality |
| Good notes | Professionalism |
| Team feedback | Collaboration |
| Learning speed | Potential |

---

## 8. Certifications

| Cert | Value |
|---|---|
| **CompTIA Security+** | Baseline knowledge |
| **CompTIA CySA+** | Analyst-oriented |
| **Microsoft SC-200** | Sentinel/Defender |
| **Splunk Core Certified User** | SPL basics |
| **BTL1 / Blue Team Level 1** | Practical blue team |
| **GCIH / GSEC** | If employer sponsors |

**Cert + lab portfolio beats cert alone.**

---

## 9. Resume and portfolio

### 9.1 Resume bullets

| Weak | Strong |
|---|---|
| "Familiar with Splunk" | "Built 12 SPL detections; reduced FP 40% on auth rules" |
| "Team player" | "Escalated 3 confirmed intrusions with full evidence packs" |
| "Knowledge of MITRE" | "Mapped 30 detections to ATT&CK; identified 8 gaps" |

### 9.2 Portfolio

- 3–5 lab writeups with methodology.
- Detection rules you wrote (Sigma/SPL).
- A small home lab diagram.
- One incident-style case study.

---

## 10. Interview

### 10.1 Common questions

1. Walk me through triaging a brute-force alert.
2. How do you tell a false positive from a benign true positive?
3. What would you check after a successful login following failures?
4. Explain DNS/HTTP to a non-technical colleague.
5. How do you prioritise 20 alerts?
6. What is the difference between IOC and TTP?
7. What do you do when you are unsure?
8. Describe an escalation you would write.
9. How do you handle a critical alert at 3 a.m. alone?
10. What did you learn from a recent campaign?

### 10.2 How to answer

- Structure: context → checks → verdict → action.
- Say what evidence you'd use.
- State uncertainty honestly.
- Mention documentation.

### 10.3 Practical test

Many employers give a mini-alert set. Practise with BOTS-style data and time yourself.

---

## 11. First 90 days

| Days | Focus |
|---|---|
| 1–7 | Tools, queue, playbooks, shadow |
| 8–30 | Triage low/medium with review |
| 31–60 | Triage high, escalate independently |
| 61–90 | Own complex triage, suggest tuning |

### 11.1 Questions to ask early

- Which alerts are noisiest?
- What does a good escalation look like here?
- Where are the playbooks?
- Who do I call at 3 a.m.?
- What are the crown jewels?
- How is success measured?

---

## 12. Common mistakes

| Mistake | Fix |
|---|---|
| Guessing verdicts | Say inconclusive + escalate |
| Not checking success-after-failure | Always check |
| Closing noisy rules as FP | Raise tuning |
| Poor documentation | Template |
| Over-investigating low alerts | Time-box |
| Under-escalating privileged accounts | Escalate early |
| Ignoring timezone | UTC discipline |
| Not asking for help | Ask early |
| Skipping handover | Written handover |

---

## 13. Growth path

```
L1 (0–2 yrs) → L2 (2–4 yrs) → Senior/IR/Hunting/Detection (4+)
```

| Next role | Bridge skill |
|---|---|
| L2 | Deeper investigation, scoping |
| IR | Forensics, containment |
| Detection engineering | SPL/Sigma, rule design |
| Threat hunting | Hypothesis, ATT&CK |
| Cloud security | IAM, cloud telemetry |

---

## 14. Self-test

1. What does L1 own vs not own?
2. List five daily responsibilities.
3. Which three technical skills matter most?
4. What are the core KPIs?
5. How do you show competence in an interview?
6. What makes a resume bullet strong?
7. What belongs in an escalation?
8. What do you do when unsure?
9. What are the first-90-day goals?
10. What is the next role after L1?

---

## 15. Revision checklist

- [ ] Role boundary: triage, enrich, escalate, document.
- [ ] Ten responsibilities.
- [ ] Day-in-the-life rhythm; documentation-heavy reality.
- [ ] Technical + soft skills.
- [ ] Tool categories.
- [ ] KPIs and judgement signals.
- [ ] Certifications.
- [ ] Resume bullets with metrics.
- [ ] Interview questions + answer structure.
- [ ] 90-day plan and questions to ask.
- [ ] Mistakes list.
- [ ] Growth path.
