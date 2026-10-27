# Threat Intelligence — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Root Cause Analysis](Root-Cause-Analysis.md) · [Timeline Analysis →](Timeline-Analysis.md)

> Goal: turn threat intelligence from a feed subscription into decisions — what to detect, what to block, what to ignore.
> Indicators themselves → [IOC-Analysis.md](IOC-Analysis.md); ATT&CK mechanics → [03 - Cybersecurity Fundamentals/MITRE-ATTACK.md](../03%20-%20Cybersecurity%20Fundamentals/MITRE-ATTACK.md).

---

## 0. How to use this note

1. §1–§3: what TI is; levels; the intelligence cycle.
2. §4–§7: requirements, sources, evaluation, sharing.
3. §8–§11: models — Diamond, Kill Chain, ATT&CK; actor profiling.
4. §12–§15: SOC consumption — enrichment, detection, hunting, briefing.
5. §16–§19: metrics, bias, legal, pitfalls.
6. §20–§22: labs, self-test, revision.

---

## 1. What threat intelligence is

> **Threat intelligence** = evidence-based knowledge about adversaries — including context, mechanisms, indicators, implications, and actionable advice — that informs decisions.

### 1.1 Data ≠ information ≠ intelligence

| Level | Example |
|---|---|
| **Data** | `203.0.113.45` |
| **Information** | "IP hosts a phishing kit, seen 40 times this week" |
| **Intelligence** | "Actor targeting our sector uses this kit; our finance team is exposed; block + hunt for clicks" |

**Most "TI feeds" sell data.**

### 1.2 Intelligence must be

| Property | Meaning |
|---|---|
| **Relevant** | Tied to your assets/sector. |
| **Timely** | Still true when consumed. |
| **Actionable** | Suggests a decision. |
| **Contextualised** | Explains why it matters. |
| **Accurate** | Sourced and evaluated. |

---

## 2. Levels of intelligence

| Level | Consumer | Answers | Example |
|---|---|---|---|
| **Strategic** | Executives, board | What threats, what risk, what investment? | "Ransomware targeting our sector is up 40%" |
| **Operational** | SOC managers, IR leads | Who might attack, how, when? | Campaign targeting our vendors |
| **Tactical** | Detection engineers | What TTPs to detect? | ATT&CK technique coverage |
| **Technical** | L1/L2 analysts | What IOCs to match? | Hashes, domains, IPs |

**Mismatch is common:** technical feeds given to executives, strategic reports given to analysts.

---

## 3. The intelligence cycle

```
1. Planning & Direction   (requirements)
2. Collection             (feeds, OSINT, internal)
3. Processing             (normalise, dedupe, translate)
4. Analysis               (evaluate, contextualise, infer)
5. Dissemination          (right format, right consumer)
6. Feedback               (did it help?)
```

### 3.1 Where SOCs fail

- Skip **requirements** → collect everything.
- Skip **analysis** → forward raw feeds.
- Skip **feedback** → never improve.

---

## 4. Requirements (PIR)

### 4.1 Priority Intelligence Requirements

| Element | Example |
|---|---|
| **Question** | Are actors targeting our SaaS integrations? |
| **Why** | Crown jewels are in SaaS. |
| **Indicator of answer** | Campaign reports, TTPs, IOCs. |
| **Consumer** | Detection + IR. |
| **Review** | Quarterly. |

### 4.2 Good requirement criteria

- Tied to a business asset or risk.
- Answerable by collection.
- Time-bound.
- Owned.

### 4.3 SIRs (specific)

PIR → SIR decomposition:

```
PIR: Is our cloud identity estate targeted?
SIR1: Which actors use token theft against Entra?
SIR2: What TTPs precede token theft?
SIR3: Which IOCs indicate the token-theft infrastructure?
```

---

## 5. Sources

| Source | Type | Cost | Notes |
|---|---|---|---|
| **Internal telemetry** | Own | Free | Highest relevance. |
| **Incident history** | Own | Free | Best detection input. |
| **ISAC/ISAO** | Shared | Membership | Sector-specific. |
| **CERT advisories** | Public | Free | Authoritative. |
| **Vendor research** | Public | Free | Marketing + useful. |
| **Commercial feeds** | Paid | High | Varies wildly. |
| **OSINT** | Public | Free | Needs verification. |
| **Dark web monitoring** | Paid | High | Early warning. |
| **Peer/industry groups** | Shared | Trust | Fast. |

### 5.1 Internal-first principle

Your own incidents produce the most relevant intelligence: actors who already hit you, TTPs that worked, infrastructure that reached you.

---

## 6. Evaluating intelligence

### 6.1 Admiralty source reliability

| Grade | Meaning |
|---|---|
| A | Completely reliable |
| B | Usually reliable |
| C | Fairly reliable |
| D | Not usually reliable |
| E | Unreliable |
| F | Cannot be judged |

### 6.2 Information credibility

| Grade | Meaning |
|---|---|
| 1 | Confirmed by other sources |
| 2 | Probably true |
| 3 | Possibly true |
| 4 | Doubtful |
| 5 | Improbable |
| 6 | Cannot be judged |

**Report as `B2`, `C3`, etc.** It prevents false certainty.

### 6.3 Questions before use

1. Who produced this and why?
2. What is the evidence?
3. Is it corroborated?
4. Is it current?
5. Does it apply to our environment?
6. What decision does it change?

**If no decision changes, it is not intelligence for you.**

---

## 7. Sharing

| Mechanism | Use |
|---|---|
| **MISP** | Structured sharing with TLP. |
| **TAXII/STIX** | Automated exchange. |
| **ISAC portals** | Sector alerts. |
| **Email lists** | Fast, unstructured. |
| **Chat communities** | Informal, verify. |

### 7.1 TLP

| Marking | Share with |
|---|---|
| RED | Named individuals only. |
| AMBER | Organisation + need-to-know. |
| AMBER+STRICT | Organisation only. |
| GREEN | Community. |
| CLEAR | Public. |

**Respect markings — leaking a source ends the relationship.**

### 7.2 Sharing hygiene

- Remove victim-identifying data.
- Defang indicators.
- Include context and confidence.
- Note the source grade.
- Track what you shared with whom.

---

## 8. Diamond Model

```
        Adversary
         /     \
 Infrastructure — Capability
         \     /
          Victim
```

| Vertex | Questions |
|---|---|
| **Adversary** | Who? Motivation, sophistication. |
| **Capability** | What tools/malware? |
| **Infrastructure** | Domains, IPs, C2, hosting. |
| **Victim** | Who/what was targeted? Sector, geo. |

### 8.1 Use

- Pivot across vertices to find related activity.
- Cluster events into campaigns.
- Identify gaps (unknown adversary, unknown capability).

### 8.2 Example pivot

Victim → infrastructure → other victims → shared capability → same adversary.

---

## 9. Cyber Kill Chain

| Stage | Detection opportunity |
|---|---|
| Reconnaissance | Scanning, OSINT |
| Weaponisation | Hard to see |
| Delivery | Email, web, USB |
| Exploitation | Process/exploit telemetry |
| Installation | Persistence |
| C2 | Beaconing |
| Actions on objectives | Exfil, encryption |

### 9.1 Limitation

Linear and perimeter-focused; poor fit for insider, cloud, or living-off-the-land. Use ATT&CK for depth.

---

## 10. ATT&CK mapping

| Use | How |
|---|---|
| **Detection coverage** | Map rules to techniques. |
| **Intel translation** | Report TTPs → techniques → rules. |
| **Hunting** | Pick technique → hypothesise → query. |
| **Purple team** | Select techniques → test → measure. |
| **Gap analysis** | Techniques with no detection. |

### 10.1 Intel-to-detection pipeline

```
Report → extract TTPs → map to ATT&CK
→ check existing coverage → gap?
→ build/hunt → validate → document
```

**Never stop at "we read the report".**

---

## 11. Actor profiling

### 11.1 Profile fields

| Field | Use |
|---|---|
| Aliases | Correlate reporting. |
| Motivation | Financial/espionage/hacktivism. |
| Sophistication | Resource level. |
| Targeting | Sector/geo/role. |
| TTPs | Detection priorities. |
| Infrastructure patterns | Hunting. |
| Tooling | Signatures/YARA. |
| Historical campaigns | Context. |

### 11.2 Attribution caution

- Attribution is probabilistic.
- False flags are common.
- Shared tooling ≠ same actor.
- Attribution rarely changes immediate defence.

**Defend against behaviour, not names.**

### 11.3 Prioritisation

```
priority = relevance (sector/geo) × capability (impact) × intent (targeting you)
```

---

## 12. SOC consumption

### 12.1 Daily

| Task | Output |
|---|---|
| Review new advisories | Relevant IOCs/TTPs. |
| Check feed health | Volume, errors. |
| Enrich alerts | TI verdicts. |
| Update watchlists | Time-boxed. |

### 12.2 Weekly

- Campaign summary for the team.
- New detections from intel.
- Hunt from a report.
- Feed precision review.

### 12.3 Monthly

- Coverage vs top actor TTPs.
- Intel requirement review.
- Source value assessment.

---

## 13. Enrichment in alerts

| Enrichment | Value |
|---|---|
| IP/domain reputation | Context |
| ASN/hosting | Infrastructure |
| Passive DNS | History |
| File reputation | Prevalence |
| Actor/campaign tag | Priority |
| Sector targeting | Relevance |

**Enrichment should change the decision, not just add colour.**

### 13.1 Enrichment failure modes

- Blocking on reputation alone.
- Stale data.
- No source/date shown.
- Rate limits hiding answers.
- Enrichment latency delaying alerts.

---

## 14. Intel-driven detection

### 14.1 From report to rule

| Report element | Detection artefact |
|---|---|
| Malware family | YARA + behaviour |
| C2 protocol | Network rule |
| Persistence method | Registry/service rule |
| Credential access | LSASS/AD rule |
| Infrastructure | IOCs + retro-hunt |

### 14.2 Prioritise by

1. Relevance to your sector/assets.
2. Technique already partially covered.
3. Cheap to detect (existing telemetry).
4. High impact if missed.

### 14.3 Avoid

- Copying vendor Sigma rules without testing.
- Blocking all IOCs from a report.
- Building rules for actors who never target you.
- Duplicating existing coverage under a new name.

---

## 15. Intel-driven hunting

```
Intel report → hypothesis → ATT&CK technique
→ data sources → query → findings → detection
```

### 15.1 Hypothesis quality

| Weak | Strong |
|---|---|
| "Are we compromised?" | "If actor X used T1059.001, we'd see encoded PowerShell from Office parents in the last 30 days." |
| "Check IOCs" | "Their infra resolves to ASN Y; do we have TLS sessions to that ASN?" |

### 15.2 Outputs

- Confirmed activity → incident.
- Negative result → coverage note.
- Behaviour observed → new detection.

---

## 16. Metrics

| Metric | Meaning |
|---|---|
| Intel-to-detection conversion | Rules produced per report. |
| Intel-sourced incidents | Incidents found via TI. |
| Feed precision | TP per 1,000 indicators. |
| Time from advisory to coverage | Responsiveness. |
| Hunt yield | Findings per hunt. |
| False alarms from TI | Noise cost. |
| Requirement answered | PIR coverage. |

---

## 17. Cognitive bias

| Bias | Effect |
|---|---|
| Confirmation | Only seek supporting evidence. |
| Anchoring | Fixate on first IOC. |
| Availability | Overweight recent/vivid reports. |
| Hype | Overreact to vendor marketing. |
| Attribution bias | Assume a specific actor. |
| Groupthink | Team converges early. |

**Countermeasure:** competing hypotheses, source grading, devil's advocate.

---

## 18. Legal and ethical

- Do not access criminal infrastructure without authorisation.
- Do not retain PII from leaks unnecessarily.
- Respect TLP and NDAs.
- Be careful with dark-web purchases (legal risk).
- Report vulnerabilities responsibly.
- Keep evidence handling lawful.

---

## 19. Pitfalls

| Pitfall | Consequence |
|---|---|
| Collecting without requirements | Feed hoarding. |
| No analysis layer | Raw data forwarded. |
| Blind blocking | Outages. |
| Ignoring internal intel | Missed relevance. |
| Chasing attribution | Wasted effort. |
| No feedback loop | No improvement. |
| Over-trusting vendor reports | Marketing-driven detections. |
| Stale indicators | Noise. |
| No TLP discipline | Broken trust. |
| Intel not tied to action | Shelfware. |

---

## 20. Labs

1. Write 3 PIRs for a fictional company.
2. Grade 5 sources with Admiralty codes.
3. Build a Diamond Model for a public campaign report.
4. Map a report's TTPs to ATT&CK techniques.
5. Convert one TTP into a Sigma rule.
6. Design a 30-day hunt from a report.
7. Build an actor profile from OSINT.
8. Draft a 5-line strategic brief for executives.
9. Create a MISP event with TLP and context.
10. Compare two feeds for precision on a 2-week sample.

---

## 21. Self-test questions

1. Data vs information vs intelligence.
2. Name the four TI levels and their consumers.
3. Recite the intelligence cycle.
4. What is a PIR, and what makes one good?
5. Why is internal telemetry the best source?
6. Explain Admiralty grading with an example.
7. What are the six questions before using intel?
8. Name the TLP levels.
9. Describe the Diamond Model's four vertices.
10. What are the Kill Chain stages?
11. Why is ATT&CK better than Kill Chain for detection?
12. What fields belong in an actor profile?
13. Why is attribution rarely actionable?
14. How does intel become a detection rule?
15. What makes a strong hunting hypothesis?
16. Name three cognitive biases and counters.
17. Which metrics show TI value?
18. Why is "collect everything" a failure?
19. What legal limits apply to TI work?
20. What is the most common SOC TI failure?

---

## 22. One-page revision checklist

- [ ] TI = contextualised, actionable, relevant knowledge.
- [ ] Levels: strategic, operational, tactical, technical.
- [ ] Cycle: direction → collection → processing → analysis → dissemination → feedback.
- [ ] PIRs/SIRs; good-requirement criteria.
- [ ] Sources ranked; internal-first.
- [ ] Admiralty A–F / 1–6 grading.
- [ ] Six pre-use questions; "what decision changes?"
- [ ] Sharing: MISP/TAXII/ISAC; TLP table.
- [ ] Diamond Model vertices and pivots.
- [ ] Kill Chain stages + limitation.
- [ ] ATT&CK uses; intel→detection pipeline.
- [ ] Actor profile fields; attribution caution; priority formula.
- [ ] Daily/weekly/monthly SOC TI tasks.
- [ ] Enrichment value and failure modes.
- [ ] Report → rule mapping; prioritisation criteria.
- [ ] Hunting hypothesis quality.
- [ ] Metrics.
- [ ] Biases and counters.
- [ ] Legal/ethical limits.
- [ ] Pitfalls memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Root Cause Analysis](Root-Cause-Analysis.md) · [Timeline Analysis →](Timeline-Analysis.md)
