# Threat Hunter — Career Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← SOC Analyst L2](SOC-Analyst-L2.md)

> Goal: find what detection never alerted on — deliberately, with hypotheses, not luck.
> TTP knowledge → [03 - Cybersecurity Fundamentals/MITRE-ATTACK.md](../03%20-%20Cybersecurity%20Fundamentals/MITRE-ATTACK.md); triage → [07 - Investigation/Alert-Triage.md](../07%20-%20Investigation/Alert-Triage.md).

---

## 0. How to use this note

1. §1–§3: the role; hunting vs monitoring; responsibilities.
2. §4–§7: hypothesis design; data; methodology; documentation.
3. §8–§11: findings to detections; metrics; skills; certs.
4. §12–§15: interview, portfolio, 90-day plan, mistakes.
5. §16–§18: self-test, revision.

---

## 1. What threat hunting is

> **Threat hunting** = proactive, hypothesis-driven search for adversary activity that existing detections did not catch.

| Monitoring | Hunting |
|---|---|
| Reactive | Proactive |
| Alert-driven | Hypothesis-driven |
| Known logic | Unknown gaps |
| Queue | Campaign |
| Answers "did it fire?" | Answers "would we know?" |

**Hunting assumes you are already compromised and looks for proof.**

---

## 2. Why it exists

| Reason | Detail |
|---|---|
| Detection gaps | Rules never cover everything |
| Novel TTPs | New techniques, old logic |
| Dwell time | Attackers live for weeks |
| Validation | Tests whether detection works |
| Intel operationalisation | Turns reports into searches |
| Assurance | Evidence of coverage |

---

## 3. Responsibilities

1. Form hypotheses from intel, ATT&CK, incidents.
2. Identify required data sources.
3. Query at scale across estate.
4. Analyse anomalies and sequences.
5. Confirm or refute hypotheses.
6. Document method and negative results.
7. Convert findings into detections.
8. Feed gaps back to detection engineering.
9. Run periodic hunts per plan.
10. Improve data coverage.

---

## 4. Hypothesis design

### 4.1 Structure

```
If <actor/technique> were present,
we would observe <behaviour> in <data source>
within <time window>, characterised by <specific pattern>.
```

### 4.2 Weak vs strong

| Weak | Strong |
|---|---|
| "Are we compromised?" | "If T1059.001 is used, Office parents will spawn encoded PowerShell in the last 30 days." |
| "Check for malware" | "If a loader runs, unsigned EXEs in %TEMP% will make TLS connections to rare ASNs." |
| "Look at DNS" | "If DNS tunnelling occurs, we will see >50 queries/min with high-entropy labels from one host." |

### 4.3 Hypothesis sources

| Source | Example |
|---|---|
| ATT&CK coverage gaps | Technique with no rule |
| Intel report | New campaign TTP |
| Incident | Missed technique |
| Purple team | Untested behaviour |
| Sector trend | Peer breach |
| Anomaly | Odd metric |

---

## 5. Data

| Requirement | Note |
|---|---|
| Retention | 30–90 days minimum |
| Fidelity | Process + network + identity |
| Normalisation | Consistent fields |
| Coverage | All hosts/cloud |
| Query performance | Fast enough to iterate |

### 5.1 Hunt data checklist

- [ ] EDR process/network
- [ ] Windows event logs
- [ ] Linux audit/journal
- [ ] DNS/proxy/firewall
- [ ] Identity/sign-in
- [ ] Cloud audit
- [ ] Email gateway
- [ ] Asset inventory

**No data → no hunt. Fix coverage first.**

---

## 6. Methodology

```
1. Pick hypothesis
2. Identify data + fields
3. Establish baseline/normal
4. Query broadly
5. Narrow with filters
6. Look for sequence and rarity
7. Pivot on anomalies
8. Test alternative explanations
9. Conclude (positive/negative/inconclusive)
10. Convert to detection or gap
```

### 6.1 Hunting patterns

| Pattern | Query shape |
|---|---|
| **Rarity** | Low-frequency values |
| **Outlier** | >Nσ from baseline |
| **Sequence** | A then B within window |
| **Absence** | Expected event missing |
| **Stacking** | Count by rare combination |
| **Clustering** | Group by shared attribute |
| **Temporal** | Periodicity, off-hours |
| **Entropy** | Randomness in names/strings |

### 6.2 Example: LOLBin hunt

```spl
index=edr process_name IN (certutil.exe, bitsadmin.exe, mshta.exe, regsvr32.exe)
| stats count values(command_line) AS cmds BY host, user, process_name
| where count > 0
```

Then review command lines for download/execute patterns.

### 6.3 Example: rare parent-child

```spl
index=edr
| stats count BY parent_name, process_name
| where count < 3
| sort count
```

Low-prevalence lineage is high-signal.

---

## 7. Documentation

### 7.1 Hunt record

```
Hunt ID / date / hunter
Hypothesis
ATT&CK technique(s)
Data sources + time window
Queries (reproducible)
Baseline
Findings (with evidence)
Verdict: confirmed / refuted / inconclusive
Detection produced (or gap)
Data gap identified
Time spent
```

### 7.2 Why negative results matter

- Prove coverage.
- Justify data investment.
- Prevent repeated hunts.
- Build institutional knowledge.

**A documented negative hunt is a result, not a failure.**

---

## 8. Findings to detections

```
Finding → behaviour → rule logic → test → deploy
```

| Finding type | Output |
|---|---|
| Confirmed intrusion | Incident + IR |
| Suspicious behaviour | New detection |
| Benign anomaly | Context/enrichment |
| Data gap | Coverage request |
| Tooling gap | Engineering task |

### 8.1 Detection handoff

Give detection engineering:

- Exact behaviour.
- Fields and values.
- Sample events (sanitised).
- Expected FP sources.
- Suggested threshold.

---

## 9. Metrics

| Metric | Meaning |
|---|---|
| Hunts per quarter | Activity |
| Confirmed findings | Yield |
| Detections produced | Conversion |
| Data gaps closed | Improvement |
| Coverage increase | Assurance |
| Time per hunt | Efficiency |
| False hypotheses | Learning (not failure) |

**Hunt yield is usually low — that is normal. Persistence matters.**

---

## 10. Skills

| Skill | Depth |
|---|---|
| ATT&CK | Strong |
| SIEM query | Expert |
| Endpoint internals | Strong |
| Network analysis | Strong |
| Identity/cloud | Working |
| Statistics/baselining | Working |
| Scripting | Working |
| Malware behaviour | Working |
| Writing | Strong |

### 10.1 Mindset

- Curiosity over confirmation.
- Comfort with negative results.
- Hypothesis discipline.
- Evidence over instinct.
- Share findings.

---

## 11. Certifications

| Cert | Value |
|---|---|
| GCDA | Detection/analysis |
| GCTI | Threat intel |
| GCFA | Forensics |
| SC-200 | Microsoft stack |
| Splunk Power User | SPL |
| Practical platforms (HTB, BTL) | Hands-on |

---

## 12. Interview

1. Walk me through a hunt you ran.
2. How do you form a hypothesis?
3. How do you handle a negative result?
4. How do you choose what to hunt next?
5. What data would you need for T1055?
6. How do you measure hunting success?
7. How do you avoid confirmation bias?
8. How do you convert a finding into a detection?
9. What do you do with a data gap?
10. How do you prioritise hunts?

---

## 13. Portfolio

| Artefact | Value |
|---|---|
| 2–3 hunt writeups | Core evidence |
| Query collection | Tooling |
| Detection produced | Conversion |
| Coverage analysis | Strategy |
| Gap-closure story | Impact |

---

## 14. First 90 days

| Days | Focus |
|---|---|
| 1–14 | Data inventory, coverage map, crown jewels |
| 15–30 | Run 2 small hunts with mentor |
| 31–60 | Own a hunt; produce 1 detection |
| 61–90 | Build a hunt plan; close 1 data gap |

---

## 15. Mistakes

| Mistake | Fix |
|---|---|
| Hunting without hypothesis | Define first |
| Only hunting IOCs | Hunt TTPs |
| Stopping at first finding | Pivot/scope |
| Confirmation bias | Try to disprove |
| No documentation | Template |
| Ignoring negative results | Record them |
| No detection output | Convert |
| Hunting rare = malicious | Add context |
| No baseline | Establish normal |
| Hunting only what's easy | Prioritise by risk |

---

## 16. Growth

| Direction | Next |
|---|---|
| Detection engineering | Rule engineering |
| IR | Response leadership |
| Threat intel | Actor research |
| Purple team | Adversary emulation |
| Cloud hunting | Cloud-native TTPs |

---

## 17. Self-test

1. Hunting vs monitoring?
2. What makes a hypothesis strong?
3. Name five hypothesis sources.
4. What data do you need?
5. List the ten-step method.
6. Name four hunting patterns.
7. Why document negative results?
8. How do you convert a finding?
9. Which metrics matter?
10. How do you avoid confirmation bias?

---

## 18. Revision checklist

- [ ] Hunting = proactive, hypothesis-driven, gap-finding.
- [ ] Why it exists.
- [ ] Ten responsibilities.
- [ ] Hypothesis structure + weak/strong examples + sources.
- [ ] Data requirements + checklist.
- [ ] Method 10 steps.
- [ ] Hunting patterns: rarity, outlier, sequence, absence, stacking, clustering, temporal, entropy.
- [ ] Two example queries.
- [ ] Hunt record fields; value of negatives.
- [ ] Finding → detection handoff.
- [ ] Metrics incl. low yield normal.
- [ ] Skills + mindset.
- [ ] Certs.
- [ ] Interview Qs + portfolio.
- [ ] 90-day plan.
- [ ] Mistakes memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← SOC Analyst L2](SOC-Analyst-L2.md)
