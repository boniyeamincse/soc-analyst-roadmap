# Alerting — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Vulnerabilities](../03%20-%20Cybersecurity%20Fundamentals/Vulnerabilities.md) · [EDR →](EDR.md)

> Goal: design, tune, and triage alerts so the SOC sees **signal, not noise**, and so every alert is actionable within minutes.
> Detection logic → section 05 [Detection-Rules.md](../05%20-%20SIEM/Detection-Rules.md); SIEM structure → [SIEM.md](SIEM.md); triage → [07 - Investigation/Alert-Triage.md](../07%20-%20Investigation/Alert-Triage.md).

---

## 0. How to use this note

1. §1–§2: why alerting is the SOC's bottleneck; alert anatomy.
2. §3–§6: design principles, severity, thresholds/baselines, correlation.
3. §7–§9: dedup/suppression, enrichment, routing.
4. §10–§12: lifecycle, triage workflow, escalation.
5. §13–§15: quality metrics, tuning, alert fatigue.
6. §16–§19: playbooks, pitfalls, labs, self-test, revision.
7. §21–§44: **Part II — Alert Engineering deep dive** (classification, confidence, rule logic, testing, risk, SLA, automation, coverage).
8. §45: extended self-test and revision addendum.

> **Coverage note:** §21 is an audit of the 40-topic alert curriculum against this note, marking each topic *covered*, *partial*, or *new*. Part II fills every gap without duplicating §1–§20.

---

## 1. Why alerting matters

- Alerts are the **output** of detection and the **input** to analysts.
- A SOC's capacity is finite: **every false alert costs triage time** and attention.
- Poor alerting causes **alert fatigue**, missed incidents, and analyst burnout.
- Good alerting provides **context, severity, and a next step** — not just "something happened".
- Alert quality is measurable; treat it like a product.

**The core question for every alert:**
> "If I am the analyst on shift, can I decide what to do within 5 minutes using only what is in this alert?"

If no → the alert is under-designed.

---

## 2. Anatomy of a good alert

| Element | Purpose |
|---|---|
| **Title** | Human-readable, specific ("PowerShell spawned by Word"), not rule jargon. |
| **Description** | What behaviour, why it matters. |
| **Severity** | Drives priority/SLA. |
| **Entities** | User, host, IP, process, hash, URL — clickable/pivotable. |
| **Evidence** | Raw event(s), command line, parent, timestamp. |
| **Context** | Asset criticality, user role, threat intel, baseline rarity. |
| **ATT&CK** | Technique mapping for context. |
| **Playbook link** | What to do next. |
| **False-positive guidance** | Known benign causes. |
| **Owner/source** | Which rule/source produced it. |

**Bad alert:** "Rule 1042 triggered."
**Good alert:** "PowerShell with encoded command spawned by WINWORD.EXE on FIN-PC-07 as j.smith (Finance). No previous PowerShell use by this user. Hash unsigned. ATT&CK T1059.001/T1027.010."

---

## 3. Design principles

1. **Detect behaviour, not just artefacts.** Hashes expire; TTPs persist.
2. **Be specific enough to act.** A rule that fires 500×/day is not a detection, it's a data feed.
3. **Correlate weak signals** instead of alerting on each.
4. **Include context** in the alert (enrichment at write time).
5. **Define severity** using impact + confidence + asset criticality.
6. **Document known-benign causes.**
7. **Provide a runbook.**
8. **Test with real data** (TP and FP).
9. **Version and review** rules.
10. **Measure** precision and value.

### 3.1 Alert vs event vs incident

| Term | Meaning |
|---|---|
| **Event** | A single log record. |
| **Alert** | A rule judged an event/pattern noteworthy. |
| **Case** | An investigation opened on one or more alerts. |
| **Incident** | Confirmed security event requiring response. |

Do not conflate them; escalation goes alert → case → incident.

---

## 4. Severity and priority

### 4.1 Severity inputs

| Factor | Question |
|---|---|
| **Impact** | What could be lost (C/I/A)? |
| **Confidence** | How sure is the detection? |
| **Asset criticality** | DC, finance, prod, dev, test? |
| **Privilege** | Admin/SYSTEM/root vs standard user? |
| **Exposure** | Internet-facing vs internal? |
| **Scope** | One host vs many? |
| **Stage** | Initial access vs confirmed exfil? |

### 4.2 Typical scale

| Severity | Meaning | Response |
|---|---|---|
| **Critical** | Active compromise, high impact, high confidence. | Immediate, escalate, page. |
| **High** | Strong malicious signal or privileged impact. | Same shift, escalate if confirmed. |
| **Medium** | Suspicious, needs investigation. | Triage within SLA. |
| **Low** | Weak signal or policy violation. | Queue, batch. |
| **Info** | Context only. | Dashboard, no queue. |

### 4.3 Priority vs severity

- **Severity** = potential impact.
- **Priority** = severity × urgency/asset importance.
- An "info" event on a domain controller may outrank a "high" on a test VM.

**Formula (pragmatic):**
```
Priority ≈ Impact × Confidence × Asset Criticality × Exposure
```

---

## 5. Thresholds and baselines

### 5.1 Static thresholds

Simple, predictable, easy to explain.

```spl
... | stats count by user | where count > 20
```

Problems: environment-dependent, easy for attackers to stay under, noisy during legitimate spikes.

### 5.2 Baseline/statistical

- Compare to the entity's own history (z-score, moving average).
- **First-seen** / **rare-value** detection.
- Peer-group comparison (same role/department).
- Seasonal adjustment (month-end, backups).

### 5.3 Choosing thresholds

1. Measure baseline volume for 2–4 weeks.
2. Set threshold above p99 (or use anomaly).
3. Validate with known attacks.
4. Tune based on FP rate.
5. Document rationale.

> A threshold is a **business decision** about acceptable noise vs coverage.

### 5.4 Rate vs count vs cardinality

| Pattern | Use |
|---|---|
| **Count** | Total events in window. |
| **Rate** | Events per second/minute. |
| **Cardinality** | Distinct values (accounts, hosts). |
| **Ratio** | Success/failure, bytes/request. |
| **Absence** | Expected event missing. |
| **Sequence** | A then B within window. |

---

## 6. Correlation and multi-stage alerts

### 6.1 Why

Single events are ambiguous; **sequences** are not.

`4625 ×20` → medium. `4625 ×20 then 4624` → high. `4625 ×20 → 4624 → service creation` → critical.

### 6.2 Patterns

| Pattern | Example |
|---|---|
| **Failure→success** | Spray then valid login. |
| **Delivery→execution** | Phishing click then Office child shell. |
| **Execution→C2** | Suspicious process then beacon. |
| **Persistence→lateral** | Task created then SMB to many hosts. |
| **Discovery→impact** | Recon tools then shadow copies deleted. |

### 6.3 Implementation options

- SIEM correlation rules (stateful).
- Scheduled searches joining windows.
- Risk-based scoring per entity.
- SOAR enrichment/orchestration.
- EDR behavioural detections.

### 6.4 Risks

- Complex rules become unmaintainable.
- Long windows increase latency.
- Missing one stage breaks the chain.
- Over-correlation creates storms.

> Prefer **several simple, well-instrumented stages** plus an entity-risk score over one giant rule.

---

## 7. Deduplication, suppression, and grouping

| Technique | Purpose | Caution |
|---|---|---|
| **Dedup** | Same alert within window → one. | Don't hide repeated attempts over days. |
| **Grouping** | Combine related alerts (same host/user). | Preserve individual evidence. |
| **Suppression** | Known-good, maintenance, scanners. | Time-bound, owned, documented. |
| **Allowlist** | Trusted process/path/user. | Broad allowlists are attack surface. |
| **Threshold** | Only alert above N. | Attackers can stay below. |
| **Flapping control** | Avoid repeated open/close. | Track state. |

**Rule:** every suppression has an **owner**, **reason**, and **expiry**. Review quarterly.

---

## 8. Enrichment at alert time

| Enrichment | Enables |
|---|---|
| **Asset criticality/owner** | Prioritise. |
| **User role/privilege** | Context (admin vs intern). |
| **GeoIP/ASN** | Travel, hosting, Tor. |
| **Threat intel** | Known bad infrastructure. |
| **Vulnerability** | Exploitable asset? |
| **Historical** | First time? How often? |
| **Related alerts** | Same entity/campaign. |
| **Change calendar** | Planned maintenance. |

**Enrichment must be fast.** An alert delayed 30 minutes for enrichment loses value.

---

## 9. Routing and queues

### 9.1 Routing dimensions

- Severity (critical → on-call; low → queue).
- Source/domain (endpoint, identity, cloud, network).
- Tenant/business unit (MSSP).
- Skill (malware, cloud, IR).
- Time zone/shift.

### 9.2 Queue hygiene

- One alert = one owner (no duplicate work).
- Backlog visible; age tracked.
- Stale alerts auto-escalate or expire with reason.
- Workload balanced across analysts.
- Shift handover notes.

### 9.3 Notification channels

| Channel | Use |
|---|---|
| **SIEM queue** | Primary. |
| **Email** | Low urgency/digest. |
| **Chat (Teams/Slack)** | High urgency, collaboration. |
| **Pager/on-call** | Critical/after-hours. |
| **Ticket (Jira/ServiceNow)** | Tracked work. |
| **SOAR** | Automated enrichment/response. |

**Avoid:** alerting to a channel nobody owns.

---

## 10. Alert lifecycle

```
Detect → Create → Enrich → Route → Acknowledge → Triage →
Investigate → Decide (TP/FP/benign) → Respond/Escalate → Close → Review
```

| State | Meaning |
|---|---|
| **New** | Not yet seen. |
| **Acknowledged** | Owned by analyst. |
| **In progress** | Investigating. |
| **Escalated** | Handed to L2/IR. |
| **Closed – TP** | Confirmed and handled. |
| **Closed – FP** | Rule incorrect. |
| **Closed – benign** | Rule correct, activity legitimate. |
| **Closed – duplicate** | Covered elsewhere. |

**Distinguish FP from benign TP** — they drive different fixes (rule vs context/allowlist).

---

## 11. Triage workflow (per alert)

### Step 1 — Read
Title, severity, entities, rule logic, evidence.

### Step 2 — Validate the alert
Is the data correct? Is it the right host/user/time? Parsing issue?

### Step 3 — Contextualise
Asset criticality, user role, baseline, change window, threat intel.

### Step 4 — Corroborate
Look for related events in other sources (identity + endpoint + network).

### Step 5 — Decide
- **FP**: rule logic wrong → document and tune.
- **Benign TP**: rule right, activity legitimate → document and tune context.
- **True positive**: malicious → investigate/respond.

### Step 6 — Act
Contain/escalate per playbook; collect evidence.

### Step 7 — Document
Query, evidence, reasoning, verdict, actions.

### Step 8 — Feed back
Improve rule/playbook if needed.

---

## 12. Escalation

### 12.1 When to escalate

- Confirmed malicious activity.
- Privileged account or critical asset.
- Multiple hosts / lateral movement.
- Data access/exfiltration.
- Ransomware indicators.
- Uncertainty with high potential impact.

### 12.2 Escalation package

```
Summary         (what, where, when, who)
Evidence        (events, queries, screenshots, hashes)
Impact          (C/I/A, scope, asset criticality)
Actions taken   (containment, blocks, resets)
Open questions  (what you couldn't determine)
Recommended next steps
```

### 12.3 Escalation path

L1 → L2 → IR/threat hunting → management/legal/comms (depending on type).

**Do not** sit on a critical finding to "finish the investigation" — escalate early with what you have.

---

## 13. Quality metrics

| Metric | Definition | Target |
|---|---|---|
| **Precision** | TP / (TP + FP) | High (>80% for queued alerts). |
| **Recall** | TP detected / total TP | Measured by purple team. |
| **FP rate** | FP / total alerts | Low, trending down. |
| **Alert volume** | Alerts/day per analyst | Sustainable. |
| **MTTD** | Mean time to detect | Minimise. |
| **MTTA** | Mean time to acknowledge | Per SLA. |
| **MTTR** | Mean time to respond/remediate | Per severity. |
| **Escalation rate** | Escalated / triaged | Context-dependent. |
| **Conversion rate** | Incidents / alerts | Insight into signal. |
| **Rule health** | Fires, errors, last tuned | Reviewed monthly. |
| **Coverage** | ATT&CK techniques detected | Increasing. |

**Per-rule scorecard:** fires/week, TP, FP, precision, avg triage time, owner, last reviewed.

---

## 14. Tuning

### 14.1 Tuning process

1. Pick a rule with high volume/low precision.
2. Sample 20–50 alerts.
3. Classify causes (FP vs benign TP vs TP).
4. Identify the discriminating feature.
5. Adjust logic/threshold/context.
6. Re-test on historical data.
7. Monitor for 2 weeks.
8. Document change and rationale.

### 14.2 Tuning options

| Option | When |
|---|---|
| Raise threshold | Legitimate volume high. |
| Add condition | Specific benign pattern identified. |
| Correlate | Single event too weak. |
| Enrich/suppress | Known-good asset/process with owner. |
| Lower severity | Low impact but useful context. |
| Retire | No longer relevant. |
| Split rule | Different behaviours need different handling. |

### 14.3 Never

- Suppress without expiry/owner.
- Disable a rule because "it's noisy" without analysis.
- Add a broad allowlist to hit a metric.
- Ignore a rule that never fires (may be broken).

---

## 15. Alert fatigue

### Symptoms
- Queue grows, analysts skim.
- "Close all low" behaviour.
- Missed high-severity amid noise.
- Cynicism and burnout.

### Causes
- Too many low-value rules.
- Poor thresholds.
- No dedup/grouping.
- Alerting on scanner noise.
- Vendor defaults not tuned.
- No ownership.

### Fixes
- Measure per-rule value.
- Reduce/retire noise.
- Improve context and auto-enrichment.
- Risk-based prioritisation.
- Rotate analysts through tuning.
- Automate known-benign handling (with logging).
- Protect focus time.

---

## 16. Playbook examples

### A. "Impossible travel"
1. Verify with user (VPN/mobile/travel).
2. Check device, app, MFA method.
3. If anomalous → revoke sessions, reset creds, check activity.

### B. "Malware detected"
1. Threat name, path, hash, action taken.
2. Executed? Persistence? Network?
3. Isolate if active; hunt estate.

### C. "Brute force"
1. Volume/source/window; any success?
2. Lockout status; user contact.
3. Block, enforce MFA, monitor.

### D. "New admin account"
1. Who created it, ticket/approval?
2. What has it done?
3. Remove if unauthorized; reset creds.

### E. "Suspicious PowerShell"
1. Decode command.
2. Parent, user, host criticality.
3. Follow network/files/children; contain if malicious.

### F. "Cloud role change"
1. Principal, role, resource, source.
2. IaC/CI or manual?
3. Revert if unauthorized; rotate keys.

---

## 17. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Alerting on every IOC match | Noise. |
| No enrichment | Slow triage. |
| Severity inflation | Everything is critical → nothing is. |
| No dedup | Duplicate work. |
| Alert without runbook | Inconsistent response. |
| No owner | Rules rot. |
| Suppression without expiry | Blind spots. |
| Measuring only volume | Ignores quality. |
| Not distinguishing FP vs benign TP | Wrong fixes. |
| Alerts to unowned channel | Missed. |
| No feedback loop | No improvement. |
| Vendor defaults untouched | Poor fit. |

---

## 18. Labs

1. Write 5 alert rules with full metadata and runbooks.
2. Measure baseline for each; set thresholds.
3. Generate TP and FP; compute precision.
4. Build a correlation rule (failure→success).
5. Implement dedup/grouping; compare queue size.
6. Create a severity matrix and apply to 10 alerts.
7. Tune a noisy rule and document before/after.
8. Build an alert-quality dashboard.
9. Write an escalation package for a simulated incident.
10. Run a tabletop on alert fatigue and propose fixes.

---

## 19. Self-test questions

1. What makes an alert actionable?
2. Differentiate event, alert, case, incident.
3. What factors determine severity?
4. Difference between severity and priority?
5. What is the risk of static thresholds?
6. Why is correlation more powerful than single-event alerting?
7. What is the difference between FP and benign TP?
8. What must every suppression have?
9. Which metrics measure alert quality?
10. How do you tune a noisy rule?
11. When should you escalate?
12. What belongs in an escalation package?
13. What causes alert fatigue, and how do you fix it?
14. Why measure precision per rule?
15. What is the danger of a rule that never fires?

---

## 20. One-page revision checklist

- [ ] Alert purpose: actionable within minutes; output of detection, input to triage.
- [ ] Anatomy: title, description, severity, entities, evidence, context, ATT&CK, playbook, FP guidance, owner.
- [ ] Design: behaviour over artefacts, specificity, correlation, context, severity, benign causes, runbook, testing, versioning, measurement.
- [ ] Event vs alert vs case vs incident.
- [ ] Severity inputs: impact, confidence, asset criticality, privilege, exposure, scope, stage; severity vs priority.
- [ ] Thresholds: static, baseline/statistical, first-seen, peer group, seasonal; count/rate/cardinality/ratio/absence/sequence.
- [ ] Correlation: failure→success, delivery→execution, execution→C2, persistence→lateral, discovery→impact; risks.
- [ ] Dedup/grouping/suppression/allowlist/threshold/flapping; owner+reason+expiry.
- [ ] Enrichment: asset, identity, geo/ASN, TI, vuln, history, related, change calendar; must be fast.
- [ ] Routing: severity, domain, tenant, skill, shift; queue hygiene; channels.
- [ ] Lifecycle states incl. TP/FP/benign/duplicate distinction.
- [ ] Triage: read → validate → contextualise → corroborate → decide → act → document → feedback.
- [ ] Escalation: when, package contents, path; escalate early.
- [ ] Metrics: precision, recall, FP rate, volume, MTTD/MTTA/MTTR, escalation/conversion, rule health, coverage; per-rule scorecard.
- [ ] Tuning: sample → classify → discriminate → adjust → retest → monitor → document; options table; never-list.
- [ ] Alert fatigue symptoms/causes/fixes.
- [ ] Playbooks: impossible travel, malware, brute force, new admin, PowerShell, cloud role change.
- [ ] Pitfalls list memorised.

---

# Part II — Alert Engineering Deep Dive

> §1–§20 cover the *concepts and the queue*. Part II covers the *engineering mechanics*: how an alert is defined, scored, tested, versioned, measured, automated, and retired.

---

## 21. Coverage audit — the 40-topic alert curriculum

| # | Topic | Status | Where |
|---|---|---|---|
| 1 | Alert Fundamentals | partial | §1–2, expanded §22 |
| 2 | Alert Lifecycle | covered | §10, expanded §39 |
| 3 | Alert Classification | **new** | §23 |
| 4 | Alert Severity & Priority | covered | §4, expanded §32 |
| 5 | Alert Confidence Scoring | **new** | §24 |
| 6 | Alert Rules & Conditions | partial | §3, expanded §25 |
| 7 | Threshold-Based Alerting | covered | §5.1, §26 |
| 8 | Frequency-Based Alerting | partial | §5.4, expanded §26 |
| 9 | Time-Window-Based Alerting | partial | §5, expanded §27 |
| 10 | Event Correlation Alerts | covered | §6 |
| 11 | Multi-Event Correlation | covered | §6, expanded §29 |
| 12 | Behavioral Alerts | **new** | §28 |
| 13 | Signature-Based Alerts | **new** | §28 |
| 14 | Anomaly-Based Alerts | partial | §5.2, expanded §28 |
| 15 | Rule Chaining & Dependencies | **new** | §29 |
| 16 | Alert Deduplication | covered | §7 |
| 17 | Alert Suppression | covered | §7 |
| 18 | Alert Grouping & Aggregation | covered | §7, expanded §33 |
| 19 | Alert Enrichment | covered | §8 |
| 20 | Alert Context & Risk Scoring | partial | §8, expanded §30 |
| 21 | False Positive Reduction | partial | §14, expanded §31 |
| 22 | Alert Tuning & Optimization | covered | §14 |
| 23 | Alert Prioritization | partial | §4.3, expanded §32 |
| 24 | Alert Escalation Logic | covered | §12 |
| 25 | Alert Routing & Assignment | covered | §9 |
| 26 | Alert Notifications | covered | §9.3 |
| 27 | Alert Flood & Noise Management | covered | §15, §33 |
| 28 | Alert Correlation & Consolidation | partial | §6, expanded §33 |
| 29 | Alert Validation & Testing | **new** | §34 |
| 30 | Alert Regression Testing | **new** | §35 |
| 31 | Alert Performance Monitoring | partial | §13, expanded §36 |
| 32 | Alert Quality Metrics | covered | §13 |
| 33 | Alert Precision & Recall | partial | §13, expanded §37 |
| 34 | Alert Coverage Mapping (ATT&CK) | **new here** | §38 (see also [05/Detection-Rules.md](../05%20-%20SIEM/Detection-Rules.md) §12) |
| 35 | Alert Documentation & Lifecycle Mgmt | partial | §2/§10, expanded §39 |
| 36 | Alert Rule Versioning & Change Mgmt | **new here** | §40 (see [05/Detection-Rules.md](../05%20-%20SIEM/Detection-Rules.md) §10) |
| 37 | Alert Expiration & Retirement | **new here** | §41 (see [05/Detection-Rules.md](../05%20-%20SIEM/Detection-Rules.md) §13) |
| 38 | Alert Automation & Response Triggers | **new** | §42 |
| 39 | Alert SLA Management | **new** | §43 |
| 40 | Alert Engineering Best Practices | partial | scattered, consolidated §44 |

---

## 22. Alert fundamentals (formal)

### 22.1 Definitions

| Term | Precise meaning |
|---|---|
| **Telemetry event** | Immutable record of something observed. |
| **Detection** | A test that evaluates telemetry and yields match / no-match. |
| **Alert** | A **persisted assertion** that a detection matched, with evidence and metadata. |
| **Notification** | Delivery of an alert to a channel/person. |
| **Case** | Container for investigating one or more alerts. |
| **Incident** | Confirmed event with response obligation. |

**Alert = assertion + evidence + severity + entities + next action.**

### 22.2 The alert contract

An alert promises the consumer:

1. **What** behaviour was observed.
2. **Where** (host, tenant, account, resource).
3. **When** (event time, detection time).
4. **Why it matters** (rationale, ATT&CK).
5. **How sure** (confidence).
6. **What to do** (runbook).
7. **What is known to be benign** (FP guidance).

If any element is missing, the alert is under-specified.

### 22.3 What deserves to be an alert

| Should alert | Should not alert |
|---|---|
| Actionable, time-sensitive behaviour | Informational context |
| Security-relevant anomaly | Raw policy violations with no impact |
| Confirmed malicious pattern | Anything the SOC cannot act on |
| Leading indicator of impact | Duplicate of an existing signal |

**Test:** "If this fires 50 times today, is the SOC still better off?"

---

## 23. Alert classification

### 23.1 Classification dimensions

| Dimension | Values | Use |
|---|---|---|
| **Source type** | Rule, TI match, anomaly, ML, user report, third-party | Routing, trust. |
| **Domain** | Identity, endpoint, network, cloud, data, email | Skill routing. |
| **Detection family** | Signature, behavioural, threshold, correlation, anomaly | Tuning strategy. |
| **Kill-chain stage** | Initial access → impact | Prioritisation. |
| **Confidence** | Low / medium / high | Handling. |
| **Actionability** | Auto-close, enrich, triage, escalate | Automation. |
| **Scope** | Single entity, multi-entity, estate-wide | Escalation. |

### 23.2 Disposition taxonomy (post-triage)

| Code | Meaning |
|---|---|
| **TP-M** | True positive, malicious. |
| **TP-B** | True positive behaviour, benign context (e.g., admin script). |
| **FP-R** | False positive, rule logic wrong. |
| **FP-D** | False positive, data/parsing wrong. |
| **DUP** | Duplicate of another alert/case. |
| **INC** | Inconclusive / insufficient data. |
| **TEST** | Red team, simulation, scanner. |

**Standardise these codes.** They drive tuning, metrics, and audits.

### 23.3 Classification in practice

```
alert.class = <domain>.<family>.<confidence>
alert.disposition = TP-M | TP-B | FP-R | FP-D | DUP | INC | TEST
```

Every alert must have exactly one disposition at close.

---

## 24. Alert confidence scoring

### 24.1 Inputs

| Input | Raises confidence when |
|---|---|
| **Telemetry fidelity** | Kernel/EDR vs user-mode vs proxy-only. |
| **Specificity** | Narrow behaviour vs broad pattern. |
| **Corroboration** | Multiple independent sources agree. |
| **Threat intel** | Known-bad infrastructure/hash. |
| **Prevalence** | Rare in the estate. |
| **Context match** | Asset/user is a plausible target. |
| **Allowlist absence** | Not a known-good pattern. |
| **Historical precision** | Rule has a strong track record. |

### 24.2 Simple scoring model

```
confidence = base(rule)
           + telemetry_fidelity (0–20)
           + corroboration      (0–20)
           + intel_match        (0–15)
           + rarity             (0–15)
           + context_fit        (0–10)
           - known_benign       (0–40)
clamp to 0–100
```

| Score | Band | Handling |
|---|---|---|
| 85–100 | Very high | Auto-escalate/maybe auto-contain. |
| 65–84 | High | Priority triage. |
| 40–64 | Medium | Standard queue. |
| 15–39 | Low | Batch review / auto-enrich. |
| 0–14 | Very low | Auto-close with audit trail. |

### 24.3 Confidence vs severity

| | Low severity | High severity |
|---|---|---|
| **High confidence** | Queue | Escalate now |
| **Low confidence** | Auto-close/sample | Enrich, then decide |

**Never let low confidence hide high potential impact** — those go to enrichment, not the bin.

### 24.4 Calibration

- Sample 30 closed alerts per confidence band monthly.
- Compare actual TP rate to the band's target.
- Recalibrate weights if a band is wrong.
- Confidence is a **prediction**, not a decorative number.

---

## 25. Alert rules and conditions

### 25.1 Condition primitives

| Primitive | Example | Notes |
|---|---|---|
| **Equality** | `EventCode=4625` | Cheapest. |
| **Set membership** | `Image IN (a,b,c)` | Prefer over OR chains. |
| **Substring** | `CommandLine contains "-enc"` | Case sensitivity matters. |
| **Prefix/suffix** | `Image endswith "\temp\x.exe"` | Avoid leading wildcard. |
| **Regex** | `(?i)invoke-expression` | Powerful, expensive, brittle. |
| **Numeric range** | `bytes_out > 100MB` | Baseline-dependent. |
| **Existence** | `field=*` | Data-quality sensitive. |
| **Absence** | expected event missing | Silence detection. |
| **Count/rate** | `count > 20 in 5m` | Threshold rules. |
| **Distinct count** | `dc(user) > 10` | Spray/fan-out. |
| **Sequence** | A then B within 10m | Correlation. |
| **Ratio** | out/in > 5 | Exfil. |

### 25.2 Boolean composition

- Use **AND** to add specificity; **OR** to broaden coverage; **NOT** to exclude known-good.
- Group explicitly — precedence bugs are a classic silent failure.
- Prefer **allowlist fields** over `NOT regex` on command lines.

### 25.3 Null, type, and case pitfalls

| Pitfall | Effect |
|---|---|
| `field != "x"` excludes nulls | Misses events entirely. |
| String comparison on numeric field | Wrong threshold behaviour. |
| Case-sensitive match on mixed-case data | Silent misses. |
| Empty string vs null | Different filters. |
| Multi-value fields | Equality fails unexpectedly. |

**Always test with null/empty data.**

### 25.4 Entity binding

Every rule should bind at least one entity:

```
user, host, src_ip, dst_ip, process, file_hash, url, cloud_resource
```

Entities enable dedup, grouping, risk scoring, and automation.

---

## 26. Frequency-based alerting

### 26.1 Count vs rate vs distinct

| Form | Expression | Use |
|---|---|---|
| **Count** | `count > 20` | Volume burst. |
| **Rate** | `count / window > x` | Sustained activity. |
| **Distinct** | `dc(target) > 10` | Fan-out/spray. |
| **Ratio** | `failures / attempts > 0.9` | Attack efficiency. |
| **Consecutive** | `N in a row` | Lockout patterns. |

### 26.2 Per-entity vs global

| Scope | Pros | Cons |
|---|---|---|
| **Per entity** (user/host/IP) | Precise, low noise. | Many entities each below threshold. |
| **Global** | Catches distributed activity. | Noisy, hides attribution. |
| **Hybrid** | Per-entity + global sanity check. | More complex. |

**Distributed attacks defeat per-IP thresholds** — add a global/aggregate rule.

### 26.3 Burst vs sustained

```spl
### burst: 20 failures in 5 minutes
... | bin _time span=5m | stats count by user,_time | where count>=20
```

```spl
### sustained: 100 failures across 6 hours
... | bin _time span=1h | stats count by user,_time
| stats sum(count) AS total dc(_time) AS hours by user
| where total>=100 AND hours>=6
```

Different attacker behaviours need different shapes.

### 26.4 Threshold selection

1. Measure 2–4 weeks of baseline.
2. Compute p95/p99 per entity.
3. Set threshold above p99.
4. Test against known attacks.
5. Re-baseline quarterly/seasonally.

**Never copy a threshold from a blog post.**

---

## 27. Time-window semantics

### 27.1 Tumbling vs sliding

| Window | Definition | Effect |
|---|---|---|
| **Tumbling** | Fixed non-overlapping buckets. | One alert per bucket; boundary gaps. |
| **Sliding** | Continuously advancing, overlapping. | Catches boundary-straddling attacks; duplicates. |

**Example:** a 10-minute attack split across two 5-minute tumbling buckets may never breach the threshold.

### 27.2 Lookback vs frequency

| Setting | Meaning | Failure mode |
|---|---|---|
| **Frequency** (run every) | How often the rule executes. | Too slow = delayed detection. |
| **Lookback** (data window) | How far back each run queries. | Shorter than frequency = **gaps**. |

**Rule:** `lookback ≥ frequency`. Prefer `lookback = frequency × 2` plus dedup.

### 27.3 Boundary handling

- Overlapping lookbacks re-alert the same events → dedup by event ID/entity.
- Late-arriving data (ingest lag) may be missed by a tight lookback.
- Clock skew across sources shifts events outside windows.
- Backfill/replay runs can duplicate alerts.

### 27.4 Windows to know

| Purpose | Typical |
|---|---|
| Brute force burst | 5–10 min |
| Password spray | 15–60 min |
| Beaconing | 1–24 h |
| Exfil volume | 1–24 h |
| First-seen behaviour | 7–30 days |
| Rare destination | 30 days |
| Impossible travel | 1–6 h |

---

## 28. Detection families: signature, behavioural, anomaly

### 28.1 Signature-based

| Element | Detail |
|---|---|
| **What** | Match known patterns: hashes, domains, IPs, strings, YARA, exploit signatures. |
| **Strengths** | Precise for known threats, explainable, cheap. |
| **Weaknesses** | Blind to new/obfuscated; IOC decay; false positives on shared infra. |
| **Tuning** | Prevalence, allowlists, confidence decay over time. |

```yara
rule Known_C2_Domain { strings: $d = "evil-c2.example" condition: $d }
```

### 28.2 Behavioural

| Element | Detail |
|---|---|
| **What** | Detect actions/TTPs regardless of specific artefact. |
| **Strengths** | Survives recompilation/renaming; catches LOLBins. |
| **Weaknesses** | Environment-dependent; needs baselines; can be noisy. |
| **Tuning** | Lineage allowlists, peer-group context, prevalence. |

Examples: Office→shell, LSASS access, shadow-copy deletion, fan-out authentication.

### 28.3 Anomaly-based

| Element | Detail |
|---|---|
| **What** | Statistical/ML deviation from baseline. |
| **Strengths** | Can catch novel activity. |
| **Weaknesses** | Opaque, drifts, seasonal noise, hard to explain to stakeholders. |
| **Tuning** | Minimum history, seasonality, feedback labels, explanation fields. |

### 28.4 Choosing a family

| Situation | Family |
|---|---|
| Known malware campaign | Signature + behavioural |
| Novel intrusion | Behavioural + anomaly |
| High-volume auth abuse | Threshold/behavioural |
| Cloud control-plane change | Behavioural + baseline |
| Low-data environment | Signature (with caution) |

**Mature programmes combine all three** and score them together.

---

## 29. Rule chaining and dependencies

### 29.1 Chain types

| Type | Example |
|---|---|
| **Enrichment chain** | Alert → add asset owner → add TI verdict. |
| **Gating chain** | Only alert if user is privileged. |
| **Sequence chain** | Alert A enables/raises B. |
| **Risk chain** | Multiple low alerts accumulate into one high. |
| **Suppression chain** | Rule B suppressed while rule A is open. |

### 29.2 Dependency risks

| Risk | Effect |
|---|---|
| **Upstream data missing** | Downstream silently never fires. |
| **Upstream schema change** | Field nulls. |
| **Circular dependencies** | Runaway alerts / deadlock. |
| **Hidden coupling** | Tuning A breaks B. |
| **Ordering assumptions** | Race conditions. |

### 29.3 Managing dependencies

1. Document the dependency graph (rule → data source → enrichment → downstream).
2. Add **health checks** for upstream prerequisites.
3. Version dependencies together.
4. Test chains end to end, not rule by rule.
5. Alert when an upstream data source goes silent.

```
Data source → ingest → normalise → rule A → risk score → rule B → escalation
```

---

## 30. Context and risk scoring

### 30.1 Entity risk model

```
risk(entity) = Σ (rule_weight × severity_factor × confidence) × decay
```

| Element | Meaning |
|---|---|
| **rule_weight** | Points assigned to the detection. |
| **severity_factor** | 1–3 multiplier. |
| **confidence** | 0–1. |
| **decay** | Points halve every N days. |

### 30.2 Example weights

| Detection | Weight |
|---|---|
| Failed logon | 1 |
| LSASS access | 40 |
| Shadow copy deletion | 50 |
| New admin account | 20 |
| Rare external RDP | 25 |
| Beaconing | 30 |

### 30.3 Thresholds

| Entity risk | Handling |
|---|---|
| < 20 | No alert (context only). |
| 20–49 | Low queue. |
| 50–99 | Medium. |
| 100+ | High/critical. |

### 30.4 Benefits and traps

| Benefit | Trap |
|---|---|
| Reduces single-event noise | Weights become arbitrary |
| Surfaces multi-stage attacks | Slow accumulation hides urgent events |
| Entity-centric investigation | High-value alerts buried under chatter |
| Natural dedup | Decay misconfigured → stale risk |

**Use risk to *add* signal, never to suppress a high-severity standalone alert.**

---

## 31. False positive reduction programme

### 31.1 Classify before tuning

| Class | Root cause | Fix |
|---|---|---|
| **FP-R** | Rule logic too broad | Add conditions/threshold |
| **FP-D** | Parsing/schema | Fix parser |
| **FP-E** | Environmental change | Add context/allowlist |
| **TP-B** | Legitimate behaviour | Narrow allowlist with owner |

**Different classes need different fixes.** Treating TP-B as FP hides real rules.

### 31.2 Process

```
Measure volume → sample 30 → classify → find discriminating feature
→ change one thing → retest TP + FP → monitor 2 weeks → document
```

### 31.3 Levers ranked by safety

1. Add **specificity** (new condition).
2. Raise **threshold** (with baseline).
3. Add **correlation** (require a second signal).
4. Scope by **asset/role**.
5. **Suppress** time-boxed, owned.
6. Disable (last resort, with sign-off).

### 31.4 Targets

| Metric | Target |
|---|---|
| Queued alert precision | > 80% |
| FP-R share of closures | < 15% |
| Repeat FP alerts | Declining |
| Analyst "close-all" sessions | None |

---

## 32. Alert prioritisation

### 32.1 Model

```
priority = severity × confidence × asset_criticality × exposure × stage_weight
```

| Factor | Range |
|---|---|
| severity | 1–4 |
| confidence | 0.3–1.0 |
| asset | 1–3 (test → prod → crown jewel) |
| exposure | 1–2 (internal → internet-facing) |
| stage | 1–3 (recon → execution → impact) |

### 32.2 Queue ordering

1. Critical + high confidence (page).
2. Critical + low confidence (enrich immediately).
3. High + high confidence.
4. Medium + high confidence.
5. Everything else by age × severity.

**Age must increase priority** — an old medium can become a breach.

### 32.3 Dynamic reprioritisation

- New intel on an entity promotes waiting alerts.
- A confirmed incident promotes all related entities.
- Business calendar (month-end, M&A) changes asset weight.
- Active campaigns promote matching techniques estate-wide.

---

## 33. Alert consolidation

### 33.1 Grouping keys

| Key | Groups |
|---|---|
| **Entity** | Same user/host/IP. |
| **Technique** | Same ATT&CK technique. |
| **Campaign** | Same infrastructure/payload. |
| **Incident** | Same root cause. |
| **Time** | Same window. |

### 33.2 Consolidation rules

- One **case** per incident, many alerts.
- Child alerts link to a parent.
- Preserve individual evidence.
- Do not merge across unrelated entities.
- Re-open/merge rather than duplicate.

### 33.3 Over-merge vs under-merge

| Problem | Effect |
|---|---|
| **Over-merge** | Distinct events hidden; slow response. |
| **Under-merge** | Duplicate work; inconsistent verdicts. |

**Rule:** merge by *shared evidence or entity*, not by *similar title*.

---

## 34. Alert validation and testing

### 34.1 Test plan per rule

| Test | Pass criteria |
|---|---|
| **Positive** | Fires on known malicious fixture. |
| **Negative** | Silent on benign fixture. |
| **Near-miss** | Silent on benign lookalike. |
| **Edge** | Nulls, unicode, long values handled. |
| **Volume** | Backtest volume acceptable. |
| **Performance** | Runtime within budget. |
| **Entity mapping** | Entities populated. |
| **Routing** | Lands in the right queue. |

### 34.2 Test data sources

- Historical replay windows.
- Purple-team / Atomic Red Team.
- Synthetic events.
- Lab detonation.
- Production sampling (read-only).

### 34.3 Acceptance gate

```
Definition of ready for production:
  ✓ positive, negative, near-miss tests pass
  ✓ backtest ≤ N alerts/day
  ✓ entities mapped
  ✓ description + FPs + runbook written
  ✓ owner assigned
  ✓ peer reviewed
```

### 34.4 Sign-off

- Detection engineer implements.
- SOC lead accepts operational load.
- Documented in the rule record.

---

## 35. Alert regression testing

### 35.1 Why

Tuning rule A can silently break rule B; parser changes can null fields; platform upgrades rename operators.

### 35.2 Regression suite

| Artefact | Purpose |
|---|---|
| **Golden dataset** | Fixed events with expected results. |
| **Expected counts** | Per-rule expected alert count. |
| **Snapshots** | Query output before/after change. |
| **CI job** | Runs on every rule/parser change. |

### 35.3 Process

```
change → run suite → compare → pass/fail → deploy or rollback
```

### 35.4 Cadence

| Trigger | Test |
|---|---|
| Rule edit | That rule + dependents |
| Parser change | All rules using that source |
| Platform upgrade | Full suite |
| Quarterly | Sample of critical rules |

### 35.5 Rollback criteria

- TP test fails.
- Volume exceeds threshold by >2×.
- Critical rule silent.
- Entity mapping empty.

---

## 36. Alert performance monitoring

### 36.1 Pipeline metrics

| Stage | Metric | Alert if |
|---|---|---|
| Ingest | events/sec, lag | lag > SLO |
| Parse | failure rate | > 1% |
| Rule eval | runtime, errors | error > 0 |
| Queue | depth, wait time | wait > SLA |
| Notification | delivery failures | > 0 |
| Automation | playbook failures | > 0 |

### 36.2 Detection latency

```
detection_latency = alert_time − event_time
```

Track p50/p95/p99 per rule. A rule that fires 40 minutes late is often useless.

### 36.3 Capacity

- Concurrent rule count vs platform limits.
- Indexer/search-head load at peak.
- Cost per alert (ingest + compute).
- Alert storms after deployments.

### 36.4 Dashboards

- Rules by runtime and error rate.
- Alert latency heatmap.
- Queue depth/age.
- Notification and automation failures.
- Silent sources (data health).

---

## 37. Precision and recall

### 37.1 Confusion matrix

| | Actually malicious | Actually benign |
|---|---|---|
| **Alerted** | TP | FP |
| **Not alerted** | FN | TN |

```
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2·(precision·recall)/(precision+recall)
```

### 37.2 Measuring

| Metric | Method |
|---|---|
| **Precision** | Sample closed alerts; adjudicate. |
| **Recall** | Purple-team tests per technique. |
| **FN rate** | Post-incident review: "which rule should have fired?" |
| **Coverage-adjusted recall** | Weighted by technique risk. |

### 37.3 Small-sample caution

- 20 alerts with 0 FP does **not** prove 100% precision.
- Report confidence intervals or use rolling windows.
- Avoid per-rule precision claims on <30 samples.

### 37.4 Programme targets

| Metric | Target |
|---|---|
| Precision (queued) | > 80% |
| Recall (critical techniques) | > 90% |
| Alert-to-incident conversion | 5–15% |
| FN discovered post-incident | Declining |

---

## 38. Alert coverage mapping (ATT&CK)

### 38.1 The chain

```
Technique → Data source → Telemetry exists → Rule exists
→ Rule tested → Alert actionable → Response playbook
```

Coverage is only real at the **last** step.

### 38.2 Mapping table

| Technique | Data source | Rule | Tested | Playbook |
|---|---|---|---|---|
| T1059.001 | 4688/4104 | PS-Encoded-01 | ✅ | ✅ |
| T1003.001 | Sysmon 10 | LSASS-Access-01 | ✅ | ✅ |
| T1110.003 | 4625 | Spray-01 | ⚠️ | ✅ |
| T1566.001 | Email gateway | Phish-Attach-01 | ✅ | ✅ |

### 38.3 Prioritisation

1. Techniques used by threat actors relevant to the business.
2. Techniques on the path to crown jewels.
3. Techniques with existing telemetry.
4. Gaps found in incidents/purple team.

**Do not chase 100% coverage.** Chase **risk-weighted, tested** coverage.

### 38.4 Reporting

- Heat map by tactic.
- Count by coverage level (nominal/data/detection/response/validated).
- Trend of validated coverage.
- Explicit "known gaps" list with owners.

---

## 39. Alert documentation and lifecycle management

### 39.1 Alert record

```
id, title, description, rationale
data source, required fields
logic / query
severity, confidence, ATT&CK
entities
threshold, window, frequency
dedup/grouping/throttle
known false positives
runbook link
owner, reviewer
status (draft/test/prod/deprecated)
version, created, modified, last reviewed, last fired
tests (positive, negative, near-miss)
```

### 39.2 Status model

```
Draft → Test → Tuned → Production → Deprecated → Retired
```

Transitions require evidence (tests, volume, sign-off).

### 39.3 Review cadence

| Alert class | Review |
|---|---|
| Critical | Monthly |
| High | Quarterly |
| Medium/low | Semi-annual |
| Silent rules | Immediately |
| Post-incident | Within 5 days |

### 39.4 Knowledge management

- Link runbook, queries, sample events, past cases.
- Keep the "why" — future analysts need rationale, not just SQL.
- Record decisions to *not* detect something (accepted risk).

---

## 40. Rule versioning and change management

### 40.1 Versioning scheme

```
MAJOR.MINOR.PATCH
MAJOR: logic/behaviour change (may change volume)
MINOR: metadata/threshold tuning
PATCH: description/typo/entity mapping fix
```

### 40.2 Change record

```
change_id, rule_id, old_version, new_version
reason, diff summary, expected impact
tests run, results
approver, date
rollback plan
```

### 40.3 Workflow (detection-as-code)

```
branch → edit rule + tests → CI (validate, backtest)
→ peer review → staging deploy → monitor
→ production → post-deploy watch 48h
```

### 40.4 Rules of change

- No direct production edits.
- One logical change per commit.
- Tests accompany logic changes.
- Backtest before deploy.
- Announce high-volume changes to the SOC.
- Roll back on regression.

---

## 41. Alert expiration and retirement

### 41.1 What expires

| Object | TTL |
|---|---|
| Suppression | 30–90 days |
| Exception/allowlist | 90 days (renewable) |
| Temporary rule | Per campaign |
| Draft rule | 30 days |
| Deprecated rule | 90 days then delete |

### 41.2 Retirement criteria

- Data source no longer exists.
- Technique no longer relevant.
- Superseded by a better rule.
- Precision too low despite tuning.
- Owner gone and no adopter.

### 41.3 Retirement process

1. Mark deprecated.
2. Stop routing to the queue (keep logging).
3. Archive tests, samples, history.
4. Remove dependencies.
5. Delete after the grace period.
6. Record why.

### 41.4 Zombie rule warnings

- Never fires (probably broken).
- Fires constantly (ignored).
- No owner.
- References dead data source.
- Duplicates another rule.

**Audit quarterly. Delete without sentiment.**

---

## 42. Alert automation and response triggers

### 42.1 Automation tiers

| Tier | Action | Risk |
|---|---|---|
| **0** | Enrich only (TI, asset, geo) | None |
| **1** | Auto-close low-confidence junk | Low (needs audit) |
| **2** | Auto-ticket/assign | Low |
| **3** | Auto-block IOC | Medium |
| **4** | Auto-contain (isolate/disable) | High (approval) |

### 42.2 Trigger design

```
IF alert.severity = critical AND entity.type = host
   AND confidence > 85
THEN enrich → notify on-call → propose isolation (approval)
```

### 42.3 Guardrails

- **Idempotent** actions.
- **Approval gate** for destructive steps.
- **Blast-radius limit** (one host, one user).
- **Dry-run** mode first.
- **Full audit log** of every action.
- **Timeout/retry** with backoff.
- **Failure escalation** to a human.
- **Kill switch** for the whole playbook.

### 42.4 Human-in-the-loop

Reserve automation for **reversible, well-understood** actions. Anything that could take down production needs a human decision — even if the human only clicks "approve".

### 42.5 Measuring automation

| Metric | Target |
|---|---|
| % alerts auto-enriched | High |
| % auto-closed | Matches precision |
| Automation failure rate | < 1% |
| Mean time saved per alert | Tracked |
| Incidents caused by automation | 0 |

---

## 43. Alert SLA management

### 43.1 Definitions

| Term | Meaning |
|---|---|
| **SLA** | Committed service level (contractual/internal). |
| **SLO** | Target objective. |
| **SLI** | Measured indicator. |
| **MTTA** | Mean time to acknowledge. |
| **MTTT** | Mean time to triage. |
| **MTTC** | Mean time to contain. |

### 43.2 Typical targets (24×7 SOC)

| Severity | Ack | Triage | Contain |
|---|---|---|---|
| Critical | 5 min | 30 min | 1 h |
| High | 15 min | 2 h | 4 h |
| Medium | 1 h | 8 h | 24 h |
| Low | 8 h | 3 days | Best effort |

Adjust to staffing and business hours; **document the assumptions**.

### 43.3 Clock rules

- Start at alert creation (not notification).
- Pause only for documented external dependencies.
- Stop at the defined milestone.
- Breaches auto-escalate.
- Report weekly by severity and rule.

### 43.4 SLA vs quality

**Do not let SLA pressure produce false "closed" verdicts.** Track reopen rate and misclassification alongside SLA compliance.

---

## 44. Alert engineering best practices (consolidated)

1. Every alert has an owner, runbook, and tests.
2. Write for the analyst at 3 a.m. — explicit, specific, actionable.
3. Bind entities on every rule.
4. Prefer behaviour over artefacts.
5. Baseline before thresholds.
6. `lookback ≥ frequency`; dedup overlaps.
7. Classify FP types separately; fix the right thing.
8. One logical change per rule revision.
9. Test positive, negative, near-miss, and edge cases.
10. Backtest volume before production.
11. Stage rollouts; watch 48 hours.
12. Keep suppressions narrow, owned, expiring.
13. Measure precision per rule, recall per technique.
14. Escalate early with partial information.
15. Automate enrichment first, response last.
16. Require approval for destructive automation.
17. Document the reasoning, not just the query.
18. Review noisy rules monthly; silent rules immediately.
19. Retire ruthlessly; coverage is not a rule count.
20. Treat the alert queue as a product with users (the analysts).

---

## 45. Extended self-test and revision addendum

### 45.1 Self-test (Part II)

1. What is the difference between an alert and a notification?
2. Why does an alert need a runbook and FP guidance?
3. Name four alert classification dimensions.
4. What are the seven disposition codes?
5. What inputs raise confidence?
6. When should low confidence *not* mean low priority?
7. What is the difference between frequency and lookback?
8. Why can tumbling windows miss an attack?
9. Signature vs behavioural vs anomaly — one strength and one weakness each.
10. What are the risks of rule chaining?
11. How does entity risk scoring reduce noise, and how can it hide an incident?
12. What are the four FP classes, and which fix applies to each?
13. What belongs in a rule's test plan?
14. What triggers a regression test?
15. How do you measure recall?
16. What are the five levels of ATT&CK coverage?
17. What belongs in an alert record?
18. What versioning scheme would you use for rules?
19. When do you retire a rule?
20. Which automation tier requires approval, and why?
21. Define MTTA, MTTT, MTTC.
22. Why is SLA compliance alone a bad health metric?

### 45.2 Revision addendum

- [ ] Alert contract: what, where, when, why, confidence, action, FP guidance.
- [ ] Alert vs notification vs case vs incident.
- [ ] Classification: source, domain, family, stage, confidence, actionability, scope.
- [ ] Dispositions: TP-M, TP-B, FP-R, FP-D, DUP, INC, TEST.
- [ ] Confidence model: fidelity, specificity, corroboration, intel, rarity, context, allowlist, history; bands and handling; calibration.
- [ ] Confidence × severity matrix.
- [ ] Condition primitives; boolean grouping; null/type/case pitfalls; entity binding.
- [ ] Frequency: count/rate/distinct/ratio/consecutive; per-entity vs global; burst vs sustained; baseline-driven thresholds.
- [ ] Time: tumbling vs sliding; lookback ≥ frequency; boundary duplication; late data; clock skew; window table.
- [ ] Families: signature, behavioural, anomaly — strengths, weaknesses, tuning, selection.
- [ ] Chaining: enrichment, gating, sequence, risk, suppression; dependency graph and health checks.
- [ ] Risk scoring formula, weights, thresholds, decay, traps.
- [ ] FP programme: classify → sample → discriminate → one change → retest → monitor; lever ranking; targets.
- [ ] Prioritisation formula; queue ordering; dynamic promotion; age escalation.
- [ ] Consolidation keys and over/under-merge risks.
- [ ] Validation: test plan, data sources, acceptance gate, sign-off.
- [ ] Regression: golden dataset, CI, cadence, rollback criteria.
- [ ] Performance: pipeline stages, latency SLO, capacity, dashboards.
- [ ] Precision/recall/F1; measurement methods; small-sample caution; targets.
- [ ] Coverage chain and five levels; risk-weighted prioritisation; reporting.
- [ ] Documentation fields, status model, review cadence, knowledge links.
- [ ] Versioning semver, change record, detection-as-code workflow, rollback.
- [ ] Expiration TTLs, retirement criteria/process, zombie-rule audit.
- [ ] Automation tiers 0–4, trigger design, guardrails, human-in-the-loop, metrics.
- [ ] SLA/SLO/SLI, MTTA/MTTT/MTTC, targets, clock rules, quality guard.
- [ ] Best-practice list memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Vulnerabilities](../03%20-%20Cybersecurity%20Fundamentals/Vulnerabilities.md) · [EDR →](EDR.md)
