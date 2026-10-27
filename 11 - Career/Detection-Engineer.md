# Detection Engineer — Career Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← TryHackMe](../10%20-%20Practice/TryHackMe.md) · [Incident Responder →](Incident-Responder.md)

> Goal: design detections as products — with requirements, tests, versioning, and measured coverage.
> Rule mechanics → [04 - Security Monitoring/Alerting.md](../04%20-%20Security%20Monitoring/Alerting.md) §21–§45; SIEM → `05 - SIEM/`.

---

## 0. How to use this note

1. §1–§3: the role; how it differs; responsibilities.
2. §4–§7: the detection lifecycle; detection-as-code; testing; data.
3. §8–§11: coverage, tuning, metrics, skills.
4. §12–§15: certs, interview, portfolio, 90-day plan.
5. §16–§18: mistakes, self-test, revision.

---

## 1. What a detection engineer is

> **Detection engineer** = someone who turns threat knowledge and telemetry into reliable, tested, maintained detections.

| Analyst | Detection engineer |
|---|---|
| Consumes alerts | Builds alerts |
| Asks "is this real?" | Asks "would this catch it?" |
| Closes cases | Closes coverage gaps |
| Per-case tuning request | Systemic tuning |
| Operates tooling | Engineers logic |

**You are a software engineer for security logic.**

---

## 2. Responsibilities

1. Translate intel/TTPs into detections.
2. Write and maintain Sigma/YARA/SPL/KQL rules.
3. Map coverage to ATT&CK.
4. Test positive, negative, near-miss, edge cases.
5. Backtest volume before deployment.
6. Maintain detection-as-code and CI.
7. Tune based on analyst feedback.
8. Document rationale, FPs, runbooks.
9. Monitor rule health and latency.
10. Retire stale rules.

---

## 3. Where you sit

```
Threat intel ─┐
Purple team ──┼→ Detection engineering → SIEM/EDR → SOC queue
IR findings ──┤                              ↑
Analyst FPs ──┘──────────────────────────────┘
```

**You are the feedback loop between operations and coverage.**

---

## 4. Detection lifecycle

```
Requirement → Research → Data check → Draft rule
→ Test → Backtest → Review → Deploy → Monitor
→ Tune/retire
```

### 4.1 Requirement sources

| Source | Example |
|---|---|
| Intel report | New C2 technique |
| Incident | Missed TTP |
| Purple team | Untested technique |
| Analyst feedback | Noisy rule |
| Compliance | Required control |
| Coverage gap | ATT&CK hole |

### 4.2 Definition of ready

- [ ] Behaviour clearly described.
- [ ] Data source exists and is parsed.
- [ ] Fields available.
- [ ] Test fixtures.
- [ ] Expected volume.
- [ ] FPs considered.
- [ ] Owner assigned.

---

## 5. Detection-as-code

### 5.1 Repository layout

```
detections/
  sigma/
    windows/credential_access_lsass.yml
    linux/persistence_cron.yml
  tests/
    fixtures/
    test_sigma.py
  mappings/attack-coverage.yml
  docs/
  ci/
```

### 5.2 Rule metadata

```yaml
title: LSASS Memory Access by Non-System Process
id: 8b1c2f4e-...
status: production
description: Detects suspicious access to LSASS memory
references: [...]
author: you
date: 2026/04/02
tags: [attack.credential_access, attack.t1003.001]
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains: ['0x1010','0x1410']
  filter:
    SourceImage|startswith: 'C:\Windows\System32\'
  condition: selection and not filter
falsepositives: [EDR agents, backup software]
level: high
```

### 5.3 CI checks

| Check | Tool |
|---|---|
| Schema valid | `sigma check` |
| Lint | YAML lint |
| Backtest | SIEM API |
| Duplicate detection | ID/hash |
| ATT&CK tag valid | Mapping script |
| Tests pass | pytest |

**No rule reaches production without CI.**

---

## 6. Testing

| Test | Fixture |
|---|---|
| Positive | Known malicious event |
| Negative | Normal admin activity |
| Near-miss | Slightly different benign variant |
| Edge | Nulls, unicode, long strings |
| Volume | 30-day replay |

### 6.1 Test example

```python
def test_lsass_positive(rule, events):
    assert rule.match(events["lsass_mimikatz"])

def test_lsass_benign_edr(rule, events):
    assert not rule.match(events["lsass_edr_agent"])
```

### 6.2 Acceptance

- Positive fires.
- Negative silent.
- Near-miss silent.
- Volume acceptable.
- Entities populated.

---

## 7. Data and telemetry

| Question | Why |
|---|---|
| Is the event logged? | No data, no detection |
| Is it parsed? | Fields needed |
| Retention sufficient? | Backtest/retro-hunt |
| Timezone normalised? | Windows |
| Latency acceptable? | Detection delay |
| Cost of query? | Platform load |

### 7.1 Data quality work

Detection engineers often fix parsing before writing rules. **A broken parser produces silent gaps, not alerts.**

---

## 8. Coverage

| Level | Definition |
|---|---|
| 0 | No data |
| 1 | Data exists |
| 2 | Rule exists |
| 3 | Rule tested |
| 4 | Alert actionable |
| 5 | Response playbook |

**Report coverage at level 5, not level 2.**

### 8.1 Prioritisation

1. Techniques used against your sector.
2. Path to crown jewels.
3. Cheap to detect with existing data.
4. Gaps found in incidents.

---

## 9. Tuning

| Signal | Action |
|---|---|
| High FP | Add specificity |
| High volume | Threshold/correlate |
| No fires | Check data/rule |
| Late fires | Reduce lookback |
| Missed TTP | Extend coverage |

### 9.1 Tuning rules

- One change at a time.
- Retest both TP and FP.
- Backtest volume.
- Document reason.
- Monitor 2 weeks.

---

## 10. Metrics

| Metric | Target |
|---|---|
| Rules in production | Growing with quality |
| Tested coverage | Increasing |
| FP rate per rule | < 15% |
| Detection latency p95 | Within SLO |
| Rule failures | 0 |
| Zombie rules | 0 |
| Time from intel to rule | Decreasing |

---

## 11. Skills

| Category | Skills |
|---|---|
| Query | SPL, KQL, EQL, Lucene |
| Formats | Sigma, YARA, STIX |
| Data | Schema/normalisation, parsers |
| Security | ATT&CK, TTPs, IR |
| Engineering | Git, CI, Python, testing |
| Ops | SIEM/EDR administration basics |

### 11.1 Soft skills

- Writing for analysts.
- Saying no to untestable requests.
- Explaining trade-offs.

---

## 12. Certifications

| Cert | Value |
|---|---|
| SC-200 | Sentinel/Defender |
| Splunk Power User / Admin | SPL + platform |
| GCDA / GDSA | Detection/security analytics |
| BTL2 | Practical |
| SANS SEC511 (if sponsored) | Detection depth |

**Portfolio of rules beats certs alone.**

---

## 13. Interview

1. Walk me through building a detection end to end.
2. How do you test a rule?
3. How do you handle a noisy rule?
4. What is the difference between IOC and TTP detection?
5. How do you measure coverage?
6. What is detection-as-code?
7. How do you prioritise gaps?
8. Show a rule you wrote and why.
9. How do you handle missing telemetry?
10. How do you retire a rule?

---

## 14. Portfolio

| Artefact | Value |
|---|---|
| 10–20 Sigma rules with tests | Core evidence |
| Coverage map | Strategic thinking |
| One CI pipeline | Engineering skill |
| One tuning case study | Measured impact |
| One detection writeup | Communication |

---

## 15. First 90 days

| Days | Focus |
|---|---|
| 1–14 | Telemetry inventory, schema, gaps |
| 15–30 | Ship 3 tested rules |
| 31–60 | Build test fixtures + CI |
| 61–90 | Coverage map + retire 2 zombie rules |

---

## 16. Mistakes

| Mistake | Fix |
|---|---|
| Writing rules without data check | Verify first |
| No negative tests | Always test benign |
| Tuning by threshold only | Fix logic |
| No ownership | Assign owner |
| Rules in UI only | Detection-as-code |
| No backtest | Measure volume |
| Chasing coverage numbers | Tested coverage only |
| Ignoring analyst feedback | Close loop |
| Never retiring | Quarterly audit |
| Opaque rationale | Document why |

---

## 17. Self-test

1. How does DE differ from analyst?
2. List five responsibilities.
3. Name the lifecycle stages.
4. What is definition of ready?
5. What belongs in a Sigma rule?
6. What CI checks do you run?
7. What are the four test types?
8. What are the six coverage levels?
9. How do you tune safely?
10. Which metrics matter?

---

## 18. Revision checklist

- [ ] Role: build, test, maintain detections.
- [ ] Feedback loop position.
- [ ] Lifecycle + requirement sources + definition of ready.
- [ ] Detection-as-code layout, metadata, CI.
- [ ] Four test types + acceptance.
- [ ] Data quality dependency.
- [ ] Coverage levels 0–5 + prioritisation.
- [ ] Tuning signals and rules.
- [ ] Metrics.
- [ ] Skills + certs.
- [ ] Interview Qs + portfolio.
- [ ] 90-day plan.
- [ ] Mistakes memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← TryHackMe](../10%20-%20Practice/TryHackMe.md) · [Incident Responder →](Incident-Responder.md)
