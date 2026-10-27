# Detection Rules — SOC Analyst Study Notes

> Goal: write, test, deploy, and maintain detection rules that find real attacks without drowning the SOC.
> Alert design/UX → `04 - Security Monitoring/Alerting.md`; query syntax → `Queries.md`; ATT&CK → `03 - Cybersecurity Fundamentals/MITRE-ATTACK.md`.

---

## 0. How to use this note

1. §1–§3: role of detections; anatomy; rule taxonomy.
2. §4–§6: logic patterns; severity/scoring; metadata.
3. §7–§10: engineering lifecycle, testing, tuning, deployment.
4. §11–§13: detection-as-code, coverage, maintenance.
5. §14–§16: examples, pitfalls, labs.
6. §17–§18: self-test, revision.

---

## 1. Why detection rules matter

- They convert raw telemetry into **analyst attention**.
- They are the SOC's **product**: coverage, quality, and cost all live here.
- Bad rules cause **alert fatigue** and **false confidence**.
- Good rules encode **adversary behaviour** and **environment knowledge**.

**Two failure modes:**
1. **False negative** — attack happens, no alert. (Breach.)
2. **False positive** — alert happens, no attack. (Waste/fatigue.)

Detection engineering optimises both, measurably.

---

## 2. Anatomy of a rule

| Component | Purpose |
|---|---|
| **Name** | Specific, human-readable. |
| **Description** | Behaviour and rationale. |
| **Logic** | Query/expression. |
| **Data source** | Which telemetry it needs. |
| **Required fields** | Parsing dependencies. |
| **Severity** | Impact/confidence. |
| **ATT&CK mapping** | Technique(s). |
| **Entities** | What to pivot on. |
| **Threshold/window** | Volume/time bounds. |
| **Throttle/dedup** | Prevent storms. |
| **False positives** | Known benign causes. |
| **Response guidance** | What to do. |
| **Owner** | Accountability. |
| **Version/date** | Change tracking. |
| **Test cases** | TP and FP samples. |

**A rule without tests is a hypothesis, not a detection.**

---

## 3. Rule taxonomy

| Type | Logic | Example |
|---|---|---|
| **Single event** | One event matches. | `7045` service installed. |
| **Threshold** | N events in window. | 20 failed logons in 5m. |
| **Pattern/sequence** | A then B. | Failure then success. |
| **Correlation** | Multiple sources align. | EDR + proxy + auth. |
| **Baseline/anomaly** | Deviation from norm. | New process first seen. |
| **Reputation/IOC** | Matches known-bad. | Hash/domain/IP match. |
| **Stateful** | Tracks entity state. | First admin logon from host. |
| **Policy** | Violates a stated policy. | USB mass storage. |
| **ML/statistical** | Learned model. | Rare command line. |
| **Composite** | Combines signals into risk. | Entity risk score. |

**Complexity ladder:** start single-event/threshold; escalate to sequence/correlation only when needed.

---

## 4. Logic patterns

### 4.1 Single event

```kusto
DeviceEvents
| where ActionType == "ServiceInstalled"
| project TimeGenerated, DeviceName, AccountName, AdditionalFields
```
Pros: simple, fast. Cons: noisy alone; easy to evade.

### 4.2 Threshold

```kusto
SecurityEvent
| where EventID == 4625
| summarize Fails=count() by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where Fails >= 20
```

### 4.3 First-seen / rarity

```kusto
let seen = DeviceProcessEvents
  | where TimeGenerated between (ago(30d) .. ago(1d))
  | summarize by FileName, SHA256, DeviceId;
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| join kind=leftanti seen on FileName, SHA256, DeviceId
```

### 4.4 Sequence

```kusto
let fail = SecurityEvent | where EventID==4625 | project T1=TimeGenerated, U=TargetUserName, IP=IpAddress;
let succ = SecurityEvent | where EventID==4624 | project T2=TimeGenerated, U=TargetUserName, IP=IpAddress;
fail | join kind=inner succ on U, IP
| where T2 between (T1 .. T1 + 10m)
```

### 4.5 Correlation across sources

```kusto
let mail = EmailEvents | where ThreatTypes has "Phish" | project T=TimeGenerated, R=RecipientEmailAddress;
let exec = DeviceProcessEvents | where FileName =~ "powershell.exe" | project T=TimeGenerated, R=AccountUpn;
mail | join kind=inner exec on R | where exec_T between (T .. T+30m)
```

### 4.6 Ratio/behaviour

```kusto
DeviceNetworkEvents
| summarize Out=sum(BytesSent), In=sum(BytesReceived) by DeviceName, bin(TimeGenerated,1h)
| extend ratio = Out / In
| where Out > 100000000 and ratio > 5
```

### 4.7 Absence

```kusto
Heartbeat
| summarize Last=max(TimeGenerated) by Computer
| where Last < ago(4h)
```
Detects **missing telemetry**, which is itself an incident indicator.

---

## 5. Severity and scoring

### 5.1 Inputs

| Factor | Higher severity when |
|---|---|
| **Impact** | Data loss, ransomware, admin compromise. |
| **Confidence** | High-fidelity telemetry, specific behaviour. |
| **Asset** | DC, finance, prod, internet-facing. |
| **Privilege** | SYSTEM/admin/root. |
| **Stage** | Later kill-chain stage. |
| **Scope** | Multiple hosts/users. |
| **Novelty** | First-seen behaviour. |

### 5.2 Simple model

```
score = impact(1-3) × confidence(1-3) × asset(1-3)
```

| score | severity |
|---|---|
| 1–4 | low |
| 5–9 | medium |
| 10–18 | high |
| 19–27 | critical |

Document the model; apply consistently.

### 5.3 Risk-based

- Each detection contributes **risk points** to an entity.
- Risk accumulates; thresholds create alerts.
- Reduces single-event noise.
- Requires tuning of point values.

### 5.4 Severity anti-patterns

- Everything "critical".
- Severity set by vendor default.
- Severity never re-evaluated after tuning.
- Severity not tied to asset context.

---

## 6. Rule metadata and naming

### 6.1 Naming convention

```
<Platform/Area> - <Behaviour> - <Entity/Technique>
```

Examples:
- `Windows - Encoded PowerShell Execution - Process`
- `AWS - IAM User Created - CloudTrail`
- `Identity - Password Spray - Sign-in`

**Good names let an analyst triage from the alert list alone.**

### 6.2 Description template

```
Detects: <behaviour>
Why it matters: <impact>
False positives: <known causes>
Response: <first actions>
ATT&CK: <tactic/technique>
Data source: <index/table>
```

### 6.3 Required fields

```
title, id, status, description, references, author, date,
modified, tags (attack.*, cve.*), logsource, detection,
falsepositives, level
```

(This is essentially the **Sigma** schema — use it even on non-Sigma platforms.)

---

## 7. Engineering lifecycle

```
1. Requirement    (intel, gap, incident lesson, ATT&CK coverage)
2. Research       (adversary behaviour, telemetry availability)
3. Design         (logic, data source, threshold, severity)
4. Implement      (query, metadata)
5. Test           (TP, FP, edge cases, performance)
6. Review         (peer, false-positive analysis)
7. Deploy         (staged: alert-only → tuned → production)
8. Monitor        (volume, precision, errors)
9. Tune           (thresholds, context, suppression)
10. Retire        (obsolete or superseded)
```

### 7.1 Requirement sources

- Threat intel reporting.
- Incident RCA ("we missed this").
- Purple-team results.
- ATT&CK coverage gaps.
- New log source.
- Vulnerability/exploit change.

---

## 8. Testing

### 8.1 Test cases needed

| Case | Expected |
|---|---|
| **True positive** | Fires. |
| **True negative** | Silent. |
| **Near-miss FP** | Silent (benign lookalike). |
| **Edge** | Empty fields, nulls, unicode, long strings. |
| **Volume** | Performance acceptable. |
| **Regression** | Old behaviour still detected. |

### 8.2 Test methods

- **Replay** historical/attack-simulation data.
- **Atomic Red Team** / Caldera / purple-team.
- **Synthetic events** (`makeresults`, Event Viewer test).
- **Lab detonation** of malware.
- **Unit tests** on query logic with fixtures.
- **Backtest** over 30–90 days for volume.

### 8.3 Backtesting

```spl
index=windows earliest=-30d latest=now
<rule logic>
| stats count
```

If it fires 4,000 times in 30 days, it is not ready.

**Set an acceptance bar:** e.g., ≤5 alerts/day and ≥1 confirmed TP in testing.

### 8.4 Testing pitfalls

- Only testing with one sample.
- Testing after deployment.
- Ignoring performance.
- Ignoring null-field behaviour.
- No negative control.

---

## 9. Tuning

### 9.1 Signals

- High volume, low precision.
- Analyst closes as FP repeatedly.
- Environmental change increases noise.
- New legitimate software/role.

### 9.2 Levers

| Lever | Effect |
|---|---|
| Threshold | Fewer alerts. |
| Add condition | Exclude benign pattern. |
| Add correlation | Improve confidence. |
| Context/asset filter | Skip low-value assets. |
| Severity change | Re-prioritise. |
| Suppression | Silence known-good (time-boxed). |
| Split rule | Different behaviours, different handling. |
| Retire/merge | Reduce duplication. |

### 9.3 Discipline

- Change one thing at a time.
- Re-test TP and FP.
- Document rationale and date.
- Re-baseline after change.
- Review within 30 days.

---

## 10. Deployment

### 10.1 Stages

1. **Draft** — not running.
2. **Test/alert-only** — visible to engineers only.
3. **Tuned** — small analyst group.
4. **Production** — routed to queue.
5. **Deprecated** — disabled with reason.

### 10.2 Change control

- Peer review.
- Version bump.
- Rollback plan.
- Changelog entry.
- Notification to SOC.

### 10.3 Environment promotion

```
dev → test → prod
```

Never test a new noisy rule directly in the production queue.

---

## 11. Detection-as-code

### 11.1 Why

- Version control (git).
- Code review.
- Automated testing/CI.
- Reproducible deployment.
- Audit trail.

### 11.2 Structure

```
detections/
├── windows/
│   ├── encoded-powershell.yml
│   └── lsass-access.yml
├── cloud/
│   └── iam-user-created.yml
├── tests/
│   └── fixtures/
└── README.md
```

### 11.3 Sigma example

```yaml
title: Encoded PowerShell Command Line
id: 6f1a3c2e-0000-4000-8000-000000000001
status: experimental
description: Detects PowerShell with base64-encoded command.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: SOC
date: 2025/01/01
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
      - ' -e '
  condition: selection
falsepositives:
  - Admin scripts using encoded commands
level: high
```

### 11.4 CI checks

- Schema validation.
- Unit tests against fixtures.
- Linting/naming conventions.
- Backtest volume estimate.
- Duplicate detection.
- ATT&CK mapping present.

---

## 12. Coverage

### 12.1 Coverage ≠ count of rules

Real coverage = **data source exists + telemetry reaches SIEM + rule is tested + analyst can act**.

### 12.2 Measurement

| Level | Evidence |
|---|---|
| **Nominal** | A rule exists for the technique. |
| **Data** | Required logs are collected and parsed. |
| **Detection** | Rule fires in a purple-team test. |
| **Response** | Playbook and containment exist. |
| **Validated** | Repeated success over time. |

### 12.3 Prioritise

- Techniques used by relevant threat actors.
- Techniques with existing data sources.
- Techniques in the kill chain path to critical assets.
- Gaps found in incidents.

**100% ATT&CK coverage is a vanity metric**; realistic prioritised coverage is the goal.

---

## 13. Maintenance

| Activity | Cadence |
|---|---|
| Rule health review (volume/precision) | Weekly |
| Top-20 noisy rules | Monthly |
| ATT&CK coverage review | Quarterly |
| Retire obsolete rules | Quarterly |
| Re-test critical rules | Quarterly |
| Data source dependency audit | Quarterly |
| Detection-as-code dependency updates | As needed |

### 13.1 Rule rot

- Data source changes → silent failure.
- Field renamed → zero results.
- Environment changes → noise.
- Adversary changes → evasion.
- Owner leaves → orphan.

**Track "last fired" and "last reviewed".** A rule that never fires may be broken.

---

## 14. Example detection set (Windows)

| Detection | Logic core | Severity |
|---|---|---|
| Encoded PowerShell | `powershell -enc <b64>` | High |
| Office spawns shell | parent in Office/browser → shell | High |
| LSASS access | OpenProcess on lsass by non-security | Critical |
| Service installed | `7045` with odd path | Medium |
| Schtasks created | `4698` by non-admin | Medium |
| Shadow copy deleted | `vssadmin delete shadows` | Critical |
| Defender disabled | `5001`/registry tamper | High |
| New local admin | `4732` to Administrators | High |
| Kerberoasting | `4769` RC4 to many SPNs | High |
| SMB fan-out | one host → many on 445 | High |
| Brute force | `4625` threshold | Medium |
| Success after failure | sequence | High |
| New external RDP | `4624` type 10 from external | High |
| WMI persistence | `__EventFilter`/`CommandLineEventConsumer` | High |
| Suspicious driver load | unsigned driver `6`/`7045` | High |

---

## 15. Common pitfalls

| Pitfall | Consequence |
|---|---|
| No test cases | Unknown behaviour. |
| Vendor-default severity | Wrong prioritisation. |
| Thresholds guessed | Noise or blindness. |
| No dedup/throttle | Storms. |
| Missing asset context | Can't prioritise. |
| No owner | Rule rot. |
| Deployed untested | Fatigue. |
| Over-complex logic | Fragile/unmaintainable. |
| Duplicate rules | Conflicting alerts. |
| No ATT&CK mapping | Blind coverage. |
| Ignoring data dependencies | Silent failure. |
| Never retiring | Queue bloat. |
| Optimising for count | Vanity coverage. |

---

## 16. Labs

1. Write a Sigma rule for encoded PowerShell; convert to two platforms.
2. Test it with Atomic Red Team; capture TP and FP.
3. Backtest 30 days; compute estimated daily volume.
4. Build a sequence rule (failure→success) and tune it.
5. Write an absence rule for a missing log source.
6. Create a severity matrix and apply to 10 rules.
7. Set up a git repo with CI validation for Sigma.
8. Tune a noisy rule; document before/after precision.
9. Map 20 rules to ATT&CK; identify 5 gaps.
10. Retire/merge 3 overlapping rules.

---

## 17. Self-test questions

1. What are the two failure modes of a detection?
2. What must every rule include besides logic?
3. Name five rule types and when to use each.
4. Why is first-seen detection powerful?
5. How do you write a sequence rule without `transaction`?
6. What factors set severity?
7. What is a backtest, and why do it?
8. What acceptance bar would you set before production?
9. What is detection-as-code?
10. What are the five levels of coverage?
11. Why is rule count a bad coverage metric?
12. What is rule rot?
13. How do you know a rule is broken?
14. How do you tune without creating blind spots?
15. What belongs in a rule's false-positive section?

---

## 18. One-page revision checklist

- [ ] Purpose: convert telemetry → attention; product of the SOC; FN = breach, FP = fatigue.
- [ ] Anatomy: name, description, logic, data source, fields, severity, ATT&CK, entities, threshold/window, throttle, FPs, response, owner, version, tests.
- [ ] Taxonomy: single event, threshold, sequence, correlation, baseline/anomaly, reputation, stateful, policy, ML, composite.
- [ ] Logic patterns: single, threshold, first-seen, sequence, cross-source, ratio, absence.
- [ ] Severity: impact, confidence, asset, privilege, stage, scope, novelty; scoring model; risk-based; anti-patterns.
- [ ] Metadata/naming: `<Area> - <Behaviour> - <Entity>`; description template; Sigma schema fields.
- [ ] Lifecycle 10 steps; requirement sources.
- [ ] Testing: TP/TN/near-miss/edge/volume/regression; replay, Atomic Red Team, synthetic, lab, unit tests, backtest; acceptance bar; pitfalls.
- [ ] Tuning levers and discipline (one change, retest, document, re-baseline).
- [ ] Deployment stages, change control, environment promotion.
- [ ] Detection-as-code: git, review, CI, Sigma YAML, checks.
- [ ] Coverage levels: nominal, data, detection, response, validated; prioritise actor-relevant techniques; count is vanity.
- [ ] Maintenance cadence; rule rot causes.
- [ ] Example detection set (Windows) recalled.
- [ ] Pitfalls list memorised.
