# SOAR — SOC Automation Study Notes

> Goal: turn repeated analyst work into reliable, auditable playbooks — without automating your way into an outage.
> API mechanics → `APIs.md`; scripting → `Python.md` / `PowerShell.md` / `Bash.md`.

---

## 0. How to use this note

1. §1–§3: what SOAR is; SIEM vs SOAR; components.
2. §4–§7: use cases; playbook design; decision logic; human-in-the-loop.
3. §8–§11: integrations; case management; testing; deployment.
4. §12–§16: metrics, governance, maturity, pitfalls.
5. §17–§19: platform notes, labs.
6. §20–§21: self-test, revision.

---

## 1. What SOAR is

> **SOAR** = Security Orchestration, Automation and Response — a platform that connects tools, runs workflows, and manages cases.

| Letter | Meaning |
|---|---|
| **S**ecurity | Scope. |
| **O**rchestration | Coordinate tools via APIs. |
| **A**utomation | Execute steps without humans. |
| **R**esponse | Act on findings. |

**SOAR is a workflow engine + integrations + case management, not a detection tool.**

---

## 2. SIEM vs SOAR

| | SIEM | SOAR |
|---|---|---|
| **Core** | Collect, correlate, detect | Orchestrate, automate, track |
| **Input** | Logs | Alerts, tickets, humans |
| **Output** | Alerts | Actions, cases, reports |
| **Strength** | Visibility | Efficiency, consistency |
| **Failure** | No data | Bad playbooks / over-automation |

**SOAR without a SIEM is blind; SIEM without SOAR is manual.**

---

## 3. Components

| Component | Function |
|---|---|
| **Playbook / workflow** | Ordered steps with logic. |
| **Integrations / apps** | Connectors to products. |
| **Actions** | Atomic operations (`isolate_host`). |
| **Case management** | Tickets, evidence, tasks. |
| **Decision logic** | Conditions, branches, loops. |
| **Human tasks** | Approval/input steps. |
| **Scheduling** | Timed jobs, polling. |
| **Reporting** | Metrics and dashboards. |
| **Secrets store** | Credentials per integration. |
| **Audit log** | Who/what/when. |

---

## 4. Use cases

| Priority | Use case | Automation level |
|---|---|---|
| 1 | **Enrichment** (TI, asset, identity) | Full |
| 2 | **Ticket creation / dedup** | Full |
| 3 | **Notification / routing** | Full |
| 4 | **Evidence collection** | Full |
| 5 | **Phishing triage** | Mostly automated + human verdict |
| 6 | **IOC blocking** | Semi (allowlist + confidence) |
| 7 | **Host isolation** | Approval-gated |
| 8 | **Account disable** | Approval-gated |
| 9 | **Eradication steps** | Human-led with automation assist |
| 10 | **Reporting** | Scheduled |

**Automate in this order. Enrichment first, containment last.**

### 4.1 Anti-use-cases

- Fully automated "close all alerts".
- Auto-remediation on low-confidence detections.
- Automating a process nobody has defined.
- Replacing analyst judgement.

---

## 5. Playbook design

### 5.1 Anatomy

```
Trigger (alert/webhook/schedule)
  → Validate input
  → Enrich (parallel where possible)
  → Score / decide
  → Branch (benign / suspicious / malicious)
  → Act (ticket / block / isolate / notify)
  → Collect evidence
  → Update case
  → Close with disposition
```

### 5.2 Design rules

| Rule | Why |
|---|---|
| One purpose per playbook | Reusability |
| Explicit inputs/outputs | Composability |
| Idempotent steps | Safe retries |
| Timeouts on every action | No hangs |
| Fail to a human task | No silent stop |
| Log every action | Audit |
| Version control | Change control |
| Test data included | Regression |

### 5.3 Naming

```
<domain>_<trigger>_<goal>_v<major>
phishing_report_enrich_and_verdict_v2
identity_risky_signin_contain_v1
```

---

## 6. Decision logic

| Pattern | Use |
|---|---|
| **If/else** | Binary branch |
| **Switch** | Multiple outcomes |
| **Loop** | Per entity (hosts, IOCs) |
| **Parallel** | Independent enrichments |
| **Join** | Wait for all branches |
| **Sub-playbook** | Reuse |
| **Retry** | Transient failures |
| **Human task** | Approval |

### 6.1 Scoring inside a playbook

```
risk = base(rule) + ti(reputation) + asset(criticality) + identity(privilege)

if risk >= 85 and action == isolate: human_approval
elif risk >= 85: escalate
elif risk >= 50: ticket
else: close_with_audit
```

**Encode policy explicitly. Do not bury it in ad-hoc conditions.**

### 6.2 Loop discipline

- Cap iterations.
- Handle partial failure per item.
- Aggregate results.
- Never loop a destructive action without confirmation.

---

## 7. Human-in-the-loop

| Tier | Human role |
|---|---|
| **0** | None — enrich only |
| **1** | Review after action (audit) |
| **2** | Approve action |
| **3** | Perform action, automation assists |
| **4** | Automation only suggests |

### 7.1 Approval design

| Element | Good |
|---|---|
| Approver | Named role, not "anyone" |
| Context | Evidence + impact summary |
| Timeout | Escalate after N minutes |
| Reversibility | Stated |
| Audit | Who approved, when, why |

**Approvals with no context become rubber stamps.**

---

## 8. Integrations

| Category | Examples |
|---|---|
| SIEM | Splunk, Sentinel, Elastic, QRadar |
| EDR | CrowdStrike, Defender, SentinelOne |
| Identity | Entra ID, Okta, AD |
| Email | M365, Google Workspace, Proofpoint |
| TI | VirusTotal, MISP, Recorded Future |
| Ticketing | ServiceNow, Jira |
| Firewall/proxy | Palo Alto, Zscaler, Fortinet |
| Cloud | AWS, Azure, GCP |
| Comms | Slack, Teams, email |
| Sandbox | Any.run, Joe Sandbox |

### 8.1 Integration quality

| Check | Why |
|---|---|
| Auth method | OAuth/key/mTLS |
| Scope | Least privilege |
| Rate limits | Throttle |
| Pagination | Completeness |
| Error semantics | Correct handling |
| Version pin | Stability |
| Data mapping | Field consistency |

**Every integration is an attack surface and a failure point.**

---

## 9. Case management

| Field | Use |
|---|---|
| Case ID | Reference |
| Severity | Priority |
| Status | Workflow |
| Assignee | Ownership |
| Tasks | Checklist |
| Evidence | Artefacts/links |
| Timeline | Actions |
| Linked alerts | Context |
| Disposition | Closure |
| SLA timers | Accountability |

### 9.1 Case hygiene

- One case per incident (not per alert).
- Close with disposition code.
- Link the playbook run.
- Attach evidence, not screenshots of evidence only.

---

## 10. Testing

| Test | Purpose |
|---|---|
| **Unit** | Single action with mock |
| **Integration** | Real API in sandbox |
| **End-to-end** | Trigger → action |
| **Negative** | Bad input handling |
| **Load** | Many concurrent runs |
| **Chaos** | API down/timeout |
| **Regression** | Golden output |

### 10.1 Test data

- Safe, synthetic alerts.
- Known-benign + known-malicious samples.
- Malformed payloads.
- Rate-limit responses.

**Never test destructive actions against production.**

### 10.2 Sandbox pattern

```
Test tenant → test EDR host → test mailbox → test ticket queue
```

---

## 11. Deployment

| Stage | Gate |
|---|---|
| Draft | Design review |
| Test | Tests pass |
| Shadow | Runs but doesn't act |
| Approval | SOC lead sign-off |
| Limited | One queue/team |
| Full | All alerts |
| Post-deploy | 48 h watch |

### 11.1 Shadow mode

Run the playbook and log what it *would* have done. Compare to analyst decisions for 2 weeks. **This is the single best pre-deployment test.**

---

## 12. Metrics

| Metric | Meaning |
|---|---|
| **Automation rate** | % alerts touched |
| **Straight-through rate** | % closed with no human |
| **MTTR improvement** | Before/after |
| **Time saved** | Hours per week |
| **Failure rate** | Runs failing |
| **False actions** | Wrong blocks/isolations |
| **Approval latency** | Human bottleneck |
| **Playbook coverage** | Alerts with a playbook |

**Automation rate is vanity; false actions are the real risk metric.**

---

## 13. Governance

| Control | Detail |
|---|---|
| Ownership | Named owner per playbook |
| Change management | Version + review |
| Least privilege | Per-integration creds |
| Audit | Immutable run logs |
| Kill switch | Disable per playbook |
| Data handling | No PII leakage |
| Retention | Per policy |
| Periodic review | Quarterly |

### 13.1 Kill switch scenarios

- Mass false isolates.
- API credential failure loop.
- Vendor outage causing retries.
- Runaway ticket creation.

**Every playbook must be disableable in under a minute.**

---

## 14. Common failure modes

| Failure | Cause |
|---|---|
| Alert storm triggers 10k actions | No dedup/throttle |
| Playbook loops forever | No iteration cap |
| Blocks own infrastructure | No allowlist |
| Credentials expire silently | No monitoring |
| Duplicate cases | No idempotency |
| Approval never granted | No timeout/escalation |
| Analyst bypasses playbook | Too slow/complex |
| Automation hides context | Over-aggregation |

---

## 15. Maturity

| Level | Characteristics |
|---|---|
| 1 | Manual, no orchestration |
| 2 | Enrichment scripts |
| 3 | Playbooks for top use cases |
| 4 | Human-in-loop containment |
| 5 | Metrics-driven, continuously tuned |

**Most SOCs should aim for level 3–4, not full autonomy.**

---

## 16. Pitfalls

| Pitfall | Consequence |
|---|---|
| Automating undefined process | Chaos at scale |
| Skipping shadow mode | Surprise outages |
| Over-broad credentials | Blast radius |
| No idempotency | Duplicates |
| No kill switch | Runaway |
| No tests | Silent breakage |
| Ignoring failure alerts | Broken automation unnoticed |
| No ownership | Decay |
| Automating judgement | Wrong verdicts |
| No audit trail | Unaccountable |

---

## 17. Platform notes

| Platform | Notes |
|---|---|
| **Splunk SOAR** | Playbooks, apps, case mgmt. |
| **Palo Alto XSOAR / Cortex** | Content packs, marketplace. |
| **Tines** | Visual, lightweight, API-first. |
| **Shuffle** | Open-source. |
| **n8n** | General automation. |
| **Sentinel Logic Apps** | Azure-native. |
| **TheHive + Cortex** | Case mgmt + analysers. |
| **Torq / Swimlane** | No-code/low-code. |

**Choose by integration fit, not feature list.**

---

## 18. Labs

1. Map one alert type to a playbook diagram.
2. Build enrichment-only playbook and measure time saved.
3. Add a scoring branch and approval task.
4. Shadow-mode a containment playbook for 20 alerts.
5. Add idempotency and dedup.
6. Simulate API failure and verify human fallback.
7. Add a kill switch and test it.
8. Create a case template.
9. Write tests for input validation.
10. Measure MTTR before/after.

---

## 19. Design review checklist

- [ ] Purpose and trigger defined.
- [ ] Inputs validated.
- [ ] Enrichment parallelised.
- [ ] Decision policy explicit.
- [ ] Destructive actions approval-gated.
- [ ] Every action idempotent.
- [ ] Timeouts and retries set.
- [ ] Failure path to human.
- [ ] Evidence collected.
- [ ] Case updated.
- [ ] Audit log complete.
- [ ] Secrets from store.
- [ ] Kill switch tested.
- [ ] Tests and shadow run done.
- [ ] Owner and review date.

---

## 20. Self-test questions

1. What does SOAR stand for?
2. SIEM vs SOAR?
3. Name the core components.
4. Which use case should you automate first?
5. What makes a playbook idempotent?
6. Why cap loops?
7. What are the five human-in-the-loop tiers?
8. What makes an approval meaningful?
9. What is shadow mode?
10. Which metric matters more than automation rate?
11. What is a kill switch for?
12. Name four common failure modes.
13. What are SOAR maturity levels?
14. Why is automating undefined process dangerous?
15. What belongs in a design review?

---

## 21. One-page revision checklist

- [ ] SOAR = orchestration + automation + response + case mgmt.
- [ ] SIEM detects; SOAR acts.
- [ ] Components: playbooks, integrations, actions, cases, decisions, human tasks, schedule, secrets, audit.
- [ ] Use-case priority: enrichment → tickets → notify → evidence → triage → block → contain.
- [ ] Playbook anatomy and design rules; naming convention.
- [ ] Decision patterns incl. parallel/join/sub-playbook/retry.
- [ ] Explicit scoring policy.
- [ ] Human-in-loop tiers 0–4; approval design.
- [ ] Integration quality checks; least privilege.
- [ ] Case fields and hygiene.
- [ ] Test types incl. negative and chaos; sandbox.
- [ ] Deployment gates incl. shadow mode.
- [ ] Metrics: automation, STP, MTTR, failures, false actions.
- [ ] Governance: owner, versioning, audit, kill switch, review.
- [ ] Failure modes table.
- [ ] Maturity 1–5.
- [ ] Pitfalls memorised.
- [ ] Design review checklist.
