# SIEM — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Network Traffic](Network-Traffic.md) · [Detection Rules →](../05%20-%20SIEM/Detection-Rules.md)

> Goal: understand what a SIEM actually does, how data flows through it, and how to use it for detection, triage, and investigation — independent of vendor.
> Log sources → [Logs.md](Logs.md); alert design → [Alerting.md](Alerting.md); query languages → section 05.

---

## 0. How to use this note

1. §1–§3: why SIEM; architecture; data flow.
2. §4–§6: collection/parsing/indexing; search; correlation.
3. §7–§9: detections/use cases; dashboards; case management.
4. §10–§12: tuning, detection-as-code, platform comparison.
5. §13–§16: investigation, triage, operations/metrics, pitfalls.
6. §17–§20: commands, labs, self-test, revision.

---

## 1. Why SIEM matters

- Centralises **logs from everywhere** into one searchable, correlatable platform.
- Turns raw events into **alerts, dashboards, reports, and investigations**.
- Provides **retention, access control, and audit** for security data.
- Enables **cross-source correlation** (identity + endpoint + network).
- Is the SOC's **primary working environment** — most analyst time is spent here.

**What SIEM is not:**
- Not a magic detection engine (rules must be written/tuned).
- Not a replacement for EDR/NDR depth.
- Not a data lake for everything (cost/performance).
- Not a guarantee of coverage.

---

## 2. Architecture

```
Sources                Collection              Processing              Consumption
───────                ──────────              ──────────              ───────────
Endpoints  ─┐   ┌─ Agents/Forwarders ─┐   ┌─ Parsing/Normalise ─┐   ┌─ Search
Servers    ─┤   ├─ Syslog             ─┤   ├─ Enrichment        ─┤   ├─ Correlation
Network    ─┼──►├─ API/Connectors     ─┼──►├─ Index/Store       ─┼──►├─ Alerts
Cloud      ─┤   ├─ WEF                ─┤   ├─ Data models       ─┤   ├─ Dashboards
Apps       ─┘   └─ Streaming          ─┘   └─ Retention tiers   ─┘   └─ Cases/Reports
```

### 2.1 Components

| Component | Role |
|---|---|
| **Collector/forwarder** | Ships events (agent, syslog, API). |
| **Ingest pipeline** | Buffers, routes, applies filters. |
| **Parser** | Extracts fields; normalises. |
| **Enrichment** | Asset/identity/GeoIP/TI lookups. |
| **Indexer/store** | Writes to searchable storage. |
| **Search engine** | Query across time/data. |
| **Correlation engine** | Rules over streams/scheduled searches. |
| **Alert manager** | Dedup, severity, routing, suppression. |
| **Case/ticketing** | Investigation workflow. |
| **Dashboard/reporting** | Visualisation, metrics. |
| **Admin** | Users, roles, retention, health. |

### 2.2 Deployment models

| Model | Notes |
|---|---|
| **On-prem** | Control, cost, maintenance burden. |
| **Cloud/SaaS** | Elastic scale, vendor-managed, egress cost. |
| **Hybrid** | Common; local collection + cloud analytics. |
| **Data lake + SIEM** | Cheap storage + compute for hunting. |
| **MSSP multi-tenant** | Isolation and per-tenant views. |

---

## 3. Data flow in detail

1. **Generate** — source writes an event.
2. **Collect** — agent/API/syslog picks it up.
3. **Buffer** — queue prevents loss during outages.
4. **Filter** — drop known noise *carefully*.
5. **Parse** — extract fields, normalise schema.
6. **Enrich** — add context (asset, identity, geo, TI).
7. **Index** — store with timestamp + fields.
8. **Correlate** — rules match patterns over time.
9. **Alert** — dedup, severity, route.
10. **Investigate** — search, pivot, timeline, case.
11. **Retain/archive** — tiered storage.

**Latency budget:** detection value drops with delay (minutes matter for ransomware/credential attacks).

---

## 4. Collection, parsing, indexing

### 4.1 Onboarding a new source (checklist)

1. **Owner/purpose** — what question does it answer?
2. **Volume estimate** — events/day, bytes.
3. **Format** — syslog/JSON/EVTX/API.
4. **Transport** — agent/syslog/API; TLS; buffering.
5. **Parsing** — field extraction; timestamp format/timezone.
6. **Normalisation** — map to common schema.
7. **Enrichment** — asset/identity lookups.
8. **Retention** — tier and duration.
9. **Use cases** — which detections/dashboards will use it?
10. **Validation** — sample events, field checks, time checks.
11. **Health monitoring** — volume, lag, errors.
12. **Documentation** — source catalogue entry.

### 4.2 Indexing strategy

- **Index by source type/retention need**, not by team.
- Avoid per-customer/per-app index explosion.
- Control **cardinality** (high-cardinality fields cost memory).
- Use **metrics** for high-volume numeric data where possible.
- Plan **hot/warm/cold**.

### 4.3 Normalisation

Map vendor fields to a common schema (Splunk CIM, Elastic ECS, OCSF):

```
user, src_ip, dest_ip, src_port, dest_port, action, status,
process, parent_process, command_line, file_path, hash,
url, domain, bytes_in, bytes_out, event_id, severity
```

**Benefit:** one rule works across vendors; dashboards stay consistent.

---

## 5. Search

### 5.1 Capabilities to expect

- Free-text and field search.
- Time-range filtering.
- Aggregations (`stats`, `count by`).
- Joins/lookups/subsearches.
- Regex extraction.
- Sorting/limiting.
- Saved searches and scheduled searches.
- Export (CSV/JSON).
- Alerting on saved searches.

### 5.2 Query strategy

1. **Scope time** first (smallest defensible window).
2. **Filter index/sourcetype** early.
3. **Filter on indexed fields** where possible.
4. **Aggregate** before sorting.
5. **Limit** results during exploration.
6. **Save** useful queries.

### 5.3 Performance anti-patterns

- `*` searches over 90 days.
- Leading wildcards (`*foo`) on huge datasets.
- Regex on raw text instead of parsed fields.
- Joins between huge datasets.
- Returning raw events when counts suffice.
- Re-running a heavy dashboard ad hoc.

### 5.4 Example patterns

**Splunk**
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| stats count by TargetUserName, src_ip
| where count > 20
```

**Elastic (KQL)**
```
event.code:4625 and winlog.event_data.TargetUserName:* 
```

**Sentinel (KQL)**
```kusto
SecurityEvent
| where EventID == 4625
| summarize count() by TargetUserName, IpAddress
| where count_ > 20
```

---

## 6. Correlation

### 6.1 Types

| Type | Example |
|---|---|
| **Threshold** | >20 failures in 5 min. |
| **Sequence** | Failure → success. |
| **Cardinality** | One source → many accounts. |
| **Temporal join** | Process + network within 60s. |
| **Entity correlation** | Same user across IdP + endpoint. |
| **Absence** | Expected event missing (backup, heartbeat). |
| **Risk-based** | Accumulate risk score per entity. |

### 6.2 Stateful correlation

- Maintain state across events (sessions, counters, windows).
- Watch for **event ordering** and **late arrivals**.
- Define **window semantics** (sliding vs tumbling).
- Avoid unbounded state (memory blowup).

### 6.3 Correlation pitfalls

- Over-correlation → alert storms.
- Under-correlation → missed chains.
- Wrong time windows → misses or noise.
- Missing entity normalisation → same user counted twice.
- No suppression → duplicates.

---

## 7. Detections and use cases

### 7.1 Use-case lifecycle

1. **Identify** — threat/behaviour/requirement.
2. **Design** — logic, data, threshold, severity.
3. **Build** — query + metadata.
4. **Test** — true positive, false positive, edge cases.
5. **Deploy** — schedule, route, document.
6. **Tune** — reduce FP, preserve TP.
7. **Review** — periodic effectiveness check.
8. **Retire** — when obsolete.

### 7.2 Use-case document fields

```
ID, name, description, ATT&CK mapping, data sources,
logic/query, threshold, severity, owner, status,
known false positives, test procedure, last reviewed,
response playbook
```

### 7.3 Coverage categories

- **Identity**: spray, impossible travel, MFA fatigue, consent, token theft.
- **Endpoint**: Office→shell, LSASS, injection, persistence, ransomware.
- **Network**: C2, DNS tunneling, exfil, scans, lateral.
- **Cloud**: IAM changes, public storage, key creation, K8s RBAC.
- **Data**: bulk access, DLP, sharing.
- **Availability**: shadow copy deletion, backup failure, service down.

### 7.4 Detection maturity

| Level | Characteristics |
|---|---|
| **1. Ad hoc** | Manual searches. |
| **2. Signature** | Simple IOC/threshold rules. |
| **3. Behavioural** | TTP-based, correlated. |
| **4. Risk-based/automated** | Entity risk, automated triage/enrichment. |
| **5. Continuous validation** | Purple-teamed, measured, improved. |

---

## 8. Dashboards and reporting

### 8.1 Dashboard types

| Type | Audience | Content |
|---|---|---|
| **Operations** | SOC | Alert queue, open cases, SLA, top sources. |
| **Detection health** | Detection eng | Rule fires, FP rate, coverage, parse errors. |
| **Threat** | Analysts | Top techniques, targeted accounts, geo. |
| **Executive** | Leadership | Trends, MTTD/MTTR, incidents, risk. |
| **Compliance** | Audit | Retention, access, control evidence. |

### 8.2 Design principles

- One question per dashboard.
- Few, meaningful panels.
- Consistent time ranges.
- Drill-down to raw events.
- Label thresholds and units.
- Avoid vanity metrics.

### 8.3 Key metrics

- Alerts/day by severity/source.
- False positive rate.
- **MTTD** (detect), **MTTA** (acknowledge), **MTTR** (respond/resolve).
- % alerts triaged within SLA.
- Detection coverage (ATT&CK).
- Log source health/coverage.
- Escalation rate, incident conversion rate.

---

## 9. Case management and workflow

- **Alert → case** when investigation is needed.
- Case fields: severity, status, owner, timeline, evidence, IOCs, actions.
- Link related alerts/cases.
- Templates per incident type.
- SLA timers and escalations.
- Post-incident notes feed lessons learned.

**Integration:** SOAR playbooks, ticketing (Jira/ServiceNow), chat (Slack/Teams), intel platforms.

---

## 10. Tuning

### 10.1 Tuning levers

| Lever | Effect |
|---|---|
| **Threshold** | Fewer/more alerts. |
| **Time window** | Aggregation scope. |
| **Allowlist** | Suppress known-good (risky if broad). |
| **Enrichment** | Context to auto-close. |
| **Correlation** | Combine weak signals. |
| **Severity** | Prioritisation. |
| **Routing** | Right team/queue. |
| **Suppression** | Dedup/known maintenance. |

### 10.2 Tuning discipline

- Never suppress to make a number look good.
- Document every exclusion with owner/expiry.
- Re-test after tuning.
- Distinguish **false positive** (rule wrong) from **benign true positive** (rule right, no action).
- Review top-firing rules monthly.

### 10.3 Alert fatigue

Symptoms: analysts ignore queues, close without reading, high FP, missed incidents.

Fixes: reduce low-value rules, improve context, auto-enrich, prioritise by risk, measure FP rate per rule.

---

## 11. Detection-as-code

- Store detections in **Git** (versioned, reviewed, tested).
- Use **Sigma** for portability.
- CI pipeline: lint, validate, unit-test with sample events, deploy.
- Peer review changes.
- Tag with ATT&CK, owner, severity, data source.
- Roll back on noise.
- Document test fixtures.

```yaml
title: Suspicious LSASS Access
id: 8b7f6c1e-4a2d-4b9e-9f1a-2c3d4e5f6a7b
status: production
tags: [attack.credential_access, attack.t1003.001]
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
  condition: selection
falsepositives:
  - EDR/backup tools
level: high
```

---

## 12. Platform comparison (conceptual)

| Platform | Strengths | Considerations |
|---|---|---|
| **Splunk** | SPL power, ecosystem, apps. | Licensing by volume. |
| **Elastic Security** | Open, ECS, scalable, cost. | Operational complexity, tuning. |
| **Microsoft Sentinel** | Azure/KQL, cloud connectors, MDE integration. | KQL learning, ingestion cost. |
| **IBM QRadar** | AQL, offence model, enterprise. | Heavier ops, licensing. |
| **Google SecOps (Chronicle)** | UDM, scale, YARA-L, Google telemetry. | Query/model learning. |
| **Sumo Logic** | Cloud-native, log analytics. | SIEM depth varies. |
| **Wazuh** | Open source, HIDS+SIEM. | Scale/ops for large estates. |
| **OpenSearch** | Open, flexible. | Build-your-own SIEM. |

> Learn **concepts + one query language deeply**; others transfer.

---

## 13. Investigation workflow in a SIEM

1. **Read the alert** — rule name, logic, severity, entities.
2. **Open the underlying event(s)** — raw + parsed.
3. **Establish time window** — UTC, include context.
4. **Pivot on entities** — user, host, IP, hash, process.
5. **Correlate across sources** — identity + endpoint + network.
6. **Build a timeline** — sequence events.
7. **Check baseline** — is this normal for this entity?
8. **Determine verdict** — TP/FP/benign.
9. **Document** — query, evidence, conclusion.
10. **Escalate or close** with reason.

---

## 14. Triage playbooks (SIEM-specific)

### A. Alert storm
1. Identify dominant rule/source.
2. Check for scanning, misconfig, or real campaign.
3. Suppress only with evidence and expiry; investigate the underlying activity.

### B. Rule firing but no data
1. Check data source health.
2. Check parsing/field names.
3. Rule may be silently broken — fix or disable.

### C. Detection gap suspected
1. Confirm telemetry exists for the technique.
2. Test with a known event (atomic).
3. Write/adjust rule; validate.

### D. High-volume source
1. Is it needed? Filter at source.
2. Reduce fields/verbosity.
3. Move to cheaper tier or metrics.

### E. Slow search
1. Narrow time/index.
2. Use fields, not raw regex.
3. Aggregate early; avoid joins.
4. Save/schedule for reuse.

---

## 15. Operations and health

| Area | Checks |
|---|---|
| **Ingest** | Volume vs baseline, lag, dropped events. |
| **Parsing** | Failure rate, field coverage. |
| **Search** | Query latency, concurrency. |
| **Storage** | Disk/index growth, retention enforcement. |
| **Alerting** | Rule success/failure, queue depth. |
| **Agents** | Heartbeat, version, coverage. |
| **Access** | RBAC, MFA, admin activity. |
| **Backup** | Config/rule backups. |

**Runbooks:** onboarding, source failure, index full, rule failure, alert storm, retention change.

---

## 16. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Collecting everything, detecting nothing | Cost without value. |
| No normalisation | Vendor lock, brittle rules. |
| No asset/identity enrichment | Weak triage. |
| Poor time handling | Broken correlation. |
| Rules never tuned | Alert fatigue. |
| No rule ownership | Rot and silent failure. |
| No coverage measurement | False confidence. |
| Over-suppression | Missed incidents. |
| No retention planning | Can't investigate. |
| Ignoring ingest health | Blind spots. |
| Dashboards without questions | Noise. |
| No detection testing | Untested claims. |

---

## 17. Commands / query patterns

**Splunk**
```spl
| tstats count where index=* by index, sourcetype
```
```spl
index=* earliest=-24h
| stats count by sourcetype, host
| sort -count
```

**Elastic**
```json
GET logs-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term": { "event.code": "4625" } },
    { "range": { "@timestamp": { "gte": "now-24h" } } }
  ]}},
  "aggs": { "by_user": { "terms": { "field": "winlog.event_data.TargetUserName" } } }
}
```

**Sentinel**
```kusto
union withsource=Table *
| where TimeGenerated > ago(1h)
| summarize count() by Table
| order by count_ desc
```

---

## 18. Labs

1. Deploy a small SIEM (Splunk Free, Elastic, or Sentinel trial).
2. Onboard 3 sources; verify fields and timestamps.
3. Write 5 detections with ATT&CK tags.
4. Build an operations dashboard and a detection-health dashboard.
5. Simulate an attack; triage end-to-end in the SIEM.
6. Break parsing; observe detection failure; fix.
7. Measure FP rate for one rule and tune it.
8. Implement detection-as-code in Git with a validation step.
9. Compare a query's performance before/after optimisation.
10. Document a source catalogue and coverage matrix.

---

## 19. Self-test questions

1. What are the core components of a SIEM?
2. What is the difference between collection, parsing, and normalisation?
3. Why does normalisation matter for multi-vendor detection?
4. What are the three storage tiers and their trade-offs?
5. What is correlation, and name four correlation types?
6. What is the difference between an alert and a case?
7. What metrics measure SOC performance?
8. What is detection-as-code?
9. How do you tune a noisy rule without hiding incidents?
10. What are three query performance anti-patterns?
11. How do you validate a new log source?
12. How do you detect that a detection rule is silently broken?
13. What is the difference between false positive and benign true positive?
14. Why is enrichment essential for triage?
15. What belongs in a use-case document?

---

## 20. One-page revision checklist

- [ ] Why: centralised search/correlation/retention; not magic, not EDR replacement, not a data lake.
- [ ] Architecture: collectors → ingest → parse → enrich → index → search/correlate → alert → case; deployment models.
- [ ] Data flow: generate, collect, buffer, filter, parse, enrich, index, correlate, alert, investigate, retain.
- [ ] Onboarding checklist: owner/purpose, volume, format, transport, parsing, normalisation, enrichment, retention, use cases, validation, health, docs.
- [ ] Indexing: retention-based, cardinality, metrics, tiers.
- [ ] Search: time first, index filter, fields, aggregate, limit, save; anti-patterns (`*` long range, leading wildcard, raw regex, huge joins).
- [ ] Correlation: threshold, sequence, cardinality, temporal join, entity, absence, risk-based; state/windows/late arrivals; pitfalls.
- [ ] Use cases: lifecycle (identify→design→build→test→deploy→tune→review→retire), fields, coverage categories, maturity levels.
- [ ] Dashboards: ops, detection health, threat, executive, compliance; one question, drill-down, key metrics (MTTD/MTTA/MTTR, FP rate, coverage).
- [ ] Cases: alert→case, fields, linking, templates, SLA, integrations.
- [ ] Tuning: thresholds, windows, allowlists, enrichment, correlation, severity, routing, suppression; discipline; alert fatigue.
- [ ] Detection-as-code: Git, Sigma, CI validation, review, tags, fixtures, rollback.
- [ ] Platforms: Splunk, Elastic, Sentinel, QRadar, Chronicle, Sumo, Wazuh, OpenSearch.
- [ ] Investigation: alert → raw events → time → pivot → correlate → timeline → baseline → verdict → document → escalate/close.
- [ ] SIEM triage: storms, no-data rules, gaps, high volume, slow search.
- [ ] Operations: ingest, parsing, search, storage, alerting, agents, access, backup; runbooks.
- [ ] Pitfalls list memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Network Traffic](Network-Traffic.md) · [Detection Rules →](../05%20-%20SIEM/Detection-Rules.md)
