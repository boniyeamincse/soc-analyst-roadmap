# Elastic Security — SOC Analyst Study Notes

> Goal: use the Elastic Stack as a SIEM — ingest, search, detect, triage, and respond — and understand the index mechanics behind it.
> Cross-platform query craft → `Queries.md`; rule engineering → `Detection-Rules.md`; collection → `Log-Collection.md`.

---

## 0. How to use this note

1. §1–§3: stack architecture; data streams/indices; ECS.
2. §4–§6: ingest pipelines; searching (KQL, DSL, ES\|QL, EQL).
3. §7–§10: detection rules; exceptions; alerts/timeline; cases.
4. §11–§13: endpoint features; dashboards; operations/hardening.
5. §14–§16: best practices, pitfalls, labs.
6. §17–§18: self-test, revision.

---

## 1. The Elastic Stack

| Component | Role |
|---|---|
| **Elasticsearch** | Store, index, search, aggregate. |
| **Kibana** | UI: Discover, Dashboards, Security app, Dev Tools. |
| **Elastic Agent + Fleet** | Unified agent + central management. |
| **Beats** | Lightweight shippers (Filebeat, Winlogbeat, Packetbeat, Auditbeat). |
| **Logstash** | Heavy processing/transform/routing. |
| **Integrations** | Package: config + index templates + dashboards + pipelines. |

### 1.1 Deployment options

- Elastic Cloud (managed).
- Self-managed (on-prem).
- Elastic Cloud Enterprise / Serverless.

**Security app** = SIEM (detections, alerts, timeline, cases) + endpoint protection + host isolation.

---

## 2. Data model

### 2.1 Indices, data streams, ILM

| Concept | Meaning |
|---|---|
| **Index** | Sharded storage unit. |
| **Data stream** | Append-only abstraction over backing indices (time-series). |
| **Index template** | Mappings/settings for new indices. |
| **ILM** | Hot → warm → cold → frozen → delete policy. |
| **Alias** | Query name over one/many indices. |

```
logs-windows.security-default-2025.01.01-000001
└── data stream: logs-windows.security-default
```

### 2.2 Mapping

- **`text`** — analyzed, for full-text.
- **`keyword`** — exact match, aggregations, sorting.
- **Numeric/date/ip/geo_point/boolean**.
- **`flattened`** / `object` / `nested`.

**Wrong type = wrong results.** `src_ip` as `text` breaks `cidr`/range queries.

### 2.3 Shards and sizing

- 1 primary + replicas per index.
- Target ~10–50 GB per shard; avoid oversized shards.
- Too many small shards = cluster overhead.
- Monitor `_cluster/health`, `_cat/indices`, `_cat/shards`.

---

## 3. ECS (Elastic Common Schema)

| Field group | Examples |
|---|---|
| **event** | `event.category`, `event.type`, `event.action`, `event.outcome`, `event.code`. |
| **host** | `host.name`, `host.ip`, `host.os.*`. |
| **user** | `user.name`, `user.domain`, `user.id`. |
| **source/destination** | `source.ip`, `source.port`, `destination.ip`. |
| **process** | `process.name`, `process.pid`, `process.parent.*`, `process.command_line`. |
| **file** | `file.path`, `file.hash.sha256`. |
| **network** | `network.protocol`, `network.bytes`, `network.direction`. |
| **url/domain** | `url.full`, `url.domain`, `dns.question.name`. |
| **cloud** | `cloud.provider`, `cloud.account.id`. |

**ECS is what makes prebuilt rules work across integrations.** Normalise custom sources to ECS.

---

## 4. Ingest pipelines

```
Agent → (integration pipeline) → (custom pipeline) → index
```

- **Grok/dissect** for unstructured logs.
- **JSON** parsing.
- **Date** processors for timestamps.
- **Rename/copy/remove** fields.
- **Script** processor for complex logic.
- **Enrich** processor with lookup indices.
- **GeoIP**.

```json
{
  "processors": [
    { "grok": { "field": "message",
        "patterns": ["%{IP:source.ip} - %{DATA:user.name} \\[%{HTTPDATE:timestamp}\\] \"%{WORD:http.request.method} %{DATA:url.original}\""] } },
    { "date": { "field": "timestamp", "formats": ["dd/MMM/yyyy:HH:mm:ss Z"] } },
    { "remove": { "field": "message" } }
  ]
}
```

**Test pipelines with `_simulate`** before deploying.

```bash
POST _ingest/pipeline/_simulate
{ "pipeline": {...}, "docs": [{ "_source": { "message": "..." } }] }
```

---

## 5. Searching

### 5.1 Kibana Query Language (KQL)

```
event.category: authentication and event.outcome: failure
user.name: ("alice" or "bob")
source.ip: 10.0.0.0/8
process.command_line: *powershell* and not process.name: "explorer.exe"
```

- Field: value; `and`/`or`/`not`; wildcards; ranges (`>=`).
- KQL is for filtering, not aggregation.

### 5.2 Query DSL (JSON)

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.code": "4625" } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ],
      "must_not": [ { "term": { "user.name": "svc_scanner" } } ]
    }
  },
  "aggs": { "by_user": { "terms": { "field": "user.name", "size": 20 } } }
}
```

- `filter` context = cacheable, no scoring → **use for security queries**.
- `term` on `keyword`, `match` on `text`.

### 5.3 ES|QL

```
FROM logs-* 
| WHERE event.category == "authentication" AND event.outcome == "failure"
| STATS failures = COUNT(*) BY user.name, source.ip
| SORT failures DESC
| LIMIT 20
```

### 5.4 EQL

```
sequence by user.name with maxspan=10m
  [ authentication where event.outcome == "failure" ]
  [ authentication where event.outcome == "success" ]
```

EQL is built for **event correlation by entity over time** — ideal for security.

### 5.5 Performance

- Filter on `@timestamp` and `event.category` first.
- Use `keyword` fields for exact match/aggregation.
- Avoid leading wildcards on `text`.
- Prefer `filter` context.
- Limit aggregation `size`.
- Check shard count and ILM.

---

## 6. Discover and investigation

- **Discover** — search, filter, field stats, saved searches.
- **Field statistics** — top values, cardinality.
- **Document view** — raw `_source` for proof.
- **Surrounding documents** — context ±N events.
- **Timeline** — investigation canvas across data sources.

### 6.1 Timeline

- Add events from Discover/alerts.
- Pivot by entity (user/host/IP).
- Add notes, pin events.
- Create cases from timeline.
- Use for building the incident story.

---

## 7. Detection rules

### 7.1 Rule types

| Type | Use |
|---|---|
| **Custom query** | KQL/DSL/Lucene/EQL match. |
| **Threshold** | N events by field in window. |
| **EQL** | Sequences by entity. |
| **Indicator match** | TI index matching (IP/domain/hash). |
| **New terms** | First-seen value for a field. |
| **Event correlation** | Multi-rule, multi-stage. |
| **Machine learning** | Anomaly detection jobs. |
| **Prebuilt (Elastic)** | Hundreds of ECS-based rules. |

### 7.2 Rule anatomy

| Setting | Meaning |
|---|---|
| **Index patterns** | Data scope. |
| **Query** | Logic. |
| **Required fields** | Mapping dependency. |
| **Schedule** | Run interval. |
| **Look-back** | Time window. |
| **Severity/risk score** | Prioritisation. |
| **Tags/threat** | ATT&CK. |
| **Actions** | Notify, webhook, case, response. |
| **Exceptions** | Scoped suppression. |
| **Max alerts per run** | Prevents storms. |

### 7.3 New terms example

- Field: `process.name`
- By: `host.name`
- Window: 7 days
- → Alerts when a host runs a process it has never run in 7 days.

**Powerful for first-seen hunting**; noisy without tuning.

### 7.4 Indicator match

- Requires a TI index with ECS threat fields.
- Joins on IP/domain/hash/URL.
- Tune for shared infrastructure FPs.

### 7.5 Prebuilt rules

- Enable by domain (Windows, Linux, cloud, AWS, Okta...).
- **Require the matching integration** and ECS fields.
- Review severity and FPs; don't enable all blindly.
- Update rules regularly; test after updates.

---

## 8. Exceptions and suppressions

### 8.1 Exception types

| Type | Scope |
|---|---|
| **Rule exception** | Specific rule. |
| **Shared exception list** | Multiple rules. |
| **Endpoint exception** | Endpoint protection. |

### 8.2 Best practice

- Narrow (field + value), not broad (`host.name: *`).
- Document owner/reason/expiry.
- Review quarterly.
- Log which exceptions fire.

**Broad exceptions are the Elastic equivalent of disabling the rule.**

---

## 9. Alerts and cases

### 9.1 Alerts

- Generated per rule run/threshold.
- Fields: rule, severity, risk score, entities, event.
- Status: open → acknowledged → closed.
- Bulk actions, tags, assignment.
- Alert details show the source event and rule logic.

### 9.2 Cases

- Group related alerts.
- Add comments, evidence, tasks.
- Assign owners, set severity, sync to external systems (ServiceNow/Jira).
- Attach Timeline.

### 9.3 Triage workflow

1. Open alert; read rule + severity + entities.
2. Inspect source event(s).
3. Pivot in Timeline (user/host/IP).
4. Check related alerts.
5. Classify: TP/FP/benign.
6. Respond/contain.
7. Document in case.
8. Add exception or tune rule if needed.

---

## 10. Endpoint capabilities

Elastic Defend (endpoint protection):

- Malware prevention (signature/ML/behaviour).
- Ransomware protection.
- Memory protection.
- Host isolation.
- Response actions: isolate, kill process, suspend process, get file, execute shell (`osquery`/response).
- Event capture (process, network, file, registry).
- **Osquery** integration for live queries.

**Response requires proper privileges and approval process.**

---

## 11. Dashboards and reporting

| Dashboard | Content |
|---|---|
| **Security overview** | Alerts by severity, rule, trend. |
| **Detection engine** | Rule health, execution, gaps. |
| **Endpoint** | Malware events, isolation status. |
| **Network** | Top talkers, DNS, flows. |
| **Cloud** | Audit events, IAM changes. |
| **Data quality** | Missing fields, pipeline errors. |

Build per-audience views; avoid 40-panel dashboards.

---

## 12. Operations and hardening

### 12.1 Health

```bash
GET _cluster/health
GET _cat/indices?v&s=store.size:desc
GET _cat/shards?v
GET _cat/nodes?v
GET _ilm/policy
```

- **Cluster status:** green/yellow/red.
- **Disk watermarks:** low/high/flood.
- **JVM heap:** <75%.
- **Shard count** vs recommended.
- **Ingest lag** and pipeline failures.
- **Rule execution** gaps (detection engine health).

### 12.2 Security hardening

| Control | Practice |
|---|---|
| **TLS** | Everywhere (transport + HTTP). |
| **Auth** | Native realm/SAML/OIDC; no anonymous. |
| **RBAC** | Roles per function; least privilege. |
| **API keys** | Scoped, rotated. |
| **Network** | Restrict 9200/5601; no public exposure. |
| **Audit logging** | Enable for compliance. |
| **Snapshots** | Regular, tested restores. |
| **Updates** | Patch Elasticsearch/Kibana. |
| **Secrets** | Vault/secret manager; not in configs. |

### 12.3 RBAC roles (typical)

| Role | Access |
|---|---|
| SOC L1 | Read alerts, cases, Discover. |
| SOC L2 | + response actions, exceptions. |
| Detection engineer | + rule authoring. |
| Admin | Cluster settings. |

---

## 13. Endpoint/agent management

- **Fleet** manages agents and policies centrally.
- **Agent policy** = integrations + settings.
- **Agent status**: healthy/unhealthy/offline/updating.
- **Version spread** should be small.
- **Tamper protection** for endpoint agent.

```bash
GET _cat/indices/logs-*?v
GET logs-*/_search { "query": { "term": { "host.name": "ws01" } }, "size": 1 }
```

---

## 14. Best practices

1. Normalise to ECS before writing detections.
2. Use data streams + ILM; size shards properly.
3. Test ingest pipelines with `_simulate`.
4. Prefer `filter` context and `keyword` fields.
5. Enable prebuilt rules **by integration**, not wholesale.
6. Map ATT&CK and set risk scores deliberately.
7. Use exceptions narrowly with expiry.
8. Keep Timeline usage habitual for investigations.
9. Monitor detection engine health for **rule gaps**.
10. Snapshot and test restores.
11. Harden cluster (TLS, RBAC, no public 9200).
12. Keep agent versions current.
13. Review noisy rules weekly.
14. Document rule intent, FPs, response.
15. Use cases for handover and metrics.

---

## 15. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Mapping `ip` as `text` | Broken range/CIDR queries. |
| Giant indices/shards | Slow searches, instability. |
| No ILM | Disk full, cluster red. |
| Anonymous access | Breach. |
| Enabling all prebuilt rules | Alert flood. |
| Broad exceptions | Blind spots. |
| `match` on keyword / `term` on text | Zero results. |
| Ignoring rule execution gaps | Silent detection loss. |
| Leading wildcards | Performance cliff. |
| No snapshots | Data loss. |
| Missing ECS fields | Integrations/rules fail. |
| No case documentation | No learning/tuning data. |

---

## 16. Labs

1. Install Elastic + Kibana; add a Windows integration.
2. Verify ECS fields in Discover.
3. Build an ingest pipeline with grok + date; simulate.
4. Write a KQL, a DSL, an ES|QL, and an EQL query for one question.
5. Create a custom query rule with ATT&CK mapping.
6. Create a threshold and a new-terms rule.
7. Add a narrow exception; verify alert suppression.
8. Build a Timeline investigation with 5 pivots.
9. Create a case and document the verdict.
10. Check detection engine health and find a rule gap.

---

## 17. Self-test questions

1. Difference between index, data stream, and alias?
2. Why does mapping matter for `source.ip`?
3. What is ECS, and why does it matter?
4. What is an ingest pipeline?
5. KQL vs DSL vs ES|QL vs EQL — when each?
6. Why use `filter` context?
7. What does a new-terms rule detect?
8. How does indicator matching work?
9. What makes an exception dangerous?
10. What is a case vs an alert?
11. How do you check detection engine health?
12. What are disk watermarks?
13. How do you harden an Elastic cluster?
14. Why test `_simulate` before pipeline deploy?
15. How do you avoid prebuilt-rule floods?

---

## 18. One-page revision checklist

- [ ] Stack: Elasticsearch, Kibana, Agent/Fleet, Beats, Logstash, integrations; Cloud/self-managed/Serverless.
- [ ] Data model: index, data stream, template, ILM hot/warm/cold/frozen/delete, alias; mapping types (text/keyword/ip/date/nested); shard sizing 10–50 GB.
- [ ] ECS field groups: event, host, user, source/destination, process, file, network, url/domain, cloud.
- [ ] Pipelines: grok/dissect, JSON, date, rename/copy/remove, script, enrich, geoip; `_simulate`.
- [ ] Query languages: KQL, DSL (filter context, term vs match), ES|QL, EQL sequences; performance rules.
- [ ] Discover/Timeline investigation.
- [ ] Rules: custom, threshold, EQL, indicator match, new terms, event correlation, ML, prebuilt; rule anatomy; exceptions (rule/shared/endpoint) narrow + expiry.
- [ ] Alerts/cases: lifecycle, triage workflow, documentation.
- [ ] Endpoint: prevention, ransomware/memory protection, isolation, kill/suspend/get file/shell, osquery.
- [ ] Dashboards: security overview, detection engine health, endpoint, network, cloud, data quality.
- [ ] Operations: cluster health, `_cat` endpoints, watermarks, heap, shards, ingest lag, rule gaps.
- [ ] Hardening: TLS, auth, RBAC roles, API keys, network restriction, audit, snapshots, patches, secrets.
- [ ] Fleet/agent policies, status, version spread, tamper protection.
- [ ] Best practices and pitfalls memorised.
