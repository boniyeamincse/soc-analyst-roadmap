# Microsoft Sentinel — SOC Analyst Study Notes

> Goal: operate Sentinel day-to-day — connect data, write analytics rules, triage incidents, and automate response.
> KQL patterns → `Queries.md`; rule engineering → `Detection-Rules.md`; collection concepts → `Log-Collection.md`.

---

## 0. How to use this note

1. §1–§3: what Sentinel is; architecture; data ingestion/pricing.
2. §4–§6: KQL in Sentinel; connectors; tables.
3. §7–§10: analytics rules; incidents; automation; workbooks/hunting.
4. §11–§13: ASIM, UEBA, content hub; operations.
5. §14–§16: best practices, pitfalls, labs.
6. §17–§18: self-test, revision.

---

## 1. What Sentinel is

- **Cloud-native SIEM + SOAR** built on Azure Monitor **Log Analytics**.
- Data lives in a **workspace**; query language is **KQL**.
- Integrates deeply with **Microsoft Defender XDR**, Entra ID, Azure, M365.
- Billing is **pay-per-GB ingested + retention**, with commitment tiers.

**SOC uses:**
- Correlate multi-cloud/on-prem identity, endpoint, network, SaaS.
- Analytics rules → **incidents** (grouped alerts).
- Automation rules + playbooks (Logic Apps).
- Hunting queries, notebooks, workbooks.
- Entity pages + UEBA insights.

---

## 2. Architecture

```
Data sources
 ├── Microsoft first-party connectors (Defender, Entra, M365, Azure Activity)
 ├── Agent-based (AMA + DCR)
 ├── API-based (Codeless Connector Framework / REST)
 ├── Syslog/CEF via AMA
 └── Custom logs (DCR / Logs Ingestion API)
        │
        ▼
Log Analytics workspace
 ├── Tables (SecurityEvent, SigninLogs, DeviceProcessEvents, ...)
 ├── Analytics rules (scheduled, NRT, fusion, ML)
 ├── Watchlists
 ├── ASIM parsers
 └── Retention + tiers
        │
        ▼
Incidents → Automation rules → Playbooks (Logic Apps)
        │
        ▼
Workbooks / Hunting / Notebooks / UEBA
```

### 2.1 Key objects

| Object | Purpose |
|---|---|
| **Workspace** | Container for data, rules, retention. |
| **Data connector** | Source → workspace pipeline. |
| **DCR (Data Collection Rule)** | Defines collection + destination + transform. |
| **Table** | Structured storage (`_CL` custom tables). |
| **Analytics rule** | Detection logic → alert → incident. |
| **Incident** | Grouped alert(s) with entities, severity, status. |
| **Automation rule** | Trigger-based automation (no code). |
| **Playbook** | Logic App workflow for response. |
| **Watchlist** | Reference data (assets, VIPs, TI). |
| **ASIM parser** | Normalisation to a common schema. |
| **Workbook** | Dashboard/report. |
| **Hunting query** | Saved ad-hoc search. |
| **Content hub** | Solution packages (connectors + rules + workbooks). |

### 2.2 Workspace design

- One workspace per environment/tenant/region (avoid sprawl).
- Consider data residency and RBAC boundaries.
- Separate dev/test workspace for rule development.
- Retention set per table (analytics vs basic logs).

---

## 3. Ingestion and pricing

### 3.1 Table plans

| Plan | Use | Query |
|---|---|---|
| **Analytics** | Full SIEM features, alerts, workbooks. | Full KQL. |
| **Basic** | High-volume verbose logs, search/incident only. | Limited KQL, cheaper. |
| **Auxiliary** | Very high volume, low-touch. | Limited. |
| **Data lake** | Long-term cheap retention. | Separate query. |

**Choosing the wrong plan** is the most common cost problem.

### 3.2 Pricing levers

- Ingestion per GB (pay-as-you-go or **commitment tier**).
- Retention (free 90 days analytics, then per-GB).
- Basic/Auxiliary cheaper ingestion, limited features.
- Data lake for long-term.
- Free data sources (e.g., some Defender/Office 365 signals).

### 3.3 Cost control

| Control | Effect |
|---|---|
| Filter at source/DCR | Less ingested. |
| Table plan selection | Cheaper tier for verbose logs. |
| Transform in DCR (`KQL transform`) | Drop fields/rows pre-ingest. |
| Exclude noisy categories | Less volume. |
| Commitment tier | Discount at steady volume. |
| Retention tuning | Avoid long analytics retention. |
| Summary rules | Pre-aggregate. |

**Never cut security-critical logs to hit budget** — route them to cheaper tiers instead.

---

## 4. KQL in Sentinel

### 4.1 Basics

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize Failures = count() by TargetUserName, IpAddress
| order by Failures desc
| take 20
```

### 4.2 Sentinel-specific

| Feature | Example |
|---|---|
| **Watchlist** | `_GetWatchlist('vips')` |
| **Workspace functions** | `_GetWatchlist`, saved functions |
| **Cross-workspace** | `workspace("prod").SecurityEvent` |
| **External data** | `externaldata(...)` |
| **Time** | `ago()`, `bin()`, `between()` |
| **Dynamic** | `pack()`, `bag_unpack()` |
| **JSON** | `parse_json()`, `todynamic()` |
| **Geo** | `geo_info_from_ip_address()` |

```kusto
let vips = _GetWatchlist('vips') | project UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1h)
| where UserPrincipalName in (vips)
| where ResultType != 0
```

### 4.3 Common tables

| Table | Content |
|---|---|
| `SecurityEvent` | Windows events (via AMA). |
| `SigninLogs` | Entra interactive sign-ins. |
| `AADNonInteractiveUserSignInLogs` | Token/background sign-ins. |
| `AuditLogs` | Entra audit. |
| `AzureActivity` | Azure control plane. |
| `DeviceProcessEvents` | Defender for Endpoint process. |
| `DeviceNetworkEvents` | Network connections. |
| `DeviceFileEvents` | File operations. |
| `DeviceRegistryEvents` | Registry. |
| `DeviceLogonEvents` | Logons. |
| `EmailEvents` | M365 email. |
| `CloudAppEvents` | Defender for Cloud Apps. |
| `AWSCloudTrail` | AWS audit. |
| `CommonSecurityLog` | CEF/Syslog appliances. |
| `Syslog` | Linux syslog. |
| `Heartbeat` | Agent health. |
| `Usage` | Ingestion volume. |

### 4.4 Performance

- Filter on `TimeGenerated` first.
- Use `where` before `join`/`summarize`.
- Prefer `has` over `contains` (indexed).
- Avoid `search *`.
- Use `materialize()` for reused subqueries.
- Limit `take` at the end.
- Use `summarize` early.
- Check `Usage` for volume surprises.

---

## 5. Connectors

### 5.1 Types

| Type | Examples |
|---|---|
| **First-party/API** | Defender XDR, Entra, Azure, M365, AWS, GCP. |
| **Agent (AMA)** | Windows/Linux with DCR. |
| **CEF/Syslog** | Firewalls, proxies, appliances via AMA. |
| **Codeless (CCF)** | Vendor SaaS via API. |
| **Custom logs** | Logs Ingestion API / DCR. |
| **Solutions (content hub)** | Bundled connectors + rules + workbooks. |

### 5.2 Coverage priorities

1. Entra sign-in + audit.
2. Defender XDR (endpoint, email, identity, cloud apps).
3. Azure Activity + AWS/GCP audit.
4. Windows Security/Sysmon.
5. Firewall/proxy/DNS.
6. Critical SaaS.

### 5.3 Verify connectors actually deliver

```kusto
Usage
| where TimeGenerated > ago(1d)
| summarize Events=sum(Quantity) by DataType
| order by Events desc
```

```kusto
Heartbeat
| summarize Last=max(TimeGenerated) by Computer
| where Last < ago(2h)
```

**A "connected" connector with zero events is a gap, not coverage.**

---

## 6. Data transformation (DCR)

- Transform **before** storage to reduce cost.
- Drop fields, filter rows, project needed columns.
- Cannot enrich with lookups (limited), but can normalise.

```kusto
source
| where EventID in (4624, 4625, 4688)
| project TimeGenerated, Computer, EventID, Account, IpAddress, CommandLine
```

---

## 7. Analytics rules

### 7.1 Rule types

| Type | Latency | Use |
|---|---|---|
| **Scheduled** | 5 min–14 days. | Most detections. |
| **NRT (near-real-time)** | ~1 min. | High-value, must-be-fast. |
| **Fusion** | ML-based, multi-stage. | Correlate Defender signals. |
| **Microsoft security** | Built-in from Defender. | Turn on, tune. |
| **ML behaviour analytics** | Built-in. | Anomalies. |
| **Anomaly** | Built-in. | Baseline deviations. |
| **Threat intelligence** | TI matches. | IOC matching. |

### 7.2 Scheduled rule anatomy

| Setting | Meaning |
|---|---|
| **Name/description** | Human-readable + rationale. |
| **Tactics/techniques** | ATT&CK mapping. |
| **Severity** | Incident severity. |
| **Status** | Enabled/disabled/test. |
| **Query** | KQL. |
| **Run every** | Frequency (e.g., 5m). |
| **Lookup data from** | Time window (e.g., last 1h). |
| **Alert threshold** | Number of results to trigger. |
| **Event grouping** | Group all / by entity. |
| **Suppression** | Stop re-alerting after trigger. |
| **Entity mapping** | Account, IP, Host, URL, Hash, Process. |
| **Custom details** | Show fields in incident. |
| **Alert details** | Name/description/severity overrides. |
| **Incident settings** | Create incident, grouping, TTL. |
| **Automation** | Attach playbook. |

### 7.3 Example rule

```kusto
let timeframe = 1h;
let threshold = 20;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4625
| summarize Failures = count(), DistinctUsers = dcount(TargetUserName)
    by IpAddress, bin(TimeGenerated, 1h)
| where Failures >= threshold
| extend AccountCustomEntity = tostring(DistinctUsers)
```

Entity mapping: IP → `IpAddress`.

### 7.4 Entity mapping matters

- Enables **entity pages**, **investigation graph**, **automation**, **grouping**.
- Map: Account (UPN/SID), Host, IP, URL, FileHash, Process, CloudApplication, Mailbox.
- Missing mapping = weaker incidents.

### 7.5 Rule quality checklist

- [ ] Query returns only intended events.
- [ ] Time window matches frequency (avoid gaps/overlap).
- [ ] Threshold justified by baseline.
- [ ] Entities mapped.
- [ ] Custom details useful.
- [ ] Severity justified.
- [ ] ATT&CK mapped.
- [ ] Tested in alert-only mode.
- [ ] Playbook attached (if actionable).
- [ ] Description includes FPs and response.

---

## 8. Incidents

### 8.1 Lifecycle

```
New → Active → Closed (True positive / False positive / Benign)
```

### 8.2 Incident structure

- **Alerts** (grouped by rule/entity/time).
- **Entities** (accounts, hosts, IPs, files, URLs).
- **Evidence** (events, related alerts).
- **Tactics/techniques**.
- **Severity/status/owner**.
- **Comments/tasks**.
- **Automation** (playbooks run).
- **Investigation graph** (if Defender).

### 8.3 Grouping

| Mode | Behaviour |
|---|---|
| **Group all** | One incident per rule run. |
| **Group by entities** | One incident per entity set. |
| **Custom grouping** | Rule-defined. |

**Over-grouping** hides distinct events; **under-grouping** creates duplicates.

### 8.4 Triage workflow

1. Read title/severity/description.
2. Review entities and evidence.
3. Pivot to logs (KQL).
4. Check related incidents/entities.
5. Determine TP/FP/benign.
6. Contain/escalate.
7. Document in comments.
8. Close with correct classification + reason.

**Classification data drives tuning** — use it.

---

## 9. Automation

### 9.1 Automation rules

- Trigger: incident created/updated.
- Conditions: severity, title, entity, tags.
- Actions: assign, change severity/status, add tags/tasks, run playbook.

### 9.2 Playbooks (Logic Apps)

| Use case | Actions |
|---|---|
| **Enrich** | VirusTotal, geo, WHOIS, TI. |
| **Notify** | Teams/email/Slack. |
| **Contain** | Disable user, revoke sessions, isolate device (Defender). |
| **Block** | Firewall/proxy/EDR IOC block. |
| **Ticket** | ServiceNow/Jira. |
| **Purge** | Remove phishing emails. |
| **Collect** | Pull logs/artifacts. |

### 9.3 Design discipline

- Least privilege (managed identity).
- Idempotent actions.
- Human approval for destructive steps.
- Log every action.
- Timeouts/retries.
- Test with benign incidents.
- Document runbooks.

**Automation without approval gates is how you delete production.**

---

## 10. Workbooks, hunting, notebooks

### 10.1 Workbooks

- Dashboards over KQL.
- SOC overview: incidents by severity, MTTD/MTTR, ingestion health, top rules.
- Identity: sign-in failures, MFA, risky users.
- Endpoint: detections, top processes.
- Network: egress, top destinations.

### 10.2 Hunting

- Saved queries → run/bookmark → promote to analytics rule.
- Use `search` across tables for unknown entities.
- Bookmark events, add to incident.

```kusto
search "suspicious-domain.example"
| where TimeGenerated > ago(7d)
```

### 10.3 Notebooks (Jupyter)

- Python + KQL (`azure-sentinel`/`msticpy`).
- Advanced analysis, visualisation, entity enrichment.
- Good for threat hunting campaigns and reporting.

---

## 11. ASIM

### 11.1 What

**Advanced Security Information Model** — normalisation layer across sources.

| Schema | Covers |
|---|---|
| **Authentication** | Sign-ins, logons. |
| **NetworkSession** | Firewall, flow, proxy. |
| **WebSession** | HTTP/proxy. |
| **Dns** | DNS. |
| **ProcessEvent** | Process creation. |
| **FileEvent** | File activity. |
| **RegistryEvent** | Registry. |
| **AuditEvent** | Administrative changes. |
| **AlertEvent** | Security alerts. |

### 11.2 Use

```kusto
_Im_Authentication
| where EventResult == "Failure"
| summarize count() by SrcIpAddr, TargetUsername
```

(via the `imAuthentication` unifying parser.)

**Benefit:** one rule works across many vendors.

---

## 12. UEBA and content hub

### 12.1 UEBA

- Behavioural baselines per user/host.
- Risk scores, peer comparisons.
- Anomalies: unusual access, volume, location, time.
- Feeds incidents and entity pages.

**Use as context, not sole evidence.**

### 12.2 Content hub

- Solutions: connectors + analytics + workbooks + playbooks.
- Examples: AWS, Okta, Cisco, Palo Alto, M365, Threat Intelligence.
- Install, then **tune** — defaults rarely fit.

---

## 13. Operations

### 13.1 Health

| Check | Query/source |
|---|---|
| Ingestion volume | `Usage` |
| Agent health | `Heartbeat` |
| Connector status | Data connectors blade |
| Rule failures | Analytics rule health |
| Automation failures | Logic App run history |
| Incident backlog | Incident queue |

### 13.2 RBAC

- Workspace roles: Reader, Microsoft Sentinel Reader/Responder/Contributor.
- Resource-group/Azure RBAC.
- Least privilege; separate triage vs content authoring.
- Use managed identities for playbooks.

### 13.3 Retention

- Analytics tier: 90 days free, extendable.
- Basic/Auxiliary: cheaper, longer.
- Data lake: long-term.
- Set per table; verify.

---

## 14. Best practices

1. One workspace per clear boundary (env/tenant/region).
2. Onboard identity + endpoint + cloud first.
3. Verify every connector with a real query.
4. Map entities on every rule.
5. Use table plans to control cost.
6. Transform in DCR.
7. Test rules in alert-only before production.
8. Tune noisy built-in and Fusion rules.
9. Automate enrichment; require approval for destructive actions.
10. Document rules with FPs and response.
11. Review incidents weekly for tuning signal.
12. Use ASIM for vendor-agnostic detections.
13. Keep dev/test workspace for content changes.
14. Monitor ingestion cost weekly.
15. Retire stale rules.

---

## 15. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Analytics plan for verbose logs | Cost explosion. |
| Trusting "connected" status | Silent gaps. |
| No entity mapping | Weak incidents. |
| Over-grouping incidents | Hidden events. |
| Testing rules in production | Fatigue. |
| Untuned built-in rules | Noise. |
| `search *` on huge time ranges | Slow/timeout. |
| Automation without approval | Outage. |
| Ignoring `Usage` | Budget surprise. |
| No dev workspace | Broken content deploys. |
| Missing time-window alignment | Gaps/duplicates. |
| Not closing incidents with classification | No tuning data. |

---

## 16. Labs

1. Connect Entra sign-in logs; verify with `SigninLogs`.
2. Build a scheduled rule for password spray with entity mapping.
3. Configure incident grouping by account.
4. Create a watchlist of VIPs; use it in a rule.
5. Write an automation rule to tag and assign by severity.
6. Build a playbook to enrich an IP (approval-gated response).
7. Create a workbook showing incidents by severity and rule.
8. Convert a rule to use an ASIM parser.
9. Run a hunting query and bookmark an event.
10. Compute ingestion cost from `Usage` and propose a plan change.

---

## 17. Self-test questions

1. What is Sentinel built on?
2. What is a workspace vs a table vs a rule?
3. Analytics vs Basic vs Auxiliary table plans?
4. What does a DCR do?
5. Name three Sentinel-specific KQL features.
6. What are the analytics rule types?
7. Why does entity mapping matter?
8. What is incident grouping and its trade-off?
9. Difference between automation rule and playbook?
10. What is ASIM?
11. What is UEBA good for, and its limit?
12. How do you verify a connector is working?
13. How do you control ingestion cost?
14. What should you check before enabling a built-in rule?
15. What classification data drives tuning?

---

## 18. One-page revision checklist

- [ ] Cloud-native SIEM+SOAR on Log Analytics; KQL; Defender XDR integration; GB pricing.
- [ ] Architecture: connectors/AMA/CCF/custom → workspace tables → analytics → incidents → automation/playbooks → workbooks/hunting/notebooks/UEBA.
- [ ] Objects: workspace, connector, DCR, table, analytics rule, incident, automation rule, playbook, watchlist, ASIM, workbook, hunting query, content hub.
- [ ] Workspace design: boundaries, dev/test, retention per table.
- [ ] Plans: Analytics vs Basic vs Auxiliary vs data lake; pricing levers; cost controls (DCR transform, plans, commitment, retention, summary).
- [ ] KQL: where/summarize/bin/join; `_GetWatchlist`, `ago`, `pack`, `parse_json`, `geo_info_from_ip_address`; common tables; performance (TimeGenerated, `has`, materialize, no `search *`).
- [ ] Connectors: first-party, AMA, CEF/syslog, CCF, custom, solutions; priority order; verify with Usage/Heartbeat.
- [ ] DCR transforms.
- [ ] Analytics: scheduled, NRT, Fusion, MS security, ML, anomaly, TI; rule anatomy (frequency vs lookback, threshold, grouping, suppression, entity mapping, custom details, incident settings); quality checklist.
- [ ] Incidents: lifecycle, structure, grouping modes, triage workflow, classification.
- [ ] Automation: automation rules vs playbooks; enrichment/notify/contain/block/ticket/purge; least privilege, approval, idempotency, logging.
- [ ] Workbooks, hunting (bookmark/promote), notebooks (msticpy).
- [ ] ASIM schemas and unifying parser.
- [ ] UEBA as context; content hub defaults need tuning.
- [ ] Operations: health checks, RBAC, retention.
- [ ] Pitfalls list memorised.
