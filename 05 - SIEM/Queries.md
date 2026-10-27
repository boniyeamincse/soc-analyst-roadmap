# Queries — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Microsoft Sentinel](Microsoft-Sentinel.md) · [Splunk →](Splunk.md)

> Goal: turn a question ("did this user get compromised?") into a correct, efficient query in whichever language the platform speaks.
> Splunk SPL depth → [Splunk.md](Splunk.md); Sentinel specifics → [Microsoft-Sentinel.md](Microsoft-Sentinel.md); Elastic → [Elastic-Security.md](Elastic-Security.md).

---

## 0. How to use this note

1. §1–§3: query thinking; the language family; data-model awareness.
2. §4–§7: core operations, joins/aggregation, sequences, time.
3. §8–§11: baselines, pivoting, optimisation, validation.
4. §12–§14: pattern library, debugging, documentation.
5. §15–§18: pitfalls, labs, self-test, revision.

---

## 1. Query thinking

Every query answers one of five question types:

| Type | Question | Shape |
|---|---|---|
| **Lookup** | "What happened to X?" | Filter by entity + time. |
| **Aggregate** | "How often / how many?" | Group by + count. |
| **Compare** | "Is this normal?" | Baseline vs current. |
| **Sequence** | "Did A then B happen?" | Ordered join / sequence. |
| **Absence** | "What's missing?" | Expected minus observed. |

**Write down the question first.** Most bad queries are bad questions.

### 1.1 Anatomy of a query

```
SCOPE (time, index/table, source)
→ FILTER (entities, conditions)
→ SHAPE (project/normalise fields)
→ AGGREGATE / SEQUENCE
→ RANK / THRESHOLD
→ PRESENT
```

---

## 2. The language family

| Language | Platform | Character |
|---|---|---|
| **SPL** | Splunk | Pipes, streaming commands. |
| **KQL** | Sentinel, Defender, Azure Data Explorer | Pipe, table-first, rich operators. |
| **Lucene** | Elasticsearch (query string) | Query DSL / boolean. |
| **ES\|QL** | Elasticsearch | Pipe-based, SQL-like. |
| **EQL** | Elastic, some EDRs | Event sequences. |
| **SQL** | BigQuery, Athena, ClickHouse, Snowflake | Declarative joins. |
| **YARA-L** | Google SecOps (Chronicle) | Detection rules. |
| **Sigma** | Portable rule format | Translates to many. |

**Transferable skills:** filtering, joining, grouping, windowing, sequencing. Syntax differs; thinking does not.

---

## 3. Know your data model

Before writing, answer:

1. Which table/index/sourcetype has this event?
2. What are the field names there?
3. What is the timestamp field?
4. Is it parsed/normalised?
5. What is the retention?
6. What is the cardinality/volume?

### 3.1 Field discovery

```spl
| metadata type=sourcetypes index=*
| fieldsummary maxvals=20
```

```kusto
Usage
| where TimeGenerated > ago(1d)
| summarize count() by DataType
```

```bash
curl -s 'localhost:9200/_cat/indices?v'
curl -s 'localhost:9200/logs-*/_mapping' | jq '.'
```

**Never guess field names.** Wrong field = silent zero results.

---

## 4. Core operations across languages

### 4.1 Filter

```spl
index=windows EventCode=4625 src_ip=10.0.0.5
| where count > 10
```

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625 and IpAddress == "10.0.0.5"
```

```sql
SELECT * FROM windows_events
WHERE event_code = 4625 AND src_ip = '10.0.0.5'
  AND ts > now() - INTERVAL '24 hours';
```

```json
{"query":{"bool":{"filter":[
  {"term":{"event.code":4625}},
  {"range":{"@timestamp":{"gte":"now-24h"}}}
]}}}
```

### 4.2 Project

```spl
| table _time, user, src_ip, EventCode
| fields - _raw
```

```kusto
| project TimeGenerated, Account, IpAddress, EventID
```

```sql
SELECT ts, username, src_ip, event_code FROM ...
```

### 4.3 Compute

```spl
| eval severity = if(count>100,"high","low")
```

```kusto
| extend severity = iff(count_ > 100, "high", "low")
```

```sql
SELECT CASE WHEN cnt > 100 THEN 'high' ELSE 'low' END AS severity
```

### 4.4 Aggregate

```spl
| stats count AS n dc(src) AS hosts BY user
```

```kusto
| summarize n = count(), hosts = dcount(SrcIp) by Account
```

```sql
SELECT username, COUNT(*) n, COUNT(DISTINCT src_ip) hosts
FROM ... GROUP BY username
```

### 4.5 Sort/limit

```spl
| sort -n | head 20
```

```kusto
| order by n desc | take 20
```

```sql
ORDER BY n DESC LIMIT 20
```

---

## 5. Joins and correlation

### 5.1 Join types

| Type | Meaning |
|---|---|
| **Inner** | Only matches. |
| **Left** | All from left + matches. |
| **Anti** | Left without match. |
| **Union** | Stack rows. |

### 5.2 Examples

```spl
### Splunk: enrich with asset criticality
index=auth
| lookup assets ip AS src_ip OUTPUT hostname, criticality
| where criticality="tier1"
```

```spl
### Splunk: users with failure and success
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) AS fails,
        count(eval(EventCode=4624)) AS succ BY user
| where fails > 5 AND succ > 0
```

```kusto
### KQL: enrich with watchlist
SecurityEvent
| join kind=leftouter Watchlist on $left.Account == $right.UserPrincipalName
| where isnotempty(WatchlistName)
```

```kusto
### KQL: anti-join — hosts without EDR
DeviceInfo
| summarize by DeviceName
| join kind=leftanti (Heartbeat | summarize by Computer) on $left.DeviceName == $right.Computer
```

**Joins are expensive.** Prefer pre-aggregation, lookups, or `stats`-based correlation.

---

## 6. Sequences and windows

### 6.1 Why

Attacks are ordered: delivery → execution → persistence → C2.

### 6.2 Splunk (stats-based, preferred)

```spl
index=windows (EventCode=4624 OR EventCode=4688)
| eval evt=if(EventCode=4624,"logon","process")
| stats min(eval(if(evt="logon",_time,null))) AS logon,
        min(eval(if(evt="process",_time,null))) AS proc BY user, host
| where proc > logon AND proc - logon < 600
```

### 6.3 KQL (`join` on time window or `make-series`)

```kusto
let logons = SecurityEvent | where EventID == 4624 | project LogonTime=TimeGenerated, Account, Computer;
let procs  = DeviceProcessEvents | project ProcTime=TimeGenerated, AccountName, DeviceName, FileName;
logons
| join kind=inner (procs) on $left.Account == $right.AccountName
| where ProcTime between (LogonTime .. LogonTime + 10m)
```

### 6.4 EQL

```eql
sequence by user.name with maxspan=10m
  [ authentication where event.outcome == "failure" ]
  [ authentication where event.outcome == "success" ]
```

### 6.5 Windows/streaming

```spl
... | streamstats window=10 count AS failures BY user
... | where failures >= 5
```

```kusto
... | summarize count() by bin(TimeGenerated, 5m), Account
```

---

## 7. Time handling

| Concept | Rule |
|---|---|
| **Always bound** | Explicit earliest/latest or `ago()`. |
| **Timezone** | Normalise UTC; convert only for display. |
| **Bucketing** | `bin`/`span` aligned to question. |
| **Windows** | Sliding vs tumbling; pick one consistently. |
| **Off-hours** | Derive from local time. |
| **Dwell time** | Search wide enough (30+ days). |

```spl
| bin _time span=1h
| eval hour=strftime(_time,"%H")
| eval weekend=if(strftime(_time,"%u")>=6,"yes","no")
```

```kusto
| summarize count() by bin(TimeGenerated, 1h), hourofday(TimeGenerated)
```

---

## 8. Baselines

### 8.1 What to baseline

- Per-user: logon hours, hosts, geo, apps.
- Per-host: processes, destinations, bytes, DNS.
- Per-role: peer group expectations.
- Per-service-account: behaviour is usually fixed.

### 8.2 Methods

| Method | Use |
|---|---|
| **First-seen** | New process/domain/host. |
| **Rare value** | <N occurrences in 30d. |
| **Z-score** | Numeric deviation. |
| **Peer comparison** | Same role/department. |
| **Time-of-day** | Off-hours activity. |
| **Volume ratio** | Bytes out/in. |

```kusto
let baseline = DeviceProcessEvents
  | where TimeGenerated between (ago(30d) .. ago(1d))
  | summarize seen = count() by FileName, DeviceId;
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| join kind=leftanti baseline on FileName, DeviceId
```

```spl
index=endpoint earliest=-30d latest=-1d
| stats count BY process_name
| where count < 3
```

**Baselines must be refreshed** and must exclude the incident window.

---

## 9. Pivoting

Good analysts pivot; bad ones stop at the first hit.

| Pivot from | To |
|---|---|
| IP | DNS, proxy, firewall, EDR network, auth |
| Domain | DNS history, proxy, sandbox, cert, WHOIS |
| User | Auth, email, VPN, cloud, endpoint |
| Host | Processes, network, autoruns, patches |
| Hash | Prevalence, other hosts, sandbox, TI |
| Process | Parent, children, command line, network |
| File | Creator, signer, other appearances |
| Time | What else happened ±15 min |

**Pivot until the story is complete or the scope is bounded.**

---

## 10. Query optimisation

### 10.1 Universal rules

1. Narrow scope first (time, index/table).
2. Filter early with indexed/normalised fields.
3. Project early (drop columns).
4. Aggregate before joining.
5. Avoid scanning raw when metadata/modelled data exists.
6. Avoid leading wildcards and regex on huge fields.
7. Limit high-cardinality `dc`/`values`.
8. Cache/summarise repeated queries.
9. Check for truncation/limits.
10. Measure before and after.

### 10.2 Platform notes

| Platform | Fast path |
|---|---|
| Splunk | `tstats` on accelerated data models. |
| Sentinel | Summary rules, `_GetWatchlist`, pre-aggregation, avoid `search *`. |
| Elastic | EQL/ES\|QL, keyword fields, avoid `wildcard` on text, use `filter` context. |
| SQL | Partition pruning, clustering keys, avoid `SELECT *`. |

### 10.3 Reading a slow query

- Is it scanning more data than needed?
- Is it joining large sets?
- Is it sorting unaggregated data?
- Is it regexing raw text?
- Is it recomputing the same subquery?

---

## 11. Validation

Before trusting a result:

1. **Positive control** — insert/replay a known event; does it appear?
2. **Negative control** — a known non-matching event; does it stay out?
3. **Count sanity** — does volume match expectations?
4. **Field null rate** — are joins silently failing?
5. **Time boundary** — check events at edges.
6. **Truncation** — verify result limits not hit.
7. **Manual spot-check** — inspect 5 raw events.
8. **Second implementation** — write it a different way.

**A query returning 0 is a claim.** Prove it.

---

## 12. Pattern library

### 12.1 Authentication

```kusto
// Password spray: many users, few passwords, one source
SecurityEvent
| where EventID == 4625
| summarize Users=dcount(TargetUserName), Attempts=count() by IpAddress, bin(TimeGenerated, 1h)
| where Users > 10 and Attempts > 20
```

```kusto
// Success after failures from same IP
SecurityEvent
| where EventID in (4624, 4625)
| summarize Fails=countif(EventID==4625), Succ=countif(EventID==4624) by IpAddress, TargetUserName
| where Fails >= 10 and Succ >= 1
```

```spl
index=okta eventType="user.session.start" OR eventType="user.authentication.auth_via_mfa"
| stats values(eventType) AS evts BY actor.alternateId
```

### 12.2 Endpoint

```kusto
// Office/browser spawning shell
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","chrome.exe","msedge.exe","firefox.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
```

```kusto
// Encoded PowerShell
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}"
```

```kusto
// LSASS access
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","csrss.exe","services.exe","wininit.exe")
```

### 12.3 Network

```spl
// Large outbound transfers to rare destinations
index=proxy earliest=-24h
| stats sum(bytes_out) AS out dc(src) AS srcs BY dest
| where out > 50000000
| sort -out
```

```kusto
// DNS with long labels (tunnelling heuristic)
DnsEvents
| extend label_len = strlen(Name)
| where label_len > 60
| summarize count() by Name, ClientIP
```

```spl
// Beaconing (low variance)
index=proxy
| bin _time span=1m
| stats count BY src, dest, _time
| stats stdev(count) AS sd avg(count) AS avg dc(_time) AS mins BY src, dest
| where mins > 30 AND sd < 1 AND avg < 5
```

### 12.4 Cloud

```kusto
// AWS: new IAM access key
AWSCloudTrail
| where EventName in ("CreateAccessKey","CreateUser","AttachUserPolicy","PutUserPolicy")
| project TimeGenerated, UserIdentityUserName, EventName, SourceIpAddress, RequestParameters
```

```kusto
// Azure: risky sign-in + MFA failure
SigninLogs
| where ResultType != 0
| summarize Fails=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where Fails > 5
```

```kusto
// M365: mass download / mailbox rule
CloudAppEvents
| where ActionType in ("New-InboxRule","Set-InboxRule","FileDownloaded")
| summarize count() by AccountDisplayName, ActionType, bin(TimeGenerated, 1h)
```

### 12.5 Persistence / change

```spl
index=windows EventCode=7045
| stats count BY ServiceName, ServiceFileName, host
```

```kusto
// New scheduled task
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, AdditionalFields
```

### 12.6 Absence

```kusto
// Hosts alive but no EDR events (agent gap)
Heartbeat
| summarize LastSeen=max(TimeGenerated) by Computer
| where LastSeen < ago(2h)
```

```spl
// Users who normally log in daily but did not
index=auth action=success earliest=-7d
| stats dc(date_mday) AS days BY user
| where days < 5
```

---

## 13. Debugging queries

| Symptom | Likely cause |
|---|---|
| Zero results | Wrong index/table, field name, time, case, quoting. |
| Too many results | Missing filter, wrong operator, OR scope. |
| Duplicates | Multiple sources, missing dedup, join fan-out. |
| Slow | Wide time, no index, leading wildcard, join, regex. |
| Truncated | Result limits. |
| Wrong aggregation | Wrong `by` field, nulls, case mismatch. |
| Field missing | Not parsed, wrong sourcetype, extraction disabled. |

**Debug method:** remove clauses until it returns data, then add back one at a time.

```spl
| stats count
```
If that is 0, the scope is wrong, not the logic.

---

## 14. Documenting queries

Every production query should record:

```
Name:
Question answered:
Platform/language:
Scope (index/table, time):
Logic summary:
Fields required:
Known false positives:
Owner:
ATT&CK:
Last validated:
Version/changelog:
```

**Store in git** where possible (`detection-as-code`). Reviewed queries are maintainable; tribal knowledge is not.

---

## 15. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Guessing field names | Silent zero results. |
| No time bound | Slow, expensive, wrong. |
| Case sensitivity mismatch | Missed events. |
| Joining on unsanitised keys | Fan-out, duplicates. |
| Using `OR` across indexes | Cross-contamination. |
| Ignoring nulls | Skewed aggregates. |
| Baseline including incident window | Anomaly disappears. |
| Assuming 0 = clean | False negative. |
| Not checking truncation | Incomplete picture. |
| Over-fitting to one sample event | Brittle query. |
| Regex on raw at scale | Performance cliff. |
| No positive control | Untested detection. |

---

## 16. Labs

1. Translate one detection between SPL, KQL, and SQL.
2. Write a lookup query, an aggregate, a compare, a sequence, and an absence query.
3. Join auth and endpoint data on user within a 10-minute window.
4. Baseline a user's login hours and flag deviation.
5. Pivot from one suspicious IP through DNS → proxy → EDR.
6. Optimise a slow query and measure the improvement.
7. Prove a zero-result query with a positive control.
8. Build a windowed sequence detection (failure → success).
9. Document a detection with the full metadata block.
10. Break a query by renaming a field; find the failure.

---

## 17. Self-test questions

1. What are the five query question types?
2. Why must you know the data model before querying?
3. What does an anti-join give you?
4. How do you detect a sequence without `transaction`?
5. When is a baseline invalid?
6. What is a positive control?
7. Why is a 0-result query a claim?
8. What are three causes of query slowness?
9. What is join fan-out?
10. How do you handle nulls in aggregation?
11. What is the difference between sliding and tumbling windows?
12. Why document queries?
13. How do you detect truncation?
14. What makes a good pivot?
15. How do you translate a detection to another platform?

---

## 18. One-page revision checklist

- [ ] Five question types: lookup, aggregate, compare, sequence, absence.
- [ ] Query anatomy: scope → filter → shape → aggregate/sequence → rank → present.
- [ ] Languages: SPL, KQL, Lucene, ES|QL, EQL, SQL, YARA-L, Sigma; shared thinking.
- [ ] Data model first: table/index, field names, timestamp, parsing, retention, volume; field discovery commands.
- [ ] Core ops: filter, project, compute, aggregate, sort — syntax per language.
- [ ] Joins: inner/left/anti/union; cost; prefer pre-aggregation/lookup/stats.
- [ ] Sequences: stats-based, KQL time-window join, EQL sequence, streamstats, binning.
- [ ] Time: bound always, UTC, binning, sliding vs tumbling, off-hours, dwell time.
- [ ] Baselines: first-seen, rare, z-score, peer, time-of-day, ratio; refresh; exclude incident window.
- [ ] Pivoting table: IP, domain, user, host, hash, process, file, time.
- [ ] Optimisation: narrow/time/index, filter early, project early, aggregate before join, avoid wildcards/regex-at-scale, tstats/summary, platform fast paths.
- [ ] Validation: positive/negative control, count sanity, null rate, boundaries, truncation, spot-check, second implementation.
- [ ] Pattern library: spray, success-after-failure, Office→shell, encoded PS, LSASS, exfil, DNS tunnel, beaconing, cloud IAM, MFA failures, mailbox rules, service creation, task creation, agent gaps, absence.
- [ ] Debugging table + remove-clauses method.
- [ ] Documentation block: name, question, platform, scope, logic, fields, FPs, owner, ATT&CK, validated, version.
- [ ] Pitfalls list memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Microsoft Sentinel](Microsoft-Sentinel.md) · [Splunk →](Splunk.md)
