# Splunk — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Queries](Queries.md) · [Wazuh →](wazuh.md)

> Goal: become fluent in SPL for triage and hunting, and understand Splunk's architecture well enough to know why a search is fast, slow, or wrong.
> Aggregation basics → [Queries.md](Queries.md); detection content → [Detection-Rules.md](Detection-Rules.md); collection → [Log-Collection.md](Log-Collection.md).

---

## 0. How to use this note

1. §1–§3: architecture and data model (why it matters for search).
2. §4–§7: SPL fundamentals — search, fields, pipes, stats, eval.
3. §8–§11: advanced — transactions, lookups, macros, datamodels/tstats.
4. §12–§14: performance, tuning, pitfalls.
5. §15–§18: detection content, cheat sheet, labs, self-test, revision.

---

## 1. What Splunk is

- A platform for **ingesting, indexing, searching, and alerting** on machine data.
- Core metaphor: **index → sourcetype → events → fields → searches**.
- SPL (Search Processing Language) is the query language.

**SOC uses:**
- Ad-hoc triage and hunting.
- Scheduled detection searches (correlation searches).
- Dashboards and reports.
- Case/notable event workflow (Enterprise Security).

---

## 2. Architecture

| Component | Role |
|---|---|
| **Universal Forwarder (UF)** | Lightweight agent: collects and forwards raw data. |
| **Heavy Forwarder (HF)** | Parses/filters/routes before sending. |
| **Indexer** | Parses, indexes, stores, searches data. |
| **Search Head** | Runs searches, UI, knowledge objects. |
| **Deployment Server** | Manages UF/HF configs and apps. |
| **Cluster Manager** | Manages indexer cluster. |
| **License Manager** | Tracks ingest volume. |
| **SmartStore** | Remote/cold storage tier. |

### 2.1 Distributed search

- Search head dispatches to indexers; results merged.
- **Search head clustering** shares knowledge objects.
- **Indexer clustering** replicates buckets for HA.

### 2.2 Data flow

```
Input → (parsing queue) → parsing → (index queue) → indexing → buckets
```

- **Parsing:** line breaking, timestamp extraction, sourcetype assignment, transforms.
- **Indexing:** write to TSIDX (time-series index) + rawdata.
- **Buckets:** hot → warm → cold → frozen (deleted).

**Why you care:** parse-time issues (`props.conf`, `transforms.conf`) cause field problems that no search can fix.

---

## 3. Data model concepts

| Concept | Meaning |
|---|---|
| **Index** | Physical storage partition (e.g., `windows`, `proxy`). |
| **Sourcetype** | Format/type of data (`WinEventLog:Security`, `access_combined`). |
| **Source** | Where it came from (file path, host). |
| **Host** | Originating machine. |
| **Event** | Single record. |
| **Field** | Extracted name=value at search time. |

**Index design:** separate by retention/access/volume, not by team whim.
**Sourcetype design:** one per format; drives parsing and field extraction.

### 3.1 Index-time vs search-time

- **Index-time:** line breaking, timestamps, default fields, some extractions (costly to change — requires reindex).
- **Search-time:** field extractions, lookups, eval, calculated fields (flexible).

**Prefer search-time** unless performance demands otherwise.

---

## 4. SPL basics

### 4.1 Search structure

```
index=<index> sourcetype=<type> <search terms>
| <command>
| <command>
```

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count by src_ip, user
| sort -count
```

### 4.2 Search terms

| Syntax | Meaning |
|---|---|
| `foo bar` | Implicit AND. |
| `foo OR bar` | Either. |
| `NOT foo` / `foo NOT bar` | Exclusion. |
| `"exact phrase"` | Phrase match. |
| `field=value` | Field equality (case-insensitive by default for many). |
| `field="*value*"` | Wildcard (leading wildcard is expensive). |
| `field>=10` | Numeric comparison. |
| `field IN (a,b)` | Set membership. |
| `field=*` | Field exists. |

### 4.3 Time

```spl
earliest=-24h latest=now
earliest=-7d@d latest=@d
```

**Always bound time.** Unbounded searches = slow and often wrong.

### 4.4 Order of operations

1. Time range filter.
2. Index/sourcetype narrowing.
3. Search terms (indexers filter).
4. Pipes (search head processes).

**Push filtering as early as possible.**

---

## 5. Core commands

| Command | Purpose |
|---|---|
| `stats` | Aggregate (count, sum, avg, dc, values, earliest, latest). |
| `eval` | Create/modify fields. |
| `where` | Filter on evaluated fields. |
| `table` | Select/order columns. |
| `fields` | Include/exclude fields (performance). |
| `rename` | Rename fields. |
| `dedup` | Remove duplicates. |
| `sort` | Order results. |
| `head`/`tail` | Limit rows. |
| `top`/`rare` | Frequency. |
| `timechart` | Time-series aggregation. |
| `chart` | Pivot-style aggregation. |
| `rex` | Regex field extraction. |
| `regex` | Filter by regex. |
| `lookup` | Enrich from CSV/KV store. |
| `join`/`append` | Combine datasets (use carefully). |
| `transaction` | Group events into sessions (expensive). |
| `eventstats` | Aggregate while keeping events. |
| `streamstats` | Running/windowed stats. |
| `tstats` | Search accelerated data models (fast). |
| `inputlookup` | Read lookup file. |
| `outputlookup` | Write lookup file. |
| `collect` | Write to summary index. |
| `makeresults` | Generate synthetic data (testing). |
| `metadata` | Index/sourcetype stats. |

---

## 6. `stats` in depth

```spl
index=proxy
| stats count AS hits,
        dc(dest) AS unique_dests,
        sum(bytes) AS total_bytes,
        avg(bytes) AS avg_bytes,
        min(_time) AS first_seen,
        max(_time) AS last_seen
        BY src, user
```

### 6.1 Common functions

| Function | Meaning |
|---|---|
| `count` | Rows. |
| `dc(f)` | Distinct count. |
| `values(f)` | All distinct values (list). |
| `sum/avg/min/max` | Numeric. |
| `median/perc95` | Percentiles. |
| `earliest(f)` / `latest(f)` | First/last value by time. |
| `stdev` | Standard deviation. |
| `list(f)` | All values (can be huge — avoid). |

### 6.2 `eventstats` vs `stats` vs `streamstats`

| Command | Keeps events? | Use |
|---|---|---|
| `stats` | No (aggregated rows). | Summaries. |
| `eventstats` | Yes (adds aggregate to each event). | Compare event to group baseline. |
| `streamstats` | Yes (running/windowed). | Behaviour change over time. |

```spl
index=auth action=failure
| eventstats count AS failures BY user
| where failures > 20
```

### 6.3 `chart` vs `timechart`

```spl
... | timechart span=5m count BY action
... | chart count OVER user BY action
```

---

## 7. `eval` in depth

### 7.1 Structure

```spl
| eval new_field = expression
| eval status = if(code>=400, "error", "ok")
| eval severity = case(
    score > 90, "critical",
    score > 70, "high",
    score > 40, "medium",
    true(), "low")
```

### 7.2 Useful functions

| Category | Functions |
|---|---|
| **String** | `lower`, `upper`, `len`, `substr`, `replace`, `split`, `mvindex`, `trim`, `tostring`, `coalesce`. |
| **Numeric** | `tonumber`, `round`, `abs`, `floor`, `ceil`, `pow`. |
| **Time** | `strftime`, `strptime`, `relative_time`, `now`, `duration`. |
| **Conditional** | `if`, `case`, `coalesce`, `nullif`, `validate`. |
| **Multivalue** | `mvcount`, `mvexpand`, `mvdedup`, `mvjoin`, `mvfilter`. |
| **JSON** | `json_extract`, `spath`, `json_array_to_mv`. |
| **IP** | `cidrmatch`. |
| **Lookup** | `lookup` command. |
| **Hashing** | `md5`, `sha1`, `sha256`. |

### 7.3 Examples

```spl
| eval hour=strftime(_time, "%H")
| eval is_internal=if(cidrmatch("10.0.0.0/8", src_ip), "yes", "no")
| eval cmd=lower(coalesce(CommandLine, ProcessCommandLine, ""))
| eval suspicious=if(match(cmd, "(?i)(-enc|-encodedcommand|downloadstring)"), 1, 0)
| eval domain=replace(url, "^https?://([^/]+).*$", "\1")
| eval user_domain=mvindex(split(user,"\\"), -1)
```

### 7.4 Regex in `eval`

- `match(field, regex)` → boolean.
- `rex field=x "(?<name>...)"` → extract.
- Use `(?i)` for case-insensitive.
- Beware catastrophic backtracking on large data.

---

## 8. `transaction` and sessionisation

```spl
index=vpn
| transaction user maxspan=1h
| where duration > 3600
```

| Limitation | Impact |
|---|---|
| Memory/CPU heavy | Slow on large data. |
| Single search head | Not distributed well. |
| Breaks at scale | Prefer `stats`/`streamstats` alternatives. |

**Modern alternative:**
```spl
| stats min(_time) AS start max(_time) AS end BY user, session_id
```

**When to use:** small windows, complex session logic, investigation (not production detections).

---

## 9. Lookups

### 9.1 Kinds

- **CSV lookup** — static file.
- **KV Store lookup** — mutable, app-managed.
- **External lookup** — script/API.
- **Automatic lookup** — applied by props.

### 9.2 Usage

```spl
| lookup asset_inventory ip OUTPUT hostname, owner, criticality
| inputlookup asset_inventory WHERE criticality="tier1"
| outputlookup append=true findings.csv
```

### 9.3 SOC use cases

- Asset inventory/criticality.
- User/role mapping.
- Threat intel (IP/domain/hash).
- Allow/deny lists.
- Watchlists.

**Lookups are the cheapest way to add context.** Keep them current, owned, and versioned.

---

## 10. Macros and knowledge objects

| Object | Use |
|---|---|
| **Macro** | Reusable SPL snippet (`index=windows EventCode=4625`). |
| **Event type** | Categorise events (`failed_login`). |
| **Tag** | Add semantic labels (`authentication`). |
| **Field extraction** | Regex/delimited at search time. |
| **Calculated field** | Derived field for a sourcetype. |
| **Field alias** | Map vendor field → common name. |
| **Workflow action** | Buttons to pivot (VT, EDR). |

**Macros keep detections consistent.** Example:

```spl
[win_failed_logon]
definition = index=windows sourcetype="WinEventLog:Security" EventCode=4625
iseval = 0
```

```spl
`win_failed_logon` | stats count by src_ip
```

---

## 11. Data models and `tstats`

### 11.1 Why

- Data models pre-accelerate common fields for fast queries.
- `tstats` queries the **TSIDX** directly — orders of magnitude faster.

```spl
| tstats count FROM datamodel=Authentication.Authentication
  WHERE Authentication.action=failure
  BY Authentication.src, Authentication.user, _time span=5m
```

### 11.2 CIM (Common Information Model)

Normalises fields across vendors:

| Model | Fields |
|---|---|
| **Authentication** | user, src, dest, action, app, signature. |
| **Network Traffic** | src, dest, bytes_in/out, transport. |
| **Endpoint** | process, file, registry, user. |
| **Web** | url, http_method, status, bytes. |
| **Change** | object, action, user. |
| **Malware** | signature, file_hash, dest. |

**CIM compliance** is what makes vendor-agnostic detections possible.

### 11.3 When to use `tstats`

- Large time ranges.
- Dashboard/report performance.
- Repeated detections.
- High-volume sources.

**Caveat:** limited to modelled/accelerated fields; less flexible than raw search.

---

## 12. Performance

### 12.1 Search job inspector

Check:
- **Execution time** by phase (dispatch, command).
- **Scan count** (how many indexers scanned).
- **Result count**.
- **Search time** vs **run time**.
- **Warnings** (e.g., "search exceeded limits").

### 12.2 Optimisation rules

1. Narrow **time** first.
2. Specify **index** and **sourcetype**.
3. Put **search terms** before pipes.
4. Use `fields` early to drop columns.
5. Avoid leading wildcards (`*foo`).
6. Avoid `transaction` at scale.
7. Prefer `stats` over `join`/`append`.
8. Use `tstats` for modelled data.
9. Use `dedup` sparingly (sorts in memory).
10. Limit `mvexpand`/`list` on high-cardinality fields.
11. Use summary indexing for repeated heavy searches.
12. Accelerate data models.

### 12.3 Limits

| Limit | Meaning |
|---|---|
| `maxresultrows` | Row cap. |
| `maxevents` | Event cap. |
| Search quota | Concurrent searches. |
| `limits.conf` | Admin-tunable. |

Hitting limits = incomplete results. Always check for truncation.

---

## 13. Detection content in Splunk

### 13.1 Saved search → alert

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count AS failures dc(src_ip) AS sources BY user
| where failures > 20
```

Configure: schedule (cron), time range, trigger condition, throttle, action (email/webhook/notable), severity.

### 13.2 Correlation search (ES)

- Uses **risk framework**: risk score per entity.
- **Notable events** appear in Incident Review.
- **Threat intelligence** framework matches lookups.

### 13.3 Best practices

- Name descriptively.
- Document purpose, owner, ATT&CK.
- Use macros for shared logic.
- Throttle by entity, not globally.
- Include context fields.
- Test with historical data.
- Version control (`detection-as-code`).

### 13.4 Example detection set

| Detection | SPL sketch |
|---|---|
| Brute force | `4625` → `stats count by user,src` → `where count>20` |
| Success after failures | join failure + 4624 windows |
| New service | `EventCode=7045` |
| Encoded PowerShell | `4104`/`4688` match `-enc` |
| LSASS access | Sysmon 10 where TargetImage=lsass.exe |
| Shadow copy deletion | `4688` cmd contains `vssadmin delete shadows` |
| Kerberoasting | `4769` where TicketEncryptionType=0x17 |

---

## 14. Common pitfalls

| Pitfall | Consequence |
|---|---|
| No time bound | Slow/timeout. |
| Missing index/sourcetype | Scans everything. |
| Leading wildcard | Full scan. |
| `join` at scale | Slow, memory blowups. |
| `transaction` in production | Performance cliff. |
| Field name mismatch | Silent zero results. |
| Case sensitivity assumptions | Missed events. |
| Not checking truncation | False conclusions. |
| Ignoring parse-time config | Wrong fields forever. |
| Over-throttling alerts | Missed attacks. |
| `list()` on huge cardinality | Memory issues. |
| Assuming `stats` order | Non-deterministic. |
| Copy-paste SPL without validation | Wrong logic. |

---

## 15. Cheat sheet

```spl
## Top talkers
index=proxy | stats sum(bytes) AS b BY src | sort -b | head 20

## Rare destinations
index=dns | stats count BY query | where count < 5 | sort count

## Failure then success (same user, 10m)
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) AS fails,
        count(eval(EventCode=4624)) AS succ BY user
| where fails > 10 AND succ > 0

## New process first seen today
index=endpoint
| stats earliest(_time) AS first BY process_name
| where first > relative_time(now(), "-1d")

## Beaconing heuristic
index=proxy
| bin _time span=1m
| stats count BY src, dest, _time
| stats stdev(count) AS sd avg(count) AS avg dc(_time) AS mins BY src, dest
| where mins > 30 AND sd < 1

## Encoded PowerShell
index=windows (EventCode=4104 OR EventCode=4688)
| eval c=lower(coalesce(ScriptBlockText, CommandLine, ""))
| where match(c, "-enc(odedcommand)?\\s+[a-z0-9+/=]{20,}")

## Data model fast search
| tstats count FROM datamodel=Authentication.Authentication
  WHERE Authentication.action=failure BY Authentication.user, _time span=1h

## Metadata: what's in my indexes
| metadata type=sourcetypes index=* | table sourcetype totalCount lastTime

## Field discovery
index=x | fieldsummary maxvals=20

## Extract with rex
index=web | rex field=_raw "user=(?<username>[^&\s]+)"

## Compare to baseline
index=auth
| eventstats avg(count) AS avg BY user
...
```

---

## 16. Labs

1. Ingest sample Windows logs; verify sourcetype and fields.
2. Write a brute-force detection and test against sample data.
3. Build a timechart of failures by hour.
4. Extract a field with `rex` from a raw log.
5. Create a lookup for asset criticality and enrich a search.
6. Create a macro and refactor three searches to use it.
7. Compare `stats` vs `tstats` runtime for the same question.
8. Use `eventstats` to flag anomalies per user.
9. Build a correlation search with throttling.
10. Use the job inspector to optimise a slow search.

---

## 17. Self-test questions

1. What does the indexer do vs the search head?
2. Index-time vs search-time: which is cheaper to change?
3. Why specify index and sourcetype?
4. Difference between `stats` and `eventstats`?
5. When is `transaction` acceptable?
6. What is `tstats`, and why is it fast?
7. What is CIM and why does it matter?
8. How do you enrich with asset criticality?
9. What are three performance anti-patterns?
10. How do you detect truncation?
11. What is a macro for?
12. How do you throttle an alert properly?
13. Why is a leading wildcard expensive?
14. What does the job inspector tell you?
15. How do you test a detection before enabling it?

---

## 18. One-page revision checklist

- [ ] Platform: index → sourcetype → events → fields → searches.
- [ ] Components: UF, HF, indexer, search head, deployment server, cluster manager, license manager, SmartStore.
- [ ] Data flow: input → parsing (line break, timestamp, sourcetype, transforms) → indexing (TSIDX + raw) → buckets hot/warm/cold/frozen.
- [ ] Concepts: index, sourcetype, source, host, event, field; index-time vs search-time; index design by retention/access/volume.
- [ ] SPL: structure, search terms, time bounds, order of operations (push filters early).
- [ ] Core commands table; stats functions; eventstats vs streamstats vs stats; chart vs timechart.
- [ ] eval: if/case, string/numeric/time/mv/json/ip functions; regex match/rex.
- [ ] transaction cost and alternatives.
- [ ] Lookups: CSV/KV/external/automatic; SOC use cases; keep current.
- [ ] Knowledge objects: macro, eventtype, tag, extraction, calculated field, field alias, workflow action.
- [ ] Data models: tstats, CIM models (Authentication, Network, Endpoint, Web, Change, Malware).
- [ ] Performance: job inspector, narrow time/index/sourcetype, early fields, no leading wildcard, avoid join/transaction, tstats, summary index, acceleration, limits/truncation.
- [ ] Detection content: saved searches, throttling, risk-based + notable events, TI framework, naming/docs/macros/versioning.
- [ ] Detection examples: brute force, success-after-failure, new service, encoded PS, LSASS, shadow deletion, Kerberoasting.
- [ ] Pitfalls list memorised.
- [ ] Cheat sheet patterns recalled: top talkers, rare destinations, first-seen, beaconing, fieldsummary, rex, metadata, tstats.

---

> **Navigation:** [Roadmap index](../README.md) · [← Queries](Queries.md) · [Wazuh →](wazuh.md)
