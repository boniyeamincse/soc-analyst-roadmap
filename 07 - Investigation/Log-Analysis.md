# Log Analysis — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← IOC Analysis](IOC-Analysis.md) · [Root Cause Analysis →](Root-Cause-Analysis.md)

> Goal: read logs like an investigator — find the event that matters, prove it, and avoid the traps that make logs lie.
> Log sources/inventory → [04 - Security Monitoring/Logs.md](../04%20-%20Security%20Monitoring/Logs.md); Windows events → [02 - Operating Systems/Windows-Event-Logs.md](../02%20-%20Operating%20Systems/Windows-Event-Logs.md); queries → [05 - SIEM/Queries.md](../05%20-%20SIEM/Queries.md); host artifacts & DFIR → [Digital-Forensics.md](Digital-Forensics.md).

---

## 0. How to use this note

1. §1–§3: what logs prove; structure; formats.
2. §4–§7: normalisation, time, fields, data quality.
3. §8–§12: analysis methods — filtering, baselining, frequency, sequence, correlation, anomaly.
4. §13–§16: source-specific analysis notes; gaps; retention; integrity.
5. §17–§19: workflow, pitfalls, labs.
6. §20–§21: self-test, revision.

---

## 1. What logs prove

| Log gives you | Log does not give you |
|---|---|
| That an action was recorded | That it succeeded |
| Who/what/where/when | Why |
| Sequence of recorded events | Events not logged |
| System's own view | Ground truth |

**Core principle: absence of evidence is not evidence of absence** — configure, then verify, then trust.

---

## 2. Log anatomy

| Element | Example | Notes |
|---|---|---|
| **Timestamp** | `2026-04-02T10:15:22Z` | Most important field. |
| **Source** | `host-01`, `fw-edge` | Origin. |
| **Event type/ID** | `4624`, `AUTH_FAIL` | Semantics. |
| **Actor** | user, process, src IP | Who. |
| **Target** | file, host, resource | What. |
| **Result** | success/failure/deny | Outcome. |
| **Severity** | info/warn/error | Vendor view, not risk. |
| **Attributes** | command line, bytes, port | Evidence. |
| **Correlation ID** | session/request/trace | Joins events. |

**If a log lacks timestamp + actor + target + result, analysis is guesswork.**

---

## 3. Formats

| Format | Where | Notes |
|---|---|---|
| **Syslog (RFC 5424/3164)** | Linux, network devices | Priority/facility; UDP lossy, TCP/TLS better. |
| **CEF** | ArcSight-style security devices | `CEF:0|Vendor|Product|...` |
| **LEEF** | IBM QRadar | Similar concept. |
| **JSON** | Cloud, apps, modern agents | Best structure; nesting matters. |
| **EVTX** | Windows | Binary XML; needs parser. |
| **CSV** | Exports, appliances | Fragile with embedded commas. |
| **Key=value** | Firewalls, VPNs | Simple, inconsistent quoting. |
| **Plain text** | Apps, web servers | Regex-dependent. |

### 3.1 Format traps

- **Escaping** — quotes inside quoted fields.
- **Multi-line events** — stack traces split.
- **Encoding** — UTF-8 vs UTF-16 vs Latin-1.
- **Truncation** — long command lines cut at 1–4 KB.
- **Nested JSON** — flattened differently by each parser.
- **Duplicate delimiters** — `key=value key2="a=b"`.

---

## 4. Normalisation

### 4.1 Why

The same concept has many names:

| Concept | Field names seen |
|---|---|
| Source IP | `src`, `src_ip`, `sourceAddress`, `client_ip` |
| User | `user`, `sAMAccountName`, `UserName`, `principal` |
| Action | `action`, `result`, `outcome`, `status` |

**Normalisation maps them to one schema** so a rule works across vendors.

### 4.2 Common schema (ECS-style)

```
@timestamp, event.category, event.action, event.outcome
user.name, user.domain
host.name, host.ip
source.ip, source.port, destination.ip, destination.port
process.name, process.command_line, process.parent.name
file.path, file.hash.sha256
network.transport, network.bytes
```

### 4.3 Normalisation checks

- [ ] Timestamp parsed to UTC.
- [ ] IPs typed as IP (not string).
- [ ] Outcome mapped to success/failure.
- [ ] User/domain split.
- [ ] Process names without path where appropriate.
- [ ] Multivalue fields handled.

---

## 5. Time

### 5.1 Timezone discipline

- Store **UTC**; display local only in reports.
- Verify source timezone; many appliances default to local.
- Watch DST transitions (duplicate/missing hour).
- Check for clock drift (NTP).

### 5.2 Timestamps that differ

| Timestamp | Meaning |
|---|---|
| **Event time** | When it happened (source clock). |
| **Ingest time** | When SIEM received it. |
| **Index time** | When stored. |
| **Alert time** | When rule fired. |

**Investigate on event time; diagnose pipelines with ingest time.**

### 5.3 Latency

```
lag = ingest_time − event_time
```

High lag = delayed detection; negative lag = clock skew.

---

## 6. Fields and values

### 6.1 Reading a field correctly

| Question | Why |
|---|---|
| Is it null or empty? | Different filters. |
| Typed or string? | Comparison behaviour. |
| Case sensitive? | Silent misses. |
| Multi-valued? | Equality fails. |
| Truncated? | Evidence lost. |
| Encoded (base64/URL/hex)? | Needs decoding. |

### 6.2 Decoding common encodings

| Encoding | Tell | Decode |
|---|---|---|
| Base64 | `-enc`, padding `=` | `base64 -d` |
| URL | `%20`, `%2F` | URL-decode |
| Hex | `0x...`, long hex | `xxd -r -p` |
| Gzip+base64 | PowerShell `-enc` | decompress |
| ROT13 | letters only | trivial |

**Always decode before judging.**

---

## 7. Data quality

| Symptom | Cause | Fix |
|---|---|---|
| Missing events | Agent down, filter, retention | Health check. |
| Duplicates | Multiple collectors | Dedup by ID/time. |
| Wrong timestamps | Timezone/clock | Normalise. |
| Null fields | Parser change | Parser tests. |
| Gaps | Network loss (UDP) | TCP/TLS, buffer. |
| Wrong severity | Vendor semantics | Map yourself. |
| Truncation | Field limits | Increase/collect at source. |

**Validate data quality before drawing conclusions.**

---

## 8. Filtering

### 8.1 Progressive narrowing

```
all events → category → actor → time window → result → context
```

### 8.2 Example (SPL)

```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, user, _time
| where count > 10
```

### 8.3 Example (KQL)

```kusto
SecurityEvent
| where EventID == 4625
| summarize Failures=count() by IpAddress, Account, bin(TimeGenerated, 5m)
| where Failures > 10
```

### 8.4 Filtering discipline

- Start broad enough to see context.
- Exclude known noise deliberately, not blindly.
- Keep the filter in your notes.
- Re-run after scope changes.

---

## 9. Baselining

### 9.1 What to baseline

| Entity | Baseline |
|---|---|
| User | Logon hours, hosts, apps, geo |
| Host | Processes, network peers, service accounts |
| Service account | Where it logs on, what it accesses |
| Network segment | Talkers, protocols, volume |
| Application | Error rates, request patterns |

### 9.2 Method

```
collect 2–4 weeks → per-entity distribution
→ p50/p95/p99 → define normal band
→ alert on deviation outside band
```

### 9.3 Seasonal effects

- Business hours vs weekends.
- Month/quarter end.
- Patch Tuesday.
- Holidays.
- Marketing campaigns.

**A baseline without seasonality is a future false positive.**

---

## 10. Frequency and rarity

### 10.1 Frequency analysis

| Pattern | Meaning |
|---|---|
| Sudden spike | Attack or outage. |
| Sudden drop | Failure or evasion. |
| Constant low rate | Beaconing. |
| Periodic jitter | C2 with sleep. |
| Rare event | Novelty — investigate. |

### 10.2 Rarity as signal

```spl
index=proxy
| stats count by dest_domain
| where count < 3
```

Rare destinations are high-value leads — but also user one-offs.

**Combine rarity with sensitivity:** rare + privileged host = strong; rare + dev laptop = weak.

### 10.3 First-seen analysis

```
first_seen(entity, value) over 90 days
```

New values entering an established environment deserve review.

---

## 11. Sequence analysis

### 11.1 Why order matters

Same events, different order, different verdict:

| Sequence | Verdict |
|---|---|
| fail ×20 → success | Brute force success |
| success → fail ×20 | User changed password/locked |
| process create → network → file write | Normal app |
| network → process create → file write | Dropper |

### 11.2 Technique

- Sort by event time (tie-break by ingest).
- Window ±N minutes around the anchor event.
- Look for the **precondition** and the **consequence**.
- Note what should have appeared but didn't.

### 11.3 Missing-event analysis

| Expected | Absent means |
|---|---|
| Logon type 3 after service start | Service didn't authenticate |
| 4688 for a running process | Auditing gap or evasion |
| DNS query for resolved domain | Direct IP or logging gap |
| Logoff after logon | Session still active or logging loss |

---

## 12. Correlation

| Type | Example |
|---|---|
| **Same entity** | User across IdP, endpoint, mail |
| **Same time** | Events within 5 min |
| **Same infrastructure** | Domain + IP + cert |
| **Causal** | Parent → child process |
| **Temporal-pattern** | Repeated at fixed interval |

**Correlation across independent sources is the strongest evidence** — an attacker must control all of them to fake it.

---

## 13. Source-specific analysis notes

### 13.1 Windows Security

| Event | Analyse |
|---|---|
| 4624 | Logon type, source, auth package, privileges |
| 4625 | Failure reason, source, account state |
| 4648 | Explicit credentials — target, process |
| 4672 | Special privileges assigned |
| 4688 | Process + command line + parent |
| 4720/4728 | Account/group change |
| 4768/4769 | Kerberos TGT/ST — encryption type |
| 7045 | Service install |

### 13.2 Linux

| Source | Analyse |
|---|---|
| `auth.log`/`secure` | SSH success/fail, sudo |
| `syslog` | Service events |
| `auditd` | Execve, file access, syscalls |
| `journalctl` | Boot, unit failures |
| `cron` | Scheduled execution |
| bash history | Interactive commands (unreliable) |

### 13.3 Network

| Source | Analyse |
|---|---|
| Firewall | Allow/deny, bytes, ports, repeat attempts |
| Proxy | URL, method, user-agent, bytes, category |
| DNS | Query/response, NXDOMAIN volume, label entropy |
| VPN | Auth, assigned IP, duration, geo |
| IDS | Signature, flow, action |

### 13.4 Cloud

| Source | Analyse |
|---|---|
| CloudTrail/Activity/Audit | Principal, action, resource, source IP, UA |
| Entra sign-in | App, CA result, MFA, risk |
| Storage access | Object, requester, bytes, public flag |

### 13.5 Application/web

| Source | Analyse |
|---|---|
| Web access | Status, path, UA, referer, payload |
| Auth app | Login result, MFA, session creation |
| API gateway | Route, key, rate, latency |

---

## 14. Gaps and coverage

### 14.1 Finding gaps

- Compare expected vs actual sources.
- Check agent health and last-seen.
- Test with a known action ("canary").
- Review retention vs investigation window.
- Check parse failure dashboards.

### 14.2 Canary testing

Perform a known action (create user, log in, connect) and verify it appears with expected fields. **Do this after every pipeline change.**

---

## 15. Retention

| Need | Retention |
|---|---|
| Live triage | 30–90 days hot |
| Incident scope | 6–12 months warm |
| Compliance | Per regulation (often 1 year+) |
| Forensic archive | Cold storage |

**Retention must exceed your detection delay + investigation window.**

---

## 16. Integrity

| Concern | Control |
|---|---|
| Tampering | Append-only/WORM, central collection |
| Deletion | Restrict local admin, forward immediately |
| Time manipulation | NTP + external time source |
| Repudiation | Signed/hashed archives |
| Chain of custody | Hash at collection, document |

**Logs an attacker can edit are evidence for the attacker, not against them.**

---

## 17. Analysis workflow

```
1. Define the question
2. Identify sources that could answer it
3. Verify data quality and time coverage
4. Query broad, then narrow
5. Establish baseline/normal for the entity
6. Look for sequence and absence
7. Correlate across sources
8. Test alternative explanations
9. Document queries, results, limits
10. State conclusion + confidence
```

### 17.1 Alternative-hypothesis discipline

For every conclusion, ask:

- Could this be legitimate admin activity?
- Could this be a logging artefact?
- Could this be a different attacker/actor?
- What evidence would disprove my conclusion?

---

## 18. Pitfalls

| Pitfall | Consequence |
|---|---|
| Trusting local timezone | Timeline wrong. |
| Ignoring nulls | Missed events. |
| Assuming success from presence of log | Action may have failed. |
| Not checking data quality | Analysis on garbage. |
| Over-filtering | Blind spots. |
| Single-source conclusion | Wrong verdict. |
| Ignoring absence | Missed evasion. |
| Not decoding payloads | Missed intent. |
| Truncated command lines | Missed arguments. |
| No query documentation | Unreproducible. |

---

## 19. Labs

1. Parse 5 log formats into one schema.
2. Find the timezone offset between two sources.
3. Build a baseline for one user for 2 weeks.
4. Identify a beacon by interval analysis.
5. Reconstruct a logon sequence from 4624/4625/4672.
6. Do missing-event analysis on a process execution.
7. Correlate proxy + DNS + EDR for one domain.
8. Run a canary test and verify fields.
9. Find a parse failure and fix it.
10. Write a 1-page analysis with stated limits.

---

## 20. Self-test questions

1. Why is absence of evidence not evidence of absence?
2. What are the four essential fields of a log?
3. Name four log formats and one trap each.
4. Why normalise fields?
5. Which timestamp do you investigate on, and which do you diagnose with?
6. What is negative lag?
7. How do you detect a truncated command line?
8. What is baselining and what must it include?
9. Why is rarity alone weak?
10. Give an example where order changes the verdict.
11. What is missing-event analysis?
12. Why is cross-source correlation strong?
13. How do you find logging gaps?
14. What is canary testing?
15. What must retention exceed?

---

## 21. One-page revision checklist

- [ ] Logs record, they don't prove success or intent.
- [ ] Anatomy: timestamp, source, type, actor, target, result, attributes, correlation ID.
- [ ] Formats: syslog, CEF, LEEF, JSON, EVTX, CSV, kv, text + traps.
- [ ] Normalisation schema: ECS-style field list.
- [ ] Time: UTC storage, four timestamps, lag formula, DST/clock skew.
- [ ] Field reading: null/type/case/multivalue/truncation/encoding.
- [ ] Decoding table (base64, URL, hex, gzip, ROT13).
- [ ] Data quality symptom → cause → fix.
- [ ] Filtering progression + SPL/KQL examples.
- [ ] Baselining: entities, method, seasonality.
- [ ] Frequency/rarity/first-seen.
- [ ] Sequence + missing-event analysis.
- [ ] Correlation types.
- [ ] Source-specific key fields (Windows, Linux, network, cloud, app).
- [ ] Gaps, canary testing, retention, integrity.
- [ ] Workflow 10 steps + alternative hypotheses.
- [ ] Pitfalls memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← IOC Analysis](IOC-Analysis.md) · [Root Cause Analysis →](Root-Cause-Analysis.md)
