# Splunk Labs — Practice Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← LetsDefend](LetsDefend.md) · [TryHackMe →](TryHackMe.md)

> Goal: build real SPL fluency on real data, then prove it with detections and dashboards.
> Splunk concepts → [05 - SIEM/Splunk.md](../05%20-%20SIEM/Splunk.md); generic query practice → [05 - SIEM/Queries.md](../05%20-%20SIEM/Queries.md).

---

## 0. How to use this note

1. §1–§3: why Splunk labs; options; setup.
2. §4–§7: SPL practice ladder; SOC searches; detections; dashboards.
3. §8–§11: BOTS-style datasets; projects; certs; pitfalls.
4. §12–§14: plan, self-test, revision.

---

## 1. Why practise Splunk specifically

| Reason | Detail |
|---|---|
| Market share | Widely deployed in enterprises |
| SPL fluency | Interview-differentiating |
| Free tier | Splunk Free / trial / dev licence |
| Datasets | BOTS and public sample data |
| Detection | SPL maps to many SIEM concepts |

---

## 2. Lab options

| Option | Notes |
|---|---|
| **Splunk Free** | Local, limited features/ingest |
| **Enterprise trial** | Full features, time-limited |
| **Splunk Cloud trial** | Hosted |
| **Docker** | Fast reset |
| **BOTS datasets** | Realistic attack data |
| **Sample logs** | Syslog, web, Windows |

### 2.1 Minimal lab

```
splunk container/host
+ Windows event sample data
+ web access logs
+ auth logs
+ BOTS dataset
```

---

## 3. Onboarding data

| Step | Action |
|---|---|
| 1 | Create index (`soc_lab`) |
| 2 | Add data → upload/monitor |
| 3 | Set sourcetype correctly |
| 4 | Verify timestamps |
| 5 | Check field extraction |
| 6 | Confirm event counts |

### 3.1 Check before analysis

```spl
index=soc_lab | stats count by sourcetype, host
index=soc_lab | head 5
index=soc_lab | fieldsummary
```

**Wrong sourcetype = wrong fields = wrong answers.**

---

## 4. SPL practice ladder

### Level 1 — shape

```spl
index=soc_lab
| stats count
| timechart span=1h count
| top limit=10 src_ip
| rare limit=10 user
```

### Level 2 — filter

```spl
index=soc_lab status=404
| where len(uri) > 100
| search "union select"
| regex uri="(?i)(\.\./|etc/passwd)"
```

### Level 3 — aggregate

```spl
index=soc_lab action=failure
| stats count AS fails dc(user) AS users BY src_ip
| where fails > 20
```

### Level 4 — sequence

```spl
index=soc_lab (EventCode=4625 OR EventCode=4624)
| eval ok=if(EventCode=4624,1,0)
| stats sum(eval(if(ok=0,1,0))) AS fails sum(ok) AS successes BY user
| where fails>=10 AND successes>0
```

### Level 5 — baseline/anomaly

```spl
index=soc_lab earliest=-30d latest=-1d
| stats avg(bytes) AS avg stdev(bytes) AS sd BY user
| join user [ search index=soc_lab earliest=-1d
  | stats sum(bytes) AS today BY user ]
| where today > avg + 3*sd
```

### Level 6 — detection

```spl
index=wineventlog EventCode=4688
| rex field=CommandLine "(?i)(?<enc>-enc(odedcommand)?\s+\S+)"
| where isnotnull(enc)
| stats count min(_time) AS first max(_time) AS last BY ComputerName, User
```

---

## 5. SOC searches to master

| Goal | Search shape |
|---|---|
| Top talkers | `stats count by src_ip` |
| Rare destinations | `stats count by dest` + low count |
| Failure spike | `timechart span=5m count by action` |
| Success after failure | `stats` per user with both |
| New process | `stats earliest(_time) by process` |
| Beacon interval | `streamstats` deltas |
| Data volume | `stats sum(bytes) by user` |
| Lateral movement | `stats dc(dest) by user` |
| Persistence | search run keys / services |
| Rare parent-child | `stats count by parent, child` |

### 5.1 Beacon detection example

```spl
index=proxy dest=* 
| sort 0 _time
| streamstats current=f last(_time) AS prev BY dest
| eval delta=_time-prev
| stats avg(delta) AS avg_d stdev(delta) AS sd count BY dest, src
| where count>20 AND sd < 5 AND avg_d < 300
```

Low variance + many connections = machine-like periodicity.

---

## 6. Detections

### 6.1 Detection record

```
name, description, rationale
SPL
required fields/sourcetype
threshold/window/schedule
severity/confidence
known FPs
runbook link
test cases
```

### 6.2 Example: password spray

```spl
index=wineventlog EventCode=4625 earliest=-15m
| stats dc(user) AS users count AS fails BY src_ip
| where users >= 5 AND fails >= 10
```

### 6.3 Example: encoded PowerShell

```spl
index=wineventlog EventCode=4104 OR EventCode=4688
| search "-enc" OR "-EncodedCommand"
| stats count values(CommandLine) BY host, user
```

### 6.4 Tuning

- Backtest 30 days.
- Measure alerts/day.
- Sample FPs.
- Add context (privilege, asset).
- Document.

---

## 7. Dashboards

| Dashboard | Panels |
|---|---|
| **Auth** | Failures by user/IP, success after failure, lockouts |
| **Endpoint** | Process anomalies, rare parents, encoded PS |
| **Network** | Top destinations, rare domains, volume |
| **Coverage** | sourcetypes, ingest lag, gaps |
| **Detection health** | alerts/day, latency, FPs |

**Dashboards are for decisions, not decoration.**

---

## 8. BOTS-style datasets

| What | Use |
|---|---|
| Web logs | SQLi, scanning, exfil |
| Windows events | Credential attacks, persistence |
| Firewall | C2, lateral, exfil |
| DNS | Tunnelling, DGA |
| AWS/CloudTrail | IAM abuse |

### 8.1 Method

```
1. Read the scenario
2. Inventory sourcetypes
3. Search broad, then narrow
4. Answer question, record SPL
5. Pivot to next question
6. Write narrative
```

---

## 9. Projects

| Project | Deliverable |
|---|---|
| Auth monitoring | 5 searches + 1 dashboard |
| Web attack detection | 3 detections + backtest |
| Beacon hunting | 1 detection + validation |
| Coverage report | sourcetype gap analysis |
| Detection-as-code | Searches in Git with tests |
| Mini-SOC | 10 alerts + runbooks |

---

## 10. Certifications

| Cert | Level |
|---|---|
| Splunk Core Certified User | Entry |
| Splunk Core Certified Power User | SPL depth |
| Splunk Enterprise Certified Admin | Platform |
| Splunk Certified Cybersecurity Defense Analyst | SOC |

**Practise the exam objectives, not just the badge.**

---

## 11. Pitfalls

| Pitfall | Consequence |
|---|---|
| Wrong sourcetype | Bad fields |
| Ignoring timezone | Wrong windows |
| `search` vs base search confusion | Slow/incorrect |
| Leading wildcards | Slow |
| No `stats` limit | Huge results |
| Not using `earliest/latest` | Wrong data |
| Trusting `count` without dedup | Inflated |
| No backtest | Noisy rule |
| Dashboard without purpose | Shelfware |
| Copying BOTS answers | No skill |

---

## 12. Eight-week plan

| Week | Focus | Output |
|---|---|---|
| 1 | Setup + data onboarding | Working lab |
| 2 | SPL levels 1–3 | 20 searches |
| 3 | Levels 4–5 | 5 correlation searches |
| 4 | Windows detections | 5 rules |
| 5 | Network detections | 5 rules |
| 6 | Dashboards | 2 dashboards |
| 7 | BOTS-style case | 1 writeup |
| 8 | Detection-as-code | Git repo + tests |

---

## 13. Self-test

1. What does `stats` do vs `timechart`?
2. Why set sourcetype correctly?
3. How do you detect spray?
4. How do you find beaconing?
5. What is `streamstats` for?
6. Why avoid leading wildcards?
7. What belongs in a detection record?
8. How do you backtest?
9. What makes a dashboard useful?
10. Why is `earliest/latest` important?

---

## 14. Revision checklist

- [ ] Why Splunk; lab options.
- [ ] Onboarding steps + verification searches.
- [ ] SPL ladder 1–6 with examples.
- [ ] Ten SOC search shapes.
- [ ] Beacon detection logic.
- [ ] Detection record + spray/encoded-PS examples + tuning.
- [ ] Dashboard set.
- [ ] BOTS method.
- [ ] Project list.
- [ ] Cert ladder.
- [ ] Pitfalls memorised.
- [ ] 8-week plan.

---

> **Navigation:** [Roadmap index](../README.md) · [← LetsDefend](LetsDefend.md) · [TryHackMe →](TryHackMe.md)
