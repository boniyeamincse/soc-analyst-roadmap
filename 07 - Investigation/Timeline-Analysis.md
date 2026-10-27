# Timeline Analysis — SOC Analyst Study Notes

> Goal: reconstruct *what happened, in order* — with enough precision that the sequence itself becomes evidence.
> Causal reasoning → `Root-Cause-Analysis.md`; log reading → `Log-Analysis.md`; forensics in `08`.

---

## 0. How to use this note

1. §1–§3: what timelines do; types; sources.
2. §4–§7: timestamps, normalisation, ordering, precision.
3. §8–§12: building a timeline; super-timelines; visualisation; gap analysis; correlation.
4. §13–§16: MACB times, memory/network/cloud, tools, attack-phase mapping.
5. §17–§19: workflow, pitfalls, labs.
6. §20–§21: self-test, revision.

---

## 1. Why timelines matter

| Without a timeline | With a timeline |
|---|---|
| Scattered facts | Sequence |
| Guessing causality | Evidence of order |
| Missed dwell time | Measured dwell time |
| Single-host view | Estate view |
| Weak report | Defensible narrative |

**Sequence is evidence.** Two events that each look benign can be damning in order.

---

## 2. Types of timeline

| Type | Scope | Use |
|---|---|---|
| **Incident timeline** | One case | Reporting, RCA. |
| **Host timeline** | One endpoint | Compromise reconstruction. |
| **Entity timeline** | One user/account | Identity investigations. |
| **Estate timeline** | Whole org | Campaign scoping. |
| **Super-timeline** | All artefacts | Forensics. |
| **Predictive timeline** | Expected events | Finding gaps. |

---

## 3. Sources

| Source | Granularity | Notes |
|---|---|---|
| SIEM events | Seconds | Broad, retention-limited. |
| EDR process/network | Seconds | Rich. |
| Windows Event Log | Seconds | Audit-dependent. |
| File system MACB | Nanoseconds* | *Actually coarse on some FS. |
| Registry | Seconds | Last-write only. |
| Prefetch/Amcache | Seconds | Execution evidence. |
| Browser history | Seconds | User activity. |
| Proxy/DNS | Seconds | Network activity. |
| Email gateway | Seconds | Delivery/click. |
| Cloud audit | Seconds | Control-plane. |
| Memory capture | Point-in-time | Running state. |
| PCAP | Microseconds | Network truth. |
| Physical access/badge | Seconds | Insider cases. |

---

## 4. Timestamps

### 4.1 The four times

| Time | Meaning |
|---|---|
| **Occurred** | When it happened at source. |
| **Recorded** | When the source wrote it. |
| **Collected** | When you acquired it. |
| **Ingested** | When the platform stored it. |

**Use occurred for narrative; use the others for diagnosing gaps.**

### 4.2 Common formats

| Format | Example |
|---|---|
| ISO 8601 | `2026-04-02T10:15:22.431Z` |
| Unix epoch | `1775124922` |
| Windows FILETIME | `133...` (100ns since 1601) |
| Syslog | `Apr  2 10:15:22` (no year!) |
| Localised | `02/04/2026 10:15` (ambiguous) |

### 4.3 Normalisation rules

1. Convert everything to **UTC**.
2. Store the original value alongside.
3. Use **ISO 8601 with milliseconds**.
4. Record the source timezone and offset.
5. Flag entries where conversion was uncertain.

---

## 5. Clock skew and drift

| Problem | Effect |
|---|---|
| Unsynchronised host | Events out of order. |
| VM snapshot restore | Time jump backwards. |
| Timezone misconfig | Hours offset. |
| DST transition | Duplicate/missing hour. |
| Manual clock change | Deliberate or accidental. |

### 5.1 Detecting skew

- Compare logon events across host/DC.
- Check NTP status and offset.
- Compare network flow times with host logs.
- Look for impossible sequences (child before parent).

### 5.2 Correcting

- Apply a consistent offset per source.
- **Document the adjustment** — never silently edit.
- Prefer sources with reliable time as anchors.

---

## 6. Ordering

### 6.1 Deterministic sort

```
sort by: occurred_utc, then source_priority, then ingest_time
```

| Source priority | Example |
|---|---|
| 1 | Network/packet capture |
| 2 | Security logs |
| 3 | EDR telemetry |
| 4 | Application logs |
| 5 | Derived artefacts |

### 6.2 Same-second events

- Sub-second precision where available.
- Otherwise use causality (parent/child, request/response).
- Mark ambiguous groups rather than inventing order.

### 6.3 Ties and contradictions

When two sources disagree, keep both rows and annotate. **Do not delete the inconvenient one.**

---

## 7. Precision and granularity

| Granularity | Use |
|---|---|
| Day | Strategic trends |
| Hour | Campaign shape |
| Minute | Incident sequence |
| Second | Most IR work |
| Millisecond | Process/network causality |

**Zoom level should match the question.** Aggregate for scope, expand for causality.

---

## 8. Building a timeline

### 8.1 Method

```
1. Define question and window
2. List sources that cover the window
3. Extract raw events
4. Normalise time and fields
5. Tag with source, entity, category
6. Sort
7. Identify phases and gaps
8. Annotate findings
9. Visualise
10. Write narrative with evidence refs
```

### 8.2 Row schema

```
timestamp_utc | source | entity | action | target | result | evidence_ref | note
```

### 8.3 Tagging

| Tag | Example |
|---|---|
| initial-access | phish delivery |
| execution | macro spawns powershell |
| persistence | run key |
| discovery | net group |
| lateral | SMB logon |
| collection | archive created |
| exfil | outbound TLS 400 MB |
| impact | shadow copy delete |

---

## 9. Super-timelines

### 9.1 What

Merge **all** artefacts (disk, memory, logs, network, cloud) into one sorted dataset.

### 9.2 Tools

| Tool | Function |
|---|---|
| **Plaso / log2timeline** | Parse many artefacts |
| **Timesketch** | Collaborative analysis |
| **KAPE** | Targeted collection |
| **Eric Zimmerman tools** | Windows artefacts |
| **Volatility** | Memory |
| **Excel/pandas** | Small timelines |
| **ELK/Splunk** | Log-based timelines |

### 9.3 Process

```
collect → parse → normalise → merge → dedupe
→ sort → filter by entity/time → analyse
```

### 9.4 Warning

Super-timelines are **huge**. Filter by entity and window before analysis or you will drown.

---

## 10. Visualisation

| View | Use |
|---|---|
| **Table** | Evidence, export, review. |
| **Swimlane by host** | Lateral movement. |
| **Swimlane by entity** | User activity. |
| **Histogram** | Bursts, gaps. |
| **Graph (nodes/edges)** | Relationships. |
| **Kill-chain bands** | Phase attribution. |

### 10.1 Good visualisation

- One row per event, colour by category.
- Time on X, entity on Y.
- Annotate key events.
- Keep a legend.
- Export the table for the report.

---

## 11. Gap analysis

### 11.1 Expected-event timeline

Build what *should* have happened, then diff with what did.

| Expected | Observed | Meaning |
|---|---|---|
| 4624 type 3 on file server | Absent | Logon not logged / failed |
| DNS for resolved IP | Absent | Direct IP / logging gap |
| Process exit event | Absent | Still running / EDR gap |
| Logoff after logon | Absent | Active session / gap |

### 11.2 Silence as signal

| Silence | Interpretation |
|---|---|
| Beacon goes quiet | Operator paused, host isolated, or evasion |
| Logs stop | Agent killed, disk full, or tampering |
| No auth events after credential theft | Token reuse / pass-the-hash |

**Investigate silence with the same rigour as activity.**

---

## 12. Correlation across sources

| Pattern | Sources |
|---|---|
| Phish → click → download → execute | mail, proxy, EDR |
| Credential theft → lateral → DC | EDR, 4624, 4769 |
| Cloud token → mailbox rule → BEC | IdP, audit, mail |
| Scan → exploit → shell | firewall/IDS, EDR |

### 12.1 Time-window correlation

| Activity | Window |
|---|---|
| Click → download | 0–5 min |
| Download → execute | 0–60 min |
| Credential theft → lateral | 0–60 min |
| Initial access → detection | days–weeks |

**Windows should reflect plausible human/machine speed.**

---

## 13. File system MACB

| Time | Meaning |
|---|---|
| **M**odified | Content changed. |
| **A**ccessed | Read/opened (often disabled). |
| **C**hanged (MFT) | Metadata changed. |
| **B**irth (created) | File created. |

### 13.1 Cautions

- Timestomping can forge M/A/C.
- `$STANDARD_INFORMATION` vs `$FILE_NAME` times can differ — compare both.
- Copying changes creation time.
- Archive extraction sets new times.
- No-atime config disables A.

### 13.2 Use

Sequence of file drops, staging, archive creation, and deletion supports the narrative.

---

## 14. Memory, network, cloud

### 14.1 Memory

- Point-in-time, not a timeline.
- Gives processes, connections, injected code, credentials.
- Correlate with disk timeline by PID/process start time.

### 14.2 PCAP

- Microsecond precision.
- Ground truth for network claims.
- Can reconstruct sessions, uploads, C2.

### 14.3 Cloud

- Control-plane events with actor, IP, UA.
- Data-plane (storage/S3) events may be separate and sampled.
- Time zones usually UTC.
- Token/session events link to IdP logs.

---

## 15. Tools

| Category | Tools |
|---|---|
| Parsing | Plaso, log2timeline, KAPE, ZIMMERMAN suite |
| Analysis | Timesketch, ELK, Splunk, pandas |
| Memory | Volatility 3 |
| Network | Wireshark, Zeek, tshark |
| Visualisation | Timesketch, Excel, Grafana |
| Correlation | SIEM, notebooks |

---

## 16. Mapping to attack phases

| Phase | Typical timeline entries |
|---|---|
| Recon | scans, OSINT lookups |
| Delivery | mail, web download |
| Exploitation | process spawn, exploit crash |
| Installation | persistence writes |
| C2 | periodic connections |
| Discovery | enumeration commands |
| Lateral | logons, service creation |
| Collection | archive/zip |
| Exfil | outbound volume |
| Impact | encryption, deletion |

**Phase annotation turns a list into a story.**

---

## 17. Workflow

```
Question → window → sources → extract → normalise
→ sort → tag → identify phases → find gaps
→ correlate → visualise → narrate → cite → review
```

### 17.1 Narrative writing

- Chronological, short paragraphs.
- Each claim cites an event/time.
- Separate observation from inference.
- State uncertainty explicitly.
- End with a scoped conclusion.

### 17.2 Review checklist

- [ ] All times UTC.
- [ ] Sources and ranges stated.
- [ ] Gaps identified.
- [ ] Contradictions annotated.
- [ ] Key events have evidence refs.
- [ ] Alternative sequence considered.
- [ ] Limits stated.

---

## 18. Pitfalls

| Pitfall | Consequence |
|---|---|
| Mixed timezones | Wrong order. |
| Ignoring skew | False causality. |
| Deleting contradictory rows | Biased narrative. |
| Over-aggregating | Missed detail. |
| Under-filtering | Drowning in data. |
| Trusting MACB alone | Timestomping. |
| Assuming log completeness | Missed activity. |
| No evidence refs | Unverifiable report. |
| Inventing order in ties | False precision. |
| Ignoring silence | Missed evasion. |

---

## 19. Labs

1. Merge 3 log sources into one UTC timeline.
2. Detect and correct a 2-hour skew.
3. Build a host timeline from Sysmon.
4. Annotate phases on a public intrusion report.
5. Do gap analysis on a logon sequence.
6. Build a swimlane for lateral movement.
7. Correlate phish → click → execute.
8. Examine MACB times for timestomping.
9. Use Timesketch on a sample image.
10. Write a 1-page narrative with citations.

---

## 20. Self-test questions

1. Why is sequence evidence?
2. Name five timeline types.
3. What are the four timestamps?
4. Which timestamp for narrative, which for gaps?
5. How do you normalise time?
6. How do you detect clock skew?
7. What is deterministic ordering?
8. What do you do with contradictory sources?
9. What is a super-timeline, and its risk?
10. What is expected-event (gap) analysis?
11. Give three examples of silence as signal.
12. What do M, A, C, B mean?
13. How can timestomping be detected?
14. What does memory add to a timeline?
15. Why annotate attack phases?
16. What belongs in a timeline narrative?

---

## 21. One-page revision checklist

- [ ] Sequence is evidence; types of timeline.
- [ ] Sources and their granularity.
- [ ] Four timestamps; ISO 8601 UTC normalisation rules.
- [ ] Clock skew causes/detection/correction (documented).
- [ ] Deterministic sort + source priority; ties handled honestly.
- [ ] Granularity matches question.
- [ ] Build method 10 steps; row schema; phase tags.
- [ ] Super-timeline process + tools + filtering warning.
- [ ] Visualisation types and good practice.
- [ ] Gap/expected-event analysis; silence as signal.
- [ ] Correlation windows.
- [ ] MACB semantics + timestomping cautions.
- [ ] Memory/PCAP/cloud contributions.
- [ ] Tools list.
- [ ] Attack-phase mapping.
- [ ] Narrative rules + review checklist.
- [ ] Pitfalls memorised.
