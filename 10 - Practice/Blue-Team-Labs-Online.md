# Blue Team Labs Online — Practice Study Notes

> Goal: use BTLO to turn theory into repeatable investigation skill — and produce artefacts you can show.
> Other platforms → `CyberDefenders.md`, `LetsDefend.md`, `Splunk-Labs.md`, `TryHackMe.md`.

---

## 0. How to use this note

1. §1–§3: what BTLO is; how it fits; pricing/limits.
2. §4–§7: challenge types; the BTLO method; difficulty ladder.
3. §8–§11: how to write up; portfolio; common traps; time management.
4. §12–§15: 8-week plan; skill mapping; self-test; revision.

---

## 1. What BTLO is

**Blue Team Labs Online** is a hands-on platform of defensive security challenges — investigations, log analysis, forensics, malware triage, threat hunting — with an interactive lab and question-based scoring.

| Property | Detail |
|---|---|
| Focus | Blue team / SOC / DFIR |
| Format | Browser-based lab + questions |
| Difficulty | Easy → hard |
| Cost | Free tier + subscription |
| Output | Answers, writeups, optional certificate paths |

> Check current pricing/features on the site — platforms change. Never rely on a note for pricing.

---

## 2. Where it fits in the roadmap

| Roadmap section | BTLO use |
|---|---|
| 04 Monitoring | Log/traffic challenges |
| 05 SIEM | Query-style investigations |
| 06 Threat Detection | Malware/phishing cases |
| 07 Investigation | IOC, timeline, triage |
| 08 IR | Case-style scenarios |
| 09 Automation | Script the repetitive parts |
| 11 Career | Portfolio evidence |

**BTLO is best for:** analyst-style reasoning on realistic artefacts.
**BTLO is weaker for:** building a SIEM from scratch, long-form IR command, and live enterprise complexity.

---

## 3. Account and setup

- Create an account; note free vs paid challenge access.
- Set up a notes system (Markdown) before starting.
- Keep a **lab log**: date, challenge, time, tools, verdict, lessons.
- Download artefacts when offered; practise offline tooling.
- Never upload sensitive/employer data to any lab platform.

---

## 4. Challenge types

| Type | What you do | Skills |
|---|---|---|
| **Log analysis** | Read web/auth/syslog, answer questions | Filtering, parsing |
| **Network** | PCAP triage | Wireshark, protocol knowledge |
| **Windows forensics** | Event logs, registry, artefacts | Windows internals |
| **Linux forensics** | auth.log, auditd, persistence | Linux internals |
| **Malware triage** | Static/dynamic basics | Hashing, strings, sandbox |
| **Phishing** | Header/URL/attachment analysis | Email auth, defanging |
| **Threat hunting** | Hypothesis-driven search | Pivoting |
| **OSINT** | Research infrastructure | Verification |
| **Incident report** | Narrative + findings | Communication |

**Do at least one from each type** — breadth beats grinding one category.

---

## 5. The BTLO method

```
1. READ the scenario twice — note the question set
2. INVENTORY the artefacts you were given
3. IDENTIFY the time window and entities
4. ANSWER the easy factual questions first
5. PIVOT on each answer to the next question
6. RECORD the exact query/filter used for each answer
7. VERIFY the final story is consistent
8. WRITE UP method + findings
```

### 5.1 Why answer order matters

Questions often form a chain: identify the host → identify the process → identify the C2 → identify the data. **Each answer is a pivot for the next.**

### 5.2 Evidence log per question

| Field | Example |
|---|---|
| Question | "What is the malicious IP?" |
| Source | `access.log` |
| Query | `grep -c "POST /upload"` |
| Evidence | line 4421 |
| Answer | `203.0.113.45` |
| Confidence | High |

**If you cannot reproduce an answer, you did not learn it.**

---

## 6. Difficulty ladder

| Level | Do this | Target |
|---|---|---|
| Easy | Log formats, basic grep/Wireshark filters | 5–8 challenges |
| Medium | Multi-source correlation | 5–8 challenges |
| Hard | Full intrusion reconstruction | 3–5 challenges |

**Do not jump to hard before you can explain easy answers without notes.**

---

## 7. Tooling

| Task | Tools |
|---|---|
| Text/logs | grep, awk, jq, `less` |
| PCAP | Wireshark/tshark, Zeek |
| Windows | Event Viewer, EvtxECmd, Autoruns, Registry Explorer |
| Linux | journalctl, auditd, `last`, `ausearch` |
| Malware | `file`, `strings`, hashes, YARA, sandbox |
| Encoding | CyberChef |
| Timeline | spreadsheet, Timesketch |
| Notes | Markdown/Obsidian |

**Learn the CLI versions too** — you will not always have a GUI.

---

## 8. Writing up

### 8.1 Structure

```
1. Scenario and objective
2. Artefacts and data sources
3. Method (step by step, with queries)
4. Findings (per question, with evidence)
5. Attack narrative
6. Detection opportunities (rules/Sigma)
7. Response recommendations
8. What I would do differently
```

### 8.2 Quality bar

- Every claim has evidence.
- Queries are reproducible.
- Timezone stated.
- Uncertainty acknowledged.
- Detection rule suggested.

**This structure is also a solid interview answer.**

---

## 9. Portfolio

| Artefact | Value |
|---|---|
| Writeups (public-safe) | Demonstrates method |
| Query collection | Shows tooling |
| Sigma rules written | Detection skill |
| Timeline diagrams | Communication |
| Lab log | Consistency |

### 9.1 Rules

- Do not publish paid challenge answers/solutions.
- Summarise method, not copyrighted content.
- Redact anything from a real employer.
- Link your GitHub/blog if you have one.

---

## 10. Common traps

| Trap | Better |
|---|---|
| Guess an answer to unlock next | Verify |
| Ignore timezone | Convert to UTC |
| Grep for keyword only | Understand the log schema |
| Trust one source | Corroborate |
| Stop at the first IOC | Pivot to scope |
| Copy a writeup | You learn nothing |
| Skip the narrative | Practice reporting |
| No notes | No retention |

---

## 11. Time management

| Phase | Time |
|---|---|
| Read + inventory | 5 min |
| Easy questions | 10–20 min |
| Deep pivots | 30–60 min |
| Writeup | 20–30 min |

If stuck > 20 min on one question: write what you know, move on, return later. **Do not burn the session.**

---

## 12. Eight-week plan

| Week | Focus | Output |
|---|---|---|
| 1 | Log analysis basics | 3 writeups |
| 2 | Windows event/artefacts | 2 writeups |
| 3 | Linux forensics | 2 writeups |
| 4 | Network/PCAP | 2 writeups |
| 5 | Phishing/email | 2 writeups |
| 6 | Malware triage | 2 writeups |
| 7 | Hunting-style challenge | 1 deep writeup |
| 8 | Redo 1 hard challenge from scratch | Comparison notes |

---

## 13. Skill mapping

| Skill | How you prove it |
|---|---|
| Log parsing | Show query + result |
| Windows knowledge | Event IDs and fields cited |
| Network | Filters and flow reasoning |
| Malware | Hash, strings, behaviour |
| Detection | Sigma/YARA written |
| Communication | Clean narrative |
| Judgement | Stated confidence |

---

## 14. Self-test

1. What does BTLO optimise for?
2. Why read all questions before starting?
3. Why is an evidence log necessary?
4. What belongs in a writeup?
5. What should you never publish?
6. Which tool for PCAP, and which for registry?
7. When do you move on from a stuck question?
8. Why do easy-to-hard progression?
9. What makes a lab reusable in interviews?
10. What is the biggest trap in lab work?

---

## 15. Revision checklist

- [ ] Know the platform's focus and format.
- [ ] Set up notes/lab log before starting.
- [ ] Method: read → inventory → window → easy answers → pivots → verify → write.
- [ ] Evidence log per question.
- [ ] Difficulty ladder and breadth across types.
- [ ] Tooling list (CLI + GUI).
- [ ] Writeup structure with detection recommendations.
- [ ] Portfolio rules and ethical limits.
- [ ] Traps memorised.
- [ ] Time-boxing rule.
- [ ] 8-week plan printed.
