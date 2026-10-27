# CyberDefenders — Practice Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Blue Team Labs Online](Blue-Team-Labs-Online.md) · [LetsDefend →](LetsDefend.md)

> Goal: practise DFIR-grade analysis on realistic artefacts — memory, disk, network, and Windows/Linux forensics.
> Other platforms → [Blue-Team-Labs-Online.md](Blue-Team-Labs-Online.md), [LetsDefend.md](LetsDefend.md).

---

## 0. How to use this note

1. §1–§3: what CyberDefenders is; fit; setup.
2. §4–§7: challenge categories; workflow; tooling.
3. §8–§11: writeups, portfolio, pitfalls, progression.
4. §12–§14: plan, self-test, revision.

---

## 1. What CyberDefenders is

**CyberDefenders** is a DFIR/blue-team challenge platform built around **realistic evidence sets** — memory dumps, disk images, PCAPs, logs — with investigative questions.

| Property | Detail |
|---|---|
| Focus | DFIR, threat hunting, SOC |
| Format | Downloadable artefacts + questions |
| Difficulty | Easy → hard |
| Cost | Free + paid/certification tracks |
| Strength | Real artefact handling |
| Weakness | Less "live SOC" than other platforms |

> Verify current pricing/cert offerings on the site.

---

## 2. Where it fits

| Skill | CyberDefenders relevance |
|---|---|
| Memory forensics | High |
| Disk/Windows artefacts | High |
| Network forensics | High |
| Malware triage | Medium-high |
| Log analysis | Medium |
| Live SOC queue | Low |
| Detection engineering | Medium (write rules after) |

**Best for:** learning to work with raw evidence rather than pre-digested logs.

---

## 3. Setup before you start

- Disk space for images (tens of GB).
- Analysis VM with snapshots (never analyse on your host).
- Toolchain installed and tested.
- Case folder per challenge:

```
cases/<challenge>/
  00-notes.md
  01-evidence/     (read-only copy)
  02-extracts/
  03-timeline/
  04-report.md
```

- Hash the evidence on acquisition and record it.

---

## 4. Challenge categories

| Category | Artefacts | Core tools |
|---|---|---|
| **Memory forensics** | `.mem`, `.raw`, dumps | Volatility 3 |
| **Windows forensics** | Disk images, hives, EVTX | KAPE, ZIMMERMAN suite, Registry Explorer |
| **Linux forensics** | Disk images, logs | `mount`, `journalctl`, `ausearch` |
| **Network forensics** | PCAP | Wireshark, tshark, Zeek |
| **Malware analysis** | Samples, sandbox output | `strings`, `file`, YARA, sandbox |
| **Threat intel/OSINT** | Indicators | Research, VT |
| **Cloud/mobile** | Varies | Platform-specific |

---

## 5. Workflow

```
1. Read the brief and all questions
2. Hash and inventory evidence
3. Identify artefact types and time range
4. Start with the easiest artefact (often logs/registry)
5. Answer, pivot, correlate across artefacts
6. Build a timeline as you go
7. Verify the narrative end-to-end
8. Write up with commands and evidence
```

### 5.1 Memory workflow

```
1. imageinfo → profile (Volatility 2) / auto (Vol3)
2. pslist / pstree → process anomalies
3. cmdline → suspicious arguments
4. netscan → connections
5. malfind → injected code
6. dlllist / handles → loaded modules
7. hashdump / lsadump → credential access
8. filescan / dumpfiles → staged data
9. registry hives → persistence
10. timeline of process starts + network
```

### 5.2 Disk workflow

```
1. Confirm image integrity
2. Identify partitions/filesystem (read-only mount)
3. Parse EVTX, registry, prefetch, amcache, shimcache
4. User artefacts: browser, downloads, recycle bin
5. Persistence: services, tasks, run keys
6. Executables/scripts in temp paths
7. Build super-timeline
8. Correlate with memory/network
```

### 5.3 Network workflow

```
1. Protocol hierarchy → what's here
2. Conversations → volume
3. DNS queries → rare/long labels
4. HTTP requests → user agents, uploads
5. TLS → SNI, JA3, certificates
6. Extract objects → files
7. Reconstruct sessions → timeline
```

---

## 6. Tooling

| Purpose | Tools |
|---|---|
| Memory | Volatility 3, MemProcFS |
| Disk parsing | KAPE, Autopsy, FTK Imager |
| Windows artefacts | EvtxECmd, PECmd, AmcacheParser, RECmd, MFTECmd, JLECmd |
| Registry | Registry Explorer |
| Timeline | Timesketch, Plaso, Excel |
| Network | Wireshark, tshark, Zeek, NetworkMiner |
| Malware | `file`, `strings`, `xxd`, YARA, capa |
| Encoding | CyberChef |
| Notes | Markdown |

**Learn one CLI path for each artefact** — GUIs hide the logic you need in interviews.

---

## 7. Answer discipline

| Rule | Why |
|---|---|
| Record the command | Reproducibility |
| Note timestamps in UTC | Consistency |
| Cite artefact + offset/PID | Evidence |
| Distinguish fact from inference | Accuracy |
| Hash extracted files | Integrity |
| Keep evidence read-only | No contamination |

### 7.1 Evidence record

```
question | artefact | command | output snippet | answer | confidence
```

---

## 8. Writeups

```
1. Brief and scope
2. Evidence inventory + hashes
3. Method per artefact
4. Findings (question → evidence)
5. Attack timeline
6. MITRE mapping
7. Detection opportunities (Sigma/YARA)
8. Gaps and limitations
```

**Detection opportunities are what separate a lab writeup from a professional report.**

---

## 9. Portfolio and ethics

- Publish method, not paid answers.
- Redact any real personal data.
- Do not redistribute evidence images.
- Keep tools/licences compliant.
- Link your methodology notes, not just answers.

---

## 10. Pitfalls

| Pitfall | Consequence |
|---|---|
| Analysing on host | Infection/contamination |
| Not hashing evidence | No integrity |
| Wrong timezone | Wrong timeline |
| Jumping to Volatility | Miss easy registry answers |
| Ignoring $MFT/$UsnJrnl | Miss file activity |
| Trusting one artefact | Wrong narrative |
| No notes | Unreproducible |
| Skipping the report | No communication skill |
| Chasing every question | Time sink |
| Not mapping to ATT&CK | No detection output |

---

## 11. Progression

| Stage | Challenges | Goal |
|---|---|---|
| 1 | Easy log/registry | Formats and artefacts |
| 2 | Easy memory | Volatility basics |
| 3 | Medium disk+memory | Correlation |
| 4 | Medium network | PCAP reconstruction |
| 5 | Hard multi-artefact | Full case |
| 6 | Re-do a hard case blind | Retention test |

---

## 12. Six-week plan

| Week | Focus | Output |
|---|---|---|
| 1 | Windows artefacts | 2 writeups |
| 2 | Memory | 2 writeups |
| 3 | Network | 2 writeups |
| 4 | Linux/cloud | 1–2 writeups |
| 5 | Multi-artefact case | 1 deep writeup |
| 6 | Blind redo + Sigma rules | 1 report + 2 rules |

---

## 13. Self-test

1. What artefacts does CyberDefenders emphasise?
2. Why hash evidence first?
3. What is the first Volatility step?
4. Name four Windows artefacts and their tools.
5. How do you build a super-timeline?
6. What do you extract from a PCAP first?
7. Why keep evidence read-only?
8. What turns a writeup into a professional report?
9. Why avoid analysing on your host?
10. What is the benefit of a blind redo?

---

## 14. Revision checklist

- [ ] Platform focus: DFIR artefact analysis.
- [ ] Case folder structure + evidence hashing.
- [ ] Categories: memory, disk/Windows, Linux, network, malware, OSINT, cloud.
- [ ] Memory workflow 10 steps.
- [ ] Disk workflow 8 steps.
- [ ] Network workflow 7 steps.
- [ ] Tooling table (CLI + GUI).
- [ ] Evidence record with command and confidence.
- [ ] Writeup structure incl. MITRE + detections.
- [ ] Ethics and portfolio rules.
- [ ] Pitfalls memorised.
- [ ] Progression ladder + 6-week plan.

---

> **Navigation:** [Roadmap index](../README.md) · [← Blue Team Labs Online](Blue-Team-Labs-Online.md) · [LetsDefend →](LetsDefend.md)
