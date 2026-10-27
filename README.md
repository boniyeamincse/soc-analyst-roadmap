# SOC Analyst Roadmap — Complete Self-Study Library

A structured, self-contained study library for becoming a **SOC Analyst** and progressing to **L2, Detection Engineering, Threat Hunting, and Incident Response**.

**70 study notes · ~38,200 lines · 11 sections · beginner → advanced**

Every note is written to be studied sequentially, used as a reference during an investigation, and revisited as a one-page revision sheet before interviews.

---

## Table of contents

1. [What this project is](#1-what-this-project-is)
2. [Who it is for](#2-who-it-is-for)
3. [Quick start](#3-quick-start)
4. [Repository structure](#4-repository-structure)
5. [Full file index](#5-full-file-index)
6. [Learning paths](#6-learning-paths)
7. [How each note is structured](#7-how-each-note-is-structured)
8. [How to study a note](#8-how-to-study-a-note)
9. [Conventions](#9-conventions)
10. [Prerequisites and tooling](#10-prerequisites-and-tooling)
11. [Suggested 24-week plan](#11-suggested-24-week-plan)
12. [Progress tracker](#12-progress-tracker)
13. [How to extend the library](#13-how-to-extend-the-library)
14. [Known gaps and notes](#14-known-gaps-and-notes)
15. [Usage and attribution](#15-usage-and-attribution)

---

## 1. What this project is

This is a **complete written curriculum** for blue-team work, organised as plain Markdown so it works in any editor, Git repo, Obsidian vault, or note app.

It is not a link collection. Each topic is explained from first principles, then taken down to:

- the exact **telemetry** and log fields involved,
- the **detection logic** (SPL/KQL/Sigma/YARA where relevant),
- the **investigation workflow**,
- the **triage playbook**,
- the **false positives and pitfalls**,
- a **lab plan**, **self-test questions**, and a **one-page revision checklist**.

The goal is that an analyst can read a note once to learn, and open it again mid-incident to act.

---

## 2. Who it is for

| Reader | How to use it |
|---|---|
| **Career changer** | Start at section 01, follow the 24-week plan |
| **L1 analyst** | Sections 04–07 for depth; 08–09 for growth |
| **L2 analyst** | Sections 05–09; use 11 for career framing |
| **Detection engineer** | 04 (Alerting Part II), 05, 06, 09 |
| **Aspiring hunter** | 03, 06, 07, 11 |
| **IR candidate** | 07, 08, 09, 11 |
| **Trainer / mentor** | Use self-test questions and labs as exercises |
| **Interview candidate** | Revision checklists at the end of every note |

**Assumed starting point:** comfortable with a computer, basic command line helpful but not required. No prior security experience needed for section 01.

---

## 3. Quick start

1. Open the folder `SOC ANALYST ROADMAP`.
2. Read this README.
3. Create a study log (`study-log.md`) with one line per session: date, note, sections, what confused you.
4. Start with [01 - Networking Fundamentals/TCP-IP.md](01%20-%20Networking%20Fundamentals/TCP-IP.md).
5. Work top-to-bottom through a section, then take the self-test **before** moving on.
6. Do the lab plan for at least one note per section — reading alone does not build skill.
7. Practice on a platform from section 10 in parallel (2–3 hours/week).

**Minimum viable path:** 01 → 02 → 03 → 04 → 05 → 06 → 07. That is the core SOC skill set.
**Everything after 07** is progression, not prerequisite.

---

## 4. Repository structure

```
SOC ANALYST ROADMAP/
├── README.md
├── 01 - Networking Fundamentals/
├── 02 - Operating Systems/
├── 03 - Cybersecurity Fundamentals/
├── 04 - Security Monitoring/
├── 05 - SIEM/
├── 06 - Threat Detection/
├── 07 - Investigation/
├── 08 - Incident Response/
├── 09 - Automation/
├── 10 - Practice/
└── 11 - Career/
```

### Section intent

| # | Section | Purpose | Level |
|---|---|---|---|
| 01 | Networking Fundamentals | How traffic and protocols actually work | Foundation |
| 02 | Operating Systems | Windows/Linux internals, logs, permissions | Foundation |
| 03 | Cybersecurity Fundamentals | Security concepts, attacks, malware, ATT&CK | Foundation |
| 04 | Security Monitoring | Logs, SIEM concepts, EDR, IDS, alerting | Core |
| 05 | SIEM | Platform-specific querying and detection | Core |
| 06 | Threat Detection | Technique-by-technique detection playbooks | Core |
| 07 | Investigation | Triage, IOC, logs, timeline, RCA, TI | Core |
| 08 | Incident Response | PICERL phases end to end | Advanced |
| 09 | Automation | APIs, scripting, SOAR | Advanced |
| 10 | Practice | Hands-on platforms and lab plans | Throughout |
| 11 | Career | Role expectations, interviews, portfolios | Throughout |

---

## 5. Full file index

### 01 — Networking Fundamentals (4,774 lines)

| File | Lines | Covers |
|---|---:|---|
| [TCP-IP.md](01%20-%20Networking%20Fundamentals/TCP-IP.md) | 893 | OSI/TCP-IP, handshakes, flags, ports, subnetting |
| [HTTP-HTTPS.md](01%20-%20Networking%20Fundamentals/HTTP-HTTPS.md) | 874 | Requests, headers, status codes, TLS, proxies |
| [DNS.md](01%20-%20Networking%20Fundamentals/DNS.md) | 754 | Resolution, record types, tunnelling, logs |
| [Routing-and-Switching.md](01%20-%20Networking%20Fundamentals/Routing-and-Switching.md) | 774 | L2/L3, VLANs, ARP, NAT, segmentation |
| [VPNs.md](01%20-%20Networking%20Fundamentals/VPNs.md) | 779 | Tunnels, IPsec/SSL, split tunnelling, logs |
| [Firewalls.md](01%20-%20Networking%20Fundamentals/Firewalls.md) | 700 | Rules, stateful inspection, NAT, evasion |

### 02 — Operating Systems (6,095 lines)

| File | Lines | Covers |
|---|---:|---|
| [Windows.md](02%20-%20Operating%20Systems/Windows.md) | 749 | Architecture, services, registry, accounts |
| [Windows-Event-Logs.md](02%20-%20Operating%20Systems/Windows-Event-Logs.md) | 817 | Event IDs, audit policy, key investigations |
| [Linux.md](02%20-%20Operating%20Systems/Linux.md) | 827 | Filesystem, processes, services, hardening |
| [File-Systems.md](02%20-%20Operating%20Systems/File-Systems.md) | 831 | NTFS/ext4, metadata, MACB, artefacts |
| [Permissions.md](02%20-%20Operating%20Systems/Permissions.md) | 747 | ACLs, sudo, SUID, privilege models |
| [Processes.md](02%20-%20Operating%20Systems/Processes.md) | 707 | Process trees, lineage, injection, memory |
| [linuxlog.md](02%20-%20Operating%20Systems/linuxlog.md) | 1,151 | syslog, journald, auditd, tampering, forwarding |
| [Container-Logging.md](02%20-%20Operating%20Systems/Container-Logging.md) | 266 | Docker/K8s telemetry, audit logs, breakouts, Falco |

### 03 — Cybersecurity Fundamentals (3,583 lines)

| File | Lines | Covers |
|---|---:|---|
| [CIA-Triad.md](03%20-%20Cybersecurity%20Fundamentals/CIA-Triad.md) | 523 | Confidentiality, integrity, availability |
| [Authentication.md](03%20-%20Cybersecurity%20Fundamentals/Authentication.md) | 643 | Passwords, MFA, sessions, SSO, tokens |
| [Common-Attacks.md](03%20-%20Cybersecurity%20Fundamentals/Common-Attacks.md) | 560 | Phishing, web, network, credential attacks |
| [Malware.md](03%20-%20Cybersecurity%20Fundamentals/Malware.md) | 628 | Types, stages, persistence, behaviour |
| [MITRE-ATTACK.md](03%20-%20Cybersecurity%20Fundamentals/MITRE-ATTACK.md) | 571 | Tactics, techniques, mapping, coverage |
| [Vulnerabilities.md](03%20-%20Cybersecurity%20Fundamentals/Vulnerabilities.md) | 658 | CVE/CVSS, exploitation, patch management |

### 04 — Security Monitoring (4,092 lines)

| File | Lines | Covers |
|---|---:|---|
| [Alerting.md](04%20-%20Security%20Monitoring/Alerting.md) | 1,596 | Alert design, triage ops, metrics **+ Part II: alert engineering (§21–§45)** |
| [SIEM.md](04%20-%20Security%20Monitoring/SIEM.md) | 555 | Architecture, ingestion, correlation, use cases |
| [Logs.md](04%20-%20Security%20Monitoring/Logs.md) | 503 | Sources, formats, collection, retention |
| [EDR.md](04%20-%20Security%20Monitoring/EDR.md) | 544 | Telemetry, detections, response, evasion |
| [IDS-IPS.md](04%20-%20Security%20Monitoring/IDS-IPS.md) | 386 | Signatures, anomalies, placement, tuning |
| [Network-Traffic.md](04%20-%20Security%20Monitoring/Network-Traffic.md) | 508 | Flows, PCAP, protocols, beaconing |

> [Alerting.md](04%20-%20Security%20Monitoring/Alerting.md) is deliberately the longest note: **Part I (§1–§20)** covers the SOC queue; **Part II (§21–§45)** is a full alert-engineering course (classification, confidence scoring, windows, rule chaining, testing, precision/recall, ATT&CK coverage, versioning, SLA, automation).

### 05 — SIEM (4,004 lines)

| File | Lines | Covers |
|---|---:|---|
| [Splunk.md](05%20-%20SIEM/Splunk.md) | 590 | SPL, indexes, sourcetypes, apps |
| [Microsoft-Sentinel.md](05%20-%20SIEM/Microsoft-Sentinel.md) | 597 | KQL, Log Analytics, analytics rules, Workbooks |
| [Elastic-Security.md](05%20-%20SIEM/Elastic-Security.md) | 494 | Elastic/ELK, EQL, detections, cases |
| [wazuh.md](05%20-%20SIEM/wazuh.md) | 571 | Wazuh manager/agents, rules, decoders, XDR |
| [Queries.md](05%20-%20SIEM/Queries.md) | 654 | Cross-platform query patterns |
| [Detection-Rules.md](05%20-%20SIEM/Detection-Rules.md) | 568 | Rule lifecycle, tuning, versioning, retirement |
| [Log-Collection.md](05%20-%20SIEM/Log-Collection.md) | 530 | Agents, forwarders, parsers, pipelines |

### 06 — Threat Detection (3,180 lines)

| File | Lines | Covers |
|---|---:|---|
| [Active-Directory-Attacks.md](06%20-%20Threat%20Detection/Active-Directory-Attacks.md) | 290 | Kerberoasting, AS-REP, DCSync, AD CS, Golden/Silver |
| [Brute-Force.md](06%20-%20Threat%20Detection/Brute-Force.md) | 433 | Password guessing/spray, thresholds, response |
| [Cloud-Detection.md](06%20-%20Threat%20Detection/Cloud-Detection.md) | 230 | AWS CloudTrail, GuardDuty, Entra ID, OAuth, BEC |
| [Credential-Attacks.md](06%20-%20Threat%20Detection/Credential-Attacks.md) | 448 | Dumping, pass-the-hash, Kerberos abuse |
| [Lateral-Movement.md](06%20-%20Threat%20Detection/Lateral-Movement.md) | 483 | SMB, RDP, WinRM, WMI, service creation |
| [Malware.md](06%20-%20Threat%20Detection/Malware.md) | 439 | Execution chains, C2, persistence, triage |
| [Phishing.md](06%20-%20Threat%20Detection/Phishing.md) | 428 | Headers, URLs, attachments, BEC |
| [Suspicious-Processes.md](06%20-%20Threat%20Detection/Suspicious-Processes.md) | 429 | LOLBins, lineage, injection, masquerading |

### 07 — Investigation (3,227 lines)

| File | Lines | Covers |
|---|---:|---|
| [Alert-Triage.md](07%20-%20Investigation/Alert-Triage.md) | 443 | Verdicts, evidence, decision trees, escalation |
| [Digital-Forensics.md](07%20-%20Investigation/Digital-Forensics.md) | 197 | Host artifacts (Prefetch, Shimcache, SRUM), Volatility, KAPE |
| [IOC-Analysis.md](07%20-%20Investigation/IOC-Analysis.md) | 521 | IOC/IOA, Pyramid of Pain, retro-hunting, decay |
| [Log-Analysis.md](07%20-%20Investigation/Log-Analysis.md) | 522 | Parsing, baselining, sequence, gaps |
| [Root-Cause-Analysis.md](07%20-%20Investigation/Root-Cause-Analysis.md) | 546 | 5 Whys, fishbone, fault tree, control failures |
| [Threat-Intelligence.md](07%20-%20Investigation/Threat-Intelligence.md) | 518 | Intel cycle, PIRs, Diamond Model, grading |
| [Timeline-Analysis.md](07%20-%20Investigation/Timeline-Analysis.md) | 480 | Normalisation, super-timelines, gap analysis |

### 08 — Incident Response (2,447 lines)

| File | Lines | Covers |
|---|---:|---|
| [Identification.md](08%20-%20Incident%20Response/Identification.md) | 505 | Declaration, severity, roles, legal clocks |
| [Containment.md](08%20-%20Incident%20Response/Containment.md) | 464 | Isolation ladder, identity/cloud/ransomware |
| [Eradication.md](08%20-%20Incident%20Response/Eradication.md) | 493 | Persistence inventory, AD/cloud cleanup, verification |
| [Ransomware-Playbook.md](08%20-%20Incident%20Response/Ransomware-Playbook.md) | 213 | RaaS lifecycle, pre-encryption detection, containment, rebuild |
| [Recovery.md](08%20-%20Incident%20Response/Recovery.md) | 392 | Backups, clean rebuild, phases, hypercare |
| [Lessons-Learned.md](08%20-%20Incident%20Response/Lessons-Learned.md) | 380 | Blameless review, actions, metrics, maturity |

### 09 — Automation (2,909 lines)

| File | Lines | Covers |
|---|---:|---|
| [APIs.md](09%20-%20Automation/APIs.md) | 512 | REST, auth, pagination, retries, webhooks |
| [Bash.md](09%20-%20Automation/Bash.md) | 519 | Text pipelines, jq, SOC recipes, cron |
| [PowerShell.md](09%20-%20Automation/PowerShell.md) | 551 | Objects, event logs, persistence, Graph |
| [Purple-Teaming.md](09%20-%20Automation/Purple-Teaming.md) | 182 | Atomic Red Team, detection testing CI/CD, scoring ladder |
| [Python.md](09%20-%20Automation/Python.md) | 676 | Requests, parsing, testing, packaging |
| [SOAR.md](09%20-%20Automation/SOAR.md) | 469 | Playbooks, integrations, approval tiers |

### 10 — Practice (1,384 lines)

| File | Lines | Covers |
|---|---:|---|
| [Blue-Team-Labs-Online.md](10%20-%20Practice/Blue-Team-Labs-Online.md) | 269 | BTLO challenge method and plan |
| [CyberDefenders.md](10%20-%20Practice/CyberDefenders.md) | 274 | DFIR artefact workflow (memory/disk/PCAP) |
| [LetsDefend.md](10%20-%20Practice/LetsDefend.md) | 275 | Simulated SOC loop and case writing |
| [Splunk-Labs.md](10%20-%20Practice/Splunk-Labs.md) | 328 | SPL practice ladder, detections, dashboards |
| [TryHackMe.md](10%20-%20Practice/TryHackMe.md) | 238 | Guided paths and attacker empathy |

### 11 — Career (1,634 lines)

| File | Lines | Covers |
|---|---:|---|
| [SOC-Analyst-L1.md](11%20-%20Career/SOC-Analyst-L1.md) | 284 | Entry role, KPIs, interviews, first 90 days |
| [SOC-Analyst-L2.md](11%20-%20Career/SOC-Analyst-L2.md) | 261 | Scoping, narratives, mentoring, growth |
| [Detection-Engineer.md](11%20-%20Career/Detection-Engineer.md) | 370 | Detection-as-code, testing, coverage, CI |
| [Incident-Responder.md](11%20-%20Career/Incident-Responder.md) | 343 | Incident command, evidence, comms, legal |
| [Threat-Hunter.md](11%20-%20Career/Threat-Hunter.md) | 376 | Hypotheses, patterns, findings → detections |

---

## 6. Learning paths

### 6.1 Core SOC Analyst (recommended default)

```
01 Networking
  → 02 Operating Systems
    → 03 Fundamentals
      → 04 Monitoring
        → 05 SIEM
          → 06 Detection
            → 07 Investigation
```

**Time:** ~14–16 weeks at 8–10 h/week.
**Outcome:** can triage alerts, query a SIEM, read logs, write a case, and explain an attack.

### 6.2 L1 → L2 fast track

```
04 Alerting (Part I) → 07 Investigation (all) → 05 Queries
→ 06 Detection (all) → 04 Alerting (Part II) → 08 IR
```

**Time:** ~6–8 weeks if section 01–03 is already solid.

### 6.3 Detection Engineering

```
04 Alerting Part II → 05 Detection-Rules → 06 (all)
→ 09 Python + APIs → 11 Detection-Engineer
→ 10 Splunk-Labs
```

**Build while reading:** 10–20 Sigma rules with tests and a coverage map.

### 6.4 Threat Hunting

```
03 MITRE-ATTACK → 05 Queries → 06 (all)
→ 07 IOC + Timeline + TI → 11 Threat-Hunter
→ 10 CyberDefenders
```

### 6.5 Incident Response

```
07 Investigation (all) → 08 IR (all)
→ 02 Windows/Linux + 01 Network → 09 Automation
→ 11 Incident-Responder
```

### 6.6 Interview in 4 weeks

```
Week 1: revision checklists of 01–03
Week 2: 04 + 06
Week 3: 07 (Alert-Triage, Log-Analysis)
Week 4: 11 (target role) + mock answers
```

---

## 7. How each note is structured

Most notes follow a consistent ~20-section pattern. Not every note needs every section, but the shape is predictable:

| Part | Sections | Purpose |
|---|---|---|
| **Orientation** | §0 | How to use the note, reading order, cross-references |
| **Why it matters** | §1–2 | Business/SOC relevance and role in the workflow |
| **Fundamentals** | §3–5 | First principles, terminology, architecture |
| **Technical depth** | §6–10 | Protocols, artefacts, fields, internals |
| **Telemetry & detection** | §11–13 | Log sources, queries, rules, examples |
| **Operations** | §14–16 | Investigation workflow, playbooks, severity |
| **Reference** | §17–18 | Commands, false positives, hardening |
| **Practice** | §19–20 | Lab plan, 15–20 self-test questions |
| **Revision** | §21 | One-page checklist for interview prep |

Large notes extend this into **Part II** for advanced material (notably [Alerting.md](04%20-%20Security%20Monitoring/Alerting.md)).

---

## 8. How to study a note

1. **Skim** the §0 orientation and the revision checklist at the end first — know the destination.
2. **Read** sections in order, but pause at every table; tables are the compressed knowledge.
3. **Write** your own one-paragraph summary at the top of a personal copy.
4. **Do** the lab plan — at minimum one exercise.
5. **Answer** the self-test questions out loud, without notes.
6. **Check** the revision checklist; mark gaps.
7. **Revisit** after 7 days and 30 days (spaced repetition).
8. **Apply** the note to a real lab alert or challenge from section 10.

### Study rules that matter

- Do not highlight. Write summaries instead.
- Do not move to the next note until the self-test is ≥80% from memory.
- Do not skip the labs — reading creates recognition, not skill.
- Keep a "confusions" list; resolve it weekly.

---

## 9. Conventions

### Filenames

- Hyphens, no slashes or parentheses ([TCP-IP.md](01%20-%20Networking%20Fundamentals/TCP-IP.md), not [TCP/IP.md](01%20-%20Networking%20Fundamentals/TCP-IP.md)).
- Section folders are numbered `01`–`11` for natural sort order.
- One topic per file; no mega-files except [Alerting.md](04%20-%20Security%20Monitoring/Alerting.md) (intentionally two-part).

### Content

| Convention | Meaning |
|---|---|
| **UTC** | All example timestamps are UTC unless stated |
| **Defanged indicators** | `hxxp://`, `evil[.]example` |
| **Cross-references** | "→ `file.md`" rather than duplicating content |
| **Tables over prose** | Comparisons, severities, checks |
| **Code blocks** | Runnable shape, not production-hardened |
| **Severity P1–P4** | Consistent across IR and triage notes |
| **Disposition codes** | TP-M, TP-B, FP-R, FP-D, DUP, INC, TEST |
| **No emojis** | Keeps notes readable in terminals |

### Deliberate non-duplication

Related topics are cross-linked rather than repeated. For example:

- Alert design lives in [04/Alerting.md](04%20-%20Security%20Monitoring/Alerting.md); triage mechanics in [07/Alert-Triage.md](07%20-%20Investigation/Alert-Triage.md).
- IOC types live in [07/IOC-Analysis.md](07%20-%20Investigation/IOC-Analysis.md); the TI programme in [07/Threat-Intelligence.md](07%20-%20Investigation/Threat-Intelligence.md).
- Log formats live in [04/Logs.md](04%20-%20Security%20Monitoring/Logs.md); log *analysis method* in [07/Log-Analysis.md](07%20-%20Investigation/Log-Analysis.md).
- Rule lifecycle lives in [05/Detection-Rules.md](05%20-%20SIEM/Detection-Rules.md); alert engineering maths in [04/Alerting.md](04%20-%20Security%20Monitoring/Alerting.md) Part II.

If you find yourself reading the same paragraph twice, that is a bug — report it.

---

## 10. Prerequisites and tooling

### Knowledge

- Basic computer literacy and file navigation.
- Comfort with a terminal is helpful (section 09 teaches enough Bash/PowerShell/Python).
- No prior security experience required.

### Free tools referenced throughout

| Category | Tools |
|---|---|
| Query / logs | Splunk Free, Elastic, Sentinel trial, Wazuh |
| Endpoint | Sysmon, Defender, Velociraptor, Autoruns |
| Network | Wireshark, tshark, Zeek, Nmap |
| Forensics | Volatility 3, KAPE, Eric Zimmerman tools, Autopsy |
| Malware | `file`, `strings`, CyberChef, YARA, capa |
| Scripting | Bash, PowerShell 7, Python 3.11+ |
| Notes | Obsidian, VS Code, any Markdown editor |
| Practice | BTLO, CyberDefenders, LetsDefend, TryHackMe, Splunk BOTS |

### Hardware guidance

- 16 GB RAM recommended for local VMs; 8 GB workable with one VM.
- 200 GB free disk for forensic images and labs.
- Snapshot your analysis VM before every exercise.

---

## 11. Suggested 24-week plan

| Weeks | Focus | Deliverable |
|---|---|---|
| 1–2 | 01 Networking | Explain a DNS lookup + TLS handshake from memory |
| 3–4 | 02 Operating Systems | Read a Windows event log and a Linux auth log unaided |
| 5–6 | 03 Fundamentals | Map 5 attacks to ATT&CK techniques |
| 7–8 | 04 Monitoring | Write 3 detections and 1 triage note |
| 9–10 | 05 SIEM | Reproduce 10 queries in Splunk/KQL |
| 11–12 | 06 Detection | Triage one alert per technique family |
| 13–14 | 07 Investigation | Full case writeup with timeline |
| 15–16 | 08 IR | Tabletop + containment decision log |
| 17–18 | 09 Automation | One working enrichment script |
| 19–20 | 10 Practice | 20 challenges, 5 writeups |
| 21–22 | 11 Career | Resume + 3 portfolio pieces |
| 23–24 | Revision + mocks | Self-test all sections ≥80% |

### Weekly rhythm

```
Mon–Tue  read 1–2 notes
Wed      lab / challenge
Thu      writeup + self-test
Fri      revise week's notes
Sat      practice platform (2 h)
Sun      rest or catch-up
```

---

## 12. Progress tracker

Copy this into your own `progress.md` and tick as you go.

### Sections

- [ ] 01 Networking Fundamentals
- [ ] 02 Operating Systems
- [ ] 03 Cybersecurity Fundamentals
- [ ] 04 Security Monitoring
- [ ] 05 SIEM
- [ ] 06 Threat Detection
- [ ] 07 Investigation
- [ ] 08 Incident Response
- [ ] 09 Automation
- [ ] 10 Practice (ongoing)
- [ ] 11 Career

### Capability milestones

- [ ] I can explain TCP, DNS, HTTP, and TLS without notes.
- [ ] I can read a Windows 4624/4625/4688 and say what happened.
- [ ] I can write a SPL/KQL query to find brute force and spray.
- [ ] I can triage an alert and produce a defensible verdict.
- [ ] I can scope a compromised host across the estate.
- [ ] I can build a timeline with UTC normalisation.
- [ ] I can explain a detection's logic, FPs, and test plan.
- [ ] I can run a containment decision and justify the trade-off.
- [ ] I can automate one repetitive task with an API.
- [ ] I can answer "walk me through an incident" for 10 minutes.

---

## 13. How to extend the library

If you add a note:

1. **Check for overlap** — cross-reference instead of duplicating.
2. Use the standard structure (§0 orientation → revision checklist).
3. Add the file to §5 of this README with a line count and coverage summary.
4. Add cross-links from at least two related notes.
5. Include a lab plan and self-test.
6. Update the progress tracker if it is a core topic.

### Suggested future additions (not yet written)

| Note | Section | Why |
|---|---|---|
| `Metrics-and-Reporting.md` | 11 | SOC management reporting, MTTD/MTTR KPIs, SLAs |
| `API-Security-Monitoring.md` | 04 | OWASP API Top 10, tokens, abuse detection |
| `Zero-Trust-Architecture.md` | 03 | ZTNA, continuous verification, micro-segmentation |

---

## 14. Known gaps and notes

| Item | Status | Detail |
|---|---|---|
| Platform pricing | **Not stated** | Sections 10 deliberately avoid prices and exact feature lists; verify on each platform's site. |
| Certifications | **Guidance only** | Section 11 lists common certs, not a recommendation to buy any. |
| Tool versions | **Era-dependent** | Commands reflect common syntax; verify against your installed version. |
| Legal specifics | **Jurisdiction-dependent** | Notification clocks in [08/Identification.md](08%20-%20Incident%20Response/Identification.md) are illustrative; confirm with legal. |

---

## 15. Usage and attribution

### Intended use

- Personal study and interview preparation.
- Team onboarding and internal training.
- Lab exercises and tabletop scenarios.
- Building detections and runbooks.

### Care required

- The notes describe **attacker techniques** for defensive understanding. Do not use them against systems you do not own or have written authorization to test.
- Legal, regulatory, and platform details change; verify before relying on them operationally.
- Code snippets are illustrative — review and adapt before production use.
- Query examples assume example field names; map them to your own schema.

### Structure of the library

```
70 study notes
11 progressive sections
~38,200 lines
0 external dependencies (plain Markdown)
```

---

## At a glance

| | |
|---|---|
| **Start here** | [01 - Networking Fundamentals/TCP-IP.md](01%20-%20Networking%20Fundamentals/TCP-IP.md) |
| **Core path** | 01 → 07 |
| **Fastest interview prep** | Revision checklists in each note + section 11 |
| **Hardest note** | [04 - Security Monitoring/Alerting.md](04%20-%20Security%20Monitoring/Alerting.md) (1,596 lines, two parts) |
| **Most practical** | `07 - Investigation/*` and `10 - Practice/*` |
| **Best next step** | Do one lab from section 10 this week |

> **Read one note. Do one lab. Write one paragraph. Repeat.** That loop, not the reading, is what makes an analyst.
