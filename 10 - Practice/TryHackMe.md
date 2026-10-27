# TryHackMe — Practice Study Notes

> Goal: use THM's guided rooms to build breadth — attacker empathy included — without mistaking walkthroughs for skill.
> SOC simulations → `LetsDefend.md`; DFIR depth → `CyberDefenders.md`.

---

## 0. How to use this note

1. §1–§3: what THM is; fit; setup.
2. §4–§7: paths and rooms that matter; how to use rooms; note-taking.
3. §8–§11: attacker empathy, pitfalls, portfolio, plan.
4. §12–§14: self-test, revision.

---

## 1. What TryHackMe is

**TryHackMe** is a gamified, guided cybersecurity platform with browser-based attack and defence labs.

| Property | Detail |
|---|---|
| Focus | Broad security fundamentals + guided labs |
| Format | Rooms with tasks, questions, VMs |
| Strength | Structure, accessibility, breadth |
| Weakness | Guided answers reduce independent thinking |
| Cost | Free rooms + subscription |

> Verify current paths/pricing on the site.

---

## 2. Where it fits

| Roadmap section | THM use |
|---|---|
| 01 Networking | Networking rooms |
| 02 Operating Systems | Linux/Windows fundamentals |
| 03 Fundamentals | Security basics, attacks, malware |
| 04 Monitoring | SIEM/log rooms |
| 06 Threat Detection | Blue team rooms |
| 07 Investigation | Forensics rooms |
| 11 Career | Junior SOC readiness |

**Best for:** filling conceptual gaps fast and getting comfortable in terminals.

---

## 3. Setup

- Account + notes app (Markdown/Obsidian).
- Use the **AttackBox** or your own VM; snapshot before experiments.
- Keep a room log: date, room, time, new concept, questions missed.
- Do not run lab techniques outside the platform.

---

## 4. Paths that matter for SOC

| Path | Why |
|---|---|
| **Pre Security** | Networking/OS/security basics |
| **Complete Beginner** | Tooling + web basics |
| **SOC Level 1** | Core analyst skills |
| **Cyber Defence** | Blue-team depth |
| **Jr Penetration Tester** | Attacker perspective |

### 4.1 SOC Level 1 areas

| Area | Content |
|---|---|
| Blue team fundamentals | SOC roles, telemetry |
| SIEM | Splunk/Elastic basics |
| Network security | IDS, traffic |
| Endpoint | Windows/Linux logs |
| Phishing | Email analysis |
| Malware | Triage basics |
| Threat intel | IOC research |
| IR | Process basics |

**Do the path, but supplement with real artefacts.**

---

## 5. How to use a room properly

```
1. Skim the task list to know the destination
2. Attempt before reading the answer
3. When stuck, use hints only after 10 minutes
4. Reproduce every command yourself
5. Write the "why", not just the answer
6. Do the room again later without notes
```

### 5.1 Room notes template

```
Room / date / time
Objective
Key concepts (3–5 bullets)
Commands/tools used
What I got wrong
Real-world application
Follow-up reading
```

**A completed room with no notes is entertainment, not training.**

---

## 6. Blue-team-relevant room types

| Type | Skills |
|---|---|
| Log analysis | grep, Event Viewer, SIEM |
| Network traffic | Wireshark, protocols |
| Windows fundamentals | AD basics, event IDs |
| Linux fundamentals | auth logs, permissions |
| Malware intro | strings, hashes, sandbox |
| Phishing | header analysis |
| Forensics | disk/memory basics |
| Threat intel | OSINT, reputation |
| Detection | Sigma/YARA intro |

---

## 7. Attacker empathy

Defenders who understand attacks triage better.

| Attacker topic | Defensive value |
|---|---|
| Enumeration | Recognise scan patterns |
| Exploitation | Understand exploit telemetry |
| Privilege escalation | Spot unusual privilege changes |
| Lateral movement | Detect auth anomalies |
| Persistence | Know what to hunt |
| Exfiltration | Recognise volume/egress anomalies |

**Learn the attack, then ask: what log would I leave?**

### 7.1 Conversion exercise

For each attack technique learned:

1. What artefact does it create?
2. Which log source captures it?
3. What would the alert look like?
4. What would a false positive look like?

---

## 8. Pitfalls

| Pitfall | Consequence |
|---|---|
| Copy answers | No skill |
| Only guided rooms | Can't work independently |
| No notes | No retention |
| Avoid hard rooms | Plateau |
| Ignore fundamentals | Weak base |
| Only offensive rooms | No defensive depth |
| Never revisit | Forgetting |
| No real artefacts | Lab-only thinking |
| Skip reporting | Weak communication |

---

## 9. Portfolio

| Artefact | Value |
|---|---|
| Room notes (method) | Shows learning discipline |
| Converted detections | Shows application |
| Path completion | Shows commitment |
| Writeups (public-safe) | Shows communication |

**Do not publish paid room answers.**

---

## 10. Twelve-week plan

| Week | Focus |
|---|---|
| 1–2 | Pre Security / networking |
| 3–4 | Linux + Windows fundamentals |
| 5–6 | SOC Level 1: SIEM + logs |
| 7–8 | SOC Level 1: phishing + malware |
| 9–10 | Cyber Defence rooms |
| 11 | Attacker rooms + convert to detections |
| 12 | Redo 3 rooms blind + write 2 Sigma rules |

---

## 11. Real-world transfer

| THM habit | Real SOC |
|---|---|
| Guided tasks | Ambiguous problems |
| Clean VMs | Messy production |
| Answer validation | No answer key |
| Single technique | Chained incidents |

**Close the gap with incident reports, BOTS-style datasets, and tabletop exercises.**

---

## 12. Self-test

1. What is THM best at?
2. What is its main weakness?
3. Which path matters most for SOC?
4. How should you handle a stuck task?
5. Why take notes per room?
6. Why study attacks as a defender?
7. What four questions convert a technique to detection?
8. What should you not publish?
9. How do you avoid the guided-lab trap?
10. What complements THM?

---

## 13. Revision checklist

- [ ] Platform focus, strengths, weaknesses.
- [ ] Roadmap mapping.
- [ ] Setup + room log.
- [ ] Paths: Pre Security, SOC L1, Cyber Defence, Jr PenTest.
- [ ] SOC L1 areas.
- [ ] Room method (attempt → hints → reproduce → why → revisit).
- [ ] Notes template.
- [ ] Blue-team room types.
- [ ] Attacker empathy + conversion exercise.
- [ ] Pitfalls memorised.
- [ ] Portfolio ethics.
- [ ] 12-week plan.
