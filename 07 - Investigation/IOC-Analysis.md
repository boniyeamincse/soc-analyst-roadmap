# IOC Analysis — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Alert Triage](Alert-Triage.md) · [Log Analysis →](Log-Analysis.md)

> Goal: consume indicators correctly — know what an IOC proves, how long it lives, and when matching one means nothing.
> Threat-intel programme/actors/feeds → [Threat-Intelligence.md](Threat-Intelligence.md); hunting method → §11 here.

---

## 0. How to use this note

1. §1–§3: what IOCs are; IOC vs IOA; the Pyramid of Pain.
2. §4–§7: types, sources, formats/standards, quality & confidence.
3. §8–§12: operational use — enrichment, matching, pivoting, hunting, decay.
4. §13–§16: false positives, safe handling, tooling, workflow.
5. §17–§19: pitfalls, labs.
6. §20–§21: self-test, revision.

---

## 1. What an IOC is

> **Indicator of Compromise (IOC)** = an observable artefact that *may* indicate compromise, derived from past incidents or research.

Key word: **may**. An IOC is a hypothesis-generating artefact, not proof.

| IOC proves | IOC does not prove |
|---|---|
| This exact artefact was seen in a known incident | This host is compromised |
| Something matching was present | Intent, actor, or scope |
| A lead worth pivoting on | That the lead is current |

---

## 2. IOC vs IOA

| | **IOC** | **IOA** |
|---|---|---|
| **Stands for** | Indicator of Compromise | Indicator of Attack |
| **Nature** | Artefact (hash, IP, domain) | Behaviour (sequence, intent) |
| **Lifespan** | Short — attacker rotates | Long — TTPs persist |
| **Detects** | Known campaigns | Novel variants of known behaviour |
| **Example** | `d41d8cd9...`, `evil.example` | Office → PowerShell → outbound TLS |
| **Failure mode** | Trivial to evade | Environment-dependent noise |

**Mature detection is IOA-heavy, IOC-informed.**

---

## 3. Pyramid of Pain

| Level | Indicator | Attacker cost to change | Analyst value |
|---|---|---|---|
| 6 | **TTPs** | High | Highest |
| 5 | **Tools** | Medium-high | High |
| 4 | **Network/host artefacts** | Medium | Medium |
| 3 | **Domain names** | Low-medium | Medium |
| 2 | **IP addresses** | Low | Low |
| 1 | **Hash values** | Trivial | Lowest |

### 3.1 Practical reading

- A hash match is **strong but narrow** — one file, easily recompiled.
- An IP match is **weak** — shared hosting, CDNs, cloud, NAT.
- A behaviour match is **strong and broad** — but needs baselining.

### 3.2 The "pain" implication

Detections built at the bottom of the pyramid are cheap for the attacker to defeat. Invest detection engineering effort higher up; use low-level IOCs for **retro-hunting and scoping**, not as the primary defence.

---

## 4. IOC types

### 4.1 Network

| Type | Example | Notes |
|---|---|---|
| IPv4/IPv6 | `203.0.113.45` | Weakest; shared infrastructure. |
| Domain | `login-secure.example` | Cheap to rotate; DGA/typosquats. |
| URL | `https://x.example/a.php?id=` | Path-specific; often short-lived. |
| URI pattern | `/gate.php?` | Behavioural-ish. |
| JA3/JA4 | TLS fingerprint | Client stack; can be shared. |
| Certificate | Serial/SHA1/issuer | Infrastructure, not victim. |
| ASN | AS64500 | Too broad for alerting. |
| User-Agent | `curl/7.68` | Weak alone. |
| DNS pattern | long random labels | Tunnelling indicator. |

### 4.2 Host

| Type | Example | Notes |
|---|---|---|
| MD5/SHA1/SHA256 | file hash | SHA256 preferred. |
| Import hash (imphash) | `f34d5f...` | Groups malware families. |
| Fuzzy hash (ssdeep/TLSH) | similarity | Variant clustering. |
| Filename/path | `%TEMP%\svch0st.exe` | Weak; masquerading context. |
| Registry key | `Run\Updater` | Persistence locus. |
| Service name | `WinDefendSvc` | Masquerading. |
| Mutex | `Global\XYZ` | Family-specific, strong. |
| Scheduled task | `\Microsoft\Updater` | Persistence. |
| Named pipe | `\\.\pipe\xyz` | Lateral/C2 tooling. |
| Process lineage | `winword.exe → powershell.exe` | Behavioural. |
| Command line | `-enc <base64>` | Behavioural. |

### 4.3 Identity / cloud

| Type | Example |
|---|---|
| Account UPN | `svc-backup@corp` |
| Access key ID | `AKIA...` |
| App/client ID | Entra app GUID |
| OAuth scope set | `mail.read offline_access` |
| User agent string | cloud CLI/SDK |
| Session/token anomaly | new device + no MFA |

### 4.4 Email

| Type | Example |
|---|---|
| Sender address/domain | `billing@examp1e.com` |
| Reply-to mismatch | display vs actual |
| Message-ID pattern | campaign clustering |
| Attachment hash | same as host |
| URL in body | same as network |

---

## 5. Sources

| Source | Typical quality | Use |
|---|---|---|
| **Own incidents** | Highest | Retro-hunt, blocking. |
| **IR/forensic reports** | High | Scoping. |
| **Commercial TI feeds** | Variable | Enrichment, blocking with care. |
| **OSINT / community** | Low-medium | Leads only. |
| **Vendor AV/EDR** | Medium | Detection, not truth. |
| **Sandbox output** | Medium-high | Campaign artefacts. |
| **ISACs / sector sharing** | High | Peer incidents. |
| **Dark web / paste** | Low | Early warning. |

**Rule:** trust is earned per source, tracked by measured precision.

---

## 6. Formats and standards

| Format | Purpose |
|---|---|
| **STIX 2.x** | Structured threat intel objects + relationships. |
| **TAXII 2.x** | Transport for STIX over HTTPS. |
| **MISP** | Sharing platform; attributes + events. |
| **OpenIOC** | Legacy XML indicator format. |
| **YARA** | File/memory pattern matching. |
| **Sigma** | Vendor-neutral log detection rules. |
| **CSV/JSON** | Ad-hoc ingestion; needs schema discipline. |

### 6.1 Minimal internal schema

```json
{
  "type": "domain",
  "value": "evil.example",
  "confidence": 80,
  "source": "ir-case-2026-014",
  "first_seen": "2026-03-01T10:00:00Z",
  "last_seen": "2026-04-02T08:00:00Z",
  "ttl_days": 90,
  "tags": ["c2", "ransomware"],
  "context": "beacon destination, 60s jitter",
  "related": ["sha256:ab12..."],
  "false_positive_notes": "also used by update service in 2025"
}
```

**Without context, an indicator is just a string.**

---

## 7. Quality and confidence

### 7.1 Scoring inputs

| Input | Effect |
|---|---|
| Source reliability | Up/down |
| Corroboration | Up |
| Recency | Up if fresh, down if stale |
| Specificity | Up for mutexes/imphashes, down for IPs |
| Prevalence in your estate | Down if common |
| Sinkhole/parking | Down |
| Shared hosting/CDN | Down |
| Prior FP history | Down |

### 7.2 Confidence vs action

| Confidence | Action |
|---|---|
| 90–100 | Block + hunt + retro-scan |
| 70–89 | Alert + hunt |
| 40–69 | Enrich only |
| <40 | Store for correlation |

**Never block on low confidence at scale.**

### 7.3 The "one strike" rule

A single weak indicator should never justify containment. Combine indicators, or require corroboration from an independent source.

---

## 8. Operational use in triage

### 8.1 Match → context → verdict

```
IOC match
  → what type? (strong/weak)
  → how confident?
  → what entity matched?
  → is that entity expected to touch this?
  → corroborating evidence?
  → verdict
```

### 8.2 Match interpretation

| Match | Interpretation |
|---|---|
| File hash on disk | File present — was it executed? |
| Domain in DNS log | Resolution — by which process? |
| IP in firewall | Connection attempt — allowed or blocked? |
| URL in proxy | Request — response received? |
| Mutex in memory | Process running now. |

**Presence ≠ execution ≠ compromise.** Each is a distinct question.

### 8.3 Enrichment questions

- Who owns this IP/ASN/domain?
- First/last seen globally and internally?
- What else in the estate touched it?
- Is it sinkholed/parked/cloud-hosted?
- Does it appear in benign software?

---

## 9. Pivoting

| Pivot from | To |
|---|---|
| Hash | Other hosts with hash, parent process, signer, imphash |
| Domain | DNS clients, resolved IPs, cert, WHOIS, passive DNS |
| IP | All connections, ASN, other domains on IP, geo |
| Process | Lineage, command line, network, file writes |
| Mutex | Processes holding it, other hosts |
| User | Sign-ins, MFA, mail rules, OAuth, endpoint logons |
| Email | All recipients, clicks, attachments, sender infra |

**Each pivot should narrow scope or raise confidence — otherwise it is noise.**

---

## 10. Retro-hunting with IOCs

The highest-value use of IOCs:

```
New IOC → query 30–90 days of historical telemetry
→ find prior contact → scope the incident
```

### 10.1 Retro-hunt checklist

- [ ] DNS/proxy/firewall logs
- [ ] EDR network events
- [ ] File hash inventory
- [ ] Email gateway logs
- [ ] Cloud audit logs
- [ ] Auth logs (if identity IOC)
- [ ] Backup/archive indexes

### 10.2 Outcome

- No hits → indicator may be irrelevant or telemetry gap.
- Hits before first alert → **earlier compromise** (re-scope).
- Hits on unexpected hosts → lateral spread.

---

## 11. IOC-driven hunting

### 11.1 From indicator to behaviour

```
IOC: domain evil.example
→ What process resolved it?
→ What else did that process do?
→ What wrote that process to disk?
→ What persistence did it create?
→ Behavioural rule candidate
```

**Hunt the behaviour the IOC revealed, not the string forever.**

### 11.2 Clustering

Group IOCs by campaign using:

- Shared infrastructure (cert, ASN, registrar).
- Shared code (imphash, signer, strings).
- Shared timing (registration burst).
- Shared TTPs.

Clusters support **family-level** detection rather than single-string blocking.

---

## 12. Aging and decay

### 12.1 Why indicators expire

- Attackers rotate infrastructure.
- Domains get re-registered by others.
- IPs get reassigned (cloud, hosting).
- Hashes become irrelevant after recompilation.

### 12.2 Suggested TTLs

| Type | TTL |
|---|---|
| IP | 30 days |
| Domain | 90 days |
| URL | 30 days |
| File hash | 1–2 years (still verify) |
| Mutex | Long |
| TTP/Sigma | Until environment changes |
| YARA | Review quarterly |

### 12.3 Decay model

```
effective_confidence = base_confidence × 0.5^(age_days / half_life)
```

| Type | Half-life |
|---|---|
| IP | 15 days |
| Domain | 45 days |
| Hash | 365 days |

**Refresh on re-observation** (`last_seen` extends life).

---

## 13. False positives

### 13.1 Common causes

| Cause | Example |
|---|---|
| Shared hosting | Thousands of sites on one IP. |
| CDN/cloud | Legit traffic to cloud ranges. |
| Sinkhole | Domain resolves to researcher IP. |
| Parking page | Re-registered expired domain. |
| Security scanner | Your own scanner in TI feeds. |
| Common file hash | Installer with same hash. |
| Benign tooling | `curl`, `rclone`, `psexec`. |
| Old report | Indicator from a 2019 campaign. |

### 13.2 Handling

- Check prevalence in your estate before alerting.
- Verify ownership/ASN.
- Check passive DNS history.
- Look for the *process* using the indicator, not just the indicator.
- Record FP notes on the IOC.

---

## 14. Safe handling

| Rule | Why |
|---|---|
| Never execute samples outside a sandbox | Obvious. |
| Defang indicators in docs | `hxxp://evil[.]example` |
| Do not paste live credentials | Leakage. |
| Treat shared IOCs as untrusted | Poisoning/error. |
| Verify before blocking at scale | Outage risk. |
| Respect licensing/TLP | Legal. |
| Keep TLP markings in tickets | Sharing control. |

### 14.1 TLP quick reference

| Marking | Sharing |
|---|---|
| TLP:RED | Named recipients only. |
| TLP:AMBER | Organisation + need-to-know. |
| TLP:GREEN | Community. |
| TLP:CLEAR | Public. |

---

## 15. Tooling

| Tool | Use |
|---|---|
| **MISP** | Store/share indicators with context. |
| **OpenCTI** | Graph-based intel platform. |
| **VirusTotal** | Multi-engine + relations. |
| **AbuseIPDB / GreyNoise** | IP reputation, scanning noise. |
| **Shodan / Censys** | Infrastructure context. |
| **Passive DNS** (SecurityTrails, VT) | Domain history. |
| **urlscan.io** | URL/site behaviour. |
| **Any.run / Joe Sandbox** | Dynamic analysis. |
| **YARA** | Pattern matching at scale. |
| **Sigma** | Behavioural rule portability. |
| **TheHive/Cortex** | Case + analyser orchestration. |

**Tools give data; analysts give judgement.**

---

## 16. Workflow

```
Receive indicator
 → normalise (type, defang, dedupe)
 → validate (syntax, existence, ownership)
 → score (source, recency, specificity)
 → store (with context + TTL)
 → deploy (enrich/alert/block per confidence)
 → retro-hunt
 → measure (hits, TP rate)
 → decay/expire
 → feedback to source quality
```

---

## 17. Pitfalls

| Pitfall | Consequence |
|---|---|
| Blocking every feed indicator | Outages. |
| Treating IP matches as proof | False incidents. |
| Never expiring indicators | Permanent noise. |
| No context on indicators | Useless at 3 a.m. |
| Ignoring internal prevalence | FP flood. |
| Hunting only hashes | Miss variants. |
| No retro-hunt | Miss earlier compromise. |
| Blind trust in feeds | Poisoning/manipulation. |
| Not recording FP notes | Repeat mistakes. |
| Confusing presence with execution | Wrong verdict. |

---

## 18. Labs

1. Take 10 indicators from a public report; classify by pyramid level.
2. Build a MISP event with context and TTL.
3. Write a STIX bundle for a domain + hash + relationship.
4. Retro-hunt one domain in a sample dataset.
5. Enrich an IP with ASN, passive DNS, reputation; write a verdict.
6. Create a YARA rule for a hash's family strings.
7. Convert a behaviour observed from an IOC into a Sigma rule.
8. Build an IOC aging table with decay.
9. Defang and document 10 indicators correctly.
10. Measure FP rate of a feed over 2 weeks.

---

## 19. Metrics

| Metric | Meaning |
|---|---|
| IOC hit rate | Alerts per 1,000 indicators. |
| IOC precision | TP / hits. |
| Feed precision | Per-source quality. |
| Mean indicator age at hit | Staleness. |
| Retro-hunt yield | Prior compromise found. |
| Expired on schedule | Hygiene. |

---

## 20. Self-test questions

1. Define IOC and explain why it is not proof.
2. IOC vs IOA — which lasts longer and why?
3. Recite the Pyramid of Pain.
4. Why are IP indicators weak?
5. What is imphash for?
6. Name five host indicators.
7. What is the minimum context an indicator needs?
8. How does confidence change action?
9. What does "presence ≠ execution" mean?
10. What is retro-hunting?
11. Give three reasons indicators expire.
12. What is a half-life in this context?
13. Name four IOC false-positive causes.
14. What is TLP and why does it matter?
15. What should you do after a successful IOC match?

---

## 21. One-page revision checklist

- [ ] IOC = possible artefact; IOA = behaviour; IOC ≠ proof.
- [ ] Pyramid: TTP > tools > artefacts > domains > IPs > hashes.
- [ ] Types: network, host, identity/cloud, email — with strength notes.
- [ ] Sources ranked by trust; measure per-source precision.
- [ ] Formats: STIX/TAXII, MISP, YARA, Sigma, OpenIOC.
- [ ] Minimum schema: type, value, confidence, source, first/last seen, TTL, tags, context, FP notes.
- [ ] Confidence bands → enrich/alert/block.
- [ ] Triage: match → context → verdict; presence/execution/compromise distinction.
- [ ] Pivots table.
- [ ] Retro-hunt checklist and interpretation.
- [ ] IOC → behaviour → clustering → family detection.
- [ ] TTL table + decay formula.
- [ ] FP causes and handling.
- [ ] Safe handling + TLP.
- [ ] Tooling list.
- [ ] Workflow 8 steps.
- [ ] Pitfalls memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Alert Triage](Alert-Triage.md) · [Log Analysis →](Log-Analysis.md)
