# CIA Triad — SOC Analyst Study Notes

> Goal: use Confidentiality, Integrity, and Availability as the **decision lens** for classifying incidents, judging impact, and choosing a response — not as a memorised definition.
> Risk framing builds on this; see `Vulnerabilities.md`, `Common-Attacks.md`, `Malware.md`.

---

## 0. How to use this note

1. §1–§2: why the triad exists and what each pillar actually means.
2. §3–§5: each pillar in depth (threats, controls, detection, response).
3. §6–§7: trade-offs and extensions (AAA, non-repudiation, privacy, safety).
4. §8–§12: incident classification, detection, investigation, triage.
5. §13–§16: severity, examples, labs, self-test, revision.

---

## 1. Why the CIA triad matters to a SOC analyst

- **It tells you what is actually damaged.** A stolen file (C), a tampered log (I), and a downed service (A) are different incidents with different owners, playbooks, and notifications.
- **It drives severity.** Ransomware hits availability; data theft hits confidentiality; fraud and tampering hit integrity. Impact wording in reports must name the pillar.
- **It explains attacker goals.** Almost every technique maps to one or more pillars: exfiltration (C), log tampering (I), DDoS/wiper (A).
- **It justifies controls.** Encryption (C), hashing/signing (I), backups/redundancy (A).
- **It prevents lazy analysis.** "The system was hacked" is not an impact statement; "confidentiality of 12k customer records was lost and integrity of billing data is unverified" is.

**SOC outcomes:** given an alert you can answer:
- Which pillar(s) are at risk?
- Is the risk realised or potential?
- What evidence proves it?
- Who owns the consequence (legal, privacy, finance, operations)?
- What response restores which pillar?

---

## 2. The three pillars

| Pillar | Question | Examples of failure |
|---|---|---|
| **Confidentiality** | Who is allowed to know/see this? | Data breach, credential theft, insider exfiltration, misconfigured bucket. |
| **Integrity** | Is the data/system exactly as authorised? | Tampering, fraud, log manipulation, unauthorized code change, corrupted backups. |
| **Availability** | Is it accessible when needed? | DDoS, ransomware, wiper, outage, resource exhaustion. |

**Memory aid:** **C** — secrets stay secret. **I** — data is trustworthy and unaltered. **A** — service is there when needed.

> The triad is a **model**, not a law. Real incidents usually hit two or three pillars at once (ransomware = A + C exfil + I log deletion).

---

## 3. Confidentiality

### 3.1 Definition and scope

Confidentiality is the property that information is **not disclosed to unauthorised principals**. It covers data at rest, in transit, and in use — including metadata (who talked to whom, when).

### 3.2 Threat actors and causes

- External attackers (credential theft, exploitation, social engineering).
- Malicious insiders (data hoarding, exfiltration before resignation).
- Accidental insiders (mis-sent email, misconfigured share, public bucket).
- Third parties/supply chain (vendor compromise, over-permissioned integrations).
- System flaws (verbose errors, unencrypted backups, exposed APIs).

### 3.3 Controls

| Layer | Controls |
|---|---|
| **Data classification** | Public/internal/confidential/restricted; handling rules. |
| **Access control** | Least privilege, RBAC/ABAC, need-to-know, MFA. |
| **Encryption** | At rest (BitLocker/LUKS, KMS, TDE, DB encryption), in transit (TLS), in use (confidential compute where relevant). |
| **Data loss prevention** | DLP, egress filtering, CASB, email DLP. |
| **Segmentation** | Network zones, microsegmentation, zero trust. |
| **Secrets management** | Vault, KMS, no hardcoded keys, rotation. |
| **Monitoring** | Access logs, DLP alerts, UEBA, cloud audit, SIEM correlation. |
| **Decommissioning** | Secure wipe, crypto-shredding. |

### 3.4 Detection signals

- Bulk file access/download (SMB, SharePoint, cloud storage).
- Access from unusual location/device/time.
- Large outbound transfers, unusual DNS, cloud storage uploads.
- Email forwarding rules, mailbox delegation, mass mail.
- DLP hits, print volume spikes, USB writes.
- Public bucket/ACL changes, sharing-link creation.
- Credential dumping, session token theft, MFA bypass.
- Access to data outside the user's role.

### 3.5 Response priorities

1. Stop the disclosure (revoke session/token, disable account, block egress).
2. Identify **what** data, **how much**, **whose**, and **where it went**.
3. Preserve evidence (logs, egress captures).
4. Engage privacy/legal — breach notification clocks may start.
5. Rotate exposed secrets/credentials.
6. Remediate the root cause (permissions, misconfig, malware).

### 3.6 Measuring

- Sensitive data accessed outside baseline.
- Time to revoke access.
- Number of public/over-permissioned resources.
- DLP prevented vs allowed.

---

## 4. Integrity

### 4.1 Definition and scope

Integrity is the property that data, code, and configuration are **accurate, complete, and only changed by authorised principals in authorised ways**. It includes authenticity (who made the change) and non-repudiation (cannot deny it).

### 4.2 Threat actors and causes

- Tampering with records (fraud, insider).
- Malware modifying files/binaries (backdoors, ransomware encryption is also integrity loss).
- Log manipulation to hide activity (1102, timestomping).
- Supply-chain compromise (malicious dependency/update).
- Configuration drift and accidental changes.

### 4.3 Controls

| Layer | Controls |
|---|---|
| **Hashing/signing** | SHA-256, code signing, package signatures, SBOM. |
| **Change management** | Approval, version control, IaC, drift detection. |
| **File integrity monitoring** | Tripwire/OSSEC/Wazuh, Sysmon file/registry events, cloud config. |
| **Access control** | Restrict write/ACL changes, least privilege, MFA. |
| **Audit trails** | Append-only/WORM logs, SIEM forwarding, log integrity. |
| **Backups** | Immutable/offline copies, verified restores. |
| **Validation** | Input validation, transactions, checksums, database constraints. |

### 4.4 Detection signals

- File hash changes on system binaries, web content, or configs.
- Unauthorised registry/service/task changes.
- Log clearing (1102/104), gaps, or clock changes.
- Timestomping (Sysmon 2).
- Unexpected code deployment or container image change.
- Database record anomalies, financial reconciliation breaks.
- Signature failures, unsigned modules, hash mismatch.
- Configuration drift from baseline.

### 4.5 Response priorities

1. Determine **what changed**, by whom, and whether it is authorised.
2. Restore known-good state from verified source.
3. Invalidate malicious changes (persistence, accounts, keys).
4. Assess downstream impact (decisions/data derived from tampered records).
5. Preserve original evidence before restoring.
6. Strengthen change controls and FIM.

### 4.6 Measuring

- % of critical files under FIM.
- Mean time to detect drift.
- Number of unauthorised changes.
- Restore verification success rate.

---

## 5. Availability

### 5.1 Definition and scope

Availability is the property that systems and data are **accessible to authorised users when required**, at the agreed performance level.

### 5.2 Threat actors and causes

- DDoS (volumetric, protocol, application-layer).
- Ransomware (encryption), wipers (destruction).
- Resource exhaustion (cryptomining, runaway jobs, disk fill).
- Insider sabotage, accidental deletion.
- Supply-chain/outage (cloud provider, DNS, CDN, certificate expiry).
- Hardware failure, misconfiguration, capacity shortfall.

### 5.3 Controls

| Layer | Controls |
|---|---|
| **Redundancy** | HA clusters, load balancing, multi-AZ/region, redundant links. |
| **Backups** | 3-2-1, offline/immutable, tested restores, air gaps. |
| **DDoS protection** | CDN/WAF/scrubbing, rate limiting, anycast. |
| **Capacity management** | Monitoring, autoscaling, quotas. |
| **Change control** | Prevent self-inflicted outages. |
| **DR** | RTO/RPO defined, DR drills, runbooks. |
| **Resilience engineering** | Graceful degradation, circuit breakers, timeouts. |

### 5.4 Detection signals

- Availability/uptime and latency SLO breaches.
- Traffic spikes, SYN floods, request floods, amplification.
- CPU/memory/disk saturation; disk filling rapidly.
- Mass file encryption/renames, ransom notes, shadow copy deletion.
- Backup deletion/tampering, replication failure.
- Service crashes, restart loops, error-rate spikes.
- DNS/certificate failures.

### 5.5 Response priorities

1. Restore service (failover, scaling, filtering, isolation of affected segment).
2. Protect backups and evidence.
3. Identify cause (attack vs failure) before broad remediation.
4. Communicate status and ETA to stakeholders.
5. Recover from verified clean state; validate integrity after restore.
6. Harden the vector (patch, rate limit, segmentation).

### 5.6 Measuring

- Uptime/SLO compliance.
- RTO/RPO achieved in drills.
- Restore test pass rate.
- Time to mitigate DDoS/outage.

---

## 6. Trade-offs and tensions

| Tension | Example | Balance |
|---|---|---|
| **C vs A** | Aggressive encryption/MFA vs friction and uptime. | Risk-based, tiered controls. |
| **I vs A** | Strict change control slows recovery. | Pre-approved emergency change path. |
| **C vs usability** | DLP blocking legitimate sharing. | Tune, educate, exception process. |
| **A vs cost** | Full redundancy is expensive. | Tier by criticality (RTO/RPO). |
| **Security vs privacy** | Monitoring employees. | Policy, proportionality, legal review. |

> A SOC analyst should be able to say **which pillar the business is optimising for** in a given decision, and flag when a control protects one pillar at unacceptable cost to another.

---

## 7. Extensions of the model

| Model | Adds |
|---|---|
| **AAA** | Authentication, Authorisation, Accounting (who, what allowed, record). |
| **Parkerian hexad** | Confidentiality, possession, integrity, authenticity, availability, utility. |
| **Non-repudiation** | Proof of origin/integrity (signatures, audit). |
| **Privacy** | Lawful/limited processing of personal data (GDPR, etc.). |
| **Safety** | Physical/operational harm (OT/ICS). |
| **DAD triad** | Disclosure, Alteration, Destruction/Denial — the attacker's mirror. |

**DAD** is useful in reports: attackers seek **Disclosure** (C), **Alteration** (I), **Destruction/Denial** (A).

---

## 8. Classifying incidents by pillar

| Incident | Primary | Secondary | Notes |
|---|---|---|---|
| Phishing email (blocked) | — | — | No impact; attempted C/I. |
| Credential theft | C | I/A | Enables further access. |
| Data exfiltration | C | I | Privacy/regulatory. |
| Ransomware | A | C (exfil), I (tamper) | Double extortion. |
| Wiper | A | I | Destructive. |
| Web defacement | I | A/C | Reputation. |
| DDoS | A | — | Often smoke screen. |
| Insider fraud | I | C | Financial. |
| Log tampering | I | C/A | Defense evasion. |
| Misconfigured bucket | C | — | Exposure duration matters. |
| Supply-chain compromise | I | C/A | Broad blast radius. |
| Certificate expiry | A | C | Trust failure. |

**Rule:** name the pillar, then the **asset**, then the **magnitude** ("confidentiality of 12k PII records", "availability of payment API for 47 minutes").

---

## 9. Detection engineering with CIA in mind

### 9.1 Map detections to pillars

| Detection | Pillar protected |
|---|---|
| Bulk download / egress anomaly | C |
| DLP / public bucket / sharing changes | C |
| FIM, hash change, registry/service change | I |
| Log clear, audit policy change, timestomping | I |
| Backup deletion, shadow copy deletion | A/I |
| DDoS/rate thresholds, saturation | A |
| Ransomware file patterns | A/I |
| Credential dumping | C/I/A |
| MFA bypass / impossible travel | C |
| Change approval mismatch | I |

### 9.2 Splunk examples

**Bulk data access (C):**
```spl
index=wineventlog EventCode=5145
| stats count dc(RelativeTargetName) as files by SubjectUserName, ShareName, src_ip
| where files > 200
```

**Integrity change on web content (I):**
```spl
index=fim path="/var/www/*"
| where action IN ("modified","created","deleted")
| stats count values(action) by path, host
```

**Log clear (I):**
```spl
index=wineventlog EventCode IN (1102,104)
| table _time, ComputerName, SubjectUserName, _raw
```

**Availability anomaly (A):**
```spl
index=web status>=500
| timechart span=5m count as errors
| where errors > 100
```

**Ransomware precursor (A/I):**
```spl
index=wineventlog EventCode=4688
| where match(lower(CommandLine), "(vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled.*no)")
```

**Public bucket (C):**
```spl
index=aws eventName IN ("PutBucketAcl","PutPublicAccessBlock","DeletePublicAccessBlock")
| table _time, userIdentity.arn, eventName, requestParameters
```

### 9.3 KQL examples

**Sensitive file mass access:**
```kusto
DeviceFileEvents
| where ActionType == "FileAccessed"
| summarize Files = dcount(FileName) by DeviceName, AccountName, bin(TimeGenerated, 10m)
| where Files > 100
```

**Log clear / audit tamper:**
```kusto
SecurityEvent
| where EventID in (1102, 4719)
| project TimeGenerated, Computer, Account, Activity
```

**Backup/shadow deletion:**
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin","wbadmin","bcdedit")
| where ProcessCommandLine has_any ("delete","shadows","recoveryenabled")
```

**Service availability drop:**
```kusto
AppRequests
| summarize Failed = countif(Success == false), Total = count() by bin(TimeGenerated, 5m), Name
| extend ErrorRate = Failed * 100.0 / Total
| where ErrorRate > 20
```

---

## 10. Investigation workflow with CIA

### Step 1 — Identify the pillar at risk
What is the alert actually about: disclosure, alteration, or denial?

### Step 2 — Identify the asset and classification
Data type, owner, criticality, regulatory scope, RTO/RPO.

### Step 3 — Determine realisation
Attempted vs successful. Evidence of actual disclosure/alteration/outage.

### Step 4 — Quantify
Records, users, duration, financial/operational/reputational impact.

### Step 5 — Determine root cause
Control failure: access, encryption, integrity check, redundancy, monitoring.

### Step 6 — Scope
Other assets/data with the same exposure.

### Step 7 — Respond per pillar
- C: revoke, rotate, notify, contain exfil.
- I: restore, verify, invalidate tampering.
- A: failover, filter, recover, validate.

### Step 8 — Document with pillar-explicit impact.

---

## 11. Triage playbooks (pillar-first)

### A. "Possible data exfiltration" (C)
1. What data, how much, to where?
2. Authorised transfer (backup, sync, vendor)?
3. Block destination, revoke tokens, preserve logs.
4. Privacy/legal assessment if PII/PHI.

### B. "File integrity alert" (I)
1. What changed, hash, who, when?
2. Approved change/deployment?
3. Restore, investigate access path, check persistence.

### C. "Service down / DDoS" (A)
1. Scope: single service or many? Internal or external cause?
2. Mitigate (filter, scale, failover).
3. Preserve evidence; check for distraction activity elsewhere.

### D. "Ransomware" (A + C + I)
1. Contain spread, protect backups.
2. Determine exfil (double extortion).
3. Recover from clean, verified backups.
4. Notify per policy/regulatory.

### E. "Log cleared" (I)
1. Who cleared, from where?
2. What is missing; use forwarded copies.
3. Treat as compromise indicator, escalate.

### F. "Public bucket" (C)
1. Was it public? For how long? Access logs?
2. What data? External access evidence?
3. Restrict, notify, assess notification duty.

### Severity by pillar

| Situation | Severity |
|---|---|
| Attempted, blocked | Low |
| Limited C exposure (internal, non-sensitive) | Medium |
| Confirmed sensitive C breach | High–Critical |
| I tampering of security controls/logs | High |
| I tampering of financial/medical records | Critical |
| A outage < RTO, no data loss | Medium–High |
| A outage > RTO / destructive | Critical |

---

## 12. Reporting impact with CIA

**Weak:** "The server was compromised."

**Strong:** "Confidentiality: attacker accessed 4,312 customer records (name, email, hashed password) between 02:10–02:55 UTC. Integrity: two admin accounts and one scheduled task were created; audit log was cleared at 02:57, so completeness is unverified. Availability: no outage observed; RTO unaffected."

Template:
```
Confidentiality: [data/scope/exposure window/evidence]
Integrity:       [what changed/verified or unverified/source of truth]
Availability:    [downtime/SLO impact/recovery state]
```

---

## 13. Commands and artifacts useful for CIA assessment

```bash
# Confidentiality
find / -type f -perm -o=r 2>/dev/null            # world-readable
aws s3api get-bucket-acl --bucket BUCKET
aws s3api get-public-access-block --bucket BUCKET

# Integrity
sha256sum -c manifest.sha256
aide --check
rpm -Va; debsums -c
Get-FileHash file -Algorithm SHA256
sigcheck -h -a file.exe

# Availability
uptime; df -h; free -m
systemctl --failed
curl -o /dev/null -s -w '%{http_code} %{time_total}\n' https://service/health
vssadmin list shadows
```

Log/artifact sources: access logs, DLP, proxy, cloud audit, FIM, backup logs, uptime monitoring, SIEM.

---

## 14. Labs

1. Classify 10 incidents by pillar and justify.
2. Simulate a public S3 bucket; detect and quantify exposure.
3. Tamper with a web file; detect via FIM; restore and verify.
4. Run a local DDoS (lab) and measure availability impact.
5. Delete shadow copies in a lab; detect and map to A/I.
6. Clear a log; reconstruct the gap from forwarded logs.
7. Write an impact statement for each scenario in the CIA template.

---

## 15. Self-test questions

1. Define confidentiality, integrity, and availability in one sentence each.
2. What is the DAD triad, and why is it useful in reports?
3. Give two controls for each pillar.
4. Why is ransomware a multi-pillar incident?
5. What is the difference between an attempted and a realised C impact?
6. Why does log clearing affect integrity, not just confidentiality?
7. What is non-repudiation, and which control supports it?
8. How does data classification drive controls?
9. Which pillar do backups primarily support?
10. What is the trade-off between integrity and availability during recovery?
11. How would you quantify a confidentiality breach?
12. What evidence proves an availability outage?
13. Why can a DDoS be a diversion?
14. Which pillar does a web defacement primarily affect?
15. How do you write a three-pillar impact statement?

---

## 16. One-page revision checklist

- [ ] CIA: C = no unauthorised disclosure; I = accurate/complete/authorised change; A = accessible when needed.
- [ ] DAD: disclosure, alteration, destruction/denial.
- [ ] Confidentiality: classification, least privilege, encryption (rest/transit/use), DLP, segmentation, secrets, monitoring, secure disposal.
- [ ] Confidentiality detections: bulk access, unusual location/time, egress, forwarding rules, DLP, public buckets, credential theft, out-of-role access.
- [ ] Integrity: hashing/signing, change management, FIM, ACLs, audit trails, immutable backups, validation.
- [ ] Integrity detections: hash changes, unauthorised registry/service/task, log clear/gaps, timestomping, drift, signature failures.
- [ ] Availability: redundancy, backups, DDoS protection, capacity, change control, DR/RTO/RPO, resilience.
- [ ] Availability detections: SLO breach, floods, saturation, encryption/wiper, backup tampering, crash loops, DNS/cert failures.
- [ ] Trade-offs: C vs A, I vs A, C vs usability, A vs cost, security vs privacy.
- [ ] Extensions: AAA, Parkerian hexad, non-repudiation, privacy, safety.
- [ ] Classification: incident → pillar(s) → asset → magnitude.
- [ ] Detections mapped to pillars; SPL/KQL examples.
- [ ] Investigation: pillar → asset/classification → realised? → quantify → root cause → scope → respond → document.
- [ ] Triage: exfiltration, FIM, outage/DDoS, ransomware, log clear, public bucket; severity by pillar.
- [ ] Reporting: explicit C/I/A impact statement, not "was hacked".
