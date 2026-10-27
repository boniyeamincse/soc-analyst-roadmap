# Recovery — Incident Response Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Lessons Learned](Lessons-Learned.md) · [APIs →](../09%20-%20Automation/APIs.md)

> Goal: bring services back to a **known-good, monitored** state — without re-importing the compromise.
> Removal → [Eradication.md](Eradication.md); post-incident learning → [Lessons-Learned.md](Lessons-Learned.md).

---

## 0. How to use this note

1. §1–§3: recovery goals; RTO/RPO; restoration priorities.
2. §4–§7: backups; restore types; validation; clean rebuild.
3. §8–§11: phased restoration, dependencies, verification, monitoring.
4. §12–§15: communications, closure criteria, hypercare, pitfalls.
5. §16–§18: playbooks, labs.
6. §19–§20: self-test, revision.

---

## 1. What recovery means

> **Recovery** = restoring affected services and data to normal operation with confidence that the attacker's foothold is gone.

Three conditions:

1. **Eradicated** — cause removed.
2. **Clean** — restored state free of malware/backdoors.
3. **Verified** — tested by the business, not just IT.

**Fast but compromised recovery is not recovery.**

---

## 2. RTO and RPO

| Term | Meaning | Example |
|---|---|---|
| **RTO** | Maximum tolerable downtime | 4 hours |
| **RPO** | Maximum tolerable data loss | 1 hour |
| **MTD** | Maximum tolerable downtime before business failure | 24 hours |
| **WRT** | Work recovery time (validation after restore) | 2 hours |

### 2.1 Real recovery time

```
actual recovery = restore time + validation time + business verification
```

**Test restores measure the first two; only the business can confirm the third.**

---

## 3. Restoration priorities

### 3.1 Tiering

| Tier | Systems | Priority |
|---|---|---|
| 0 | Identity, DNS, PKI, network | First |
| 1 | Business-critical apps | Second |
| 2 | Supporting services | Third |
| 3 | Non-critical | Last |

### 3.2 Dependency mapping

Restore in dependency order — a database before the app, DNS before almost everything, IdP before SSO apps.

**Restoring an app before its identity dependency wastes the window.**

---

## 4. Backups

### 4.1 Strategy

| Principle | Meaning |
|---|---|
| **3-2-1** | 3 copies, 2 media, 1 offsite |
| **3-2-1-1-0** | + 1 offline/immutable, 0 errors |
| **Immutable** | Cannot be altered/deleted during retention |
| **Air-gapped** | Physically isolated |
| **Encrypted** | At rest and in transit |
| **Tested** | Restore drills |

### 4.2 Backup-specific attack risks

| Risk | Control |
|---|---|
| Backup deletion by attacker | Immutability, separate credentials |
| Backup encryption by ransomware | Offline copies |
| Compromised backup server | Isolated network, separate admin |
| Poisoned backups (malware present) | Scan before restore |
| Stale backups | Monitoring + alerts |
| Credential reuse into backups | Dedicated accounts |

### 4.3 Verify before you need them

- Restore a random file monthly.
- Full restore quarterly.
- Measure actual RTO.
- Confirm immutable retention.

**An untested backup is a hope.**

---

## 5. Restore options

| Option | Best for | Risk |
|---|---|---|
| **Restore from backup** | Data, clean systems | Backup may contain malware or be stale |
| **Rebuild from image** | Standard endpoints | Image may be outdated |
| **Rebuild from scratch** | Servers, Tier-0 | Slow |
| **Failover to DR site** | Critical services | DR may share weaknesses |
| **Re-deploy from IaC** | Cloud | Drift, secrets |
| **Manual reconstruction** | Small services | Human error |

### 5.1 Choosing

| Situation | Option |
|---|---|
| File corrupted/deleted | Restore file |
| Endpoint infected | Rebuild + restore user data |
| Server compromised | Rebuild; restore data only |
| Ransomware | Immutable backup restore to clean segment |
| Cloud compromised | Re-deploy from IaC + rotate secrets |

---

## 6. Validation before restore

| Check | Method |
|---|---|
| Backup integrity | Hash/size, restore test |
| Malware-free | AV/YARA scan of restored data |
| Timeframe | Backup predates compromise |
| Completeness | Required data present |
| Permissions | Correct ACLs |
| Secrets | Not the compromised set |
| Config | Baseline-compliant |

**Never restore from a backup taken after the compromise time unless proven clean.**

### 6.1 Determining "compromise time"

Use the earliest evidence of access — not the first alert. Backups after that point may contain attacker changes.

---

## 7. Clean rebuild

### 7.1 Workflow

```
1. Start from trusted image/installer
2. Patch to current baseline
3. Install EDR/agent and verify connectivity
4. Apply hardened configuration
5. Restore DATA only (not apps/binaries from the old host)
6. Rotate machine credentials
7. Verify no persistence
8. Join to management/monitoring
9. Business acceptance test
10. Return to service
```

### 7.2 Do not restore

- Executables/binaries from compromised hosts.
- Registry hives wholesale.
- Home directories without scanning.
- Browser profiles with extensions.
- Scheduled tasks/services.
- Trust relationships.

---

## 8. Phased restoration

| Phase | Content | Gate |
|---|---|---|
| **P0** | Identity, DNS, network, logging | Core services reachable; monitoring live |
| **P1** | Critical business apps | Business owner sign-off |
| **P2** | Supporting services | Stable for 24 h |
| **P3** | Non-critical/legacy | Documented exceptions |

### 8.1 Gates

Each phase requires:

- Verification passed.
- Monitoring in place.
- Rollback plan.
- Business owner acceptance.

**Do not skip gates to save time — that is how re-infection spreads.**

---

## 9. Verification

| Layer | Test |
|---|---|
| **Technical** | Service up, health checks, synthetic transactions |
| **Security** | EDR reporting, no malware, no C2, no rogue accounts |
| **Data** | Integrity, completeness, reconciliation |
| **Business** | Real users complete real tasks |
| **Compliance** | Logging, retention, controls active |

### 9.1 Business acceptance

The business — not IT — confirms the service works. Define acceptance criteria **before** the incident.

---

## 10. Monitoring after recovery

### 10.1 Enhanced monitoring

| Period | Focus |
|---|---|
| 0–24 h | Re-infection, instability |
| 24–72 h | Beaconing, persistence re-creation |
| 7–30 days | Actor return, dormant behaviour |

### 10.2 Specific watches

- Re-created accounts/rules/keys.
- Re-appearing hashes/domains.
- Unusual auth from restored identities.
- Performance anomalies (cryptominers).
- Backup job success.
- New alerts on cleaned hosts.

---

## 11. Rollback

Every restoration step needs a rollback:

| Step | Rollback |
|---|---|
| Patch | Uninstall/snapshot revert |
| Config change | Restore prior config |
| Data restore | Keep prior copy |
| Failover | Fail back plan |
| New service | Disable |

**If rollback is impossible, treat the step as high-risk and require approval.**

---

## 12. Communications

| Audience | Content |
|---|---|
| Business | Service status, ETA, workarounds |
| IT | Technical steps, dependencies, gates |
| Exec | Impact, risk, decisions |
| Customers | Per legal/comms |
| Regulator | Per legal |

### 12.1 Update discipline

- Scheduled updates even with no change.
- State uncertainty honestly.
- Don't announce "all clear" before monitoring window.

---

## 13. Closure criteria

- [ ] Eradication verified.
- [ ] Services restored and accepted.
- [ ] Data integrity reconciled.
- [ ] Monitoring window completed.
- [ ] No re-infection indicators.
- [ ] Credentials rotated.
- [ ] Root cause addressed or risk accepted.
- [ ] Documentation complete.
- [ ] Legal/regulatory obligations met.
- [ ] Lessons-learned scheduled.

---

## 14. Hypercare

| Aspect | Detail |
|---|---|
| **Duration** | 1–4 weeks |
| **Team** | Surge support, dedicated channel |
| **Focus** | Stability, re-infection, user issues |
| **Exit** | Stable metrics + business confidence |

**Recovery ends when the business says so — not when the server pings.**

---

## 15. Pitfalls

| Pitfall | Consequence |
|---|---|
| Restoring from post-compromise backup | Re-infection |
| Restoring binaries | Malware returns |
| Skipping validation | Hidden compromise |
| Restoring out of dependency order | Failed recovery |
| No rollback | Stuck in a bad state |
| Declaring recovery too early | Relapse |
| Ignoring business acceptance | Users blocked |
| Not monitoring after | Silent re-entry |
| Shared backup credentials | Backups destroyed |
| Untested restore | Longer outage |

---

## 16. Playbook: ransomware recovery

```
1. Confirm immutable backups exist and predate infection
2. Build clean environment (identity, network, logging)
3. Restore Tier-0 services
4. Scan restored data
5. Restore business apps in dependency order
6. Rotate all credentials
7. Verify with business
8. Enhanced monitoring 30 days
9. Document actual RTO/RPO
```

---

## 17. Labs

1. Measure real restore time for a test VM.
2. Restore a file and verify hash.
3. Rebuild a host from image and validate baseline.
4. Test dependency-ordered restore of a small app stack.
5. Simulate a backup containing malware; detect it.
6. Write acceptance criteria for a service.
7. Practise a rollback.
8. Build a hypercare plan.
9. Verify enhanced monitoring catches a test beacon.
10. Reconcile restored data against source of truth.

---

## 18. Recovery log template

```
time_utc | system | action | owner | validation
| result | rollback_ready | business_signoff
```

---

## 19. Self-test questions

1. What three conditions define recovery?
2. RTO vs RPO vs WRT.
3. Why restore in dependency order?
4. What is 3-2-1-1-0?
5. Why are backups an attack target?
6. How do you determine "compromise time"?
7. What should never be restored from a compromised host?
8. What are the four restoration phases?
9. What are the five verification layers?
10. How long do you monitor after recovery?
11. Why is rollback required?
12. Who confirms recovery?
13. What are closure criteria?
14. What is hypercare?
15. Name four recovery pitfalls.

---

## 20. One-page revision checklist

- [ ] Recovery = eradicated + clean + verified.
- [ ] RTO/RPO/MTD/WRT; actual recovery includes validation.
- [ ] Tiering and dependency order.
- [ ] Backups: 3-2-1-1-0, immutable, air-gapped, encrypted, tested; attacker risks.
- [ ] Restore options matrix; rebuild from IaC for cloud.
- [ ] Pre-restore validation: integrity, malware-free, timing, completeness, secrets.
- [ ] Compromise-time determines safe backup.
- [ ] Clean rebuild workflow; data only.
- [ ] Phased restoration P0–P3 with gates.
- [ ] Verification layers + business acceptance.
- [ ] Enhanced monitoring windows and watches.
- [ ] Rollback per step.
- [ ] Communications and update discipline.
- [ ] Closure criteria.
- [ ] Hypercare and exit.
- [ ] Pitfalls memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Lessons Learned](Lessons-Learned.md) · [APIs →](../09%20-%20Automation/APIs.md)
