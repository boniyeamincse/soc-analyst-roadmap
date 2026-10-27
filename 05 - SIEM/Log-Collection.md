# Log Collection — SOC Analyst Study Notes

> Goal: get the **right logs, complete, on time, parsed correctly**, into the SIEM — and know when that silently stops happening.
> Log concepts → `04 - Security Monitoring/Logs.md`; SIEM architecture → `SIEM.md`; detection → `Detection-Rules.md`.

---

## 0. How to use this note

1. §1–§2: why collection is the foundation; source inventory.
2. §3–§6: collection methods, transports, pipelines, parsing.
3. §7–§9: time, volume/licensing, filtering.
4. §10–§12: health monitoring, troubleshooting, retention.
5. §13–§15: source checklists, onboarding process, governance.
6. §16–§19: pitfalls, commands, labs, self-test, revision.

---

## 1. Why collection is the foundation

> **No log = no detection.** Every detection, hunt, and investigation is downstream of collection.

- Coverage gaps are invisible until an incident proves them.
- Bad parsing produces detections that silently never fire.
- Volume problems cause missed events (dropped/queued) or cost explosions.
- Time skew destroys correlation.
- Collection is the **most common root cause of "we didn't see it."**

**Rule:** treat log ingestion like a production service — with SLOs, monitoring, and owners.

---

## 2. Source inventory

### 2.1 Build the inventory first

For each source record:

| Field | Example |
|---|---|
| **Source type** | Windows Security, Linux auth, proxy, EDR, cloud audit |
| **Host/tenant** | DC01, prod-aws, tenant-id |
| **Business owner** | Platform team |
| **Criticality** | Tier 1 |
| **Transport** | Agent / syslog / API / connector |
| **Volume (GB/day, EPS)** | 2 GB/day |
| **Retention** | 90 days hot, 1 year cold |
| **Parser/format** | ECS, ASIM, CIM, custom |
| **Contact** | on-call |
| **Status** | healthy / degraded / missing |

### 2.2 Coverage frameworks

Map sources to:

- **Identity:** AD/Entra, Okta, VPN, PAM, MFA.
- **Endpoint:** EDR, Sysmon, AV, OS logs.
- **Network:** firewall, proxy, DNS, IDS, flow, VPN.
- **Cloud:** control plane audit, storage, IAM.
- **SaaS:** M365, Google Workspace, Salesforce, GitHub.
- **Application:** web, API, database.
- **Security tooling:** vulnerability scanner, DLP, email gateway.

### 2.3 Priority order (typical)

1. Identity/authentication (AD, Entra, VPN).
2. Endpoint (EDR, Sysmon, Defender).
3. Perimeter (firewall, proxy, DNS).
4. Cloud control plane.
5. Email gateway.
6. Critical application logs.
7. Everything else.

**Rationale:** account compromise and endpoint execution are the highest-frequency real incidents.

---

## 3. Collection methods

| Method | How | Best for | Cautions |
|---|---|---|---|
| **Agent/forwarder** | Installed agent (Splunk UF, Elastic Agent, AMA, Wazuh agent). | Servers/workstations, reliable delivery, buffering. | Deployment/upgrade overhead. |
| **Syslog** | UDP/TCP/TLS 514/6514. | Network devices, appliances, Linux. | UDP loss; parsing pain; no auth by default. |
| **Windows Event Forwarding (WEF)** | Windows-native subscription. | Windows at scale without agents. | Requires AD/GPO design. |
| **API pull** | Poll vendor API. | SaaS, cloud, M365, EDR. | Rate limits; latency; auth rotation. |
| **Cloud connectors** | Native (AWS S3/SQS, Azure Event Hub, GCP Pub/Sub). | Cloud audit logs. | Regional config; IAM scope. |
| **HEC (HTTP Event Collector)** | HTTP POST with token. | Custom apps, scripts. | Token security; batching. |
| **Kafka/stream** | Durable bus. | High volume, multiple consumers. | Operational complexity. |
| **Database/file pull** | Scheduled extract. | Legacy apps. | Latency; breaks on schema change. |
| **Packet/flow** | NetFlow, IPFIX, PCAP. | Network visibility. | Not event logs; different pipeline. |

### 3.1 Choosing

- **Reliability** (buffering, retry) > lowest effort.
- **TLS everywhere** where supported.
- **One transport per source class**; avoid sprawl.
- Prefer vendor-supported connectors for SaaS.
- Keep a **fallback** (syslog) for appliances without agents.

---

## 4. Transport and delivery guarantees

| Concern | Practice |
|---|---|
| **Loss** | TCP/TLS, disk buffering on agent, ACK, retry. |
| **Duplication** | Idempotent ingest; dedup by event ID. |
| **Ordering** | Don't rely on it; use event timestamps. |
| **Latency** | Monitor ingest lag; batch sensibly. |
| **Encryption** | TLS 1.2+; certificates validated. |
| **Authentication** | Per-source tokens/credentials; rotate. |
| **Backpressure** | Queue, drop policy, alerting. |

**UDP syslog is lossy by design.** Use it only where unavoidable and monitor for gaps.

---

## 5. Pipeline stages

```
Source → Agent/Connector → Transport → Ingest endpoint → Parse
      → Normalise → Enrich → Index/Store → Detect → Alert
```

| Stage | Failure symptom |
|---|---|
| **Agent** | No data from that host. |
| **Transport** | Partial/late data; TLS errors. |
| **Ingest** | 401/403/429; dropped events. |
| **Parse** | Fields null, `_raw` only, wrong types. |
| **Normalise** | Field names inconsistent across sources. |
| **Enrich** | Missing asset/user context. |
| **Index** | Wrong index, retention mismatch, search slow. |

**Monitor each stage**, not just the final count.

---

## 6. Parsing and normalisation

### 6.1 Why

Detections must query **consistent field names** across sources (`user`, `src_ip`, `process_name`), not vendor-specific ones.

### 6.2 Schemas

| Schema | Ecosystem |
|---|---|
| **ECS (Elastic Common Schema)** | Elastic. |
| **OCSF** | Open Cybersecurity Schema Framework (vendor-neutral). |
| **ASIM** | Microsoft Sentinel. |
| **CIM** | Splunk. |
| **STIX/TAXII** | Threat intel exchange (different purpose). |

### 6.3 Parsing techniques

- **Regex/syslog parsing** — brittle, test thoroughly.
- **JSON** — preferred; avoid double-encoding.
- **KV/CSV** — simple, order-dependent.
- **Grok/dissect** — pattern-based.
- **Vendor parsers** — maintained, still validate.
- **Multiline** — stack traces must be joined, not split.

### 6.4 Normalisation rules

1. Map to one schema per platform.
2. Keep `_raw`/original event for proof.
3. Normalise timestamps to UTC.
4. Normalise IPs (v4/v6), ports (int), booleans.
5. Standardise user identifiers (UPN vs sAMAccountName vs email).
6. Preserve vendor-specific fields with a prefix.
7. Document field mappings.

### 6.5 Validation

- Sample 100 events after every parser change.
- Compare parsed fields to raw.
- Check null rates per field.
- Verify timestamp parsing (epoch vs local).
- Test unicode/encoding, long lines, multiline.

---

## 7. Time synchronisation

- All sources must use **NTP**; check drift.
- Store **event time** and **ingest time** separately.
- Normalise to **UTC**; display in local tz if needed.
- Watch timezone-less formats (`2024-01-01 10:00:00`).
- Clock skew breaks correlation, timelines, and legal defensibility.

```bash
timedatectl status
chronyc tracking
w32tm /query /status
```

---

## 8. Volume, licensing, and cost

### 8.1 Volume drivers

- Verbose debug logging.
- Firewall "deny" logs at scale.
- Proxy full-URL logging.
- Repeated health pings.
- Duplicate collection (agent + API).

### 8.2 Control methods

| Method | Effect |
|---|---|
| **Filter at source** | Drop known-noise before transport. |
| **Sampling** | Reduce high-volume flow data (careful). |
| **Tiering** | Hot/warm/cold storage. |
| **Retention** | Shorter for verbose low-value sources. |
| **Drop noisy categories** | Only with risk acceptance. |
| **Compression** | Transport and storage. |

### 8.3 Never cut

- Authentication (success + failure).
- Privileged account activity.
- Process creation on critical assets.
- Cloud control-plane audit.
- Security tool alerts.
- Anything used by a production detection.

**Cutting logs to save cost is a risk decision — document owner and approval.**

---

## 9. Filtering and exclusions

- Prefer **filter at the source** for known noise (health checks, scanner IPs).
- Keep exclusion lists with **owner + justification + expiry**.
- Never filter by broad event IDs that detections need.
- Log a sample of filtered events for auditing.
- Revisit quarterly.

---

## 10. Health monitoring

### 10.1 Per-source health signals

| Signal | Meaning |
|---|---|
| **Last event time** | Silence detection. |
| **Events/min vs baseline** | Drop or spike. |
| **Parse failure rate** | Parser broken. |
| **Ingest lag** | Pipeline delay. |
| **Agent heartbeat** | Host reachable/agent alive. |
| **Queue depth** | Backpressure. |
| **HTTP 4xx/5xx** | Auth/quota problems. |

### 10.2 Silence alerts

```
Alert if a source that normally sends >X events/min sends 0 for N minutes
during business hours (and N hours otherwise).
```

**Silence is the most dangerous failure** — it looks like "all quiet."

### 10.3 Dashboards

- Sources by status (green/amber/red).
- EPS by source vs licensed.
- Parse failure top-N.
- Agent version spread.
- Coverage vs inventory (%).

---

## 11. Troubleshooting missing logs

### 11.1 Ordered checks

1. **Is it generated?** (source-side logging enabled? test event?)
2. **Is it collected?** (agent running? service up?)
3. **Is it transported?** (network/TLS/firewall? queue?)
4. **Is it ingested?** (auth, licence, index?)
5. **Is it parsed?** (search `_raw` for a known string.)
6. **Is it retained?** (index/retention/frozen?)
7. **Is it searchable?** (field names, time range, permissions.)

### 11.2 Commands

```bash
# Agent status
systemctl status splunkforwarder
sudo /opt/elastic/elastic-agent status
sudo systemctl status wazuh-agent
sc query AMA

# Connectivity
nc -vz siem.example.com 6514
curl -k -v https://siem:8088/services/collector/health

# Local test event
logger -t test "soc collection test $(date -u +%FT%TZ)"
```

### 11.3 Common causes

| Cause | Fix |
|---|---|
| Logging disabled at source | Enable audit policy. |
| UDP loss | Move to TCP/TLS. |
| Wrong index/retention | Fix index routing. |
| Parser change | Validate fields. |
| Certificate expiry | Renew. |
| Token expired | Rotate. |
| Licence/quota hit | Raise or filter. |
| Agent outdated | Upgrade. |
| Firewall change | Open path. |
| Time skew | NTP. |

---

## 12. Retention and storage

- **Hot:** fast search, days–weeks.
- **Warm:** slower, weeks–months.
- **Cold/archive:** cheapest, restore-on-demand.
- **Legal hold:** immutable retention for investigations.

**Set retention from requirements:**
- Regulatory (e.g., PCI 1 year, others vary).
- Investigation dwell-time assumption (≥30–90 days searchable).
- Detection lookback windows.
- Cost tolerance.

Document retention per source class. Confirm deletion is actually enforced.

---

## 13. Source checklists

### 13.1 Windows

- Security (4624/4625/4634/4648/4672/4688/4720/4726/4732/4768/4769/4771/4776/7045).
- System (7045, 7036, 104).
- Sysmon (1,3,7,8,10,11,12,13,22).
- PowerShell (4103/4104/4100).
- Defender (1116/1117/5001/5007).
- Task Scheduler, WMI activity, AppLocker/WDAC.

### 13.2 Linux/macOS

- auth/sudo/cron/systemd/journald.
- auditd/auditbeat.
- SSH, package manager, kernel.

### 13.3 Network

- Firewall allow/deny.
- Proxy (URL, user, bytes, category).
- DNS queries.
- VPN auth.
- IDS/IPS alerts.
- NetFlow.

### 13.4 Cloud

- AWS CloudTrail + GuardDuty + VPC Flow + S3 access.
- Azure Activity + Entra sign-in/audit + NSG flow.
- GCP Audit Logs + SCC.

### 13.5 SaaS/identity

- M365 Unified Audit Log.
- Okta System Log.
- Google Workspace Admin.
- GitHub audit.
- Email gateway (message trace).

**Verify each has a real event in the SIEM**, not just a documented connector.

---

## 14. Onboarding a new source

1. **Request** — owner, purpose, data classification.
2. **Inventory** — volume estimate, format, transport.
3. **Security review** — TLS, credentials, least privilege.
4. **Parsing plan** — schema mapping, fields, tests.
5. **Detection plan** — which rules will use it.
6. **Deploy** in staging if possible.
7. **Validate** — sample events, field null rates, time.
8. **Monitor** — silence/lag alerts.
9. **Document** — runbook, owner, retention.
10. **Review** after 30 days.

**No source goes live without a health check and an owner.**

---

## 15. Governance

| Control | Practice |
|---|---|
| **Ownership** | Every source has an owner. |
| **Change control** | Parser/transport changes reviewed. |
| **Access control** | Ingest tokens scoped; search RBAC. |
| **Data classification** | PII/PCI tags; handling rules. |
| **Audit** | Who changed configs, when. |
| **Cost** | Volume reviewed monthly. |
| **Coverage** | Quarterly gap analysis vs ATT&CK. |
| **Retention** | Enforced and verified. |
| **Decommission** | Remove source + parser + rules. |

---

## 16. Common pitfalls

| Pitfall | Consequence |
|---|---|
| No source inventory | Unknown gaps. |
| Assume connector = collection | Silent missing data. |
| UDP syslog only | Loss. |
| No silence alerts | Blind for weeks. |
| Parser untested | Detections never fire. |
| Inconsistent field names | Rules fail silently. |
| Local timezones | Broken correlation. |
| Duplicate ingestion | Double cost/alerts. |
| Filtering needed events | Detection blindness. |
| No retention plan | Can't investigate old incidents. |
| Orphaned parsers/sources | Cost and confusion. |
| No owner | Nobody fixes breakage. |

---

## 17. Commands

```bash
# Verify event delivery end-to-end
logger -t SOCTEST "collection-test-$(uuidgen)"
# then search SIEM for SOCTEST

# Windows test event
eventcreate /T INFORMATION /ID 999 /L APPLICATION /D "SOC collection test"

# Networking
ss -tunp | grep -E '6514|8088|9997'
openssl s_client -connect siem:6514 -brief

# Splunk UF
/opt/splunkforwarder/bin/splunk list forward-server
/opt/splunkforwarder/bin/splunk btool outputs list --debug | head -50

# Elastic Agent
elastic-agent status
elastic-agent inspect output

# Wazuh
/var/ossec/bin/agent_control -l
tail -f /var/ossec/logs/ossec.log
```

```spl
| metadata type=sourcetypes index=* 
| table sourcetype totalCount recentTime lastTime
```

```kusto
Usage
| where TimeGenerated > ago(1d)
| summarize Events=sum(Quantity) by DataType
| order by Events desc
```

---

## 18. Labs

1. Build an inventory of 10 lab sources with volume estimates.
2. Onboard Linux auth logs via agent and verify fields.
3. Onboard Windows Security via WEF; validate 4624 parsing.
4. Break a parser deliberately; observe nulls; fix.
5. Create a silence alert for one source.
6. Measure ingest lag during a load test.
7. Filter health-check noise at source; verify detection still works.
8. Compare coverage against ATT&CK data sources.
9. Write a runbook for "source stopped sending."
10. Compute cost per GB and propose tiering.

---

## 19. Self-test questions

1. Why is collection the most common cause of missed detections?
2. What belongs in a source inventory?
3. Agent vs syslog vs API vs connector — trade-offs?
4. Why is UDP syslog risky?
5. What is normalisation, and why does it matter?
6. Name three schemas.
7. Why keep raw events?
8. What is a silence alert and why is it critical?
9. How do you troubleshoot a missing log, in order?
10. Which logs should never be cut for cost?
11. How do you validate a parser change?
12. Why is time sync essential?
13. What is ingest lag?
14. What governance controls apply to log collection?
15. How do you prove a new source is actually working?

---

## 20. One-page revision checklist

- [ ] Collection = foundation; coverage gaps invisible; treat as a service with SLOs.
- [ ] Inventory fields: type, host/tenant, owner, criticality, transport, volume, retention, parser, contact, status.
- [ ] Coverage: identity, endpoint, network, cloud, SaaS, app, tooling; priority order.
- [ ] Methods: agent, syslog, WEF, API pull, cloud connector, HEC, Kafka, DB/file, flow.
- [ ] Transport: TCP/TLS, buffering, retry, dedup, ordering, auth, backpressure; UDP lossy.
- [ ] Pipeline stages and their failure symptoms.
- [ ] Parsing: ECS/OCSF/ASIM/CIM; regex/JSON/KV/grok/dissect; multiline; normalisation rules; validation.
- [ ] Time: NTP, event vs ingest time, UTC, timezone-less risk.
- [ ] Volume/cost: drivers, filtering at source, sampling, tiering, retention; never-cut list.
- [ ] Exclusions: owner + justification + expiry; sample retained.
- [ ] Health: last event, rate, parse failures, lag, heartbeat, queue, HTTP errors; silence alerts; dashboards.
- [ ] Troubleshooting order: generated → collected → transported → ingested → parsed → retained → searchable; commands.
- [ ] Retention tiers and regulatory/dwell-time requirements.
- [ ] Source checklists: Windows, Linux/macOS, network, cloud, SaaS/identity — with real event verification.
- [ ] Onboarding 10 steps; governance controls (ownership, change control, access, classification, audit, cost, coverage, retention, decommission).
- [ ] Pitfalls list memorised.
- [ ] Commands: logger/eventcreate test, port checks, UF/Elastic/Wazuh status, sourcetype metadata, Usage query.
