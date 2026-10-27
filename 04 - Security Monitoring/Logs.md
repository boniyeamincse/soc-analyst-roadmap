# Logs — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← IDS / IPS](IDS-IPS.md) · [Network Traffic →](Network-Traffic.md)

> Goal: know which logs exist, what they answer, how they get to the SIEM, and why most detection failures are actually **logging failures**.
> SIEM platform → [SIEM.md](SIEM.md); alert design → [Alerting.md](Alerting.md); Windows specifics → [Windows-Event-Logs.md](../02%20-%20Operating%20Systems/Windows-Event-Logs.md).

---

## 0. How to use this note

1. §1–§2: why logs matter; the log pipeline.
2. §3–§5: sources, formats, levels.
4. §6–§8: collection, parsing/normalisation, enrichment.
5. §9–§11: storage/retention, time, integrity.
6. §12–§15: analysis techniques, detections, investigation, triage.
7. §16–§19: pitfalls, commands, labs, self-test, revision.

---

## 1. Why logs matter to a SOC analyst

- **No log = no detection, no investigation, no proof.** Most "we can't investigate" incidents are logging gaps.
- Logs are the **raw material of the SOC**: alerts, dashboards, hunts, timelines, reports.
- Different questions need **different logs**; knowing the map is the core skill.
- Log **quality** (fields, timestamps, completeness) determines detection quality.
- Attackers know this and **target logging** (clear logs, disable audit, tamper agents).

**SOC outcomes:** given a question you can answer:
- Which log source would contain the answer?
- Is it collected, parsed, retained, and time-synced?
- What fields can I filter on?
- What are its blind spots?
- How do I prove completeness?

---

## 2. Types of telemetry

| Family | Examples | Answers |
|---|---|---|
| **Endpoint** | EDR, Sysmon, Windows Security, auditd, osquery | What ran, touched, persisted. |
| **Identity** | AD, Entra ID, Okta, RADIUS, VPN | Who authenticated, from where, MFA. |
| **Network** | Firewall, proxy, DNS, IDS/IPS, NetFlow, Zeek | What talked to what. |
| **Application** | Web server, app logs, API gateway, DB | Requests, errors, business actions. |
| **Cloud** | CloudTrail, Azure Activity, GCP Audit, K8s audit | Control-plane changes, data access. |
| **Email** | Mail gateway, M365/Google audit | Delivery, clicks, rules, forwarding. |
| **Data** | DLP, CASB, file server, object storage | Data movement/exposure. |
| **Physical** | Badge, CCTV | Insider/physical. |
| **SaaS** | Admin audit, sharing events | Collaboration abuse. |
| **OT** | PLC/SCADA logs | Industrial anomalies. |

**Rule:** for every alert, know the **primary** and **corroborating** sources.

---

## 3. Common log sources and what they answer

| Source | Key questions |
|---|---|
| **Windows Security** | Logons, accounts, privileges, process, object access, shares. |
| **Sysmon** | Deep process/network/file/registry/injection telemetry. |
| **PowerShell logs** | Script content and module use. |
| **Linux auditd** | Syscalls, execve, file/perm changes. |
| **Linux auth/syslog** | SSH, sudo, PAM, cron, services. |
| **EDR** | Process trees, memory, response actions, detections. |
| **Firewall** | Allowed/denied connections, NAT, VPN. |
| **Proxy** | URLs, user agents, uploads/downloads, categories. |
| **DNS** | Queries, responses, NXDOMAIN, tunneling. |
| **IDS/IPS** | Signature/behaviour hits, payload context. |
| **NetFlow/IPFIX** | Who talked to whom, volume, duration. |
| **Zeek** | Rich connection/DNS/HTTP/TLS/SSL logs. |
| **Web server** | Requests, status, user agent, payloads. |
| **WAF** | Blocked/allowed attacks, rules. |
| **Load balancer** | Traffic distribution, health, errors. |
| **VPN** | Auth, source IP, device posture, session. |
| **AD/DC** | Kerberos, NTLM, account changes, GPO. |
| **Entra ID/Okta** | Sign-ins, MFA, conditional access, app consents. |
| **M365/Google** | Mailbox rules, sharing, downloads, admin. |
| **CloudTrail/Activity/Audit** | API calls, IAM, storage, network changes. |
| **Kubernetes audit** | API requests, RBAC, exec, secrets. |
| **CI/CD** | Builds, deployments, secrets, runners. |
| **Database** | Queries, errors, auth, slow log. |
| **Backup** | Job success/failure, deletions. |
| **Hypervisor** | VM lifecycle, console access. |

---

## 4. Log formats

| Format | Where | Characteristics |
|---|---|---|
| **Syslog (RFC3164/5424)** | Linux, network devices | `<pri>timestamp host app[pid]: msg`; UDP/TCP/TLS. |
| **JSON** | Apps, cloud, agents | Structured, nested, easy to parse. |
| **CEF** | Security devices | `CEF:0|Vendor|Product|Version|ID|Name|Severity|ext`. |
| **LEEF** | IBM QRadar | `LEEF:2.0|Vendor|Product|Version|ID|...`. |
| **EVTX** | Windows | Binary XML; needs agent/parser. |
| **W3C/CSV** | IIS, firewalls | Space/comma separated with headers. |
| **NetFlow/IPFIX** | Routers/switches | Flow records, not payload. |
| **PCAP** | Packet capture | Full packets, heavy. |
| **Key-value** | Many appliances | `key=value` pairs. |
| **Protobuf/Avro/Parquet** | Cloud/data lakes | Compact, schema-based. |
| **OCSF / ECS** | Open standards | Normalised schema for security events. |

**Structured > unstructured.** If you must regex unstructured logs, expect maintenance pain.

---

## 5. Log levels and severity

| Level | Use |
|---|---|
| **DEBUG/TRACE** | Development; high volume. |
| **INFO** | Normal operations. |
| **NOTICE** | Significant normal events. |
| **WARNING** | Potential issue. |
| **ERROR** | Operation failed. |
| **CRITICAL/ALERT/EMERGENCY** | Service/security critical. |

**SOC caveat:** vendor "severity" ≠ security severity. A firewall "high" may be noise; a "low" auth failure may be the key signal.

---

## 6. Collection methods

| Method | Description | Pros/Cons |
|---|---|---|
| **Agent** (forwarder) | Software on host ships logs | Reliable, parsing, buffering; maintenance. |
| **Agentless** | Pull via WMI/SSH/API/SNMP | No install; latency, credentials. |
| **Syslog** | Device → collector | Universal; UDP loss, no auth (use TLS). |
| **Windows Event Forwarding** | Native WEF subscription | No third-party agent; Windows-only. |
| **API polling** | Cloud/SaaS APIs | Rich data; rate limits/latency. |
| **Cloud connector** | Native integration (e.g., Sentinel) | Managed; config complexity. |
| **Streaming** | Kafka/Kinesis/PubSub | Scale; engineering overhead. |
| **Network tap/SPAN** | Packet/flow capture | Deep visibility; volume. |

### 6.1 Collection checklist

- **Coverage:** all critical assets and identity/cloud control planes.
- **Completeness:** are all needed event IDs enabled? (Audit policy, SACL, diagnostic settings.)
- **Latency:** near-real-time for detection.
- **Reliability:** buffering, retry, agent health monitoring.
- **Volume/cost:** filter at source where safe.
- **Parsing:** fields extracted correctly.
- **Time:** NTP, UTC, consistent.

---

## 7. Parsing and normalisation

### 7.1 Why

Raw logs are inconsistent: different field names (`src_ip`, `sourceAddress`, `client_ip`), formats, timestamps. Normalisation makes queries portable and correlations possible.

### 7.2 Common normalised fields

```
timestamp, host, user, src_ip, src_port, dest_ip, dest_port,
protocol, action (allow/deny), status, bytes_in, bytes_out,
process, parent_process, command_line, file_path, hash,
url, domain, user_agent, event_id, severity, vendor, product
```

### 7.3 Techniques

- **Regex extraction** (`rex`, `parse`).
- **Grok patterns** (Elastic).
- **Delimited/JSON/XML** parsing.
- **Field aliases** (map vendor names to common schema).
- **Data models** (Splunk CIM, Elastic ECS, OCSF).
- **Lookup enrichment** (asset DB, identity, GeoIP, threat intel).

### 7.4 Parsing failures

- Field not extracted → detection misses.
- Timestamp parsed in wrong timezone → correlation breaks.
- Multiline events split → stack traces lost.
- Truncation → command lines cut.
- Encoding issues → unicode/obfuscation.

**Monitor parse failure rate** as a health metric.

---

## 8. Enrichment

| Enrichment | Value |
|---|---|
| **Asset inventory** | Owner, criticality, OS, exposure. |
| **Identity** | Department, role, privilege, manager. |
| **GeoIP/ASN** | Location, hosting/VPN/Tor. |
| **Threat intel** | IOC reputation, campaign. |
| **Vulnerability** | Known CVEs on asset. |
| **Business context** | Change windows, maintenance. |
| **Historical baseline** | Rare/new behaviour. |

**Enrichment turns an event into a decision.** A failed login is noise; a failed login from a hosting ASN against a privileged account at 03:00 is an incident.

---

## 9. Storage, retention, and cost

### 9.1 Tiers

| Tier | Use | Cost |
|---|---|---|
| **Hot** | Recent, fast search (7–30 days). | High. |
| **Warm** | Occasional search (30–90 days). | Medium. |
| **Cold/archive** | Compliance/investigation (1y+). | Low, slow. |
| **Frozen** | Legal hold. | Lowest. |

### 9.2 Retention drivers

- Regulatory (e.g., 1 year, 3 years, 7 years).
- Investigation needs (dwell time — assume 30–90+ days).
- Cost/licensing.
- Data minimisation/privacy.

### 9.3 Cost control

- Filter noisy sources at source.
- Drop debug/verbose where not needed.
- Sample flows (not security events).
- Compress/archive.
- Tiered storage.
- Avoid indexing everything; use metrics for high-volume.

> **Never** drop logs you need for detection/investigation just to save cost; measure value first.

---

## 10. Time synchronization and ordering

- **NTP** everywhere; drift breaks correlation.
- Store/query in **UTC**; convert only for display.
- Know each source's timestamp semantics (event time vs ingest time).
- Use monotonic IDs (`EventRecordID`) within a log when ordering matters.
- Beware **clock skew** (Kerberos `0xC0000133`), timezone mislabels, DST.
- Late-arriving logs: use event time, not ingest time, for timelines.

---

## 11. Log integrity and anti-tampering

- **Centralise immediately** — local logs are attacker-visible.
- **Restrict access** to log infrastructure; separate admin plane.
- **Append-only/WORM** storage for critical logs.
- **Hash/sign** log bundles for evidence.
- **Monitor tampering:** Windows 1102/104, audit policy change 4719, agent stop/uninstall, config changes (Defender 5001/5007), cloud trail disable (`StopLogging`, `DeleteTrail`).
- **Detect gaps:** expected volume drop, missing hosts, sequence gaps.
- **Chain of custody** for investigations.

> Attackers who clear logs are telling you they were there — treat it as high severity.

---

## 12. Log analysis techniques

### 12.1 Basic operations

| Operation | Purpose |
|---|---|
| **Filter** | Narrow to relevant events. |
| **Aggregate** | Count by field (top talkers, failures). |
| **Group** | Bucket by time/user/host. |
| **Correlate** | Join across sources (user + process + network). |
| **Baseline** | Compare to normal. |
| **Sequence** | Order events into a timeline. |
| **Anomaly** | Rare/new values (first-seen). |
| **Pivot** | Follow an entity (IP, user, hash, host). |

### 12.2 Analytical questions

1. **What** happened? (event type)
2. **Who**? (user, service, process)
3. **Where**? (host, IP, geo)
4. **When**? (time, duration, frequency)
5. **How**? (protocol, tool, technique)
6. **Why**? (business context)
7. **So what**? (impact)

### 12.3 Baselines

- Per-user: normal hours, hosts, apps, locations.
- Per-host: normal processes, connections, services.
- Per-service: request rates, error rates.
- Per-account: typical data volume.

**First-seen** and **rare-value** analysis are workhorses for hunting.

---

## 13. Detection with logs

### 13.1 Detection design

1. Choose behaviour (ATT&CK technique).
2. Choose data source that observes it.
3. Confirm the field exists and is parsed.
4. Write logic with thresholds/baselines.
5. Test with true/false positives.
6. Tune, document, map to ATT&CK.
7. Monitor rule health (fires? too much? never?).

### 13.2 Examples

**Splunk**
```spl
index=wineventlog EventCode=4625
| stats count by TargetUserName, src_ip
| where count > 20
```

```spl
index=proxy
| stats sum(bytes_out) as out by src_ip, dest
| where out > 100000000
```

**KQL**
```kusto
SecurityEvent
| where EventID == 4688
| where Process has_any ("powershell.exe","cmd.exe")
| summarize count() by Account, Computer, bin(TimeGenerated, 1h)
```

**Elastic (EQL)**
```
process where process.parent.name == "winword.exe" and process.name in ("cmd.exe","powershell.exe")
```

---

## 14. Investigation with logs

### Step 1 — Define the question
What exactly are you trying to prove?

### Step 2 — Pick sources
Primary (where the behaviour lands) + corroborating.

### Step 3 — Establish time window
UTC, include buffer before/after.

### Step 4 — Filter and pivot
Start narrow, follow entities.

### Step 5 — Build timeline
Merge sources by time; note gaps.

### Step 6 — Validate
Cross-check with a second source; confirm parsing/timestamps.

### Step 7 — Document
Queries, sources, counts, screenshots, conclusions.

---

## 15. Triage playbooks (log-health)

### A. "No logs from host"
1. Agent running? Network? Credentials? Disk?
2. Host powered on? Time correct?
3. Is it in scope/inventory?
4. Treat as blind spot during incidents.

### B. "Log volume spike"
1. New source, config change, attack, or misconfiguration?
2. Top talkers/events.
3. Could be DoS on logging or noise hiding signal.

### C. "Log volume drop"
1. Agent/service stopped, disk full, filtering change.
2. Could be attacker disabling logging.
3. Verify with host-based check.

### D. "Parse failures"
1. Format change after upgrade.
2. Fix parser; re-index if possible.
3. Check detections dependent on fields.

### E. "Time skew"
1. NTP status.
2. Fix; note impact on past correlation.
3. Re-check detections using time windows.

### F. "Suspected log tampering"
1. 1102/104, 4719, agent stop, cloud trail stop.
2. Compare with forwarded copies.
3. Escalate as high severity.

---

## 16. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Missing audit policy/SACL | Events never generated. |
| Only collecting default logs | Blind to process/object/cloud detail. |
| Not parsing key fields | Detections can't filter. |
| Timezone inconsistency | Broken correlation/timelines. |
| No NTP | Skew and false ordering. |
| Local-only logs | Attacker clears them. |
| No retention | Can't investigate past 7 days. |
| Over-filtering | Signal dropped. |
| Ignoring agent health | Silent blind spots. |
| Volume without value | Cost explosion. |
| Trusting vendor severity | Misprioritisation. |
| No baselines | Everything looks anomalous or nothing does. |
| Logging secrets/PII | Compliance risk. |

---

## 17. Commands

```bash
# Linux
journalctl -u ssh --since "1 hour ago"
journalctl -p err -b
tail -f /var/log/auth.log
grep -i "failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
ausearch -m EXECVE -ts today
last -ai | head
logger -t test "hello"           # test syslog pipeline

# Network captures
tcpdump -i any -nn -s0 -w cap.pcap host 10.0.0.5
tshark -r cap.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Zeek
zeek -i eth0 local
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration
```

```powershell
# Windows
Get-WinEvent -LogName Security -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 50
wevtutil qe Security /c:20 /rd:true /f:text
Get-EventLog -LogName Application -Newest 20   # legacy
```

```bash
# Syslog test / forwarding
nc -u syslog.server 514
openssl s_client -connect syslog.server:6514
```

---

## 18. Labs

1. Build a log pipeline: host → syslog → SIEM; verify timestamps/fields.
2. Enable Windows audit policy + Sysmon; collect and parse.
3. Configure auditd rules; generate events; query them.
4. Intentionally break an agent; observe the gap.
5. Create a parse failure (change format); fix it.
6. Compare event time vs ingest time with delayed logs.
7. Build a baseline for one user and one host.
8. Clear a local log; prove the forwarded copy survives.
9. Write 5 detections from raw logs without vendor rules.
10. Document a source inventory with owner, retention, fields, gaps.

---

## 19. Self-test questions

1. What are the four log pipeline stages?
2. Why is structured logging better than regex parsing?
3. What is the difference between hot, warm, and cold storage?
4. Why must NTP be correct for a SOC?
5. What is log normalisation, and why does it matter?
6. Which log source answers "what process ran"?
7. Which log source answers "who authenticated"?
8. Which log source answers "what left the network"?
9. What is enrichment, and give three examples?
10. How do you detect log tampering?
11. Why is local-only logging insufficient?
12. What is a baseline, and how is it used?
13. What are three signs of a log pipeline failure?
14. How do you prove a log source is complete?
15. What is the difference between event time and ingest time?

---

## 20. One-page revision checklist

- [ ] Why: no log = no detection/investigation/proof; logging gaps are detection gaps.
- [ ] Families: endpoint, identity, network, application, cloud, email, data, physical, SaaS, OT.
- [ ] Source map: Windows Security/Sysmon/PowerShell, auditd/auth, EDR, firewall, proxy, DNS, IDS/IPS, NetFlow, Zeek, web, WAF, LB, VPN, AD/DC, Entra/Okta, M365/Google, cloud audit, K8s, CI/CD, DB, backup, hypervisor.
- [ ] Formats: syslog, JSON, CEF, LEEF, EVTX, W3C/CSV, NetFlow/IPFIX, PCAP, KV, protobuf, OCSF/ECS.
- [ ] Levels: debug→emergency; vendor severity ≠ security severity.
- [ ] Collection: agent, agentless, syslog, WEF, API, connector, streaming, tap/SPAN; coverage/completeness/latency/reliability/volume/parsing/time.
- [ ] Parsing: normalised fields, regex/grok/delimited/JSON/XML, aliases, data models, enrichment; parse failure monitoring.
- [ ] Enrichment: asset, identity, GeoIP/ASN, TI, vuln, business, baseline.
- [ ] Storage: hot/warm/cold/frozen, retention drivers, cost control.
- [ ] Time: NTP, UTC, event vs ingest, skew, late arrival.
- [ ] Integrity: centralise, restrict, WORM, hash, tamper monitoring (1102/104/4719/5001/5007/cloud trail), gaps, chain of custody.
- [ ] Analysis: filter, aggregate, group, correlate, baseline, sequence, anomaly, pivot; what/who/where/when/how/why/so-what; baselines and first-seen.
- [ ] Detection: behaviour → source → field → logic → test → tune → map → monitor.
- [ ] Investigation: question → sources → window → filter/pivot → timeline → validate → document.
- [ ] Log-health triage: missing logs, spikes, drops, parse failures, skew, tampering.
- [ ] Pitfalls list memorised.
- [ ] Commands: journalctl, auth.log, ausearch, tcpdump, tshark, zeek-cut, Get-WinEvent, wevtutil, syslog test.

---

> **Navigation:** [Roadmap index](../README.md) · [← IDS / IPS](IDS-IPS.md) · [Network Traffic →](Network-Traffic.md)
