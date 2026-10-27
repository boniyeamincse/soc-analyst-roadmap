# EDR — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Alerting](Alerting.md) · [IDS / IPS →](IDS-IPS.md)

> Goal: understand what endpoint detection and response actually records and can do, how to hunt with it, and where its blind spots are.
> Process behaviour → [Processes.md](../02%20-%20Operating%20Systems/Processes.md); Windows telemetry → [Windows-Event-Logs.md](../02%20-%20Operating%20Systems/Windows-Event-Logs.md); alert design → [Alerting.md](Alerting.md).

---

## 0. How to use this note

1. §1–§2: why EDR; definitions and comparisons.
2. §3–§5: architecture, telemetry, capabilities.
3. §6–§8: detection model, hunting, response actions.
4. §9–§11: deployment, tuning/exclusions, limitations.
5. §12–§15: alerts, triage, investigation, integration.
6. §16–§19: pitfalls, labs, self-test, revision.

---

## 1. Why EDR matters

- Endpoint is where **execution, credential theft, persistence, and ransomware** happen.
- EDR gives **process-level visibility with context** that traditional AV and Windows logs miss.
- It supports **active response** (isolate, kill, quarantine, collect) in seconds.
- It is the **primary investigative tool** for most incidents.
- It produces high-fidelity behavioural detections when tuned.

**What EDR is not:** an antivirus replacement (though it includes AV), a network tool, or a guarantee of detection.

---

## 2. Definitions and comparisons

| Term | Focus |
|---|---|
| **AV (anti-virus)** | Malware signatures/heuristics; block known threats. |
| **EPP (endpoint protection platform)** | Prevention suite: AV, firewall, HIPS, device control, encryption. |
| **EDR** | Continuous endpoint telemetry + behavioural detection + response. |
| **XDR** | Correlates endpoint with network/identity/cloud/email. |
| **MDR** | Managed detection & response service (people + tech). |
| **NDR** | Network detection & response. |
| **HIDS** | Host intrusion detection (file/integrity/log-based). |
| **SIEM** | Aggregated log analytics/correlation. |

**Relationship:** EPP prevents; EDR records/detects/responds; XDR correlates across domains; MDR operates it for you.

---

## 3. Architecture

```
Endpoint
├── Kernel driver (minifilter, callbacks, ETW consumer)
├── User-mode agent (service + UI)
├── Local cache/buffer
└── Tamper protection
        │
        ▼ (TLS, compressed, batched)
Cloud console / on-prem server
├── Ingest + storage
├── Detection engine (behavioural, ML, IOC, rules)
├── Threat intel
├── Hunting/search UI
├── Response orchestration
└── APIs/integrations
```

### 3.1 Data collection mechanisms

| Mechanism | Provides |
|---|---|
| **Kernel callbacks** | Process/thread/image/registry/file/network events. |
| **Minifilter** | File I/O with path and process. |
| **ETW** | Rich OS telemetry (process, DNS, network, scripts). |
| **User-mode hooks** | API-level context (can be bypassed). |
| **Memory scanning** | Injected code, fileless malware. |
| **Script/AMSI** | Script content and intent. |
| **Network** | Connections with process attribution. |

### 3.2 Deployment models

- Cloud-managed (most common).
- On-prem server.
- Hybrid.
- Air-gapped/offline mode (limited).

---

## 4. Telemetry (what EDR records)

### 4.1 Core event types

| Event | Fields |
|---|---|
| **Process create** | PID/PPID, image, path, command line, user, hash, signer, parent, integrity, session. |
| **Process terminate** | PID, exit code. |
| **Image/module load** | DLL/path/hash/signer, unsigned flag. |
| **File create/modify/delete** | Path, hash, process, user. |
| **Registry** | Key/value, process. |
| **Network connection** | PID, src/dst IP/port, protocol, domain, bytes. |
| **DNS query** | Process, domain, response. |
| **Script** | Content, interpreter, user. |
| **Injection** | Source/target process, technique. |
| **Credential access** | LSASS handle/read, protected store. |
| **Service/task/driver** | Creation/modification. |
| **Logon** | User, type, source. |
| **USB/device** | Device, mount, file. |
| **Tamper** | Agent stop, config change, exclusion. |

### 4.2 Useful fields for hunting

```
hostname, os, agent_version, user, domain, integrity_level,
process_name, process_path, process_hash, process_signer,
parent_name, parent_path, parent_hash, command_line,
remote_ip, remote_port, remote_domain, url,
file_path, file_hash, registry_key, service_name,
technique, detection_name, severity
```

### 4.3 Retention

- Raw telemetry: days–weeks (cost).
- Detections: months.
- Process/file/network summaries: weeks–months.
- Plan around **dwell time** (assume 30+ days).

---

## 5. Capabilities

### 5.1 Detection

- Signature/AV.
- Behavioural rules (process lineage, injection, credential access).
- ML/anomaly (prevalence, sequence).
- IOC matching (hash/domain/IP).
- Script/AMSI analysis.
- Ransomware behaviour (mass encryption, shadow deletion).
- Exploit protection (memory mitigations).
- Device control.

### 5.2 Response

| Action | Effect |
|---|---|
| **Isolate host** | Block network except management. |
| **Kill process** | Terminate PID/tree. |
| **Quarantine file** | Move/deny execution. |
| **Live response shell** | Remote commands. |
| **Collect file/memory** | Evidence. |
| **Retrieve artifacts** | Logs, autoruns, MFT. |
| **Block hash/IP/domain** | Prevent spread. |
| **Rollback** | Revert changes (ransomware). |
| **Scan** | On-demand. |

### 5.3 Hunting

- Search by process, hash, command line, parent, network, registry.
- Pivot across hosts/time.
- Build queries and save.
- Compare prevalence.

---

## 6. Detection model

### 6.1 Behavioural detection patterns

1. Office/browser → shell.
2. Web server → shell.
3. Service host → unusual binary.
4. Encoded/obfuscated scripts.
5. Unsigned binary with network.
6. Execution from temp/AppData.
7. LSASS access.
8. Process injection.
9. Credential store access.
10. Persistence creation.
11. Ransomware behaviours.
12. Defense evasion (Defender disable, AMSI bypass).
13. Suspicious driver load.
14. Lateral tool usage.
15. Rare process/prevalence anomaly.

### 6.2 Why EDR detections work

- **Context**: parent, user, command line, hash, signer, prevalence.
- **Sequence**: events linked into a story.
- **Behaviour**: independent of hash.
- **Response**: can act immediately.

### 6.3 Why they fail

- User-mode hook bypass (direct syscalls, unhooking).
- Kernel-level rootkits/BYOVD.
- Encrypted/obfuscated scripts not seen by AMSI.
- Living-off-the-land with legitimate tools.
- Agent disabled/tampered (if protection fails).
- Cloud-only visibility gaps (offline endpoints).
- Over-broad exclusions.

---

## 7. Hunting with EDR

### 7.1 Hunt workflow

1. **Hypothesis** (from intel/ATT&CK/incident).
2. **Translate to telemetry** (process/network/file).
3. **Query** (EDR search).
4. **Baseline** (prevalence, expected parents).
5. **Triage hits**.
6. **Pivot** across hosts.
7. **Document and convert** to detection.

### 7.2 Example hunts

**Rare parent-child pairs**
```sql
SELECT parent_name, process_name, COUNT(*) c
FROM process_events
WHERE time > now() - 7d
GROUP BY parent_name, process_name
ORDER BY c ASC
```

**Unsigned binaries making network connections**
```kusto
DeviceNetworkEvents
| join kind=inner DeviceFileEvents on DeviceId, FolderPath
| where SignatureState != "Valid"
```

**LSASS access by non-security processes**
```kusto
DeviceEvents
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","csrss.exe","services.exe")
```

**Persistence created by non-admin user**
```kusto
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has "CurrentVersion\\Run"
| where InitiatingProcessAccountName !endswith "$"
```

### 7.3 Prevalence

- How many hosts have this hash/path?
- Is this process normal in this role?
- First seen when?

**Prevalence is the best false-positive filter.**

---

## 8. Response actions (operational discipline)

### 8.1 Before acting

- Confirm host identity and business criticality.
- Confirm the process/file is malicious (or isolate first if active).
- Consider evidence preservation (memory before kill/reboot).
- Notify stakeholders for production systems.

### 8.2 Isolation nuances

- Network isolation may block management/EDR — verify.
- Some isolates allow only EDR cloud.
- Isolation ≠ shutdown; preserves memory/state.
- Document start/end.

### 8.3 Killing processes

- Kill the **tree**, not just the parent.
- Watch for watchdog/respawn.
- Persistence may restart it — remove persistence first or isolate.

### 8.4 Quarantine/rollback

- Quarantine may break legitimate apps if FP.
- Rollback only for supported ransomware behaviours.
- Verify integrity after rollback.

### 8.5 Live response

- Use read-only commands first (whoami, netstat, tasklist).
- Record all commands and outputs for evidence.
- Avoid altering timestamps/state unnecessarily.
- Chain of custody.

---

## 9. Deployment and coverage

### 9.1 Coverage checklist

- All servers, workstations, critical VMs.
- Containers/host nodes (if supported).
- Cloud workloads.
- Remote/VDI.
- macOS/Linux if in scope.
- Offline/laptop coverage.
- Servers with legacy OS support.

### 9.2 Health monitoring

- Agent version and heartbeat.
- Policy assignment.
- Last check-in.
- Tamper status.
- Sensor health (driver loaded, ETW).
- Coverage % vs inventory.

**Unprotected endpoints are blind spots** — track them like outages.

### 9.3 Policies

- Prevention mode (block) vs detect-only.
- Exclusions.
- Response permissions (who can isolate).
- Data collection level.
- Retention.

---

## 10. Tuning and exclusions

### 10.1 Why exclusions exist

Performance (build servers, databases), compatibility (legacy apps, backup), false positives.

### 10.2 Exclusion risk

- Attackers target excluded paths/processes.
- Broad exclusions = blind spots.
- Exclusions are persistent and often forgotten.

### 10.3 Discipline

- Every exclusion: **owner, justification, scope, expiry**.
- Prefer narrow path/hash over directory/process name.
- Never exclude user-writable directories, temp, or PowerShell.
- Review quarterly.
- Monitor for exclusion changes (Defender 5007).

### 10.4 Performance tuning

- Tune scan scope and exclusions narrowly.
- Monitor CPU/IO impact.
- Use vendor guidance.
- Prefer detection over blocking for noisy low-risk rules.

---

## 11. Limitations and blind spots

| Limitation | Impact |
|---|---|
| User-mode hook bypass | Misses fileless/injected. |
| Kernel rootkits/BYOVD | Hides activity. |
| Encrypted scripts | No content visibility. |
| LOLBins | Legitimate binaries look normal. |
| Agent disabled/tampered | No telemetry. |
| Offline endpoints | Delayed/lost data. |
| Network-only attacks | Not visible. |
| Cloud/SaaS control plane | Needs cloud logs. |
| Over-broad exclusions | Blind spots. |
| Retention limits | Can't investigate old incidents. |
| Alert-only (no prevention) | Malware may run. |
| Data volume | Cost and search latency. |

**Complement EDR with** SIEM (identity/network/cloud), NDR, email, and cloud audit.

---

## 12. EDR alerts and triage

### 12.1 Common alert types

- Malware detected/quarantined.
- Suspicious process/behaviour.
- Credential access.
- Injection.
- Ransomware behaviour.
- Defense evasion/tamper.
- Persistence.
- Lateral movement.
- Exploit attempt.
- Policy violation (USB, app).

### 12.2 Triage steps

1. Read detection name/description/technique.
2. Identify host, user, process, parent, command line, hash.
3. Determine if execution occurred vs blocked.
4. Check behaviour (children, network, files, registry).
5. Check prevalence and signature.
6. Check persistence and credential exposure.
7. Decide: FP/benign/malicious; contain if needed.
8. Document and hunt estate-wide.

### 12.3 Severity considerations

- Privileged context (SYSTEM/admin).
- Critical asset (DC, finance, prod).
- Active network/C2.
- Persistence established.
- Credential access.
- Multiple hosts.

---

## 13. Investigation workflow

### Step 1 — Establish the endpoint
Host role, owner, criticality, OS, exposure.

### Step 2 — Establish the process
Image, path, hash, signer, command line, user, integrity, parent chain.

### Step 3 — Establish behaviour
Children, modules, network, files, registry, services, tasks.

### Step 4 — Establish persistence
Autoruns, services, tasks, WMI, drivers.

### Step 5 — Establish credential exposure
LSASS, SAM, browsers, tokens.

### Step 6 — Scope
Same hash/process/network across estate.

### Step 7 — Contain and collect
Isolate, preserve memory/files, block IOCs.

### Step 8 — Eradicate and recover
Remove persistence, reimage if needed, verify.

---

## 14. Integration

| Integration | Value |
|---|---|
| **SIEM** | Correlate endpoint with identity/network/cloud. |
| **SOAR** | Automated enrichment/response. |
| **Threat intel** | IOC matching, reputation. |
| **Identity** | Disable user, revoke sessions. |
| **Email** | Purge campaign. |
| **Firewall/proxy** | Block C2. |
| **Ticketing** | Track cases. |
| **Vulnerability mgmt** | Prioritise exploitable hosts. |
| **NDR** | Network context. |

**XDR** is essentially this correlation productised.

---

## 15. Vendor landscape (conceptual)

| Category | Examples |
|---|---|
| **Enterprise EDR/XDR** | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Palo Alto Cortex XDR, Trend Vision One, Sophos Intercept X. |
| **Open source** | Wazuh, Velociraptor, OSQuery+SIEM, Sysmon+SIEM. |
| **MDR** | Vendor-managed services on top of EDR. |

**Concepts transfer:** telemetry → detection → response. Learn the model, not the buttons.

---

## 16. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Treating EDR as AV only | Miss behavioural detections. |
| Ignoring health/coverage | Blind endpoints. |
| Broad exclusions | Attacker hiding places. |
| No response permissions | Slow containment. |
| Alert-only mode everywhere | Malware runs. |
| Not preserving memory | Lost evidence. |
| Killing parent only | Respawn. |
| No prevalence check | FP churn. |
| No integration with identity | Slow account response. |
| Ignoring low-severity behavioural alerts | Missed chains. |
| No retention planning | Investigation limits. |
| Assuming full visibility | Overconfidence. |

---

## 17. Labs

1. Deploy Sysmon + a free EDR/Wazuh in a lab.
2. Generate Office→PowerShell; compare telemetry.
3. Test LSASS access detection with a benign tool.
4. Inject a benign DLL; observe injection events.
5. Create persistence; find it via EDR queries.
6. Hunt rare parent-child pairs in your lab.
7. Test isolation and live response on a VM.
8. Create an exclusion and demonstrate the blind spot.
9. Compare EDR vs Sysmon vs Windows logs for one incident.
10. Write an investigation report from EDR telemetry alone.

---

## 18. Self-test questions

1. Difference between AV, EPP, EDR, XDR, MDR?
2. What telemetry does EDR collect that Windows logs do not?
3. How does EDR detect process injection?
4. What is prevalence, and why does it matter?
5. What are three response actions and their risks?
6. Why isolate instead of shutting down?
7. What is tamper protection?
8. Why are exclusions dangerous?
9. What are three EDR blind spots?
10. How do you hunt for LSASS access?
11. What is the difference between a detection and a hunt?
12. How does EDR integrate with identity?
13. What should you preserve before killing a process?
14. How do you measure EDR coverage?
15. Why is EDR insufficient alone?

---

## 19. One-page revision checklist

- [ ] Definitions: AV, EPP, EDR, XDR, MDR, NDR, HIDS, SIEM.
- [ ] Architecture: kernel driver/callbacks, minifilter, ETW, user-mode hooks, memory scan, AMSI, network; cloud console; deployment models.
- [ ] Telemetry: process create/terminate, module load, file, registry, network, DNS, script, injection, credential access, service/task/driver, logon, USB, tamper; key fields.
- [ ] Capabilities: detection (signature, behavioural, ML, IOC, script, ransomware, exploit, device control) and response (isolate, kill, quarantine, live shell, collect, block, rollback, scan).
- [ ] Detection patterns (15) and why detections work/fail.
- [ ] Hunting: hypothesis → telemetry → query → baseline/prevalence → triage → pivot → document/convert.
- [ ] Response discipline: confirm, preserve memory, isolate nuances, kill tree, persistence, quarantine/rollback, live response read-only + logging + chain of custody.
- [ ] Deployment: coverage, health (version/heartbeat/policy/tamper/sensor), policies (prevent vs detect), permissions, collection level, retention.
- [ ] Tuning/exclusions: owner/justification/scope/expiry, narrow, never temp/user-writable/PowerShell, review, monitor changes; performance.
- [ ] Limitations: hook bypass, rootkits/BYOVD, encrypted scripts, LOLBins, tamper, offline, network-only, cloud, exclusions, retention, alert-only, volume; complement with SIEM/NDR/email/cloud.
- [ ] Alerts: types, triage steps, severity considerations.
- [ ] Investigation: endpoint → process → behaviour → persistence → creds → scope → contain/collect → eradicate/recover.
- [ ] Integration: SIEM, SOAR, TI, identity, email, firewall, ticketing, vuln mgmt, NDR.
- [ ] Vendors: CrowdStrike, MDE, SentinelOne, Cortex XDR, Trend, Sophos; Wazuh, Velociraptor, osquery, Sysmon.
- [ ] Pitfalls list memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Alerting](Alerting.md) · [IDS / IPS →](IDS-IPS.md)
