# IDS / IPS — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← EDR](EDR.md) · [Logs →](Logs.md)

> Goal: understand how network intrusion detection/prevention works, what its alerts mean, and when to believe or dismiss them.
> Network telemetry → [Network-Traffic.md](Network-Traffic.md); alerting → [Alerting.md](Alerting.md); packets → [01 - Networking Fundamentals/TCP-IP.md](../01%20-%20Networking%20Fundamentals/TCP-IP.md).

---

## 0. How to use this note

1. §1–§3: definitions; IDS vs IPS; detection methods.
2. §4–§6: placement, deployment, evasion.
3. §7–§9: rules, alerts, tuning.
4. §10–§13: encrypted traffic, NSM, triage, investigation.
5. §14–§17: pitfalls, commands, labs, self-test, revision.

---

## 1. What IDS/IPS is

- **IDS (Intrusion Detection System)** — monitors traffic, **alerts** on suspicious patterns. Passive.
- **IPS (Intrusion Prevention System)** — **inline**, can **block/drop** malicious traffic. Active.
- **NIDS/NIPS** — network-based.
- **HIDS/HIPS** — host-based (file/log/syscall).
- Often the same engine in different modes (detect vs prevent).

**Value:** catches known attack signatures, policy violations, scanning, exploit attempts, and some anomalies — at the network edge and internally.

**Limitation:** encryption, evasion, tuning, and signature lag.

---

## 2. IDS vs IPS

| Aspect | IDS | IPS |
|---|---|---|
| **Placement** | Out-of-band (SPAN/tap). | Inline (traffic path). |
| **Action** | Alert. | Alert + drop/reset. |
| **Latency** | None. | Adds latency. |
| **Risk** | Misses blocked traffic (no impact). | False positive = outage. |
| **Visibility** | Sees all traffic on segment. | Sees only what passes through. |
| **Failure mode** | Blind if tap fails. | Fail-open (blind) or fail-closed (outage). |

**Common pattern:** IDS at perimeter for visibility; IPS inline for critical segments; both feed SIEM.

---

## 3. Detection methods

| Method | How | Strengths | Weaknesses |
|---|---|---|---|
| **Signature** | Match known patterns. | Accurate for known attacks, fast. | Misses new/obfuscated; needs updates. |
| **Stateful protocol** | Track protocol state, flag violations. | Catches malformed/abused protocols. | Complex parsers; evasion. |
| **Anomaly** | Deviation from baseline. | Finds unknown. | Noisy; hard to tune. |
| **Reputation** | Known-bad IP/domain. | Cheap, useful. | Shared infra, false positives. |
| **Heuristic/behavioural** | Suspicious behaviour. | Broader coverage. | FP-prone. |
| **Policy** | Disallowed protocols/apps. | Enforces rules. | Bypass via allowed ports. |
| **ML** | Learned patterns. | Novel detection. | Opaque, drift. |

**Practical reality:** most deployments are **signature + reputation + some anomaly**, with tuning to control noise.

---

## 4. Placement and deployment

| Location | Sees | Use |
|---|---|---|
| **Perimeter (before firewall)** | All inbound. | Internet attacks, scans. |
| **After firewall (DMZ)** | Allowed inbound. | Actual attack surface. |
| **Internal/core** | East-west. | Lateral movement, malware spread. |
| **Data center** | Server-to-server. | Critical assets. |
| **Cloud VPC** | Cloud traffic (mirror/tap). | Cloud workloads. |
| **Host** | Host traffic. | Encrypted/endpoint context. |

### 4.1 Capture methods

- **SPAN/mirror port** — switch copies traffic.
- **Network tap** — passive optical/copper split.
- **Inline bridge** — traffic passes through.
- **Cloud traffic mirroring / VPC flow + packet mirror**.
- **Agent on host**.

### 4.2 Capacity planning

- Throughput (Gbps) vs sensor capacity.
- Packet size distribution.
- Session count.
- Storage for PCAP (if enabled).
- Drop rate monitoring — **dropped packets = blind spots**.

### 4.3 High availability

- Inline bypass (hardware/software).
- Fail-open vs fail-closed decision.
- Redundant sensors.
- Heartbeat monitoring.

---

## 5. Evasion techniques

| Technique | Description | Detection |
|---|---|---|
| **Fragmentation** | Split payload across packets. | Reassembly, normalisation. |
| **TCP segmentation overlap** | Conflicting segments. | Target-based reassembly. |
| **Encoding/obfuscation** | URL/Unicode/Base64. | Decode + normalise. |
| **Polymorphism** | Change payload each time. | Behavioural/anomaly. |
| **Protocol tunnelling** | Hide in DNS/HTTP/ICMP. | Anomaly, volume, entropy. |
| **Encryption** | TLS hides payload. | Metadata, JA3/JA4, certs. |
| **Slow scanning** | Evade thresholds. | Longer windows, baselines. |
| **Source spoofing/distributed** | Many IPs. | Reputation, behaviour. |
| **Insertion attacks** | Sensor sees different data than target. | Target-based modelling. |
| **Session splicing** | Split across sessions. | Stateful correlation. |

> **Encryption is the biggest limitation.** Modern IDS relies heavily on metadata, endpoints, and TLS inspection where lawful/appropriate.

---

## 6. Signatures vs behaviour in practice

**Signature example (Suricata):**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible SQL Injection in URI";
  flow:established,to_server;
  http.uri; content:"UNION"; nocase;
  content:"SELECT"; nocase; distance:0;
  classtype:web-application-attack; sid:1000001; rev:1;
)
```

**Behavioural example:** many failed connections to distinct ports (scan), or periodic beacon-like connections.

**Best practice:** signatures for known exploits; behavioural for post-exploitation; both mapped to ATT&CK.

---

## 7. Alerts: what they contain

| Field | Meaning |
|---|---|
| **Timestamp** | When seen (sensor clock!). |
| **Signature/SID/rev** | Which rule fired. |
| **Severity/priority** | Vendor-assigned. |
| **Source/destination IP/port** | Flow. |
| **Protocol/app** | HTTP, TLS, SMB, DNS. |
| **Action** | Allowed/blocked. |
| **Payload/flow** | Evidence (if captured). |
| **Sensor/interface** | Where seen. |
| **Direction** | Inbound/outbound/internal. |

**Read the whole alert.** A high-severity signature on an allowed flow to a patched server may be noise; a low-severity anomaly on a critical segment may matter more.

---

## 8. Tuning

### 8.1 Why tune

Default rulesets produce enormous noise; untuned IDS = ignored IDS.

### 8.2 Tuning levers

| Lever | Effect |
|---|---|
| **Disable irrelevant rules** | OS/app not in estate. |
| **Threshold** | Reduce repeated hits. |
| **Suppress** | Known-good source/dest/flow. |
| **Pass rules** | Exclude trusted traffic (careful). |
| **Severity adjust** | Re-prioritise. |
| **Flowbits/xbits** | Correlate multi-packet. |
| **Policy** | Align to environment. |

### 8.3 Tuning discipline

- Baseline hit counts by SID.
- Review top 20 noisy SIDs monthly.
- Suppress with **justification + expiry**.
- Never suppress entire categories (e.g., all web attacks) to reduce noise.
- Re-test after rule updates.

### 8.4 False positives vs false negatives

- **FP:** alert on benign traffic. Cost: fatigue.
- **FN:** miss attack. Cost: breach.
- Tuning trades one for the other — measure both.

---

## 9. Rule sources and management

| Source | Notes |
|---|---|
| **Vendor/ET Open/ET Pro** | Emerging Threats rulesets. |
| **Snort community/VRT** | Broad signature coverage. |
| **Suricata rules** | ET, custom. |
| **Custom rules** | Environment-specific. |
| **Threat intel feeds** | IOC-based. |

### 9.1 Rule hygiene

- Track SID/rev/date.
- Review new rules before enabling.
- Test in IDS mode before IPS.
- Document custom rules.
- Monitor rule update failures.
- Map rules to ATT&CK where possible.

---

## 10. Encrypted traffic

### 10.1 Options

| Option | Trade-off |
|---|---|
| **Metadata only** | No payload; privacy-friendly; limited. |
| **TLS inspection (MITM)** | Full visibility; legal/privacy/operational complexity. |
| **Endpoint telemetry** | Best for encrypted app activity. |
| **JA3/JA4 fingerprinting** | Identify clients/tools without decryption. |
| **Certificate/SNI analysis** | Domain and cert anomalies. |
| **Flow behaviour** | Volumes, timing, destinations. |

### 10.2 What you can still detect

- Malicious destinations (reputation).
- Rare/untrusted certificates.
- SNI mismatches, domain fronting indicators.
- Beacon periodicity (metadata).
- Large uploads.
- Unusual ports.

---

## 11. NSM and Zeek complement

- **Zeek** produces rich logs (conn, dns, http, ssl, files, notice) without signatures.
- **Suricata** can produce both alerts and `eve.json` with protocol metadata.
- **Argus/NetFlow** for flow-level.
- **PCAP** for deep investigation.

**Pattern:** Zeek/flow for hunting and baselines; IDS for known-bad; PCAP for proof.

---

## 12. Triage workflow

### Step 1 — Identify the alert
SID, signature, severity, action.

### Step 2 — Establish the flow
Source, destination, port, protocol, direction, bytes.

### Step 3 — Identify the asset
Internal host role, owner, criticality, exposure.

### Step 4 — Determine outcome
Blocked or allowed? Did the target respond (200, shell, RST)?

### Step 5 — Corroborate
Web logs, EDR, auth logs, DNS, proxy.

### Step 6 — Classify
FP, benign (scanner/pentest), attempted, successful.

### Step 7 — Respond
Block source, patch, isolate, escalate.

### Step 8 — Tune/document
Suppress known-good with justification; record evidence.

---

## 13. Investigation examples

| Alert | Next steps |
|---|---|
| **SQLi signature** | Check web logs for status/payload; look for shell child; assess DB errors. |
| **Scan detected** | Is source internal (compromised host) or external (recon)? Follow-up exploitation? |
| **Malware C2 signature** | Identify internal host/process; isolate; check EDR. |
| **Exploit attempt** | Was it blocked? Did service crash? Any child process? |
| **Policy violation** | Is protocol allowed? Data sensitivity? |
| **DNS tunneling** | Volume, entropy, destination reputation, host process. |
| **Brute force** | Auth logs, success, source diversity. |

---

## 14. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Untuned defaults | Alert fatigue. |
| Sensor overload | Dropped packets/blind spots. |
| Tap failure unnoticed | Silent blindness. |
| Ignoring encryption | False confidence. |
| No asset context | Can't prioritise. |
| Suppressing broad categories | Missed attacks. |
| No rule updates | Stale coverage. |
| IPS false positive | Outage. |
| Clock skew | Wrong correlation. |
| No PCAP capability | Hard to prove. |
| Alert-only, no triage | Useless deployment. |

---

## 15. Commands

```bash
# Suricata
suricata -T -c /etc/suricata/suricata.yaml -v          # test config
suricata -i eth0 -c /etc/suricata/suricata.yaml
tail -f /var/log/suricata/fast.log
jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | head

# Snort
snort -T -c /etc/snort/snort.conf
snort -A console -q -c /etc/snort/snort.conf -i eth0

# Capture / replay
tcpdump -i eth0 -w cap.pcap
tcpreplay -i eth0 cap.pcap
tcpdump -r cap.pcap -nn -A 'tcp port 80'

# Zeek
zeek -i eth0 local
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service
cat http.log | zeek-cut host uri method status_code

# Rules
grep -R "sid:1000001" /etc/suricata/rules/
suricatasc -c ruleset-stats
```

---

## 16. Labs

1. Deploy Suricata in IDS mode on a lab interface.
2. Generate scan/exploit traffic; observe alerts.
3. Write a custom rule for a lab attack; test.
4. Tune a noisy SID; measure before/after.
5. Test fragmentation evasion; enable normalisation.
6. Use Zeek logs to reconstruct a session.
7. Capture PCAP and analyse with Wireshark.
8. Simulate DNS tunneling; detect via volume/entropy.
9. Test inline IPS with a benign block rule.
10. Build an alert-to-triage runbook.

---

## 17. Self-test questions

1. Difference between IDS and IPS?
2. What is SPAN vs tap vs inline?
3. Name four detection methods and their trade-offs.
4. Why is encryption a fundamental limitation?
5. What is signature lag?
6. What are three evasion techniques?
7. What does a SID identify?
8. How do you tune a noisy rule?
9. Why monitor drop rate?
10. What is the difference between FP and FN?
11. What can JA3/JA4 tell you without decryption?
12. How does Zeek complement IDS?
13. What evidence proves an exploit attempt succeeded?
14. Why is fail-open a security risk?
15. How do you prioritise an IDS alert?

---

## 18. One-page revision checklist

- [ ] Definitions: IDS passive/alert, IPS inline/block, NIDS/NIPS, HIDS/HIPS; same engine different mode.
- [ ] IDS vs IPS table: placement, action, latency, risk, visibility, failure mode.
- [ ] Detection methods: signature, stateful protocol, anomaly, reputation, heuristic, policy, ML — strengths/weaknesses.
- [ ] Placement: perimeter, post-firewall, internal, data center, cloud, host; SPAN/tap/inline/cloud mirror/agent; capacity/drop rate; HA/bypass; fail-open vs fail-closed.
- [ ] Evasion: fragmentation, overlap, encoding, polymorphism, tunnelling, encryption, slow scan, distributed, insertion, splicing.
- [ ] Signatures vs behaviour; Suricata/Snort syntax basics; ATT&CK mapping.
- [ ] Alerts: timestamp, SID, severity, flow, protocol, action, payload, sensor, direction.
- [ ] Tuning: disable irrelevant, threshold, suppress, pass, severity, flowbits; baseline top SIDs; justification+expiry; FP vs FN trade-off.
- [ ] Rule sources/hygiene: ET, Snort, custom, TI; SID/rev, test before IPS, docs, updates, ATT&CK.
- [ ] Encrypted traffic: metadata, TLS inspection, endpoint, JA3/JA4, cert/SNI, flow behaviour; what remains detectable.
- [ ] NSM: Zeek, Suricata eve.json, Argus/NetFlow, PCAP.
- [ ] Triage: alert → flow → asset → outcome → corroborate → classify → respond → tune/document.
- [ ] Investigation examples: SQLi, scan, C2, exploit, policy, DNS tunnel, brute force.
- [ ] Pitfalls list memorised.
- [ ] Commands: suricata -T/eve.json, snort -T, tcpdump, tcpreplay, zeek/zeek-cut, rule grep/suricatasc.

---

> **Navigation:** [Roadmap index](../README.md) · [← EDR](EDR.md) · [Logs →](Logs.md)
