# Network Traffic — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Logs](Logs.md) · [SIEM →](SIEM.md)

> Goal: read network evidence — packets, flows, and protocol metadata — to answer "what talked to what, how much, and does it look normal?"
> Protocol details → `01 - Networking Fundamentals/`; IDS rules → [IDS-IPS.md](IDS-IPS.md); alerting → [Alerting.md](Alerting.md).

---

## 0. How to use this note

1. §1–§3: why traffic matters; capture points; packet vs flow.
2. §4–§7: capture and analysis tooling; reading a session.
3. §8–§11: protocol focus — DNS, HTTP/TLS, SMB/auth, others.
4. §12–§14: hunting patterns — beaconing, tunnelling, exfil, lateral, scans.
5. §15–§18: workflow, evidence handling, pitfalls, commands.
6. §19–§21: labs, self-test, revision.

---

## 1. Why network traffic matters

- Network evidence shows **what actually left and entered** the estate.
- It reveals **C2, exfiltration, lateral movement, and data access** that endpoint logs may miss.
- It provides **independent corroboration** of endpoint/host findings.
- It is essential when endpoints are unmanaged, encrypted at rest, or offline.
- Flow data scales to whole estates; packets give ground truth.

**Core questions traffic answers:**
1. Which internal host talked to which external service?
2. How much data, over what period, in which direction?
3. What protocol/application, and was it normal for that asset?
4. Was the destination known-bad, rare, or newly registered?
5. Did the session succeed (handshake, auth, response codes)?

---

## 2. Capture points

| Point | Sees | Notes |
|---|---|---|
| **Perimeter egress** | All outbound | Best for C2/exfil. |
| **Perimeter ingress** | All inbound | Attacks, scans. |
| **DMZ** | Internet-facing services | Exploit attempts, webshells. |
| **Core/internal** | East-west | Lateral movement. |
| **Server VLAN** | Server traffic | Data access, DC traffic. |
| **Cloud VPC mirror** | Cloud workloads | Depends on provider. |
| **Host capture** | One endpoint | Encrypted app context, precise. |
| **Proxy logs** | HTTP/S metadata | Decrypted at proxy if TLS inspection. |
| **DNS logs** | Resolution | Cheap, high-value. |
| **Firewall/flow logs** | Connections | Scalable, no payload. |

**Design principle:** capture at **choke points** (egress, DC entry, AD servers) and rely on **flow + metadata** broadly, **full PCAP** selectively.

---

## 3. Packets vs flows vs metadata

| Layer | Data | Volume | Use |
|---|---|---|---|
| **PCAP** | Full packets | Very high | Deep analysis, proof, malware extraction. |
| **Protocol metadata** | Per-session fields (Zeek/Suricata eve) | Medium | Hunting, baselines, context. |
| **Flow (NetFlow/IPFIX)** | 5-tuple + bytes/packets/time | Low | Estate-wide visibility, anomaly, retention. |

**Rule of thumb:**
- Flows answer **"who/how much/when"**.
- Metadata answers **"what protocol/domain/cert/user-agent"**.
- PCAP answers **"exactly what happened"**.

**Retention:** flows 30–90+ days; metadata 7–30 days; PCAP hours–days (or on-demand).

---

## 4. Tooling

| Tool | Purpose |
|---|---|
| **tcpdump** | CLI capture/filter. |
| **tshark** | CLI Wireshark, field extraction. |
| **Wireshark** | GUI deep analysis. |
| **Zeek** | Structured protocol logs. |
| **Suricata** | Alerts + eve.json metadata. |
| **Argus / nfdump / SiLK** | Flow analysis. |
| **Moloch/Arkime** | Large-scale PCAP indexing/search. |
| **NetworkMiner** | File/artifact extraction. |
| **ngrep** | Pattern grep on traffic. |

---

## 5. Capturing correctly

### 5.1 Capture filters (BPF) vs display filters

```bash
# Capture: host + port
tcpdump -i eth0 -nn 'host 10.0.0.5 and port 443'

# Capture: exclude noise
tcpdump -i eth0 -nn 'not port 22 and not arp'

# Capture: rotate files, size limit
tcpdump -i eth0 -nn -w cap-%Y%m%d-%H%M%S.pcap -G 3600 -C 500

# Count rather than capture
tcpdump -i eth0 -nn -c 100 'udp port 53'
```

### 5.2 Snaplen and loss

- `-s 0` = full packet (needed for payload).
- Smaller snaplen = headers only (privacy/perf).
- Watch **kernel drop** stats: `tcpdump -i eth0 -nn` prints "packets dropped by kernel".

### 5.3 Time

- Capture with **UTC**, consistent with SIEM.
- Record **start/end** and **interface**.
- NTP matters; skewed capture times break correlation.

---

## 6. Reading a session

### 6.1 TCP fundamentals reminder

```
SYN → SYN/ACK → ACK            (handshake)
data / ACK ...
FIN/ACK → ACK → FIN/ACK → ACK  (teardown)
RST                            (abort/refuse)
```

**Red flags in a session:**
- SYN with no SYN/ACK (blocked/filtered/firewall).
- SYN/ACK then RST (service refused).
- Handshake then immediate RST (reset by middlebox/IDS).
- Very long-lived idle sessions (beacon keepalive).
- Asymmetric byte counts (upload-heavy = exfil).
- Repeated retransmissions (network issue or evasion).

### 6.2 What to extract per session

| Field | Why |
|---|---|
| 5-tuple | Identity. |
| Start/end/duration | Pattern. |
| Bytes in/out | Exfil, download size. |
| Packets | Retransmits, overhead. |
| Application protocol | Expected vs actual. |
| SNI/host/URI | Destination intent. |
| User agent / cert | Client identity. |
| Status code / result | Success/failure. |
| Process (if host/EDR) | Attribution. |

---

## 7. Analysis workflow

1. **Frame the question** ("did host X exfiltrate?").
2. **Start with flows** to find candidate sessions.
3. **Narrow with metadata** (domain, SNI, user-agent, bytes).
4. **Pull PCAP** for the candidate window.
5. **Reassemble and inspect** (follow stream, export objects).
6. **Extract indicators** (domains, IPs, hashes, URLs).
7. **Correlate** with DNS, proxy, EDR, auth logs.
8. **Document** evidence with timestamps and hashes.

---

## 8. DNS — highest-value protocol

### 8.1 Why

- Nearly every connection starts with DNS.
- Cheap to log, hard to fully encrypt (DoH being the exception).
- Reveals intent: domains, DGA, tunnelling, C2.

### 8.2 What to look for

| Pattern | Indicator |
|---|---|
| **DGA** | High-entropy, random labels, many NXDOMAIN. |
| **Tunnelling** | Long labels, high volume, TXT/NULL/CNAME abuse. |
| **Beaconing** | Periodic queries to rare domain. |
| **Newly registered** | Young domain age. |
| **Typosquats** | Lookalike brand names. |
| **Fast flux** | Many A records, short TTL, rapid change. |
| **DoH to unknown resolver** | Bypass of DNS logging. |
| **Rare TLD/record type** | Unusual for the estate. |

### 8.3 Queries

```bash
# High-volume DNS talkers
tcpdump -i eth0 -nn 'udp port 53' -c 1000

# Zeek DNS summary
cat dns.log | zeek-cut query qtype_name rcode | sort | uniq -c | sort -rn | head

# Long labels (tunnelling heuristic)
cat dns.log | zeek-cut query | awk '{ if (length($0) > 60) print }'
```

```spl
index=dns
| eval label_len=len(query)
| stats count avg(label_len) as avg_len dc(query) as uniq by src
| where avg_len > 40 or uniq > 500
```

### 8.4 False positives

- CDNs, telemetry, antivirus, SaaS, load balancers.
- Baseline per asset type before alerting.

---

## 9. HTTP / HTTPS

### 9.1 Cleartext HTTP

Extract: method, host, URI, user-agent, status, content-type, body size, referer.

**Red flags:** long query strings, encoded payloads, unusual user-agents, uploads to unknown hosts, direct-to-IP requests, missing host header.

### 9.2 HTTPS without inspection

You still get: SNI, certificate (issuer, CN, validity, SAN), JA3/JA4, byte counts, timing, destination reputation.

**Red flags:**
- Self-signed/odd certs on external hosts.
- SNI not matching cert.
- Rare JA3/JA4 fingerprint for the estate.
- Domain fronting indicators (SNI vs Host mismatch at proxy).
- Long-lived periodic connections.

### 9.3 TLS inspection

- Enables payload visibility but has **legal, privacy, and performance** implications.
- Never inspect banking/health sites without policy.
- Certificate pinning breaks apps — handle exceptions.

### 9.4 Proxy logs

Often the **best** HTTP source: URL, category, user, bytes, action, user-agent. Correlate proxy user with endpoint user.

---

## 10. SMB and authentication traffic

| Protocol | Port | Watch for |
|---|---|---|
| **SMB** | 445 | Lateral movement, admin shares, PsExec, ransomware. |
| **Kerberos** | 88 | Kerberoasting (RC4 tickets), AS-REP roasting, unusual SPNs. |
| **LDAP** | 389/636 | Enumeration, BloodHound queries. |
| **RDP** | 3389 | Remote access, brute force. |
| **WinRM** | 5985/5986 | Remote execution. |
| **NTLM** | — | Relay, downgrade. |

**Patterns:**
- One host → many hosts on 445 (spread).
- Admin share access (`C$`, `ADMIN$`) from unusual hosts.
- Kerberos RC4 (`etype 23`) requests for many SPNs.
- NTLM auth to many hosts.

> AD attack detail → [03 - Cybersecurity Fundamentals/Common-Attacks.md](../03%20-%20Cybersecurity%20Fundamentals/Common-Attacks.md); Windows events → [02 - Operating Systems/Windows-Event-Logs.md](../02%20-%20Operating%20Systems/Windows-Event-Logs.md).

---

## 11. Other protocols worth knowing

| Protocol | Port | Use/risk |
|---|---|---|
| **SSH** | 22 | Admin access; brute force; tunnelling. |
| **FTP/SFTP** | 21/22 | Cleartext creds/data. |
| **SMTP** | 25/587 | Phishing, spam. |
| **ICMP** | — | Tunnelling, recon. |
| **NTP** | 123 | Amplification, time attacks. |
| **SNMP** | 161 | Default community strings, recon. |
| **DHCP** | 67/68 | Rogue server. |
| **mDNS/LLMNR/NBNS** | — | Poisoning, relay. |
| **QUIC/HTTP3** | 443/UDP | Encrypted, harder to inspect. |
| **Tor** | 9001/9030/443 | Anonymisation. |

---

## 12. Hunting: beaconing

### 12.1 What it looks like

- Regular intervals (fixed or jittered).
- Small, consistent request/response sizes.
- Same destination, often rare domain.
- Long duration across days.
- Survives reboots.

### 12.2 Detection approach

```
For each (src, dst, port):
  compute inter-arrival times
  compute coefficient of variation (low CV = periodic)
  compute session size consistency
  compute destination rarity
```

### 12.3 Query sketch

```spl
index=proxy
| bin _time span=1m
| stats count by src, dest, _time
| stats stdev(count) as sd avg(count) as avg dc(_time) as minutes by src, dest
| where minutes > 30 and sd < 2 and avg < 5
```

**Caution:** NTP, telemetry, update checks, and SaaS heartbeats are periodic. Filter known-good.

---

## 13. Hunting: tunnelling and exfiltration

### 13.1 Tunnelling indicators

- DNS: long labels, high query volume, TXT records.
- ICMP: large/regular payloads.
- HTTP: long URIs, base64, unusual content types.
- SSH: long-lived sessions to rare external hosts.
- Protocol on wrong port (SSH over 443, DNS over 53/TCP unusually).

### 13.2 Exfiltration indicators

- Large **outbound** volume relative to normal.
- Upload:download ratio inverted for the asset.
- Transfers to cloud storage/paste sites.
- Off-hours transfers.
- Archive file creation then upload.
- Sustained low-and-slow transfers (harder).

### 13.3 Queries

```spl
index=flow direction=outbound
| stats sum(bytes_out) as out sum(bytes_in) as in by src
| eval ratio=out/in
| where out > 100000000 and ratio > 3
```

```bash
# Zeek: top outbound talkers
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes \
  | awk '{o[$1]+=$3; r[$1]+=$4} END {for (h in o) print o[h], r[h], h}' \
  | sort -rn | head -20
```

---

## 14. Hunting: lateral movement and scanning

### 14.1 Lateral movement indicators

- Internal host → many internal hosts on admin ports (445, 3389, 5985, 22).
- Sequential IP sweeps.
- Authentication from unusual source hosts.
- SMB session with `ADMIN$`/`C$` access.
- Service creation remotely.
- DC traffic from non-admin workstations.

### 14.2 Scanning indicators

- Many destination ports from one source in short window.
- Many destinations on one port.
- SYN without complete handshakes.
- Distributed low-and-slow scans.

```spl
index=flow
| bin _time span=5m
| stats dc(dest_port) as ports dc(dest_ip) as hosts by src, _time
| where ports > 50 or hosts > 50
```

---

## 15. Evidence handling

- Record capture start/end, interface, filter, tool version.
- Hash PCAP files (SHA-256) at acquisition and after transfer.
- Store read-only; work on copies.
- Note timezone and clock source.
- Maintain chain of custody.
- Minimise PII exposure; redact in reports.
- Export only necessary artefacts (files, streams) with hashes.

---

## 16. Performance and storage

| Concern | Mitigation |
|---|---|
| **Volume** | Flow first, metadata second, PCAP selectively. |
| **Retention** | Tiered storage; roll PCAP. |
| **Loss** | Monitor drops; size sensors; use hardware capture. |
| **Search speed** | Index metadata (Arkime), not raw PCAP. |
| **Privacy** | Snaplen limits, access control, retention policy. |
| **Encryption** | Metadata + endpoint telemetry. |

---

## 17. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Only looking at PCAP, no flows | Miss the forest. |
| Only flows, no packets | Can't prove. |
| Ignoring DNS | Miss C2/tunnelling. |
| Assuming HTTPS = invisible | Miss metadata signals. |
| No baseline | Can't spot anomalies. |
| Clock skew | Wrong timeline. |
| Not monitoring drops | Silent gaps. |
| Over-retention of PCAP | Cost/privacy risk. |
| Treating volume as malicious alone | FP (backups, updates). |
| Correlation with wrong user | Mis-attribution (NAT, proxies). |
| No hashing/chain of custody | Evidence unusable. |
| Ignoring internal traffic | Miss lateral movement. |

---

## 18. Commands

```bash
# tcpdump
tcpdump -i eth0 -nn -s0 -w out.pcap 'host 10.1.1.10 and not port 22'
tcpdump -r out.pcap -nn -A 'tcp port 80' | less
tcpdump -i eth0 -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# tshark
tshark -r out.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tshark -r out.pcap -Y 'dns' -T fields -e dns.qry.name | sort | uniq -c | sort -rn
tshark -r out.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name
tshark -r out.pcap --export-objects http,./objects

# Zeek
zeek -r out.pcap local
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes | sort -k4 -rn | head
cat ssl.log  | zeek-cut server_name issuer subject
cat files.log | zeek-cut mime_type filename md5 sha1 | head

# Flow
nfdump -r nfcapd.current -s srcip/bytes -n 20
nfdump -r nfcapd.current -c 20
```

---

## 19. Labs

1. Capture and analyse a browser session; extract SNI and user-agent.
2. Build a Zeek conn.log summary of top talkers.
3. Simulate DNS tunnelling (iodine/dnscat in a lab); detect.
4. Simulate beaconing with a script; detect periodicity.
5. Export an HTTP object from PCAP and hash it.
6. Detect a port scan with flow data.
7. Identify SMB lateral movement between two lab hosts.
8. Compare proxy logs vs PCAP for the same session.
9. Compute JA3 for a lab client and compare to known tools.
10. Write an evidence-handling note for a PCAP you captured.

---

## 20. Self-test questions

1. When do you use flows vs PCAP?
2. What are the capture choke points?
3. How do you detect beaconing?
4. What DNS patterns indicate tunnelling?
5. What can you learn from TLS without decryption?
6. How do you spot exfiltration?
7. How do you detect lateral movement in flow data?
8. Why hash PCAP files?
9. What causes packet drops, and why does it matter?
10. How do you attribute traffic to a user behind NAT?
11. Why is DNS the highest-value protocol?
12. What is the risk of TLS inspection?
13. How do you baseline "normal" for an asset?
14. What are three false-positive sources for high-volume alerts?
15. What must a capture record include to be evidence?

---

## 21. One-page revision checklist

- [ ] Traffic value: independent corroboration, C2/exfil/lateral, works for unmanaged/offline endpoints.
- [ ] Capture points: egress, ingress, DMZ, core, server VLAN, cloud mirror, host, proxy, DNS, firewall flows; choke-point design; flow+metadata broad, PCAP selective.
- [ ] Packets vs metadata vs flows: question fit and retention (flows 30–90d, metadata 7–30d, PCAP hours–days).
- [ ] Tools: tcpdump, tshark, Wireshark, Zeek, Suricata, Argus/nfdump/SiLK, Arkime, NetworkMiner, ngrep.
- [ ] Capture: BPF filters, snaplen, rotation, drop monitoring, UTC/NTP, record start/end/interface.
- [ ] Session reading: handshake/teardown/RST patterns, duration, byte asymmetry, retransmits; extract 5-tuple, bytes, protocol, SNI/URI, UA/cert, status, process.
- [ ] Workflow: question → flows → metadata → PCAP → reassemble/export → indicators → correlate → document.
- [ ] DNS: DGA, tunnelling, beaconing, new domains, typosquats, fast flux, DoH, rare types; queries; FPs.
- [ ] HTTP/HTTPS: methods/URI/UA/status; SNI/cert/JA3/JA4/bytes/timing; inspection trade-offs; proxy logs as best source.
- [ ] SMB/auth: 445/88/389/3389/5985; lateral, Kerberoasting RC4, NTLM relay, admin shares.
- [ ] Other protocols: SSH, FTP, SMTP, ICMP, NTP, SNMP, DHCP, LLMNR/NBNS, QUIC, Tor.
- [ ] Beaconing: periodicity/CV, size consistency, rarity; query sketch; filter NTP/telemetry/SaaS.
- [ ] Tunnelling/exfil: DNS/ICMP/HTTP/SSH indicators; volume/ratio/off-hours/archive-then-upload; low-and-slow.
- [ ] Lateral/scan: admin ports fan-out, IP sweeps, SYN-only, distributed scans; query sketches.
- [ ] Evidence: record metadata, SHA-256, read-only copies, timezone, chain of custody, PII redaction, export artefacts with hashes.
- [ ] Performance: tiering, retention, drops, indexing, privacy, encryption.
- [ ] Pitfalls list memorised.
- [ ] Commands: tcpdump capture/filter, tshark fields/export, zeek-cut conn/ssl/files, nfdump top talkers.

---

> **Navigation:** [Roadmap index](../README.md) · [← Logs](Logs.md) · [SIEM →](SIEM.md)
