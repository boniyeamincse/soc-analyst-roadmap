# Firewalls — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← DNS](DNS.md) · [HTTP / HTTPS →](HTTP-HTTPS.md)

> Goal: understand how firewalls make and log decisions, so you can **read perimeter/egress logs, tell a blocked scan from a real intrusion, hunt for C2/exfil, and tune noisy rules**.
> DNS-specific concepts live in [DNS.md](DNS.md); VPN tunnelling in [VPNs.md](VPNs.md). This note does not repeat them.

---

## 0. How to use this note

1. §1–§5 build the model: what a firewall is, how sessions and rules work, zones/NAT.
2. §6–§9 cover modern firewall features and the logs they produce.
3. §10–§14 are the SOC work: telemetry, detections, investigation, triage.
4. §15–§17 cover tooling, false positives, and hardening.
5. §18–§20 are practice, self-test, and revision.

---

## 1. Why firewalls matter to a SOC analyst

- The firewall is the **primary enforcement and observation point** for network policy: what may talk to what, on which port, in which direction.
- It produces **allow and deny logs** for every session — the backbone of network detection and incident scoping.
- Most attacks cross at least one firewall boundary: phishing callback, C2 egress, lateral SMB/RDP, data exfiltration, VPN brute force.
- Firewalls also fail: **permissive any-any rules, shadowed rules, missing egress control, disabled logging, TLS blind spots** — SOC must know these gaps.

**SOC outcomes:** from a firewall log line you can answer:
- Who initiated? (`src_ip`, `src_port`, user/asset if enriched)
- To where? (`dst_ip`, `dst_port`, `dst_host`, geo/ASN)
- Allowed or denied? (`action`), by which rule/policy?
- What protocol/app? (`proto`, `app`, `url`, `sni`)
- Bytes/packets/duration — is it a beacon, a transfer, or a scan?
- Is this expected for this asset/time, and what is the next step?

---

## 2. Firewall types and where they sit

| Type | Layer | How it decides | SOC notes |
|---|---|---|---|
| **Packet filter (stateless ACL)** | L3/L4 | 5-tuple per packet, no memory | Cheap, weak; can't tell a reply from an unsolicited packet. Router ACLs, cloud NACLs. |
| **Stateful firewall** | L3/L4 | Connection table (state) + rules | The baseline. Understands `NEW`, `ESTABLISHED`, `RELATED`. |
| **Proxy / application gateway** | L7 | Terminates and re-originates connections | Deep visibility, but breaks end-to-end TLS unless inspected. |
| **NGFW** | L3–L7 | 5-tuple + App-ID + user + content + threat intel | App-ID, URL filtering, IPS, TLS inspection, sandbox. Main enterprise log source. |
| **UTM** | Mixed | Bundled NGFW-ish features | Common in SMBs; feature quality varies. |
| **WAF** | L7 HTTP | HTTP request/response signatures | Protects web apps; logs are HTTP-centric. |
| **Host firewall** | Host | Local rules per process/port | Windows Defender Firewall, iptables/nftables, ufw — process attribution is the win. |
| **Cloud firewall / security group** | Virtual | Allow rules attached to workloads | AWS SG/NACL, Azure NSG/ASG, GCP VPC firewall. Default-deny, but logging often off. |
| **Virtual/NFV firewall** | Virtual | Same as appliance | Cloud/VMware edge; watch for misconfigured "any" rules. |
| **Microsegmentation** | Workload | Identity/label-based policy | East-west control; deny logs are high-value. |

### North-south vs east-west

- **North-south** — traffic entering/leaving the data centre or cloud (internet ⇄ internal).
- **East-west** — server-to-server and host-to-host inside (lateral movement).
- Most SOC coverage is north-south; **east-west is where ransomware spreads**. Internal segmentation firewall logs are critical.

### Zones

| Zone | Typical contents | Policy intent |
|---|---|---|
| **Untrusted / Internet** | Public internet | Default deny inbound; tightly controlled outbound. |
| **DMZ** | Public-facing servers | Reachable from internet on specific ports; limited reach into internal. |
| **Internal / Trusted** | User and server LANs | Controlled egress; no direct inbound from internet. |
| **Management** | Firewall/network device admin | Restricted to jump hosts; never internet-facing. |
| **Guest / IoT** | Untrusted devices | Internet-only, isolated from corporate. |
| **Cloud VPC/VNet** | Workloads | Default-deny SG rules, explicit egress. |

> Zone design is a **security control**. Flat networks with one "internal" zone make lateral movement trivial and deny logs useless.

---

## 3. How stateful inspection works (the mental model)

### 3.1 The connection table

A stateful firewall records each session with at least:
`src_ip, src_port, dst_ip, dst_port, protocol, state, timeout, sequence tracking, NAT translation`.

States (vendor naming varies): `NEW` (first packet, e.g. TCP SYN), `ESTABLISHED` (bidirectional traffic seen), `RELATED` (e.g. FTP data, ICMP errors tied to a session), `INVALID` (doesn't fit any state — suspicious), `CLOSED/TIME_WAIT`.

### 3.2 TCP handshake through a firewall

1. Client sends `SYN` → firewall matches a rule; state `NEW`.
2. Server replies `SYN/ACK` → `ESTABLISHED`.
3. Client sends `ACK` → session established.
4. `FIN`/`RST` teardown; state ages out after timeout.

Consequences:
- Return traffic is allowed by state, **not** by a reverse rule — misreading this creates confusion ("why is inbound allowed?").
- **Asymmetric routing** breaks state: if the reply bypasses the firewall, the session stalls and logs show repeated SYN or INVALID.
- **Session timeouts** let attackers keep long-lived beacons alive with keepalives; default TCP timeout is often 1 hour, UDP 30–60 s.

### 3.3 TCP flags you will read in logs

| Flag | Meaning | SOC relevance |
|---|---|---|
| `SYN` | Connection attempt | Scans, new sessions, beacons. |
| `SYN/ACK` | Server accepting | Reachable service. |
| `ACK` | Acknowledging | Often used in ACK scans / stateless bypass. |
| `FIN`, `RST` | Teardown / refusal | RST floods, resets from IPS, closed ports. |
| `PSH` | Push data | Data transfer. |
| `URG`, `NULL`, `XMAS` | Odd combinations | Evasion/scan attempts. |

### 3.4 Fragmentation and evasion

- Fragmented packets can slip past naive filters; modern firewalls reassemble or drop.
- Overlapping fragments, tiny fragments, and malformed headers are evasion techniques — INVALID/drop logs matter.
- **Log what is dropped**, not just what is allowed; drops are detection signal.

---

## 4. Rule anatomy and evaluation

### 4.1 A rule usually contains

| Element | Example |
|---|---|
| **Action** | allow / deny / drop / reject / log-only |
| **Direction** | inbound / outbound / both, or zone→zone |
| **Source** | any, `10.0.0.0/8`, address object, user/group, geo |
| **Destination** | any, host object, FQDN, URL category |
| **Service/port** | `tcp/443`, `tcp/3389`, `any` |
| **Application** | App-ID (`ssl`, `dns`, `facebook-chat`) |
| **User** | AD/Entra group (User-ID) |
| **Schedule** | time-based |
| **Logging** | none / session end / at start / both |
| **Profile** | IPS, AV, URL, file, SSL inspection |

### 4.2 Evaluation order

- Most firewalls evaluate **top-down, first match wins** (some platforms are best-match or zone-pair based).
- **Shadowed rule** — an earlier broader rule makes a later specific rule unreachable.
- **Redundant rule** — duplicates another.
- **Orphaned rule** — references a decommissioned object.
- **Any-any** — allows everything; usually a temporary rule that survived.

> Rule hygiene is a SOC/GRC finding: any-any, shadowed denies, and unlogged rules are common and exploitable.

### 4.3 Deny vs drop vs reject (does it matter?)

- **Drop** — silently discard; sender times out. Scans look slower; logs show drops.
- **Reject** — send RST/ICMP unreachable; faster failure, reveals the host exists.
- **Deny** — vendor-specific; may mean drop or reject.
- For SOC: **a spike in drops from one source** = scan; **a single drop then success** = probing/retry; **repeated drops to many ports** = sweep.

---

## 5. NAT and what it does to logs

| NAT type | What happens | Log consequence |
|---|---|---|
| **SNAT / PAT** | Many internal IPs → one public IP with ports | Logs show translated source; you must map back via NAT table/timestamp. |
| **DNAT / port forward** | Public IP:port → internal server | Logs show public dst; map to internal asset. |
| **Static NAT** | 1:1 | Easier mapping; still record original. |
| **Hairpin/NAT loopback** | Internal clients reach public IP of internal server | Can look like external traffic; know your NAT design. |

**Investigation rule:** always determine whether the logged IP is **pre- or post-NAT**. Ambiguity here produces wrong scoping. Capture `translated_src`/`translated_dst` if available and record both.

---

## 6. NGFW capabilities that change detection

| Feature | What it does | SOC value / blind spot |
|---|---|---|
| **App-ID / application control** | Identifies apps regardless of port (e.g. SSH on 443) | Catches port-hopping; may miss custom protocols. |
| **URL filtering** | Category + reputation per URL/FQDN | Phishing/malware category hits; encrypted URLs limited. |
| **IPS** | Signature/anomaly detection inline | Exploit attempts, scan signatures; tuning required. |
| **TLS/SSL inspection** | Decrypts outbound/inbound TLS | Deep visibility; privacy/legal and performance costs; pinned apps break. |
| **DNS security** | Sinkholes/blocks malicious domains at the firewall | Complements resolver logs; see [DNS.md](DNS.md). |
| **File/sandbox** | Extracts and detonates files | Zero-day verdicts; latency and coverage limits. |
| **User-ID** | Maps IP → AD user | Turns IP logs into user attribution; breaks on shared hosts/VPN. |
| **Geo-IP / geo-block** | Blocks by country | Reduces noise, but attackers use proxies/cloud. |
| **DLP** | Detects sensitive data patterns | Exfil signal; false positives on templates. |
| **SD-WAN / ZTNA** | Policy by identity/app | New log formats; different semantics. |

**TLS inspection caveat:** if you don't decrypt, you see only SNI/IP/port and certificate metadata. Beaconing to a CDN or DoH traffic becomes nearly invisible. Cross-reference proxy and EDR.

---

## 7. Firewall log formats and fields

### 7.1 Common transports

- **Syslog** (UDP/TCP 514, TLS 6514) — most appliances.
- **CEF** (ArcSight), **LEEF** (QRadar), **JSON**, **CSV**, **NetFlow/IPFIX** (metadata only).
- **Cloud-native**: AWS VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs.
- **Windows Firewall** — Security event log 5156/5157 (allowed/blocked) when audit is enabled.

### 7.2 Field cheat sheet

| Field | Meaning |
|---|---|
| `timestamp` | Normalise to UTC. |
| `src_ip`, `src_port` | Initiator. |
| `dst_ip`, `dst_port` | Destination. |
| `proto` | TCP/UDP/ICMP/etc. |
| `action` | allow/deny/drop/reject/reset. |
| `rule` / `policy_id` / `rule_name` | Which rule matched (critical for "why allowed?"). |
| `interface` / `zone` | Ingress/egress. |
| `app` / `service` | App-ID or port-based service. |
| `url` / `sni` / `host` | L7 destination (if available). |
| `bytes_sent`, `bytes_received`, `packets` | Volume; exfil/beacon analysis. |
| `duration` / `elapsed` | Long-lived sessions = tunnels/keepalives. |
| `session_id` / `conn_id` | Correlate start/end records. |
| `nat_src`, `nat_dst` | Translation. |
| `user` | User-ID enrichment (if present). |
| `threat_name` / `severity` | IPS/AV verdicts. |
| `category` | URL category. |
| `repeat_count` | Aggregated repeated events (some platforms). |
| `reason` | Why dropped (policy, scan, reputation). |

### 7.3 Flow logs vs session logs

- **Flow logs** (NetFlow/IPFIX/VPC Flow) = metadata: 5-tuple, bytes, packets, timestamps, action. No payload, no app.
- **Session/firewall logs** = richer: rule, app, URL, threat, user.
- **Syslog from the firewall** may split start/end records; join on `session_id`.

### 7.4 Windows host firewall events

| Event ID | Meaning |
|---|---|
| **5156** | Connection allowed (verbose; needs audit policy). |
| **5157** | Connection blocked. |
| **5155** | Rule blocked listening. |
| **4946/4947** | Firewall rule added/changed (audit). |
| **4950** | Setting changed. |

> Host firewall logs give **process** context that perimeter logs cannot.

---

## 8. Cloud firewall logging (know the names)

| Cloud | Control | Log | Notes |
|---|---|---|---|
| **AWS** | Security Group (stateful, allow-only), NACL (stateless) | VPC Flow Logs (`ACCEPT`/`REJECT`, `NODATA`) | SG has no deny rules; `REJECT` comes from NACL. Flow logs are metadata only; enable at ENI/VPC/subnet. |
| **AWS** | Network Firewall | Alert/flow logs | Stateful managed firewall; has Suricata-style rules. |
| **Azure** | NSG (stateful), ASG, Azure Firewall | NSG flow logs, Firewall logs | NSG rules have priority numbers; `Deny` explicit. |
| **GCP** | VPC firewall rules (hierarchical) | VPC Flow Logs, Firewall Rules Logging | Priority-based; implied deny ingress / allow egress by default. |
| **Kubernetes** | NetworkPolicy / CNI policies | CNI/flow logs | Default-allow unless policies exist. |

SOC gotchas:
- Cloud flow logs are **sampled** in some configurations — absence of evidence is not evidence of absence.
- SG changes are **control-plane events** — enable CloudTrail/Activity Log and alert on changes.
- Egress is often **wide open** by default — the top cloud detection gap.

---

## 9. Firewalls and the attack lifecycle

| Phase | Firewall-visible behaviour | Detection idea |
|---|---|---|
| **Recon** | Port scans, sweeps, service probes; many denies | Deny spikes, sequential ports, many dst hosts. |
| **Initial access** | Phishing callback, exploit attempt to DMZ, VPN brute force | Blocked exploit signatures, VPN auth failures, new egress. |
| **Execution/C2** | Beaconing to rare IPs/domains, non-standard ports, long sessions | Periodic egress, low-and-slow bytes, unusual ports. |
| **Lateral movement** | SMB 445, RDP 3389, WinRM 5985/5986, SSH 22 east-west | Internal denies/allows from workstations to servers. |
| **Exfiltration** | Large uploads, cloud storage, DNS/HTTPS tunnels, off-hours | Bytes-out anomalies, destination category, duration. |
| **Impact** | Ransomware C2, mass SMB, backup destruction | Burst east-west, blocked lateral attempts. |

### Ports worth memorising (firewall/SOC context)

| Port | Service | Why it matters |
|---|---|---|
| 22 | SSH | Admin access; brute force; tunneling. |
| 23 | Telnet | Cleartext; should be rare. |
| 25/587 | SMTP submission | Spam/mail abuse. |
| 53 | DNS | Tunneling (see [DNS.md](DNS.md)). |
| 80/443 | HTTP/S | C2, exfil, phishing. |
| 135/139/445 | RPC/NetBIOS/SMB | Lateral movement, ransomware. |
| 389/636 | LDAP/LDAPS | AD enumeration; cleartext binds. |
| 1433/1521/3306/5432/27017 | Databases | Direct DB access is a red flag from user LAN. |
| 3389 | RDP | Brute force, lateral movement. |
| 5985/5986 | WinRM | Remote admin abuse. |
| 8080/8443 | Alt HTTP/S | Proxies, admin panels, C2. |
| 853 | DoT | Encrypted DNS bypass. |

---

## 10. Detection engineering with firewall logs

> Baseline first. Volume rules without baselines produce alert fatigue and get disabled.

### 10.1 High-signal ideas

1. **Inbound deny spike / scan** — many denies from one source across ports/hosts.
2. **Egress to rare destinations** — destination never seen in 30 days, especially from servers.
3. **Egress on unusual ports** — outbound to 4444, 1337, 8080, 9001, 53/TCP, high ports.
4. **Beaconing periodicity** — repeated connections with near-constant interval and similar bytes.
5. **Long-lived sessions** — duration far above asset baseline.
6. **Large uploads** — bytes_out > threshold to external, off-hours.
7. **Server-initiated internet traffic** — servers should rarely browse; high signal.
8. **Workstation-to-workstation SMB/RDP** — lateral movement.
9. **Any-any / rule change** — firewall policy modified (audit log).
10. **TLS to rare SNI / SNI-IP mismatch** — domain fronting/CDN abuse.
11. **Geo anomaly** — first-ever egress to a high-risk country for this asset.
12. **VPN brute force / spray** — many failed VPN auths, then a success.
13. **Blocked exploit signature** — IPS hit followed by successful session.
14. **Cloud SG opened to 0.0.0.0/0** — control-plane change.
15. **Data to anonymisers** — Tor exit nodes, VPN providers, proxy services.

### 10.2 Splunk SPL examples

**Top denied sources (scan candidates):**
```spl
index=firewall action=deny OR action=drop OR action=blocked
| stats count dc(dst_ip) as targets dc(dst_port) as ports by src_ip
| where targets > 20 OR ports > 20
| sort -count
```

**Deny spike in 5-minute buckets:**
```spl
index=firewall (action=deny OR action=drop)
| bin _time span=5m
| stats count by src_ip, _time
| where count > 500
| sort -count
```

**Outbound to rare destinations (30-day lookback approximation):**
```spl
index=firewall direction=outbound action=allow
| stats count earliest(_time) as first latest(_time) as last by src_ip, dst_ip
| where count < 5
| sort first
```

**High outbound bytes to external:**
```spl
index=firewall direction=outbound action=allow NOT (dst_ip="10.0.0.0/8" OR dst_ip="172.16.0.0/12" OR dst_ip="192.168.0.0/16")
| stats sum(bytes_out) as out_bytes by src_ip, dst_ip
| where out_bytes > 100000000
| sort -out_bytes
```

**Unusual destination ports from internal hosts:**
```spl
index=firewall direction=outbound action=allow
| where NOT (dst_port IN (80,443,53,123,25,587,993,995))
| stats count by src_ip, dst_port, dst_ip
| where count > 10
| sort -count
```

**Server-initiated browsing (requires asset lookup):**
```spl
index=firewall action=allow direction=outbound dst_port IN (80,443)
| lookup asset_inventory ip AS src_ip OUTPUT asset_type, owner
| where asset_type="server"
| stats count by src_ip, dst_ip, dst_port
```

**Beacon heuristic (constant interval):**
```spl
index=firewall action=allow direction=outbound
| sort 0 src_ip, dst_ip, dst_port, _time
| streamstats current=f window=1 last(_time) as prev_time by src_ip, dst_ip, dst_port
| eval delta=_time-prev_time
| stats count stdev(delta) as jitter avg(delta) as avg_delta by src_ip, dst_ip, dst_port
| where count > 20 AND jitter < 5 AND avg_delta < 300
```

### 10.3 Microsoft Sentinel / Defender KQL examples

**Inbound rejects by source (CommonSecurityLog — vendor-dependent fields):**
```kusto
CommonSecurityLog
| where DeviceAction in ("deny","drop","blocked","reject")
| summarize Denies = count(), Targets = dcount(DestinationIP), Ports = dcount(DestinationPort)
    by SourceIP
| where Targets > 20 or Ports > 20
| order by Denies desc
```

**Large outbound transfers:**
```kusto
CommonSecurityLog
| where DeviceAction =~ "allow"
| where ipv4_is_private(DestinationIP) == false
| summarize BytesOut = sum(SentBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 1h)
| where BytesOut > 100000000
```

**AWS VPC Flow Logs rejects (custom table or `AWSVPCFlow` via connector):**
```kusto
AWSVPCFlow
| where Action == "REJECT"
| summarize Rejects = count(), Targets = dcount(DstAddr), Ports = dcount(DstPort) by SrcAddr
| where Targets > 20 or Ports > 20
```

**Rare external destination seen for the first time:**
```kusto
CommonSecurityLog
| where ipv4_is_private(DestinationIP) == false
| summarize Hosts = dcount(SourceIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by DestinationIP, DestinationPort
| where Hosts == 1
| order by FirstSeen desc
```

> Always verify field names in your connector (CEF aliases differ by vendor). Test against real data before enabling.

### 10.4 Sigma-style skeleton (concept)

```yaml
title: High Volume of Firewall Denies from Single Source
logsource:
  category: firewall
detection:
  selection:
    action: deny
  timeframe: 5m
  condition: selection | count() by src_ip > 500
level: medium
```

### 10.5 Correlation sources

Firewall logs alone are shallow. Pair with:
- **DNS** ([DNS.md](DNS.md)) — domain behind the IP.
- **Proxy/TLS** — SNI, URL, user-agent, bytes.
- **EDR** — process and user.
- **Authentication** — VPN/AD logins around the same time.
- **Asset inventory** — is this a server, workstation, OT device?
- **Threat intel** — IP/domain reputation, ASN, first-seen.

---

## 11. Investigation workflow (step by step)

### Step 1 — Capture facts
- Time (UTC), `src_ip`, `dst_ip`, ports, proto, action, rule/policy, app, bytes, duration.
- Which detection fired and its logic.

### Step 2 — Normalise NAT
- Is the source internal or a NAT public IP? Map to internal host/user.
- Note both pre- and post-NAT addresses.

### Step 3 — Identify the asset and user
- Asset inventory: server/workstation/OT, owner, criticality, OS.
- User-ID / DHCP / VPN logs for attribution.

### Step 4 — Identify the process (if possible)
- EDR/Sysmon network events, host firewall 5156/5157.
- Process name, hash, parent, command line.

### Step 5 — Characterise the traffic
- Volume, direction, duration, periodicity.
- Baseline: does this asset normally talk to this destination/port?
- Payload visibility: URL/SNI/app-ID; pcap if available and authorised.

### Step 6 — Enrich destination
- IP reputation, ASN, hosting/cloud, geo, Tor/VPN, passive DNS.
- Domain popularity and age (see [DNS.md](DNS.md) §12/§15 for enrichment discipline).

### Step 7 — Scope
- Search 24h/7d/30d for same dst IP/domain across all sources.
- Find all hosts/users affected.
- Check for inbound session, then outbound follow-ons.

### Step 8 — Decide
- Benign (vendor/update/CDN, baseline match), suspicious or malicious.
- Escalate per severity; don't over-escalate a single deny.

### Step 9 — Respond
- Block IP/domain/port per policy, isolate host, tune rule, preserve evidence.
- Verify the block is effective (no retries succeeding).

### Step 10 — Document
- Timeline, evidence, scope, impact, actions, recommendations.

---

## 12. Triage playbooks

### A. "Inbound deny spike from one external IP"

1. Is it a scan (many ports/hosts) or targeted (one port)?
2. Did **any** connection succeed from the same source (allow logs)?
3. Is the target exposed (DMZ/web/VPN)? Check IPS hits and app logs.
4. Block at edge if noisy/malicious; report if targeted exposure found.
5. **If a success follows the denies → incident**, not just a scan.

### B. "Host beaconing to external IP"

1. Confirm periodicity and bytes (do not judge on one connection).
2. Attribute process; check parent/child and file hash.
3. Enrich destination; check other hosts.
4. Pull pcap if authorised; look for TLS SNI, HTTP host, JA3/JA4.
5. **Confirmed → isolate, block, hunt, IR.**

### C. "Large outbound transfer"

1. Is the destination a sanctioned cloud/backup/vendor?
2. Which process and user? Off-hours?
3. Compare to baseline for that asset.
4. Check DLP/proxy logs for data type.
5. **Unsactioned + sensitive → escalate as possible exfil.**

### D. "Blocked exploit attempt (IPS alert)"

1. Identify CVE/signature and target asset/service.
2. Did the session continue or succeed afterwards?
3. Is the target vulnerable/patch level? Is it internet-exposed?
4. Check for post-exploitation traffic (new egress, webshell, lateral).
5. Block source, patch/contain target, hunt for success elsewhere.

### E. "VPN brute force"

1. Count failures per source/user; check for spray across many users.
2. Any success after failures? From same source?
3. MFA failures? Impossible travel/time anomalies?
4. Disable/lock targeted accounts, block source, force reset if success.
5. Cross-reference with internal activity from that account.

### F. "Firewall/VPN config changed"

1. Who changed what, when, from where (audit log, change ticket)?
2. Was an any-any or public exposure introduced?
3. Revert unauthorised changes and review logs for the exposure window.
4. Treat unexplained changes as a **possible compromise** of the network device.

### G. "Cloud security group opened to 0.0.0.0/0"

1. Confirm change via CloudTrail/Activity Log (principal, time, source IP).
2. Identify exposed resources and ports (22, 3389, DB).
3. Check for connections during exposure.
4. Revert, rotate credentials if warranted, assess data access.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| External scan, all denied, no success | Low |
| Repeated denies against exposed service | Medium |
| Blocked exploit with vulnerable target | High |
| Confirmed C2 beacon / exfil | High–Critical |
| Unauthorised firewall rule / any-any | High |
| Lateral movement allowed east-west | High–Critical |

---

## 13. Handy commands

### Linux host firewall

```bash
# nftables (modern)
sudo nft list ruleset
sudo nft list tables
sudo nft list chain inet filter input

# iptables (legacy)
sudo iptables -L -n -v --line-numbers
sudo iptables -S
sudo iptables -t nat -L -n -v

# ufw
sudo ufw status verbose
sudo ufw status numbered

# firewalld
sudo firewall-cmd --list-all
sudo firewall-cmd --list-all-zones
sudo firewall-cmd --get-active-zones

# conntrack (state table)
sudo conntrack -L
sudo conntrack -L -p tcp --dport 443
```

### Windows host firewall

```powershell
Get-NetFirewallProfile
Get-NetFirewallRule -Enabled True | Select DisplayName,Direction,Action,Profile
Get-NetFirewallRule -Direction Inbound -Enabled True | Where-Object Action -eq 'Allow'
Get-NetFirewallPortFilter | Where-Object LocalPort -eq 3389
netsh advfirewall show allprofiles
netsh advfirewall firewall show rule name=all
netsh advfirewall monitor show firewall
```

### Packet-level verification

```bash
sudo tcpdump -ni eth0 host 203.0.113.10 and port 443 -vv
sudo tcpdump -ni eth0 'tcp[tcpflags] & tcp-syn != 0'    # SYN attempts
sudo tcpdump -ni eth0 -w cap.pcap 'host 203.0.113.10'   # preserve evidence
```

### Cloud

```bash
# AWS
aws ec2 describe-security-groups --group-ids sg-xxxx
aws ec2 describe-flow-logs
aws logs filter-log-events --log-group-name /aws/vpc/flowlogs

# Azure
az network nsg show --name NSG1 --resource-group RG1
az network watcher flow-log show --location eastus --nsg NSG1

# GCP
gcloud compute firewall-rules list
gcloud compute firewall-rules describe RULE_NAME
```

> Running scans, pcap capture, or config changes requires authorisation. Capturing other users' traffic may have legal/privacy implications — follow the engagement rules.

---

## 14. Common false positives

| Alert | Often actually |
|---|---|
| Inbound denies | Internet background noise; scanners hit everyone. |
| Outbound to new IP | CDN/cloud rotation, SaaS, updates, telemetry. |
| High bytes out | Backups, video calls, cloud sync, large uploads. |
| Unusual ports | Legit apps (e.g. 8080/8443 admin), games, vendor tools. |
| Beacon-like periodicity | NTP, monitoring agents, heartbeats, license checks. |
| Server browsing | Package updates, vendor agents, misconfigured apps (still worth fixing). |
| Geo-block hits | Travelling users, cloud regions, CDN edges. |
| VPN failures | Password expiry, MFA prompts, user error, mobile reconnects. |
| Any-any finding | Temporary rule never removed (still a finding, but not an incident). |
| East-west SMB | File servers, backup, admin tools — baseline per subnet. |

**Rule of thumb:** a deny is an attempt, not a compromise. Escalate on **success**, **repetition**, or **corroboration**.

---

## 15. Hardening and rule hygiene

- **Default deny** inbound and outbound; allow explicitly by service/asset group.
- **Egress filtering** — servers and workstations should not reach arbitrary internet destinations/ports.
- **Least privilege rules** — no any-any, no broad `0.0.0.0/0` to management/DB ports.
- **Zone segmentation** — separate user/server/OT/management/guest; log inter-zone denies.
- **Enable logging on all deny rules** and critical allow rules (internet-facing, egress).
- **Centralise logs** to SIEM with reliable time sync (NTP) and retention ≥ 30–90 days.
- **Rule review cadence** — detect shadowed/redundant/orphaned/expired rules; track owners.
- **Change management + audit** — alert on rule/config changes, especially outside change windows.
- **TLS inspection** where lawful/feasible; document blind spots.
- **Patch firewall/IPS signatures** — appliances are targets (edge device CVEs are common).
- **MFA on VPN/admin**, restrict management plane to jump hosts.
- **Cloud**: default-deny SGs, explicit egress, flow logs on, alert on SG changes.
- **Host firewalls** enabled with logging; process-level visibility via EDR.
- **Purple-team**: validate that detections fire for scans, beacons, exfil simulations.

---

## 16. Lab practice plan

1. Build a small lab: client VM, server VM, Linux firewall (nftables) or pfSense/OPNsense.
2. Write default-deny rules; allow 80/443/53 only; enable logging.
3. Scan with `nmap` from client; observe deny logs and tune a rule.
4. Set up a simple HTTP server; verify allow/state behaviour and NAT.
5. Simulate beaconing (loop `curl` every 60 s); test the periodicity heuristic.
6. Simulate exfil (large upload to a lab endpoint); measure bytes.
7. Break state with asymmetric routing or a timeout; observe INVALID/stalls.
8. Try cloud flow logs in a free-tier VPC; create an SG rule, read the logs.
9. Write SPL/KQL for scan, rare destination, and beacon; run against lab data.
10. Complete a tabletop from §12 with timeline and evidence.

---

## 17. Self-test questions

1. What is the difference between a stateful firewall and a packet filter?
2. Why does return traffic not need a reverse rule?
3. What does `NEW` vs `ESTABLISHED` vs `INVALID` tell you?
4. Why is asymmetric routing a problem for stateful inspection?
5. What is the difference between deny, drop, and reject?
6. How does NAT complicate incident scoping, and what two addresses should you record?
7. What is a shadowed rule?
8. Which firewall log fields are essential for a beaconing detection?
9. Why is east-west traffic more important than north-south for ransomware?
10. What visibility do you lose without TLS inspection, and how do you compensate?
11. What does an AWS Security Group `REJECT` actually come from?
12. How would you distinguish a scan from a targeted attack in firewall logs?
13. When is a single deny worth escalating?
14. What is SNI-IP mismatch, and why is it suspicious?
15. What controls would you recommend for outbound traffic from servers?

---

## 18. One-page revision checklist

- [ ] Types: packet filter, stateful, proxy, NGFW, UTM, WAF, host, cloud SG, microsegmentation.
- [ ] Zones: internet, DMZ, internal, management, guest, cloud; north-south vs east-west.
- [ ] State: NEW/ESTABLISHED/RELATED/INVALID, TCP handshake, timeouts, asymmetric routing.
- [ ] Rules: first-match, shadowed/redundant/orphaned, any-any, logging, direction.
- [ ] NAT: SNAT/PAT, DNAT, static, hairpin; pre/post-NAT logging.
- [ ] NGFW: App-ID, URL filtering, IPS, TLS inspection, DNS security, sandbox, User-ID, DLP, geo.
- [ ] Logs: syslog/CEF/LEEF/JSON, flow vs session, key fields, Windows 5156/5157, cloud flow logs.
- [ ] Attacks: scan, exploit, C2 beacon, exfil, lateral movement, VPN brute force, rule tampering.
- [ ] Detections: deny spikes, rare destinations, unusual ports, periodic beacons, large uploads, server browsing, east-west SMB/RDP, config changes.
- [ ] Investigation: facts → NAT → asset/user → process → traffic character → enrichment → scope → verdict → respond → document.
- [ ] False positives: internet noise, CDNs, backups, monitoring heartbeats, vendor agents, VPN user errors.
- [ ] Hardening: default deny, egress filtering, least privilege, segmentation, logging, rule review, change audit, MFA, patch, cloud SG discipline.
- [ ] Commands: nft/iptables/ufw/firewalld, `Get-NetFirewallRule`, `netsh`, `tcpdump`, AWS/Azure/GCP CLIs.

---

> **Navigation:** [Roadmap index](../README.md) · [← DNS](DNS.md) · [HTTP / HTTPS →](HTTP-HTTPS.md)
