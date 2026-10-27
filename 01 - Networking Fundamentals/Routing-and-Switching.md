# Routing & Switching — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← HTTP / HTTPS](HTTP-HTTPS.md) · [TCP/IP →](TCP-IP.md)

> Goal: understand how frames and packets actually reach their destination, so you can **detect lateral movement, ARP/VLAN attacks, rogue DHCP, scanning, and routing anomalies** from switch/router/flow telemetry.
> Firewall policy/NAT → [Firewalls.md](Firewalls.md); DNS → [DNS.md](DNS.md); HTTP → [HTTP-HTTPS.md](HTTP-HTTPS.md); VPN tunnels → [VPNs.md](VPNs.md). This note covers L2/L3 forwarding.

---

## 0. How to use this note

1. §1–§3: L2 model, switching, VLANs.
2. §4–§5: routing, protocols, path selection.
3. §6–§8: segmentation, overlays, telemetry.
4. §9–§12: detections, investigation, triage.
5. §13–§15: commands, false positives, hardening.
6. §16–§18: labs, self-test, revision.

---

## 1. Why routing and switching matter to a SOC analyst

- **Lateral movement is an L2/L3 event.** RDP, SMB, WinRM, SSH, and internal scans are visible in flow and switch data before EDR catches them.
- **The LAN is an attack surface**: ARP spoofing, MAC flooding, rogue DHCP, VLAN hopping, STP manipulation, and 802.1X bypass.
- **Flow records (NetFlow/IPFIX/sFlow)** are one of the cheapest, highest-coverage telemetry sources you have — and they expose east-west traffic that perimeter logs miss.
- **Routing anomalies** (route changes, BGP hijacks, asymmetric paths) explain outages and can indicate compromise of network devices.
- Knowing the topology lets you **scope incidents**: which VLAN, subnet, switch port, and host are affected?

**SOC outcomes:** given flow/switch data you can answer:
- Who talked to whom, for how long, how much? (`src/dst`, bytes, packets, duration)
- Which VLAN/subnet/switch port is the host on?
- Is this internal scanning, lateral movement, or normal service traffic?
- Did the L2 path change (ARP/MAC/STP) unexpectedly?
- Do the route and the observed path agree (asymmetry, hijack)?

---

## 2. Layers, encapsulation, and addresses

### 2.1 OSI vs TCP/IP (the practical view)

| OSI | TCP/IP | Address | SOC relevance |
|---|---|---|---|
| L1 Physical | Link | — | Cable/port, SPAN/TAP access. |
| L2 Data Link | Link | **MAC** (48-bit) | Switching, ARP, VLANs, spoofing. |
| L3 Network | Internet | **IP** | Routing, subnets, flows. |
| L4 Transport | Transport | **Port** | TCP/UDP sessions, scans. |
| L5–L7 | Application | — | HTTP/DNS/etc. (see their notes). |

### 2.2 Encapsulation

```
Ethernet frame: | Dst MAC | Src MAC | [802.1Q tag] | EtherType | Payload (IP packet) | FCS |
IP packet:     | Ver/IHL | TOS | Total Len | ID | Flags/Frag | TTL | Proto | Src IP | Dst IP | Payload |
TCP segment:   | Src Port | Dst Port | Seq | Ack | Flags | Window | Checksum | Urgent | Payload |
```

- **EtherType** tells the receiver what's inside: `0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP, `0x8100` 802.1Q.
- **MTU** 1500 bytes typical; fragmentation (IPv4) and PMTUD (IPv6) issues look like "connections hang".
- **Jumbo frames** (9000) in storage/DC networks — mismatches cause silent drops.

### 2.3 MAC addresses

- 48 bits: `OUI` (24 bits, vendor) + NIC-specific (24 bits). `AA:BB:CC:DD:EE:FF`.
- **Broadcast** `FF:FF:FF:FF:FF:FF`; **multicast** `01:00:5E:...` (IPv4), `33:33:...` (IPv6).
- **Locally administered** bit (second-least-significant bit of first octet) set = often virtual/random/spoofed.
- **Randomized MACs** on phones/laptops defeat MAC-based policy — expect and design around it.
- **OUI lookup** helps identify device vendor; a "Cisco" MAC on a user port is suspicious.

---

## 3. Switching

### 3.1 How a switch forwards

1. **Learn** — record source MAC → ingress port in the **CAM/MAC address table**.
2. **Flood** — unknown unicast, broadcast, multicast → all ports in the VLAN (except ingress).
3. **Forward** — known unicast → the learned port.
4. **Filter** — same ingress/egress port → drop.
5. **Age** — entries expire (default ~300 s) and are re-learned.

| Concept | Meaning | SOC angle |
|---|---|---|
| **CAM table** | MAC → port mapping | Overflow = MAC flooding; rapid moves = spoofing/VM churn. |
| **Unknown unicast flooding** | No CAM entry | Normal briefly; sustained = table pressure/attack. |
| **Broadcast domain** | One VLAN | Broadcast storms, ARP scans, DHCP floods. |
| **Collision domain** | Per port (full duplex) | Mostly historic. |
| **Store-and-forward** | Full frame check | Drops bad FCS; cut-through forwards faster. |

### 3.2 VLANs and trunking

- **VLAN** = logical L2 segment (IDs **1–4094**; 1 is default, often avoided).
- **Access port** — one VLAN, untagged, to a host.
- **Trunk port** — carries many VLANs with **802.1Q** tags (4-byte tag, 12-bit VLAN ID).
- **Native VLAN** — untagged traffic on a trunk; **mismatch or VLAN 1 native = risk**.
- **Inter-VLAN routing** — router-on-a-stick (subinterfaces) or L3 switch **SVI**.
- **Voice VLAN** — separate VLAN for phones; misconfig can expose data VLAN.
- **Private VLANs** — isolate hosts within a VLAN (promiscuous/isolated/community).
- **VXLAN** — L2 over L3 with a 24-bit VNI (scales beyond 4094); common in DC/cloud.

### 3.3 Spanning Tree Protocol (STP)

- Prevents L2 loops by electing a **root bridge** and blocking redundant ports.
- **Root bridge** = lowest **bridge ID** (priority + MAC); default priority **32768**.
- **Path cost** to root; **port roles**: root, designated, alternate/blocking.
- **States (802.1D)**: blocking → listening (15 s) → learning (15 s) → forwarding; convergence ~30–50 s.
- **RSTP (802.1w)** — faster, port roles alternate/backup, edge ports.
- **MSTP (802.1s)** — multiple instances/VLAN groups.
- **Protections**: **BPDU Guard** (edge ports), **Root Guard** (don't accept superior BPDUs), **Loop Guard**, **UDLD**.

**Attacks:** root bridge takeover (attacker wins election → traffic through attacker), BPDU flood/DoS, STP manipulation causing outages or MitM.

### 3.4 Link aggregation and redundancy

- **LACP/802.3ad** — bundle links; misconfig can cause loops/blackholes.
- **First-hop redundancy** — HSRP/VRRP/GLBP provide a virtual gateway IP/MAC; a rogue HSRP speaker can become the gateway (MitM).

---

## 4. Routing fundamentals

### 4.1 The routing table and path selection

1. **Longest prefix match** wins (e.g. `/24` beats `/16`).
2. If equal prefix, lower **administrative distance (AD)** wins.
3. If same AD, lower **metric** wins.
4. If still equal, load-balance (ECMP) per flow.

| Route source | Cisco AD (default) | Trust level |
|---|---|---|
| Connected | 0 | Highest |
| Static | 1 | High |
| eBGP | 20 | — |
| EIGRP (internal) | 90 | — |
| OSPF | 110 | — |
| RIP | 120 | — |
| EIGRP (external) | 170 | — |
| iBGP | 200 | Lowest of common |

> AD is Cisco-centric; other vendors use preference values. The **concept** (trust ordering) is universal.

### 4.2 Static vs dynamic

- **Static** — manual, predictable, no failover unless tracked.
- **Dynamic** — OSPF/EIGRP/IS-IS (IGP, inside an AS), BGP (EGP, between ASes).
- **Default route** `0.0.0.0/0` — "everything else"; a rogue default route can blackhole or redirect traffic.
- **Null/blackhole route** — intentional drop; often used for DDoS mitigation.
- **Floating static** — higher AD backup route.

### 4.3 Protocol comparison

| Protocol | Type | Metric | Convergence | SOC notes |
|---|---|---|---|---|
| **RIP** | Distance-vector | Hop count (max 15) | Slow | Legacy; spoofable; rarely seen. |
| **OSPF** | Link-state | Cost (ref BW / BW) | Fast | Areas, LSAs, DR/BDR; adjacency changes are signal. |
| **EIGRP** | Hybrid (DUAL) | Composite (BW, delay, ...) | Very fast | Cisco-proprietary (now open); feasible successors. |
| **IS-IS** | Link-state | Cost | Fast | Service-provider/DC; less common in enterprise. |
| **BGP** | Path-vector | AS path, attributes | Tunable | Internet routing; hijacks/leaks; RPKI. |

### 4.4 OSPF essentials

- **Areas** — area 0 (backbone); others connect to it.
- **Neighbors** — Hello packets; must match area, hello/dead timers, authentication, MTU, subnet.
- **DR/BDR** — elected on broadcast segments.
- **LSA types** — 1 router, 2 network, 3 summary, 4 ASBR summary, 5 external, 7 NSSA.
- **Cost** — lower is better; manipulated costs can shift traffic.
- **SOC signal**: repeated adjacency flaps, new neighbors, unexpected area/route changes.

### 4.5 BGP essentials (security-relevant)

- **AS** — autonomous system number. **eBGP** between ASes; **iBGP** inside.
- **Attributes** — AS_PATH, NEXT_HOP, LOCAL_PREF, MED, communities.
- **Best path** — highest weight → highest LOCAL_PREF → locally originated → shortest AS_PATH → lowest origin → lowest MED → eBGP over iBGP → lowest IGP metric.
- **Hijack** — announce someone else's prefix; **route leak** — export routes you shouldn't.
- **Defences** — RPKI/ROV, prefix filters, max-prefix, TTL security (GTSM), BGPsec (limited).
- **SOC signal**: prefix origin changes, sudden AS_PATH changes, new peers, route withdrawal spikes.

### 4.6 TTL and path analysis

- Initial TTL is OS-dependent: **Linux/macOS 64**, **Windows 128**, **network devices 255**.
- Each router decrements by 1; **traceroute** uses TTL expiry + ICMP.
- **TTL anomalies** suggest: spoofed packets, tunnels, NAT/proxy insertion, or a different OS than claimed.
- **Asymmetric routing** — reply takes a different path; breaks stateful firewalls and confuses investigations (see [Firewalls.md](Firewalls.md) §3).

---

## 5. ARP, DHCP, and neighbour discovery

### 5.1 ARP (IPv4)

- "Who has `10.0.0.5`? Tell `10.0.0.1`" — broadcast request, unicast reply.
- **ARP cache** maps IP → MAC; entries age out (~minutes).
- **Gratuitous ARP** — unsolicited announcement (IP conflict detection, HA failover) — also the tool for poisoning.
- **Proxy ARP** — a router answers on behalf of another subnet.

**ARP attacks:**

| Attack | How | Detection |
|---|---|---|
| **ARP spoofing/poisoning** | Send forged replies mapping gateway IP to attacker MAC | Same IP with multiple MACs; MAC changes; gratuitous ARP floods; gateway MAC change. |
| **ARP scan** | Sweep the subnet with ARP requests | Many ARP requests from one host; CAM/ARP table churn. |
| **ARP flooding** | Overwhelm ARP tables | ARP volume spikes, table exhaustion. |
| **MAC flooding** | Fill CAM table so switch floods everything | CAM table near limit; unknown unicast spike; attacker sees traffic. |

**Defences:** **Dynamic ARP Inspection (DAI)** using DHCP snooping bindings, **IP Source Guard**, static ARP for critical hosts, port security, segmentation.

### 5.2 DHCP

- DORA: **Discover** (broadcast) → **Offer** → **Request** → **Ack**.
- Options: 3 (gateway), 6 (DNS), 15 (domain), 42 (NTP), 119 (domain search), 121 (classless routes).
- **Rogue DHCP server** hands out attacker gateway/DNS → MitM. Detection: DHCP offers from non-approved servers, many DISCOVERs, new leases with odd options.
- **DHCP starvation** — exhaust the pool with fake MACs; then rogue server wins.
- **Defences:** **DHCP snooping** (trusted uplink, untrusted access ports), rate limiting, port security.

### 5.3 IPv6 neighbour discovery (NDP)

- **NS/NA** replace ARP; **RS/RA** replace DHCP discovery (SLAAC).
- **Rogue RA** can set attacker as default gateway/DNS → MitM.
- **Defences:** **RA Guard**, DHCPv6 Guard, IPv6 First-Hop Security, ND inspection.
- **SOC note:** IPv6 is often unmonitored — a real blind spot. Look for RA floods, unexpected IPv6 traffic on IPv4-only networks, Teredo/6to4.

---

## 6. Segmentation and network design

| Control | What it does | SOC value |
|---|---|---|
| **VLANs/subnets** | L2/L3 separation | Limits broadcast domains; enables ACLs. |
| **ACLs** | L3/L4 filtering between segments | Deny logs reveal lateral attempts. |
| **VRFs** | Separate routing tables on one device | Tenant/zone isolation. |
| **Private VLANs** | Host isolation within a VLAN | Blocks host-to-host. |
| **Microsegmentation** | Per-workload policy (identity/label) | East-west deny logs are high-signal. |
| **802.1X / NAC** | Port-based identity before network access | Blocks rogue devices; logs auth failures. |
| **Zero Trust** | Deny by default, verify identity/device | Shrinks blast radius. |

**Design patterns:** user/server/DMZ/management/OT/guest zones; **no flat networks**; restrict management plane; separate backup and hypervisor networks; egress via proxy.

**OT/ICS caution:** L2 attacks and scans can disrupt physical processes. Never scan OT without explicit authorisation and change control.

---

## 7. Overlay and tunnel technologies (SOC-relevant)

| Tech | What it does | Detection angle |
|---|---|---|
| **GRE** | Encapsulates L3 in IP (proto 47) | Unusual GRE between hosts; covert tunnels. |
| **IPsec** | Encrypted L3 tunnel | See [VPNs.md](VPNs.md); egress to non-approved peers. |
| **VXLAN** | L2 over UDP 4789 | DC/cloud; unexpected VXLAN from endpoints. |
| **GENEVE** | Overlay (UDP 6081) | Similar. |
| **SD-WAN** | Policy-based WAN overlay | New flows/encryption; vendor-specific logs. |
| **MPLS** | Provider L3 VPN | Limited visibility; rely on provider. |
| **Teredo/6to4/ISATAP** | IPv6 transition tunnels | Often unmonitored; can bypass controls. |
| **ICMP tunnels** | Data in ICMP echo | Large/regular ICMP payloads; high frequency. |

**SOC rule:** any unexpected encapsulation from a user subnet is worth a look. Attackers tunnel to bypass segmentation and logging.

---

## 8. Telemetry: what you can see

| Source | Data | Strengths / gaps |
|---|---|---|
| **NetFlow v5/v9, IPFIX** | 5-tuple, bytes, packets, timestamps, flags, interfaces | Cheap, broad; **no payload**; sampling possible. |
| **sFlow** | Sampled packets + counters | Lightweight; probabilistic. |
| **Zeek `conn.log`** | Rich connection metadata incl. duration, bytes, state | Passive; needs TAP/SPAN. |
| **Switch/router syslog** | Link up/down, STP, ARP, auth, config | Device health/attacks; format varies. |
| **SNMP** | Interface counters, CPU, tables | Polling; useful for anomalies. |
| **SPAN / TAP** | Full packet capture | Deep analysis; bandwidth/storage cost. |
| **NMS / IPAM** | Topology, subnets, assets | Context for scoping. |
| **802.1X/NAC logs** | Auth success/failure, device posture | Rogue device detection. |
| **DHCP logs** | Leases, MAC, hostname, options | Asset attribution. |
| **Cloud flow logs** | VPC/VNet flows | Cloud east-west; schema differs. |
| **EDR** | Process + connection | Attribution; host coverage. |

### 8.1 NetFlow record essentials

`src_ip, dst_ip, src_port, dst_port, proto, tcp_flags, bytes, packets, start, end, input_if, output_if, next_hop, src_as, dst_as`

- **Direction**: ingress/egress relative to the exporter; normalise before analysis.
- **Sampling**: 1:1000 means counts are estimates — never claim exact byte counts.
- **Flow timeout**: long flows may be split into multiple records; aggregate by 5-tuple.

### 8.2 Zeek `conn.log` essentials

`ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, local_resp, missed_bytes, history`

`conn_state` values (e.g. `S0` SYN no reply, `REJ` rejected, `SF` normal, `RSTO`/`RSTR` resets) are a fast way to spot scans and blocked traffic.

### 8.3 Minimum fields for detection

- Time (UTC), src/dst IP and port, protocol, bytes each way, packets, duration, interface/VLAN, TCP flags, host/user/process if available.
- For switch data: MAC, port, VLAN, ARP/ND entries, STP events, DHCP leases.

---

## 9. Detection engineering with flow/switch data

> Baseline per subnet and asset role. Servers talk to servers; workstations do not talk to each other on 445.

### 9.1 High-signal ideas

1. **Internal port scanning** — one internal host, many dst hosts/ports, short flows, `S0`/`REJ` states.
2. **Host sweep** — one source to many IPs on one port (e.g. 445, 3389, 22).
3. **Workstation-to-workstation SMB/RDP/WinRM** — lateral movement.
4. **Server-initiated internet traffic** — egress from servers.
5. **New internal host pair** (never seen in 30 days) on a sensitive port.
6. **East-west data spikes** — large transfers between segments.
7. **Unusual protocol on a port** (e.g. SSH on 443) — needs DPI or app-ID.
8. **ARP anomalies** — IP with multiple MACs, gratuitous ARP floods, gateway MAC change.
9. **CAM/MAC anomalies** — table exhaustion, rapid MAC moves, spoofed OUI.
10. **Rogue DHCP / rogue RA** — offers from non-approved servers.
11. **STP anomalies** — root bridge change, BPDU flood, topology change storms.
12. **Broadcast/multicast storms** — high broadcast rate, unknown unicast flooding.
13. **ICMP tunneling** — large/frequent echo, unusual payload sizes.
14. **Routing changes** — OSPF/BGP neighbor flaps, new routes, next-hop changes.
15. **BGP prefix anomalies** — origin change, AS_PATH length spike, withdrawals.
16. **Asymmetric routing** — reply path differs; stateful devices drop, sessions stall.
17. **TTL anomalies** — unexpected initial TTL, decrement mismatch.
18. **802.1X failures / new MACs** — rogue devices, NAC bypass.
19. **VLAN hopping indicators** — tagged frames on access ports, double-tagged packets.
20. **Tunnel protocols** — GRE/VXLAN/IPsec from endpoints that shouldn't.

### 9.2 Splunk SPL examples (NetFlow/Zeek)

**Internal scanning (many destinations, short flows):**
```spl
index=netflow
| eval internal=if(cidrmatch("10.0.0.0/8",src_ip) OR cidrmatch("172.16.0.0/12",src_ip) OR cidrmatch("192.168.0.0/16",src_ip),1,0)
| where internal=1
| bin _time span=5m
| stats dc(dst_ip) as targets dc(dst_port) as ports count by src_ip, _time
| where targets > 20 OR ports > 20
| sort -count
```

**Workstation-to-workstation SMB/RDP (needs asset lookup):**
```spl
index=netflow dst_port IN (445,3389,5985,5986)
| lookup asset_inventory ip AS src_ip OUTPUT asset_type AS src_type
| lookup asset_inventory ip AS dst_ip OUTPUT asset_type AS dst_type
| where src_type="workstation" AND dst_type="workstation"
| stats count sum(bytes) as total_bytes by src_ip, dst_ip, dst_port
| sort -total_bytes
```

**East-west top talkers:**
```spl
index=netflow
| where cidrmatch("10.0.0.0/8",src_ip) AND cidrmatch("10.0.0.0/8",dst_ip)
| stats sum(bytes) as total_bytes by src_ip, dst_ip
| sort -total_bytes
| head 50
```

**Rare port/protocol pairs:**
```spl
index=netflow
| stats count dc(src_ip) as hosts by dst_port, proto
| where hosts < 3 AND count < 10
| sort count
```

**Unusual egress from servers:**
```spl
index=netflow
| lookup asset_inventory ip AS src_ip OUTPUT asset_type
| where asset_type="server" AND NOT (cidrmatch("10.0.0.0/8",dst_ip))
| stats sum(bytes) as bytes by src_ip, dst_ip, dst_port
| sort -bytes
```

**Zeek connection states indicative of scan/block:**
```spl
index=zeek sourcetype=conn
| where conn_state IN ("S0","REJ","RSTO","RSTR")
| stats count dc(id.resp_h) as targets dc(id.resp_p) as ports by id.orig_h
| where targets > 20 OR ports > 20
```

**Large internal transfer (possible staging/exfil):**
```spl
index=netflow
| stats sum(bytes) as total_bytes by src_ip, dst_ip
| where total_bytes > 500000000
| sort -total_bytes
```

### 9.3 Microsoft Sentinel / Defender KQL examples

**Internal connections to many hosts (DeviceNetworkEvents):**
```kusto
DeviceNetworkEvents
| where ipv4_is_private(RemoteIP) == true
| summarize Targets = dcount(RemoteIP), Ports = dcount(RemotePort), Count = count()
    by DeviceName, bin(TimeGenerated, 1h)
| where Targets > 20 or Ports > 20
| order by Targets desc
```

**Lateral movement ports between devices:**
```kusto
DeviceNetworkEvents
| where RemotePort in (445, 3389, 5985, 5986, 22)
| where ipv4_is_private(RemoteIP) == true
| summarize Count = count(), Bytes = sum(ReceivedBytes + SentBytes)
    by DeviceName, RemoteIP, RemotePort
| order by Count desc
```

**Rare internal destination for a device:**
```kusto
DeviceNetworkEvents
| where ipv4_is_private(RemoteIP) == true
| summarize Devices = dcount(DeviceId), FirstSeen = min(TimeGenerated)
    by RemoteIP, RemotePort
| where Devices <= 2
| order by FirstSeen desc
```

**Cloud flow logs — internal scanning (AWSVPCFlow):**
```kusto
AWSVPCFlow
| where Action == "ACCEPT"
| where ipv4_is_private(SrcAddr) and ipv4_is_private(DstAddr)
| summarize Targets = dcount(DstAddr), Ports = dcount(DstPort) by SrcAddr, bin(TimeGenerated, 1h)
| where Targets > 20 or Ports > 20
```

### 9.4 Sigma-style skeleton (concept)

```yaml
title: Internal Host Sweep on SMB
logsource:
  category: firewall   # or netflow mapping in your pipeline
detection:
  selection:
    dst_port: 445
  timeframe: 5m
  condition: selection | count(dst_ip) by src_ip > 20
level: high
```

### 9.5 Switch/ARP detections (vendor logs or Zeek)

- `arp` events: same IP, different MAC within short window → spoofing.
- `dhcp` events: server messages from non-approved IP → rogue DHCP.
- STP: topology change bursts, root bridge change → possible attack.
- CAM: MAC move count per minute > threshold → loops/spoofing.

Example Zeek ARP heuristic (concept):

```spl
index=zeek sourcetype=arp
| stats dc(mac) as macs values(mac) as mac_list by ip
| where macs > 1
```

---

## 10. Investigation workflow (step by step)

### Step 1 — Capture the facts
- Time (UTC), src/dst IP and port, protocol, bytes, packets, duration.
- VLAN/subnet, switch port, exporter/interface.
- Which detection fired and its logic.

### Step 2 — Identify endpoints
- Asset inventory: server/workstation/OT/printer, owner, criticality.
- MAC → OUI → device type; DHCP lease → hostname/user.
- 802.1X/NAC identity if available.

### Step 3 — Determine the flow pattern
- One-to-many (scan), many-to-one (targeted), one-to-one (interaction), periodic (beacon).
- Bytes symmetry: small request/large response (download) vs reverse (upload/exfil).
- Duration: short resets vs long-lived tunnels.

### Step 4 — Check L2 context
- ARP/MAC anomalies on the same segment.
- VLAN and port; is this traffic expected across that boundary?
- STP events around the same time.

### Step 5 — Correlate
- Firewall allow/deny for the same 5-tuple ([Firewalls.md](Firewalls.md)).
- EDR process/network events.
- Auth logs (RDP/SMB/WinRM logons).
- DNS for domain resolution ([DNS.md](DNS.md)).

### Step 6 — Enrich external endpoints
- IP reputation, ASN, geo, passive DNS.
- Is it a CDN/cloud/vendor? Tor/VPN?

### Step 7 — Scope
- Same source/destination across 24h/7d/30d.
- Other hosts with same behaviour.
- Any successful authentication or data transfer.

### Step 8 — Verdict and response
- Benign/suspicious/malicious/unknown.
- Block, isolate, segment, reset credentials, preserve evidence.
- Tune thresholds.

### Step 9 — Document
Timeline, topology context, evidence, scope, impact, actions, recommendations.

---

## 11. Triage playbooks

### A. "ARP spoofing detected"

1. Confirm: same IP with multiple MACs; which MAC is legitimate?
2. Identify the offending port/MAC; is it a user device, VM, or attacker?
3. Check for MitM effects: credential capture, session hijack, traffic redirection.
4. Shut the port / quarantine VLAN; enable DAI and DHCP snooping.
5. Hunt for credential use and lateral movement from affected hosts.

### B. "MAC flooding / CAM table exhaustion"

1. Verify CAM table size/utilisation and unknown-unicast flooding.
2. Identify the source port/MAC (usually one host with many MACs).
3. Shut the port, enable port security (max MACs, violation action).
4. Assess whether traffic was captured (attacker could see everything).

### C. "Rogue DHCP server"

1. Identify server IP/MAC and port; compare to approved list.
2. Inspect offered options (gateway/DNS) — were clients redirected?
3. Find leases handed out during the window; check affected hosts for MitM.
4. Shut the port, enable DHCP snooping, rotate any exposed credentials.

### D. "VLAN hopping / double tagging"

1. Look for tagged frames on access ports, unusual VLAN IDs, trunk negotiation.
2. Identify the source port/host.
3. Disable DTP, set access ports explicitly, prune allowed VLANs on trunks, change native VLAN.
4. Check whether cross-VLAN access occurred.

### E. "STP root change / BPDU flood"

1. Confirm root bridge ID/priority change and topology change count.
2. Identify the port sending superior BPDUs.
3. Enable BPDU Guard/Root Guard; shut offending port.
4. Assess outage/MitM window.

### F. "Internal scanning"

1. Source: compromised host, authorised scanner, inventory tool?
2. Pattern: ports, targets, timing, any success.
3. If unauthorised: isolate, identify malware, hunt for lateral movement.
4. If authorised: document and tune exclusion by scanner identity.

### G. "Lateral movement (SMB/RDP/WinRM)"

1. Confirm source/destination roles (workstation → server is expected; workstation → workstation is not).
2. Check authentication logs (success/failure, account, time).
3. Look for service creation, scheduled tasks, remote process execution (EDR).
4. Isolate source, reset credentials, hunt for persistence and additional hops.

### H. "BGP prefix anomaly / route leak"

1. Verify with looking-glass/RPKI data; is the origin valid?
2. Check your own announcements and filters; contact the provider if hijacked.
3. Assess traffic redirection/blackhole impact.
4. Apply prefix filters/ROV, max-prefix, and monitor.

### I. "Broadcast storm / network outage"

1. Identify source (looping port, NIC, VM, malware).
2. Check STP state and loop indicators; enable storm control.
3. Shut offending port; verify recovery.
4. Investigate whether the storm was accidental or malicious.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| ARP spoof attempt, no impact | Medium |
| Confirmed ARP MitM / credential capture | High–Critical |
| MAC flooding/CAM exhaustion | High |
| Rogue DHCP with redirection | High |
| VLAN hopping success | High–Critical |
| Internal scan from compromised host | High |
| Confirmed lateral movement | Critical |
| BGP hijack affecting your prefix | Critical |
| Broadcast storm/outage | High (availability) |

---

## 12. Commands

### Linux

```bash
# Interfaces, addresses, links
ip -br addr
ip link show
ip -s link

# Routing
ip route
ip route get 8.8.8.8
ip -6 route
ip rule show
ip route show table all

# Neighbours (ARP/ND)
ip neigh
ip neigh show dev eth0
arp -an                    # legacy

# Bridge / VLAN / FDB
bridge link
bridge fdb show
bridge vlan show
ip -d link show type bridge

# Sockets/connections
ss -tulpen
ss -tan state established

# Path analysis
traceroute -n 8.8.8.8
mtr -rwzc 20 8.8.8.8
tracepath 8.8.8.8

# Capture L2 (authorised only)
sudo tcpdump -ni eth0 -e arp
sudo tcpdump -ni eth0 -e 'vlan'
sudo tcpdump -ni eth0 -e 'ether proto 0x0806'
sudo tcpdump -ni eth0 -s0 -w l2.pcap
```

### Windows

```powershell
Get-NetAdapter
Get-NetIPAddress
Get-NetRoute -AddressFamily IPv4
route print
Get-NetNeighbor
arp -a
Get-NetTCPConnection -State Established
Test-NetConnection 10.0.0.5 -Port 445
tracert 8.8.8.8
pathping 8.8.8.8
```

### Cisco-style network devices (privileged; authorised access only)

```
show ip interface brief
show interfaces status
show mac address-table
show mac address-table count
show vlan brief
show interfaces trunk
show spanning-tree
show spanning-tree root
show ip arp
show ip route
show ip route 10.0.0.0
show ip protocols
show ip ospf neighbor
show ip ospf interface brief
show ip eigrp neighbors
show ip bgp summary
show ip bgp
show etherchannel summary
show port-security
show port-security interface gi0/1
show ip dhcp snooping
show ip dhcp snooping binding
show ip arp inspection
show cdp neighbors detail
show lldp neighbors detail
show logging
show running-config | include (vlan|spanning-tree|arp|dhcp)
```

> Reading device configs requires authorisation and often change control. Never run disruptive commands (`clear`, `shutdown`, `reload`) during an investigation without approval.

---

## 13. Common false positives

| Alert | Often actually |
|---|---|
| Internal scan | Vulnerability scanner, asset discovery, backup, monitoring. |
| Workstation-to-workstation SMB | Admin file shares, collaboration tools, print servers. |
| Many flows to one host | Load balancer, backup target, DB, monitoring collector. |
| Broadcast spikes | Discovery protocols (LLDP, mDNS, NetBIOS), VM migration. |
| MAC moves | Laptop dock/undock, Wi-Fi roaming, VM live migration, randomised MACs. |
| ARP changes | HA failover (HSRP/VRRP), IP renumbering, DHCP churn, clustering. |
| CAM table growth | Virtualisation hosts, containers, dense Wi-Fi. |
| STP topology changes | Link flaps, maintenance, new switch, cabling. |
| Asymmetric routing | Multi-homed design, SD-WAN, policy routing. |
| TTL anomalies | NAT, proxies, tunnels, different OS versions. |
| IPv6 traffic | OS defaults (privacy addresses, Teredo) on dual-stack networks. |
| Legitimate tunnels | VPN, SD-WAN, VXLAN in DC. |

**Rule of thumb:** switch/router noise is context-heavy. Always map MAC/IP to asset and role before escalating.

---

## 14. Hardening and recommendations

- **Segment** by role: user, server, DMZ, management, guest, OT. No flat networks.
- **Explicit access ports** (no DTP), prune VLANs on trunks, change native VLAN away from 1, disable unused ports.
- **Port security** (max MACs, sticky, violation action), **DHCP snooping**, **DAI**, **IP Source Guard**, **RA Guard**, **BPDU Guard**, **Root Guard**.
- **802.1X/NAC** for wired and wireless; MAB only where unavoidable.
- **Storm control** and broadcast suppression on access ports.
- **Disable** unused services: CDP/LLDP externally, proxy ARP where unneeded, IPv6 if not used (or secure it properly).
- **Management plane**: out-of-band, ACL-restricted, MFA/AAA (TACACS+/RADIUS), no internet exposure, patched.
- **Routing**: authentication on OSPF/EIGRP/BGP, prefix filters, max-prefix, RPKI/ROV, TTL security, route change monitoring.
- **Redundancy hygiene**: HSRP/VRRP authentication, consistent STP priorities, documented root bridge.
- **Monitor** flows, ARP/MAC/STP/DHCP events, config changes, and 802.1X failures.
- **Time sync** (NTP) everywhere — investigations depend on aligned timestamps.
- **Asset inventory/IPAM** kept current — attribution depends on it.
- **Change management** for VLAN/routing changes; alert on unexplained changes.
- **Purple-team** L2 attacks and lateral movement in a lab; validate detections.

---

## 15. Lab practice plan

1. Build a lab in GNS3/EVE-NG/Containerlab or Packet Tracer: two VLANs, a router, a switch.
2. Configure inter-VLAN routing (SVI and router-on-a-stick); verify with `traceroute`.
3. Enable port security, DHCP snooping, DAI; test violations.
4. Run an authorised ARP spoof in the lab; observe ARP/CAM changes and build a detection.
5. Simulate a rogue DHCP server; observe client redirection and detection.
6. Configure STP, change priorities, observe root election; try Root Guard.
7. Capture flows with `softflowd`/`nfdump` or Zeek; query with SPL/KQL.
8. Simulate an internal scan with `nmap`; tune a threshold.
9. Simulate lateral movement (SMB/RDP) between lab VMs; correlate with auth logs.
10. Document an incident end-to-end using §10/§11 with timeline and evidence.

---

## 16. Self-test questions

1. What is the difference between a collision domain and a broadcast domain?
2. How does a switch learn and forward? What is unknown unicast flooding?
3. What is the native VLAN, and why is VLAN 1 risky?
4. Explain 802.1Q tagging and trunk vs access ports.
5. How does STP elect a root bridge, and what are the port states?
6. What is the difference between BPDU Guard and Root Guard?
7. How does ARP spoofing enable a MitM, and how do you detect it?
8. What is DHCP snooping, and why does DAI depend on it?
9. What is the difference between a routing table and a FIB?
10. Explain longest-prefix match, administrative distance, and metric.
11. What is the difference between OSPF and BGP, and why does it matter?
12. What is a BGP hijack vs a route leak?
13. Why is asymmetric routing a problem for stateful firewalls?
14. How can TTL help you fingerprint an OS or spot a tunnel?
15. Which telemetry would you use to detect lateral movement between VLANs?

---

## 17. One-page revision checklist

- [ ] Encapsulation: Ethernet → IP → TCP/UDP; EtherTypes; MTU/fragmentation.
- [ ] MAC: 48-bit, OUI, broadcast/multicast, locally administered, randomisation.
- [ ] Switching: learn/flood/forward/age; CAM table; unknown unicast; broadcast domain.
- [ ] VLANs: 1–4094, access/trunk, 802.1Q, native VLAN, SVI/router-on-a-stick, private VLAN, VXLAN.
- [ ] STP: root bridge, bridge ID/priority, costs, states/timers, RSTP/MSTP, BPDU/Root Guard.
- [ ] Routing: longest prefix, AD, metric, static/default/floating, FIB/ECMP.
- [ ] Protocols: RIP, OSPF (areas/LSA/DR), EIGRP (DUAL), IS-IS, BGP (AS_PATH/attributes/hijack).
- [ ] ARP/NDP/DHCP: cache, gratuitous ARP, DORA, options, rogue server, RA.
- [ ] L2 attacks: ARP spoof, MAC flood, VLAN hop, STP attack, rogue DHCP/RA, 802.1X bypass.
- [ ] Defences: port security, DHCP snooping, DAI, IPSG, RA Guard, BPDU Guard, storm control, 802.1X, segmentation.
- [ ] Telemetry: NetFlow/IPFIX/sFlow, Zeek conn, SNMP, syslog, SPAN/TAP, DHCP/802.1X logs.
- [ ] Detections: internal scans, sweeps, lateral SMB/RDP/WinRM, east-west spikes, rare pairs, ARP/MAC/CAM/STP/DHCP anomalies, routing changes, TTL anomalies, tunnels.
- [ ] Investigation: facts → endpoints → flow pattern → L2 context → correlation → enrichment → scope → verdict → respond → document.
- [ ] Triage: ARP spoof, MAC flood, rogue DHCP, VLAN hop, STP change, internal scan, lateral movement, BGP anomaly, broadcast storm.
- [ ] Commands: `ip route/neigh`, `bridge`, `ss`, `traceroute/mtr`, `tcpdump -e`, `Get-NetRoute/Neighbor`, Cisco `show` commands.
- [ ] Hardening: segmentation, port security, snooping/DAI, NAC, management plane, routing auth/RPKI, monitoring, NTP, inventory, change control.

---

> **Navigation:** [Roadmap index](../README.md) · [← HTTP / HTTPS](HTTP-HTTPS.md) · [TCP/IP →](TCP-IP.md)
