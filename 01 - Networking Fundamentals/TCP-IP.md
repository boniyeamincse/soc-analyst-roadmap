# TCP/IP — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Routing & Switching](Routing-and-Switching.md) · [VPNs →](VPNs.md)

> Goal: understand IP, TCP, UDP, and ICMP at packet level so you can **read pcaps, explain connection failures, detect scans/floods/tunnels, and write reliable network detections**.
> L2/VLAN/ARP → [Routing-and-Switching.md](Routing-and-Switching.md); firewall policy → [Firewalls.md](Firewalls.md); DNS → [DNS.md](DNS.md); HTTP → [HTTP-HTTPS.md](HTTP-HTTPS.md).

---

## 0. How to use this note

1. §1–§4: model, IP, addressing/subnetting, protocol numbers.
2. §5–§7: TCP, UDP, ICMP in depth.
3. §8–§9: ports, scans, attack patterns.
4. §10–§13: packet analysis, telemetry, detections, investigation, triage.
5. §14–§16: commands, false positives, hardening.
6. §17–§19: labs, self-test, revision.

---

## 1. Why TCP/IP matters to a SOC analyst

- Every alert ultimately reduces to **packets and connections**. If you can read them, you can validate or kill most network findings.
- Scan, flood, spoofing, tunneling, and exfil detection all depend on **TCP flags, states, ports, and byte counts**.
- pcaps are the **ground truth** when logs disagree (and they often do).
- Attackers exploit protocol quirks: fragmentation, half-open connections, RST injection, ICMP tunnels, UDP amplification.
- Understanding normal behaviour is the only reliable way to spot abnormal behaviour.

**SOC outcomes:** given a packet/flow you can answer:
- Is the handshake complete? Who spoke first? Who reset?
- Is this a scan, a flood, or a real session?
- What protocol/port, and is that expected for this asset?
- How many bytes each way, over how long?
- Is the source spoofed? Is the path plausible?
- What should happen next?

---

## 2. The TCP/IP model and encapsulation

| TCP/IP layer | OSI equivalent | Protocols | Address |
|---|---|---|---|
| **Application** | 5–7 | HTTP, DNS, SMTP, SSH, SMB, TLS | URLs/names |
| **Transport** | 4 | **TCP, UDP**, (QUIC over UDP) | **Ports** |
| **Internet** | 3 | **IPv4, IPv6, ICMP**, GRE, ESP | **IP** |
| **Link** | 1–2 | Ethernet, Wi-Fi, ARP, VLAN | **MAC** |

```
[Ethernet header][IP header][TCP/UDP header][Application data][Ethernet FCS]
```

Each layer adds its own header and does **not** inspect the layer above (except middleboxes). This is why:
- A firewall can block by port without understanding HTTP.
- TLS hides application content from the network.
- Fragmentation and tunnels can hide the real protocol.

**MTU/MSS:** Ethernet MTU 1500; TCP MSS typically 1460 (1500 − 20 IP − 20 TCP). Mismatches cause hangs and fragmentation.

---

## 3. IPv4

### 3.1 Header fields

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  | DSCP/ECN |          Total Length               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      TTL      |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (0–40 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Meaning | SOC relevance |
|---|---|---|
| **Version** | 4 or 6 | Mixed/odd versions = evasion/malformed. |
| **IHL** | Header length in 32-bit words (5 = 20 bytes) | Bad IHL = malformed. |
| **DSCP/ECN** | QoS/ECN | Rarely security-relevant; ECN abuse is niche. |
| **Total Length** | Header + payload | Inconsistencies = malformed/smuggling. |
| **Identification** | Fragment grouping | Fragment attacks/reassembly. |
| **Flags** | DF (don't fragment), MF (more fragments) | Fragmentation behaviour. |
| **Fragment Offset** | Position in original datagram | Overlap/teardrop attacks. |
| **TTL** | Hop limit; decremented per router | OS fingerprint, tunneling, spoof detection. |
| **Protocol** | Payload type (TCP 6, UDP 17, ICMP 1) | Identify protocol; protocol filtering. |
| **Header Checksum** | Integrity of header only | Corrupt headers dropped. |
| **Source/Destination** | IP addresses | Spoofing, direction, scope. |

### 3.2 Addresses, ranges, and special-use

| Range | Purpose |
|---|---|
| **10.0.0.0/8** | Private (RFC1918) |
| **172.16.0.0/12** | Private (172.16–172.31) |
| **192.168.0.0/16** | Private |
| **127.0.0.0/8** | Loopback |
| **169.254.0.0/16** | Link-local / APIPA |
| **100.64.0.0/10** | Carrier-grade NAT (CGNAT) |
| **224.0.0.0/4** | Multicast |
| **240.0.0.0/4** | Reserved |
| **255.255.255.255** | Limited broadcast |
| **192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24** | Documentation (safe in examples) |
| **198.18.0.0/15** | Benchmarking |
| **0.0.0.0/8** | "This host"/unspecified (0.0.0.0 as source = DHCP discover). |

- **Unicast** — one destination.
- **Broadcast** — all hosts in the subnet (IPv4 only).
- **Multicast** — group membership.
- **Anycast** — same IP in multiple places, routed to nearest (DNS roots, CDNs).

### 3.3 IPv6 essentials

- 128-bit, written as 8 groups of 4 hex digits; `::` compresses zeros once.
- **No broadcast**; uses multicast + NDP.
- Typical LAN prefix **/64**; global unicast `2000::/3`; link-local `fe80::/10`; ULA `fc00::/7`; loopback `::1`; multicast `ff00::/8`.
- **SLAAC** — hosts self-configure from Router Advertisements; **DHCPv6** optional.
- **Privacy addresses** — temporary addresses rotate; makes host tracking harder.
- **NAT is not a security control** in IPv6; firewalling is.
- **SOC gap:** IPv6 is frequently unlogged. Look for unexpected IPv6, RA floods, Teredo/6to4, and IPv6 egress bypassing IPv4 controls.

### 3.4 Fragmentation

- IPv4 routers may fragment; the destination reassembles.
- **DF=1** — don't fragment; if too big, ICMP "fragmentation needed" (PMTUD).
- **MF=1** — more fragments follow; last fragment has offset > 0 and MF=0.
- **Attacks:** teardrop/overlapping fragments, tiny fragments, fragment floods, evasion of stateless filters.
- **SOC signal:** fragmented traffic from hosts that never normally fragment; overlapping offsets; fragment reassembly timeouts.

### 3.5 TTL

- Decremented at each router; packet dropped at 0 (ICMP Time Exceeded).
- Initial values: **Linux/macOS 64**, **Windows 128**, **network gear 255**.
- **Uses:** OS fingerprinting, traceroute, loop detection.
- **Anomalies:** unexpected initial TTL (spoof/tunnel/proxy), inconsistent TTL for the same source, TTL used to bypass filters (rare).

---

## 4. Protocol numbers and common IP protocols

| Number | Protocol | Notes |
|---|---|---|
| **1** | ICMP | Ping, errors, traceroute. |
| **2** | IGMP | Multicast group management. |
| **6** | **TCP** | Most application traffic. |
| **17** | **UDP** | DNS, DHCP, QUIC, VoIP, SNMP. |
| **41** | IPv6 encapsulation | 6in4 tunnels. |
| **47** | GRE | Tunnels (also PPTP). |
| **50** | ESP | IPsec encrypted payload. |
| **51** | AH | IPsec authentication. |
| **58** | ICMPv6 | NDP, ping6, errors. |
| **89** | OSPF | Routing. |
| **132** | SCTP | Telecom/signalling. |

> Firewalls and flow logs often record `proto=6/17/1`. Knowing the numbers lets you filter accurately.

---

## 5. TCP

### 5.1 Header fields

| Field | Meaning | SOC relevance |
|---|---|---|
| **Src/Dst port** | Application endpoints | Service identification, scans, policy. |
| **Sequence number** | Byte offset of this segment | Hijacking, RST injection, retransmissions. |
| **Acknowledgment number** | Next expected byte | Session validation. |
| **Data offset** | Header length (20–60 bytes) | Options present. |
| **Flags** | URG, ACK, PSH, RST, SYN, FIN (+NS, CWR, ECE) | Scan/attack classification. |
| **Window** | Receive buffer space | Flow control, zero-window probes. |
| **Checksum** | Integrity | Corruption/malformed packets. |
| **Urgent pointer** | Urgent data | Rare; can indicate evasion. |
| **Options** | MSS, SACK, timestamps, window scale | Fingerprinting, performance. |

### 5.2 Flags in detail

| Flag | Meaning | Attack/scan use |
|---|---|---|
| **SYN** | Open a connection | SYN scan, SYN flood. |
| **ACK** | Acknowledge data | ACK scan (map firewalls). |
| **PSH** | Deliver to app immediately | Data transfer. |
| **FIN** | Sender finished | FIN scan, teardown. |
| **RST** | Abort/reset | RST scan, RST injection, resets from IPS. |
| **URG** | Urgent data | Evasion. |
| **NULL** | No flags set | NULL scan. |
| **XMAS** | FIN+PSH+URG | XMAS scan. |
| **CWR/ECE** | Congestion notification | Rare; anomalies. |

### 5.3 Three-way handshake

```
Client                       Server
  |------ SYN (seq=x) --------->|     state: SYN_SENT
  |<-- SYN/ACK (seq=y, ack=x+1)-|     state: SYN_RECEIVED
  |------ ACK (ack=y+1) ------->|     state: ESTABLISHED
```

- **Half-open** — SYN sent, no final ACK; repeated half-opens = SYN flood or scan.
- **SYN cookies** — server avoids storing state until the handshake completes (SYN flood mitigation).
- **Simultaneous open** — both send SYN (rare, valid).
- **Passive open** — server listening (`LISTEN`).

### 5.4 Teardown

```
Client                       Server
  |------ FIN ----------------->|     FIN_WAIT_1
  |<----- ACK -----------------|     FIN_WAIT_2
  |<----- FIN -----------------|     CLOSE_WAIT / LAST_ACK
  |------ ACK ----------------->|     TIME_WAIT → CLOSED
```

- **RST** aborts immediately (no graceful close).
- **TIME_WAIT** (~2×MSL, often 60 s) prevents stray segments; lots of TIME_WAIT = many short connections (scan, load test, broken app).

### 5.5 TCP state machine (names you'll see in logs)

`CLOSED → LISTEN → SYN_SENT → SYN_RECEIVED → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → CLOSE_WAIT → LAST_ACK → TIME_WAIT → CLOSING → CLOSED`

Zeek `conn_state` mapping (useful):

| State | Meaning |
|---|---|
| `S0` | SYN sent, no reply (filtered/scan). |
| `S1` | Established, no data. |
| `SF` | Normal establishment and shutdown. |
| `REJ` | Connection rejected (RST). |
| `S2` | Established, originator closed first. |
| `S3` | Established, responder closed first. |
| `RSTO` | Originator sent RST. |
| `RSTR` | Responder sent RST. |
| `RSTOS0` | Originator sent RST after SYN, no reply. |
| `SH` | SYN then FIN (weird/scan). |
| `SHR` | SYN, FIN, RST. |
| `OTH` | Mid-stream traffic without SYN. |

### 5.6 Flow control and reliability

- **Sliding window** — receiver advertises buffer space; sender adjusts.
- **Window scaling** — option to exceed 65,535.
- **Retransmission** — timeout or duplicate ACKs; fast retransmit.
- **SACK** — selective acknowledgment of missing segments.
- **Nagle's algorithm** — batches small writes (latency vs efficiency).
- **Keepalive** — periodic probes to detect dead peers.
- **Zero window** — receiver full; sender probes.

**SOC reading:** retransmissions/zero-window in a pcap often mean packet loss, MTU issues, or a slow/overloaded target — not necessarily an attack. High retransmission from one host can also indicate a network fault or DoS.

### 5.7 TCP attacks

| Attack | Mechanism | Detection |
|---|---|---|
| **SYN flood** | Many half-open connections exhaust backlog | SYN without ACK, `SYN_RECEIVED` growth, low completion rate. |
| **SYN/ACK flood** | Spoofed SYN/ACKs | Unexpected SYN/ACKs from non-servers. |
| **ACK flood** | Spoofed ACKs consume state/CPU | High ACK rate without handshake. |
| **RST injection** | Forged RST with guessed seq kills session | Unexplained resets mid-session; seq anomalies. |
| **Session hijacking** | Predict/steal seq, inject data | Duplicate data, IP/UA change, seq anomalies. |
| **TCP spoofing (blind)** | Send data without receiving replies | No handshake from source; TTL/OS mismatch. |
| **LAND attack** | src IP/port = dst IP/port | Loops/crashes; malformed flows. |
| **Fragmentation attacks** | Overlapping/tiny fragments | Reassembly errors; IDS/IPS alerts. |
| **Slowloris / slow HTTP** | Hold connections open slowly | Many long-lived partial requests. |
| **Port exhaustion** | Consume ephemeral ports | Connection failures, high TIME_WAIT/CLOSE_WAIT. |

---

## 6. UDP

### 6.1 Characteristics

- **Connectionless**, no handshake, no reliability, no ordering.
- Header: src port, dst port, length, checksum (8 bytes).
- Common services: DNS 53, DHCP 67/68, NTP 123, SNMP 161/162, Syslog 514, TFTP 69, mDNS 5353, LLMNR 5355, NetBIOS 137/138, QUIC 443, VXLAN 4789, IPsec NAT-T 4500, RADIUS 1812/1813.
- **UDP scans** are slow/unreliable: open port → no response; closed → ICMP port unreachable; filtered → nothing.
- **Amplification/reflection**: spoof source, send small request to a service with a large response (DNS, NTP monlist, memcached, CLDAP, SSDP).
- **QUIC/HTTP3** over UDP 443 is encrypted and often **not logged** — visibility gap.

### 6.2 UDP attacks

| Attack | Mechanism | Detection |
|---|---|---|
| **UDP flood** | Volume of datagrams exhausts target/network | High pps to one host/port; random ports. |
| **Amplification** | Spoofed request → large response to victim | Inbound spikes from DNS/NTP/memcached; spoofed sources. |
| **UDP scan** | Probe ports, infer by ICMP unreachable | Many UDP flows, ICMP type 3 code 3. |
| **Fragmentation abuse** | Fragment floods/overlaps | Fragment rate, reassembly failures. |
| **QUIC evasion** | Encrypted UDP 443 bypasses proxy/DNS | Unexpected UDP 443 egress. |

---

## 7. ICMP

### 7.1 Message types you must know

| Type | Code | Meaning |
|---|---|---|
| **0** | — | Echo reply. |
| **3** | 0/1/2/3 | Destination unreachable: network / host / protocol / **port**. |
| **3** | 4 | Fragmentation needed (PMTUD). |
| **3** | 13 | Communication administratively prohibited (firewall). |
| **5** | 0–3 | Redirect (gateway/route) — rarely legit, often attack. |
| **8** | — | Echo request. |
| **11** | 0/1 | Time exceeded: TTL / fragment reassembly. |
| **12** | — | Parameter problem (malformed header). |
| **13/14** | — | Timestamp request/reply (legacy; disable). |

### 7.2 ICMP attack surface

- **Ping sweep** — host discovery; many echo requests across a subnet.
- **Smurf** — spoofed echo request to a broadcast address, replies flood the victim.
- **Fraggle** — UDP variant of Smurf.
- **Ping of death** — oversized fragmented ICMP (historic; mostly patched).
- **ICMP redirect** — attacker tells a host to use a malicious gateway (MitM).
- **ICMP tunneling** — data hidden in echo payloads (e.g. `ptunnel`, `icmpsh`); large/regular payloads.
- **Covert channel** — timing/fields used to exfiltrate.
- **Recon via errors** — ICMP unreachable reveals topology/firewall rules.

**Defences:** rate-limit ICMP, block redirects, allow only necessary types (echo for monitoring), monitor payload size/frequency.

---

## 8. Ports and scans

### 8.1 Port ranges

| Range | Name |
|---|---|
| 0–1023 | Well-known (system) |
| 1024–49151 | Registered |
| 49152–65535 | Dynamic/ephemeral (Linux often 32768–60999 or 32768–65535) |

### 8.2 Common ports

| Port | Service | SOC note |
|---|---|---|
| 20/21 | FTP | Cleartext; data channel complexity. |
| 22 | SSH | Admin, brute force, tunnels. |
| 23 | Telnet | Cleartext; should be gone. |
| 25/465/587 | SMTP | Mail abuse. |
| 53 | DNS | Tunneling ([DNS.md](DNS.md)). |
| 67/68 | DHCP | Rogue server ([Routing-and-Switching.md](Routing-and-Switching.md)). |
| 69 | TFTP | Config exfil, malware staging. |
| 80/443 | HTTP/S | Web, C2, exfil. |
| 88 | Kerberos | AD attacks. |
| 123 | NTP | Amplification (monlist). |
| 135/139/445 | RPC/NetBIOS/SMB | Lateral movement, ransomware. |
| 137/138 | NetBIOS | Legacy; poisoning. |
| 161/162 | SNMP | Info leak, default community strings. |
| 389/636 | LDAP/S | AD enumeration. |
| 443/UDP | QUIC/HTTP3 | Visibility gap. |
| 445 | SMB | WannaCry, PsExec, exfil. |
| 1433/1521/3306/5432/27017 | Databases | Direct access is suspicious. |
| 3389 | RDP | Brute force, lateral movement. |
| 4789/UDP | VXLAN | Overlay abuse. |
| 5985/5986 | WinRM | Remote admin abuse. |
| 8080/8443 | Alt HTTP/S | Proxies, admin, C2. |
| 853 | DoT | Encrypted DNS bypass. |

### 8.3 Scan types

| Scan | Mechanism | Packet signature |
|---|---|---|
| **TCP connect** | Full handshake via OS | Completed handshakes, then RST/FIN; noisy. |
| **TCP SYN (half-open)** | SYN, read SYN/ACK, send RST | SYN → SYN/ACK → RST; `S0`/`REJ` patterns. |
| **FIN/NULL/XMAS** | Odd flag combos; closed ports reply RST | FIN/NULL/XMAS to many ports. |
| **ACK** | Probe firewall state | ACK to many ports; RST vs no response. |
| **UDP** | Probe, infer from ICMP unreachable | Many UDP flows + ICMP 3/3. |
| **Idle/zombie** | Use a third-party IPID | Spoofed-looking, indirect; hard to trace. |
| **Fragmented** | Split probes across fragments | Fragmented SYNs. |
| **Decoy** | Mix real with spoofed sources | Many sources, similar timing. |
| **Slow scan** | Long intervals to evade thresholds | Low-and-slow; needs baselines/long windows. |

**Nmap port states:** `open`, `closed`, `filtered`, `unfiltered`, `open|filtered`, `closed|filtered`.

**SOC reading:** a scan is **many destinations or ports from one source in a short window**, often with incomplete handshakes. Distinguish authorised scanners (asset inventory, vulnerability management) by **known source IPs/tags**.

---

## 9. Spoofing, hijacking, and protocol abuse

| Technique | What it is | Detection |
|---|---|---|
| **IP spoofing** | Forged source IP (blind attacks, reflection) | No return traffic; TTL/OS mismatch; ingress filtering (BCP38) missing. |
| **TCP session hijacking** | Inject into an established session | Duplicate/odd seq, resets, sudden UA/IP change. |
| **RST injection** | Forge reset to kill connections | Unexplained mid-session RSTs, censorship/firewall behaviour. |
| **DNS spoofing** | Forged DNS replies | See [DNS.md](DNS.md). |
| **ARP spoofing** | Forged ARP | See [Routing-and-Switching.md](Routing-and-Switching.md). |
| **ICMP redirect** | Forged gateway redirect | Type 5 packets; route changes. |
| **Tunneling** | Data in ICMP/DNS/GRE/HTTP | Protocol anomalies, payload size/entropy. |
| **Covert timing channel** | Encode via timing | Statistical analysis; hard. |
| **Fragmentation evasion** | Overlaps/tiny fragments | IDS/IPS alerts, reassembly errors. |
| **Reflection/amplification** | Spoof victim, hit open services | Inbound flood, spoofed source, known amplifiers. |

**Key defensive concept:** **ingress/egress filtering (BCP38)** prevents source spoofing inside your network. If your hosts can spoof, investigations become unreliable.

---

## 10. Packet analysis

### 10.1 Capture tools

| Tool | Use |
|---|---|
| **tcpdump** | CLI capture/filter on Linux/network devices. |
| **tshark** | CLI Wireshark, field extraction, scripting. |
| **Wireshark** | GUI deep analysis, streams, expert info. |
| **Zeek** | Passive metadata/logs at scale. |
| **Suricata/ Snort** | Signature IDS/IPS with pcap output. |
| **dumpcap** | Efficient capture (Wireshark engine). |
| **pktmon / netsh trace** | Windows built-in capture. |

### 10.2 Useful tcpdump

```bash
sudo tcpdump -ni eth0 -nn
sudo tcpdump -ni eth0 -nn 'host 10.0.0.5 and port 443'
sudo tcpdump -ni eth0 -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
sudo tcpdump -ni eth0 -nn 'tcp[tcpflags] & tcp-rst != 0'
sudo tcpdump -ni eth0 -nn 'icmp'
sudo tcpdump -ni eth0 -nn 'udp port 53'
sudo tcpdump -ni eth0 -nn -A -s0 'tcp port 80'
sudo tcpdump -ni eth0 -nn -X -s0 'port 445'
sudo tcpdump -ni eth0 -s0 -w cap.pcap 'host 203.0.113.10'
sudo tcpdump -r cap.pcap -nn
```

### 10.3 Useful tshark

```bash
tshark -r cap.pcap -q -z conv,tcp
tshark -r cap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src -e tcp.dstport
tshark -r cap.pcap -Y 'tcp.analysis.retransmission'
tshark -r cap.pcap -Y 'tcp.flags.reset==1' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
tshark -r cap.pcap -Y 'icmp' -T fields -e ip.src -e ip.dst -e icmp.type -e icmp.code
tshark -r cap.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e ip.dst -e tls.handshake.extensions_server_name
tshark -r cap.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri -e http.user_agent
tshark -r cap.pcap -Y 'tcp.stream eq 3' -V
```

### 10.4 Wireshark display filters

| Filter | Purpose |
|---|---|
| `ip.addr == 10.0.0.5` | Any traffic to/from host. |
| `ip.src == 10.0.0.5 && tcp.port == 445` | Specific flow. |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Connection attempts. |
| `tcp.flags.reset == 1` | Resets. |
| `tcp.analysis.retransmission` | Retransmissions. |
| `tcp.analysis.zero_window` | Zero-window events. |
| `tcp.stream eq N` | Follow one stream. |
| `icmp.type == 8` | Echo requests. |
| `dns` / `http` / `tls` | Protocol filters. |
| `frame contains "cmd.exe"` | Payload search (cleartext only). |
| `tls.handshake.extensions_server_name contains "example"` | SNI. |
| `tcp.len > 0 && tcp.port == 443` | Data in TLS (encrypted). |
| `!(arp || icmp || dns)` | Noise reduction. |

**Follow TCP Stream** reconstructs a session (cleartext). **Expert Information** flags retransmissions, resets, malformed packets.

### 10.5 What to capture and preserve

- Full packet capture (`-s0`) around the event window.
- Note capture point (SPAN/TAP/host), interface, and time source.
- Keep the pcap hash for evidence integrity.
- Don't capture other users' traffic without legal authorisation.

---

## 11. Telemetry and fields

| Source | Fields | Notes |
|---|---|---|
| **NetFlow/IPFIX** | 5-tuple, bytes, packets, flags, start/end, interfaces | No payload; sampling possible. |
| **Zeek `conn.log`** | `id.orig_h/p`, `id.resp_h/p`, `proto`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history` | Best passive metadata. |
| **Zeek `weird.log`** | Protocol anomalies | Malformed/odd traffic. |
| **Suricata** | Alerts, flow, protocol metadata | Signature + anomaly. |
| **Firewall** | Action, rule, app, bytes | See [Firewalls.md](Firewalls.md). |
| **IDS/IPS** | Alert signature, severity, payload snippet | Tuning needed. |
| **EDR** | Process, connections | Attribution. |
| **Switch/router** | Interface counters, ACL hits | L2/L3 context. |

**Minimum detection fields:** time (UTC), src/dst IP, src/dst port, proto, bytes in/out, packets, duration, flags/state, interface, host/user/process.

---

## 12. Detection engineering

> Baselines per subnet and role. Normal for a server is abnormal for a workstation.

### 12.1 High-signal ideas

1. **Horizontal scan** — one source, many destinations.
2. **Vertical scan** — one source/destination, many ports.
3. **Incomplete handshakes** — many `S0`/`SYN_RECEIVED`/`REJ`.
4. **SYN flood** — high SYN rate, low completion, backlog growth.
5. **RST anomalies** — resets mid-session, resets from unexpected sources.
6. **ACK/FIN/NULL/XMAS scans** — odd flag combinations.
7. **UDP probing** — many UDP flows + ICMP port unreachable.
8. **Data volume spikes** — bytes out per host/flow.
9. **Long-lived sessions** — duration outliers (tunnels, keepalives).
10. **Rare protocol/port pair** — e.g. SSH on 443, DNS over TCP from clients.
11. **ICMP tunneling** — large/regular payloads, high frequency.
12. **Fragmentation anomalies** — fragment rate, overlaps, tiny fragments.
13. **Spoofing indicators** — no return traffic, TTL/OS mismatch, many sources with similar patterns.
14. **UDP amplification** — inbound spikes from DNS/NTP/memcached, spoofed sources.
15. **Egress to unusual ports** — 4444, 1337, 9001, 53/TCP, high ports.
16. **Beaconing** — periodic flows with low jitter.
17. **Connection churn** — high TIME_WAIT/CLOSE_WAIT, port exhaustion.
18. **IPv6 anomalies** — unexpected IPv6, RA floods, tunnels (Teredo/6to4).
19. **QUIC/HTTP3 egress** — UDP 443 where proxy required.
20. **Mid-stream flows (`OTH`)** — traffic without handshake (spoofing, mid-capture, evasion).

### 12.2 Splunk SPL examples

**Horizontal scan (many destinations, short window):**
```spl
index=netflow
| bin _time span=5m
| stats dc(dst_ip) as targets dc(dst_port) as ports count by src_ip, _time
| where targets > 20 OR ports > 20
| sort -targets
```

**Incomplete handshakes (Zeek):**
```spl
index=zeek sourcetype=conn
| where conn_state IN ("S0","REJ","RSTO","RSTR","RSTOS0","SH","SHR")
| stats count dc(id.resp_h) as targets dc(id.resp_p) as ports by id.orig_h
| where targets > 20 OR ports > 20
| sort -count
```

**SYN-heavy traffic:**
```spl
index=netflow tcp_flags="SYN"
| bin _time span=1m
| stats count by src_ip, dst_ip, _time
| where count > 500
| sort -count
```

**Large outbound transfer:**
```spl
index=netflow direction=outbound
| stats sum(bytes) as total_bytes by src_ip, dst_ip, dst_port
| where total_bytes > 500000000
| sort -total_bytes
```

**ICMP with large payloads:**
```spl
index=netflow proto=1 icmp_type=8
| where bytes > 1000
| stats count avg(bytes) as avg_bytes by src_ip, dst_ip
| where count > 20
```

**Rare destination ports:**
```spl
index=netflow
| stats count dc(src_ip) as hosts by dst_port
| where hosts < 2
| sort count
```

**Beaconing from flow records:**
```spl
index=netflow
| sort 0 src_ip, dst_ip, dst_port, _time
| streamstats current=f window=1 last(_time) as prev by src_ip, dst_ip, dst_port
| eval delta=_time-prev
| stats count stdev(delta) as jitter avg(delta) as avg_delta by src_ip, dst_ip, dst_port
| where count > 20 AND jitter < 5 AND avg_delta < 600
```

### 12.3 Microsoft Sentinel / Defender KQL examples

**Many internal destinations in an hour:**
```kusto
DeviceNetworkEvents
| where ipv4_is_private(RemoteIP) == true
| summarize Targets = dcount(RemoteIP), Ports = dcount(RemotePort), Count = count()
    by DeviceName, bin(TimeGenerated, 1h)
| where Targets > 20 or Ports > 20
| order by Targets desc
```

**Large outbound connections:**
```kusto
DeviceNetworkEvents
| where ipv4_is_private(RemoteIP) == false
| summarize Sent = sum(SentBytes), Recv = sum(ReceivedBytes)
    by DeviceName, RemoteIP, RemotePort, bin(TimeGenerated, 1h)
| where Sent > 100000000
| order by Sent desc
```

**Unusual ports:**
```kusto
DeviceNetworkEvents
| where RemotePort !in (80,443,53,123,25,587,993,995)
| summarize Count = count(), Devices = dcount(DeviceId)
    by RemotePort, RemoteIP
| where Devices == 1
| order by Count desc
```

**Azure/AWS flow logs (schema varies):**
```kusto
AWSVPCFlow
| where Action == "ACCEPT"
| summarize Bytes = sum(Bytes) by SrcAddr, DstAddr, DstPort, bin(TimeGenerated, 1h)
| where Bytes > 100000000
```

### 12.4 Sigma-style skeleton

```yaml
title: Potential Horizontal Port Scan
logsource:
  category: firewall
detection:
  selection:
    action: deny
  timeframe: 5m
  condition: selection | count(dst_ip) by src_ip > 20
level: medium
```

---

## 13. Investigation workflow (step by step)

### Step 1 — Capture the facts
- Time (UTC), 5-tuple, protocol, bytes, packets, duration, flags/state.
- Capture point and exporter/interface.

### Step 2 — Classify the connection
- Handshake complete? Who closed/reset?
- One-to-many, many-to-one, one-to-one, periodic.
- Bytes symmetry and ratio.

### Step 3 — Attribute endpoints
- Asset inventory, DHCP/DNS names, user, OS.
- TTL/spoof plausibility: does the source make sense?

### Step 4 — Baseline the behaviour
- Has this pair communicated before? On this port? At this volume?
- Compare to peer assets in the same role.

### Step 5 — Correlate
- Firewall allow/deny ([Firewalls.md](Firewalls.md)).
- DNS ([DNS.md](DNS.md)), HTTP/TLS ([HTTP-HTTPS.md](HTTP-HTTPS.md)).
- EDR process, auth logs, switch/ARP events.

### Step 6 — Enrich external IPs
- Reputation, ASN, geo, passive DNS, Tor/VPN.

### Step 7 — Scope
- Same 5-tuple/behaviour across 7–30 days.
- Other hosts with same pattern.

### Step 8 — Verdict and response
- Benign/suspicious/malicious/unknown.
- Block/isolate/segment, reset credentials, preserve pcap.

### Step 9 — Document
Timeline, packets/flows, evidence hashes, scope, impact, actions.

---

## 14. Triage playbooks

### A. "Port scan detected"

1. Source internal or external? Authorised scanner?
2. Horizontal (many hosts) vs vertical (many ports) vs both.
3. Any `open`/`SYN/ACK` responses? Any follow-on connection?
4. If external and noisy → block/rate-limit.
5. If internal and unauthorised → isolate, find malware, hunt lateral movement.

### B. "SYN flood"

1. Confirm SYN rate, completion ratio, backlog/`SYN_RECEIVED` growth.
2. Source diversity — single host or spoofed/distributed?
3. Are legitimate users affected? Service degradation?
4. Enable SYN cookies/rate limiting, upstream scrubbing if needed.
5. Preserve logs; distinguish DoS from scan.

### C. "Possible ICMP tunnel"

1. Confirm payload size/frequency and symmetry.
2. Identify process (EDR) and destination.
3. Pull pcap; inspect echo payloads for encoded data.
4. **Confirmed → isolate, block, hunt, IR.**

### D. "Large outbound transfer (possible exfil)"

1. Destination sanctioned (backup/cloud/vendor)?
2. Process/user/time; baseline for asset.
3. Inspect protocol/TLS metadata; DLP verdict.
4. Unsanctioned + sensitive → escalate, block, preserve evidence.

### E. "Spoofed source / no return traffic"

1. Verify ingress filtering; is the source internal? If internal, spoofing is a finding.
2. Check TTL/OS mismatch and pcap direction.
3. If reflection/amplification → block amplifiers, rate-limit.
4. If internal spoofing → isolate host, find malware/rootkit.

### F. "Unexplained RSTs / session drops"

1. Who sent the RST? Correct sequence?
2. IPS/firewall reset? Load balancer idle timeout?
3. RST injection/censorship? On-path device?
4. Check for session hijack indicators (duplicate data, seq anomalies).

### G. "UDP amplification inbound"

1. Identify amplifier service and spoofed victim source.
2. Block/disable amplifier (memcached, NTP monlist, open DNS).
3. Rate-limit/scrub; contact provider if needed.
4. Assess whether the source was spoofed (it almost always is).

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| External scan, all filtered | Low |
| Internal scan from workstation | High |
| SYN flood with service impact | High–Critical |
| Confirmed ICMP/DNS tunnel | High–Critical |
| Confirmed exfiltration | Critical |
| Internal spoofing | High |
| Session hijack/RST injection | High |
| Amplification attack against you | High (availability) |

---

## 15. Commands

### Linux

```bash
# Interfaces / addresses / routes
ip -br addr
ip route
ip -6 route
ip neigh

# Connections
ss -tan
ss -tanp
ss -s
ss -tan state syn-sent
ss -tan state time-wait | wc -l

# Capture
sudo tcpdump -ni any -nn
sudo tcpdump -ni eth0 -nn 'tcp port 445'
sudo tcpdump -ni eth0 -nn -w cap.pcap 'host 10.0.0.5'
sudo tcpdump -r cap.pcap -nn -A

# Path / reachability
ping -c 4 8.8.8.8
traceroute -n 8.8.8.8
mtr -rwzc 20 8.8.8.8
nc -vz 10.0.0.5 445
```

### Windows

```powershell
Get-NetTCPConnection
Get-NetTCPConnection -State SynSent
Get-NetTCPConnection -State TimeWait | Measure-Object
Test-NetConnection 10.0.0.5 -Port 445
Test-NetConnection 8.8.8.8 -TraceRoute
ping 8.8.8.8
tracert 8.8.8.8
pathping 8.8.8.8
netstat -ano
Get-NetIPConfiguration
```

### Wireshark/tshark

```bash
tshark -r cap.pcap -q -z io,stat,1
tshark -r cap.pcap -q -z endpoints,ip
tshark -r cap.pcap -q -z conv,tcp
tshark -r cap.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport
tshark -r cap.pcap -Y 'tcp.stream eq 0' -T fields -e tcp.payload
```

---

## 16. Common false positives

| Alert | Often actually |
|---|---|
| Port scan | Vulnerability scanner, monitoring, inventory, backup. |
| Many SYN packets | Load balancer health checks, monitoring, retries after loss. |
| RSTs | Firewall/IPS resets, idle timeouts, app crashes, service restarts. |
| Retransmissions | Packet loss, MTU/PMTUD issues, congested links. |
| ICMP errors | Normal unreachable/PMTUD; rate-limited by design. |
| Large transfers | Backups, updates, video, cloud sync. |
| Rare ports | Legit admin tools, games, vendor agents, dev environments. |
| Fragmentation | VPN/overlay encapsulation, large DNS replies, PMTUD. |
| UDP 443 | QUIC/HTTP3 browser traffic. |
| Long-lived sessions | Keepalives, SSH, VPN, database pools. |
| `OTH` flows | Mid-capture start, asymmetric routing. |
| Timeouts | Idle session cleanup, NAT timeouts. |

**Rule of thumb:** look for **completion + repetition + corroboration**. One reset is nothing; sustained half-opens from one host is a scan or flood.

---

## 17. Hardening and recommendations

- **Ingress/egress filtering (BCP38)** to stop spoofing.
- **Stateful firewalls** at boundaries; default deny; see [Firewalls.md](Firewalls.md).
- **SYN cookies / connection limits / rate limiting** on exposed services.
- **Disable unused services and legacy protocols** (Telnet, FTP, SMBv1, LLMNR/NBT-NS if possible).
- **Segment** networks; restrict east-west (see [Routing-and-Switching.md](Routing-and-Switching.md)).
- **ICMP policy** — allow necessary types, rate-limit, block redirects.
- **Patch** network stacks and appliances; edge devices are targeted.
- **Monitor** flows, resets, scans, fragments, and ICMP anomalies.
- **NTP everywhere** for consistent timestamps.
- **Capture capability** (TAP/SPAN) with retention for investigations.
- **Tune IDS/IPS** and validate with purple-team traffic.
- **Block/limit** amplification services you don't need (open DNS, NTP monlist, memcached).
- **Control QUIC/HTTP3** if proxy visibility is required.

---

## 18. Lab practice plan

1. Capture normal traffic with tcpdump; identify handshakes, teardown, retransmissions.
2. Run `nmap` scans (SYN, connect, FIN, UDP) against lab VMs; compare packet patterns.
3. Generate a SYN flood with `hping3` in an isolated lab; observe `SYN_RECEIVED`, backlog, mitigation.
4. Use `hping3`/`scapy` to craft spoofed packets; see how ingress filtering blocks them.
5. Build an ICMP tunnel with `ptunnel` between lab VMs; inspect payloads.
6. Simulate fragmentation with `ping -s`/scapy; observe reassembly.
7. Parse pcaps with tshark; write filters for scans/resets/retransmissions.
8. Build flow records with `softflowd`; write SPL/KQL detections.
9. Do a tabletop from §14 with timeline and evidence.
10. Document a pcap-based incident end-to-end.

---

## 19. Self-test questions

1. What is the difference between TCP and UDP at the transport layer?
2. Walk through the TCP three-way handshake and teardown.
3. What does each TCP flag mean, and which are used in scans?
4. What is a half-open connection, and why does it matter?
5. What is the difference between `S0`, `REJ`, `SF`, and `RSTO` in Zeek?
6. How does a SYN flood work, and what mitigations exist?
7. How would you detect a horizontal vs vertical scan?
8. What is the difference between a SYN scan and a connect scan?
9. How does UDP scanning infer open/closed ports?
10. What are the main ICMP types, and which are abused?
11. How can ICMP be used as a covert channel?
12. What is IP spoofing, and what stops it?
13. Why are TTL values useful in investigations?
14. What is fragmentation, and how is it abused?
15. Which fields would you use to detect beaconing in flow data?

---

## 20. One-page revision checklist

- [ ] Model/encapsulation: Ethernet → IP → TCP/UDP → app; MTU/MSS.
- [ ] IPv4 header fields; protocol numbers (1/6/17/47/50/51/58/89).
- [ ] Addressing: RFC1918, loopback, link-local, CGNAT, multicast, documentation ranges.
- [ ] IPv6: 128-bit, /64, link-local, ULA, SLAAC/NDP, no broadcast/NAT, visibility gap.
- [ ] Fragmentation: DF/MF/offset, PMTUD, teardrop/overlap, reassembly timeouts.
- [ ] TTL: initial values (64/128/255), fingerprinting, anomalies.
- [ ] TCP: header, flags, handshake, teardown, states, window/retransmission, keepalive.
- [ ] UDP: connectionless, common services, amplification, UDP 443/QUIC gap.
- [ ] ICMP: types/codes, ping/traceroute, redirect, tunneling, Smurf/fraggle.
- [ ] Ports: ranges, common services, scan types, Nmap states.
- [ ] Attacks: SYN flood, ACK/RST floods, hijacking, spoofing, session reset, fragmentation, amplification, tunnels.
- [ ] Telemetry: NetFlow/IPFIX, Zeek conn/weird, Suricata, firewall, EDR; minimum fields.
- [ ] Detections: horizontal/vertical scans, incomplete handshakes, SYN flood, RST anomalies, odd flags, UDP probes, volume spikes, long sessions, rare ports, ICMP tunnels, fragments, spoofing, amplification, beaconing, churn, QUIC, OTH.
- [ ] Investigation: facts → classify → attribute → baseline → correlate → enrich → scope → verdict → respond → document.
- [ ] Triage: scan, SYN flood, ICMP tunnel, exfil, spoofing, RST injection, amplification.
- [ ] Commands: `ip`, `ss`, `tcpdump`, `tshark`, Wireshark filters, `Get-NetTCPConnection`, `Test-NetConnection`.
- [ ] Hardening: BCP38, stateful filtering, SYN cookies, disable legacy, segment, ICMP policy, patch, monitor, NTP, capture, tune, block amplifiers, control QUIC.

---

> **Navigation:** [Roadmap index](../README.md) · [← Routing & Switching](Routing-and-Switching.md) · [VPNs →](VPNs.md)
