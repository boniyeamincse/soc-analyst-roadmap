# DNS — SOC Analyst Study Notes

> Goal: understand DNS deeply enough to **read DNS logs, spot malicious patterns, triage alerts, and explain findings** in an incident report.
> Work top-to-bottom once, then use the checklists in §18–§20 for revision.

---

## 0. How to use this note

1. Read §1–§6 for the mental model (how DNS actually works).
2. Read §7–§9 for the attack surface (what adversaries do with DNS).
3. Read §10–§14 for the SOC work (logs, detection, investigation, triage).
4. Practise §15–§17 and answer §19 without looking.
5. Re-read only §18–§20 before an interview or shift.

---

## 1. Why DNS matters to a SOC analyst

- **Almost every intrusion touches DNS.** Initial access (phishing domains), C2 (beaconing), exfiltration (tunneling), lateral movement (internal name resolution), and discovery all generate DNS queries.
- **DNS is one of the few protocols you can log cheaply and centrally.** Most environments aggregate DNS logs from the resolver, domain controller, proxy, or EDR.
- **DNS is frequently the earliest observable signal.** A query to a newly registered domain can appear *before* malware executes its payload.
- **Attackers know this** — hence DGA, DNS tunneling, DoH/DoT, fast flux, and "living-off-the-land" domains. Your job is to understand both sides.

**SOC outcome for this topic:** given a DNS query log line, you can answer:
- Who asked? (`src_ip`, `user`, `host`)
- What was asked? (`query`, `qtype`, `rcode`)
- Where did it go? (resolver, response IP, ASN, geo)
- Is it normal for this asset/user/time?
- What should I do next? (close / enrich / escalate / contain)

---

## 2. Core concepts and vocabulary

| Term | Meaning |
|---|---|
| **Namespace** | The hierarchical tree of names (root → TLD → domain → subdomain). |
| **Domain name** | A label in that tree, e.g. `example.com`. |
| **FQDN** | Fully Qualified Domain Name, ends with the root dot: `www.example.com.` |
| **Label** | One dot-separated component (`www`, `example`, `com`). Max 63 bytes each; total name ≤ 253 bytes. |
| **TLD** | Top-Level Domain (`.com`, `.org`, `.bd`, `.io`). |
| **Root** | The `.` at the top; served by 13 root server identities (hundreds of anycast instances). |
| **Zone** | A portion of the namespace managed by one authoritative server (e.g. `example.com` zone). |
| **Authoritative server** | Holds the real records for a zone and answers definitively. |
| **Recursive resolver** | Does the legwork for clients (ISP resolver, `8.8.8.8`, enterprise resolver). |
| **Stub resolver** | The tiny client-side resolver in the OS that asks the recursive resolver. |
| **Forwarder** | A resolver that passes queries to another resolver (common in AD). |
| **Caching** | Resolvers/OS keep answers for a TTL to reduce load. |
| **TTL** | Time To Live — seconds a record may be cached. |
| **Negative caching** | Caching of NXDOMAIN/NODATA answers (governed by SOA minimum). |
| **Delegation** | Parent zone points to child zone's authoritative servers (NS records + glue). |
| **Glue record** | A/AAAA provided by the parent so the child's NS can be reached. |
| **Recursion** | Resolver performs the full lookup on the client's behalf. |
| **Iteration** | Each server refers the resolver to the next server ("ask them"). |
| **Authoritative vs recursive** | "I own this zone" vs "I'll find it for you". Never expose an open recursive resolver to the internet. |
| **Internal zone** | AD-integrated zone (e.g. `corp.local`) resolved only inside the network. |
| **Split-horizon DNS** | Same name resolves differently inside vs outside. |
| **Open resolver** | A recursive resolver that answers anyone — abused for amplification. |

### Name structure

```
www . example . com .
 │      │        │    └── root (.)
 │      │        └────── TLD (com)
 │      └─────────────── registered domain (example.com)
 └────────────────────── host / subdomain label (www)
```

### Common name categories you will meet in alerts

- **Registered domain / eTLD+1** — `example.com` (use for grouping subdomains).
- **Subdomain** — `login.example.com`.
- **CNAME chain** — aliases resolved step by step.
- **Wildcard** — `*.example.com` answers any label.
- **IDN / punycode** — `xn--...` form of a Unicode domain (homograph attacks).
- **Typosquat** — `examp1e.com`, `exampel.com`, `example[.]com`.
- **Dangling / takeover** — a CNAME points to a de-provisioned cloud resource.

---

## 3. DNS record types

### Must know

| Type | Purpose | SOC relevance |
|---|---|---|
| **A** | Name → IPv4 | Where the host actually goes; pivot to IP reputation/ASN. |
| **AAAA** | Name → IPv6 | Same, plus IPv6 blind spots. |
| **CNAME** | Alias to another name | Long chains, dangling CNAMEs, CDN fronts. |
| **MX** | Mail exchanger | Phishing infra, SPF/DMARC context. |
| **NS** | Authoritative name servers | Delegation, zone ownership, hijack checks. |
| **TXT** | Free text | SPF, DKIM, DMARC, domain verification, malware often abuses TXT for C2 data. |
| **SOA** | Zone metadata (primary NS, admin, serial, timers) | Negative-cache TTL; AXFR detection. |
| **PTR** | Reverse lookup IP → name | Attribution; PTR ≠ identity. |
| **SRV** | Service location (host:port) | Kerberos (`_kerberos._tcp`), LDAP, SIP; AD recon. |
| **CAA** | Which CAs may issue certs | Certificate mis-issuance checks. |

### Good to know

| Type | Purpose |
|---|---|
| **DS / DNSKEY / RRSIG / NSEC(3)** | DNSSEC chain of trust and denial of existence. |
| **HTTPS / SVCB** | Service binding + hints (newer than A/AAAA usage). |
| **NAPTR** | Service discovery (legacy, SIP/ENUM). |
| **TLSA** | DANE — cert pinning via DNS. |
| **HINFO** | Host info (rare; sometimes abused for tunneling). |
| **ANY** | "Give me everything" — abused for amplification; often blocked. |

### Non-DNS name resolution (related, often logged alongside)

- **LLMNR** (UDP 5355) and **NBT-NS** (UDP 137) — Windows fallback name resolution; abused by **Responder** for credential capture (poisoning).
- **mDNS** (UDP 5353) — local discovery (Bonjour/Avahi).
- **WPAD** — proxy auto-discovery; classic credential-theft/rogue-proxy target.
- **NetBIOS name service** — legacy, still noisy in Windows networks.

> These are *not* DNS, but a SOC analyst must recognise them because "DNS poisoning"-style attacks often use LLMNR/NBT-NS.

---

## 4. Resolution process (step by step)

### 4.1 Recursive resolution (the normal case)

1. Application calls `getaddrinfo("www.example.com")`.
2. OS **stub resolver** checks local hosts file → local cache → configured DNS servers.
3. If not cached, stub sends a **recursive query** (RD=1) to the **recursive resolver** (UDP 53).
4. Resolver checks its own cache.
5. If missing, resolver walks the tree with **iterative queries**:
   1. Ask a **root server** → returns referral to the `.com` TLD servers.
   2. Ask a **`.com` TLD server** → returns referral to `example.com`'s authoritative NS.
   3. Ask the **authoritative server** → returns the A/AAAA (and CNAME chain) answer.
6. Resolver caches the answer for the TTL (honouring decremented TTL) and returns it to the stub.
7. OS caches it (bounded by OS cache policy) and returns the IP to the app.

Response flags you will read in logs/pcap: `QR`, `AA` (authoritative answer), `RD` (recursion desired), `RA` (recursion available), `TC` (truncated → retry over TCP), `rcode` (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, FORMERR).

### 4.2 Caching and TTL — why "it resolved yesterday" is not evidence

- **TTL too high** → stale answers after an incident response change (hard to flush everywhere).
- **TTL too low (0–60s)** → classic **fast flux** / frequently changing infrastructure; a red flag.
- Resolver cache, OS cache, browser cache, and CDN answers can all disagree.
- When investigating, always record: **timestamp, query, answer, TTL, resolver, src IP**.

### 4.3 DNS message anatomy (quick reference)

| Section | Contents |
|---|---|
| Header | ID, flags, counts (QD/AN/NS/AR) |
| Question | QNAME, QTYPE, QCLASS |
| Answer | RRs answering the query |
| Authority | NS/SOA referring to authoritative servers |
| Additional | Glue A/AAAA, OPT (EDNS) |

EDNS(0) adds larger UDP payload sizes, DO bit (DNSSEC OK), client subnet (ECS — privacy concern), and cookies.

### 4.4 Transport

| Transport | Port | When |
|---|---|---|
| UDP | 53 | Default; small answers |
| TCP | 53 | Truncated (TC=1), large answers, zone transfers |
| DoT (DNS over TLS) | 853 | Encrypted, dedicated port |
| DoH (DNS over HTTPS) | 443 | Encrypted, blends into web traffic |
| DoQ (DNS over QUIC) | 853/UDP | Emerging |
| DNSCrypt | 443/other | Third-party encryption |

> Encrypted DNS is a **visibility gap**. If endpoints use DoH/DoT to external resolvers, your resolver logs go blind. Detect via EDR/browser policy and network egress to known DoH providers.

---

## 5. DNS infrastructure roles

| Role | What it does | SOC note |
|---|---|---|
| **Root servers** | Referral at the top | Rarely logged directly. |
| **TLD servers** | Referral for a TLD | `.com`, `.bd`, etc. |
| **Authoritative NS** | Owns a zone | Check NS/TTL when judging a domain. |
| **Recursive resolver** | Answers clients | **Primary log source.** ISP, `8.8.8.8`, `1.1.1.1`, enterprise resolver. |
| **Forwarder** | Passes to upstream | AD DNS often forwards to ISP/cloud. |
| **AD-integrated DNS** | Zone data in AD | Logs show internal queries and DC replication. |
| **DNS sinkhole** | Returns a safe/blocked IP for bad domains | Sinkhole hits are high-value alerts. |
| **RPZ** | Response Policy Zone — policy-based blocking/rewriting | Alerts often come from RPZ hits. |
| **DNS firewall / secure resolver** | Cloud filtering (e.g. Cisco Umbrella, Infoblox) | Logs + categories are gold for triage. |

---

## 6. Zones, delegation, and zone transfers

- A **zone file** contains the records for a zone; the **SOA serial** increments on change.
- **Delegation** is done with **NS records** in the parent plus **glue** A/AAAA.
- **AXFR** = full zone transfer (TCP 53); **IXFR** = incremental.
- **AXFR should be restricted** to known secondaries. An internet-exposed AXFR leaks the entire internal namespace and is a common finding.
- Authoritative servers must **refuse recursion** for unknown clients to avoid being an open resolver.

---

## 7. DNSSEC (and why it still fails)

- **Purpose:** cryptographic integrity/authenticity of DNS answers (not confidentiality).
- **Chain of trust:** root `DNSKEY` → `DS` in parent → child `DNSKEY` → `RRSIG` over records.
- **Denial of existence:** `NSEC` (proves what does not exist, can leak names) or `NSEC3` (hashed, better).
- **Validation** happens at a validating resolver; a **non-validating** stub will accept bogus data.
- **Common gaps:** zone not signed, broken chain, expired signatures, `SERVFAIL` because of misconfiguration, and **DNS tunneling still works over DNSSEC-signed domains** (signatures protect records, not payload semantics).
- **SOC angle:** `SERVFAIL` spikes can be an attack/blocking side-effect; DNSSEC does **not** stop DGA, tunneling, or phishing.

---

## 8. Attack surface — what adversaries do with DNS

### 8.1 Spoofing / cache poisoning

- Attacker injects a forged answer into a resolver's cache; clients then go to attacker IP.
- Classic vectors: predictable TXID/ports, **Kaminsky-style** birthday attacks, on-path spoofing, malicious local resolver, rogue DHCP handing out attacker DNS.
- **Detection:** answer doesn't match authoritative data, sudden changes for a stable domain, client-subnet/EDNS oddities, rogue DNS server IP on the LAN.
- **Defence:** DNSSEC validation, randomized source ports/TXID, 0x20 encoding, egress filtering (only approved resolvers), DHCP snooping, DNS over TLS internally.

### 8.2 DNS tunneling / exfiltration

- Encodes data in **QNAME labels**, TXT records, or query volume; C2 and exfil channel.
- **Signals:**
  - Very long labels (50–63 chars) or long total names.
  - High-entropy subdomains (base32/base64-looking).
  - High volume of **unique** subdomains under one parent (thousands).
  - Repeated **TXT** or **NULL**/`ANY` queries.
  - Consistent beacon interval, small jitter.
  - Unusual record types for the environment.
  - Large response sizes / many answers.
- **Tools attackers use:** iodine, dnscat2, dns2tcp, Cobalt Strike DNS beacon, Sliver, custom scripts.
- **Detection:** entropy + volume + uniqueness baselines per host; see §11.
- **Triage:** identify process making the queries (EDR), pull pcap, check data volume, isolate host.

### 8.3 DGA (Domain Generation Algorithms)

- Malware generates many candidate domains; only a few are registered for C2.
- **Signals:** hundreds/thousands of **NXDOMAIN** from one host, random-looking labels, consonant clusters, varied TLDs, bursty timing.
- **Detection:** NXDOMAIN ratio per host, lexical randomness scoring, newly seen parent domains, low reputation.
- **Caveat:** some legitimate software (telemetry, CDNs, security products) generates NXDOMAIN noise — baseline first.

### 8.4 Fast flux

- Rapidly changing A records / NS / CNAMEs with very low TTL to hide C2 or phishing.
- **Signals:** TTL 0–60, answers rotating across many ASNs/countries, high NS churn, many A records for one name.

### 8.5 Domain fronting / CDN abuse

- Uses a trusted CDN domain with a different `Host`/SNI to hide the true destination.
- **DNS view:** query goes to a benign CDN name; **TLS SNI/Host mismatch** is the tell. DNS alone won't show it — correlate proxy/TLS logs.

### 8.6 Typosquatting, homographs, and lookalikes

- `micros0ft.com`, `paypa1.com`, punycode `xn--...`, added/hyphenated words.
- **Detection:** newly registered domains, brand similarity, low reputation, unusual TLDs (`.top`, `.xyz`, `.tk`, free TLDs), certificate transparency + brand monitoring.

### 8.7 Subdomain takeover / dangling CNAME

- CNAME points to an unclaimed cloud resource; attacker claims it.
- **Detection:** CNAME to `*.s3.amazonaws.com`, `*.cloudfront.net`, `*.herokuapp.com`, `*.azurewebsites.net` that returns provider error pages.
- This is usually a **web** issue, but DNS logs reveal the dangling chain.

### 8.8 DNS hijacking / registrar compromise

- NS records changed, registrar account taken over, or resolver config changed.
- **Detection:** unexpected NS/SOA changes, domain suddenly resolving elsewhere, certificate changes.

### 8.9 DoS and amplification

- **Reflection/amplification** using open resolvers and `ANY`/`DNSKEY` queries (spoofed source).
- **Water-torture / random subdomain floods** against authoritative servers.
- **Detection:** traffic spikes, high `ANY` volume, spoofed sources, resolver queue/CPU alerts.

### 8.10 DNS rebinding

- A malicious page resolves its own domain to a private IP after TTL expiry, bypassing same-origin assumptions to reach internal services.
- **Detection:** browser process querying external domain that returns `127.0.0.1`/RFC1918, TTL 0, repeated resolution changes.

### 8.11 Internal DNS abuse in AD

- **ADIDNS** records can be poisoned for coercion/relay (e.g. adding records for `wpad`, `*` wildcard).
- **Detection:** new/modified DNS records by non-admin accounts, wildcard records, `wpad` queries.
- **Kerberos/LDAP SRV** lookups reveal lateral movement targets — cross-reference DC logs.

### 8.12 DNS as a "trusted" blind spot

- Attackers prefer **legitimate services** (GitHub, Dropbox, Telegram, Discord, paste sites, cloud storage) so DNS looks benign.
- Therefore DNS is **necessary but not sufficient** — correlate with proxy, TLS, EDR, and authentication logs.

---

## 9. Where DNS logs come from (SOC data sources)

| Source | Typical fields | Strengths / gaps |
|---|---|---|
| **Enterprise recursive resolver / DNS firewall** | timestamp, client IP, qname, qtype, rcode, answer, category, action | Best central view; misses DoH/DoT and some internal zones. |
| **AD DNS server logs (Windows DNS)** | Event 256 (query), 257 (response), 5501 (AXFR), 150/770 (policy) | Internal names + DC context; can be noisy/disabled. |
| **Domain controller (Security logs)** | 4768/4769 (Kerberos), LDAP | Confirms AD-dependent activity. |
| **Proxy / secure web gateway** | CONNECT host, SNI, URL | Catches DoH and tunneling over TLS. |
| **EDR / Sysmon** | Event 22 (DNS query), process context | **Best process attribution**; only on covered endpoints. |
| **Zeek / Suricata (network)** | `dns.log`, `dns_query`, `dns_answer` | Passive, good for pcap and validation. |
| **Firewall / netflow** | IP, port 53/853/443 | Volume, egress to odd resolvers. |
| **Cloud DNS (Route53, Cloud DNS, Azure DNS)** | query logs | Cloud workloads; often missed. |
| **DHCP** | lease, DNS servers handed out | Detects rogue DNS via DHCP. |
| **Certificate Transparency / passive DNS** | historical resolutions | Enrichment, domain age, infrastructure pivoting. |

**Minimum viable DNS logging checklist:**
- [ ] All client DNS goes to a **logged, controlled resolver** (block direct 53 egress).
- [ ] Query logging enabled with **client IP + qname + qtype + rcode + answer**.
- [ ] Logs shipped to SIEM with **15–30 day hot retention** (longer for investigations).
- [ ] **DoH/DoT egress controlled or monitored**.
- [ ] Sysmon Event ID 22 rolled out where possible.
- [ ] Passive DNS / threat-intel enrichment integrated.

---

## 10. DNS log fields you must be able to read

Example (Zeek-style, simplified):

```
ts=2026-10-27T13:40:12Z  id.orig_h=10.10.5.23  query=api[.]evil-cdn[.]xyz
qtype=A  rcode=NOERROR  answers=185.199.108.1  TTL=60  trans_id=0x1a2b
```

| Field | Why it matters |
|---|---|
| `ts` | Timeline anchor; correlate with EDR/proxy/auth. |
| `src_ip` / `host` / `user` | Scope of compromise. |
| `query` / `qname` | The claim being made; inspect length/entropy/lexical pattern. |
| `qtype` | TXT/ANY/NULL are suspicious; A/AAAA normal. |
| `rcode` | `NXDOMAIN` = DGA signal; `SERVFAIL` = breakage/block; `REFUSED` = policy. |
| `answers` | Where the host really goes; enrich IP reputation/ASN/geo. |
| `TTL` | 0–60 = fast flux candidate. |
| `trans_id`, `flags` | Spoofing/malformed analysis. |
| `resolver` | Which server answered (internal vs external). |
| `category` / `action` | Secure resolver verdict (blocked/malware/phishing). |

---

## 11. Detection engineering for DNS

> Always **baseline per environment** before enabling volume-based rules. A rule that fires on "1000 queries/hour" will page you forever on a busy build server.

### 11.1 High-signal detection ideas

1. **DGA-like NXDOMAIN burst** — one host, many NXDOMAIN, random labels, short window.
2. **Tunneling volume + uniqueness** — high unique-subdomain count under one parent, long labels, TXT heavy.
3. **Newly registered domain (NRD) access** — domain age < 30 days from internal host, especially from finance/HR.
4. **Rare parent domain seen once across the estate** — long-tail domains.
5. **DoH/DoT to external resolvers** — egress to known DoH IPs/hostnames or port 853.
6. **Direct-to-internet DNS** — client querying `8.8.8.8`/`1.1.1.1` instead of internal resolver.
7. **Sinkhole/RPZ hits** — any hit is worth a look, repeated hits are incidents.
8. **Suspicious qtype** — TXT/NULL/ANY spikes.
9. **Low TTL + rotating answers** — fast flux.
10. **Domain/IP mismatch** — internal name resolving to external IP (DNS rebinding / split-horizon abuse).
11. **Rogue resolver via DHCP** — DHCP option 6 not matching approved resolvers.
12. **AXFR attempts** — external or unauthorized zone transfers.
13. **Lookalike brand domains** — lexical similarity to owned brands.
14. **High-entropy long labels** (`len(qname label) > 40`, entropy > 3.5).
15. **Beacon periodicity** — near-constant inter-query interval ± jitter to same parent.

### 11.2 Splunk SPL examples

**NXDOMAIN burst per host (5 min buckets):**
```spl
index=dns sourcetype=dns
| where rcode="NXDOMAIN"
| bin _time span=5m
| stats count as nx_count dc(query) as unique_q by src_ip, _time
| where nx_count > 200 AND unique_q > 100
| sort -nx_count
```

**Long / high-entropy query labels:**
```spl
index=dns sourcetype=dns
| eval label=mvindex(split(query,"."),0)
| eval label_len=len(label)
| where label_len >= 40
| stats count values(query) as samples by src_ip
| where count > 20
```

**Unique subdomains per parent domain (tunnel heuristic):**
```spl
index=dns sourcetype=dns
| eval parent=mvjoin(mvindex(split(query,"."), 1, 40), ".")
```
> Simpler and more reliable: extract the registered domain in your pipeline (e.g. `url`/`domain` extraction or an asset lookup), then:
```spl
index=dns sourcetype=dns
| bin _time span=1h
| stats dc(query) as uniq_q values(qtype) as qtypes by src_ip, parent_domain, _time
| where uniq_q > 1000
| sort -uniq_q
```

**TXT-heavy traffic:**
```spl
index=dns sourcetype=dns qtype=TXT
| stats count values(query) as q by src_ip
| where count > 50
| sort -count
```

**Clients bypassing internal resolver:**
```spl
index=dns sourcetype=dns
| where resolver IN ("8.8.8.8","1.1.1.1","9.9.9.9")
| stats count by src_ip, resolver
```

### 11.3 Microsoft Sentinel / Defender KQL examples

**Rare domains seen across the estate (DeviceNetworkEvents DNS):**
```kusto
DeviceNetworkEvents
| where ActionType == "DnsConnectionInspected" or ActionType has "Dns"
| summarize Hosts = dcount(DeviceId), FirstSeen = min(TimeGenerated)
    by RemoteUrl, bin(TimeGenerated, 1d)
| where Hosts <= 2
| order by FirstSeen desc
```

**DNS query volume anomaly per device:**
```kusto
DeviceEvents
| where ActionType == "DnsQueryResponse"
| summarize Queries = count(), Unique = dcount(AdditionalFields)
    by DeviceName, bin(TimeGenerated, 1h)
| where Queries > 2000 or Unique > 500
```

**NXDOMAIN-heavy devices (if you ingest resolver logs into `CommonSecurityLog` or a custom table):**
```kusto
DnsEvents
| where ResultCode == "NXDOMAIN" or ResponseCodeName == "NXDOMAIN"
| summarize Nx = count(), Unique = dcount(Name) by ClientIP, bin(TimeGenerated, 15m)
| where Nx > 100 and Unique > 50
```

> Table/field names vary by connector (DnsEvents, CommonSecurityLog, custom). Always confirm the schema in your tenant before deploying a rule.

### 11.4 Zeek / Suricata signals

- `dns.log`: `query`, `qtype_name`, `rcode_name`, `answers`, `TTL`, `rejected`.
- Suricata: DNS keywords in rules (`dns_query`, `dns.rrtype`), plus JA3/JA4 for DoH.
- Build **entropy** and **length** scripts in Zeek for tunneling; use `known_domains` / intel frameworks for NRD and blocklists.

### 11.5 Sigma-style rule skeleton (concept)

```yaml
title: High Volume of NXDOMAIN Responses from Single Host
logsource:
  product: dns
detection:
  selection:
    rcode: NXDOMAIN
  timeframe: 5m
  condition: selection | count(query) by src_ip > 200
level: medium
```

---

## 12. Investigation workflow (step by step)

Use this every time a DNS alert fires.

### Step 1 — Capture the facts
- Timestamp (UTC), source IP/host/user, query, qtype, rcode, answers, TTL, resolver, count.
- Which detection fired and why (threshold? reputation? policy?).

### Step 2 — Establish the timeline
- First-seen and last-seen of the domain across the estate (24h/7d/30d).
- Did it start after a login, email open, USB insert, or software install?
- Pull adjacent logs ±15 minutes.

### Step 3 — Attribute the process
- EDR/Sysmon Event 22 → which process made the query? Parent process? Command line? Hash?
- Browser vs service vs unknown binary changes the severity dramatically.

### Step 4 — Enrich the domain
- **Age / registration date** (NRD < 30 days is suspicious).
- **Reputation** (VirusTotal, URLhaus, AlienVault OTX, abuse.ch, vendor TI).
- **Passive DNS** — what has it resolved to recently? Shared infrastructure?
- **ASN / geo / hosting type** — bulletproof hosting, VPS, Tor, cloud.
- **Certificate** — issuer, SANs, first seen (CT logs).
- **Lexical** — entropy, length, typosquat similarity, suspicious TLD.
- **Category** — secure resolver category (newly seen, malware, phishing, uncategorized).

### Step 5 — Enrich the answers (IPs)
- Reputation, ASN, geo, hosting provider, open ports (careful: no unauthorised scanning).
- Are multiple hosts in the estate resolving the same domain? (scope).
- Is the IP shared/CDN — reputation may be noisy.

### Step 6 — Determine the verdict
- **Benign** — known vendor/CDN, baseline exists, process expected.
- **Suspicious** — NRD/uncategorized, odd process, single host, low volume.
- **Malicious** — TI hit + anomalous process/volume + related alerts.
- **Unknown** — document gaps and escalate rather than guess.

### Step 7 — Scope and respond
- Hunt the domain/IP across 30 days of DNS, proxy, EDR, auth logs.
- Identify all affected hosts/users.
- Contain (isolate host, block domain/IP, sinkhole) per IR playbook.
- Preserve evidence (pcap, logs, hashes) before remediation.
- Document IOCs and close-out with lessons learned.

### Step 8 — Write it up
State: what happened, evidence, scope, impact, actions taken, recommendations. Link every claim to a log line or artifact.

---

## 13. Commands cheat sheet

```bash
# Basic lookups
dig example.com A
dig example.com AAAA
dig example.com MX
dig example.com NS
dig example.com TXT
dig example.com SOA
dig example.com ANY            # often blocked; may trigger alarms

# Reverse lookup
dig -x 8.8.8.8

# Use a specific resolver
dig @1.1.1.1 example.com A
dig @10.0.0.10 internal.corp A

# Trace the delegation path
dig +trace example.com

# Short output / batch
dig +short example.com
dig -f domains.txt +short

# DNSSEC validation status
dig +dnssec +cd example.com
dig example.com DNSKEY
dig example.com DS

# Zone transfer (only with authorisation)
dig AXFR example.com @ns1.example.com
# host -l example.com ns1.example.com

# TTL / answer inspection
dig +noall +answer +ttlid example.com

# DNSSEC / EDNS debugging
dig +bufsize=4096 +edns=0 example.com
```

```powershell
# Windows
Resolve-DnsName example.com -Type A
Resolve-DnsName example.com -Server 10.0.0.10 -DnsOnly
Resolve-DnsName -Name 8.8.8.8 -Type PTR
ipconfig /displaydns
ipconfig /flushdns
Get-DnsClientServerAddress
Get-DnsServerZone            # DNS server role
Get-DnsServerResourceRecord -ZoneName "corp.local"
Resolve-DnsName example.com -DnssecOk
```

```bash
# Linux clients
nslookup example.com
nslookup example.com 1.1.1.1
host example.com
host -t TXT example.com
resolvectl query example.com
resolvectl status
cat /etc/resolv.conf
systemd-resolve --statistics
```

```bash
# Passive / historical enrichment (use within engagement scope)
# subfinder / amass / dnsx for authorised recon
dnsx -d example.com -a -resp
# whois example.com        (registration data / age)
# curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq
```

> **Rules of engagement:** never run AXFR, port scans, or internet-wide queries against third parties without written authorisation. Querying public resolvers/threat-intel APIs is fine; attacking is not.

---

## 14. Triage playbook — DNS alert → decision

### Alert type A: "Host queried newly registered / suspicious domain"

1. Confirm the detection and record fields.
2. Identify process via EDR/Sysmon 22.
3. Check domain age, reputation, passive DNS, certificate.
4. Check whether other hosts queried it (scope).
5. Check for follow-on activity: HTTP/HTTPS to the answer IP, file writes, child processes, credential access.
6. **If TI-malicious + unexpected process + follow-on activity → escalate to incident.**
7. Block domain/IP, isolate if needed, hunt estate-wide.

### Alert type B: "Possible DNS tunneling"

1. Confirm query volume, uniqueness, label length/entropy, qtype.
2. Identify the process; is it a known DNS tool or a script?
3. Measure data volume (query + response bytes) over time.
4. Pull pcap; look for periodic beacons and encoded payloads.
5. Check egress firewall logs for accompanying connections.
6. **If confirmed → isolate host, capture memory/disk, block parent domain, hunt other hosts.**

### Alert type C: "Client bypassing DNS controls / using DoH"

1. Verify destination (known DoH provider?).
2. Check endpoint/browser configuration and installed software (VPN, browser, malware).
3. Determine whether it is policy violation, shadow IT, or malware evasion.
4. Enforce resolver policy; consider blocking external DoH.
5. Document as a control gap even if benign.

### Alert type D: "Sinkhole/RPZ hit"

1. What was blocked, from which host, at what time?
2. Was the query preceded by phishing email, link click, or macro execution?
3. Check for retries or alternate domains (attackers rotate).
4. If repeated/successful elsewhere → incident; else note and monitor.

### Alert type E: "DNS spoofing / resolver anomaly"

1. Compare answers to authoritative data (`dig +trace`).
2. Check resolver configuration, DHCP option 6, rogue devices.
3. Look for on-path anomalies, ARP spoofing, rogue AP.
4. Rotate/secure resolver, flush caches, validate DNSSEC.
5. Assess credential exposure if traffic was redirected.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| Single blocked phishing domain, no execution | Low |
| NRD query from expected browser, no payload | Low–Medium |
| Rogue executable querying DGA domains | High |
| Confirmed DNS tunneling with data transfer | High–Critical |
| Resolver compromise / internal DNS poisoning | Critical |

---

## 15. IOC analysis and enrichment (DNS-specific)

**Domain IOCs to extract:** qname, parent domain, TLD, all answers, NS, MX, TXT, certificate SANs, passive-DNS history, first/last seen, query count, affected hosts.

**Pivots:**
- Domain → IPs → other domains on the same IP (passive DNS / reverse-IP).
- Domain → certificate → other domains with same cert/issuer.
- Domain → WHOIS/registrar → related registrations.
- Domain → email sender domain → phishing campaign.
- IP → ASN/hosting → campaign infrastructure.
- Hash/process → parent domain queries → C2 pattern.

**Confidence ladder:**
1. Reputation hit only → *suspicious*.
2. Reputation + anomalous process → *likely malicious*.
3. Above + follow-on HTTP/TLS/file activity → *confirmed*.
4. Above + data transfer or lateral movement → *incident*.

**IOC hygiene:** record the exact string as observed (`evil[.]com` defanged in reports), timestamp, source, and confidence. Do not invent TTL/IPs.

---

## 16. Common false positives (do not escalate without context)

| Looks suspicious | Often actually |
|---|---|
| Many NXDOMAIN | Browser prefetch, telemetry, security agents, typo-laden user traffic, CDN probes. |
| Long random subdomains | CDN/analytics/session tokens (e.g. telemetry endpoints), antivirus cloud lookups. |
| TXT queries | SPF/DKIM/DMARC checks, domain verification, mail flow. |
| DoH traffic | Browser defaults (Firefox/Chrome), privacy tools, OS resolver. |
| Low TTL | CDNs, load balancers, dynamic DNS (some legit). |
| Newly registered domain | Marketing, SaaS trials, legitimate new vendors. |
| Multiple A records | CDNs, round-robin, load balancing. |
| Sinkhole hits | User clicked a blocked link; not necessarily compromise. |
| Internal name → public IP | Split-horizon design, VPN, cloud migration. |

**Rule of thumb:** correlation beats single-signal verdicts. One weird query is noise; weird query + unusual process + follow-on connection is a case.

---

## 17. Hardening and recommendations (what you tell the client)

- Force all DNS through **approved, logged resolvers**; block direct 53/853 egress and unknown DoH.
- Enable **query logging** at the resolver and **Sysmon 22** on endpoints.
- Deploy **DNSSEC validation** where feasible; monitor `SERVFAIL`.
- Use **RPZ / secure DNS** with tuned categories; alert on sinkhole hits.
- Restrict **AXFR**; disable recursion for untrusted clients; patch DNS software.
- Enforce **DHCP snooping**, **dynamic ARP inspection**, and fixed DNS via DHCP option 6 / GPO.
- Baseline and alert on **NRD**, **DGA/NXDOMAIN bursts**, **tunneling entropy/volume**, **fast flux**, **lookalike brands**.
- Monitor **internal DNS record changes** (ADIDNS) and **wildcard records**.
- Retain DNS logs long enough for IR (≥ 30–90 days recommended).
- Add DNS indicators to **blocklists** and **threat-intel feeds**; automate enrichment.
- Include DNS in **purple-team** exercises (DGA sim, tunneling sim with dnscat2 in a lab).

---

## 18. Lab practice plan

1. **Set up a resolver you can see** — Pi-hole / Unbound / BIND / Windows DNS in a lab VM; enable query logging.
2. **Generate normal traffic** — browse, `dig` common domains, observe A/AAAA/CNAME/TXT/TTL.
3. **Generate NXDOMAIN noise** — query random labels; write a Splunk/KQL rule; tune threshold.
4. **Simulate DGA** — script random domains; confirm the NXDOMAIN burst heuristic.
5. **Simulate tunneling** — `dnscat2` or `iodine` between lab VMs (isolated network); inspect pcap and logs.
6. **Simulate fast flux** — low TTL, multiple A records; observe rotation.
7. **Parse with Zeek** — read `dns.log`, filter fields, build a simple detection.
8. **Enrich a domain** — WHOIS age, VT, passive DNS, CT logs; write a one-page verdict.
9. **Do a tabletop** — "host beaconing to `api[.]suspicious[.]xyz`"; run §14 playbook end-to-end.
10. **Document** — write an incident note with timeline, evidence, scope, verdict, actions.

---

## 19. Self-test questions (answer without notes)

1. Difference between recursive and iterative resolution?
2. What does `AA` mean, and why does it matter in a spoofing investigation?
3. Why is `NXDOMAIN` a DGA signal, and what else causes it?
4. List five indicators of DNS tunneling.
5. Why is a TTL of 30 seconds suspicious in some contexts?
6. What is the difference between DoT and DoH, and what visibility gap does each create?
7. What does DNSSEC protect against — and what does it **not** protect against?
8. How would you detect a client bypassing the corporate resolver?
9. What is a dangling CNAME, and why is it dangerous?
10. What logs would you pull to attribute a DNS query to a process?
11. How do LLMNR/NBT-NS relate to DNS attacks (Responder)?
12. Give three pivots from a suspicious domain.
13. When would you NOT escalate a newly registered domain alert?
14. What is DNS rebinding, and what would the resolver logs show?
15. What would you block first: domain, IP, or hash? Why? (Discuss trade-offs.)

---

## 20. One-page revision checklist

- [ ] Resolution flow: stub → recursive → root → TLD → authoritative → cache → client.
- [ ] Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA, DNSSEC RRs.
- [ ] Transports: 53/UDP, 53/TCP, 853/DoT, 443/DoH.
- [ ] Flags/rcodes: AA, RD, RA, TC, NOERROR, NXDOMAIN, SERVFAIL, REFUSED.
- [ ] Attacks: spoofing, tunneling, DGA, fast flux, typosquat, takeover, hijack, rebinding, DoS, DoH evasion.
- [ ] Detection signals: NXDOMAIN bursts, entropy, label length, unique subdomains, TXT/ANY, low TTL, NRD, sinkhole hits, resolver bypass.
- [ ] Log sources: resolver, AD DNS 256/257/5501, Sysmon 22, Zeek `dns.log`, proxy/SNI, DHCP, cloud DNS.
- [ ] Investigation: facts → timeline → process attribution → domain/IP enrichment → verdict → scope → contain → report.
- [ ] Enrichment: age, reputation, passive DNS, ASN/geo, certificate, category, lexical.
- [ ] False positives: prefetch, telemetry, CDNs, SPF/DKIM, browser DoH, sinkhole clicks.
- [ ] Hardening: controlled resolvers, logging, DNSSEC, RPZ, AXFR restriction, DHCP snooping, NRD/tunneling monitoring.
- [ ] Commands: `dig`, `Resolve-DnsName`, `nslookup`, `host`, `ipconfig`, `resolvectl`, `dig +trace`, `dig -x`.
