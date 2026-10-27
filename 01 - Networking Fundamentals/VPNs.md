# VPNs — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← TCP/IP](TCP-IP.md) · [File Systems →](../02%20-%20Operating%20Systems/File-Systems.md)

> Goal: understand how VPNs authenticate, tunnel, and log traffic, so you can **triage remote-access attacks, impossible-travel alerts, stolen sessions, split-tunnel abuse, and VPN appliance exploitation**.
> IPsec/TLS internals overlap with [TCP-IP.md](TCP-IP.md) and [HTTP-HTTPS.md](HTTP-HTTPS.md); firewall/NAT with [Firewalls.md](Firewalls.md). This note focuses on VPN-specific behaviour and telemetry.

---

## 0. How to use this note

1. §1–§3: VPN types, protocols, and how tunnels are built.
2. §4–§6: authentication, access models, and logs.
3. §7–§10: attack surface, detections, investigation, triage.
4. §11–§13: commands, false positives, hardening.
5. §14–§16: labs, self-test, revision.

---

## 1. Why VPNs matter to a SOC analyst

- **Remote access is the front door.** Compromised VPN credentials are a top initial-access vector for ransomware and nation-state actors.
- VPN logs are **identity + network** telemetry: user, source IP, device, MFA result, assigned IP, duration, bytes.
- VPNs concentrate risk: one appliance protects the whole estate, and **edge appliances have a long history of pre-auth RCE and auth-bypass CVEs**.
- **Split tunnelling, DNS/IPv6 leaks, and post-auth access control** mean "connected to VPN" ≠ "contained".
- Attackers also *use* commercial VPNs/proxies for anonymisation — so "VPN traffic" is both a control and a threat signal.

**SOC outcomes:** from VPN logs you can answer:
- Who connected, from where, with what device/auth method?
- Did MFA succeed, fail, or get denied/pushed repeatedly?
- Is the location plausible? Concurrent with another session?
- What did they access, how much data, for how long?
- Did the appliance itself show exploit attempts or anomalies?
- What should happen next — monitor, verify with the user, or contain?

---

## 2. VPN types

| Type | Purpose | Typical protocols | SOC notes |
|---|---|---|---|
| **Remote-access VPN** | User device → corporate network | IPsec/IKEv2, SSL/TLS, WireGuard, OpenVPN, SSTP, L2TP | Primary identity attack surface. |
| **Site-to-site VPN** | Network ↔ network (branch, cloud, partner) | IPsec, GRE over IPsec, DMVPN, SD-WAN | Tunnel logs; partner trust; lateral movement across sites. |
| **Clientless SSL VPN** | Browser portal → internal apps | TLS, reverse proxy | Web logs; file/URL access; session cookies. |
| **ZTNA / SASE** | Per-app, identity-based access | TLS, proprietary | Replaces full tunnel; logs in IdP/proxy, not classic VPN. |
| **Mesh / overlay** | Peer-to-peer encrypted network | WireGuard, Nebula, Tailscale | Easy to deploy; **shadow IT** risk; hard to monitor. |
| **Cloud VPN** | On-prem ↔ cloud VPC/VNet | IPsec, WireGuard, proprietary | Cloud logs; misrouting/exposure possible. |

### 2.1 Full tunnel vs split tunnel

| Mode | Behaviour | Risk |
|---|---|---|
| **Full tunnel** | All traffic (incl. internet) goes through corporate | Higher visibility/control; performance cost. |
| **Split tunnel** | Only corporate subnets go through VPN; internet direct | **Bypasses proxy/DNS/egress controls**; malware can egress directly. |
| **Inverse split** | Only specified traffic bypasses | Common for SaaS/Teams; still a policy gap. |
| **Per-app (ZTNA)** | Only the app's traffic is tunnelled | Better least privilege; different telemetry. |

**Leaks to check:** DNS (queries to local resolver), IPv6 (traffic bypasses IPv4 tunnel), WebRTC, and applications bound to the physical interface.

---

## 3. Protocol internals (what you need to know)

### 3.1 IPsec

- **IKE** (Internet Key Exchange) negotiates SAs. **IKEv1** (main/aggressive mode) vs **IKEv2** (preferred).
- **Phase 1** — IKE SA: authentication (PSK, certificates, EAP), encryption/integrity proposals, DH group. UDP **500**.
- **Phase 2** — IPsec SA: ESP/AH parameters, selectors (subnets), PFS. ESP = IP protocol **50**, AH = **51**.
- **NAT-T** — UDP **4500** when NAT is detected.
- **ESP** — encrypts + authenticates payload. **AH** — integrity/auth only (no encryption; rarely used).
- **Transport vs tunnel mode** — host-to-host vs gateway-to-gateway.
- **DPD** (Dead Peer Detection) — keepalives; repeated failures = tunnel down.
- **PFS** — new DH per Phase 2; limits key compromise.
- **PSK risk** — shared secret; if leaked, anyone can authenticate (aggressive mode can leak a PSK hash to an attacker).

**SOC signals:** many IKE negotiations from one source, aggressive-mode attempts, malformed IKE, PSK auth failures, new peers, tunnel flapping, unexpected selectors/subnets.

### 3.2 SSL/TLS VPN

- Uses TLS (TCP **443**) for the control channel; data may use **DTLS** (UDP 443) for performance.
- **Clientless** — reverse-proxied web apps, bookmarks, file shares.
- **Client-based** — tunnel adapter, routes, split/full tunnel, posture checks.
- **Certificate-based** or **username/password + MFA**.
- **SOC advantage:** TLS VPN often has richer per-user logs and integrates with IdP/MFA.
- **Caveat:** encrypted payload; visibility depends on the appliance and endpoint.

### 3.3 WireGuard

- UDP (default **51820**), **Noise_IK** handshake, Curve25519, ChaCha20-Poly1305, BLAKE2s.
- **Static key pairs**; peers configured with allowed IPs; **no dynamic negotiation**.
- **Silent by default** — does not respond to unauthenticated packets, so it doesn't show up in scans.
- **Logging is minimal** on the server; you need its own logs or endpoint telemetry.
- **Risk:** trivial to set up (shadow IT, rogue tunnels), hard to identify by port if changed.

### 3.4 OpenVPN

- TLS-based; default UDP **1194** (often TCP 443 to look like HTTPS).
- Uses certificates/keys; can use username/password + MFA.
- **SOC signal:** TLS to unusual destinations, client configs with inline certs, long-lived UDP flows, `openvpn` process.

### 3.5 Legacy/other

| Protocol | Ports | Status |
|---|---|---|
| **PPTP** | TCP 1723 + GRE (47) | Broken (MS-CHAPv2); do not use. |
| **L2TP/IPsec** | UDP 1701 + 500/4500 | Legacy; pre-shared key weaknesses. |
| **SSTP** | TCP 443 | TLS-based, Windows-centric. |
| **IKEv2/IPsec** | UDP 500/4500 | Preferred IPsec remote access. |
| **SSTP/SoftEther** | 443 | Sometimes used for evasion. |

### 3.6 Port/protocol cheat sheet

| Protocol | Port/Proto |
|---|---|
| IKE | UDP 500 |
| NAT-T / IKEv2 NAT | UDP 4500 |
| ESP | IP proto 50 |
| AH | IP proto 51 |
| L2TP | UDP 1701 |
| PPTP | TCP 1723 + GRE 47 |
| OpenVPN | UDP 1194 (or TCP 443) |
| SSL VPN | TCP 443 (+ UDP 443 DTLS) |
| SSTP | TCP 443 |
| WireGuard | UDP 51820 (configurable) |

---

## 4. Authentication and access control

| Method | Strength | SOC notes |
|---|---|---|
| **Password only** | Weak | Spray/brute-force target; MFA expected. |
| **Password + MFA** | Good | Watch MFA fatigue/denied pushes; token theft. |
| **Certificate** | Strong | Stolen cert/device = access; revocation matters. |
| **Certificate + MFA** | Strongest common | Device + user binding. |
| **SAML/OIDC SSO** | Good | Logs in IdP; conditional access applies. |
| **PSK (IPsec)** | Weak if shared | Leak = full access; rotate and scope. |
| **RADIUS/LDAP backend** | Depends | Correlate VPN and directory logs. |

### 4.1 Access-control concepts

- **Authorization after authentication** — VPN gets you on the network; ACLs/ZTNA/firewall decide what you reach.
- **Posture / device compliance** — OS patch, AV, disk encryption, MDM; failing posture may still allow limited access.
- **Least privilege** — group-based routes/ACLs, not "all internal subnets".
- **Session controls** — idle timeout, max session, re-auth interval, concurrent-session limits.
- **Always-On VPN** — forces tunnel; reduces split-tunnel bypass.
- **Kill switch** — blocks traffic if tunnel drops.

> **VPN is not a trust boundary by itself.** Flat internal access after VPN is how one phished credential becomes ransomware.

---

## 5. VPN logs: what to collect

### 5.1 Typical fields

| Field | Why it matters |
|---|---|
| `timestamp` (UTC) | Timeline. |
| `user` / `username` | Identity. |
| `src_ip` (public) | Geo/ASN/reputation; attacker infrastructure. |
| `assigned_ip` (internal) | Pivot into internal logs (DHCP, firewall, EDR). |
| `device_name` / `device_id` | New device = signal. |
| `os` / `client_version` | Outdated/vulnerable client; spoofed UA. |
| `auth_method` | Password/MFA/cert/SSO. |
| `mfa_result` / `reason` | Push denied, OTP fail, timeout. |
| `action` | success / failure / disconnect. |
| `gateway` / `vpn_profile` | Which concentrator/policy. |
| `tunnel_type` | IPsec/SSL/WireGuard. |
| `duration` | Long sessions, keepalives. |
| `bytes_in` / `bytes_out` | Exfil/anomaly. |
| `assigned_dns` / `routes` | Split-tunnel/DNS leak analysis. |
| `posture_result` | Non-compliant device. |
| `session_id` | Correlate start/stop. |
| `reason` | Disconnect cause (idle, admin, error). |

### 5.2 Where logs live

| Source | Contents |
|---|---|
| **VPN concentrator** (Cisco ASA/FTD, FortiGate, Palo Alto GlobalProtect, Ivanti/Pulse, Citrix ADC, SonicWall, Check Point) | Auth, tunnel, bytes, client info. |
| **RADIUS/NPS** | Access-Accept/Reject, policy, reason (Windows NPS events 6272/6273). |
| **IdP / SSO** | SAML/OIDC assertions, conditional access, MFA. |
| **AD / Entra** | Logon events, risk detections. |
| **Firewall** | Site-to-site tunnel up/down, encrypted flows. |
| **Endpoint / EDR** | VPN client process, routes, connection events. |
| **DHCP/IPAM** | Assigned IP → host mapping. |
| **Cloud** | VPN gateway logs (AWS Client VPN/Site-to-Site, Azure VPN Gateway, GCP). |
| **ZTNA/SASE** | Per-app access logs, device posture. |

### 5.3 Windows client events

- **RasClient Operational log** — connection attempts/results.
- **Security 4624** — logon (type 3 network / 10 remote interactive depending on flow).
- **NPS Event 6272/6273** — access granted/denied.
- **RemoteAccess** logs — RRAS/VPN service.
- Always verify event IDs in your environment; versions differ.

---

## 6. What "normal" looks like (baseline first)

- Users connect from home ISPs, mobile carriers, hotels, and corporate offices; geolocation of the same ISP can vary.
- Some users connect daily at similar times; others sporadically.
- Device names are stable; client versions update over time.
- Session durations vary by role; bytes correlate with file access/RDP.
- Shared NAT egress means **many users can share one public IP** (office, carrier NAT).
- Travelling staff create legitimate geo jumps.

> Impossible-travel logic must account for VPN egress changes, carrier NAT, and corporate egress. **Verify with the user** before declaring compromise.

---

## 7. Attack surface and abuse patterns

### 7.1 Credential attacks

| Attack | How | Detection |
|---|---|---|
| **Password spraying** | Few passwords × many users | Many users fail from one IP/subnet; low per-user count. |
| **Brute force** | Many passwords × one user | High failure count per user/IP; account lockout. |
| **Credential stuffing** | Leaked creds across many users | Distributed source IPs; high success rate; new devices. |
| **MFA fatigue** | Repeated push notifications until user approves | Many MFA pushes/denials, then success. |
| **MFA phishing / relay** | Fake portal or real-time relay | Successful MFA from new device/geo; token reuse. |
| **Password reset abuse** | Helpdesk/social engineering | Reset + immediate VPN login from new location. |

### 7.2 Session and token attacks

- **Cookie/token theft** (malware, infostealer) → replay from attacker IP.
- **Session hijack** — same session ID from two IPs/UAs.
- **Refresh-token abuse** — long-lived tokens after password reset unless revoked.
- **Concurrent sessions** — same account in two places.

**Detection:** same user, overlapping sessions, different ASN/geo/device, UA change, token use after logout/password change.

### 7.3 Split-tunnel and leak abuse

- Malware egresses directly to the internet, bypassing proxy/DNS logging.
- DNS queries leak to local resolver; IPv6 bypasses IPv4-only tunnel.
- Attacker uses VPN access to reach internal services without passing monitored egress.

**Detection:** endpoint DNS/HTTP to internet while VPN connected; IPv6 traffic; proxy logs showing direct egress; split-tunnel route analysis.

### 7.4 VPN appliance exploitation

Edge VPN appliances are high-value: pre-auth RCE, auth bypass, path traversal, SQLi, and information disclosure have all been exploited at scale.

Known historical examples (verify current advisories — this list is illustrative, not exhaustive):
- Fortinet FortiOS SSL VPN path traversal (CVE-2018-13379) and later FortiOS SSL VPN issues.
- Pulse Secure / Ivanti Connect Secure auth bypass and command injection (e.g. CVE-2019-11510, CVE-2023-46805/CVE-2024-21887).
- Citrix ADC/NetScaler (e.g. CVE-2019-19781, CVE-2023-3519).
- Palo Alto GlobalProtect (e.g. CVE-2024-3400).
- SonicWall SSL VPN (e.g. CVE-2024-40766).
- Cisco ASA/FTD and AnyConnect issues over the years.

**SOC signals:**
- Exploit attempts in WAF/IPS/HTTP logs (`/..%2f`, `/dana-na/`, `/global-protect/`, unusual POST bodies).
- Appliance filesystem changes, new admin users, config exports.
- Outbound connections from the appliance.
- Authentication bypass patterns (success without MFA/login).
- Web shells on the appliance.
- Vendor advisory + asset inventory mismatch (unpatched).

### 7.5 Rogue and shadow VPNs

- Users/attackers run WireGuard/OpenVPN on endpoints or cloud VMs.
- **Detection:** VPN client processes, UDP 51820/1194/443 egress, `wg`/`openvpn` binaries, new tunnel adapters, cloud instances.
- **Risk:** bypasses controls; data exfil; persistence.

### 7.6 VPN as attacker infrastructure

- Threat actors use commercial VPNs, residential proxies, and hosting ASNs to hide source.
- **Detection:** egress/login from hosting/VPN/Tor ASNs; geography inconsistent with user; impossible travel; new device.
- **Caveat:** many legitimate users also use privacy VPNs — policy and verification matter.

### 7.7 Site-to-site abuse

- Compromised branch/partner network pivots through the tunnel.
- Overly broad selectors (0.0.0.0/0) expose entire networks.
- **Detection:** unexpected internal scans arriving via tunnel, new peer IPs, tunnel flapping, traffic from partner subnets to sensitive assets.

### 7.8 Insider / misuse

- Data staging and transfer over VPN off-hours.
- Access to systems outside role.
- **Detection:** volume anomalies, unusual destinations, access to sensitive subnets, off-hours patterns.

---

## 8. Detection engineering for VPNs

> Baseline per user, role, device, and usual geography. Coordinate with HR/IT for travel and new hires to avoid noise.

### 8.1 High-signal ideas

1. **Spray pattern** — many users, few attempts each, one source/subnet.
2. **Brute force** — many failures for one user, then success.
3. **Success after failures** — failure burst → successful login (credential guess).
4. **MFA fatigue** — many pushes/denials, then approval.
5. **Impossible travel** — two successful logins too far apart in time.
6. **Concurrent sessions** — same user, overlapping, different ASN/geo/device.
7. **New device** — first-seen device ID/name for a user.
8. **New geo/ASN** — first-ever country/hosting ASN for a user.
9. **Hosting/Tor/VPN ASN** login — anonymisation infrastructure.
10. **Off-hours login** — outside the user's baseline window.
11. **Post-reset login** — password reset followed by VPN login from new location.
12. **Disabled/locked account attempts** — persistence or spray against stale accounts.
13. **Volume anomaly** — bytes_out far above user/role baseline.
14. **Split-tunnel bypass** — direct internet egress while VPN connected.
15. **IPv6/DNS leak** — traffic outside the tunnel.
16. **Admin access over VPN** — privileged account from unusual context.
17. **VPN appliance exploit indicators** — traversal paths, odd POSTs, new admin users, config export.
18. **Appliance egress** — VPN gateway initiating outbound connections.
19. **Tunnel flapping** — repeated up/down (DoS or config attack).
20. **Rogue VPN client** — WireGuard/OpenVPN processes, UDP 51820/1194.
21. **Sessions after termination** — token/session still active after disable/reset.
22. **Geo velocity within one session** — IP changes mid-session (mobility vs hijack).

### 8.2 Splunk SPL examples

**Failures per user and source (spray/brute):**
```spl
index=vpn action=failure
| bin _time span=15m
| stats count dc(user) as users by src_ip, _time
| where count > 20 OR users > 5
| sort -count
```

**Success after multiple failures (same user/source):**
```spl
index=vpn
| bin _time span=30m
| stats count(eval(action="failure")) as fails count(eval(action="success")) as success by user, src_ip, _time
| where fails >= 5 AND success > 0
| sort -fails
```

**MFA fatigue (many denied/pushes, then success):**
```spl
index=vpn (mfa_result="denied" OR mfa_result="timeout" OR action="mfa_push")
| bin _time span=10m
| stats count(eval(mfa_result="denied")) as denied count(eval(action="success")) as success by user, _time
| where denied > 5 AND success > 0
```

**Concurrent sessions for one user:**
```spl
index=vpn action=success
| stats values(src_ip) as src_ips values(device_name) as devices earliest(_time) as first latest(_time) as last dc(src_ip) as ip_count by user
| where ip_count > 1
| sort -last
```

**First-seen country/ASN per user:**
```spl
index=vpn action=success
| iplocation src_ip
| stats earliest(_time) as first_seen by user, Country
| sort first_seen
```
> Better: maintain a lookup of known countries/ASNs per user and alert on new values.

**Off-hours logins (example 20:00–06:00 local):**
```spl
index=vpn action=success
| eval hour=strftime(_time, "%H")
| where tonumber(hour) >= 20 OR tonumber(hour) < 6
| stats count by user, src_ip
| sort -count
```

**Large outbound volume per user:**
```spl
index=vpn action=disconnect
| stats sum(bytes_out) as out_bytes by user, src_ip
| where out_bytes > 1000000000
| sort -out_bytes
```

**Split-tunnel bypass (proxy sees direct egress from VPN-assigned IP):**
```spl
index=proxy
| lookup vpn_sessions assigned_ip AS src_ip OUTPUT user
| where isnotnull(user)
| stats sum(bytes) as bytes by user, dest_host
| sort -bytes
```

**VPN appliance exploit signatures:**
```spl
index=web OR index=waf
| where match(url, "(?i)(/dana-na/|/global-protect/|/remote/login|/\+CSCOE\+/|\.\.%2f|%2e%2e%2f|/api/v1/.*(auth|login))")
| stats count values(url) as urls by src_ip
| where count > 5
```

### 8.3 Microsoft Sentinel / Defender KQL examples

**VPN failures per IP (CommonSecurityLog, vendor-dependent):**
```kusto
CommonSecurityLog
| where DeviceEventClassID has "vpn" or Activity has "login"
| where DeviceAction in ("failure","denied","failed")
| summarize Failures = count(), Users = dcount(SourceUserName)
    by SourceIP, bin(TimeGenerated, 15m)
| where Failures > 20 or Users > 5
| order by Failures desc
```

**Success after failures:**
```kusto
CommonSecurityLog
| where Activity has "login"
| summarize Failures = countif(DeviceAction in ("failure","failed")),
            Success = countif(DeviceAction =~ "success")
    by SourceUserName, SourceIP, bin(TimeGenerated, 30m)
| where Failures >= 5 and Success > 0
```

**New country for a user (Entra sign-ins, if VPN uses SSO):**
```kusto
SigninLogs
| where AppDisplayName has "VPN" or AppDisplayName has "GlobalProtect" or AppDisplayName has "AnyConnect"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize FirstSeen = min(TimeGenerated) by UserPrincipalName, Country
| order by FirstSeen desc
```

**Impossible travel (conceptual — needs geo distance function):**
```kusto
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress,
          Lat = todouble(LocationDetails.geoCoordinates.latitude),
          Lon = todouble(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevLat = prev(Lat), PrevLon = prev(Lon),
         PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend Hours = datetime_diff("minute", TimeGenerated, PrevTime) / 60.0
// compute distance with your geo function and flag speed > ~900 km/h
| where Hours > 0
```
> Use a supported geo-distance function or watchlist; treat as **suspicious**, then verify.

**MFA denial pattern (Entra):**
```kusto
SigninLogs
| where ResultType in ("50074","50076","50158")   // verify codes in your tenant
| summarize Denials = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where Denials > 5
```

### 8.4 Sigma-style skeleton

```yaml
title: VPN Login Success After Multiple Failures
logsource:
  product: vpn
detection:
  selection:
    action: success
  timeframe: 30m
  condition: selection | count(action='failure') by user, src_ip >= 5
level: high
```

---

## 9. Investigation workflow (step by step)

### Step 1 — Capture the facts
- Time (UTC), user, src IP, assigned IP, device, client version, auth method, MFA result, action, duration, bytes.
- Which detection fired and its logic.

### Step 2 — Establish the baseline
- Does the user normally connect from this country/ASN/device/time?
- Previous sessions, device history, travel/HR context.
- Is the source IP shared (carrier NAT, corporate egress, VPN provider)?

### Step 3 — Check authentication sequence
- Failures → success? MFA push count? Method changed?
- Account locked/disabled? Password recently reset?
- SSO/conditional-access decisions.

### Step 4 — Check session integrity
- Concurrent sessions, IP change mid-session, new device, UA change.
- Token/cookie reuse after logout.

### Step 5 — Check post-auth activity
- What internal systems were accessed (firewall, proxy, EDR, app logs)?
- Lateral movement, privilege escalation, data access.
- Volume and destinations.

### Step 6 — Enrich the source IP
- Reputation, ASN/hosting/Tor/VPN, geo, passive DNS.
- Is it a known corporate egress or shared ISP?

### Step 7 — Verify with the user (when appropriate)
- Out-of-band contact (phone/Teams), not the possibly compromised channel.
- Confirm travel/device/new login.

### Step 8 — Scope
- Other accounts from the same IP/subnet/ASN.
- Other sessions from the same device.
- Data accessed/exfiltrated.

### Step 9 — Respond
- Disable account, revoke sessions/tokens, reset password, enforce MFA re-registration.
- Block source IP/ASN if clearly malicious (careful with shared NAT).
- Isolate device if malware suspected; hunt for infostealer.
- Preserve logs.

### Step 10 — Document
Timeline, evidence, scope, impact, actions, recommendations.

---

## 10. Triage playbooks

### A. "VPN brute force / password spray"

1. Count failures per user and per source; pattern (one user vs many).
2. Any success? From same source? At what time?
3. Is the account privileged? Is MFA enforced?
4. Block source, rate-limit, lock/reset targeted accounts.
5. If success → treat as account compromise (playbook C).

### B. "Impossible travel"

1. Compute times and distances; check for carrier NAT/corporate egress.
2. Verify with the user out-of-band.
3. Check devices and MFA method for both sessions.
4. If both legitimate (travel/VPN egress) → document and tune.
5. If not → revoke sessions, reset credentials, investigate.

### C. "Suspected account compromise"

1. Confirm anomalous session (geo/device/time/MFA).
2. Review post-auth activity and data access.
3. Disable account, revoke tokens/sessions, reset password, re-register MFA.
4. Isolate endpoint; check for infostealer/malware.
5. Hunt for persistence and lateral movement.
6. Notify per IR plan.

### D. "MFA fatigue"

1. Count pushes/denials; identify source IP/device.
2. Did the user approve? When?
3. If approved → treat as compromise; revoke and reset.
4. Enforce number matching / phishing-resistant MFA.
5. Block source; user awareness.

### E. "Split-tunnel bypass / data exfil over VPN"

1. Confirm direct egress (DNS/proxy/EDR) while tunnel is up.
2. Identify process and destination.
3. Quantify data; sensitivity.
4. Block/disable split tunnel if policy allows; isolate host.
5. Escalate if sensitive data left the estate.

### F. "VPN appliance exploit attempt"

1. Identify appliance, version, and targeted path/CVE.
2. Check for successful exploitation: new admin users, config export, filesystem changes, outbound connections, web shells.
3. Isolate the appliance from the internet if compromised; preserve evidence.
4. Patch/upgrade; rotate credentials/certs/PSKs.
5. Hunt for lateral movement from the appliance into the network.

### G. "Rogue/shadow VPN"

1. Identify client/process and destination.
2. Policy violation, developer need, or malware?
3. Block/remove; enforce endpoint controls.
4. Check for data transfer over the tunnel.

### H. "Site-to-site tunnel anomaly"

1. Tunnel up/down/flap; peer IP changes.
2. Traffic selectors and volumes.
3. Unexpected scans or access from the remote site.
4. Coordinate with the partner/site owner; rotate PSK/certs if needed.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| Failed spray, no success | Medium |
| Success after failures (unverified) | High |
| Confirmed account compromise | Critical |
| MFA fatigue with approval | High–Critical |
| Split-tunnel exfil | High–Critical |
| Appliance exploit attempt, blocked | Medium–High |
| Appliance compromise | Critical |
| Rogue VPN, no data movement | Medium |
| Site-to-site anomaly | Medium–High |

---

## 11. Commands and tools

### 11.1 Client-side (authorised devices)

```bash
# OpenVPN
sudo openvpn --config client.ovpn
ip addr show tun0
ip route show table all

# WireGuard
sudo wg show
sudo wg-quick up wg0
wg pubkey < private.key

# strongSwan / IPsec
sudo ipsec statusall
sudo swanctl --list-sas
ip xfrm state
ip xfrm policy

# Certificate inspection
openssl x509 -in client.crt -noout -subject -issuer -dates -fingerprint -sha256
openssl pkcs12 -in client.p12 -info -nodes

# Tunnel traffic capture
sudo tcpdump -ni any 'udp port 500 or udp port 4500 or udp port 1194 or udp port 51820'
```

### 11.2 Windows

```powershell
Get-VpnConnection
Get-VpnConnection -AllUserConnection
rasdial
rasdial "VPN Name" user pass
Get-NetAdapter | Where-Object InterfaceDescription -match 'VPN|WireGuard|TAP'
Get-NetRoute -InterfaceAlias "VPN Name"
route print

# Logs
Get-WinEvent -LogName "Microsoft-Windows-RasClient/Operational" -MaxEvents 50
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 20
```

### 11.3 Server/appliance (authorised)

```bash
# Cisco ASA/FTD
show vpn-sessiondb detail anyconnect
show vpn-sessiondb summary
show crypto ikev2 sa
show crypto ipsec sa
show running-config webvpn

# FortiGate
diagnose vpn ssl list
diagnose vpn tunnel list
get vpn ipsec tunnel summary

# Palo Alto
show global-protect-gateway current-user
show vpn ike-sa
show vpn ipsec-sa

# strongSwan
ipsec statusall
swanctl --list-sas --list-conns

# WireGuard
wg show all
wg show wg0 dump
```

### 11.4 Analysis aids

- `ike-scan` (authorised testing of IKE endpoints) — identifies gateways and aggressive-mode behaviour.
- `nmap` IKE/IPsec scripts — only with authorisation.
- Zeek: `ike.log`, `ssl.log`, `conn.log`; Suricata rules for VPN exploit attempts.
- TLS/JA3/JA4 for SSL VPN clients.

---

## 12. Common false positives

| Alert | Often actually |
|---|---|
| Impossible travel | Carrier NAT, corporate egress, privacy VPN, legitimate travel. |
| Concurrent sessions | Device reconnect before old session timed out, phone + laptop, roaming. |
| New country | Business travel, relocation, ISP geo-DB error, VPN egress. |
| New device | Reinstall, upgrade, new phone, device name change. |
| Failures | Expired password, MFA timeout, user error, client upgrade. |
| Off-hours login | On-call, different time zone, shift work. |
| Large transfer | Legitimate file access, backups, video, development. |
| Source IP change mid-session | Mobile network handover, Wi-Fi/cellular switch, load balancer. |
| Hosting ASN | Corporate cloud egress, VPN provider, SaaS proxy. |
| Rogue VPN process | Approved developer/testing tool, corporate ZTNA client. |
| Tunnel flaps | ISP instability, DPD, maintenance, rekey. |
| Exploit-looking paths | Vulnerability scanners, generic internet noise (still block). |

**Rule of thumb:** verify identity out-of-band before containment, and never lock out a travelling executive based on geo alone.

---

## 13. Hardening and recommendations

- **MFA everywhere**, preferably **phishing-resistant** (FIDO2/passkeys) for VPN/ZTNA.
- **Number matching / context** in push MFA to reduce fatigue attacks.
- **Certificate + device posture** for managed endpoints; conditional access.
- **Least-privilege access** post-auth: group-based routes/ACLs, not full network.
- **Patch VPN appliances aggressively**; subscribe to vendor advisories; inventory exposed gateways.
- **Remove internet exposure** of management interfaces; restrict admin access.
- **Disable legacy protocols** (PPTP, IKEv1 aggressive mode, weak ciphers, TLS 1.0/1.1).
- **Rotate PSKs/certs**; avoid shared PSKs; use certificates/IKEv2.
- **Session controls**: idle/max timeouts, concurrent-session limits, re-auth.
- **Revoke sessions/tokens** on password reset, disable, or role change.
- **Full tunnel or ZTNA** for sensitive roles; document split-tunnel exceptions.
- **DNS/IPv6 leak protection**; kill switch; always-on VPN where feasible.
- **Log everything**: auth, MFA, assigned IP, device, bytes, gateway, posture.
- **Centralise and correlate** VPN with IdP, EDR, DHCP, firewall, proxy.
- **Monitor appliance integrity** (file hashes, admin changes, egress).
- **Block rogue VPN clients** via application control where policy allows.
- **User awareness** for MFA fatigue and credential phishing.
- **Tabletop** an infostealer → VPN → lateral movement scenario.

---

## 14. Lab practice plan

1. Set up WireGuard or OpenVPN between two lab VMs; enable verbose logs.
2. Capture the handshake (IKE or Noise/TLS) with tcpdump/tshark.
3. Configure split tunnel; prove DNS/IPv6 leaks; then fix them.
4. Build a RADIUS/NPS lab (or FreeRADIUS) and generate success/failure logs.
5. Simulate password spray against a lab VPN (authorised); tune detections.
6. Simulate MFA fatigue with a test IdP; observe logs.
7. Test concurrent sessions and reconnects; refine the heuristic.
8. Create an impossible-travel scenario with a geo-IP lab or mock data.
9. Review a VPN appliance's logs for exploit paths using a safe test page.
10. Write an incident report from §9/§10 with timeline and evidence.

---

## 15. Self-test questions

1. What is the difference between full tunnel and split tunnel, and what risks does each carry?
2. Which ports/protocols does IPsec use (IKE, NAT-T, ESP)?
3. What is the difference between IKEv1 and IKEv2, and why does aggressive mode matter?
4. What is the difference between ESP and AH?
5. How does WireGuard differ from IPsec/OpenVPN in logging and discoverability?
6. What logs would you use to prove a VPN login?
7. How would you distinguish a password spray from a brute force?
8. What is MFA fatigue, and how do you detect it?
9. Why is "impossible travel" often a false positive, and how do you verify?
10. What are the signs of session/token theft?
11. What is a split-tunnel DNS leak?
12. What post-auth controls matter after VPN login?
13. What indicators suggest a VPN appliance was exploited?
14. How would you scope a compromised VPN account?
15. What would you do first: disable the account, block the IP, or contact the user? Why?

---

## 16. One-page revision checklist

- [ ] Types: remote access, site-to-site, clientless, ZTNA/SASE, mesh, cloud.
- [ ] Tunnel modes: full, split, inverse split, per-app; DNS/IPv6 leaks.
- [ ] IPsec: IKEv1/v2, phase 1/2, ESP/AH, NAT-T, DPD, PFS, PSK risk.
- [ ] SSL VPN: TLS 443, DTLS, clientless vs client, posture.
- [ ] WireGuard: UDP 51820, Noise, static keys, silent, minimal logs.
- [ ] OpenVPN: TLS, 1194/443, certs, client configs.
- [ ] Legacy: PPTP (1723+GRE), L2TP (1701), SSTP (443) — avoid/retire.
- [ ] Auth: password, MFA, cert, SSO, PSK, RADIUS/LDAP.
- [ ] Access: authorization after auth, least privilege, posture, session controls, always-on, kill switch.
- [ ] Logs: user, src/assigned IP, device, client, auth/MFA, action, gateway, bytes, duration, posture, session ID.
- [ ] Sources: concentrator, RADIUS/NPS, IdP, AD/Entra, firewall, EDR, DHCP/IPAM, cloud, ZTNA.
- [ ] Attacks: spray/brute, stuffing, MFA fatigue, token theft, split-tunnel abuse, appliance exploits, rogue VPN, anonymisation, site-to-site abuse, insider.
- [ ] Detections: spray, failures→success, MFA fatigue, impossible travel, concurrency, new device/geo/ASN, off-hours, volume, split-tunnel bypass, exploit paths, appliance egress, flapping, rogue clients, post-termination sessions.
- [ ] Investigation: facts → baseline → auth sequence → session integrity → post-auth activity → enrich IP → verify user → scope → respond → document.
- [ ] Triage: brute force, impossible travel, compromise, MFA fatigue, split-tunnel exfil, appliance exploit, rogue VPN, site-to-site anomaly.
- [ ] Hardening: MFA/FIDO2, cert+posture, least privilege, patch appliances, retire legacy, rotate secrets, session controls, revoke tokens, full tunnel/ZTNA, leak protection, logging, integrity monitoring, awareness.

---

> **Navigation:** [Roadmap index](../README.md) · [← TCP/IP](TCP-IP.md) · [File Systems →](../02%20-%20Operating%20Systems/File-Systems.md)
