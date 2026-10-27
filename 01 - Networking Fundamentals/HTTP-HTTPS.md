# HTTP / HTTPS — SOC Analyst Study Notes

> Goal: read requests, responses, headers, and TLS metadata well enough to **triage phishing URLs, web-shell traffic, C2 beacons, exfiltration, and suspicious web requests** from proxy/WAF/EDR/Zeek logs.
> DNS is covered in `DNS.md`, firewall policy/NAT in `Firewalls.md`. This note focuses on the web protocol layer.

---

## 0. How to use this note

1. §1–§4: HTTP message model, methods, status codes, headers, URLs.
2. §5–§7: state, cookies, auth, HTTPS/TLS, proxies/CDNs.
3. §8–§10: what gets logged and where.
4. §11–§14: attacks, detections, investigation, triage.
5. §15–§17: commands, false positives, hardening.
6. §18–§20: labs, self-test, revision.

---

## 1. Why HTTP/HTTPS matters to a SOC analyst

- It is the **most abused protocol on the internet**: phishing pages, C2, exfiltration, web shells, exploit delivery, credential theft.
- Nearly all enterprise traffic is HTTP/HTTPS, so **almost every alert touches it** — even "DNS" and "firewall" cases resolve to an HTTP session.
- Encryption is the norm, so you often work from **metadata**: SNI, certificate, URL, user-agent, method, status, bytes, timing.
- Understanding the protocol lets you tell **benign browser behaviour from attacker behaviour** and write detections that survive false-positive review.

**SOC outcomes:** from a web log line or pcap you can answer:
- Who/what made the request? (`src_ip`, `user`, `process`, `user-agent`)
- To where? (`host`, `SNI`, `IP`, `path`)
- What was asked? (`method`, `URI`, `headers`, `body`)
- What came back? (`status`, `content-type`, `length`, `server`)
- Is it normal? (`baseline`, `reputation`, `sequence`)
- What next? (`close / enrich / escalate / contain`)

---

## 2. HTTP fundamentals

### 2.1 The message model

HTTP is a **request/response** protocol: client sends a request, server returns a response; each is a start line, headers, blank line, optional body.

```http
GET /login?next=/dashboard HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml
Cookie: session=abc123; theme=dark
Connection: keep-alive

```

```http
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=UTF-8
Content-Length: 5120
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax
Cache-Control: no-store
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### 2.2 HTTP versions

| Version | Transport | Key traits | SOC impact |
|---|---|---|---|
| **HTTP/1.0** | TCP | New connection per request by default | Rare now; odd if seen from modern clients. |
| **HTTP/1.1** | TCP | Persistent connections, pipelining, chunked encoding, `Host` required | Classic logs; smuggling risk. |
| **HTTP/2** | TCP + TLS (usually) | Multiplexed streams, HPACK header compression, binary framing, pseudo-headers (`:method`, `:path`, `:authority`) | Proxy logs may not show per-request detail; header anomalies harder to see. |
| **HTTP/3** | QUIC over UDP 443 | Encrypted transport, 0-RTT | **Major visibility gap** — many tools log little/nothing; egress UDP 443 worth alerting on. |

### 2.3 Methods

| Method | Semantics | SOC relevance |
|---|---|---|
| **GET** | Retrieve | Most traffic; long query strings can carry data/exfil. |
| **POST** | Submit data | Uploads, logins, C2 check-ins, exfil. |
| **PUT** | Create/replace resource | WebDAV abuse, webshell upload. |
| **PATCH** | Partial update | API abuse. |
| **DELETE** | Remove | Destructive actions, API abuse. |
| **HEAD** | GET without body | Recon, health checks, sometimes scanners. |
| **OPTIONS** | Capabilities | CORS preflight; also recon. |
| **TRACE** | Echo request | Should be disabled; XST history. |
| **CONNECT** | Tunnel | Proxies, HTTPS tunneling; abused for pivoting. |

### 2.4 Status codes

| Class | Meaning | Examples that matter |
|---|---|---|
| **1xx** | Informational | `101 Switching Protocols` (WebSocket upgrade), `100 Continue`. |
| **2xx** | Success | `200 OK`, `201 Created`, `204 No Content`. |
| **3xx** | Redirection | `301`, `302`, `307`, `308` — open redirects, phishing chains. |
| **4xx** | Client error | `401/403` authz failures, `404` scanning, `429` rate limiting. |
| **5xx** | Server error | `500` exploit attempts/breakage, `502/503` outage, `508` loops. |

**SOC reading:** many `404` from one client = content discovery/scanning. Many `401/403` = credential guessing or authz probing. `200` after a burst of `403` = possible bypass.

---

## 3. URLs, encoding, and parameters

### 3.1 Anatomy

```
https://user:pass@app.example.com:8443/path/to/page?query=1&lang=en#section
└─┬─┘   └───┬───┘└──────┬──────┘└┬┘└─────┬─────┘└──────┬──────┘└──────┬───┘└──┬──┘
scheme   userinfo       host      port     path           query        fragment
```

| Part | Notes for SOC |
|---|---|
| **Scheme** | `http` vs `https`; mixed content; `file:`, `javascript:` in redirects. |
| **Userinfo** | `user:pass@host` — credential phishing and URL obfuscation trick. |
| **Host** | Compare with SNI and `Host:` header (mismatch = fronting/proxy abuse). |
| **Port** | Non-standard ports on "normal" domains are suspicious. |
| **Path** | Webshell names, traversal (`../`), double encoding. |
| **Query** | Parameters, tokens, base64 blobs, exfil. |
| **Fragment** | Client-side only; used in OAuth/SPA tricks, not sent to server. |

### 3.2 Encoding you must recognise

- **Percent-encoding** — `%2e%2e%2f` = `../`, `%00` null, `%20` space.
- **Double encoding** — `%252e` decodes twice; WAF bypass.
- **Unicode/overlong** — `%c0%ae`, homoglyphs.
- **Base64** — long alnum strings ending in `=`; in URLs, cookies, bodies.
- **Hex** — `\x41`, `0x41`.
- **HTML entities** — `&lt;`, `&#x3c;` in XSS payloads.
- **URL shorteners** — `bit.ly`, `t.co`, `tinyurl` hide destination; resolve safely.

> Always decode once or twice before judging. Encoded payloads are a common evasion and a common false positive (legit apps encode everything).

### 3.3 Query strings and REST paths

- `/api/v1/users/123` — path parameter; IDOR testing ground.
- `?id=123&debug=1` — parameter tampering.
- Long/complex query strings from a non-browser process = exfil or C2.
- JSON bodies to `/api/*` are normal for apps, suspicious from `powershell.exe`.

---

## 4. Headers that matter

### 4.1 Request headers

| Header | Why it matters |
|---|---|
| **Host** | Virtual host routing; mismatch with SNI = fronting suspicion. |
| **User-Agent** | Client identity; scripted/malicious UAs, rare UAs, version mismatches. |
| **Referer** | Where the request came from; weird referers = injected pages/phishing. |
| **Cookie** | Session tokens; theft/replay. |
| **Authorization** | `Basic`, `Bearer` JWT, API keys; leakage in logs. |
| **Content-Type** | Body format; `multipart/form-data` uploads, `application/json` APIs. |
| **Content-Length / Transfer-Encoding** | Body framing; **smuggling** when both/inconsistent. |
| **X-Forwarded-For / X-Real-IP / Forwarded** | Client IP through proxies; spoofable unless proxy overwrites. |
| **X-Requested-With** | AJAX marker; can be spoofed. |
| **Accept / Accept-Encoding / Accept-Language** | Client fingerprint; anomalies help spot tools. |
| **Connection** | Keep-alive/close; hop-by-hop. |
| **Range** | Partial content; download abuse. |
| **Upgrade / Sec-WebSocket-Key** | WebSocket handshake. |

### 4.2 Response headers

| Header | Why it matters |
|---|---|
| **Server / X-Powered-By** | Tech fingerprint (version disclosure). |
| **Set-Cookie** | Session issuance; missing flags = finding. |
| **Location** | Redirect target; open redirect. |
| **Content-Type** | Body interpretation; `text/html` vs `application/octet-stream`. |
| **Content-Disposition** | Download filename; malware delivery. |
| **Content-Length / Transfer-Encoding** | Body framing; smuggling. |
| **Cache-Control / Pragma / Expires** | Caching; web cache deception/poisoning. |
| **Strict-Transport-Security (HSTS)** | Enforces HTTPS; downgrade protection. |
| **Content-Security-Policy (CSP)** | XSS mitigation; missing/weak = risk. |
| **X-Frame-Options / frame-ancestors** | Clickjacking. |
| **X-Content-Type-Options** | MIME sniffing. |
| **Access-Control-Allow-Origin** | CORS; `*` with credentials = risk. |
| **WWW-Authenticate** | Auth scheme; NTLM leaks. |
| **ETag / Last-Modified** | Caching; can leak existence. |
| **Alt-Svc** | Advertises HTTP/3 — visibility gap signal. |

### 4.3 Security headers quick audit

| Header | Good baseline |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (preload optional) |
| `Content-Security-Policy` | Restrictive; no `unsafe-inline`/`unsafe-eval` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` (or CSP `frame-ancestors`) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | Disable unused features |
| `Access-Control-Allow-Origin` | Explicit origins; not `*` with credentials |

---

## 5. State: cookies, sessions, and authentication

### 5.1 Cookies

`Set-Cookie: session=abc; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600`

| Attribute | Meaning | SOC note |
|---|---|---|
| `Secure` | HTTPS only | Missing = theft over cleartext. |
| `HttpOnly` | Not accessible to JS | Missing = XSS can steal. |
| `SameSite` | Cross-site sending (`Strict`, `Lax`, `None`) | Weak/missing = CSRF risk. |
| `Domain` | Scope | Over-broad = sibling subdomain theft. |
| `Path` | Scope | Rarely a security boundary. |
| `Max-Age`/`Expires` | Lifetime | Long-lived sessions = persistence. |

**Session theft signals:** same cookie from multiple IPs/ASNs, impossible travel, UA change mid-session, cookie used after logout, token replay.

### 5.2 Auth schemes

| Scheme | Where you see it | Notes |
|---|---|---|
| **Basic** | `Authorization: Basic base64(user:pass)` | Credentials in every request; only safe over TLS. |
| **Bearer / JWT** | `Authorization: Bearer eyJ...` | Decode header/payload (not secret); check `alg`, `exp`, audience. |
| **API keys** | Headers/query | Leakage in URLs/logs. |
| **Cookie session** | `Cookie:` | Opaque ID; server-side state. |
| **OAuth2/OIDC** | Redirects + tokens | See OAuth flows; token in fragment/URL. |
| **SAML** | POST form `SAMLResponse` | Base64 XML; signature wrapping issues. |
| **Mutual TLS** | Client cert | Strong; hard to replay without key. |

> Deep auth/session testing belongs to the authentication/authorization skills in this library; here you only need to **recognise the scheme in logs**.

---

## 6. HTTPS and TLS

### 6.1 What TLS gives you

- **Confidentiality** (encryption), **integrity** (MAC/AEAD), **authentication** (certificate).
- It does **not** hide: IPs, ports, timing, packet sizes, **SNI** (unless ECH), certificate metadata.
- It does **not** stop malicious content — phishing sites use valid TLS.

### 6.2 TLS handshake (TLS 1.2 vs 1.3)

**TLS 1.2 (simplified):**
1. ClientHello — versions, cipher suites, **SNI**, random, extensions (ALPN).
2. ServerHello — chosen version/cipher, random.
3. Certificate — server cert chain.
4. ServerKeyExchange / ClientKeyExchange — key agreement.
5. ChangeCipherSpec + Finished (both sides).
6. Application data.

**TLS 1.3 (simplified):**
1. ClientHello (with key share).
2. ServerHello + key share + EncryptedExtensions + Certificate + CertificateVerify + Finished.
3. Client Finished.
4. Application data.
> Faster (1-RTT, 0-RTT resumption), but **most of the handshake after ServerHello is encrypted** — including the certificate. SNI still visible unless ECH is used.

### 6.3 Certificate fields for investigation

| Field | Use |
|---|---|
| **Subject CN / SANs** | Which domains the cert covers; many SANs/odd domains = shared infra. |
| **Issuer** | Let's Encrypt (free, common in phishing) vs corporate CA. |
| **Validity** | Very short (90 days) is normal for ACME; brand-new cert + new domain is suspicious. |
| **Serial / fingerprint** | Pivot across infrastructure. |
| **CT logs** | When the cert/domain first appeared. |
| **Key type/size** | Weak keys = finding. |

### 6.4 SNI, ALPN, and ECH

- **SNI** — client tells the server which hostname it wants; visible in ClientHello. **Primary HTTPS metadata for SOC.**
- **ALPN** — protocol negotiation (`h2`, `http/1.1`, `h3`).
- **ECH (Encrypted Client Hello)** — hides SNI. If enabled, destination hostname becomes invisible; rely on IP/ASN/cert/EDR.

### 6.5 Pinning, mTLS, and inspection

- **Certificate pinning** — app only trusts a specific cert/key; breaks TLS inspection.
- **mTLS** — client certificate required; stolen cert = access.
- **TLS inspection** — proxy decrypts, inspects, re-encrypts. Legal/privacy implications; pinned apps fail; visibility gain is large.
- **Without inspection** you see: SNI, IP, cert, timing, byte counts, JA3/JA4.

### 6.6 TLS fingerprinting

- **JA3/JA3S** — hash of ClientHello/ServerHello fields; identifies client stacks/tools.
- **JA4/JA4+** — modern successor, more robust.
- **Use:** spot malware/tooling with unusual TLS fingerprints; baseline your estate.
- **Caveat:** browsers share fingerprints; VPN/proxy can normalise; not identity.

### 6.7 Downgrade and stripping

- **SSL stripping** — attacker downgrades HTTPS to HTTP; HSTS mitigates.
- **Weak protocol/cipher** — TLS 1.0/1.1, RC4, 3DES, NULL ciphers = finding.
- **Downgrade attacks** (e.g. LOGJAM-style) — require MitM position; check for anomalous cipher negotiation.

---

## 7. Proxies, CDNs, and infrastructure

| Component | Role | SOC impact |
|---|---|---|
| **Forward proxy** | Clients → internet via proxy | Logs URL, user, bytes; policy enforcement. |
| **Reverse proxy / LB** | Internet → apps | Hides origin; logs client IP via `X-Forwarded-For`. |
| **CDN** | Caches content at edge | Many domains share IPs; reputation noisy; SNI is the real destination. |
| **WAF** | Inspects HTTP | Blocks attacks; logs rule IDs and payloads. |
| **API gateway** | Auth/rate limit/routing | Logs API keys, paths, status. |
| **NAT** | Address translation | See `Firewalls.md` §5. |
| **Tor/proxy services** | Anonymisation | Egress to Tor = high-signal policy/threat event. |

**Key concepts:**
- **Host header vs SNI vs certificate vs IP** — compare all four. Mismatch = domain fronting, CDN abuse, or misconfiguration.
- **X-Forwarded-For** — only trust it if your proxy sets/overwrites it; attackers spoof it otherwise.
- **Caching** — `Cache-Control`, `Vary`, CDN keys; web cache deception/poisoning. (See the dedicated web-cache skills if available.)
- **Keep-alive** — long-lived connections reduce log volume but enable tunnels.
- **WebSocket** — `Upgrade: websocket`; persistent bidirectional channel; CSWSH risk.

---

## 8. What gets logged (and where)

| Source | Contents | Strengths / gaps |
|---|---|---|
| **Web server (Apache/Nginx/IIS)** | Access log (Common/Combined), error log | Full URL/method/status/UA/referer; no body; origin only. |
| **Reverse proxy / LB** | Similar + upstream timing | Client IP via XFF; TLS termination. |
| **Forward proxy / SWG** | URL, category, user, bytes, action | Best user attribution; TLS inspection optional. |
| **WAF** | Request, rule ID, action, payload snippet | Attack detail; false positives/negatives. |
| **CDN logs** | Edge requests, cache status, geo | High volume; delayed delivery. |
| **Zeek** | `http.log`, `ssl.log`, `files.log`, `conn.log` | Rich passive view incl. SNI/JA3; no body by default. |
| **Suricata** | `http`, `tls`, `fileinfo`, alerts | Signature + metadata. |
| **EDR** | Process + network events, HTTP via browser | **Process attribution**; varies by product. |
| **Cloud WAF/LB** | AWS ALB/CloudFront, Azure App Gateway/Front Door, GCP LB | Cloud-native; field schemas differ. |
| **Email gateway** | URLs in messages | Pre-click intelligence; rewrites links. |
| **IdP / SSO logs** | Auth events with app/URL | Correlate logins to suspicious apps. |

### 8.1 Common Log Format (CLF)

```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
```

| Field | Meaning |
|---|---|
| `127.0.0.1` | Client IP (or proxy IP). |
| `-` | Ident (rarely used). |
| `frank` | Authenticated user (if any). |
| `[...]` | Timestamp with timezone. |
| `"GET /path HTTP/1.0"` | Request line. |
| `200` | Status. |
| `2326` | Bytes sent. |

**Combined** adds `"Referer" "User-Agent"`. Some servers add response time, XFF, TLS version, SNI, etc.

### 8.2 Zeek `http.log` essentials

`ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, method, host, uri, referrer, user_agent, status_code, request_body_len, response_body_len, info_code, info_msg, tags, username, password, proxied, orig_fuids, resp_fuids, orig_mime_types, resp_mime_types`

### 8.3 Zeek `ssl.log` essentials

`ts, uid, id.orig_h, id.resp_h, id.resp_p, version, cipher, curve, server_name (SNI), resumed, established, cert_chain_fuids, client_cert_chain_fuids, subject, issuer, validation_status, ja3, ja3s, ja4, ja4s`

### 8.4 Minimum detection fields

- Time (UTC), src/dst IP, port, host/SNI, URI, method, status, UA, referer, bytes in/out, content-type, user, process, action.
- For TLS-only: SNI, cert subject/issuer/validity, JA3/JA4, bytes, duration.

---

## 9. Web attacks a SOC analyst sees

> This is **observation-focused**: know what the traffic/log looks like. Deep exploitation methodology lives in the dedicated hunting skills.

| Attack | Traffic/log signature |
|---|---|
| **Phishing page** | New domain, valid TLS, login form, credential POST to different host, URL shortener/redirect chain. |
| **Open redirect** | `3xx` `Location:` to external host, parameters like `url=`, `next=`, `redirect=`. |
| **Drive-by / exploit kit** | Landing page → obfuscated JS → payload download (`application/octet-stream`, `.exe`, `.js`, `.hta`). |
| **Web shell** | POST/GET to odd `.php`/`.jsp`/`.aspx` file, base64/`eval`/`cmd` parameters, tiny responses, regular check-ins. |
| **C2 over HTTP(S)** | Periodic GET/POST to same URI, small consistent bytes, encoded body (base64), cookie carrying data, custom UA. |
| **Data exfil** | Large POST/PUT, upload to cloud storage/paste site, long query strings, uploads off-hours. |
| **Credential theft** | POST to `/login` from unusual geo/UA, many 401s, password-spray patterns, MFA fatigue. |
| **Session hijack** | Cookie reused from different IP/UA, impossible travel, concurrent sessions. |
| **XSS** | `<script>`, `onerror=`, `javascript:`, encoded payloads in URL/body; reflected in response. |
| **SQLi** | `' OR 1=1--`, `UNION SELECT`, `sleep(`, error-based strings, `xp_cmdshell`. |
| **Path traversal / LFI** | `../`, `%2e%2e%2f`, `/etc/passwd`, `win.ini`, wrapper schemes (`php://`). |
| **SSRF** | Server fetching user-supplied URL; requests to `169.254.169.254`, `127.0.0.1`, internal RFC1918. |
| **XXE** | XML body with `<!DOCTYPE ... SYSTEM "file:///etc/passwd">` or external entity. |
| **Command injection** | `;`, `|`, `&&`, `$()`, backticks in parameters; `cmd.exe`, `/bin/sh` in logs. |
| **File upload abuse** | `multipart/form-data` to upload endpoints; double extensions, magic bytes, oversized files. |
| **Request smuggling** | `Content-Length` + `Transfer-Encoding` mismatch, duplicate headers, front-end/back-end disagreement. |
| **Log4Shell / JNDI** | `${jndi:ldap://...}` in headers/params (UA, X-Api-Version, etc.). |
| **Web cache poisoning/deception** | Unkeyed headers, path confusion, cached authenticated pages. |
| **API abuse** | Mass enumeration of IDs, high 404/403 rate, token reuse, GraphQL introspection. |
| **Domain fronting** | SNI and Host mismatch; traffic to trusted CDN but different internal host. |

### 9.1 Webshell traffic pattern (practical)

- Same URI hit at regular intervals from one client.
- Response size tiny but constant (command output echoed).
- Parameter values look encoded (`cmd=...`, `c=...`, long base64).
- Requests often `POST` with `application/x-www-form-urlencoded`.
- Server may return `200` with no HTML structure.
- Correlate with file-write events on the web server (EDR), new files in webroot, and outbound connections from the web server.

### 9.2 Beacon pattern (practical)

- Fixed interval ± small jitter (e.g. 60 s, 300 s).
- Same destination, same URI, same UA, similar bytes.
- Often `GET` with encoded query or `POST` with small JSON.
- May use legitimate services (GitHub, Telegram, Discord, cloud storage) to blend in.
- **Detection needs aggregation**, not single events.

---

## 10. Detection engineering for HTTP/HTTPS

> Baselines are mandatory. "Rare UA" in a diverse estate may still be thousands of hits/day; scope by asset and process.

### 10.1 High-signal ideas

1. **Rare user-agent** (never seen in 30 days) from a server or non-browser process.
2. **Scripted UA** (`python-requests`, `curl`, `wget`, `powershell`, `Go-http-client`, `libwww-perl`, `Java/`, `okhttp`) on user subnets.
3. **Long/encoded URI** — base64-looking path/query, high entropy, very long query strings.
4. **POST to rare destination** or rare URI from an internal host.
5. **Periodic requests** — beaconing heuristics.
6. **Large uploads** to external/cloud storage/paste sites.
7. **Download of executables/scripts** — `.exe`, `.dll`, `.js`, `.vbs`, `.hta`, `.ps1`, `.iso`, `.img`, `.lnk`, archives.
8. **Suspicious `Content-Type`** — `application/octet-stream` for pages, `text/html` for binaries.
9. **Redirect chains** to newly registered or uncategorised domains.
10. **SNI/Host mismatch** — domain fronting.
11. **HTTP to non-standard port** / HTTPS to odd ports.
12. **CONNECT to odd destinations** via proxy.
13. **Web shell indicators** — repeated POSTs to non-index script, tiny responses, encoded params.
14. **SSRF indicators** — requests from server to `169.254.169.254`, `127.0.0.1`, RFC1918.
15. **Suspicious status patterns** — many 404/403 from one client (scan), 200 after 403 (bypass), many 500 (exploit attempts).
16. **JNDI/Log4Shell strings** in any header or parameter.
17. **Tor/anonymiser** egress.
18. **HTTP/3 (UDP 443) from hosts that should use the proxy** — visibility gap.
19. **Self-signed/odd certificate** on an internal-looking domain.
20. **Referer from unrelated domain** on sensitive POSTs (CSRF attempts).

### 10.2 Splunk SPL examples

**Scripted user-agents on user subnets:**
```spl
index=proxy sourcetype=proxy
| where match(user_agent, "(?i)(python-requests|curl/|wget/|powershell|go-http-client|libwww-perl|okhttp|java/|axios)")
| stats count by src_ip, user_agent, dest_host
| sort -count
```

**Rare user-agent (30-day approximation):**
```spl
index=proxy sourcetype=proxy
| stats dc(src_ip) as hosts count by user_agent
| where hosts <= 2 AND count < 20
| sort count
```

**Long query strings:**
```spl
index=proxy sourcetype=proxy
| eval qlen=len(url)
| where qlen > 200
| stats count values(url) as samples by src_ip, dest_host
| where count > 10
```

**Large POST uploads to external:**
```spl
index=proxy sourcetype=proxy method=POST
| stats sum(bytes_out) as out_bytes by src_ip, dest_host, url
| where out_bytes > 50000000
| sort -out_bytes
```

**Periodic beaconing:**
```spl
index=proxy sourcetype=proxy
| sort 0 src_ip, dest_host, url, _time
| streamstats current=f window=1 last(_time) as prev by src_ip, dest_host, url
| eval delta=_time-prev
| stats count stdev(delta) as jitter avg(delta) as avg_delta by src_ip, dest_host, url
| where count > 20 AND jitter < 5 AND avg_delta < 600
```

**Executable/script downloads:**
```spl
index=proxy sourcetype=proxy
| where match(url, "(?i)\.(exe|dll|scr|msi|bat|cmd|ps1|vbs|js|hta|iso|img|lnk|jar)(\?|$)")
| stats count values(url) as urls by src_ip, dest_host
```

**Web-shell-ish repeated POSTs:**
```spl
index=web sourcetype=access_combined method=POST
| eval uri_path=urldecode(uri_path)
| stats count avg(bytes) as avg_bytes dc(uri_path) as paths by src_ip, uri
| where paths=1 AND count > 20 AND avg_bytes < 2000
| sort -count
```

**Scan behaviour (many 404):**
```spl
index=web sourcetype=access_combined status=404
| bin _time span=5m
| stats count dc(uri) as uris by src_ip, _time
| where uris > 50
```

**JNDI / Log4Shell strings:**
```spl
index=* (jndi OR "${jndi" OR "ldap://" OR "rmi://")
| stats count values(_raw) as evidence by host, src_ip
```

### 10.3 Microsoft Sentinel / Defender KQL examples

**Rare URLs from devices (DeviceNetworkEvents):**
```kusto
DeviceNetworkEvents
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemoteUrl has "http"
| summarize Hosts = dcount(DeviceId), FirstSeen = min(TimeGenerated)
    by RemoteUrl, bin(TimeGenerated, 1d)
| where Hosts == 1
| order by FirstSeen desc
```

**Suspicious user-agents (proxy `CommonSecurityLog`):**
```kusto
CommonSecurityLog
| where RequestUserAgent matches regex @"(?i)(python-requests|curl/|wget/|powershell|go-http-client|libwww-perl|okhttp)"
| summarize Count = count() by SourceIP, RequestUserAgent, RequestURL
| order by Count desc
```

**Large outbound HTTP POST (if bytes fields available):**
```kusto
CommonSecurityLog
| where RequestMethod == "POST"
| summarize Sent = sum(SentBytes) by SourceIP, DestinationHostName, RequestURL
| where Sent > 50000000
```

**Process using HTTP with scripted UA (Defender XDR):**
```kusto
DeviceNetworkEvents
| extend UA = tostring(parse_json(AdditionalFields).UserAgent)
| where UA matches regex @"(?i)(python|curl|wget|powershell)"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, UA
```

### 10.4 Sigma-style skeleton (concept)

```yaml
title: Scripted User-Agent from Internal Host
logsource:
  category: proxy
detection:
  selection:
    cs-user-agent|contains:
      - 'python-requests'
      - 'curl/'
      - 'powershell'
      - 'Go-http-client'
  filter_internal:
    dst_ip|startswith:
      - '10.'
      - '192.168.'
  condition: selection and not filter_internal
level: medium
```

---

## 11. Investigation workflow (step by step)

### Step 1 — Capture the request facts
- Time (UTC), src IP/user/process, method, host/SNI, URI, status, UA, referer, bytes, content-type.
- Which detection fired and its logic.

### Step 2 — Attribute the client
- Proxy user mapping, DHCP/asset inventory.
- EDR process, parent, hash, command line; browser vs script vs service.
- UA/OS mismatch is a clue (Chrome UA from `powershell.exe`).

### Step 3 — Analyse the URL
- Decode once/twice; inspect path/query for base64, traversal, payloads.
- Resolve redirects **safely** (don't fetch from a production host; use a sandbox or passive data).
- Check shorteners, punycode, lookalike domains.

### Step 4 — Enrich destination
- Domain age, reputation, category, passive DNS, certificate, ASN/geo.
- Is it a known SaaS/CDN? Does the estate normally visit it?
- Check SNI vs Host vs cert.

### Step 5 — Analyse the response
- Status, content-type, size, filename.
- Was a file downloaded? Hash it; check reputation/sandbox.
- Was data uploaded? Estimate volume and sensitivity.

### Step 6 — Build the sequence
- Reconstruct the session: initial redirect → landing → download → execution → follow-on.
- Correlate proxy + DNS + EDR + firewall on the same host/time.

### Step 7 — Scope
- Same domain/IP/URI/JA3 across 7–30 days.
- Other hosts/users with same behaviour.
- Check for successful exploitation (web logs, file writes, new processes).

### Step 8 — Verdict and response
- Benign / suspicious / malicious / unknown.
- Block URL/domain/IP, isolate host, reset credentials, preserve evidence.
- Tune detections based on findings.

### Step 9 — Document
Timeline, IOCs (defanged), evidence, scope, impact, actions, recommendations.

---

## 12. Triage playbooks

### A. "User visited a malicious/phishing URL"

1. Confirm the click and timing; was it blocked or allowed?
2. Did the user submit credentials? Check POST to login endpoints and subsequent auth anomalies.
3. Any file download/execution? EDR process tree.
4. Reset password and revoke sessions if credentials may be exposed.
5. Block the URL/domain; hunt for other clickers.
6. User awareness follow-up.

### B. "Possible web shell on server"

1. Identify the URI and request pattern (repeated POST, encoded params).
2. Correlate with file-write events in webroot and new processes (e.g. `cmd.exe`, `sh`, `whoami`).
3. Check server's outbound connections after the first hit.
4. Preserve the file and logs; hash the shell.
5. Isolate/rebuild the server; hunt for persistence and lateral movement.
6. Find the initial access vector (upload, vulnerable plugin, creds).

### C. "Beaconing HTTP traffic"

1. Confirm periodicity/bytes across multiple intervals.
2. Attribute process and hash.
3. Enrich destination; check SNI/cert/UA.
4. Pull pcap if authorised; look for encoded content.
5. **Confirmed → isolate, block, IR, hunt.**

### D. "Large outbound upload"

1. Destination sanctioned (backup, M365, Drive, vendor)?
2. Process/user/time; baseline for asset.
3. Inspect URL path and content-type; DLP verdict.
4. Sensitive/unsanctioned → escalate as possible exfil; preserve logs.

### E. "Scanning / 404 burst against web app"

1. Source: external scanner vs internal host.
2. Targeted paths (admin, `.env`, `.git`, backups) vs generic.
3. Any `200` among the `404`s → possible find.
4. WAF/IPS blocks? Rate limit?
5. Block/geo-filter if noisy; investigate if targeted or any success.

### F. "Exploit attempt (WAF/IPS alert)"

1. Identify CVE/rule and target asset/version.
2. Did the request succeed (status, response size, follow-on)?
3. Check for webshell/backdoor creation, outbound traffic, new users.
4. Patch/contain; hunt for successful exploitation elsewhere.

### G. "SNI/Host mismatch"

1. Known CDN/domain fronting pattern or misconfiguration?
2. Which internal host/process?
3. If suspicious → treat as potential evasion; inspect payload via TLS inspection/EDR.
4. Block if malicious; document if sanctioned.

### H. "Unauthorised HTTP/3 or DoH egress"

1. Which app/process and destination?
2. Policy violation, shadow IT, or malware evasion?
3. Enforce proxy/DNS policy; block if needed.
4. Record as a visibility gap.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| Blocked phishing URL, no interaction | Low |
| Credentials submitted to phishing site | High |
| Malware download + execution | High–Critical |
| Confirmed web shell | Critical |
| Confirmed C2 / exfil | Critical |
| External scanning, no success | Low–Medium |
| Targeted exploit with success | High–Critical |
| Scripted UA from a server (no further signs) | Medium |

---

## 13. Commands and tools

### 13.1 Safe URL analysis (do not fetch from prod)

```bash
# Headers only, follow redirects manually, no body
curl -sS -I --max-time 10 https://example.com/
curl -sS -D - -o /dev/null --max-time 10 https://example.com/

# Show redirect chain without following
curl -sS -I --max-time 10 http://example.com/

# Follow redirects but show each step
curl -sSIL --max-time 10 http://example.com/

# Inspect TLS certificate and chain
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null

# SNI / ALPN check
openssl s_client -connect example.com:443 -servername example.com -alpn h2,http/1.1 </dev/null

# Certificate dates / subject
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256

# DNS + TLS + HTTP in one (authorised targets only)
curl -v --max-time 10 https://example.com/
```

> Use isolated/sandbox infrastructure (or URL analysis services) for potentially malicious URLs. Never open attacker content from a corporate workstation.

### 13.2 Packet-level

```bash
# Capture HTTP (cleartext) with headers
sudo tcpdump -ni eth0 -A -s0 'tcp port 80'

# Capture TLS SNI (ClientHello), no decryption
sudo tcpdump -ni eth0 -s0 -w tls.pcap 'tcp port 443'
# then in Wireshark: filter tls.handshake.extensions_server_name

# tshark summaries
tshark -r http.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.method -e http.request.uri -e http.user_agent
tshark -r tls.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.src -e tls.handshake.extensions_server_name
tshark -r http.pcap -Y http.response -T fields -e ip.dst -e http.response.code -e http.content_type -e http.content_length

# Extract objects/files
tshark -r http.pcap --export-objects http,./objects
```

### 13.3 Windows

```powershell
Invoke-WebRequest -Uri "https://example.com" -Method Head
Invoke-WebRequest -Uri "https://example.com" -MaximumRedirection 0
(Invoke-WebRequest -Uri "https://example.com").Headers
(Invoke-WebRequest -Uri "https://example.com").StatusCode

# TLS/cert inspection
$req = [Net.HttpWebRequest]::Create("https://example.com")
$req.GetResponse()
$req.ServicePoint.Certificate

# DNS + connection
Resolve-DnsName example.com
Test-NetConnection example.com -Port 443
```

### 13.4 Log hunting one-liners

```bash
# Top hosts / URIs from an Apache combined log
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
awk '{print $7}' access.log | sort | uniq -c | sort -rn | head

# Find downloads
grep -Ei '\.(exe|dll|ps1|js|hta|iso|img|zip|rar)(\?|$)' access.log

# Find traversal / injection attempts
grep -Ei '(\.\./|%2e%2e|union.*select|<script|jndi:)' access.log

# Status distribution
awk '{print $9}' access.log | sort | uniq -c | sort -rn
```

> For large logs prefer your SIEM; these are for small evidence files.

---

## 14. Common false positives

| Alert | Often actually |
|---|---|
| Scripted UA | Monitoring, backups, package managers, CI/CD, vendor agents. |
| Rare UA | New browser versions, niche apps, mobile clients. |
| Long URLs | Search, analytics, OAuth, signed URLs, CDN tokens. |
| Periodic requests | Health checks, NTP-like polls, license checks, update agents. |
| Large uploads | Backups, video calls, cloud sync, telemetry bundles. |
| 404 bursts | Crawlers, broken links, favicon probes, security scanners (authorised). |
| Suspicious paths | Legit `.git` on dev servers, admin panels, API docs. |
| Certificate errors | Expired cert, internal CA, captive portal. |
| SNI/Host mismatch | CDN fronting, reverse proxy config, Host-header-based routing. |
| HTTP/3 egress | Browser default (Chrome/Edge), CDN optimisation. |
| JNDI strings | Security scanners/tests, log samples in documentation. |

**Rule of thumb:** attribute the process and check the baseline before escalating a URL. One weird UA is noise; weird UA + rare domain + periodic POST + new process is a case.

---

## 15. Hardening and recommendations

- Enforce **HTTPS everywhere** with **HSTS** (and preload where appropriate).
- Add **CSP**, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`.
- Cookies: `Secure`, `HttpOnly`, `SameSite`, scoped `Domain`/`Path`, short lifetimes.
- Disable legacy TLS (1.0/1.1), weak ciphers, and insecure renegotiation.
- Enable **TLS inspection** where lawful/feasible; document pinned apps and blind spots.
- **Egress filtering** and mandatory proxy/DNS; block direct HTTP/3/DoH where policy requires.
- **WAF** in blocking mode with tuned rules; log all actions.
- Patch web servers, frameworks, and plugins; remove default pages/samples.
- Restrict upload endpoints: type/size validation, no execution in webroot, AV scanning.
- Disable unused methods (`TRACE`, `PUT` if not needed), directory listing, and verbose errors.
- Centralise web/proxy/WAF logs in SIEM with **full URL, UA, status, bytes, user**.
- Alert on **new web-facing assets**, certificate changes, and config drift.
- Run **DAST/SAST** and periodic external attack-surface reviews.
- Red-team the detections (phishing sim, beacon sim, webshell in lab).

---

## 16. Lab practice plan

1. Run a local web server (Nginx/Apache) and a proxy (Squid/mitmproxy); generate traffic.
2. Inspect a TLS handshake with Wireshark; extract SNI and certificate.
3. Set up a phishing-style page locally; capture the credential POST (lab only).
4. Create a simple web shell in a lab app; generate traffic; build a detection.
5. Simulate beaconing with `curl` in a loop; test periodicity heuristics.
6. Upload a large file to a lab endpoint; measure bytes and write an exfil rule.
7. Break TLS inspection intentionally (pinned client); observe the failure mode.
8. Parse Apache/Zeek logs with `awk`/SPL/KQL; build three detections.
9. Analyse a public malware-traffic pcap (safe, offline) in Wireshark/Zeek.
10. Run the §12 playbooks as tabletop exercises with timelines and evidence.

---

## 17. Self-test questions

1. What are the differences between HTTP/1.1, HTTP/2, and HTTP/3?
2. Which parts of an HTTPS connection remain visible without decryption?
3. What is SNI, and why does it matter for SOC visibility?
4. How do you distinguish a `302` redirect chain from an open redirect?
5. What cookie attributes matter, and what does each protect against?
6. What does a `401` vs `403` tell you during an investigation?
7. How would you detect a web shell from logs alone?
8. What are the observable signs of HTTP beaconing?
9. Why is `Content-Length` + `Transfer-Encoding` a smuggling risk?
10. What is JA3/JA4, and what are its limits?
11. What is domain fronting, and how do you spot it?
12. Which headers would you check on a suspicious login request?
13. How do you safely analyse a potentially malicious URL?
14. What is the difference between a forward proxy and a reverse proxy in logs?
15. Which logs would you correlate to prove a drive-by download?

---

## 18. One-page revision checklist

- [ ] Message model: request line, headers, body; response status/headers/body.
- [ ] Versions: 1.1 (text, keep-alive), 2 (binary, multiplexed, HPACK), 3 (QUIC/UDP 443).
- [ ] Methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT.
- [ ] Status classes and the ones that matter (3xx redirect, 401/403, 404 scan, 5xx exploit/breakage).
- [ ] URL anatomy + encoding (percent, double, base64, hex, entities, shorteners, punycode).
- [ ] Key headers: Host, UA, Referer, Cookie, Authorization, Content-Type, CL/TE, XFF; security headers.
- [ ] Cookies: Secure, HttpOnly, SameSite, Domain/Path, lifetime.
- [ ] Auth schemes: Basic, Bearer/JWT, API key, cookie session, OAuth/OIDC, SAML, mTLS.
- [ ] TLS: handshake 1.2 vs 1.3, SNI, ALPN, ECH, certificates, pinning, JA3/JA4, inspection limits.
- [ ] Infra: forward/reverse proxy, CDN, WAF, LB, cache, Host/SNI/cert mismatch.
- [ ] Logs: CLF/combined, Zeek http/ssl, proxy, WAF, EDR, cloud; minimum fields.
- [ ] Attacks: phishing, redirect, drive-by, webshell, C2, exfil, cred theft, XSS/SQLi/LFI/SSRF/XXE/cmdi, smuggling, JNDI, cache, API abuse.
- [ ] Detections: scripted/rare UA, long/encoded URL, rare destination, periodic beacon, large upload, executable download, 404/403 patterns, JNDI, SNI mismatch.
- [ ] Investigation: facts → client attribution → URL analysis → enrichment → response analysis → sequence → scope → verdict → response → document.
- [ ] False positives: monitoring/backup agents, analytics URLs, health checks, CDNs, scanners, HTTP/3 defaults.
- [ ] Hardening: HSTS, CSP, cookie flags, TLS hygiene, inspection, egress control, WAF, patching, upload restrictions, logging.
- [ ] Commands: `curl -I/IL`, `openssl s_client`, `tcpdump -A`, `tshark -Y`, `Invoke-WebRequest`, `openssl x509`.
