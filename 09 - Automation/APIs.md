# APIs — SOC Automation Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Recovery](../08%20-%20Incident%20Response/Recovery.md) · [Bash →](Bash.md)

> Goal: use product APIs safely and predictably so automations are reliable, auditable, and least-privileged.
> Orchestration platforms → [SOAR.md](SOAR.md); scripting → [Python.md](Python.md), [PowerShell.md](PowerShell.md), [Bash.md](Bash.md).

---

## 0. How to use this note

1. §1–§3: HTTP/REST fundamentals; requests and responses.
2. §4–§7: authentication, authorisation, pagination, rate limits.
3. §8–§11: reliability — errors, retries, idempotency, versioning.
4. §12–§15: SOC use cases; webhooks; secrets; security rules.
5. §16–§19: patterns, debugging, pitfalls, labs.
6. §20–§21: self-test, revision.

---

## 1. What an API is

> **API** = a contract that lets one system call another without a human UI.

| Concept | Meaning |
|---|---|
| **Endpoint** | URL path for a resource. |
| **Method** | Verb (GET/POST/PUT/PATCH/DELETE). |
| **Headers** | Metadata (auth, content type). |
| **Body** | Payload (usually JSON). |
| **Status** | Numeric result. |
| **Schema** | Documented shape of data. |

---

## 2. HTTP methods

| Method | Semantics | Safe | Idempotent |
|---|---|---|---|
| **GET** | Read | Yes | Yes |
| **POST** | Create / action | No | No |
| **PUT** | Replace | No | Yes |
| **PATCH** | Partial update | No | Not guaranteed |
| **DELETE** | Remove | No | Yes |
| **HEAD** | Headers only | Yes | Yes |
| **OPTIONS** | Capabilities | Yes | Yes |

### 2.1 SOC implications

- **GET for searches** — cheap, cacheable, safe to retry.
- **POST for containment actions** — retrying may duplicate the action; needs idempotency keys or checks.
- **DELETE requires confirmation and audit**.

---

## 3. Request anatomy

```http
POST /api/v3/alerts/search HTTP/1.1
Host: siem.example.com
Authorization: Bearer eyJ...
Content-Type: application/json
Accept: application/json
X-Request-ID: 7f3c...

{"query":"severity >= high","from":"2026-04-01T00:00:00Z","size":100}
```

### 3.1 Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-RateLimit-Remaining: 42

{"total":1,"items":[{"id":"A-1023","severity":"high"}]}
```

### 3.2 Status codes

| Code | Meaning | Automation reaction |
|---|---|---|
| 200 | OK | Proceed |
| 201 | Created | Read returned object |
| 202 | Accepted (async) | Poll/await |
| 204 | No content | Success |
| 301/302 | Redirect | Follow if safe |
| 304 | Not modified | Use cache |
| 400 | Bad request | Fix payload — do not retry |
| 401 | Unauthenticated | Refresh token |
| 403 | Forbidden | Permissions problem — do not retry |
| 404 | Not found | Check ID |
| 405 | Method not allowed | Fix method |
| 409 | Conflict | Resolve state |
| 422 | Validation error | Fix payload |
| 429 | Rate limited | Back off and retry |
| 500 | Server error | Retry with backoff |
| 502/503 | Upstream/unavailable | Retry |
| 504 | Timeout | Retry |

**Retry only 429 and 5xx (plus network timeouts). Never retry 4xx blindly.**

---

## 4. Authentication

| Method | How | Notes |
|---|---|---|
| **API key** | Header/query | Simple; long-lived; treat as secret. |
| **Basic auth** | base64(user:pass) | Only over TLS; avoid. |
| **Bearer token** | `Authorization: Bearer` | Often JWT/OAuth2. |
| **OAuth2 client credentials** | Token endpoint → access token | Best for service-to-service. |
| **OAuth2 authorization code** | User consent | Human-delegated. |
| **mTLS** | Client certificate | Strong; operationally heavy. |
| **Signed requests** | HMAC of request | AWS-style. |

### 4.1 API keys

```bash
curl -sS -H "Authorization: ApiKey $SOC_API_KEY" \
     "https://siem.example.com/api/v3/alerts?limit=5"
```

**Never in code, never in git, never in logs.**

### 4.2 OAuth2 client credentials

```bash
TOKEN=$(curl -sS -X POST "$IDP/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=alerts.read incidents.write" | jq -r .access_token)

curl -sS -H "Authorization: Bearer $TOKEN" \
     "https://siem.example.com/api/v3/alerts?limit=5"
```

### 4.3 Token lifecycle

- Cache tokens until near expiry.
- Refresh proactively (skew, e.g. 60 s).
- Handle 401 by refreshing once, then fail.
- Revoke on decommission.

---

## 5. Authorisation and least privilege

| Principle | Practice |
|---|---|
| Separate credentials per integration | Revoke independently. |
| Read-only by default | Write only where required. |
| Scope tokens narrowly | `alerts.read`, not `*`. |
| Separate containment identity | Higher approval bar. |
| Service account, not a person | Survives staff changes. |
| No shared admin keys | No attribution. |

### 5.1 Permission matrix

| Automation | Needs |
|---|---|
| Alert enrichment | Alerts read, TI read, asset read |
| Ticket creation | Tickets write |
| Host isolation | EDR isolate scope only |
| Account disable | Directory user write (specific OU) |

**An integration with domain-admin is a breach waiting for a bug.**

---

## 6. Pagination

| Style | Example |
|---|---|
| **Offset/limit** | `?offset=200&limit=100` |
| **Page number** | `?page=3` |
| **Cursor** | `?cursor=eyJpZCI6...` |
| **Link header** | `Link: <...>; rel="next"` |
| **Token** | `?nextToken=...` |

### 6.1 Loop pattern

```python
def iter_all(fetch, page_size=100):
    cursor = None
    while True:
        batch, cursor = fetch(cursor, page_size)
        if not batch:
            return
        yield from batch
        if not cursor:
            return
```

### 6.2 Rules

- Never assume one page contains everything.
- Respect `total`/`has_more`.
- Avoid unbounded fetches in real time.
- Add max-page guard to prevent infinite loops.

---

## 7. Rate limits

| Signal | Meaning |
|---|---|
| `429` | Too many requests |
| `Retry-After` | Seconds to wait |
| `X-RateLimit-*` | Quota state |
| `Reset` | Window reset time |

### 7.1 Backoff

```python
import time, random

def with_backoff(fn, retries=5, base=1.0, cap=60):
    for attempt in range(retries):
        try:
            return fn()
        except RateLimited as e:
            wait = min(cap, base * 2 ** attempt) * (0.5 + random.random())
            time.sleep(max(wait, e.retry_after or 0))
    raise
```

- Exponential with **jitter**.
- Respect `Retry-After` absolutely.
- Cap retries; then alert.
- Never tight-loop on 429 — you will be blocked.

---

## 8. Error handling

| Class | Example | Action |
|---|---|---|
| **Client error** | 400, 422 | Fix request; alert developer. |
| **Auth error** | 401, 403 | Refresh/rotate; alert. |
| **Transient** | 429, 5xx, timeout | Retry with backoff. |
| **Business error** | 409 | Reconcile state. |
| **Data error** | missing fields | Validate schema. |

### 8.1 Error body

```json
{"error":{"code":"invalid_query","message":"unknown field 'sev'","request_id":"7f3c"}}
```

**Log `request_id` — support will ask for it.**

---

## 9. Retries and idempotency

| Operation | Retry safety |
|---|---|
| GET | Safe |
| PUT (full replace) | Safe |
| DELETE | Safe-ish |
| POST create | **Not safe** — may duplicate |
| POST action (isolate) | Check state first |

### 9.1 Idempotency

- Send an `Idempotency-Key` where supported.
- Or check current state before acting:

```python
if get_host(host_id)["isolated"]:
    return "already isolated"
isolate_host(host_id)
```

**Duplicate isolation is harmless; duplicate ticket creation is not.**

---

## 10. Versioning

| Style | Example |
|---|---|
| Path | `/api/v3/...` |
| Header | `Accept: application/vnd.x.v3+json` |
| Query | `?version=3` |

### 10.1 Rules

- Pin a version.
- Read changelogs before upgrades.
- Test in staging.
- Watch deprecation headers.
- Version your own automations too.

---

## 11. Timeouts

| Setting | Guidance |
|---|---|
| Connect timeout | 5–10 s |
| Read timeout | 30–60 s (long queries) |
| Total timeout | Bounded |
| Async jobs | Poll with cap |

**An automation without timeouts hangs a playbook indefinitely.**

---

## 12. SOC use cases

| Use case | API surface |
|---|---|
| Alert enrichment | SIEM read, TI, asset DB |
| Auto-ticket | ITSM create |
| Host isolation | EDR isolation |
| Account disable | IdP/AD write |
| IOC push | Firewall/proxy/DNS |
| Evidence export | EDR/SIEM archive |
| Posture checks | Cloud audit read |
| Reporting | SIEM aggregate queries |

### 12.1 Example: enrich → decide → act

```python
alert = siem.get_alert(alert_id)
reputation = ti.lookup(alert["src_ip"])
asset = cmdb.get(alert["host"])
risk = score(alert, reputation, asset)

if risk >= 85:
    edr.isolate(alert["host"], reason=f"incident {alert_id}")
    itsm.create_incident(alert, evidence=[reputation])
```

---

## 13. Webhooks

| Concept | Detail |
|---|---|
| **Push model** | Provider calls your URL. |
| **Payload** | JSON event. |
| **Signature** | HMAC header for authenticity. |
| **Replay protection** | Timestamp + nonce. |
| **Retries** | Provider retries on failure. |
| **Idempotency** | You must dedupe. |

### 13.1 Receiver checklist

- [ ] Verify signature.
- [ ] Check timestamp freshness.
- [ ] Dedupe by event ID.
- [ ] Respond 2xx quickly; process async.
- [ ] Timeout-tolerant.
- [ ] Log without secrets.
- [ ] Rate-limit your own endpoint.

### 13.2 Why respond fast

Most providers retry if you take too long, causing duplicate storms.

---

## 14. Secrets management

| Bad | Good |
|---|---|
| Hard-coded key | Vault/secret manager |
| `.env` committed | Injected at runtime |
| Key in logs | Redaction |
| Shared key across tools | Per-integration |
| Never rotated | Rotation schedule |

### 14.1 Rules

- Least privilege + short-lived tokens.
- Rotate on staff change and suspected exposure.
- Never echo secrets in CI.
- Redact `Authorization` in logs.
- Store only what you must.

---

## 15. API security for automations

| Risk | Control |
|---|---|
| Over-privileged token | Scope down |
| Token theft | Short TTL, IP allowlist, mTLS |
| SSRF through automation | Allowlist destinations |
| Injection into downstream | Validate/encode |
| Data leakage in logs | Redaction |
| Supply-chain of libs | Pin + scan deps |
| Insecure TLS | Verify certs (never `verify=False`) |
| Replay | Nonce/timestamp |

**Your automation is a privileged user — protect it like one.**

---

## 16. Patterns

| Pattern | Use |
|---|---|
| **Polling** | Simple, higher latency |
| **Webhook** | Fast, needs endpoint |
| **Batch export** | Bulk, scheduled |
| **Cursor sync** | Incremental |
| **Fan-out** | One event → many actions |
| **Circuit breaker** | Stop hammering a failing API |

### 16.1 Circuit breaker

```python
if failures > 5:
    open_circuit(seconds=60)   # fail fast
```

Protects both you and the provider.

---

## 17. Debugging

| Step | Action |
|---|---|
| 1 | `curl -v` the exact call |
| 2 | Check status + body |
| 3 | Verify token scope/expiry |
| 4 | Compare to docs |
| 5 | Check rate limit headers |
| 6 | Inspect `request_id` |
| 7 | Reproduce with minimal payload |
| 8 | Test in staging |

---

## 18. Pitfalls

| Pitfall | Consequence |
|---|---|
| Retrying 400s | Wasted quota, noise |
| No pagination | Missed data |
| No timeout | Hung workflows |
| Hard-coded secrets | Breach |
| Over-broad scope | Blast radius |
| Ignoring 429 | Blocked |
| Assuming POST is safe to retry | Duplicates |
| Unverified TLS | MITM |
| No version pin | Breakage |
| No request logging | Undebuggable |

---

## 19. Labs

1. Query a public API with `curl` and `jq`.
2. Implement OAuth2 client credentials.
3. Page through 500 results safely.
4. Handle 429 with backoff and jitter.
5. Build an idempotent "isolate host" function.
6. Verify a webhook signature.
7. Create a scoped read-only token and test denials.
8. Add timeouts and a circuit breaker.
9. Log a full request trace with secrets redacted.
10. Write an integration checklist for a new product.

---

## 20. Self-test questions

1. What is an API contract?
2. Which methods are idempotent?
3. Which status codes should you retry?
4. How does OAuth2 client credentials work?
5. Why scope tokens?
6. Name three pagination styles.
7. What is exponential backoff with jitter?
8. Why is POST create unsafe to retry?
9. How do you make an action idempotent?
10. What is webhook replay protection?
11. Name four secrets anti-patterns.
12. What is a circuit breaker?
13. Why pin API versions?
14. What do you log, and what must you redact?
15. Why is your automation a privileged user?

---

## 21. One-page revision checklist

- [ ] API = endpoint + method + headers + body + status + schema.
- [ ] Methods and idempotency table.
- [ ] Status codes and retry policy (429/5xx only).
- [ ] Auth: key, basic, bearer, OAuth2 CC, mTLS, signed.
- [ ] Token caching, refresh skew, 401 handling.
- [ ] Least privilege, per-integration creds, separate containment identity.
- [ ] Pagination styles + loop pattern + guards.
- [ ] Rate limits: `Retry-After`, backoff with jitter, cap.
- [ ] Error classes and `request_id` logging.
- [ ] Idempotency keys or state checks.
- [ ] Version pinning.
- [ ] Timeouts.
- [ ] SOC use-case table + enrich/decide/act pattern.
- [ ] Webhooks: signature, freshness, dedupe, fast 2xx, async.
- [ ] Secrets management rules.
- [ ] Automation security risks/controls.
- [ ] Patterns incl. circuit breaker.
- [ ] Debugging 8 steps.
- [ ] Pitfalls memorised.

---

> **Navigation:** [Roadmap index](../README.md) · [← Recovery](../08%20-%20Incident%20Response/Recovery.md) · [Bash →](Bash.md)
