# Phishing — SOC Analyst Study Notes

> Goal: triage a reported or detected phish quickly — verdict, blast radius, purge, and prevent the next click from becoming a breach.
> BEC/ATO response → `Credential-Attacks.md`; email telemetry → `04 - Security Monitoring/Logs.md`; ATT&CK → T1566.

---

## 0. How to use this note

1. §1–§3: why phishing dominates; the attack chain; what you're deciding.
2. §4–§6: headers and authentication; sender/domain analysis; URL analysis.
3. §7–§9: attachments, credential harvesting, BEC patterns.
4. §10–§12: workflow, scoping, response.
5. §13–§15: metrics, controls, pitfalls.
6. §16–§17: labs, self-test/revision.

---

## 1. Why phishing matters

- **Most common initial access vector** (T1566) for ransomware and BEC.
- One click can lead to credential theft, malware, or MFA fatigue.
- Attackers exploit **trust and urgency**, not technical flaws.
- Detection is a mix of **email analytics, user reports, and post-click telemetry**.

**The SOC's job isn't only "block the email"** — it's "did anyone click, enter creds, or open the attachment, and what happened next?"

---

## 2. The phishing chain

```
Recon → Infrastructure (domain/cert) → Send → Deliver
   → User reads → Clicks link / opens attachment
   → Credential page / malware execution
   → MFA capture / token theft / C2
   → BEC / ransomware / data theft
```

**Each stage leaves different evidence:**

| Stage | Evidence |
|---|---|
| Delivery | Gateway logs, message trace, headers |
| Click | Proxy, DNS, EDR browser process |
| Credential entry | Auth logs, new device/geo, MFA events |
| Execution | Process creation, EDR |
| Post-compromise | Mailbox rules, OAuth, lateral |

---

## 3. What you're deciding

| Verdict | Action |
|---|---|
| **Malicious — blocked** | Confirm no delivery; close. |
| **Malicious — delivered, no click** | Purge, block, warn users. |
| **Malicious — clicked, no creds** | Purge, block, check endpoint, hunt. |
| **Malicious — creds entered** | Reset, revoke sessions, MFA re-register, hunt. |
| **Malicious — executed** | Isolate, IR. |
| **Benign/spam** | Close, tune. |
| **Legit but suspicious-looking** | Verify with sender; close benign. |

---

## 4. Email authentication

### 4.1 The three records

| Record | Purpose | Pass means |
|---|---|---|
| **SPF** | Authorised sending IPs. | Envelope sender IP allowed. |
| **DKIM** | Cryptographic signature. | Message unmodified, signed by domain. |
| **DMARC** | Policy + alignment. | SPF/DKIM aligned with From domain. |

**DMARC result matters most** — it ties SPF/DKIM to the visible From domain.

### 4.2 Reading `Authentication-Results`

```
Authentication-Results: mx.example.com;
  spf=pass smtp.mailfrom=example.com;
  dkim=pass header.d=example.com;
  dmarc=pass header.from=example.com
```

| Combination | Interpretation |
|---|---|
| **SPF pass, DKIM fail, DMARC fail** | Likely spoof/forwarding issue. |
| **SPF fail, DKIM pass, DMARC pass** | Common with forwarders; check alignment. |
| **DMARC none** | Receiver didn't evaluate or no record. |
| **DMARC fail with p=none** | Domain owner not enforcing. |

**Caveat:** a *pass* does not mean legitimate — attackers compromise real domains or use lookalikes with valid records.

### 4.3 Common spoofing types

| Type | Signal |
|---|---|
| **Display-name spoof** | Name looks right, address is different. |
| **Lookalike domain** | `examp1e.com`, `example.co`, homoglyphs. |
| **Subdomain abuse** | `example.com.attacker.net`. |
| **Compromised real account** | All auth passes, content is odd. |
| **Reply-To mismatch** | From legit, replies go elsewhere. |
| **Newly registered domain** | Young domain age. |
| **Free mail** | Gmail/Outlook for corporate business. |

---

## 5. Header analysis

### 5.1 Key headers

| Header | Look for |
|---|---|
| **From** | Display name vs address mismatch. |
| **Return-Path** | Envelope sender (bounce). |
| **Reply-To** | Different from From. |
| **Received** | Path, delays, first hop, sending IP. |
| **Message-ID** | Domain mismatch. |
| **Authentication-Results** | SPF/DKIM/DMARC. |
| **Received-SPF** | Detailed SPF reason. |
| **X-Originating-IP** | Webmail origin. |
| **Content-Type** | HTML/text, encoding tricks. |
| **X-Mailer** | Bulk tool fingerprint. |

### 5.2 Received chain

Read **bottom-up** (oldest first). Check:

- Does the first hop belong to the sender domain?
- Unexpected relays/gateways.
- Large time gaps (delayed delivery).
- Private IPs (internal origin).

### 5.3 Tools

```bash
# Extract headers and URLs
python3 - <<'PY'
import email, sys
msg = email.message_from_file(open(sys.argv[1]))
for h in ("From","Return-Path","Reply-To","Received","Authentication-Results","Message-ID"):
    print(h, "=", msg.get(h))
PY

# URL analysis
grep -Eo 'https?://[^"<> ]+' message.eml | sort -u
```

---

## 6. URL analysis

### 6.1 Static checks

| Check | Red flag |
|---|---|
| **Domain age** | < 30 days. |
| **Registrar/privacy** | Bulk/anonymous. |
| **TLS cert** | Free DV, mismatched, very new. |
| **Path** | Long random, base64, many subdomains. |
| **Redirects** | To file download or login. |
| **Credentials in URL** | `?email=...`. |
| **Punycode** | `xn--` homoglyph. |
| **URL shortener** | Hidden destination. |
| **IP-literal URL** | No domain. |
| **Open redirect** | Legit domain + external param. |

### 6.2 Safe detonation

- Use an isolated browser/VM or URL sandbox.
- Do **not** open on your workstation.
- Capture redirect chain, final URL, page content, JS.
- Check for credential harvesting form (action target, exfil endpoint).

### 6.3 Credential phishing page tells

- Brand impersonation + login form.
- Form posts to a non-brand domain.
- Captures email **and** password (and often MFA).
- "Session expired" redirect after submit.
- Newly registered domain, short-lived hosting.
- Reverse-proxy kits (Evilginx) — real-looking, MFA-capable.

**If MFA is captured, assume session takeover** — reset + revoke, not just password.

---

## 7. Attachments

| Type | Risk | Check |
|---|---|---|
| **Office (doc/xls/ppt)** | Macros, DDE, external templates, exploits. | `olevba`, sandbox. |
| **PDF** | JS, launch actions, embedded files. | `pdfid`, `pdf-parser`. |
| **HTML/SVG** | Credential forms, smuggling. | Render isolated. |
| **Archive (zip/rar/iso/img)** | Nested payload, MotW bypass. | List + hash contents. |
| **LNK** | Command execution. | Target + arguments. |
| **ISO/IMG/VHD** | Bypass Mark-of-the-Web. | Mount isolated. |
| **Scripts (js/vbs/ps1)** | Execution. | Read content. |
| **OneNote** | Embedded scripts. | Inspect objects. |

### 7.1 Mark-of-the-Web

- Downloads get MotW; archives/ISO may bypass.
- Office "Protected View"/macro blocking relies on it.
- Check `Zone.Identifier` on endpoint files.

### 7.2 Macro tells

- Auto-exec (`AutoOpen`, `Document_Open`).
- Obfuscated strings, `Shell`, `CreateObject`.
- Downloads from URL.
- Suspicious child process after document open.

---

## 8. BEC patterns (no link, no attachment)

| Pattern | Signal |
|---|---|
| **CEO fraud** | Urgent payment, secrecy, unusual channel. |
| **Vendor invoice change** | Bank details changed. |
| **Payroll diversion** | HR asks to update direct deposit. |
| **Gift card request** | Urgency, untraceable. |
| **Thread hijack** | Real thread, new reply-to. |
| **Compromised account** | Internal sender, odd content/links. |
| **Legal/exec pretext** | "Confidential", "time-sensitive". |

**BEC often passes all authentication** when sent from a compromised mailbox.

**Detection:** NLP/keyword rules, new bank details, reply-to mismatch, unusual sender-recipient pairs, mailbox rule creation.

---

## 9. Post-click telemetry

| Signal | Meaning |
|---|---|
| Proxy/DNS hit to phish domain | Clicked. |
| Browser process → credential page | Viewing. |
| Auth log from new geo/device | Creds used. |
| MFA push/denial | MFA prompt. |
| New inbox rule / forwarding | BEC setup. |
| New OAuth consent | Token abuse. |
| EDR child process from browser | Malware execution. |

**Always check what happened after the click** — the email is only the delivery vehicle.

---

## 10. Triage workflow

### Step 1 — Capture the report
Original `.eml`, headers, URLs, attachments, reporter, recipients, time.

### Step 2 — Authenticate
SPF/DKIM/DMARC; From vs Return-Path vs Reply-To; lookalike check.

### Step 3 — Analyse content
Links (static + sandbox), attachments (static + sandbox), pretext.

### Step 4 — Determine verdict
Malicious / suspicious / spam / benign / legit.

### Step 5 — Scope delivery
Message trace: how many recipients, delivered/blocked/quarantined, other campaigns from same sender/infrastructure.

### Step 6 — Check engagement
Clicks (proxy/DNS), creds (auth), execution (EDR), rules/OAuth.

### Step 7 — Respond
- Purge from mailboxes.
- Block sender/domain/URL/hash.
- Reset creds + revoke sessions for submitters.
- Isolate endpoints.
- Warn users.

### Step 8 — Document and tune
IOCs, verdict, actions, rule/gateway tuning.

---

## 11. Response specifics

### 11.1 Purge and block

- **Soft delete vs hard delete** per policy.
- Search by Message-ID, sender, subject, URL, hash.
- Block at gateway **and** proxy/EDR (defence in depth).
- Consider blocking the whole campaign infrastructure, not one URL.

### 11.2 If credentials entered

1. Reset password.
2. **Revoke refresh tokens/sessions.**
3. Re-register MFA if methods changed.
4. Review sign-in logs for new devices/geo.
5. Check mailbox rules, forwarding, delegates.
6. Check sent items for new phishing.

### 11.3 If attachment executed

- Follow the malware playbook (`Malware.md`).
- Isolate, scope by hash, hunt.

### 11.4 If internal account compromised

- Treat as BEC: check rules, forwarding, OAuth, mailbox audit.
- Notify recipients of any outbound phish.

---

## 12. Severity guidance

| Condition | Severity |
|---|---|
| Blocked at gateway | Low/Info |
| Delivered, no engagement | Medium |
| Clicked, no creds | Medium/High |
| Credentials submitted | High/Critical |
| MFA/session captured | Critical |
| Malware executed | Critical |
| Internal account sending | Critical |
| Executive/finance target | Escalate regardless |

---

## 13. Metrics

| Metric | Meaning |
|---|---|
| **Report rate** | % users reporting. |
| **Click rate** | % clicking (simulations). |
| **Credential submission rate** | % entering creds. |
| **Time to report** | MTTD via users. |
| **Time to purge** | Containment speed. |
| **Repeat clickers** | Training target. |
| **False report rate** | Report quality. |
| **Campaign volume** | Trend. |

**User reports are a detection source** — make reporting one click and reward it.

---

## 14. Controls

| Layer | Control |
|---|---|
| **Authentication** | SPF, DKIM, DMARC `p=reject`. |
| **Gateway** | Attachment sandboxing, URL rewriting, impersonation protection. |
| **Links** | Safe Links/time-of-click detonation. |
| **Identity** | MFA (phishing-resistant), Conditional Access, token protection. |
| **Endpoint** | Macro blocking, ASR rules, EDR. |
| **Browser** | Password manager (domain-bound), blocking of credential entry on lookalikes. |
| **Awareness** | Training, simulations, easy reporting. |
| **Response** | Playbooks, purge automation. |

**Phishing-resistant MFA (FIDO2/passkeys) is the single biggest lever** — it defeats credential + OTP phishing.

---

## 15. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Judging by display name only | Miss spoof. |
| Trusting DMARC pass as legit | Compromised account. |
| Opening links on analyst workstation | Infection. |
| Not checking post-click telemetry | Miss compromise. |
| Purging without blocking | Re-delivery. |
| Resetting password without revoking tokens | Attacker persists. |
| Ignoring BEC (no link) | Financial loss. |
| Broad domain blocks | Business disruption. |
| Not scoping recipients | Others still phished. |
| No user feedback loop | Reports decline. |

---

## 16. Labs

1. Analyse a benign phishing sample; extract headers and verdict.
2. Check SPF/DKIM/DMARC for a spoofed test email.
3. Detonate a URL in an isolated sandbox; capture redirect chain.
4. Inspect a macro document with `olevba`.
5. Build a message-trace scope for a campaign.
6. Simulate a credential phish in a test tenant; detect submission.
7. Detect a BEC inbox rule and write the query.
8. Practise purge + block + reset + revoke end to end.
9. Write a phishing triage report.
10. Run a simulation and compute report/click/submit rates.

---

## 17. Self-test questions

1. What do SPF, DKIM, and DMARC each protect?
2. Why can a DMARC pass still be malicious?
3. What is display-name spoofing?
4. How do you read a Received chain?
5. What are three URL red flags?
6. Why is MFA capture worse than password capture?
7. What is MotW, and how is it bypassed?
8. What are four BEC signals?
9. What post-click telemetry do you check?
10. What must you do beyond a password reset?
11. How do you scope a campaign?
12. What is the strongest phishing control?
13. What metrics show programme health?
14. How do you handle an internal compromised sender?
15. Why is purging without blocking insufficient?

---

## 18. One-page revision checklist

- [ ] T1566; chain delivery→click→creds/execution→BEC/ransomware.
- [ ] Decisions: blocked, delivered, clicked, creds entered, executed, benign, legit.
- [ ] Auth: SPF (IP), DKIM (signature), DMARC (alignment/policy); Authentication-Results interpretation; pass ≠ legitimate.
- [ ] Spoof types: display name, lookalike, subdomain, compromised account, reply-to, new domain, free mail.
- [ ] Headers: From/Return-Path/Reply-To/Received/Message-ID/Auth-Results/Received-SPF/X-Originating-IP/Content-Type/X-Mailer; bottom-up Received.
- [ ] URL analysis: age, cert, path, redirects, credentials, punycode, shortener, IP literal, open redirect; safe detonation; credential page tells; MFA capture → session takeover.
- [ ] Attachments: Office/PDF/HTML/archives/LNK/ISO/scripts/OneNote; MotW; macro tells.
- [ ] BEC: CEO fraud, vendor change, payroll, gift cards, thread hijack, compromised internal, legal pretext; detection via NLP/bank change/reply-to/rules.
- [ ] Post-click: proxy/DNS, auth, MFA, inbox rule, OAuth, EDR.
- [ ] Workflow 8 steps; response (purge/block/reset/revoke/MFA/isolation/warn).
- [ ] Severity table; metrics; controls (DMARC reject, gateway, safe links, phishing-resistant MFA, ASR, training, playbooks).
- [ ] Pitfalls list memorised.
