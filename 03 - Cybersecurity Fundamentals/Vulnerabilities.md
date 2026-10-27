# Vulnerabilities — SOC Analyst Study Notes

> Goal: understand what a vulnerability is, how it is scored and prioritised, and how to triage **exploitation attempts** and scanner noise — without confusing a vulnerability record with an incident.
> Attack patterns → `Common-Attacks.md`; technique mapping → `MITRE-ATTACK.md`; CIA impact framing → `CIA-Triad.md`.

---

## 0. How to use this note

1. §1–§3: why vulnerabilities matter; core vocabulary; lifecycle.
2. §4–§6: identifiers and scoring (CVE, CVSS, EPSS, KEV, CWE).
3. §7–§9: discovery, prioritisation, remediation.
4. §10–§12: common vulnerability classes; exploit attempts in logs; triage.
5. §13–§16: detection, investigation, severity, commands.
6. §17–§20: false positives, hardening, labs, self-test, revision.

---

## 1. Why vulnerabilities matter to a SOC analyst

- Vulnerabilities are **how attackers get in**; SOC logs show **when someone tries to use them**.
- SOCs receive **scanner, threat-intel, and CVE feeds** and must decide what is actionable *now*.
- Not every CVE is an incident. The job is **distinguishing exploitation from scanning**, and **known-exploited from theoretical**.
- Vulnerability data gives **context to web/IDS alerts**: a 500 error on a path matching a new CVE is more interesting than a random 404.
- Understanding severity helps you **escalate correctly** and avoid alert fatigue.

**SOC outcomes:** given a vulnerability-related alert you can answer:
- Is this a scan, an attempt, or successful exploitation?
- What is the affected asset and exposure?
- Is the CVE known-exploited (KEV) / likely exploited (EPSS)?
- What is the blast radius if it succeeds?
- Patch, mitigate, or monitor?

---

## 2. Core vocabulary

| Term | Meaning |
|---|---|
| **Vulnerability** | A weakness that can be exploited to cause harm. |
| **Exploit** | Code/technique that leverages a vulnerability. |
| **Threat** | Actor/capability with intent to exploit. |
| **Risk** | Likelihood × impact, in your context. |
| **Exposure** | Whether the asset is reachable/usable by an attacker. |
| **Attack surface** | Sum of reachable weaknesses. |
| **Zero-day** | Exploited before public patch/disclosure. |
| **N-day** | Known vulnerability with available patch. |
| **Mitigation** | Control that reduces exploitability without a patch. |
| **Compensating control** | Alternative protection when patching is impossible. |
| **False positive** | Scanner reports a vulnerability that does not exist. |
| **False negative** | Real vulnerability not reported. |

**Formula to remember:**
> **Risk = Threat × Vulnerability × Impact** (contextualised by exposure and asset criticality)

---

## 3. Vulnerability lifecycle

1. **Introduction** — insecure code/config shipped.
2. **Discovery** — researcher, vendor, attacker, scanner.
3. **Disclosure** — private to vendor, then coordinated/public.
4. **CVE assignment** — identifier issued.
5. **Patch/update** — vendor fix.
6. **Exploitation** — PoC, weaponisation, in-the-wild.
7. **Detection** — signatures, scanner checks.
8. **Remediation** — patch/mitigate/replace.
9. **Verification** — rescan/validate.
10. **Retirement** — asset decommissioned.

**SOC relevance:** the **window between disclosure and patching** is the risk period; KEV and EPSS estimate exploitation during that window.

---

## 4. Identifiers

| Identifier | What it is |
|---|---|
| **CVE** | Unique ID for a publicly disclosed vulnerability (`CVE-2021-44228`). |
| **CWE** | Weakness class (`CWE-79` XSS, `CWE-89` SQLi). |
| **CAPEC** | Attack pattern (`CAPEC-66` SQL injection). |
| **NVD** | NIST database enriching CVEs with CVSS/CPE. |
| **GHSA** | GitHub advisory (open source). |
| **MSRC/Adobe/etc.** | Vendor advisories. |
| **KEV** | CISA Known Exploited Vulnerabilities catalogue. |
| **EPSS** | Exploit Prediction Scoring System (probability of exploitation in 30 days). |
| **SBOM** | Software bill of materials (component inventory). |
| **CPE** | Product identifier used by scanners. |

**Relationships:** CWE (class) → CVE (instance) → CAPEC (attack pattern) → ATT&CK (adversary behaviour).

---

## 5. CVSS

**CVSS** (Common Vulnerability Scoring System) scores **severity 0–10** based on intrinsic characteristics.

### 5.1 CVSS v3.1 base metrics

| Metric | Values |
|---|---|
| **Attack Vector (AV)** | Network (N), Adjacent (A), Local (L), Physical (P). |
| **Attack Complexity (AC)** | Low (L), High (H). |
| **Privileges Required (PR)** | None (N), Low (L), High (H). |
| **User Interaction (UI)** | None (N), Required (R). |
| **Scope (S)** | Unchanged (U), Changed (C). |
| **Confidentiality (C)** | None/Low/High. |
| **Integrity (I)** | None/Low/High. |
| **Availability (A)** | None/Low/High. |

### 5.2 Qualitative ratings

| Score | Rating |
|---|---|
| 0.0 | None |
| 0.1–3.9 | Low |
| 4.0–6.9 | Medium |
| 7.0–8.9 | High |
| 9.0–10.0 | Critical |

### 5.3 Temporal and environmental

- **Temporal:** exploit code maturity, remediation level, report confidence.
- **Environmental:** modified metrics reflecting your asset (e.g., confidentiality impact if data is public).

**CVSS v4.0** adds more granularity (attack requirements, subsequent system impact) but the logic is the same: **intrinsic severity, not your risk**.

### 5.4 CVSS limitations

- Does **not** say whether it is exploited.
- Does **not** know your exposure or asset value.
- Vendor scores vary; some CVEs are over/under-scored.
- A 9.8 on an unreachable dev host may be lower risk than a 6.5 on an internet-facing VPN.

> **Rule:** CVSS is an input, not a decision.

---

## 6. EPSS and KEV

### 6.1 EPSS

- Probability (0–1) that a CVE is exploited in the wild **within 30 days**.
- Updated daily; based on exploit/PoC/threat signals.
- Use to **rank** a large backlog: high EPSS + high CVSS + exposed = act now.

### 6.2 CISA KEV

- Catalogue of CVEs **confirmed exploited in the wild**.
- Federal remediation deadlines (and a useful priority signal for everyone).
- **KEV + internet-facing = emergency.**

### 6.3 Combining signals

| Signal | Meaning |
|---|---|
| CVSS | How bad if exploited. |
| EPSS | How likely to be exploited. |
| KEV | Confirmed exploited. |
| Exposure | Can an attacker reach it? |
| Asset criticality | How much does it matter? |
| Compensating controls | Is it blocked/mitigated? |

**Priority matrix:**

| | Low exposure | High exposure |
|---|---|---|
| **KEV** | Patch soon | **Emergency** |
| **High EPSS** | Plan patch | Patch urgently |
| **High CVSS only** | Scheduled | Prioritise |
| **Low everything** | Backlog | Monitor |

---

## 7. Discovery

| Method | Description | Notes |
|---|---|---|
| **Network scan** | Unauthenticated probing | Sees version, not internal config. |
| **Authenticated scan** | Credentials used | Finds missing patches/config. |
| **Agent-based** | Installed on host | Continuous, works off-network. |
| **Cloud/ASM** | External attack surface | Public exposure. |
| **Container/image scan** | Layers/packages | SBOM-based. |
| **SAST/DAST/SCA** | Code/app/dependencies | Dev-side. |
| **Bug bounty/pentest** | Human creativity | Deep, point-in-time. |
| **Threat intel** | KEV/EPSS/vendor | Exploitation context. |
| **Manual review** | Config audits | Misconfigurations. |

**SOC receives:** scanner exports, ASM findings, CVE alerts, exploit-attempt logs, bug bounty reports.

---

## 8. Prioritisation

### 8.1 Risk-based approach

Score each finding on:

1. **Exploitability** (KEV? EPSS? public PoC? CVSS AV/AC/PR).
2. **Exposure** (internet-facing? internal? air-gapped?).
3. **Asset criticality** (crown jewel? PII? production? domain controller?).
4. **Blast radius** (what can be reached after exploitation).
5. **Compensating controls** (WAF, segmentation, MFA, EDR).
6. **Data sensitivity** (regulated?).

### 8.2 SLA example

| Severity | Internet-facing | Internal |
|---|---|---|
| Critical/KEV | 24–72h | 7 days |
| High | 7 days | 30 days |
| Medium | 30 days | 90 days |
| Low | 90 days | 180 days |

Adjust to policy/regulatory requirements.

### 8.3 Common prioritisation mistakes

- Sorting by CVSS only.
- Ignoring KEV.
- Treating scanner count as risk.
- Forgetting **misconfigurations** and **identity** issues.
- Ignoring **compensating controls**.
- No owner/deadline → backlog grows.

---

## 9. Remediation

| Option | When |
|---|---|
| **Patch/update** | Preferred. |
| **Upgrade/replace** | EOL software. |
| **Configuration change** | Misconfig/default creds. |
| **Compensating control** | Cannot patch: WAF rule, segmentation, disable feature, MFA, EDR. |
| **Isolation** | Remove from network. |
| **Accept** | Documented risk acceptance with expiry. |
| **Verify** | Rescan/validate after fix. |

**SOC role:** detect exploitation, confirm scope, support containment, verify remediation, track exceptions.

---

## 10. Common vulnerability classes

| Class | Examples | Detection angle |
|---|---|---|
| **Injection** | SQLi, command, LDAP, XPath, template | Payload patterns, errors, child processes. |
| **XSS** | Reflected/stored/DOM | Payloads in logs, CSP reports. |
| **CSRF** | State-changing GET/POST | Origin/Referer anomalies. |
| **SSRF** | Internal/metadata requests | Internal IPs, `169.254.169.254`. |
| **Path traversal/LFI** | `../`, wrappers | Encoded traversal, file access. |
| **File upload** | Web shell, polyglot | New executable in webroot, child shell. |
| **Deserialization** | Java/PHP/.NET | Serialized blobs, gadget traffic. |
| **XXE** | External entities | `<!DOCTYPE`, OOB callbacks. |
| **Auth flaws** | Broken auth, default creds, JWT | Auth failures, token anomalies. |
| **Access control** | IDOR/BOLA, missing authz | Sequential IDs, cross-tenant access. |
| **Misconfiguration** | Public bucket, debug mode, default admin | Config change logs, exposure scans. |
| **Outdated software** | Unpatched edge/VPN/CMS | Version fingerprint, KEV. |
| **Weak crypto/TLS** | Deprecated protocols, bad certs | TLS scan, downgrade. |
| **Credential issues** | Hardcoded secrets, weak passwords | Secret scanning, auth patterns. |
| **Race conditions** | TOCTOU, double-spend | Anomalous duplicates. |
| **Business logic** | Price manipulation, workflow bypass | Business anomaly monitoring. |
| **Supply chain** | Malicious dependency | SBOM alerts, behavioural change. |
| **Cloud IAM** | Over-broad roles, public access | Control-plane audit. |

---

## 11. Exploit attempts in SOC telemetry

### 11.1 Where to look

| Source | Signal |
|---|---|
| **WAF** | Blocked/allowed attacks, payloads. |
| **Web server logs** | 4xx/5xx patterns, payloads, user agents. |
| **IDS/IPS** | Signature hits, severity. |
| **Proxy** | C2, exploit kits. |
| **EDR** | Child process from web/app, crashes. |
| **Auth logs** | Spray/brute force. |
| **Cloud audit** | IAM/storage abuse. |
| **Scanner logs** | Who is scanning you. |
| **Honeypots** | Early warning. |

### 11.2 Attempt vs success

| Evidence | Interpretation |
|---|---|
| Payload in request, 400/403/404 | Attempt, blocked/failed. |
| Payload, 200 with error text | Possible success (info leak). |
| `cmd.exe`/`sh` child of web server | Likely RCE. |
| New file in webroot | Likely web shell. |
| Outbound connection from web server | Post-exploitation. |
| Crash/restart of service | Possible exploit attempt. |
| Repeated identical payloads across hosts | Campaign. |

> **Detection of exploitation is behavioural**, not just signature-based: a web request alone is weak evidence; a web request plus a shell child process is strong.

---

## 12. Triage workflow for vulnerability alerts

### Step 1 — Identify the finding
CVE/ID, product/version, asset, exposure, CVSS, EPSS, KEV.

### Step 2 — Validate applicability
Is the product/version actually present? Is the vulnerable feature enabled? Is it reachable?

### Step 3 — Determine activity
Scan only, attempt, or successful exploitation? What do the logs show?

### Step 4 — Assess impact
What can be reached? What data/privilege?

### Step 5 — Check compensating controls
WAF, segmentation, MFA, EDR, disabled feature.

### Step 6 — Decide
Emergency patch/mitigate, scheduled, monitor, or false positive.

### Step 7 — Contain if exploited
Isolate, block, preserve, hunt.

### Step 8 — Verify and document.
Rescan, confirm, update ticket, note exceptions.

---

## 13. Triage playbooks

### A. "Scanner reports Critical CVE on internet-facing host"
1. Confirm version and exposure.
2. KEV/EPSS? Public exploit?
3. Is the service actually reachable?
4. Patch/mitigate within SLA; scan for exploitation attempts.

### B. "IDS/WAF exploit signature hit"
1. Source IP, target, payload, response code.
2. Blocked or allowed?
3. Any follow-on (shell, outbound, file)?
4. If success indicators → incident.

### C. "Known exploited CVE alert (KEV)"
1. Asset inventory match.
2. Exposure and compensating controls.
3. Emergency change if exposed.
4. Hunt for exploitation artefact.

### D. "Suspicious web request leading to shell"
1. Full request/response, user agent.
2. Child process, file creation, network.
3. Assume compromise; isolate and IR.

### E. "Public bucket / exposed service"
1. Confirm exposure and duration.
2. Access logs / external access evidence.
3. Restrict, notify, assess data impact.

### F. "Hardcoded secret found"
1. Validate if live (safe check).
2. Rotate immediately; check usage.
3. Remove from code/history, add scanning.

### G. "Unpatched EOL system"
1. Compensating controls (segmentation, virtual patching).
2. Replacement plan; monitor for exploitation.

### Severity guide

| Situation | Severity |
|---|---|
| Vuln reported, not exposed, no activity | Low |
| Exposed, high CVSS, no exploitation | Medium–High |
| Exposed + KEV/active exploitation in wild | Critical |
| Exploitation attempt blocked | Medium–High |
| Confirmed successful exploitation | Critical |
| Public data exposure | High–Critical |
| Secret leak, live | Critical |
| EOL system, segmented | Medium |

---

## 14. Detection engineering for exploitation

### 14.1 High-signal ideas

1. Web/app server spawning shell.
2. New executable/script in webroot.
3. Outbound connection from server to internet.
4. Repeated 500s + exploit payloads.
5. Scanner user-agent + follow-up exploitation.
6. Path traversal/LFI patterns.
7. SSRF to metadata/internal IPs.
8. Deserialization payloads (Java/PHP/.NET).
9. Web shell signatures (`c99`, `r57`, `eval`, `base64_decode`).
10. Suspicious uploads (.php/.jsp/.aspx).
11. Auth bypass (200 on protected path).
12. Credential spray (auth logs).
13. Cloud IAM abuse.
14. Public storage changes.
15. EOL software with exploitation attempts.

### 14.2 Splunk

**Web exploit attempt + successful response:**
```spl
index=web
| eval attack=if(match(lower(uri), "(union.*select|\.\./|etc/passwd|<script|cmd=|exec=|base64_decode)"),1,0)
| where attack=1
| stats count values(status) as codes by src_ip, uri, host
```

**Web server child shell:**
```spl
index=edr EventCode=1
| where match(lower(ParentImage), "(w3wp|httpd|nginx|php-fpm|tomcat|java)\.exe$")
| where match(lower(Image), "(cmd|powershell|sh|bash|whoami|curl|wget|nc)\.exe$")
```

**New file in webroot:**
```spl
index=fim path="/var/www/*"
| where action="created"
| where match(path, "(?i)\.(php|jsp|aspx|ashx|cgi|pl)$")
```

**SSRF to metadata:**
```spl
index=web
| where match(uri, "(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|localhost|127\.0\.0\.1)")
```

**Scanner then exploit:**
```spl
index=web
| eval is_scan=if(match(user_agent,"(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|qualys|zgrab)"),1,0)
| stats sum(is_scan) as scans count by src_ip
| where scans > 0
```

### 14.3 KQL

**Exploit attempt with follow-on process:**
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","java.exe","tomcat.exe")
| where FileName in~ ("cmd.exe","powershell.exe","sh","bash","curl.exe","wget.exe","whoami.exe")
```

**Suspicious upload:**
```kusto
DeviceFileEvents
| where FolderPath has_any ("\\inetpub\\wwwroot","/var/www","/srv/http")
| where FileName has_any (".php",".jsp",".aspx",".ashx",".cgi")
| where ActionType == "FileCreated"
```

**WAF exploit attempts:**
```kusto
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| summarize Attacks = count() by clientIp_s, requestUri_s, ruleId_s, bin(TimeGenerated, 1h)
| where Attacks > 20
```

**Public storage exposure:**
```kusto
AWSCloudTrail
| where EventName in ("PutBucketAcl","PutBucketPolicy","DeletePublicAccessBlock")
| project TimeGenerated, UserIdentityArn, EventName, RequestParameters, SourceIpAddress
```

### 14.4 Sigma sketch

```yaml
title: Web Server Spawning Command Shell
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\nginx.exe'
      - '\php-cgi.exe'
  child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: parent and child
level: critical
```

---

## 15. Investigation workflow

### Step 1 — Anchor the finding
CVE/ID, asset, version, exposure, score, source of the alert.

### Step 2 — Validate
Product/version/feature present? Reachable? Compensating controls?

### Step 3 — Determine activity
Scans, attempts, successes. Which logs prove each?

### Step 4 — Build exploitation chain
Request → exploit → execution → persistence → lateral → exfil.

### Step 5 — Scope
Other assets with same version; same source IP; same payload.

### Step 6 — Contain
Patch/mitigate/isolate; block source; preserve evidence.

### Step 7 — Eradicate/recover
Patch, remove web shells, reset creds, verify.

### Step 8 — Document
CVE, ATT&CK mapping, timeline, impact, actions, residual risk.

---

## 16. Commands

```bash
# Version / service fingerprint
nmap -sV -p 443,8443,80 host
curl -I https://host
openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null | openssl x509 -noout -subject -dates

# Web exploit evidence
grep -E "(union|select|\.\./|etc/passwd|<script|cmd=|exec=)" access.log
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head

# Package/vuln inventory
dpkg -l | grep package
rpm -qa | grep package
apt list --upgradable
```

```powershell
# Patch/inventory
Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 20
Get-CimInstance Win32_Product | Select Name, Version
Get-WindowsUpdateLog   # (heavy)

# Defender/ASR
Get-MpPreference | Select ExclusionPath, AttackSurfaceReductionRules_Ids
```

```bash
# Cloud exposure
aws s3api get-bucket-acl --bucket BUCKET
aws s3api get-public-access-block --bucket BUCKET
gcloud storage buckets describe gs://BUCKET
az storage container show-permissions --name C --account-name A
```

**External references (read-only):** NVD, MITRE CVE, CISA KEV, EPSS (FIRST), vendor advisories.

---

## 17. Common false positives

| Alert | Often actually |
|---|---|
| SQLi signature | Legitimate search with quotes, security scanner. |
| Path traversal | Encoded URLs, file names with dots, CDN normalisation. |
| XSS payload | Security testing, WAF test, benign content. |
| SSRF | Health checks to localhost, internal integrations. |
| Web shell | Admin tools, legitimate upload functionality. |
| Scanner finding | False positive (version banner wrong, feature disabled). |
| Critical CVE | Not exploitable in your config, mitigated. |
| Public bucket | Intended public content (static assets). |
| Secret found | Test/placeholder key, revoked key. |
| Brute force | Misconfigured app, cached creds. |
| Unpatched | Compensating controls in place, accepted risk. |

**Validate with:** asset ownership, config, WAF logs, response codes, follow-on behaviour, and exploitability checks (not just presence).

---

## 18. Hardening and vulnerability management

- **Asset inventory** (you cannot patch what you do not know).
- **SBOM** for software supply chain.
- **Patch SLAs** by severity/exposure; emergency path for KEV.
- **Attack surface management** for internet-facing assets.
- **Secure configuration baselines** (CIS).
- **WAF/IPS virtual patching** where patching lags.
- **Segmentation** to limit blast radius.
- **MFA/least privilege** to reduce post-exploitation.
- **Secret scanning** in repos and CI.
- **Dependency scanning** (SCA) and lockfiles.
- **EOL/EOS tracking** and replacement plans.
- **Bug bounty/pentest** for depth.
- **Verification** after remediation (rescan).
- **Metrics**: mean time to remediate, % KEV remediated, exposure reduction.

---

## 19. Labs

1. Scan a lab VM with OpenVAS/Nessus; interpret and prioritise findings.
2. Reproduce a known CVE in an isolated lab (e.g., a vulnerable web app).
3. Write WAF/IDS detections for SQLi, traversal, and SSRF.
4. Create a web shell in a lab; detect with FIM + process + logs.
5. Build an exploit-attempt dashboard from web logs.
6. Compare CVSS vs EPSS vs KEV for 10 CVEs and rank.
7. Respond to a simulated "KEV on internet-facing host" ticket.
8. Test SSRF to a lab metadata endpoint; detect.
9. Scan a container image; map findings to packages.
10. Write a vulnerability prioritisation policy with SLAs.

---

## 20. Self-test questions

1. Differentiate vulnerability, exploit, threat, and risk.
2. What is a zero-day vs an n-day?
3. What does a CVE identify, and what does a CWE identify?
4. List the eight CVSS v3.1 base metrics.
5. Why is CVSS alone insufficient for prioritisation?
6. What does EPSS estimate?
7. What is the CISA KEV list used for?
8. What five factors drive risk-based prioritisation?
9. How do you confirm a scanner finding is real?
10. What is virtual patching?
11. Which log evidence proves successful web exploitation?
12. How do you distinguish a scan from an exploit attempt?
13. What is SSRF, and which internal target is most dangerous?
14. What should you do first for a live leaked secret?
15. How do you verify remediation?

---

## 21. One-page revision checklist

- [ ] Vocabulary: vulnerability, exploit, threat, risk, exposure, attack surface, zero-day, n-day, mitigation, compensating control, FP/FN.
- [ ] Risk = threat × vulnerability × impact (context: exposure, criticality).
- [ ] Lifecycle: introduction → discovery → disclosure → CVE → patch → exploitation → detection → remediation → verification → retirement.
- [ ] IDs: CVE, CWE, CAPEC, NVD, GHSA, vendor advisories, KEV, EPSS, SBOM, CPE.
- [ ] CVSS 3.1 metrics (AV/AC/PR/UI/S/C/I/A), ratings, temporal/environmental, limitations; CVSS 4.0 exists.
- [ ] EPSS (30-day probability), KEV (confirmed exploited), combined priority matrix.
- [ ] Discovery: network/auth scan, agent, ASM, container, SAST/DAST/SCA, bounty/pentest, intel, manual.
- [ ] Prioritisation: exploitability, exposure, asset criticality, blast radius, compensating controls, data sensitivity; SLA by severity/exposure; common mistakes.
- [ ] Remediation: patch, upgrade, config, compensating, isolate, accept, verify.
- [ ] Classes: injection, XSS, CSRF, SSRF, traversal/LFI, upload, deserialization, XXE, auth, access control, misconfig, outdated, crypto, secrets, race, business logic, supply chain, cloud IAM.
- [ ] Exploit telemetry: WAF, web logs, IDS/IPS, proxy, EDR, auth, cloud, scanner, honeypot; attempt vs success evidence.
- [ ] Triage: identify → validate applicability → activity → impact → controls → decide → contain → verify/document.
- [ ] Playbooks: critical CVE, WAF hit, KEV, web shell, public bucket, secret, EOL.
- [ ] Severity table.
- [ ] Detections: web→shell, webroot file, outbound from server, repeated 500+payload, scanner+exploit, traversal, SSRF, deserialization, web shell, uploads, auth bypass, spray, cloud IAM, public storage, EOL exploitation.
- [ ] SPL/KQL/Sigma patterns.
- [ ] Investigation: anchor → validate → activity → chain → scope → contain → eradicate/recover → document.
- [ ] Hardening/VM program: inventory, SBOM, SLA/KEV, ASM, baselines, virtual patch, segmentation, MFA/least privilege, secret/dependency scanning, EOL, bounty/pentest, verification, metrics.
