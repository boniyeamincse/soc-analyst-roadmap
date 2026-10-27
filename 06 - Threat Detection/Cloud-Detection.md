# Cloud Detection & Identity Threats — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Phishing](Phishing.md) · [Suspicious Processes →](Suspicious-Processes.md)

> Goal: Detect, triage, and respond to identity compromises, privilege escalation, data exfiltration, and control-plane attacks across multi-cloud environments (AWS, Azure, and Microsoft 365 / Entra ID).
> Related notes: [05 - SIEM/Microsoft-Sentinel.md](../05%20-%20SIEM/Microsoft-Sentinel.md); [04 - Security Monitoring/Alerting.md](../04%20-%20Security%20Monitoring/Alerting.md); [Credential-Attacks.md](Credential-Attacks.md); [Phishing.md](Phishing.md).

---

## 0. How to use this note

1. §1–§2: The shared responsibility model, cloud kill chain, and primary telemetry sources.
2. §3–§5: AWS telemetry & attack patterns (CloudTrail, GuardDuty, IMDS SSRF, IAM privilege escalation, S3 exfiltration).
3. §6–§8: Microsoft 365 & Entra ID threats (Impossible Travel, MFA fatigue, OAuth illicit consent grants, Exchange backdoor rules).
4. §9–§11: Detection queries (KQL & SPL), triage workflows, and incident severity metrics.
5. §12–§14: Hardening recommendations, hands-on lab exercises, self-test questions, and revision checklist.

---

## 1. Cloud attack surface & the cloud kill chain

```
Initial Compromise
   ├── Stolen IAM Access Keys (GitHub leaks, developer workstations)
   ├── Phished Entra ID / M365 Credentials (AiTM / Device Code Phishing)
   └── Web App Vulnerability (SSRF to AWS IMDS 169.254.169.254)
   ↓
Reconnaissance & Discovery
   ├── AWS: GetCallerIdentity, ListUsers, DescribeInstances, ListBuckets
   └── Azure/M365: Graph API queries, List Enterprise Apps, Read Directory
   ↓
Privilege Escalation
   ├── AWS: IAM policy alteration (AttachUserPolicy, CreateAccessKey, PassRole)
   └── Azure: Global Admin role assignment, service principal secret creation
   ↓
Persistence & Defense Evasion
   ├── OAuth App / Illicit Consent Grant (acts with user delegated permissions)
   ├── CloudTrail / Activity Log disabling (StopLogging, DeleteTrail)
   └── Exchange Inbox forwarding / redirect rules (hidden from Outlook UI)
   ↓
Impact / Exfiltration
   ├── S3 bucket sync / snapshot sharing across external AWS accounts
   ├── Mailbox exfiltration via Graph API
   └── Resource hijacking for crypto-mining (EC2 / Azure VM spinning)
```

---

## 2. Telemetry sources across cloud providers

| Cloud Provider | Telemetry Source | What It Logs | Key Fields for SOC |
|---|---|---|---|
| **AWS** | **AWS CloudTrail** | API calls across management console, SDKs, CLI. | `eventName`, `eventSource`, `userIdentity.arn`, `sourceIPAddress`, `userAgent`, `errorCode` |
| **AWS** | **Amazon GuardDuty** | ML-based threat detection (threat intel, DNS logs, CloudTrail, Flow Logs). | `type`, `severity`, `resource.instanceDetails`, `service.action` |
| **AWS** | **VPC Flow Logs** | IP traffic going to and from network interfaces in your VPC. | `srcaddr`, `dstaddr`, `srcport`, `dstport`, `action` (ACCEPT/REJECT), `bytes` |
| **Azure / M365** | **Entra ID Sign-in Logs** | Interactive and non-interactive user authentications. | `UserPrincipalName`, `IPAddress`, `Location`, `ConditionalAccessStatus`, `RiskState` |
| **Azure / M365** | **Entra ID Audit Logs** | Directory changes (users, roles, apps, groups). | `ActivityDisplayName`, `InitiatedBy`, `TargetResources`, `Result` |
| **Azure** | **Azure Activity Logs** | Control-plane operations across Azure subscriptions. | `OperationName`, `Caller`, `ResourceGroup`, `HTTPStatus` |
| **M365** | **Unified Audit Log (UAL)** | User actions across SharePoint, OneDrive, Exchange, Teams. | `Workload`, `Operation`, `UserId`, `ClientIP`, `Parameters` |

---

## 3. AWS attack techniques & detection

### 3.1 Instance Metadata Service (IMDS) SSRF exploitation
- **Concept:** Web applications with Server-Side Request Forgery (SSRF) vulnerabilities can query the internal AWS link-local IP (`http://169.254.169.254/latest/meta-data/iam/security-credentials/<RoleName>`).
- **Impact:** Attacker steals temporary session tokens (`AccessKeyId`, `SecretAccessKey`, `SessionToken`) of the EC2 IAM role.
- **Defensive Telemetry:**
  - In CloudTrail: API calls originating from an external/attacker IP address using the identity `userIdentity.type == "AssumedRole"` belonging to an EC2 instance.
  - Web Server logs: Inbound HTTP requests containing `169.254.169.254`.

```spl
# Splunk: Detect EC2 AssumedRole used from an external, non-AWS IP
index=aws_cloudtrail eventSource="*.amazonaws.com" userIdentity.type="AssumedRole"
| where match(userIdentity.arn, "arn:aws:sts::.*:assumed-role/.*")
| iplocation sourceIPAddress
| where isnotnull(Country) AND sourceIPAddress!="127.0.0.1" AND NOT cidrmatch("10.0.0.0/8", sourceIPAddress)
| table _time, eventName, userIdentity.arn, sourceIPAddress, Country, userAgent
```

### 3.2 CloudTrail tampering & defense evasion (T1562.008)
Attackers who obtain administrative access immediately attempt to blind the SOC by stopping or deleting audit trails:

```spl
# Splunk: Detect CloudTrail destruction or logging termination
index=aws_cloudtrail eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors")
| table _time, eventName, userIdentity.arn, sourceIPAddress, userAgent, responseElements
```

### 3.3 S3 data exfiltration (T1537 / T1530)
- Look for mass `GetObject` requests, `PutBucketPolicy` enabling public access, or `PutBucketAcl`.
- Unusually high outbound egress bytes in VPC Flow Logs or S3 Access Logs.

---

## 4. Microsoft 365 & Entra ID (Azure AD) identity attacks

### 4.1 Impossible Travel & anomalous logins
- **Concept:** An account logs in from New York at 10:00 AM and from London at 10:20 AM. The physical transit between geographic locations is mathematically impossible within the time delta.
- **Log Source:** Entra ID `SigninLogs`.
- **False Positive checks:** Legitimate corporate VPN hubs, Zscaler/proxy egress points, multi-tenant cloud automation scripts.

```kusto
// KQL: Impossible Travel / Rapid Geolocation Shift Detection
SigninLogs
| where ResultType == 0 // Successful logon
| project TimeGenerated, UserPrincipalName, IPAddress, Location = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city)
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevLocation = prev(Location), PrevIP = prev(IPAddress)
| extend TimeDeltaMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where UserPrincipalName == prev(UserPrincipalName)
| where Location != PrevLocation and TimeDeltaMinutes between (1 .. 120)
| project TimeGenerated, UserPrincipalName, Location, IPAddress, PrevLocation, PrevIP, TimeDeltaMinutes
```

### 4.2 OAuth App consent abuse / Illicit Consent Grants (T1528)
- **Concept:** Instead of stealing a password, the attacker sends a phishing link requesting the user to approve a third-party application. The app requests scopes like `Mail.ReadWrite`, `Files.ReadWrite.All`, and `offline_access`.
- **Why attackers love this:**
  - Bypasses MFA and password rotation entirely.
  - Works as long as the token is valid or refreshed.
- **Log Source:** Entra ID `AuditLogs`.
- **Activity:** `Consent to application` or `Add service principal`.

```kusto
// KQL: Detect User Consenting to High-Risk OAuth Application
AuditLogs
| where LoggedByService == "Core Directory"
| where ActivityDisplayName in ("Consent to application", "Add delegated permission grant", "Add service principal")
| extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "MailboxSettings.ReadWrite", "Files.ReadWrite.All", "full_access_as_app")
| project TimeGenerated, ActivityDisplayName, InitiatingUser, AppDisplayName, Permissions
```

### 4.3 Malicious Exchange forwarding & inbox rule persistence (T1114.003)
Following a Business Email Compromise (BEC), the attacker creates an inbox rule to hide vendor invoices or forward banking communications to an external mailbox:
- Operations in Unified Audit Log: `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`.
- Rule actions: `ForwardTo`, `ForwardAsAttachmentTo`, `DeleteMessage`, `MoveToFolder` (e.g. RSS Subscriptions, Junk).

```kusto
// KQL: Detect External Email Auto-Forwarding Rules Created
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

---

## 5. Cloud Triage Playbook

### Step-by-Step Incident Investigation

```
Alert: Risky Sign-in / Unusual Cloud API Call / Suspicious Consent Grant
   │
   ├─ 1. Identity Verification & Context
   │     • Check UserPrincipalName / IAM ARN role.
   │     • Compare Source IP with the user's historical login baseline.
   │     • Check Threat Intelligence: Is the source IP an anonymizing VPN, Tor exit node, or hosting provider (DigitalOcean, AWS, Linode)?
   │
   ├─ 2. Evaluate Authentication Quality
   │     • Did MFA prompt succeed? What MFA method was used (FIDO2 vs SMS vs Push Notification fatigue)?
   │     • Was a Conditional Access Policy applied or bypassed?
   │
   ├─ 3. Activity Scoping (What happened next?)
   │     • Query all audit events for the compromised identity within +/- 4 hours.
   │     • Check for newly created access keys, modified permissions, or downloaded files.
   │     • Review Exchange trace: Were any emails sent from this account to external partners?
   │
   └─ 4. Immediate Cloud Containment Actions
         • Revoke all active user sessions / refresh tokens (`Revoke-AzureADUserAllRefreshToken`).
         • Reset account password immediately.
         • AWS: Deactivate compromised IAM Access Key pair (`aws iam update-access-key --status Inactive`).
         • Remove malicious OAuth application consent grants or forwarding inbox rules.
```

---

## 6. Cloud Hardening & Best Practices

| Area | Recommended Control | Security Impact |
|---|---|---|
| **Identity** | Enforce Phishing-Resistant MFA (FIDO2 / Windows Hello) | Neutralizes AiTM / Evilginx reverse proxy credential harvesting. |
| **M365** | Block User App Consent | Prevent standard users from granting permissions to unverified third-party apps. |
| **AWS IMDS** | Enforce **IMDSv2** (`HttpTokens=required`, `HttpPutResponseHopLimit=1`) | Completely mitigates SSRF metadata credential theft by requiring session tokens via PUT. |
| **AWS IAM** | Prohibit Root Account API Keys & use IAM Identity Center | Eliminates persistent high-privilege keys. |
| **Data Protection** | S3 Block Public Access at the organization level | Prevents accidental or malicious data leaks. |
| **Audit Trails** | Protect CloudTrail S3 bucket with Object Lock & MFA Delete | Prevents attackers from erasing audit logs. |

---

## 7. Hands-on Labs

1. **AWS CloudTrail Querying:** In CloudTrail lake or Athena, write queries to detect unauthorized `GetCallerIdentity` followed by `Describe*` calls.
2. **IMDSv2 Verification:** Deploy a test EC2 instance, query IMDSv1 vs IMDSv2 via `curl`, and observe how hop limits prevent SSRF.
3. **Entra ID Consent Simulation:** In a developer tenant, register a test app requesting `Mail.Read`, grant consent, and trace the event in `AuditLogs`.
4. **Exchange Inbox Rule Hunt:** Create a rule forwarding emails to an external email and write a KQL query to catch the rule parameter.
5. **Impossible Travel Alerting:** Write a Sentinel analytics rule using simulated login coordinates and tune out known proxy false positives.

---

## 8. Self-test questions

1. What makes IMDSv2 immune to basic SSRF attacks compared to IMDSv1?
2. Why is an OAuth illicit consent grant often more dangerous than a stolen password?
3. What is the difference between AWS CloudTrail management events and data events?
4. How do you distinguish between legitimate corporate VPN usage and an actual "Impossible Travel" compromise?
5. Which API calls does an attacker frequently use in AWS immediately after getting a foothold to determine who they are?
6. If an Entra ID user's session cookie is stolen via AiTM, will resetting their password alone immediately terminate the attacker's active session?
7. What are the key parameters to look for in `New-InboxRule` when investigating Business Email Compromise (BEC)?

---

## 9. One-page revision checklist

- [ ] AWS CloudTrail: `eventName`, `userIdentity.arn`, `sourceIPAddress`, `errorCode` (AccessDenied spikes).
- [ ] IMDSv1 vs IMDSv2: `169.254.169.254`, IMDSv2 requires `X-aws-ec2-metadata-token` PUT request; hop limit = 1 prevents SSRF.
- [ ] AWS defense evasion: Alert immediately on `StopLogging`, `DeleteTrail`, `UpdateTrail`.
- [ ] Entra ID sign-ins: `ResultType == 0` (success), `ResultType == 50126` (invalid password), `50074` (MFA required).
- [ ] Impossible Travel: Evaluate travel velocity, look for distinct ISP/ASN shifts, verify VPN/SASE egress IPs.
- [ ] Illicit Consent Grant: Third-party app granted `offline_access`, `Mail.ReadWrite`, `Files.ReadWrite.All`; event `Consent to application`.
- [ ] BEC indicators: `New-InboxRule` forwarding to external domains, rules moving mail to Junk/RSS, modified bank details.
- [ ] Incident containment: Invalidate tokens (`Revoke-AzureADUserAllRefreshToken`), disable IAM access keys, isolate workloads.

---

> **Navigation:** [Roadmap index](../README.md) · [← Phishing](Phishing.md) · [Suspicious Processes →](Suspicious-Processes.md)
