# Wazuh — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Splunk](Splunk.md) · [Brute Force →](../06%20-%20Threat%20Detection/Brute-Force.md)

> Goal: operate Wazuh as an open-source SIEM/XDR — deploy agents, read alerts, tune rules, and use FIM/SCA/vulnerability/active-response.
> Concepts shared with other SIEMs → [Log-Collection.md](Log-Collection.md), [Detection-Rules.md](Detection-Rules.md); query craft → [Queries.md](Queries.md).

---

## 0. How to use this note

1. §1–§3: what Wazuh is; architecture; deployment.
2. §4–§6: agents; log collection/decoders; rules.
3. §7–§10: FIM, SCA, vulnerability detection, active response.
4. §11–§13: alerts/triage; integration; tuning.
5. §14–§16: pitfalls, commands, labs.
6. §17–§18: self-test, revision.

---

## 1. What Wazuh is

- **Open-source SIEM + XDR + HIDS** platform (GPLv2).
- Combines: log analysis, file integrity monitoring (FIM), security configuration assessment (SCA), vulnerability detection, active response, MITRE ATT&CK mapping.
- Ships **agents** for Windows/Linux/macOS/containers/cloud.
- Scales from a lab VM to enterprise clusters.

**Positioning:** strong host-based visibility and free licence; weaker than commercial SIEMs for huge ingestion, long retention, and advanced correlation — often paired with Elastic/OpenSearch.

---

## 2. Architecture

```
Agents (endpoints/servers)
   │ (encrypted, port 1514)
   ▼
Wazuh Manager
 ├── Analysis engine (decoders + rules)
 ├── API (55000)
 ├── Agent enrollment (1515)
 ├── Cluster (master/worker)
 └── Active response
   │
   ▼
Wazuh Indexer (OpenSearch fork, 9200)
   │
   ▼
Wazuh Dashboard (443)
```

| Component | Role |
|---|---|
| **Agent** | Collects logs, FIM, SCA, vulnerability data; enforces active response. |
| **Manager** | Receives events, decodes, matches rules, generates alerts, runs AR. |
| **Indexer** | Stores alerts/events (OpenSearch-based). |
| **Dashboard** | Kibana/OpenSearch Dashboards UI. |
| **Filebeat** | Ships manager alerts to indexer (in the all-in-one). |

### 2.1 Event flow

```
Log → agent → manager queue → decoder → rule match → alert
                                                    ├── indexer
                                                    ├── active response
                                                    └── integrations (email, Slack, webhook)
```

### 2.2 Ports

| Port | Purpose |
|---|---|
| 1514/TCP | Agent → manager events. |
| 1515/TCP | Enrollment. |
| 55000/TCP | REST API. |
| 9200/TCP | Indexer. |
| 443/TCP | Dashboard. |

---

## 3. Deployment

### 3.1 Models

| Model | Use |
|---|---|
| **All-in-one** | Lab/small. |
| **Distributed** | Separate manager/indexer/dashboard. |
| **Cluster** | Master + workers, indexer cluster. |
| **Cloud** | Wazuh Cloud. |
| **Docker** | `wazuh-docker` compose. |

### 3.2 Sizing

- Manager: CPU for rule matching, RAM for queues.
- Indexer: disk (hot/warm), heap (~50% RAM, max ~31 GB).
- Dashboard: modest.

### 3.3 Hardening

- Change default passwords (`admin`, `wazuh`, `kibanaserver`).
- TLS for API, indexer, agents.
- Restrict 55000/9200 to management networks.
- Least-privilege API users.
- Backups of manager config and indexer snapshots.
- Keep versions current.

---

## 4. Agents

### 4.1 Enrollment

```bash
# Agent-side (Linux)
WAZUH_MANAGER="10.0.0.10" yum install wazuh-agent
systemctl enable --now wazuh-agent

# Or with authd password
/var/ossec/bin/agent-auth -m 10.0.0.10 -P "<enrollment-password>"
```

```powershell
# Windows MSI
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="10.0.0.10" WAZUH_REGISTRATION_SERVER="10.0.0.10"
```

### 4.2 Management

```bash
/var/ossec/bin/agent_control -l           # list
/var/ossec/bin/agent_control -i 001       # info
/var/ossec/bin/agent_control -r -a        # restart all
/var/ossec/bin/manage_agents              # interactive add/remove
/var/ossec/bin/agent_groups -l            # groups
```

### 4.3 Agent configuration

- `ossec.conf` on the agent.
- Centralised via **agent groups** (`/var/ossec/etc/shared/<group>/`).
- `local_internal_options.conf` for debug.

### 4.4 Health

- Agent status: active / disconnected / never connected.
- Last keep-alive.
- Version spread.
- Agent groups correct.

**Disconnected agents = blind endpoints.** Alert on them.

---

## 5. Log collection and decoders

### 5.1 Local files

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>/var/log/app/audit.json</location>
</localfile>
```

### 5.2 Windows

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 5.3 Commands

```xml
<localfile>
  <log_format>command</log_format>
  <command>netstat -ano</command>
  <frequency>300</frequency>
</localfile>
```

### 5.4 Decoders

- Convert raw log text into fields.
- Built-in decoders for SSH, Apache, Windows, syslog, JSON.
- Custom decoders in `/var/ossec/etc/decoders/local_decoder.xml`.

```xml
<decoder name="myapp-login">
  <program_name>myapp</program_name>
  <regex>user=(\S+) src=(\S+) status=(\S+)</regex>
  <order>user, srcip, status</order>
</decoder>
```

**Test with `wazuh-logtest`:**

```bash
/var/ossec/bin/wazuh-logtest
# paste a log line, see decoder + rule match
```

`wazuh-logtest` is the single most useful troubleshooting tool.

---

## 6. Rules

### 6.1 Structure

```xml
<group name="myapp,authentication_failed,">
  <rule id="100100" level="5">
    <decoded_as>myapp-login</decoded_as>
    <field name="status">failed</field>
    <description>MyApp failed login for $(user) from $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

### 6.2 Levels

| Level | Meaning |
|---|---|
| 0 | Ignored (no alert). |
| 1–3 | Low/info. |
| 4–6 | Medium. |
| 7–9 | High. |
| 10–11 | Critical. |
| 12+ | Severe (reserved). |

### 6.3 Common rule mechanics

| Mechanism | Use |
|---|---|
| `<if_sid>` | Parent rule chaining. |
| `<if_matched_sid>` | Frequency/composite. |
| `<frequency>` + `<timeframe>` | Threshold. |
| `<same_source_ip>` / `<same_id>` | Correlation by entity. |
| `<field name="x">value</field>` | Match decoded field. |
| `<regex>` | Regex on full log. |
| `<srcip>` | Negate/allow source. |
| `<mitre>` | ATT&CK mapping. |
| `<options>no_full_log</options>` | Reduce alert size. |

### 6.4 Example: brute force

```xml
<rule id="100200" level="10" frequency="8" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>MyApp brute force from $(srcip)</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

### 6.5 Rule files

- `/var/ossec/etc/rules/local_rules.xml` — custom.
- Rule IDs: 100000–120000 for local.
- Order matters; first match wins unless `overwrite`.
- Use groups for organisation.

### 6.6 Rule testing

```bash
/var/ossec/bin/wazuh-logtest
/var/ossec/bin/wazuh-analysisd -t          # config test
```

**Always test before restarting the manager.**

---

## 7. File Integrity Monitoring (FIM)

### 7.1 Config

```xml
<syscheck>
  <frequency>43200</frequency>
  <directories check_all="yes" realtime="yes">/etc</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc</directories>
  <ignore>/etc/mtab</ignore>
</syscheck>
```

### 7.2 Options

| Option | Effect |
|---|---|
| `check_all` | Size, permissions, owner, hash, mtime. |
| `realtime` | Inotify/ETW immediate. |
| `report_changes` | Diff content. |
| `whodata` | User/process attribution (audit/ETW). |
| `nodiff` | Exclude sensitive files from diff. |

### 7.3 Use in SOC

- Detect webshell drops in web roots.
- Detect persistence (cron, systemd, Run keys, drivers).
- Detect tampering with security binaries/config.
- Detect credential file changes.

**Whodata is the high-value feature** — tells you which process changed the file.

### 7.4 Noise

- Exclude caches/logs/temp/package directories.
- Baseline after deployment; large first scan is normal.
- Keep FIM scope tight and business-driven.

---

## 8. SCA (Security Configuration Assessment)

- Policy-based checks (CIS benchmarks for Windows/Linux).
- Produces pass/fail per check with remediation text.
- Run on schedule; track score over time.

**SOC use:** identify hosts drifting from baseline; support compliance evidence.

---

## 9. Vulnerability detection

- Correlates installed packages/OS with CVE feeds.
- Reports per agent, severity, CVE, package.
- Requires updated feeds.

**SOC use:** prioritise hosts with actively exploited CVEs; complement with scanner data.

---

## 10. Active response

### 10.1 What

Manager triggers a command on an agent when a rule fires.

| Response | Effect |
|---|---|
| `firewall-drop` | Block source IP (iptables). |
| `host-deny` | Deny host in hosts.deny. |
| `disable-account` | Lock user (PAM). |
| `restart-wazuh` | Restart agent. |
| Custom script | Any action. |

### 10.2 Config

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100200</rules_id>
  <timeout>600</timeout>
</active-response>
```

### 10.3 Discipline

- **High-confidence rules only.** A false positive can lock out an admin or block a service.
- Timeout always set.
- Log every AR action.
- Test in lab; monitor for lockouts.
- Prefer temporary blocks over account disables.
- Document which rules trigger AR.

---

## 11. Alerts and triage

### 11.1 Alert fields

- Rule ID, level, description.
- Agent (host), manager.
- Decoder, source/dest IP, user.
- Full log, MITRE IDs, groups.
- Timestamp.

### 11.2 Triage workflow

1. Read rule level/description/MITRE.
2. Identify agent and asset criticality.
3. Inspect full log and decoded fields.
4. Pivot: same rule across estate, same agent across rules.
5. Corroborate with FIM/SCA/vuln data.
6. Decide: TP/FP/benign.
7. Respond (AR, isolate, escalate).
8. Tune rule / add exception.

### 11.3 Dashboards

- Security events over time.
- Top rules by level.
- Top agents by alert count.
- MITRE ATT&CK coverage.
- FIM changes.
- Vulnerability summary.
- Agent status.

---

## 12. Integration

| Target | Method |
|---|---|
| **Email** | `<global><email_notification>` + SMTP. |
| **Slack/Teams** | Integration script/webhook. |
| **Elastic/OpenSearch** | Filebeat → indexer. |
| **TheHive/Cortex** | Webhook/API. |
| **Syslog/SIEM** | `<syslog_output>`. |
| **VirusTotal** | Integration module. |
| **Shuffle/n8n** | Webhook automation. |

**Wazuh is often the collection/analysis tier feeding a larger SIEM.**

---

## 13. Tuning

### 13.1 Signals

- Top rules by volume.
- Rules with level ≥7 firing constantly.
- FIM noise from package updates.
- SCA churn.
- Disconnected agents.

### 13.2 Levers

| Lever | Effect |
|---|---|
| Rule level adjustment | Re-prioritise. |
| `<frequency>`/`<timeframe>` | Fewer threshold alerts. |
| Rule suppression (`<rule id="x" level="0">`) | Silence specific patterns. |
| FIM ignore lists | Reduce churn. |
| Agent groups | Scope rules to host classes. |
| Decoder fixes | Correct parsing. |

### 13.3 Discipline

- Never silence an entire category.
- Document each override with reason and date.
- Re-test after changes.
- Review monthly.

---

## 14. Common pitfalls

| Pitfall | Consequence |
|---|---|
| Default passwords | Compromise. |
| Public 55000/9200 | Breach. |
| No agent health monitoring | Blind hosts. |
| FIM on everything | Noise and load. |
| AR on low-confidence rules | Outages. |
| Untested custom rules | Broken matching. |
| No decoders for custom logs | Unparsed noise. |
| Ignoring `wazuh-logtest` | Slow debugging. |
| No retention plan | Disk full. |
| No backups | Config loss. |
| Version drift | Incompatibility. |
| Over-broad ignore lists | Blind spots. |

---

## 15. Commands

```bash
# Service
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard

# Config test / rule test
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-logtest

# Agents
/var/ossec/bin/agent_control -l
/var/ossec/bin/agent_control -i 001
/var/ossec/bin/agent_groups -l -g default

# Logs
tail -f /var/ossec/logs/ossec.log
tail -f /var/ossec/logs/alerts/alerts.log
tail -f /var/ossec/logs/alerts/alerts.json | jq

# Cluster
/var/ossec/bin/cluster_control -l
/var/ossec/bin/cluster_control -a

# API
curl -k -u user:pass https://localhost:55000/agents?pretty=true
curl -k -u user:pass https://localhost:55000/manager/status?pretty=true
```

```bash
# Search alerts
grep -c '"rule":{"level":1[0-9]' /var/ossec/logs/alerts/alerts.json
jq 'select(.rule.level >= 10) | {agent:.agent.name, rule:.rule.description}' alerts.json | head
```

---

## 16. Labs

1. Deploy all-in-one Wazuh in Docker.
2. Enroll a Linux and a Windows agent.
3. Enable FIM with whodata on `/etc`; modify a file; observe.
4. Write a custom decoder + rule for an app log; test with `wazuh-logtest`.
5. Create a brute-force rule with `<frequency>` and `<same_source_ip>`.
6. Trigger active response `firewall-drop` with a test rule.
7. Run SCA and review failing checks.
8. Review vulnerability findings for one host.
9. Build a dashboard for top rules and agent status.
10. Forward alerts to Slack via webhook.

---

## 17. Self-test questions

1. What are Wazuh's four components?
2. Which ports does it use?
3. What is a decoder vs a rule?
4. How do you test a rule?
5. What is `wazuh-logtest` for?
6. How does rule level map to severity?
7. What is `<if_matched_sid>` used for?
8. What does `whodata` add to FIM?
9. What is SCA?
10. What are the risks of active response?
11. How do you centralise agent config?
12. How do you detect disconnected agents?
13. How does Wazuh integrate with a larger SIEM?
14. What should you harden first?
15. How do you reduce FIM noise?

---

## 18. One-page revision checklist

- [ ] Wazuh = open-source SIEM/XDR/HIDS: log analysis, FIM, SCA, vuln detection, active response, ATT&CK.
- [ ] Architecture: agents → manager (decoders/rules/API/AR) → indexer → dashboard; Filebeat; ports 1514/1515/55000/9200/443.
- [ ] Deployment: all-in-one, distributed, cluster, cloud, Docker; sizing; hardening (default creds, TLS, network restriction, backups, updates).
- [ ] Agents: enrollment (authd/MSI), management commands, groups, ossec.conf, health (active/disconnected), version spread.
- [ ] Log collection: localfile (syslog/json/eventchannel/command).
- [ ] Decoders: built-in vs local_decoder.xml; order fields; `wazuh-logtest`.
- [ ] Rules: id/level/description, groups, if_sid, if_matched_sid, frequency/timeframe, same_source_ip/id, field/regex, mitre; levels 0–12; local_rules IDs 100000+; test before restart.
- [ ] FIM: syscheck, check_all, realtime, report_changes, whodata, nodiff, ignore; webshell/persistence/tamper use cases; noise control.
- [ ] SCA: CIS policies, pass/fail, drift tracking.
- [ ] Vulnerability detection: package/OS vs CVE feed; prioritise.
- [ ] Active response: firewall-drop/host-deny/disable-account/restart/custom; high-confidence only, timeout, logging, lab test.
- [ ] Alerts/triage: fields, workflow, dashboards (events, top rules, top agents, ATT&CK, FIM, vuln, agent status).
- [ ] Integration: email, Slack/Teams, Elastic/OpenSearch, TheHive, syslog, VT, Shuffle.
- [ ] Tuning: level, frequency, suppression, FIM ignore, agent groups, decoder fixes; document and review.
- [ ] Pitfalls list memorised.
- [ ] Commands: service status, analysisd -t, logtest, agent_control, cluster_control, API curl, alerts.json jq.

---

> **Navigation:** [Roadmap index](../README.md) · [← Splunk](Splunk.md) · [Brute Force →](../06%20-%20Threat%20Detection/Brute-Force.md)
