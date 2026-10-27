# Purple Teaming & Adversary Emulation — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← SOAR](SOAR.md) · [Practice / Section 10 →](../10%20-%20Practice/TryHackMe.md)

> Goal: Master the methodology of collaborative Purple Teaming, adversary emulation using Atomic Red Team, and automated continuous detection testing to validate SOC detection rules.
> Related notes: [SOAR.md](SOAR.md); [05 - SIEM/Detection-Rules.md](../05%20-%20SIEM/Detection-Rules.md); [03 - Cybersecurity Fundamentals/MITRE-ATTACK.md](../03%20-%20Cybersecurity%20Fundamentals/MITRE-ATTACK.md); [06 - Threat Detection/Suspicious-Processes.md](../06%20-%20Threat%20Detection/Suspicious-Processes.md).

---

## 0. How to use this note

1. §1–§2: What is Purple Teaming and why traditional static detection rules fail.
2. §3–§4: The Adversary Emulation lifecycle and threat modeling for test cases.
3. §5–§7: Hands-on with Atomic Red Team (execution, cleanup, prerequisites, and logging).
4. §8–§9: Building an automated continuous detection testing pipeline (CI/CD detection-as-code).
5. §10–§12: Scoring detection efficacy (telemetry vs alert vs block), self-test questions, and revision checklist.

---

## 1. Why Purple Teaming is essential

Traditional defensive security operates in silos:
- **Red Team** runs covert engagements once a year, delivers a 100-page report, and walks away.
- **Blue Team (SOC)** is inundated with alerts, has no visibility into *why* an attack bypassed their rules, and assumes that having a rule means having coverage.

```
       [RED TEAM]                           [BLUE TEAM]
 (Adversary Emulation)                   (SOC / Detection)
          │                                      │
          └───────────────► ◄────────────────────┘
                             │
                     [PURPLE TEAMING]
        Collaborative, transparent, loop-based testing:
        1. Emulate atomic TTP
        2. Inspect SIEM/EDR raw telemetry
        3. Validate rule firing & SLA
        4. Tune false positives & harden defenses
        5. Repeat & automate regression test
```

### Core Value to the SOC Analyst
1. **Verifies Telemetry Pipelines:** Proves that endpoint logs (Sysmon/EDR) are actually forwarding to the SIEM.
2. **Eliminates Detection Blind Spots:** Discovers whether evasion techniques (e.g. LOLBins, command-line obfuscation) bypass your filters.
3. **Validates Alert Escalation:** Tests whether an alert actually generates an analyst ticket or gets dropped by flood throttling.

---

## 2. Detection Efficacy Scoring Framework

When testing a MITRE ATT&CK technique, evaluate the defensive posture against this progressive scoring ladder:

| Score Level | Outcome | What It Means | SOC Action Required |
|---|---|---|---|
| **Level 0: Blind** | No Telemetry | The endpoint or network does not log the activity. | Enable audit policy, update Sysmon config, or deploy EDR. |
| **Level 1: Logged** | Raw Telemetry Present | Log exists in SIEM/data lake, but no alert or detection rule exists. | Author a detection rule (Sigma / KQL / SPL). |
| **Level 2: Detected** | Alert Generated | SIEM/EDR generated an alert; ticket created in SOC queue. | Review alert fidelity, context fields, and false positive rate. |
| **Level 3: Blocked** | Prevented / Quarantined | EDR/AV or ASR (Attack Surface Reduction) rule blocked execution. | Validate that block telemetry is captured and forwarded to SIEM. |

---

## 3. Atomic Red Team (The Industry Standard)

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary is an open-source library of simple, repeatable, and scripted test cases mapped directly to MITRE ATT&CK techniques.

### 3.1 Invoke-AtomicRedTeam Architecture
- **Atomics Folder:** Contains YAML definitions of tests for each technique (e.g. `T1059.001` for PowerShell, `T1003.001` for LSASS memory).
- **Execution Engine:** `Invoke-AtomicRedTeam` PowerShell module to execute atomics, check prerequisites, and clean up test artifacts.

```powershell
# Install Invoke-AtomicRedTeam in a dedicated test lab VM
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics
```

### 3.2 Executing an Atomic Test

```powershell
# 1. Inspect available tests for T1059.001 (PowerShell)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# 2. Check and satisfy prerequisites for Test #1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -CheckPrereqs

# 3. Execute the atomic test
Invoke-AtomicTest T1059.001 -TestNumbers 1

# 4. Mandatory Step: Clean up all artifacts created by the test!
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

---

## 4. Step-by-Step Purple Teaming Exercise

### Example: Testing T1053.005 (Scheduled Task Creation)

```
[Phase 1: Hypothesis & Threat Intelligence]
  • Threat Intel reports threat actor Akira creating scheduled tasks named "WindowsUpdateTask"
    via schtasks.exe to establish persistence.
  • Blue Team hypothesis: "Our SIEM rule catches all non-system scheduled task creation."

[Phase 2: Emulation Execution]
  • Red executes Atomic Test for T1053.005:
    cmd.exe /c schtasks /create /sc minute /mo 1 /tn "MaliciousTask" /tr "calc.exe"

[Phase 3: Telemetry & Detection Verification]
  • Did Windows Security Log generate Event ID 4698 (A scheduled task was created)?
  • Did Sysmon capture Event ID 1 (Process creation: schtasks.exe with /create argument)?
  • Did our SIEM rule trigger an alert within 3 minutes?

[Phase 4: Findings & Remediation]
  • Finding: Event ID 4698 was NOT logged because Advanced Audit Policy "Audit Other Object
    Access Events" was disabled in Group Policy!
  • Fix: Enable audit subcategory via GPO; re-run test; confirm Event 4698 is now ingested.
  • Result: Score upgraded from Level 0 (Blind) to Level 2 (Detected).
```

---

## 5. Automated Continuous Detection Testing (CI/CD)

Modern detection engineering treats detections as software code (Detection-as-Code). Detection validation is automated through CI/CD pipelines (e.g. GitHub Actions / GitLab CI):

```
[Git Commit: New Sigma Rule Added]
         │
         ▼
[GitHub Actions Runner / Lab VM]
         │
         ├─ 1. Syntax & Schema Linting (yamllint, sigma-cli check)
         │
         ├─ 2. Spin up ephemeral Windows Server VM in cloud/sandbox
         │
         ├─ 3. Run Invoke-AtomicRedTeam against targeted ATT&CK ID
         │
         ├─ 4. Query SIEM API / Elasticsearch index for alert firing
         │
         ├─ 5. Test Assertion:
         │      • If alert found within 5 min ──► PASS (Merge to Prod)
         │      • If no alert generated       ──► FAIL (Block deployment)
         │
         └─ 6. Teardown test VM
```

---

## 6. Real-World Pitfalls & Safety Rules

> [!CAUTION]
> **Safety First:** Never run automated emulation tools directly in production environments without explicit written authorization and strict change window controls.

1. **Always Run `-Cleanup`:** Failing to clean up test artifacts leaves dummy persistence keys, test accounts, and registry entries that cause confusion in future investigations.
2. **Prevent Domain-Wide Impact:** When testing credential dumping (e.g. DCSync or Mimikatz), use isolated Active Directory test domains. Never execute live DCSync against production DCs during normal business hours without coordinating with IT and executive stakeholders.
3. **Differentiate Benign Test Alerts from Actual Threats:** Tag all automated test payloads with identifiable command markers (e.g., `-Comment "AtomicTest-RunID-8842"`), enabling the SOC to correlate alerts with planned test windows.

---

## 7. Self-test questions

1. What is the fundamental difference between an annual Red Team assessment and a continuous Purple Team exercise?
2. What are the four levels of the Detection Efficacy Scoring ladder?
3. What is the purpose of the `-CheckPrereqs` and `-Cleanup` flags in `Invoke-AtomicRedTeam`?
4. If a malicious scheduled task is created but no Event ID 4698 appears in the SIEM, which two audit policies should you verify?
5. How does a Detection-as-Code CI/CD pipeline prevent regression in SOC alerting capabilities?
6. Why should test payloads include a unique tracking comment or execution ID?

---

## 8. One-page revision checklist

- [ ] Purple Teaming: Collaborative feedback loop between Red (emulation) and Blue (detection/response).
- [ ] Scoring ladder: Level 0 (Blind) → Level 1 (Logged) → Level 2 (Detected) → Level 3 (Blocked).
- [ ] Atomic Red Team: Open-source, YAML-based scripted TTPs mapped directly to MITRE ATT&CK.
- [ ] `Invoke-AtomicTest`: Syntax, `-ShowDetails`, `-CheckPrereqs`, execution, `-Cleanup`.
- [ ] Verification steps: Confirm raw telemetry on endpoint → verify SIEM ingestion → check alert rule firing.
- [ ] Detection-as-Code: Version control for rules (Git), automated testing in CI/CD pipeline before production release.
- [ ] Operational safety: Strict authorization, lab/staging execution first, mandatory artifact cleanup.

---

> **Navigation:** [Roadmap index](../README.md) · [← SOAR](SOAR.md) · [Practice / Section 10 →](../10%20-%20Practice/TryHackMe.md)
