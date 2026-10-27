# Ransomware Incident Response Playbook — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Containment](Containment.md) · [Eradication →](Eradication.md)

> Goal: Master the operational triage, emergency containment, forensic preservation, and recovery orchestration for enterprise ransomware and double-extortion attacks.
> Related notes: [Containment.md](Containment.md); [Eradication.md](Eradication.md); [Recovery.md](Recovery.md); [06 - Threat Detection/Malware.md](../06%20-%20Threat%20Detection/Malware.md); [07 - Investigation/Timeline-Analysis.md](../07%20-%20Investigation/Timeline-Analysis.md).

---

## 0. How to use this note

1. §1–§2: The modern Ransomware-as-a-Service (RaaS) anatomy and double/triple extortion models.
2. §3–§4: Pre-encryption attack indicators (the critical window to stop ransomware).
3. §5–§7: Emergency containment ladder, network isolation procedures, and evidence preservation.
4. §8–§10: Triage queries (SPL/KQL), eradication, decryptor validation, and crisis communications.
5. §11–§13: Real-world tabletop scenario, self-test questions, and revision checklist.

---

## 1. The RaaS ecosystem & extortion models

Modern ransomware is rarely the work of a single lone hacker; it operates as an enterprise business model known as **Ransomware-as-a-Service (RaaS)**:

```
[Initial Access Broker (IAB)]
   │  (Sells VPN creds, RDP footholds, unpatched CVE web exploits)
   ▼
[RaaS Core Operator / Cartel (e.g., LockBit, BlackCat/ALPHV, Akira)]
   │  (Maintains malware builder, leak site, and negotiation infrastructure)
   ▼
[Affiliate (The Attacker inside your network)]
   │  (Performs AD recon, credential dumping, data exfiltration, deployment)
   ▼
[Target Enterprise Network]
```

### Extortion Tiers

| Extortion Tier | Mechanism | Attacker Leverage |
|---|---|---|
| **Single Extortion** | Bulk encryption of files on endpoints and servers (`.locked`, `.crypted`). | Denies operational access to data. Recoverable if offline immutable backups exist. |
| **Double Extortion** | Pre-encryption data theft and exfiltration (customer PII, financial, source code). | Threatens public release on Dark Web leak sites even if victim restores from backup. |
| **Triple Extortion** | Direct harassment of customers, regulatory reporting, or DDoS against corporate web assets. | Maximizes executive panic, public relations fallout, and regulatory penalties. |

---

## 2. Pre-encryption vs Execution: The Critical Window

The most critical realization for a SOC analyst is that **encryption is the very last step** of an attack that typically took days or weeks.

```
Initial Access ──► Recon / AD Enum ──► Credential Access ──► Data Staging & Exfil ──► Defense Evasion & Backup Kill ──► Mass Encryption
[Day 0]             [Day 1–3]          [Day 3–5]             [Day 5–7]                 [Hour 0: Pre-detonation]            [Detonation]
                                                                                       ▲
                                                                                       │
                                                                   LAST CHANCE TO PREVENT OUTAGE!
```

### Red Flag Pre-detonation Behaviors (Hours/Minutes Before Encryption)
1. **Disabling Security Tools & Defender:**
   - PowerShell: `Set-MpPreference -DisableRealtimeMonitoring $true`
   - Service stoppage: Stopping `WinDefend`, `Sophos`, `SentinelAgent`, `CarbonBlack`.
2. **Shadow Copy & Backup Destruction:**
   - `vssadmin.exe delete shadows /all /quiet`
   - `wmic shadowcopy delete`
   - `wbadmin delete catalog -quiet`
   - `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures`
   - `bcdedit.exe /set {default} recoveryenabled no`
3. **Mass Storage Mounts & PsExec Distribution:**
   - Rapid execution of batch scripts or Group Policy Objects (GPO) pushing binaries across `SYSVOL`.

---

## 3. SIEM Detection Queries

```spl
# Splunk: Detect Volume Shadow Copy Deletion (T1490)
index=windows EventCode=4688
| where match(lower(CommandLine), "(vssadmin.*delete\s+shadows|wmic.*shadowcopy\s+delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled\s+no)")
| table _time, Computer, NewProcessName, CommandLine, SubjectUserName
```

```kusto
// KQL: Detect Ransomware Mass File Renaming / High Velocity I/O on Endpoints
DeviceFileEvents
| where ActionType in ("FileRenamed", "FileCreated")
| where FileName has_any (".locked", ".crypto", ".enc", ".crypted", "README.txt", "DECRYPT_FILES.txt")
| summarize RenamedCount = count(), UniqueExtensions = dcount(FileName) by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 5m)
| where RenamedCount > 100
```

```spl
# Splunk: Detect Cloud Storage Data Exfiltration tools (Rclone, MegaSync, FileZilla)
index=windows EventCode=4688
| where match(lower(NewProcessName), "(rclone|megasync|filezilla|putty|winscp)\.exe")
| table _time, Computer, NewProcessName, CommandLine, SubjectUserName
```

---

## 4. The Emergency Containment Ladder

When active ransomware detonation is suspected or underway, seconds matter. Follow this progressive containment escalation:

```
[Level 1: Host-level Isolation]
  • Trigger EDR Network Isolation (isolates host from LAN/WAN while keeping EDR cloud link alive).
  • If EDR unresponsive: Pull physical Ethernet cable or disconnect Wi-Fi. DO NOT POWER OFF!

[Level 2: Network Segmentation & Perimeter Cut]
  • Sever internal site-to-site VPNs and SD-WAN links to branch offices to stop lateral spread.
  • Block outbound traffic to known cloud exfiltration endpoints (Mega.nz, Dropbox, external SFTP).
  • Isolate Domain Controllers (DCs) and Hypervisors (VMware ESXi / Hyper-V).

[Level 3: Identity Lockdown]
  • Disable compromised administrative accounts and Service Accounts.
  • Block incoming remote management protocols (SMB 445, RDP 3389, WinRM 5985/5986) at core firewalls.
  • Temporarily disable Entra ID / Okta cloud sync if on-prem DC compromise is suspected.

[Level 4: "Glass-Break" Full Isolation]
  • In catastrophic outbreaks: Disconnect main datacenter core switches from the network.
```

> [!WARNING]
> **DO NOT REBOOT OR POWER OFF INFECTED MACHINES!**
> Powering off a machine destroys volatile RAM evidence, unallocated encryption keys held in memory, and running process trees. Use EDR isolation or pull the physical network cable.

---

## 5. Triage & Evidence Preservation

Before wiping or reimaging compromised assets, preserve the critical evidentiary artifacts:

1. **Volatile Memory (RAM):**
   - Acquire full memory dump using `WinPmem`, `DumpIt`, or hypervisor snapshot.
   - Some ransomware strains store decryption keys in volatile memory before terminating.
2. **Encrypted Sample + Extortion Note:**
   - Save copies of the ransom note (`HOW_TO_DECRYPT.txt`, `README.txt`).
   - Collect 2–3 pairs of original files vs encrypted files for cryptographic analysis.
3. **Malware Binary & Dropper:**
   - Capture the encryptor binary (e.g. from `C:\Windows\Temp\` or `C:\Users\Public\`).
   - Extract SHA-256 hash and submit to internal sandbox or VirusTotal.
4. **Identify Ransomware Family:**
   - Upload ransom note and sample encrypted file to [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) or No More Ransom project.
   - Check if a free public decryptor exists before considering any other course.

---

## 6. Eradication & Clean Rebuild

1. **Locate Ground Zero (Patient Zero):**
   - Determine how the affiliate breached the perimeter (VPN log review, unpatched Edge device, phishing email).
   - Trace lateral movement from the initial host to the distribution server (GPO/PsExec/SCCM).
2. **Eliminate Persistence Mechanisms:**
   - Audit all Active Directory Scheduled Tasks, Group Policy Objects, and WMI event subscriptions.
   - Look for web shells on DMZ servers and rogue administrative accounts created in AD.
   - Perform a mandatory **two-stage `krbtgt` password reset**.
3. **Backup Integrity Validation:**
   - Do NOT plug offline backup drives into the infected network!
   - Verify that backups were not accessed, modified, or poisoned by the threat actor prior to encryption.
   - Restore systems into an isolated, segregated "clean-room" VLAN for inspection before reconnecting to production.

---

## 7. Crisis Communications & Negotiation Governance

- **Out-of-Band Communications:** Assume all corporate email (Exchange/M365), internal Teams, and Slack channels are monitored by the attacker. Use external, out-of-band communication (Signal, personal phones).
- **Involve Legal & Cyber Insurance Immediately:**
  - Cyber insurance carriers mandate specific approved incident response firms and breach counsel.
  - Legal counsel establishes attorney-client privilege over technical investigative reports.
- **Ransom Payments:**
  - Payment should always be the absolute last resort.
  - Paying ransoms does not guarantee decryption keys will work (flawed decryptors frequently corrupt databases).
  - May violate OFAC sanctions if the RaaS group is designated on financial blacklist entities.

---

## 8. Real-world Tabletop Scenario

**Scenario:** It is Saturday at 02:00 AM. SIEM triggers a High alert: 15 Domain Controllers and file servers report Event ID 4688 with `vssadmin delete shadows /all /quiet`. Minutes later, EDR alerts on multiple hosts creating files with extension `.akira`.

* **Phase 1 (0–15 min):** On-duty analyst initiates Level 1 & 2 containment. Immediately isolate file servers and hypervisors via EDR. Sever cross-datacenter VPN tunnels. Page the Incident Commander and IR lead.
* **Phase 2 (15–60 min):** Identify distribution source. Discover Domain Admin account compromised; PsExec used to push `update.exe` from internal staging server `10.10.40.15`. Block account in AD.
* **Phase 3 (1–4 hrs):** Memory capture from staging host. Collect encrypted samples and note. Verify integrity of immutable tape/cloud backups.
* **Phase 4 (Recovery):** Rebuild DCs from clean media. Restore data onto newly imaged servers in quarantined recovery network.

---

## 9. Self-test questions

1. Why do ransomware operators wait until the very end of their intrusion to execute the encryption binary?
2. What command-line utilities do attackers commonly use to delete Volume Shadow Copies and recovery boot options?
3. Why is powering off an endpoint during active ransomware detonation considered a major mistake?
4. What is the difference between double extortion and triple extortion?
5. How can a SOC detect data staging and exfiltration prior to ransomware detonation?
6. What public community resource helps identify ransomware families and provides verified decryptor tools?
7. Why is out-of-band communication required during a major enterprise ransomware incident?

---

## 10. One-page revision checklist

- [ ] RaaS structure: Operator (infrastructure/code) vs Affiliate (hands-on-keyboard intrusion) vs IAB (initial access).
- [ ] Critical pre-encryption indicators: `vssadmin delete shadows`, `Set-MpPreference -DisableRealtimeMonitoring`, stopping services, staging via Rclone/Mega.
- [ ] Immediate containment: EDR network isolation, sever site-to-site VPNs, isolate DCs and backups; **never power off**.
- [ ] Identification: Ransom note, extension pattern, ID Ransomware submission, file hashes.
- [ ] Preservation: Volatile memory dump (RAM), sample encrypted files + note, web server & VPN logs.
- [ ] Communications: Out-of-band channels (Signal/voice); engage legal counsel and cyber insurer immediately.
- [ ] Restoration: Validate backup immutability; rebuild in segregated staging VLAN before connecting to production.

---

> **Navigation:** [Roadmap index](../README.md) · [← Containment](Containment.md) · [Eradication →](Eradication.md)
