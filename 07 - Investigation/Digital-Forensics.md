# Digital Forensics & Host Artifacts — SOC Analyst Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← Log Analysis](Log-Analysis.md) · [Timeline Analysis →](Timeline-Analysis.md)

> Goal: Master the extraction, parsing, and interpretation of host-based forensic artifacts on Windows and Linux endpoints to reconstruct attacker actions even when event logs have been cleared or tampered with.
> Related notes: [Log-Analysis.md](Log-Analysis.md); [Timeline-Analysis.md](Timeline-Analysis.md); [02 - Operating Systems/File-Systems.md](../02%20-%20Operating%20Systems/File-Systems.md); [02 - Operating Systems/Processes.md](../02%20-%20Operating%20Systems/Processes.md).

---

## 0. How to use this note

1. §1–§2: The role of DFIR in SOC operations and the order of volatility.
2. §3–§5: Windows program execution artifacts (Prefetch, Shimcache, Amcache, SRUM).
3. §6–§7: File opening, folder access & persistence artifacts (LNK, Shellbags, Jumplists, USN Journal, $MFT).
4. §8–§9: Memory forensics (Volatility) and forensic triage collection (KAPE, Velociraptor).
5. §10–§12: Practical correlation scenarios, self-test questions, and revision checklist.

---

## 1. DFIR in the SOC & Order of Volatility

When an attacker clears event logs (`wevtutil cl System`, `wevtutil cl Security`) or disables logging, host-level forensic artifacts left behind by the operating system kernel provide undeniable evidence of execution and interaction.

### RFC 3227: Order of Volatility (Preserve Fastest Dying First)

```
1. CPU Registers & Cache                   (Nanoseconds — lost on power disruption)
      │
2. Volatile Memory (RAM)                   (Seconds to hours — contains plaintext creds, unbacked code)
      │
3. Network State & Active Connections      (Active sockets, routing tables, ARP cache)
      │
4. Running Processes & Kernel Data         (Process tree, loaded DLLs, open handles)
      │
5. Disk Storage / File Systems             (Persistent — MFT, registry hives, logs)
      │
6. Remote / Centralized Backups & Archives (Permanent)
```

---

## 2. Windows Program Execution Artifacts

These artifacts prove that an application was executed on a system, even if the executable file was deleted.

| Artifact | Location | What It Proves | Forensic Utility |
|---|---|---|---|
| **Prefetch (`.pf`)** | `C:\Windows\Prefetch\` | Executable ran, run count, last 8 run timestamps, loaded DLLs and file paths. | Created by Windows Memory Manager to optimize boot/launch times. Preserves execution history up to 1,024 files on Win 10/11. |
| **Shimcache (AppCompatCache)** | `SYSTEM` registry hive (`...Control\Session Manager\AppCompatCache`) | File existence, full path, file size, last modified time, execution flag. | Tracks application compatibility. Written to registry on clean reboot/shutdown. |
| **Amcache** | `C:\Windows\appcompat\Programs\Amcache.hve` | SHA-1 hash of executed binary, compile time, full path, installation timestamps. | Critical for identifying renamed malicious binaries by file hash. |
| **SRUM (System Resource Usage Monitor)** | `C:\Windows\System32\sru\SRUDB.dat` | Bytes uploaded/downloaded per process, CPU cycles, execution duration over past 30 days. | Proves data exfiltration volumes for specific executables (e.g., `rclone.exe`). |

### 2.1 Prefetch Analysis
- Windows names prefetch files as: `<EXECUTABLE_NAME>-<HASH>.pf` (e.g. `MIMIKATZ.EXE-B4A1D9C2.pf`).
- Parsing tools: `PECmd.exe` (Eric Zimmerman tool).
- Output reveals: First run time, last run time, run counter, and all files/directories referenced by the executable within its first 10 seconds of execution.

```cmd
# Command line: Parse prefetch directory to CSV using Eric Zimmerman's PECmd
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Analysis\Prefetch_Parsed"
```

### 2.2 Amcache: Finding Malicious File Hashes
- Even if an attacker executes malware named `svchost.exe` from a temp folder and deletes it, Amcache records the SHA-1 hash of the file.
- Parsing tools: `AmcacheParser.exe`.

```cmd
AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv "C:\Analysis\Amcache_Parsed"
```

---

## 3. File & Folder Interaction Artifacts

Proves whether an attacker opened, viewed, or interacted with specific confidential documents, directories, or drives.

### 3.1 Shellbags
- **Location:** `NTUSER.DAT` and `UsrClass.dat` registry hives.
- **What it proves:** GUI folder browsing activity. Records directory names, folder positions, and access dates through Windows Explorer — **even for deleted folders, mapped network shares, or mounted USB drives**.
- **Tool:** `SBECmd.exe` (ShellBags Explorer Command line).

### 3.2 Shortcut (LNK) Files & Jump Lists
- **LNK Files:** Automatically created in `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Recent\` when a user opens a local or remote file.
  - Contains: Target file path, creation/access dates, volume serial number, and target machine MAC address.
- **Jump Lists:** Taskbar recent files list (`AutoDestinations` and `CustomDestinations`). Shows files pinned or recently opened per application.

---

## 4. File System Forensics: The \$MFT and USN Journal

When an attacker downloads tools, stages archives, and deletes them, the underlying NTFS filesystem preserves the transaction records:

```
[Attacker creates staging folder] ──► $MFT Record created ($STANDARD_INFORMATION, $FILE_NAME)
                                   └── USN Journal entry: FILE_CREATE
[Attacker zips sensitive PII]     ──► USN Journal entry: DATA_OVERWRITE / EXTEND
[Attacker deletes tools & logs]   ──► USN Journal entry: FILE_DELETE
                                   └── $MFT Record marked as "unallocated" (content still recoverable!)
```

### 4.1 Master File Table (\$MFT)
- Contains an entry for every file and directory on an NTFS volume.
- Each record holds attributes:
  - `$STANDARD_INFORMATION` ($SI): Timestamps displayed by Windows Explorer. Susceptible to **timestomping**.
  - `$FILE_NAME` ($FN): Timestamps updated only by the Windows kernel. **Immune to user-mode timestomping**.
- **Timestomp Detection:** If `$SI` timestamp is older than `$FN` timestamp, timestomping occurred!

### 4.2 USN Journal (\$UsnJrnl:\$J)
- High-volume transaction log tracking every creation, modification, renaming, and deletion of files.
- Invaluable for detecting ransomware mass file modifications or anti-forensic wiping scripts.

---

## 5. Memory Forensics with Volatility 3

Memory analysis allows detection of unbacked executable memory, injected threads, rootkits, and active network connections.

| Volatility 3 Plugin | Purpose | What to Look For |
|---|---|---|
| `windows.pslist` | Walks the active EPROCESS process link list. | Standard process hierarchy. |
| `windows.psscan` | Scans memory pool allocations for unlinked processes. | Hidden processes unlinked by rootkits (DKOM). |
| `windows.pstree` | Displays visual parent-child process tree. | Anomalous parentage (e.g., `cmd.exe` spawned by `spoolsv.exe`). |
| `windows.netscan` | Scans memory for TCP/UDP endpoints and sockets. | Active C2 connections, established connections to external IPs. |
| `windows.malfind` | Scans for memory pages with `PAGE_EXECUTE_READWRITE` (RWX) without file backing. | Injected DLLs, Cobalt Strike beacons, Process Hollowing. |
| `windows.cmdline` | Extracts process command-line arguments. | Obfuscated PowerShell commands, dumped credentials flags. |

```bash
# Basic Volatility 3 triage execution
python3 vol.py -f memory.raw windows.pstree
python3 vol.py -f memory.raw windows.malfind
python3 vol.py -f memory.raw windows.netscan
```

---

## 6. Fast Forensic Triage Collection: KAPE & Velociraptor

In modern enterprise incidents, acquiring a full 1 TB disk image takes hours. **Triage collection** gathers only critical forensic artifacts (Prefetch, MFT, Registry, SRUM, Event logs) in under 5 minutes.

### 6.1 KAPE (Kroll Artifact Parser and Extractor)
- Uses `.kape` targets to copy locked system files using raw disk access (Volume Shadow Copy).
- Modules parse the raw artifacts directly into structured CSV/JSON.

```cmd
# Execute KAPE to collect Essential Windows Triage Artifacts
kape.exe --tsource C: --tdest D:\TriageOutput --target KapeTriage --gui false
```

### 6.2 Velociraptor
- Endpoint monitoring and incident response tool.
- Uses VQL (Velociraptor Query Language) to query thousands of endpoints simultaneously across an enterprise:
  - Query Prefetch across 5,000 machines in 60 seconds to find where a specific hash executed.
  - Hunt for persistence keys across all endpoints remotely.

---

## 7. Practical Correlation Scenario

**Scenario:** SIEM alert indicates Defender was disabled on host `FINANCE-WS01`. However, all Windows Security Event Logs have been cleared.

1. **Step 1: Collect Triage Package:** Run KAPE against `FINANCE-WS01`.
2. **Step 2: Check Prefetch:** Parse `C:\Windows\Prefetch`. Found `WEVTUTIL.EXE-<hash>.pf` with execution timestamp matching the alert time. Found `RCLONE.EXE-<hash>.pf` executed 10 minutes prior.
3. **Step 3: Check Amcache:** Extract SHA-1 hash for `RCLONE.EXE`. Hash matches known exfiltration binary.
4. **Step 4: Check SRUM:** Open `SRUDB.dat`. Locate `rclone.exe` under Network Usage table: proves 14.8 GB of outbound data was transmitted over port 443.
5. **Step 5: Check USN Journal:** Found records of `.zip` files created in `C:\Users\Public\Music\` containing financial spreadsheets, followed by `FILE_DELETE`.
6. **Verdict:** Confirmed data exfiltration incident with anti-forensic log wiping. True Positive.

---

## 8. Self-test questions

1. What is the order of volatility according to RFC 3227, and why does it dictate live response sequence?
2. How does comparing `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps in the `$MFT` reveal timestomping?
3. Which artifact proves the volume of network bytes exfiltrated by a specific process over the last 30 days?
4. What information does Amcache preserve that is invaluable when an attacker renames a malicious executable?
5. Why are Shellbags uniquely valuable during an investigation involving unauthorized USB storage devices?
6. What is the primary purpose of Volatility's `malfind` plugin?
7. What is the operational advantage of KAPE triage collection over traditional dead-box full disk imaging?

---

## 9. One-page revision checklist

- [ ] Order of volatility: Registers/Cache → RAM → Network State → Process list → Disk/MFT → Backup.
- [ ] Prefetch (`.pf`): `C:\Windows\Prefetch`, execution proof, run count, last 8 run times, loaded DLLs.
- [ ] Shimcache: `AppCompatCache` in `SYSTEM` hive; path, size, last mod time, executed flag.
- [ ] Amcache: `Amcache.hve`, records SHA-1 file hash of executed binaries and compile times.
- [ ] SRUM: `SRUDB.dat`, historical 30-day process resource usage (network bytes sent/received, CPU).
- [ ] Shellbags: `NTUSER.DAT` / `UsrClass.dat`, folder browsing history, proves access to deleted/USB folders.
- [ ] LNK & JumpLists: Recent files opened, volume serial, target path, original file timestamps.
- [ ] NTFS: `$MFT` ($SI vs $FN timestomping check), USN Journal (file creation/deletion transaction history).
- [ ] Memory: Volatility (`pstree`, `malfind` for RWX unbacked code, `netscan` for active C2 sockets).
- [ ] Triage tools: KAPE (targeted artifact extraction), Velociraptor (enterprise VQL endpoint hunting).

---

> **Navigation:** [Roadmap index](../README.md) · [← Log Analysis](Log-Analysis.md) · [Timeline Analysis →](Timeline-Analysis.md)
