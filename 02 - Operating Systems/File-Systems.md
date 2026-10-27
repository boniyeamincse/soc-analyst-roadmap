# File Systems — SOC Analyst Study Notes

> Goal: understand how files are stored, timestamped, altered, and deleted — so you can **investigate ransomware, data staging/exfil, persistence, timestomping, USB activity, and deleted-file recovery** from host and share telemetry.
> Permissions/ACLs → `Permissions.md`; OS internals → `Linux.md` / `Windows.md`; Windows event IDs → `Windows-Event-Logs.md`.

---

## 0. How to use this note

1. §1–§3: why file systems matter, core concepts, partitioning/volumes.
2. §4–§8: NTFS, FAT/exFAT/ReFS, Linux, macOS/APFS, network/cloud storage.
3. §9–§11: forensic artifacts, ransomware/exfil patterns, detection telemetry.
4. §12–§15: detections, investigation, triage, commands.
5. §16–§18: false positives, hardening, labs, self-test, revision.

---

## 1. Why file systems matter to a SOC analyst

- **Every intrusion leaves file-system traces**: droppers, payloads, scripts, archives, ransom notes, staged data.
- **Ransomware is a file-system event**: mass encryption, extension changes, note creation, shadow-copy deletion.
- **Exfiltration usually starts with staging**: archives in temp directories, cloud-sync folders, USB copies.
- **Persistence lives on disk**: services, scheduled tasks, startup folders, cron, `authorized_keys`, web shells.
- **Timestamps are evidence** — and attackers forge them (timestomping).
- **File shares** (SMB/NFS) are both a lateral-movement path and a data-loss path.

**SOC outcomes:** given file events you can answer:
- What was created/modified/deleted, where, by which process/user?
- When — and do timestamps agree across sources?
- Is this file type/name/location normal for that host?
- Was data staged, archived, copied to USB, or synced to cloud?
- Was the file deleted/renamed to hide activity?
- What should be preserved before remediation?

---

## 2. Core concepts

| Concept | Meaning | SOC/DFIR note |
|---|---|---|
| **Block/cluster** | Smallest allocation unit (often 4 KB) | Slack space can hold old data. |
| **Inode (Unix)** | Metadata record for a file | Stores permissions, size, timestamps, block pointers — not the name. |
| **MFT record (NTFS)** | Metadata record (default 1 KB) | Central artifact; `$MFT` is the file-system index. |
| **Directory entry** | Name → inode/MFT mapping | Renames change the directory entry. |
| **Journal** | Metadata transaction log | Enables recovery/consistency; forensic gold. |
| **CoW (copy-on-write)** | Write new blocks, then update pointer | Snapshots/clones; APFS/Btrfs/ZFS. |
| **Extent** | Contiguous block range | Reduces fragmentation metadata. |
| **Sparse file** | Holes read as zeros | Can hide data/size anomalies. |
| **Compression/dedup** | Stored differently than logical content | Affects carving and hashing. |
| **Encryption (BitLocker/LUKS/FileVault)** | Volume or file encryption | Without keys, limited analysis; escrow matters. |
| **Mount point** | Where a FS attaches | `C:\`, `/`, `/mnt/usb`. |
| **Volume/partition** | Addressable storage region | MBR (legacy) vs GPT. |
| **Allocated/unallocated** | In-use vs free space | Deleted data often recoverable until overwritten. |
| **Slack space** | Unused bytes in last cluster | Can retain prior file content. |
| **Hard link** | Multiple names → same inode | Deleting one name doesn't delete data. |
| **Symlink/junction** | Reference to another path | Abuse for redirection/persistence. |
| **Alternate data stream (ADS)** | Extra NTFS data stream | Hides payloads; `Zone.Identifier`. |
| **Extended attributes (xattr)** | Name/value metadata | Quarantine flags, capabilities, SELinux labels. |

### 2.1 Timestamps: MACB

| Letter | Timestamp | Meaning |
|---|---|---|
| **M** | Modified | Content changed. |
| **A** | Accessed | Read/opened (may be disabled/relatime). |
| **C** | Changed (MFT entry change) | Metadata changed (permissions, rename). |
| **B** | Birth/Created | File creation. |

Windows NTFS has **two sets** of timestamps:
- **`$STANDARD_INFORMATION` (0x10)** — user-visible, easily modified (timestomping).
- **`$FILE_NAME` (0x30)** — directory entry, updated on rename/move; harder to forge.

Linux surfaces `mtime`, `atime`, `ctime`, and (on some FS) `btime` via `statx`. **`ctime` is not creation time** on Unix — it is inode-change time.

---

## 3. Partitioning, volumes, and storage layers

| Layer | Examples | Notes |
|---|---|---|
| **Disk** | HDD, SSD, NVMe | Image the whole disk, not just files. |
| **Partition table** | MBR (4 primary, 2 TiB limit), GPT (128 partitions, 9.4 ZiB) | GPT is modern; protective MBR. |
| **Partition** | Windows `C:`, Linux `/dev/sda1` | Contains a file system. |
| **Volume manager** | LVM (Linux), Storage Spaces (Windows), RAID | Logical volumes may span disks. |
| **File system** | NTFS, ext4, APFS | What the OS mounts. |
| **Encryption** | BitLocker, LUKS, FileVault | Needs key/recovery key. |
| **Container/overlay** | overlayfs, Docker layers | Changes in writable layer. |
| **Network/cloud** | SMB, NFS, S3, OneDrive | Different artifacts; provider logs. |

**Imaging rule:** capture the **whole disk/volume** (bit-for-bit) with a **write blocker**, hash before and after, and document the chain of custody. Never boot a suspect disk normally.

---

## 4. NTFS (Windows)

### 4.1 Structure

- **$MFT** — Master File Table; one record per file/directory (plus system files).
- **System metadata files** (all start with `$`):
  - `$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef`, `$Bitmap`, `$Boot`, `$BadClus`, `$Secure`, `$UpCase`, `$Extend`.
  - `$Extend\$UsnJrnl` (`:$J` change journal, `:$Max`), `$Extend\$Quota`, `$Extend\$ObjId`, `$Extend\$Reparse`.
- **Attributes** — `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA` (content; can be resident if small), `$ATTRIBUTE_LIST`, `$SECURITY_DESCRIPTOR`, `$INDEX_ROOT`, `$INDEX_ALLOCATION`, `$BITMAP`, `$REPARSE_POINT`, `$EA`.
- **Resident vs non-resident** — small data stored inside the MFT record; large data in clusters.
- **Cluster size** default 4 KB; **MFT record** default 1 KB.

### 4.2 Alternate Data Streams (ADS)

- `file.txt:secret` is an extra stream on `file.txt`.
- **`Zone.Identifier`** — Mark-of-the-Web from downloads; shows source URL/zone.
- **Abuse:** hide executables/payloads, bypass naive scanners, store config.
- **Detection:** `dir /r`, PowerShell `Get-Item -Stream *`, Sysmon Event **15** (`FileCreateStreamHash`).

### 4.3 NTFS timestamps and tunnelling

- Both `$SI` and `$FN` store MACB times.
- **Timestomping** — attacker sets creation/modified times via API/tools (`SetFileTime`, PowerShell, `timestomp`). Usually alters `$SI` but not `$FN`.
- **Detection:** `$SI` vs `$FN` mismatch, sub-second precision zeroed to `:00`, creation before volume creation, timestamps inconsistent with `$USN`/`$LogFile`.
- **Tunnelling** — legacy behaviour: renaming/recreating a file with the same name within ~15 s can inherit the old creation time (forensic caveat).

### 4.4 Change journal and logs

| Artifact | What it records | Use |
|---|---|---|
| **`$UsnJrnl:$J`** | File create/delete/rename/metadata changes with reasons and timestamps | Timeline, deleted-file names, ransomware bursts. |
| **`$LogFile`** | Metadata transactions (low-level) | Recover recent metadata changes. |
| **`$Secure`** | Security descriptors | Permission changes. |
| **`$Bitmap`** | Allocated clusters | Deleted-space analysis. |
| **`$Recycle.Bin`** | `$I` (original path/metadata) + `$R` (content) | Deleted files, user attribution. |
| **`$MFT`** | All file metadata | Primary timeline source. |
| **VSS** | Point-in-time snapshots | Compare before/after; ransomware deletes them. |

Parse with **Eric Zimmerman tools** (`MFTECmd`, `PECmd`, `RBCmd`, `JLECmd`, `LECmd`), **TSK** (`fls`, `icat`), **Autopsy**, **Plaso**. (Execution artifacts like Prefetch/AmCache belong to `Windows.md`.)

### 4.5 NTFS features with security impact

| Feature | Impact |
|---|---|
| **Junctions/symlinks** | Redirect paths; persistence/evasion. |
| **Hard links** | Same data, multiple names; malware hiding. |
| **Sparse/compressed files** | Size anomalies; reduced forensic fidelity. |
| **EFS** | Per-file encryption; recovery agent matters. |
| **BitLocker** | Full-volume encryption; recovery key escrow. |
| **Data Deduplication** | Chunked storage; hashing/carving complications. |
| **Object IDs** | Track files across moves; `$ObjId`. |
| **USN** | Change history (if enabled and not wrapped). |

---

## 5. FAT, exFAT, and ReFS

| FS | Traits | SOC notes |
|---|---|---|
| **FAT12/16/32** | Simple, no journal, no permissions; FAT32 4 GiB file limit | USB/SD cards, firmware; timestamps in local time (no UTC); deleted entries recoverable. |
| **exFAT** | Large files/volumes, no journal, no permissions | Common on removable media; minimal metadata. |
| **ReFS** | Resilient, CoW-ish, integrity streams, block cloning | Server/storage; **does not support all NTFS features** (e.g. named streams/ADS, compression, EFS) — verify version; different forensic tooling. |

**Removable media:** FAT/exFAT timestamps can be affected by time-zone and by the writing OS; treat with caution.

---

## 6. Linux file systems

### 6.1 Common file systems

| FS | Traits | Forensic notes |
|---|---|---|
| **ext2** | No journal | Simple; deletion recovery easier. |
| **ext3** | Journal | Metadata consistency. |
| **ext4** | Journal, extents, delayed allocation, 64-bit, dir_index | Default for years; `debugfs`, `extundelete`; `crtime` via `statx`. |
| **XFS** | Journaling, extents, high performance | No undelete tooling comparable to ext; `xfs_db`; metadata in `xfs_repair`. |
| **Btrfs** | CoW, snapshots, subvolumes, checksums | Snapshots can preserve pre-encryption state; `btrfs restore`. |
| **ZFS** | CoW, checksums, snapshots, pools | Snapshots/`zfs send`; strong integrity. |
| **tmpfs** | RAM-backed | Volatile; evidence lost on reboot. |
| **procfs/sysfs** | Kernel interfaces | Not disk files; live-response sources. |
| **overlayfs** | Layered container FS | Changes in upper layer; image layers read-only. |
| **squashfs** | Compressed read-only | Firmware/containers; carve carefully. |
| **NFS/CIFS** | Network mounts | Server-side artifacts; client cache. |

### 6.2 Linux metadata and artifacts

- **inode** — `ls -li`, `stat`, `debugfs -R "stat <inode>"`.
- **timestamps** — `mtime`, `atime`, `ctime`, `crtime` (if supported); `relatime`/`noatime` affect `atime` reliability.
- **permissions** — mode bits, ACLs (`getfacl`), xattrs (`getfattr`), capabilities (`getcap`).
- **immutable/append-only** — `chattr +i/+a`; attackers use for persistence.
- **hidden files** — dotfiles, names with spaces/newlines, unicode tricks.
- **`/tmp`, `/var/tmp`, `/dev/shm`, `/run`** — common malware staging; `/dev/shm` is RAM-backed.
- **`/etc/passwd`, `/etc/shadow`** — accounts; unusual UID 0 accounts.
- **`~/.ssh/authorized_keys`** — persistence.
- **cron/systemd** — `/etc/cron*`, `/var/spool/cron`, unit files.
- **shell history** — `.bash_history`, `.zsh_history`; often disabled/cleared by attackers.
- **logs** — `/var/log/` (syslog, auth, audit), journald.
- **deleted files** — ext4 journal, `extundelete`, `photorec`, `debugfs`; overwritten data unrecoverable.

### 6.3 Linux deletion and recovery

- Deleting a file removes the directory entry; inode/data may persist until reused.
- **ext4** — `extundelete`, `debugfs`, `photorec`; stop writes immediately.
- **XFS** — recovery is limited; rely on backups/journal.
- **Btrfs/ZFS** — snapshots are the best recovery path.
- **LUKS** — need passphrase/key file; without it, no analysis.

---

## 7. macOS / APFS (brief)

- **APFS** — CoW, snapshots, clones, space sharing, per-volume encryption, 64-bit inodes.
- **HFS+** — legacy; journaled.
- **Extended attributes** — `xattr -l`; `com.apple.quarantine` marks downloaded files.
- **Resource forks / `.DS_Store`** — Finder metadata; can reveal paths.
- **Time Machine** — local snapshots/backups; `tmutil listlocalsnapshots`.
- **Unified log** — `log show` (not a file system, but key evidence).
- **FileVault** — full-disk encryption; recovery key escrow.

---

## 8. Network and cloud storage

### 8.1 SMB/CIFS shares

- File access over SMB generates **server-side** logs: Security **5140/5145** (share access), **4663** (object access, if auditing), **4656** (handle).
- Ransomware encrypts shares rapidly; watch for mass rename/write from one account/host.
- **Admin shares** (`C$`, `ADMIN$`, `IPC$`) — lateral movement; access is high-signal.
- **SMB signing/encryption** — protects integrity/confidentiality; logging still shows metadata.

### 8.2 NFS

- Exports in `/etc/exports`; weak `no_root_squash` = privilege risk.
- Server logs (often `/var/log/messages`, `nfsd`); client mounts reveal access.

### 8.3 Cloud object/file storage

| Service | Artifacts |
|---|---|
| **S3/GCS/Blob** | Object versioning, access logs, CloudTrail/Activity Log, lifecycle, MFA delete. |
| **OneDrive/SharePoint/Drive/Dropbox** | Version history, sync client logs, audit logs, sharing events. |
| **Cloud sync clients** | Local cache directories, sync logs, conflict files. |

**SOC note:** object storage has **no inodes/MACB semantics**. Use provider audit logs and versioning instead. Cloud sync is a common exfil path that bypasses network egress controls when clients use HTTPS to sanctioned providers.

---

## 9. Forensic artifacts by investigative question

| Question | Artifacts |
|---|---|
| What files existed? | `$MFT`, directory listings, USN, `$LogFile`, ext4 journal. |
| What was created/deleted? | USN journal, Sysmon 11/23/26, Audit 4663, `$Recycle.Bin`, extundelete. |
| What executed? | Prefetch, AmCache, ShimCache, SRUM, EDR (see `Windows.md`). |
| What was downloaded? | `Zone.Identifier` ADS, browser downloads, proxy logs. |
| What was staged? | Temp directories, archives, `$Recycle.Bin`, cloud sync folders. |
| What was copied to USB? | USBSTOR registry, `setupapi.dev.log`, Event 20001/20003, Sysmon device events. |
| Was time forged? | `$SI` vs `$FN`, sub-second zeros, USN mismatch, `$LogFile`. |
| What was encrypted? | Extension changes, ransom notes, entropy, VSS deletion, backup deletion. |
| What was shared? | 5140/5145, SMB client logs, NFS exports, cloud sharing audit. |
| What was hidden? | ADS, dotfiles, unicode names, alternate directories, rootkits. |

---

## 10. Ransomware and exfiltration patterns

### 10.1 Ransomware file-system indicators

- **Mass file modification/rename** in a short window (thousands of writes).
- **New extensions** (`.locky`, `.encrypted`, `.crypt`, random strings) or **no extension**.
- **Ransom notes** (`README.txt`, `HOW_TO_DECRYPT.txt`, `!README!`, HTML notes).
- **Deleted shadow copies** (`vssadmin delete shadows`, `wmic shadowcopy delete`, `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`).
- **Backup/recovery tampering** (`wbadmin delete catalog`, `bcdedit /set recoveryenabled No`, disabling services).
- **High disk I/O**, CPU spikes, file lock errors, users reporting inaccessible files.
- **Encrypted shares**: rapid write/rename on SMB shares from one host.
- **Canary files** trigger (honeytokens in shares).
- **Entropy** increase in modified files.

### 10.2 Exfiltration/staging indicators

- Archives created in temp/user dirs (`zip`, `rar`, `7z`, `tar.gz`), especially large/unusual.
- Data copied to `%TEMP%`, `C:\ProgramData`, `/tmp`, `/dev/shm`.
- **USB** copies of sensitive directories.
- **Cloud sync** of sensitive folders to personal accounts.
- **Email/web upload** of archives (proxy logs).
- **Rclone/rsync/scp** usage; cloud CLI tools.
- **Deleted staging files** after upload (USN/recycle bin).
- **Compression then deletion** within minutes.

---

## 11. Telemetry for file activity

| Source | What it gives | Gaps |
|---|---|---|
| **Sysmon** | Event 11 (create), 23 (delete), 26 (delete logged), 2 (time changed), 15 (ADS), 1 (process) | Requires deployment/tuning; 23 is archived-only. |
| **Windows Security** | 4663 object access, 4656 handle, 5140/5145 share access, 4907 audit policy change | Object auditing must be enabled; noisy. |
| **EDR** | File create/modify/rename/delete with process + user | Vendor-specific coverage. |
| **FIM** (Wazuh/OSSEC/Tripwire) | Integrity changes on monitored paths | Scope limited. |
| **Linux auditd** | `open`, `write`, `unlink`, `rename`, `execve` | Rules must be configured. |
| **File server logs** | SMB/NFS access | Metadata only. |
| **Cloud audit** | S3/CloudTrail, SharePoint/Drive events | Provider-dependent; retention. |
| **Backup/VSS** | Historical copies | Frequency/window. |
| **USN/MFT** (offline) | Full history | Not real-time; needs collection. |
| **DLP** | Sensitive data movement | Policy coverage. |

### 11.1 Key Sysmon events for file work

| Event | Name | Use |
|---|---|---|
| **2** | File creation time changed | Timestomping. |
| **11** | FileCreate | Droppers, payloads, notes, archives. |
| **15** | FileCreateStreamHash | ADS creation (incl. Zone.Identifier). |
| **23** | FileDelete (archived) | Deleted executables (if configured). |
| **26** | FileDelete (logged) | Deletion events. |
| **1** | ProcessCreate | Parent/child context. |

### 11.2 Linux auditd examples

```
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /root/.ssh -p wa -k ssh_keys
-w /tmp -p w -k tmp_write
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -k file_delete
```

> Audit rules are powerful but can flood logs; scope to sensitive paths and test volume.

---

## 12. Detection engineering

> Baseline file activity per role. A build server legitimately writes thousands of files; a receptionist PC does not.

### 12.1 High-signal ideas

1. **Ransomware extension burst** — many files renamed with the same odd extension.
2. **Ransom note creation** — known note filenames across multiple directories.
3. **Shadow copy deletion / recovery tampering**.
4. **Mass file modification** per host per minute.
5. **Archive creation in temp** by non-archive processes.
6. **Large archive + outbound transfer** correlation.
7. **USB copy** of sensitive paths.
8. **Cloud sync of sensitive folders** to personal accounts.
9. **ADS creation** — especially executable content or unusual streams.
10. **Timestomping** — Event 2, `$SI`/`$FN` mismatch.
11. **Files created in startup locations** (cross-ref `Windows.md`).
12. **Web shell writes into webroot** (`.php`, `.jsp`, `.aspx`) by web process.
13. **Executables in user temp/downloads** (`%TEMP%`, `%APPDATA%`, `/tmp`).
14. **Hidden/dotfile executables** or double extensions (`invoice.pdf.exe`).
15. **LNK/ISO/IMG/HTA** delivery files.
16. **Mass deletion** (anti-forensics).
17. **Permission changes** on sensitive files (cross-ref `Permissions.md`).
18. **SMB share mass writes** from one account.
19. **Reads of sensitive files** by unusual processes (credential hunting).
20. **Files matching threat-intel hashes** (hash reputation).

### 12.2 Splunk SPL examples

**Ransomware-like extension burst:**
```spl
index=sysmon EventCode=11
| eval ext=lower(mvindex(split(TargetFilename,"."), -1))
| stats count dc(TargetFilename) as files by Computer, ext
| where ext IN ("locky","encrypted","crypt","crypted","locked","wncry","ryuk","conti","babuk")
   OR (files > 500 AND len(ext) BETWEEN 5 AND 12)
| sort -files
```

**Ransom note creation:**
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(readme|how[_-]?to[_-]?decrypt|decrypt[_-]?instructions|restore[_-]?files|!readme!)")
| stats count values(TargetFilename) as notes by Computer
| where count > 1
```

**Shadow copy deletion:**
```spl
index=wineventlog (EventCode=4688 OR sourcetype=sysmon EventCode=1)
| where match(CommandLine, "(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|Get-WmiObject.*Win32_ShadowCopy|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no)")
| table _time, Computer, User, CommandLine
```

**Mass file writes per host:**
```spl
index=sysmon EventCode IN (11,2)
| bin _time span=1m
| stats count dc(TargetFilename) as files by Computer, _time
| where files > 1000
| sort -files
```

**Archives created in temp:**
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(\\Temp\\|\\AppData\\Local\\Temp\\|/tmp/|/dev/shm/)")
| where match(TargetFilename, "(?i)\.(zip|rar|7z|tar|gz|tgz|cab)$")
| table _time, Computer, User, Image, TargetFilename
```

**ADS creation:**
```spl
index=sysmon EventCode=15
| stats count values(TargetFilename) as streams by Computer, Image
| sort -count
```

**Timestomping:**
```spl
index=sysmon EventCode=2
| table _time, Computer, User, Image, TargetFilename, PreviousCreationUtcTime, CreationUtcTime
```

**Sensitive file reads (example with auditd/Sysmon FileRead if available):**
```spl
index=edr action=file_read
| where match(file_path, "(?i)(/etc/shadow|/etc/passwd|\.ssh/|NTDS\.dit|SAM|SECURITY|\.kdbx|\.pem|\.pfx)")
| stats count by host, user, process_name, file_path
```

**USB file copy (Defender/Sysmon device + file events):**
```spl
index=sysmon EventCode=11
| where match(TargetFilename, "^[A-Z]:\\")
| where NOT match(TargetFilename, "^C:")
| stats count by Computer, User, TargetFilename
```

### 12.3 Microsoft Sentinel / Defender KQL examples

**Ransomware-like file burst (DeviceFileEvents):**
```kusto
DeviceFileEvents
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| summarize Files = dcount(FileName), Count = count()
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 5m)
| where Files > 500
| order by Files desc
```

**Ransom note creation:**
```kusto
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)(readme|how[_-]?to[_-]?decrypt|decrypt[_-]?instructions|restore[_-]?files)"
| summarize Notes = count(), Paths = make_set(FolderPath, 5) by DeviceName
```

**Shadow copy deletion:**
```kusto
DeviceProcessEvents
| where ProcessCommandLine matches regex @"(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no)"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

**Sensitive file access by unusual process:**
```kusto
DeviceFileEvents
| where FolderPath has_any ("\\Windows\\NTDS", "\\Windows\\System32\\config", "\\.ssh", "\\Users\\")
| where FileName in ("NTDS.dit","SAM","SECURITY","id_rsa","id_ed25519")
| summarize Accesses = count() by DeviceName, InitiatingProcessFileName, FileName
| where Accesses > 0
```

**Archive staging then upload (requires network events):**
```kusto
let archives = DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)\.(zip|rar|7z|tar|gz)$"
| project DeviceName, ArchiveTime = TimeGenerated, ArchiveName = FileName;
DeviceNetworkEvents
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| join kind=inner archives on DeviceName
| where TimeGenerated between (ArchiveTime .. ArchiveTime + 30m)
| project DeviceName, ArchiveName, ArchiveTime, RemoteUrl, RemoteIP
```

**ADS creation (Defender may not expose all ADS; use Sysmon/EDR):**
```kusto
DeviceEvents
| where ActionType == "FileCreated"
| extend Stream = tostring(parse_json(AdditionalFields).StreamName)
| where isnotempty(Stream)
```

### 12.4 Sigma-style skeleton

```yaml
title: Ransomware Extension Burst
logsource:
  product: windows
  category: file_event
detection:
  selection:
    EventID: 11
  timeframe: 5m
  condition: selection | count(TargetFilename) by Computer > 500
level: high
```

---

## 13. Investigation workflow (step by step)

### Step 1 — Facts
- Time (UTC), host, user, process, file path, action, hash, size.
- Which detection fired.

### Step 2 — Preserve
- Stop destructive actions; capture memory if malware suspected (volatile first).
- Collect logs (Sysmon/EDR/audit), `$MFT`/USN if possible, and hashes.
- Do not "clean" before imaging.

### Step 3 — Identify the file
- Path/name/extension (watch double extensions), size, entropy.
- Hash → reputation/sandbox; signature/issuer for executables.
- `Zone.Identifier` for download source.

### Step 4 — Attribute the process
- EDR/Sysmon parent chain, command line, user context.
- Is the writing process expected for that path?

### Step 5 — Build the timeline
- Merge file events with process/network/auth events.
- Look for create → execute → persistence → lateral → exfil sequence.

### Step 6 — Check persistence and hiding
- Startup folders, services, tasks, cron, `authorized_keys`, web shells.
- ADS, hidden files, unicode names, timestomp indicators.

### Step 7 — Scope
- Same file/hash/path across hosts.
- SMB share shares; USB; cloud sync.
- Deleted data and shadow copies.

### Step 8 — Respond
- Isolate host, block hash/domain/IP, disable account if needed.
- Restore from known-good backup (verify no persistence in backup).
- Preserve evidence before rebuild.

### Step 9 — Document
Timeline, artifacts, hashes, scope, impact, actions, recommendations.

---

## 14. Triage playbooks

### A. "Ransomware-like file activity"

1. Confirm mass rename/modify, extensions, notes.
2. Check shadow copy/backup deletion.
3. Identify patient zero and encryption process (EDR).
4. Isolate affected hosts/shares immediately; disable compromised accounts.
5. Preserve evidence; identify variant (hash/note/extension/TI).
6. Restore from offline/immutable backups after verifying cleanliness.
7. Hunt for initial access and lateral movement.

### B. "Data staging / possible exfil"

1. Identify archive/content, size, location, creating process.
2. Check for subsequent upload/USB/cloud sync.
3. Determine sensitivity (DLP, data classification).
4. If exfil occurred → escalate to data-breach process, preserve logs.
5. Block destination, isolate host, rotate credentials if exposed.

### C. "Suspicious USB activity"

1. Confirm device insertion (ID, serial, vendor) and user.
2. Identify files copied (Sysmon/EDR/USB logs).
3. Check for autorun/malware; scan media.
4. Policy violation vs malicious exfil; involve HR/legal as required.

### D. "Timestomping detected"

1. Compare `$SI` vs `$FN`, sub-second precision, USN.
2. Identify process/user that changed timestamps.
3. Treat as anti-forensics — escalate; preserve image before changes.
4. Look for other evidence of intrusion (tooling, persistence).

### E. "Web shell written"

1. Confirm file creation in webroot, type, content.
2. Identify writing process (web server, upload, exploit).
3. Check access logs for exploitation and subsequent commands.
4. Isolate server, preserve shell, hunt for lateral movement.
5. Rebuild rather than trust a repaired server.

### F. "Deleted files / anti-forensics"

1. Stop writes; image the volume.
2. Recover via USN/`$Recycle.Bin`/journal/snapshots.
3. Check for secure-deletion tools, log clearing, VSS deletion.
4. Correlate with the incident timeline.

### G. "Mass SMB share writes"

1. Identify source host/account and pattern.
2. Distinguish backup/AV/migration from ransomware.
3. Check for encryption extensions/notes.
4. Isolate source; disable account; protect backups.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| Single suspicious file in temp | Medium |
| Confirmed payload execution | High |
| Staged archive, no movement | Medium–High |
| Confirmed exfiltration | Critical |
| Ransomware encryption | Critical |
| Web shell | Critical |
| Timestomping/anti-forensics | High |
| USB policy violation, no sensitive data | Low–Medium |

---

## 15. Commands

### Windows

```powershell
# Listing and metadata
Get-ChildItem -Force -Recurse C:\Path | Select FullName, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc
Get-Item C:\Path\file.exe | Format-List *
Get-Item C:\Path\file.exe -Stream *
Get-ChildItem C:\Path -Recurse -Force -Stream * | Where-Object Stream -ne ':$DATA'

# Hashes
Get-FileHash C:\Path\file.exe -Algorithm SHA256
certutil -hashfile C:\Path\file.exe SHA256

# ACLs / ownership
Get-Acl C:\Path | Format-List
icacls C:\Path

# ADS / attributes
dir /r C:\Path
attrib C:\Path\file.exe

# Deleted / recycle bin
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse | Select FullName, Length, CreationTimeUtc

# Shadow copies
vssadmin list shadows
vssadmin list shadowstorage
Get-CimInstance Win32_ShadowCopy

# Encryption
cipher /c C:\Path\file.txt
manage-bde -status

# USN (built-in parsing is limited; use tools)
fsutil usn queryjournal C:\
fsutil usn readjournal C:\

# MFT / volume info
fsutil fsinfo volumeinfo C:
fsutil volume diskfree C:
```

> Prefer **read-only** collection for evidence. `Get-FileHash` reads; avoid opening files in a way that changes `atime` on evidence media (mount read-only).

### Linux

```bash
# Metadata
ls -li
stat file
stat -c '%n inode=%i mode=%a uid=%u gid=%g size=%s atime=%x mtime=%y ctime=%z birth=%w' file
find /path -xdev -printf '%i %s %TY-%Tm-%Td %TH:%TM:%TS %p\n'

# Hashes
sha256sum file
md5sum file

# Types / strings
file file
xxd -l 64 file
strings -a file | head

# xattrs / capabilities
getfattr -d -m - file
getcap -r / 2>/dev/null

# Permissions / links
namei -l /path
readlink -f /path
find / -xdev -samefile file 2>/dev/null

# Mounts / disks
lsblk -f
mount
findmnt
df -hT

# Deleted recovery (stop writes first; mount read-only)
sudo debugfs -R 'lsdel' /dev/sdX1
sudo extundelete /dev/sdX1 --restore-all
sudo photorec /dev/sdX1

# Journal / audit
sudo journalctl --since "2026-10-27 00:00"
sudo ausearch -k file_delete
sudo aureport -f

# Integrity
sudo aide --check
```

### macOS

```bash
ls -lO
xattr -l file
mdls file
stat -f '%N %i %z %Sm %Sc %SB' file
tmutil listlocalsnapshots /
diskutil apfs list
log show --last 1h --predicate 'eventMessage CONTAINS "file"'
```

### Forensic imaging (authorised)

```bash
# Identify device first
lsblk
# Image with hash and verification (write blocker required)
sudo dc3dd if=/dev/sdb of=/evidence/disk.img hash=sha256 log=/evidence/dc3dd.log
sudo sha256sum /dev/sdb /evidence/disk.img

# EWF via ewfacquire (if installed)
sudo ewfacquire /dev/sdb

# Mount read-only for analysis
sudo mount -o ro,noatime,loop /evidence/disk.img /mnt/evidence
```

> Never image or mount a suspect disk without authorisation and a documented chain of custody. Use a hardware write blocker for original media.

---

## 16. Common false positives

| Alert | Often actually |
|---|---|
| Many file writes | Build systems, package installs, backups, AV scans, sync clients. |
| Archives in temp | Installers, update packages, application exports. |
| Executables in temp | Software installers/updaters, self-extracting packages. |
| Shadow copy deletion | Authorised backup/maintenance (verify change ticket). |
| File extension changes | Application renames, user actions, batch jobs. |
| ADS | Mark-of-the-Web on downloads, browser/Office behaviour. |
| Timestamp anomalies | Legitimate copy/restore, backup restore, archive extraction. |
| USB events | Approved removable media, docks, keyboards. |
| Sensitive file reads | Backup agents, AV, DLP, admin scripts. |
| Mass SMB writes | Backup, migration, AV, indexing. |
| Deleted files | Normal user cleanup, log rotation. |
| Cloud sync | Sanctioned OneDrive/Drive/SharePoint. |

**Rule of thumb:** correlate **process + path + volume + user + timing**. A thousand writes by `backup.exe` are not ransomware.

---

## 17. Hardening and recommendations

- Enable **file auditing/Sysmon/EDR** with tuned rules; retain logs ≥ 30–90 days.
- Protect **shadow copies/backups** (offline/immutable, separate credentials, MFA).
- Deploy **FIM** on critical paths (webroot, configs, `authorized_keys`, startup folders).
- Restrict **write access** to webroots; run web apps with least privilege.
- **Application control** (WDAC/AppLocker) to block execution from temp/user dirs.
- Disable **Autorun/Autoplay**; control USB via policy/Device Guard.
- Enforce **disk encryption** (BitLocker/LUKS/FileVault) with escrowed recovery keys.
- Use **SMB signing/encryption**; restrict admin shares; audit share access.
- **DLP** and cloud-app controls for sensitive data; block personal sync where policy requires.
- **Log and monitor** `vssadmin`/`wbadmin`/`bcdedit` deletion commands.
- Keep **asset/data classification** current to judge exfil impact.
- **Canary/honeytoken files** in shares and sensitive directories.
- Test **restore** regularly; ransomware recovery depends on it.
- Train users on double extensions, macros, and removable media.

---

## 18. Lab practice plan

1. Create a lab VM with NTFS; generate files; inspect `$MFT`/ADS with tools.
2. Enable Sysmon; create/rename/delete files; observe events 11/2/23/26/15.
3. Timestomp a file with PowerShell; compare `$SI` and `$FN` using MFTECmd.
4. Delete files; recover from `$Recycle.Bin` and USN; document.
5. Build a small ransomware simulator (lab only) that renames files; write a detection.
6. Create ZIP archives in temp; simulate upload; correlate file+network events.
7. Set up a Linux VM with ext4; practice `stat`, `debugfs`, `extundelete`, `photorec`.
8. Configure auditd rules; generate file events; query `ausearch`.
9. Mount a disk image read-only; use TSK (`fls`, `icat`) to list/extract.
10. Write an incident report from §13/§14 with timeline and artifacts.

---

## 19. Self-test questions

1. What is an inode, and what does it not store?
2. What is the NTFS MFT, and why is it central to forensics?
3. What are the two sets of NTFS timestamps, and which is easier to forge?
4. What is an alternate data stream, and how would you find one?
5. What does the USN journal record, and why is it useful?
6. What does the `$Recycle.Bin` `$I` file contain?
7. Why is FAT32 timestamp evidence weaker than NTFS?
8. What is the difference between `mtime`, `atime`, `ctime`, and `btime` on Linux?
9. How does `relatime` affect investigations?
10. What is copy-on-write, and how do snapshots help incident response?
11. What artifacts prove a file was downloaded from the internet on Windows?
12. How would you detect timestomping?
13. What file-system signs indicate ransomware?
14. How would you prove data was staged for exfiltration?
15. Why must you image a disk before analysis, and how do you preserve integrity?

---

## 20. One-page revision checklist

- [ ] Concepts: blocks, inodes/MFT, journal, CoW, extents, sparse, encryption, allocated/unallocated, slack, links, ADS, xattrs.
- [ ] Timestamps: MACB; NTFS `$SI` vs `$FN`; Linux `mtime/atime/ctime/btime`; relatime.
- [ ] Partitioning/volumes: MBR/GPT, LVM/Storage Spaces, encryption, overlays, network/cloud.
- [ ] NTFS: MFT/system files, attributes, ADS/Zone.Identifier, tunnelling, USN/`$LogFile`/`$Secure`/`$Bitmap`/`$Recycle.Bin`, VSS, junctions/hard links/EFS/BitLocker/dedup.
- [ ] FAT/exFAT/ReFS traits and forensic caveats.
- [ ] Linux: ext2/3/4, XFS, Btrfs, ZFS, tmpfs, procfs, overlayfs; artifacts (`/tmp`, `/dev/shm`, `/etc/passwd`, SSH keys, cron, history, logs); deletion/recovery.
- [ ] macOS/APFS: CoW, snapshots, xattrs/quarantine, Time Machine, FileVault.
- [ ] Network/cloud: SMB 5140/5145/4663, NFS, S3/CloudTrail, OneDrive/Drive audit, sync clients.
- [ ] Forensics artifacts by question: existence, creation/deletion, execution, download, staging, USB, timestomp, encryption, sharing, hiding.
- [ ] Ransomware: mass rename/modify, extensions, notes, VSS/backup deletion, share encryption, canaries.
- [ ] Exfil: archives in temp, USB, cloud sync, uploads, rclone/rsync, deletion after upload.
- [ ] Telemetry: Sysmon 2/11/15/23/26, Security 4663/4656/5140/5145, EDR, FIM, auditd, cloud audit, USN/MFT offline.
- [ ] Detections: extension bursts, notes, shadow deletion, mass writes, archive staging, USB, cloud sync, ADS, timestomp, startup writes, web shells, temp executables, hidden files, mass deletion, permission changes, share writes, sensitive reads, hash IOCs.
- [ ] Investigation: facts → preserve → identify file → attribute process → timeline → persistence/hiding → scope → respond → document.
- [ ] Triage: ransomware, staging/exfil, USB, timestomping, web shell, deleted files, mass share writes.
- [ ] Commands: PowerShell/`Get-FileHash`/`dir /r`/`vssadmin`/`fsutil`, Linux `stat`/`getfattr`/`debugfs`/`extundelete`/`photorec`/`ausearch`, macOS `xattr`/`tmutil`, imaging with hashes.
- [ ] Hardening: audit/EDR, protect backups/VSS, FIM, least privilege, WDAC, USB control, encryption, SMB security, DLP/cloud controls, monitor anti-recovery commands, canaries, restore tests.
