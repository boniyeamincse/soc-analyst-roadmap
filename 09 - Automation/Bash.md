# Bash — SOC Automation Study Notes

> **Navigation:** [Roadmap index](../README.md) · [← APIs](APIs.md) · [PowerShell →](PowerShell.md)

> Goal: parse, filter, and act on logs and API output from the command line — reliably and safely.
> API mechanics → [APIs.md](APIs.md); Windows equivalent → [PowerShell.md](PowerShell.md); orchestration → [SOAR.md](SOAR.md).

---

## 0. How to use this note

1. §1–§3: shell basics; quoting; exit codes.
2. §4–§8: text pipeline — grep, cut, sort, uniq, awk, sed, jq.
3. §9–§12: files, loops, functions, error handling.
4. §13–§16: SOC recipes; safe automation; cron; logging.
5. §17–§19: pitfalls, labs.
6. §20–§21: self-test, revision.

---

## 1. Basics

```bash
#!/usr/bin/env bash
set -euo pipefail
```

| Option | Effect |
|---|---|
| `-e` | Exit on error |
| `-u` | Error on undefined variable |
| `-o pipefail` | Pipeline fails if any stage fails |
| `-x` | Trace (debug only) |

### 1.1 Structure

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

main() {
  local input="${1:?usage: $0 <file>}"
  process "$input"
}

main "$@"
```

---

## 2. Variables and quoting

| Form | Meaning |
|---|---|
| `"$var"` | Expand, safe with spaces |
| `'$var'` | Literal |
| `${var:-default}` | Default if unset/empty |
| `${var:?msg}` | Fail if unset |
| `${#var}` | Length |
| `"${arr[@]}"` | All array elements |

**Always quote variables.** Unquoted expansion breaks on spaces and globbing.

```bash
count=0
for f in "$dir"/*.log; do
  [[ -e "$f" ]] || continue
  ((count++))
done
```

---

## 3. Exit codes and conditionals

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error |
| 2 | Misuse |
| 126 | Not executable |
| 127 | Not found |
| 130 | Ctrl-C |

```bash
if command -v jq >/dev/null 2>&1; then
  echo "jq available"
else
  echo "install jq" >&2
  exit 1
fi
```

Use `[[ ]]` in bash; `[ ]` only for POSIX.

---

## 4. grep

| Flag | Use |
|---|---|
| `-i` | Case-insensitive |
| `-v` | Invert |
| `-c` | Count |
| `-n` | Line numbers |
| `-r` | Recursive |
| `-E` | Extended regex |
| `-F` | Fixed strings (fast) |
| `-o` | Only match |
| `-A/-B/-C` | Context |
| `-l` | Files with match |

```bash
grep -c "Failed password" auth.log
grep -E "Failed password|Invalid user" auth.log \
  | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
```

### 4.1 Practical tips

- `-F` when searching literal IOCs (dots in domains).
- Use `rg` when available for speed.
- `LC_ALL=C` speeds up byte-oriented matching.

---

## 5. cut, sort, uniq, wc

```bash
cut -d' ' -f1,3 access.log
sort -u ips.txt
sort ips.txt | uniq -c | sort -rn | head -20
wc -l alerts.log
```

| Command | Trap |
|---|---|
| `cut` | Breaks on multiple spaces; prefer `awk` |
| `sort -n` | Needed for numeric |
| `sort -k2,2` | Field sorting |
| `uniq` | Only removes **adjacent** duplicates — sort first |
| `wc -l` | Counts newlines, not lines if no trailing newline |

---

## 6. awk

```bash
awk '{print $1, $7}' access.log
awk -F',' '$3 == "Failed" {print $1}' events.csv
awk '{sum += $10} END {print sum}' traffic.log
```

### 6.1 Common uses

| Use | Example |
|---|---|
| Field extraction | `awk '{print $5}'` |
| Condition | `awk '$9 >= 400'` |
| Aggregation | `awk '{c[$1]++} END {for (k in c) print c[k], k}'` |
| Formatting | `printf "%-20s %s\n", $1, $2` |
| Deduplicate by key | `!seen[$0]++` |

### 6.2 Log parsing example

```bash
awk '{print $1}' access.log \
  | sort | uniq -c | sort -rn | head -10
```

Top talkers in one line.

---

## 7. sed

```bash
sed -n '10,20p' file.log        # print range
sed 's/http/hxxp/g' iocs.txt    # defang
sed -E 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/<IP>/g' log
```

| Flag | Use |
|---|---|
| `-n` | No auto-print |
| `-E` | Extended regex |
| `-i` | In-place (dangerous — back up) |
| `-e` | Multiple expressions |

**Prefer `sed -i.bak` or write to a new file.**

---

## 8. jq for JSON

```bash
jq '.items[] | {id, severity}' alerts.json
jq -r '.items[].id' alerts.json
jq 'map(select(.severity=="high")) | length' alerts.json
jq -r '.[] | [.ip, .count] | @tsv' counts.json
```

### 8.1 Useful filters

| Filter | Meaning |
|---|---|
| `.a.b` | Nested access |
| `.[]` | Iterate |
| `select(cond)` | Filter |
| `map(f)` | Transform |
| `sort_by(.x)` | Sort |
| `group_by(.x)` | Group |
| `@tsv`, `@csv` | Output formats |
| `-r` | Raw strings |
| `-c` | Compact |
| `//` | Default |

### 8.2 API pipeline

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "$API/alerts?limit=100" \
  | jq -r '.items[] | select(.severity=="high") | [.id,.host,.user] | @tsv'
```

---

## 9. Files and paths

| Command | Use |
|---|---|
| `find . -type f -name '*.log' -mtime -1` | Recent logs |
| `find . -type f -size +100M` | Large files |
| `xargs -r -n1` | Batch arguments |
| `xargs -P8` | Parallel |
| `mktemp` | Temp file |
| `trap 'rm -f "$tmp"' EXIT` | Cleanup |
| `readlink -f` | Canonical path |

```bash
find /var/log -name '*.log' -mtime -1 -print0 \
  | xargs -0 -r grep -l "invalid user"
```

**Always use `-print0` / `-0` for filenames with spaces.**

---

## 10. Loops

```bash
while IFS= read -r line; do
  echo "processing: $line"
done < iocs.txt

while IFS=, read -r ip count; do
  echo "$ip seen $count times"
done < counts.csv
```

| Rule | Why |
|---|---|
| `IFS= read -r` | Preserves backslashes/spaces |
| `while read` not `for` | Handles whitespace |
| `< file` not `cat file \|` | Avoids subshell |
| Avoid `for x in $(cat)` | Word splitting |

---

## 11. Functions

```bash
defang() {
  local value="$1"
  printf '%s\n' "${value//./[.]}"
}

log() {
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2
}

main() {
  local f="${1:?file required}"
  [[ -r "$f" ]] || { log "unreadable: $f"; return 1; }
  defang "evil.example"
}

main "$@"
```

- `local` for function variables.
- Return codes, not global mutation.
- Log to stderr; data to stdout.

---

## 12. Error handling

```bash
set -euo pipefail

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

if ! curl -fsS "$URL" -o "$tmp"; then
  echo "fetch failed" >&2
  exit 1
fi
```

| Technique | Use |
|---|---|
| `set -euo pipefail` | Fail fast |
| `trap ... EXIT` | Cleanup |
| `command \|\| { echo err; exit 1; }` | Explicit handling |
| Check file exists/readable | Avoid silent no-op |
| Validate counts | Detect partial results |

---

## 13. SOC recipes

### 13.1 Failed logons by source

```bash
awk '/Failed password/ {for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
  auth.log | sort | uniq -c | sort -rn | head -20
```

### 13.2 IOC sweep in logs

```bash
while IFS= read -r ioc; do
  [[ -z "$ioc" || "$ioc" == \#* ]] && continue
  hits=$(grep -F -c -- "$ioc" logs/*.log || true)
  printf '%s\t%s\n' "$ioc" "$hits"
done < iocs.txt
```

### 13.3 Hash and verify

```bash
sha256sum sample.bin | tee sample.sha256
sha256sum -c sample.sha256
```

### 13.4 Defang and share

```bash
sed -E 's#https?://#hxxp://#g; s#\.#[.]#g' iocs_raw.txt > iocs_safe.txt
```

### 13.5 JSON alert triage

```bash
jq -r '.alerts[] | select(.status=="open")
       | [.id, .severity, .host, .user] | @tsv' alerts.json \
  | column -t
```

### 13.6 Timeline from logs

```bash
jq -r '.[] | [.timestamp, .source, .action] | @tsv' events.json \
  | sort -k1,1 | column -t
```

### 13.7 Compare two exports

```bash
diff <(jq -r '.items[].id' before.json | sort) \
     <(jq -r '.items[].id' after.json  | sort)
```

---

## 14. Safe automation

| Rule | Why |
|---|---|
| Dry-run by default | Prevents accidents |
| `--confirm` for destructive actions | Intent |
| Log every action with timestamp | Audit |
| Validate input (IP/CIDR/domain) | Injection |
| Quote everything | Spaces/globs |
| Use `--` before user input | Avoid option injection |
| Limit blast radius | One target per run |
| Timeouts on network calls | No hangs |
| Never `rm -rf "$var/"` unguarded | Catastrophe |

### 14.1 Destructive pattern

```bash
read -r -p "Isolate $host? [y/N] " ans
[[ "$ans" == "y" ]] || exit 1
edr_isolate "$host"
```

---

## 15. Cron

```cron
# m h dom mon dow command
0 */6 * * * /opt/soc/enrich.sh >> /var/log/soc/enrich.log 2>&1
```

| Rule | Detail |
|---|---|
| Absolute paths | Cron has minimal PATH |
| Redirect output | Otherwise mail/lost |
| Lock against overlap | `flock` |
| Log with timestamps | Audit |

```bash
flock -n /tmp/enrich.lock /opt/soc/enrich.sh
```

---

## 16. Logging

```bash
exec >> /var/log/soc/automation.log 2>&1
echo "$(date -u +%FT%TZ) starting run_id=$RUN_ID"
```

| Field | Include |
|---|---|
| Timestamp UTC | Yes |
| Run ID | Yes |
| Action | Yes |
| Target | Yes |
| Result | Yes |
| Error | Yes |
| Secret | **Never** |

---

## 17. Pitfalls

| Pitfall | Consequence |
|---|---|
| Unquoted variables | Breakage/injection |
| `for x in $(cat)` | Wrong splitting |
| `uniq` without `sort` | Wrong counts |
| `set -e` with pipes | Missed failures without `pipefail` |
| `sed -i` no backup | Data loss |
| `rm -rf` with var | Catastrophe |
| Ignoring exit codes | Silent failure |
| `grep` regex on IOCs | Unintended matches |
| No `--` separator | Option injection |
| No timeouts | Hung jobs |
| Secrets in argv | Visible in `ps` |

---

## 18. Labs

1. Parse an auth log for top failing IPs.
2. Build an IOC sweep script with a dry-run.
3. Convert CSV to JSON with `awk` + `jq`.
4. Write a defang/refang pair.
5. Add `set -euo pipefail`, trap cleanup, and logging.
6. Page through an API with `curl` + `jq`.
7. Parallelise a scan with `xargs -P`.
8. Diff two alert exports.
9. Schedule with `flock` and verify no overlap.
10. Write a script with confirmation + audit log.

---

## 19. ShellCheck

```bash
shellcheck script.sh
```

Fix all warnings before production. Common finds: unquoted vars, useless `cat`, unsafe `rm`, `[[` misuse.

---

## 20. Self-test questions

1. What does `set -euo pipefail` do?
2. Why quote variables?
3. When do you use `while read` over `for`?
4. Why sort before `uniq`?
5. What does `jq -r` do?
6. How do you avoid option injection?
7. What is `-print0` for?
8. How do you make a script fail-safe with temp files?
9. Why is `--` important?
10. What does `flock` solve in cron?
11. Name three destructive-script safeguards.
12. What should never appear in argv?
13. How do you verify a downloaded file?
14. What does `sort -rn` do?
15. Why log to stderr vs stdout?

---

## 21. One-page revision checklist

- [ ] Shebang + `set -euo pipefail` + `IFS`.
- [ ] Quoting rules and parameter expansions.
- [ ] Exit codes; `command -v`.
- [ ] `grep` flags, `-F` for IOCs, context flags.
- [ ] `cut/sort/uniq/wc` traps.
- [ ] `awk` fields, conditions, aggregation.
- [ ] `sed` ranges, substitution, in-place caution.
- [ ] `jq` filters, `-r`, `select`, `@tsv`.
- [ ] `find`/`xargs -0`/`mktemp`/`trap`.
- [ ] `while IFS= read -r`.
- [ ] Functions with `local`, log to stderr.
- [ ] Error handling patterns.
- [ ] SOC recipes: top talkers, IOC sweep, hashing, defang, JSON triage, timeline, diff.
- [ ] Safe automation rules + confirmation.
- [ ] Cron with absolute paths, redirect, flock.
- [ ] Logging fields; never secrets.
- [ ] Pitfalls memorised; ShellCheck.

---

> **Navigation:** [Roadmap index](../README.md) · [← APIs](APIs.md) · [PowerShell →](PowerShell.md)
