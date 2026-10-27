# Python — SOC Automation Study Notes

> Goal: build small, reliable tools for parsing, enriching, and automating SOC work — with code you can trust.
> API patterns → `APIs.md`; orchestration → `SOAR.md`; shell equivalents → `Bash.md`.

---

## 0. How to use this note

1. §1–§3: why Python; environment; language essentials.
2. §4–§8: data structures, files, JSON/CSV, regex, dates.
3. §9–§13: HTTP, errors, logging, CLI, concurrency.
4. §14–§17: SOC examples; testing; security; packaging.
5. §18–§20: pitfalls, labs.
6. §21–§22: self-test, revision.

---

## 1. Why Python in a SOC

| Strength | Use |
|---|---|
| Readable | Analysts can maintain it |
| Ecosystem | `requests`, `pandas`, `yara-python` |
| Glue | Ties APIs, files, tools together |
| Notebooks | Investigation and reporting |
| Cross-platform | Same tool on Linux/Windows/macOS |

**Python is for analysis and glue. It is not automatically fast or safe.**

---

## 2. Environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -U pip
pip install requests pandas python-dateutil
pip freeze > requirements.txt
```

| Practice | Why |
|---|---|
| Virtualenv per project | Isolation |
| Pin versions | Reproducibility |
| `requirements.txt` | Deploy |
| `.env` + `python-dotenv` | Local config |
| Never commit secrets | Breach |

### 2.1 Project layout

```
triage/
  pyproject.toml
  requirements.txt
  triage/
    __init__.py
    api.py
    parse.py
    cli.py
  tests/
    test_parse.py
```

---

## 3. Language essentials

```python
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

@dataclass
class Alert:
    alert_id: str
    severity: str
    host: str
    user: str | None = None

def is_high(a: Alert) -> bool:
    return a.severity.lower() in {"high", "critical"}
```

| Feature | Note |
|---|---|
| f-strings | `f"{host}:{port}"` |
| Type hints | Documentation + tooling |
| `dataclass` | Clean records |
| Comprehensions | Concise transforms |
| `pathlib` | Cross-platform paths |
| `contextlib` | Resource handling |

### 3.1 Truthiness traps

| Value | Truthy? |
|---|---|
| `0`, `""`, `[]`, `{}`, `None`, `False` | No |
| `"0"` | **Yes** |
| `[0]` | Yes |

**`if value:` is wrong when 0 or empty is meaningful.**

---

## 4. Data structures

```python
alerts = []

alerts.append(Alert("A-1", "high", "WS-01"))
by_host: dict[str, list[Alert]] = {}
for a in alerts:
    by_host.setdefault(a.host, []).append(a)

unique_ips = {a.user for a in alerts if a.user}
```

| Structure | Use |
|---|---|
| `list` | Ordered, duplicates |
| `dict` | Key lookup |
| `set` | Uniqueness, membership |
| `tuple` | Immutable record |
| `Counter` | Frequency |
| `defaultdict` | Grouping |
| `deque` | Queue |

```python
from collections import Counter, defaultdict

counts = Counter(ip for ip in ips)
groups = defaultdict(list)
for a in alerts:
    groups[a.host].append(a)
```

---

## 5. Files and paths

```python
from pathlib import Path

p = Path("logs/access.log")
text = p.read_text(encoding="utf-8", errors="replace")

with p.open(encoding="utf-8", errors="replace") as fh:
    for line in fh:
        ...

out = Path("out"); out.mkdir(parents=True, exist_ok=True)
```

| Rule | Why |
|---|---|
| Always specify encoding | Mojibake |
| `errors="replace"` for messy logs | No crash |
| Stream large files | Memory |
| Use `with` | Close handles |
| `pathlib` over string concat | Portability |

### 5.1 Streaming

```python
def rows(path: Path):
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n")
```

**Never `read_text()` a 10 GB log.**

---

## 6. JSON and CSV

```python
import json, csv

data = json.loads(payload)
json.dump(obj, fh, indent=2, default=str)

with open("iocs.csv", newline="", encoding="utf-8") as fh:
    for row in csv.DictReader(fh):
        ...
```

| Trap | Fix |
|---|---|
| Dates not serialisable | `default=str` |
| Nested structure depth | Flatten explicitly |
| CSV delimiter/quoting | `csv` module, not `split(",")` |
| BOM | `encoding="utf-8-sig"` |
| Newlines on Windows | `newline=""` |

### 6.1 NDJSON

```python
for line in fh:
    record = json.loads(line)   # one JSON object per line
```

Common for large exports and log shipping.

---

## 7. Regex for IOCs

```python
import re

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
```

### 7.1 Defanging

```python
def defang(value: str) -> str:
    return (value.replace("http", "hxxp")
                 .replace(".", "[.]"))

def refang(value: str) -> str:
    return (value.replace("hxxp", "http")
                 .replace("[.]", "."))
```

### 7.2 Validation over regex

Regex finds candidates; it does not validate them.

```python
import ipaddress

def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
```

**`999.999.999.999` matches many regexes and is not an IP.**

---

## 8. Dates and timezones

```python
from datetime import datetime, timezone

now = datetime.now(timezone.utc)
parsed = datetime.fromisoformat("2026-04-02T10:15:22+00:00")
epoch = parsed.timestamp()

def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("naive datetime")
    return dt.astimezone(timezone.utc)
```

| Rule | Why |
|---|---|
| Always tz-aware | Avoid silent offsets |
| Store UTC | Consistency |
| Reject naive datetimes | Ambiguity |
| ISO 8601 in output | Interop |

**`datetime.utcnow()` is naive — prefer `datetime.now(timezone.utc)`.**

---

## 9. HTTP with requests

```python
import requests

session = requests.Session()
session.headers.update({"Authorization": f"Bearer {token}"})

resp = session.get(f"{base}/alerts", params={"limit": 100}, timeout=(5, 30))
resp.raise_for_status()
alerts = resp.json()["items"]
```

| Practice | Why |
|---|---|
| `Session` | Connection reuse |
| `timeout=(connect, read)` | No hangs |
| `raise_for_status()` | Explicit errors |
| `params=` | Encoding |
| Retry adapter | Resilience |

### 9.1 Retries

```python
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

retry = Retry(
    total=5, backoff_factor=0.5,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset({"GET", "HEAD"}),
)
session.mount("https://", HTTPAdapter(max_retries=retry))
```

**Never retry non-idempotent POSTs automatically.**

---

## 10. Errors

```python
class ApiError(RuntimeError):
    pass

def get_alerts() -> list[dict]:
    try:
        r = session.get(url, timeout=30)
        r.raise_for_status()
        return r.json()["items"]
    except requests.Timeout as exc:
        raise ApiError("timeout") from exc
    except requests.HTTPError as exc:
        raise ApiError(f"HTTP {exc.response.status_code}") from exc
```

| Rule | Why |
|---|---|
| Catch specific exceptions | Not `except:` |
| Chain with `from` | Traceability |
| Fail loudly for automation | Silent success is worse |
| Log context | Debuggability |

**Bare `except:` hides KeyboardInterrupt and real bugs.**

---

## 11. Logging

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("triage")

log.info("alert=%s host=%s action=enrich", alert_id, host)
```

| Level | Use |
|---|---|
| DEBUG | Payloads (redacted) |
| INFO | Actions, results |
| WARNING | Recoverable issues |
| ERROR | Failed operations |
| CRITICAL | Automation broken |

**Never log tokens, passwords, or full PII.**

---

## 12. CLI with argparse

```python
import argparse

def main() -> int:
    p = argparse.ArgumentParser(description="Enrich alerts")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--limit", type=int, default=100)
    args = p.parse_args()

    if args.dry_run:
        print("dry run")
        return 0

    return run(args.input, args.limit)

if __name__ == "__main__":
    raise SystemExit(main())
```

| Practice | Why |
|---|---|
| `--dry-run` default for risky tools | Safety |
| Return exit codes | Automation |
| `type=Path` | Validation |
| Help text | Usability |

---

## 13. Concurrency

| Model | Use |
|---|---|
| **Sequential** | Simple, safe |
| **ThreadPoolExecutor** | I/O-bound (API calls) |
| **ProcessPoolExecutor** | CPU-bound |
| **asyncio** | Many concurrent I/O |

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def enrich(ip: str) -> dict:
    ...

with ThreadPoolExecutor(max_workers=8) as pool:
    futures = {pool.submit(enrich, ip): ip for ip in ips}
    for fut in as_completed(futures):
        ip = futures[fut]
        try:
            results[ip] = fut.result()
        except Exception as exc:
            log.warning("enrich failed ip=%s err=%s", ip, exc)
```

**Throttle to the API's limit; more threads is not more reliable.**

---

## 14. SOC examples

### 14.1 Parse auth log

```python
import re
from collections import Counter

FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")

def failed_by_ip(path: Path) -> Counter:
    counts: Counter = Counter()
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = FAIL.search(line)
            if m:
                counts[m.group(2)] += 1
    return counts

for ip, n in failed_by_ip(Path("auth.log")).most_common(10):
    print(f"{n:5d}  {ip}")
```

### 14.2 Enrich alerts

```python
def enrich(alert: dict, ti, cmdb) -> dict:
    ip = alert.get("src_ip")
    rep = ti.lookup(ip) if ip else None
    asset = cmdb.get(alert["host"])
    alert["ti"] = rep
    alert["asset_criticality"] = asset.get("criticality", "unknown")
    return alert
```

### 14.3 Bulk hash a directory

```python
import hashlib

def sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()
```

### 14.4 Search events for IOCs

```python
def sweep(events: list[dict], iocs: set[str]) -> list[dict]:
    hits = []
    for e in events:
        for value in e.values():
            if isinstance(value, str) and value in iocs:
                hits.append(e)
                break
    return hits
```

### 14.5 Build a timeline

```python
def timeline(events: list[dict]) -> list[dict]:
    return sorted(events, key=lambda e: e["timestamp_utc"])
```

### 14.6 Pandas quick analysis

```python
import pandas as pd

df = pd.read_json("alerts.json")
top = (df.groupby(["host", "severity"]).size()
         .reset_index(name="count")
         .sort_values("count", ascending=False))
print(top.head(20))
```

**Pandas is for exploration; scripts for production.**

---

## 15. Testing

```python
# tests/test_parse.py
from triage.parse import failed_by_ip

def test_counts_failures(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Failed password for root from 10.0.0.5 port 22 ssh2\n"
        "Failed password for root from 10.0.0.5 port 22 ssh2\n"
    )
    counts = failed_by_ip(log)
    assert counts["10.0.0.5"] == 2
```

```bash
pytest -q
ruff check .
mypy triage
```

| Test type | Purpose |
|---|---|
| Unit | Parsing/filtering |
| Integration | API contract |
| Golden-file | Output stability |
| Property | Edge cases |

**At minimum test your parsers — they silently break on format changes.**

---

## 16. Security

| Risk | Control |
|---|---|
| Hard-coded secrets | Env/vault |
| `eval`/`exec` on input | Never |
| `pickle` on untrusted data | Never |
| `subprocess` with `shell=True` | Avoid; pass list |
| Path traversal | Resolve + validate |
| Dependency CVEs | Pin + scan |
| Logging secrets | Redact |
| TLS verification off | Never |

```python
import subprocess

subprocess.run(["grep", "-F", "--", ioc, "file.log"], check=True)
```

**`shell=True` with user data is command injection by design.**

---

## 17. Packaging

```toml
# pyproject.toml
[project]
name = "triage"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["requests>=2.31", "python-dateutil>=2.8"]
```

```bash
pip install -e .
triage --help
```

Ship with: README, `requirements.txt`/lock, env example, runbook, tests, license.

---

## 18. Pitfalls

| Pitfall | Consequence |
|---|---|
| Naive datetimes | Wrong timelines |
| `except:` bare | Hidden failures |
| No timeout | Hung jobs |
| Reading whole file | OOM |
| Retrying POST | Duplicate actions |
| `shell=True` | Injection |
| Unpinned deps | Breakage/CVE |
| Secrets in code | Breach |
| No tests on parsers | Silent breakage |
| `if value:` on 0 | Logic bugs |
| Huge thread pools | API blocks you |

---

## 19. Labs

1. Parse an auth log and output top 10 IPs.
2. Build a JSON → CSV converter for alerts.
3. Write an IOC defang/refang module with tests.
4. Call an API with retries and timeouts.
5. Enrich 50 IOCs concurrently with throttling.
6. Hash a directory and export CSV.
7. Build a timeline from mixed JSON sources.
8. Add `--dry-run` and logging to a script.
9. Write 5 pytest cases including a malformed line.
10. Package a CLI with `pyproject.toml`.

---

## 20. Code review checklist

- [ ] Types and docstrings.
- [ ] Exceptions specific and chained.
- [ ] Timeouts on all network calls.
- [ ] Encoding specified.
- [ ] No secrets.
- [ ] Dry-run for destructive actions.
- [ ] Logging with context, no secrets.
- [ ] Tests for parsers.
- [ ] Pinned dependencies.
- [ ] Exit codes correct.

---

## 21. Self-test questions

1. Why use a virtualenv?
2. What is wrong with `if value:` for a count?
3. Why specify encoding when reading logs?
4. How do you stream a large file?
5. Why does regex not validate an IP?
6. Why are naive datetimes dangerous?
7. What does `raise_for_status()` do?
8. Which methods are safe to auto-retry?
9. Why chain exceptions with `from`?
10. What must never be logged?
11. Why use `--dry-run`?
12. Threads vs processes?
13. Why avoid `shell=True`?
14. Why test parsers specifically?
15. What belongs in a review checklist?

---

## 22. One-page revision checklist

- [ ] venv, pinned deps, project layout.
- [ ] Type hints, dataclasses, f-strings, pathlib.
- [ ] Truthiness traps.
- [ ] list/dict/set/Counter/defaultdict.
- [ ] Encoding, streaming, `with`, `pathlib`.
- [ ] JSON/CSV/NDJSON traps.
- [ ] Regex + validation (`ipaddress`), defang/refang.
- [ ] tz-aware UTC datetimes, ISO 8601.
- [ ] `requests` Session, timeouts, `raise_for_status`, retries.
- [ ] Custom exceptions, chaining, fail loudly.
- [ ] Logging levels, no secrets.
- [ ] argparse, exit codes, `--dry-run`.
- [ ] Concurrency models + throttling.
- [ ] SOC examples: parse, enrich, hash, sweep, timeline, pandas.
- [ ] Tests with pytest; ruff/mypy.
- [ ] Security: no eval/pickle/shell=True, path validation, TLS, deps.
- [ ] Packaging with pyproject.
- [ ] Pitfalls memorised.
