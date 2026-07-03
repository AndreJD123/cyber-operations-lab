# Scripts Overview

One-liner summary of every script in this lab.
Update this file each time you add a new script.

---

## python/scripts/

| Script | What it does | Key Python concepts | MITRE ATT&CK |
|---|---|---|---|
| `ssh_bruteforce_detector.py` | Reads SSH auth logs, counts failed logins per IP, flags IPs above a threshold and any that failed then succeeded | regex, defaultdict, sets, list comprehensions, sorting | T1110 — Brute Force |
| `windows_event_analyzer.py` | Parses Windows Security Event JSON logs and detects brute force (4625→4624), suspicious process execution (4688), and lateral movement (4648) | json, pathlib.Path, defaultdict with tuple keys, re.search(), list comprehensions, any() | T1110 Brute Force, T1059.001 PowerShell, T1059.003 Cmd Shell, T1021 Lateral Movement |
| `log_parser.py` | — | — | — |

---

## python/soc-automation-toolkit/

Full multi-module pipeline project. Run with `python run.py [source]` from the toolkit directory.

| Module | What it does | Key Python concepts | MITRE ATT&CK |
|---|---|---|---|
| `src/parsers/edr.py` | Normalizes EDR endpoint alerts (process, parent, command line, hashes) into shared schema | inheritance, ABC, dict.get() with defaults | T1059.001 — PowerShell |
| `src/parsers/okta.py` | Normalizes Okta impossible-travel events; extracts nested geo data | class-level constants, nested dict chaining | T1078 — Valid Accounts |
| `src/parsers/guardduty.py` | Normalizes GuardDuty findings; converts numeric severity (0.1–8.9) to categorical label | static method, dict comprehension, chained .get() | T1552 — Unsecured Credentials |
| `src/parsers/wiz.py` | Normalizes Wiz toxic-combination findings; maps UPPERCASE severity | class constant dict, list comprehension over nested list | T1190 — Exploit Public-Facing App |
| `src/parsers/dlp.py` | Normalizes DLP alerts; captures prior violation count as first-class field | conditional expression (ternary), f-string interpolation | T1048 — Exfil Over Alternative Protocol |
| `src/risk_scorer.py` | Additive risk scoring (severity base + contextual bonuses); records each factor | list accumulation, any() with generator, str.startswith() tuple, min() | — |
| `src/mitre_mapper.py` | Resolves ATT&CK technique IDs to full metadata from a curated local DB | module-level constant dict, list comprehension with None filter | T1059.001, T1078, T1110, T1190, T1048, T1552, T1133, T1140, T1021, T1567 |
| `src/ioc_extractor.py` | Extracts IPs, MD5/SHA256 hashes, emails, URLs via compiled regex; recursively flattens raw dict | re.compile(), re.findall(), set() dedup, recursive function with depth limit | — |
| `src/case_summary.py` | Assembles all enrichment outputs + triage playbook into CaseSummary; renders as text or dict | enumerate() with start, function composition, manual JSON serialization | — |

---

## python/practice/

| File | Concepts covered |
|---|---|
| `01_python_fundamentals.py` | Variables, strings, f-strings, lists, dicts, sets, functions, file I/O, conditionals |

---

## How to run a script

```bash
# Always run from the scripts/ directory so relative paths work
cd ~/cyberlab/python/scripts
python3 ssh_bruteforce_detector.py
```

---

## How to push changes to GitHub

```bash
cd ~/cyberlab
bash push.sh "your commit message here"
```

---

## Notes

- Sample log files live in `python/datasets/`
- Never push `venv/`, `aws/`, `.env`, or `awscliv2.zip`
- Session history → `notes/progress-log.md`
