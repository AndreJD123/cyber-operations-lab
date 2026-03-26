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
