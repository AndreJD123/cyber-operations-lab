# Cyber Operations Lab

Security engineering lab building toward the intersection of **cloud security**, **detection engineering**, and **AI-assisted security tooling**.

Built by a SOC analyst with a Masters in Cyber & Information Security (NSA CAE), DLP/Insider Risk domain expertise, and a long-term focus on cloud security engineering and AI security.

---

## What This Lab Is

Hands-on engineering reps to close the gap between security theory and execution. Every script maps to a real detection use case, a MITRE ATT&CK technique, and the kind of logic that runs under the hood of a production SIEM.

The tooling here is intentionally built from scratch — no pre-built rules, no dashboard clicks.

---

## Scripts

| Script | What it detects | MITRE ATT&CK | Key Tech |
|---|---|---|---|
| [ssh_bruteforce_detector.py](python/scripts/ssh_bruteforce_detector.py) | SSH brute force — repeated failures per IP, flags IPs that failed then succeeded | T1110 — Brute Force | `re`, `defaultdict`, set intersection |
| [windows_event_analyzer.py](python/scripts/windows_event_analyzer.py) | Windows brute force (4625→4624), suspicious process execution (4688), lateral movement (4648) | T1110, T1059.001, T1059.003, T1021 | `json`, `pathlib`, `defaultdict`, `re` |
| [log_parser.py](python/scripts/log_parser.py) | SSH failed login counter — foundational log parsing exercise | T1110 — Brute Force | `re`, `sys.argv`, dict comprehension |

See [python/scripts/README.md](python/scripts/README.md) for full documentation on each script.

---

## Lab Structure

```
cyberlab/
├── python/
│   ├── scripts/        # Finished security tools
│   ├── practice/       # Python fundamentals with security context
│   └── datasets/       # Sample logs and mock event data for testing
├── notes/
│   ├── scripts-overview.md   # One-liner index of every script
│   └── python-cheatsheet.md  # Running reference of Python concepts used
└── bash/               # Bash scripts
```

---

## Roadmap

- [x] SSH log analysis and brute force detection
- [x] Windows Security Event log analysis (4624, 4625, 4648, 4672, 4688)
- [ ] AWS-native detection pipeline (CloudTrail + GuardDuty + Athena)

---

## Stack

- **Python 3** — core scripting language
- **AWS** (boto3, GuardDuty, IAM, S3) — cloud security tooling
- **MITRE ATT&CK** — technique mapping for all detections
- **WSL2 / Linux** — development environment
