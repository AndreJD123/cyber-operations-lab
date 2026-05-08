# Security Scripts

Finished detection engineering tools. Each script is self-contained, runs against sample data in `../datasets/`, and maps to one or more MITRE ATT&CK techniques.

---

## ssh_bruteforce_detector.py

**Detects:** SSH brute force attacks — repeated failed logins per IP, and the worst case: an IP that failed many times and then succeeded.

**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

**How to run:**
```bash
cd ~/cyberlab/python/scripts
python3 ssh_bruteforce_detector.py
```

**Detection logic:**
1. Parse each SSH auth log line with regex — extract IP, username, success/failure, timestamp
2. Count failed attempts per source IP using a `defaultdict`
3. Track IPs with successful logins in a `set`
4. Flag IPs above the failure threshold (default: 3)
5. Cross-reference failures vs successes — IPs in both = brute force succeeded = critical alert

**Sample output:**
```
============================================================
  SSH BRUTE FORCE DETECTION REPORT
============================================================

[!!] HIGH SEVERITY — Brute Force + Successful Login:
     These IPs failed repeatedly THEN got in.

     IP: 192.168.1.50  |  Failed attempts: 7

[!]  SUSPICIOUS IPs (>= 3 failed attempts):

     IP Address           Failed Attempts
     -------------------- ---------------
     192.168.1.50                       7 <-- ALSO SUCCEEDED
     10.0.0.99                          4
```

**Why it matters in a real environment:**
A single failed SSH login is noise. Five failed logins from one IP in 30 seconds is a scanner. Five failed logins followed by a success is a breach. This script automates exactly the correlation chain a SIEM analyst would trace manually.

---

## windows_event_analyzer.py

**Detects:** Three attack patterns from Windows Security Event logs:
1. Brute force — repeated 4625s (failed logon) from the same source, with a flag if a 4624 (success) followed
2. Suspicious process execution — 4688 (process creation) events involving known LOLBins or dangerous command-line arguments
3. Lateral movement indicators — 4648 (explicit credential logon) events, which signal an attacker using stolen credentials to move laterally

**MITRE ATT&CK:**
- T1110 — Brute Force
- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell
- T1021 — Remote Services / Lateral Movement

**How to run:**
```bash
cd ~/cyberlab/python/scripts
python3 windows_event_analyzer.py
```

**Sample data:** `../datasets/windows_events.json` — mock Windows Security Events with both benign and malicious entries for testing.

**Detection logic:**

*Brute force:*
Counts 4625 events per (IP, username) tuple. Flags pairs above threshold. Checks if a 4624 from the same pair exists — if so, the brute force succeeded.

*Suspicious processes:*
Scans 4688 events for process names known to be abused (PowerShell, cmd.exe, mshta.exe, certutil.exe, rundll32.exe, etc.) and command-line patterns that indicate execution policy bypass, encoded commands, download cradles, or post-exploitation recon.

*Lateral movement:*
Extracts all 4648 events. These represent an account authenticating to another machine using explicitly supplied credentials — the signature of an attacker pivoting with harvested creds. Flags them with logon type decoded from the numeric code.

**Key event IDs decoded:**

| Event ID | Meaning | Why analysts care |
|---|---|---|
| 4624 | Successful logon | Baseline — normal activity |
| 4625 | Failed logon | Volume = brute force |
| 4648 | Logon with explicit credentials | Lateral movement indicator |
| 4672 | Special privileges assigned | Admin-level access granted |
| 4688 | Process created | Process tree — what ran and from where |

**Why it matters in a real environment:**
Individual events are noise. Chained events tell a story. A 4625 spike → 4624 → 4648 from the same source IP, within minutes of each other, is an intrusion chain: brute force access, then lateral movement. This is the correlation logic that fires SIEM rules.

---

## log_parser.py

**Detects:** SSH failed logins — counts failures per IP and flags IPs above a threshold.

**MITRE ATT&CK:** T1110 — Brute Force

**Note:** This is an earlier, simpler version of `ssh_bruteforce_detector.py`. It demonstrates foundational log parsing patterns — regex extraction, dict counting, `sys.argv` for CLI arguments — without the success/failure correlation logic.

**How to run:**
```bash
cd ~/cyberlab/python/scripts
python3 log_parser.py path/to/auth.log
```
