"""
Windows Event Log Analyzer
===========================
Parses Windows Security Event logs (in JSON format) and flags suspicious
activity based on Event ID patterns.

Run it:
    cd ~/cyberlab/python/scripts
    python3 windows_event_analyzer.py

SOC Context:
    Windows Security Events are the raw telemetry behind most SIEM alerts.
    Every alert you triage in enterprise SIEM started as one of these events.
    This script teaches you to think in events, not just dashboard tiles.

Key Event IDs covered:
    4624 — Successful logon
    4625 — Failed logon
    4648 — Logon using explicit credentials (lateral movement indicator)
    4672 — Special privileges assigned (admin-level logon)
    4688 — Process creation (process tree telemetry)

MITRE ATT&CK techniques this script detects:
    T1110   — Brute Force (repeated 4625s)
    T1059.001 — PowerShell execution (4688 with powershell.exe)
    T1021   — Remote Services / Lateral Movement (4648)
    T1059.003 — Windows Command Shell (4688 with cmd.exe + recon commands)
"""

import json                           # built-in library for reading/writing JSON data
import re                             # regex for pattern matching in command lines
from collections import defaultdict  # auto-initializing dict — used for counting per IP/user
from pathlib import Path              # modern way to handle file paths across OS


# ── Configuration ──────────────────────────────────────────────────────────────

EVENTS_FILE = Path("../datasets/windows_events.json")  # Path object — cleaner than raw strings

# Threshold: how many 4625s from one source before we call it brute force
BRUTE_FORCE_THRESHOLD = 3

# Suspicious process names — lowercase for case-insensitive matching
# These aren't always malicious, but always warrant a second look
SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",    # Windows Script Host — used to run .vbs/.js malware
    "cscript.exe",    # Command-line Script Host — same concern as wscript
    "mshta.exe",      # HTML Application Host — LOLBin (living off the land binary)
    "rundll32.exe",   # Loads DLLs — commonly abused for malware execution
    "regsvr32.exe",   # Registers COM objects — used to bypass AppLocker
    "certutil.exe",   # Certificate tool — abused to download files
]

# Command-line flags that are high-confidence suspicious
SUSPICIOUS_CMD_PATTERNS = [
    r"-[Ee]nc(odedCommand)?",   # PowerShell encoded command — hides what's being run
    r"-[Ee][Pp]\s",             # -EP or -ep = ExecutionPolicy bypass
    r"bypass",                  # ExecutionPolicy bypass
    r"IEX|Invoke-Expression",   # Executes a string as code — download cradles use this
    r"DownloadString|DownloadFile|WebClient",  # network download in PowerShell
    r"whoami|net user|net group|ipconfig|systeminfo",  # recon commands
    r"net localgroup administrators",  # checking/modifying admin group
]

# Logon types explained — this is what enterprise SIEM shows when you look at a 4624/4625
# Knowing these lets you tell interactive user logins from service/network logins
LOGON_TYPE_MAP = {
    0: "System",
    2: "Interactive (local console login)",
    3: "Network (e.g. file share, remote login)",
    4: "Batch (scheduled task)",
    5: "Service",
    7: "Unlock (screen unlock)",
    8: "NetworkCleartext (password sent in plain text — bad)",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive (cached domain creds)",
}


# ── Data Loading ───────────────────────────────────────────────────────────────

def load_events(filepath):
    """
    Load Windows events from a JSON file into a list of dicts.

    Args:
        filepath (Path): Path to the JSON events file.

    Returns:
        list[dict]: A list of event dictionaries, one per log entry.

    Python concepts: pathlib.Path, json.load(), with/open context manager.
    """

    # Path.exists() checks if the file is actually there before trying to open it
    if not filepath.exists():
        print(f"[ERROR] File not found: {filepath}")
        return []                           # return an empty list so the rest of the script doesn't crash

    with open(filepath, "r") as f:
        events = json.load(f)               # json.load() parses the entire file into a Python list/dict

    print(f"Loaded {len(events)} events from {filepath.name}\n")
    return events


# ── Detection Functions ────────────────────────────────────────────────────────

def detect_brute_force(events, threshold):
    """
    Find source IPs/users with repeated 4625 (failed logon) events.
    Also flags if a successful logon (4624) followed the failures — the worst case.

    Args:
        events (list[dict]): All parsed events.
        threshold (int): How many failures before flagging as brute force.

    Returns:
        list[dict]: Each finding as a dict with keys: ip, user, count, succeeded.

    Python concepts: defaultdict with tuple keys, set membership, list of dicts.
    """

    # Use a tuple (ip, user) as the dictionary key so we track per IP+username combo
    # defaultdict(int) means any new tuple key starts at 0
    failure_counts = defaultdict(int)

    # Track which (ip, user) combos later got a successful login
    success_pairs = set()                   # set — fast membership checks with 'in'

    for event in events:
        ip = event.get("IpAddress", "")
        user = event.get("SubjectUserName", "").lower()   # lowercase for consistent matching
        eid = event.get("EventID")

        if eid == 4625 and ip:              # failed logon with a source IP
            failure_counts[(ip, user)] += 1

        elif eid == 4624 and ip:            # successful logon
            success_pairs.add((ip, user))

    findings = []
    for (ip, user), count in failure_counts.items():
        if count >= threshold:
            findings.append({
                "ip": ip,
                "user": user,
                "count": count,
                # check if this pair also has a success — set lookup is O(1)
                "succeeded": (ip, user) in success_pairs,
            })

    # Sort worst offenders first
    return sorted(findings, key=lambda x: x["count"], reverse=True)


def detect_suspicious_processes(events):
    """
    Scan 4688 (process creation) events for suspicious executables or command-line flags.
    This is the core of process tree analysis — what ran, from where, with what arguments.

    Args:
        events (list[dict]): All parsed events.

    Returns:
        list[dict]: Each finding with keys: time, computer, user, process, cmdline, reasons.

    Python concepts: .lower() for case-insensitive matching, re.search(),
                     any() with a generator expression, list accumulation.
    """

    findings = []

    for event in events:
        if event.get("EventID") != 4688:    # only look at process creation events
            continue

        process = event.get("ProcessName", "")
        cmdline = event.get("CommandLine", "")
        reasons = []                        # list of strings explaining WHY this was flagged

        # Check if the process name matches our suspicious list
        # os.path.basename() would give us just "powershell.exe" from the full path
        # instead, we use .lower() and check if any suspicious name is in the full path string
        process_lower = process.lower()
        for sus_proc in SUSPICIOUS_PROCESSES:
            if sus_proc in process_lower:
                reasons.append(f"Suspicious process: {sus_proc}")
                break                       # one match is enough, stop checking

        # Check the command line against all our suspicious patterns
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            # re.search() returns a match object if found, or None — truthy/falsy
            if re.search(pattern, cmdline, re.IGNORECASE):  # re.IGNORECASE = case-insensitive
                reasons.append(f"Suspicious argument pattern: {pattern}")

        if reasons:                         # only add to findings if something was flagged
            findings.append({
                "time": event.get("TimeCreated"),
                "computer": event.get("Computer"),
                "user": event.get("SubjectUserName"),
                "process": process,
                "cmdline": cmdline,
                "reasons": reasons,         # list of all the reasons this was flagged
            })

    return findings


def detect_lateral_movement(events):
    """
    Flag 4648 events (explicit credential logon) — a common indicator of lateral movement.
    Attackers use stolen creds to authenticate to other machines in the network.

    Args:
        events (list[dict]): All parsed events.

    Returns:
        list[dict]: Each 4648 event as a finding dict.

    Python concepts: list comprehension as a filter, dict.get() with defaults.

    SOC Note:
        4648 alone isn't an alert — admins use explicit creds legitimately.
        It becomes suspicious when correlated with a prior brute force or
        unusual source IP. This is why SIEM correlation rules exist.
    """

    # List comprehension used as a filter — only keep 4648 events
    return [
        {
            "time": e.get("TimeCreated"),
            "computer": e.get("Computer"),
            "user": e.get("SubjectUserName"),
            "target_ip": e.get("IpAddress"),
            "logon_type": LOGON_TYPE_MAP.get(e.get("LogonType", 0), "Unknown"),
        }
        for e in events
        if e.get("EventID") == 4648
    ]


# ── Reporting ──────────────────────────────────────────────────────────────────

def print_report(brute_findings, process_findings, lateral_findings):
    """
    Print a structured report to the terminal, organized by severity.

    Args:
        brute_findings (list[dict]): Output of detect_brute_force().
        process_findings (list[dict]): Output of detect_suspicious_processes().
        lateral_findings (list[dict]): Output of detect_lateral_movement().

    Returns:
        None — side-effect function (output only).

    Python concepts: f-strings with formatting, nested loops, conditional
                     string construction, '\n'.join() for list-to-string.
    """

    print("=" * 65)
    print("  WINDOWS EVENT LOG — THREAT ANALYSIS REPORT")
    print("=" * 65)

    # ── Brute Force ──────────────────────────────────────────────
    print("\n[1] BRUTE FORCE DETECTION (Event ID 4625 → 4624)\n")

    if brute_findings:
        for f in brute_findings:
            # Severity changes based on whether the brute force succeeded
            severity = "[!!] CRITICAL" if f["succeeded"] else "[!]  HIGH"
            outcome = "SUCCEEDED — account likely compromised" if f["succeeded"] else "no successful logon yet"
            print(f"  {severity}")
            print(f"  Source IP : {f['ip']}")
            print(f"  Username  : {f['user']}")
            print(f"  Failures  : {f['count']}")
            print(f"  Outcome   : {outcome}\n")
    else:
        print("  None detected.\n")

    # ── Suspicious Processes ──────────────────────────────────────
    print("[2] SUSPICIOUS PROCESS EXECUTION (Event ID 4688)\n")

    if process_findings:
        for f in process_findings:
            print(f"  [!] {f['time']} | {f['computer']} | User: {f['user']}")
            print(f"      Process : {f['process']}")
            print(f"      CmdLine : {f['cmdline']}")
            # '\n'.join() converts a list to a single string with newlines between items
            reasons_str = "\n      ".join(f["reasons"])
            print(f"      Flagged : {reasons_str}\n")
    else:
        print("  None detected.\n")

    # ── Lateral Movement ─────────────────────────────────────────
    print("[3] LATERAL MOVEMENT INDICATORS (Event ID 4648)\n")

    if lateral_findings:
        for f in lateral_findings:
            print(f"  [!] {f['time']} | {f['computer']} | User: {f['user']}")
            print(f"      Target IP  : {f['target_ip']}")
            print(f"      Logon Type : {f['logon_type']}")
            print()
    else:
        print("  None detected.\n")

    print("=" * 65)
    print("  SOC NOTE: Correlate findings across all 3 sections.")
    print("  A brute force win (section 1) + lateral movement (section 3)")
    print("  from the same IP = high-confidence intrusion chain.")
    print("=" * 65 + "\n")


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    """
    Orchestrates the full analysis pipeline.

    Python concepts: tuple unpacking, calling functions in sequence,
    pathlib.Path for file handling.
    """

    events = load_events(EVENTS_FILE)

    if not events:                          # guard clause — stop early if no data loaded
        return

    brute_findings    = detect_brute_force(events, BRUTE_FORCE_THRESHOLD)
    process_findings  = detect_suspicious_processes(events)
    lateral_findings  = detect_lateral_movement(events)

    print_report(brute_findings, process_findings, lateral_findings)


if __name__ == "__main__":
    main()
