"""
SSH Brute Force Detector
========================
Reads an SSH auth log, identifies IPs with repeated failed login attempts,
and flags them as potential brute force attackers.

Run it:
    python ssh_bruteforce_detector.py

SOC Context:
    SSH brute force is one of the top initial-access techniques (MITRE T1110).
    This script automates what an analyst would do manually in a SIEM:
    count failures per source IP and threshold on suspicious volume.
"""

import re                  # 're' is Python's regex library — used for pattern matching in log lines
from collections import defaultdict  # a dict that auto-creates a default value for new keys

# ── Configuration ─────────────────────────────────────────────────────────────

LOG_FILE = "../datasets/mock_ssh.log"   # path to the log file we're analyzing

# How many failed attempts before we flag an IP as suspicious
# Tradeoff: lower = more sensitive (more false positives), higher = less noise
BRUTE_FORCE_THRESHOLD = 3


# ── Core Functions ─────────────────────────────────────────────────────────────

def parse_log_line(line):
    """
    Extract structured data from a single SSH log line.

    Args:
        line (str): A raw log line string, e.g.:
                    'Mar 25 10:01:01 server sshd[1001]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2'

    Returns:
        dict: A dictionary with keys 'status', 'user', 'ip', 'timestamp'
              if the line matches a known pattern, or None if it doesn't match.

    Python concepts: regex named groups, re.search(), returning None as a sentinel value.
    """

    # Regex pattern for FAILED login lines
    # Named groups (?P<name>...) let us pull out parts by name instead of position
    failed_pattern = re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+)"   # e.g. "Mar 25 10:01:01"
        r".+Failed password for (?:invalid user )?"  # optional "invalid user" prefix
        r"(?P<user>\w+) from (?P<ip>[\d.]+)"     # captures username and IP address
    )

    # Regex pattern for SUCCESSFUL login lines
    success_pattern = re.compile(
        r"(?P<timestamp>\w+ \d+ \d+:\d+:\d+)"
        r".+Accepted password for (?P<user>\w+) from (?P<ip>[\d.]+)"
    )

    # re.search() scans the whole string for a match (vs re.match() which only checks the start)
    failed_match = failed_pattern.search(line)
    success_match = success_pattern.search(line)

    if failed_match:
        # .groupdict() returns a dict of all named groups from the regex
        result = failed_match.groupdict()
        result["status"] = "FAILED"    # add a status key so callers know what type this is
        return result

    if success_match:
        result = success_match.groupdict()
        result["status"] = "SUCCESS"
        return result

    return None  # line didn't match either pattern — skip it


def analyze_log(filepath):
    """
    Read the entire log file and build a summary of activity per IP.

    Args:
        filepath (str): Path to the SSH log file to analyze.

    Returns:
        tuple: (failed_counts, success_ips, all_events)
               - failed_counts: dict mapping IP -> number of failed attempts
               - success_ips: set of IPs that had at least one successful login
               - all_events: list of all parsed event dicts

    Python concepts: file context managers (with/open), defaultdict, sets, list accumulation.
    """

    # defaultdict(int) means any new key starts at 0 automatically
    # vs a regular dict where you'd need: if ip not in d: d[ip] = 0
    failed_counts = defaultdict(int)

    # A set stores unique values only — perfect for "did this IP ever succeed?"
    success_ips = set()

    all_events = []  # list to hold every parsed event dict

    # 'with open(...)' is a context manager — it automatically closes the file when done
    # even if an exception occurs. Always prefer this over open()/close() pairs.
    with open(filepath, "r") as log_file:

        for line in log_file:           # iterate line by line (memory efficient — doesn't load whole file)
            line = line.strip()         # remove leading/trailing whitespace and newline characters

            if not line:                # skip blank lines
                continue

            parsed = parse_log_line(line)  # try to extract structured data

            if parsed is None:          # line didn't match any known pattern
                continue

            all_events.append(parsed)   # save the event

            if parsed["status"] == "FAILED":
                failed_counts[parsed["ip"]] += 1   # increment failure counter for this IP

            elif parsed["status"] == "SUCCESS":
                success_ips.add(parsed["ip"])      # add to the set of IPs with a successful login

    return failed_counts, success_ips, all_events


def detect_brute_force(failed_counts, threshold):
    """
    Filter IPs that exceed the failure threshold.

    Args:
        failed_counts (dict): IP -> failure count mapping.
        threshold (int): Minimum failures to be flagged as suspicious.

    Returns:
        list of tuples: [(ip, count), ...] sorted by count descending (worst offenders first).

    Python concepts: dict.items(), list comprehensions, sorted() with a key function, lambda.
    """

    # List comprehension: concise way to build a list by filtering another iterable
    # Equivalent to a for loop with an if condition
    suspicious = [
        (ip, count)                          # what to keep: a tuple of (ip, count)
        for ip, count in failed_counts.items()  # iterate over each IP and its count
        if count >= threshold                # only include IPs above the threshold
    ]

    # sorted() returns a new sorted list — it doesn't modify the original
    # key=lambda x: x[1] means "sort by the second element of each tuple" (the count)
    # reverse=True means highest count first
    return sorted(suspicious, key=lambda x: x[1], reverse=True)


def check_successful_after_failures(suspicious_ips, success_ips):
    """
    Identify IPs that failed many times AND eventually succeeded.
    This is the most critical finding — it suggests a successful brute force.

    Args:
        suspicious_ips (list): List of (ip, count) tuples from detect_brute_force().
        success_ips (set): Set of IPs with at least one successful login.

    Returns:
        list: IPs that appear in both — high severity alerts.

    Python concepts: set intersection via 'in', list comprehension filtering.
    """

    # Extract just the IP strings from the suspicious list (not the counts)
    suspicious_ip_set = {ip for ip, _ in suspicious_ips}  # set comprehension, _ means "I don't need this value"

    # Find IPs in both sets — these are the dangerous ones
    compromised = suspicious_ip_set & success_ips   # & is set intersection in Python

    return list(compromised)


def print_report(suspicious_ips, compromised_ips, failed_counts, success_ips):
    """
    Print a formatted summary report to the terminal.

    Args:
        suspicious_ips (list): IPs that exceeded the failure threshold.
        compromised_ips (list): IPs that failed many times then succeeded.
        failed_counts (dict): Full failed attempt counts per IP.
        success_ips (set): IPs with a successful login.

    Returns:
        None — this function is purely for output (a "side effect" function).

    Python concepts: f-strings, string formatting, print(), conditional logic.
    """

    print("=" * 60)
    print("  SSH BRUTE FORCE DETECTION REPORT")
    print("=" * 60)

    # ── High Severity: Failed then Succeeded ──────────────────────
    if compromised_ips:
        print("\n[!!] HIGH SEVERITY — Brute Force + Successful Login:")
        print("     These IPs failed repeatedly THEN got in.\n")
        for ip in compromised_ips:
            # f-strings (f"...") embed variables directly in strings — much cleaner than concatenation
            print(f"     IP: {ip}  |  Failed attempts: {failed_counts[ip]}")
    else:
        print("\n[OK] No IPs with failed attempts followed by success.")

    # ── Medium Severity: Only Failures ────────────────────────────
    print(f"\n[!]  SUSPICIOUS IPs (>= {BRUTE_FORCE_THRESHOLD} failed attempts):\n")

    if suspicious_ips:
        # Print a simple table header
        print(f"     {'IP Address':<20} {'Failed Attempts':>15}")
        print(f"     {'-'*20} {'-'*15}")

        for ip, count in suspicious_ips:
            # :<20 means left-align in a 20-char wide column
            # :>15 means right-align in a 15-char wide column
            flag = " <-- ALSO SUCCEEDED" if ip in success_ips else ""
            print(f"     {ip:<20} {count:>15}{flag}")
    else:
        print("     None found.")

    # ── Successful Logins ─────────────────────────────────────────
    print(f"\n[i]  Successful logins from: {', '.join(success_ips) if success_ips else 'none'}")

    print("\n" + "=" * 60)
    print(f"  Threshold used: {BRUTE_FORCE_THRESHOLD} failed attempts")
    print("=" * 60 + "\n")


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    """
    Orchestrates the full analysis pipeline.

    Python concepts: calling functions in sequence, tuple unpacking,
    and the if __name__ == '__main__' pattern (see bottom of file).
    """

    print(f"\nAnalyzing: {LOG_FILE}\n")

    # Tuple unpacking — assign multiple return values from one function call
    failed_counts, success_ips, all_events = analyze_log(LOG_FILE)

    suspicious_ips = detect_brute_force(failed_counts, BRUTE_FORCE_THRESHOLD)

    compromised_ips = check_successful_after_failures(suspicious_ips, success_ips)

    print_report(suspicious_ips, compromised_ips, failed_counts, success_ips)

    print(f"Total log lines parsed: {len(all_events)}")


# ── Guard ──────────────────────────────────────────────────────────────────────

# This block only runs when you execute this file directly (python script.py)
# It does NOT run if another script imports this file as a module.
# This is a Python best practice — it makes your functions reusable.
if __name__ == "__main__":
    main()
