"""
log_parser.py — SSH Auth Log Analyzer
Reads a mock SSH log file, detects failed login attempts,
counts failures per IP, and flags suspicious sources.
"""

import re                    # built-in module for regular expressions
import sys                   # built-in module to access command-line arguments


# --- Constants ---
FAILURE_THRESHOLD = 3        # flag any IP with more than this many failures
LOG_FILE = "mock_ssh.log"    # default log file to parse


def parse_failed_logins(filepath):
    """
    Reads a log file and returns a dict mapping each IP to its failure count.

    Args:
        filepath (str): Path to the SSH log file to read.

    Returns:
        dict: Keys are IP address strings, values are integer failure counts.

    Python concepts: file I/O with 'with' statement, loops, regex, dicts.
    """
    failure_counts = {}      # dict to store {ip_address: count} pairs

    # Regex pattern to match "Failed password" lines and capture the IP
    # Breakdown:
    #   Failed password  — literal text we're looking for
    #   .*               — any characters (the username part)
    #   from\s+          — the word "from" followed by whitespace
    #   ([\d.]+)         — capture group: one or more digits or dots (the IP)
    pattern = re.compile(r"Failed password.*from\s+([\d.]+)")

    # 'with open' ensures the file is closed automatically after the block,
    # even if an error occurs — safer than manually calling file.close()
    with open(filepath, "r") as log_file:

        for line in log_file:            # iterate over each line in the file
            match = pattern.search(line) # search anywhere in the line for the pattern

            if match:                    # if the pattern was found on this line...
                ip = match.group(1)      # group(1) extracts the first capture group (the IP)

                # dict.get(key, default) returns the current count or 0 if key doesn't exist yet
                failure_counts[ip] = failure_counts.get(ip, 0) + 1

    return failure_counts               # hand the completed dict back to the caller


def flag_suspicious(failure_counts, threshold):
    """
    Filters the failure dict and returns only IPs that exceed the threshold.

    Args:
        failure_counts (dict): IP-to-failure-count mapping from parse_failed_logins().
        threshold (int): Minimum number of failures to be considered suspicious.

    Returns:
        dict: Subset of failure_counts where count > threshold.

    Python concepts: dict comprehension, comparison operators.
    """
    # Dict comprehension: builds a new dict from items that pass the filter.
    # Equivalent to a for-loop that checks each item and adds it if it qualifies.
    return {ip: count for ip, count in failure_counts.items() if count > threshold}


def print_report(failure_counts, suspicious_ips, threshold):
    """
    Prints a formatted summary report to the terminal.

    Args:
        failure_counts (dict): All IPs and their failure counts.
        suspicious_ips (dict): IPs that exceeded the failure threshold.
        threshold (int): The threshold value, used in the report header.

    Returns:
        None

    Python concepts: f-strings, string multiplication for separators,
                     dict iteration, conditional logic.
    """
    separator = "-" * 45    # string * int repeats the string — quick way to make a line

    print(separator)
    print("  SSH FAILED LOGIN REPORT")
    print(separator)

    print(f"\n{'IP Address':<20} {'Failures':>8}")   # f-string with alignment formatting
    print(f"{'----------':<20} {'--------':>8}")     # <20 = left-align in 20 chars, >8 = right-align in 8

    # Sort by failure count descending so the worst offenders appear first.
    # sorted() with key=lambda returns a new sorted list without changing the original.
    for ip, count in sorted(failure_counts.items(), key=lambda x: x[1], reverse=True):
        # Conditional expression (ternary): value_if_true if condition else value_if_false
        flag = "  <-- SUSPICIOUS" if ip in suspicious_ips else ""
        print(f"{ip:<20} {count:>8}{flag}")

    print(separator)
    print(f"\nTotal unique IPs with failures : {len(failure_counts)}")
    print(f"Suspicious IPs (> {threshold} failures): {len(suspicious_ips)}")

    if suspicious_ips:                                # truthy check: non-empty dict = True
        print("\n[!] Suspicious IPs to investigate:")
        for ip in suspicious_ips:                    # iterate over dict keys
            print(f"    - {ip}  ({suspicious_ips[ip]} failures)")

    print(separator)


def main():
    """
    Entry point: wires together parsing, flagging, and reporting.

    Args:
        None (reads sys.argv for an optional filepath argument).

    Returns:
        None

    Python concepts: sys.argv for CLI args, calling functions in sequence,
                     the 'if __name__ == "__main__"' guard pattern.
    """
    # sys.argv is a list: [script_name, arg1, arg2, ...]
    # If the user passes a file path as the first argument, use it; otherwise use the default.
    filepath = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE

    print(f"\nParsing log file: {filepath}\n")

    failure_counts = parse_failed_logins(filepath)   # step 1: read and count
    suspicious_ips = flag_suspicious(failure_counts, FAILURE_THRESHOLD)  # step 2: filter
    print_report(failure_counts, suspicious_ips, FAILURE_THRESHOLD)      # step 3: display


# This guard prevents main() from running if this file is imported as a module.
# When run directly (python log_parser.py), __name__ equals "__main__".
if __name__ == "__main__":
    main()
