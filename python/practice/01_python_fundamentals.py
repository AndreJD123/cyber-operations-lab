"""
Python Fundamentals Practice
=============================
Covers the core Python concepts used in security scripting.
Work through each section, read the comments, then try modifying
the examples to make sure you understand them.

Concepts covered:
    1. Variables and data types
    2. Strings and f-strings
    3. Lists and loops
    4. Dictionaries
    5. Functions
    6. File I/O
    7. Conditionals
"""

# ── 1. Variables and Data Types ────────────────────────────────────────────────

ip_address = "192.168.1.50"     # str  — text, always in quotes
failed_attempts = 7             # int  — whole number
threshold = 3.5                 # float — decimal number
is_suspicious = True            # bool — True or False (capital T/F in Python)

# type() tells you what type a variable is — useful for debugging
print(type(ip_address))         # <class 'str'>
print(type(failed_attempts))    # <class 'int'>


# ── 2. Strings and F-Strings ───────────────────────────────────────────────────

# Old way (string concatenation) — avoid this, it gets messy
alert_old = "IP " + ip_address + " had " + str(failed_attempts) + " attempts"

# Modern way: f-strings — embed variables directly with {}
alert = f"IP {ip_address} had {failed_attempts} failed attempts"
print(alert)

# Useful string methods you'll use constantly in log parsing
raw_line = "  Mar 25 10:01:01 server sshd[1001]: Failed password  \n"
print(raw_line.strip())         # removes leading/trailing whitespace and \n
print(raw_line.lower())         # converts to lowercase — useful for case-insensitive matching
print("failed" in raw_line.lower())  # 'in' checks if a substring exists — returns True/False


# ── 3. Lists and Loops ─────────────────────────────────────────────────────────

# A list is an ordered collection — use [] to define it
suspicious_ips = ["192.168.1.50", "203.0.113.7", "198.51.100.22"]

# for loop — iterate over every item in the list
for ip in suspicious_ips:
    print(f"  Flagged: {ip}")

# append() adds an item to the end of a list
suspicious_ips.append("10.0.0.99")

# len() returns the count of items
print(f"Total suspicious IPs: {len(suspicious_ips)}")

# List comprehension — build a new list by transforming or filtering another
# Read as: "give me each ip, for each ip in the list, if it starts with 192"
internal_ips = [ip for ip in suspicious_ips if ip.startswith("192")]
print(f"Internal range IPs: {internal_ips}")


# ── 4. Dictionaries ────────────────────────────────────────────────────────────

# A dictionary maps keys to values — like a lookup table
# This is how you'd store structured data parsed from a log line
event = {
    "ip": "192.168.1.50",
    "user": "admin",
    "status": "FAILED",
    "attempts": 5,
}

# Access a value by its key
print(event["ip"])              # "192.168.1.50"

# .get() is safer — returns None instead of crashing if key doesn't exist
print(event.get("port"))        # None  (no "port" key exists)
print(event.get("port", 22))    # 22    (use a default value instead of None)

# Add or update a key
event["severity"] = "HIGH"

# Loop over a dictionary's key-value pairs
for key, value in event.items():
    print(f"  {key}: {value}")


# ── 5. Functions ───────────────────────────────────────────────────────────────

def is_brute_force(ip, failed_count, threshold=3):
    """
    Decide if an IP's failure count crosses the brute force threshold.

    Args:
        ip (str): The source IP address.
        failed_count (int): Number of failed login attempts.
        threshold (int): Minimum failures to be flagged. Defaults to 3.

    Returns:
        bool: True if the IP is suspicious, False otherwise.

    Python concept: functions with default argument values.
    """
    # A function takes inputs, does work, and returns an output
    if failed_count >= threshold:
        print(f"[ALERT] {ip} exceeded threshold with {failed_count} attempts")
        return True     # return exits the function and sends a value back to the caller
    return False


# Call the function and store its return value
result = is_brute_force("192.168.1.50", 7)
print(result)           # True

# Use the default threshold (3)
result2 = is_brute_force("10.0.0.1", 2)
print(result2)          # False


# ── 6. File I/O ────────────────────────────────────────────────────────────────

# Writing a file
# 'w' mode = write (creates file, overwrites if it exists)
with open("practice_output.txt", "w") as f:
    f.write("IP Analysis Results\n")           # \n = newline character
    f.write(f"Checked IP: {ip_address}\n")

# Reading a file back
# 'r' mode = read
with open("practice_output.txt", "r") as f:
    contents = f.read()     # reads the entire file as one string
    print(contents)

# Reading line by line (better for large files — doesn't load everything into memory)
with open("practice_output.txt", "r") as f:
    for line in f:
        print(f"Line: {line.strip()}")


# ── 7. Conditionals ────────────────────────────────────────────────────────────

attempt_count = 9

# if / elif / else — only one branch runs
if attempt_count >= 10:
    severity = "CRITICAL"
elif attempt_count >= 5:
    severity = "HIGH"       # this branch runs — 9 >= 5
elif attempt_count >= 3:
    severity = "MEDIUM"
else:
    severity = "LOW"

print(f"Severity: {severity}")  # HIGH

# Ternary (one-line if/else) — useful for simple assignments
# Read as: value_if_true if condition else value_if_false
label = "suspicious" if attempt_count > 3 else "normal"
print(f"Label: {label}")
