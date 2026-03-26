# Python Cheatsheet — Security Scripting

Quick reference for the Python concepts used in this lab.
Each section links to where it's used in practice.

---

## Variables & Data Types

```python
ip = "192.168.1.50"   # str   — text
count = 7             # int   — whole number
ratio = 3.5           # float — decimal
flag = True           # bool  — True / False (capital)

type(ip)              # check what type a variable is → <class 'str'>
```

---

## Strings

```python
# f-strings — embed variables directly (preferred)
print(f"IP {ip} had {count} attempts")

# Useful methods for log parsing
line.strip()            # remove whitespace + newlines
line.lower()            # lowercase — for case-insensitive matching
"failed" in line        # check if substring exists → True/False
line.startswith("Mar")  # check beginning of string
line.split()            # split into a list on whitespace
line.split(":")         # split on a specific character
```

---

## Lists

```python
ips = ["192.168.1.1", "10.0.0.5"]   # ordered, allows duplicates

ips.append("172.16.0.1")   # add to end
len(ips)                    # count of items
ips[0]                      # access by index (0 = first)

# Loop
for ip in ips:
    print(ip)

# List comprehension — filter or transform in one line
internal = [ip for ip in ips if ip.startswith("10.")]
```

---

## Dictionaries

```python
event = {
    "ip": "192.168.1.50",
    "status": "FAILED",
    "attempts": 5,
}

event["ip"]               # access value by key
event.get("port")         # safe access — returns None if key missing
event.get("port", 22)     # safe access — returns 22 as default
event["severity"] = "HIGH"  # add or update a key

# Loop over key-value pairs
for key, value in event.items():
    print(f"{key}: {value}")
```

---

## Sets

```python
# Unordered, unique values only — great for "has this IP appeared before?"
seen = {"10.0.0.1", "10.0.0.2"}
seen.add("10.0.0.3")
"10.0.0.1" in seen        # True

# Set intersection — items in both sets
a = {"10.0.0.1", "10.0.0.2"}
b = {"10.0.0.2", "10.0.0.3"}
both = a & b              # {"10.0.0.2"}
```

---

## defaultdict

```python
from collections import defaultdict

# Like a normal dict but auto-creates a default value for new keys
# defaultdict(int) → new keys start at 0
counter = defaultdict(int)
counter["192.168.1.50"] += 1   # no KeyError — starts at 0 automatically

# defaultdict(list) → new keys start as []
grouped = defaultdict(list)
grouped["FAILED"].append("192.168.1.50")
```

---

## Functions

```python
def check_ip(ip, threshold=3):
    """
    What it does: checks if IP crosses failure threshold.
    Args: ip (str), threshold (int, default 3)
    Returns: bool
    """
    return count >= threshold   # return sends value back to caller

result = check_ip("10.0.0.1")  # call with default threshold
result = check_ip("10.0.0.1", threshold=5)  # override default
```

---

## Conditionals

```python
if count >= 10:
    severity = "CRITICAL"
elif count >= 5:
    severity = "HIGH"
else:
    severity = "LOW"

# Ternary — one-line if/else for simple assignments
label = "suspicious" if count > 3 else "normal"
```

---

## Loops

```python
# for — iterate over a list, dict, file, etc.
for line in lines:
    print(line)

# while — repeat until condition is False (use carefully — can loop forever)
i = 0
while i < 5:
    print(i)
    i += 1

# skip current iteration
for line in lines:
    if not line.strip():
        continue          # skip blank lines

# exit loop early
for line in lines:
    if "CRITICAL" in line:
        break             # stop looping
```

---

## File I/O

```python
# Reading — line by line (memory efficient for large logs)
with open("auth.log", "r") as f:
    for line in f:
        print(line.strip())

# Reading entire file at once
with open("auth.log", "r") as f:
    contents = f.read()

# Writing
with open("report.txt", "w") as f:    # 'w' overwrites
    f.write("Analysis Results\n")

# Appending
with open("report.txt", "a") as f:    # 'a' adds to end
    f.write("New line\n")
```

---

## Regex (`re` module)

```python
import re

# search() — scan anywhere in the string, return first match or None
match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
if match:
    ip = match.group(1)   # group(1) = first capture group ()

# Named groups — pull out parts by name
pattern = re.compile(r"from (?P<ip>[\d.]+) port (?P<port>\d+)")
match = pattern.search(line)
if match:
    print(match.group("ip"))    # cleaner than match.group(1)
    print(match.groupdict())    # → {"ip": "...", "port": "..."}

# Common patterns
r"\d+"          # one or more digits
r"[\d.]+"       # digits and dots (IP address)
r"\w+"          # word characters (letters, digits, underscore)
r".+"           # any character, one or more
r"\s+"          # whitespace
```

---

## Sorting

```python
items = [("10.0.0.1", 3), ("192.168.1.1", 9), ("172.16.0.1", 1)]

# Sort by second element (count), highest first
sorted_items = sorted(items, key=lambda x: x[1], reverse=True)
# → [("192.168.1.1", 9), ("10.0.0.1", 3), ("172.16.0.1", 1)]

# lambda — a small anonymous function
# lambda x: x[1]  means  "given x, return x[1]"
```

---

## pathlib.Path

```python
from pathlib import Path

# Path objects are smarter than raw strings for file handling
filepath = Path("../datasets/windows_events.json")

filepath.exists()       # True/False — check before opening
filepath.name           # "windows_events.json" — just the filename
filepath.parent         # "../datasets" — the directory
filepath.suffix         # ".json" — the extension

# Use with open() exactly like a string
with open(filepath, "r") as f:
    data = f.read()
```

---

## json module

```python
import json

# Read JSON from a file → Python list or dict
with open("events.json", "r") as f:
    events = json.load(f)        # json.load() = file → Python object

# Read JSON from a string
data = json.loads('{"ip": "10.0.0.1"}')   # json.loads() = string → Python object

# Write Python object to a JSON file
with open("output.json", "w") as f:
    json.dump(events, f, indent=2)         # indent=2 makes it human-readable

# Convert Python object to JSON string
json_str = json.dumps({"ip": "10.0.0.1"})
```

---

## Tuple as a Dictionary Key

```python
# Regular dict keys are usually strings or ints
# Tuples can also be keys — useful for grouping by multiple fields
from collections import defaultdict

failure_counts = defaultdict(int)
failure_counts[("203.0.113.55", "administrator")] += 1  # key = (ip, username)

# Check membership in a set of tuples
success_pairs = {("10.0.0.1", "alice")}
("10.0.0.1", "alice") in success_pairs    # True — O(1) lookup
```

---

## Guard Clause (Early Return)

```python
# Instead of deeply nesting logic, return early if preconditions fail
# Makes functions easier to read — happy path is always at the bottom

def analyze(events):
    if not events:          # guard clause — stop immediately if input is empty
        return []
    # ... rest of logic runs only if events exist
```

---

## `if __name__ == "__main__"`

```python
def main():
    print("Running script")

# This block only runs when you execute the file directly:
#   python script.py
# It does NOT run when another script imports this file.
# Best practice: always wrap your entry point in this.
if __name__ == "__main__":
    main()
```
