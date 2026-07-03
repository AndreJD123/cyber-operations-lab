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

---

## dataclass (`@dataclass`)

```python
from dataclasses import dataclass, field

@dataclass
class Alert:
    alert_id: str
    severity: str
    tags: list[str] = field(default_factory=list)   # mutable default — must use field()

# @dataclass auto-generates __init__, __repr__, __eq__
# No need to write: def __init__(self, alert_id, severity, tags=None): ...
a = Alert(alert_id="001", severity="high")
print(a)  # Alert(alert_id='001', severity='high', tags=[])
```

Use `field(default_factory=list)` for mutable defaults (lists, dicts). Without it,
ALL instances would share the SAME list — a classic Python gotcha.

---

## ABC — Abstract Base Class

```python
from abc import ABC, abstractmethod

class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw: dict) -> dict:
        ...   # subclasses MUST implement this

class EDRParser(BaseParser):
    def parse(self, raw: dict) -> dict:
        return {"source": "edr", "id": raw["alert_id"]}

# EDRParser() works fine.
# A class that inherits BaseParser but skips parse() raises TypeError at instantiation.
```

Use ABCs when you want a contract that fails fast — at class instantiation, not at call time.

---

## Factory function + dispatch table

```python
from .edr import EDRParser
from .okta import OktaParser

# Dict maps string keys to classes (not instances)
_PARSERS = {
    "edr": EDRParser,
    "okta": OktaParser,
}

def get_parser(source: str):
    cls = _PARSERS.get(source.lower())
    if cls is None:
        raise ValueError(f"Unknown source: {source}")
    return cls()   # instantiate and return
```

O(1) lookup instead of if/elif chain. Adding a new source = one new dict entry.

---

## `re.compile()` — pre-compiled regex

```python
import re

# Compile once at module load — reuse many times (faster in loops)
_RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

text = "Connection from 203.0.113.1, hash 5d41402abc4b2a76b9719d911017c592"
ips = _RE_IP.findall(text)    # ['203.0.113.1']
md5s = _RE_MD5.findall(text)  # ['5d41402abc4b2a76b9719d911017c592']
```

`findall()` returns all non-overlapping matches as a list.
`compile()` vs inline `re.findall(pattern, text)`: same result, faster in a loop.

---

## `any()` with generator expression

```python
keywords = ("admin", "svc_", "root")

# Check if ANY keyword appears in a username — short-circuits on first True
username = "svc_backup"
is_privileged = any(kw in username.lower() for kw in keywords)  # True

# Equivalent for loop (less idiomatic):
is_privileged = False
for kw in keywords:
    if kw in username.lower():
        is_privileged = True
        break
```

`any()` stops evaluating as soon as it finds a True result — efficient.

---

## `str.startswith()` with a tuple

```python
# Check multiple prefixes in ONE call — no loop needed
private_prefixes = ("10.", "192.168.", "127.", "172.16.")
ip = "192.168.1.100"

is_private = ip.startswith(private_prefixes)  # True — checks all prefixes at once
```

Much cleaner than `ip.startswith("10.") or ip.startswith("192.168.") or ...`

---

## `enumerate()` with a start value

```python
steps = ["Isolate the host", "Collect memory dump", "Search for lateral movement"]

# enumerate gives (index, value) pairs — start=1 makes it a natural numbered list
for i, step in enumerate(steps, start=1):
    print(f"  {i}. {step}")
# Output:
#   1. Isolate the host
#   2. Collect memory dump
#   3. Search for lateral movement
```

Avoids a manual counter variable (`i = 0; i += 1` pattern).

---

## Recursive function with depth limit

```python
def flatten_dict(d: dict, depth: int = 0) -> list[str]:
    """Extract all string values from a nested dict, any depth."""
    if depth > 5:          # safety valve — stop if too deep
        return []
    results = []
    for value in d.values():
        if isinstance(value, str):
            results.append(value)
        elif isinstance(value, dict):
            results.extend(flatten_dict(value, depth + 1))   # recurse
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    results.extend(flatten_dict(item, depth + 1))
    return results
```

Recursive functions call themselves. The depth limit prevents infinite recursion on
pathological inputs. Used here to extract IOC strings from deeply nested alert JSON.

---

## List comprehension with `None` filter

```python
results_or_none = [lookup(x) for x in ids]       # may contain None values
clean_results   = [r for r in results_or_none if r is not None]  # filter None out

# One-liner version:
clean = [r for r in (lookup(x) for x in ids) if r is not None]
```

Pattern: look up each item (may return None), then filter the None values in one pass.
