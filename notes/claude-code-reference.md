# Claude Code Reference

How to get the most out of Claude Code in this lab.

---

## Prompt Patterns That Work Well

### Build a script
```
Build me a Python script that [what it does] using [data/file].
Explain each section after.
```

### Explain existing code
```
Explain what this function does line by line and what I'd see
in a real SOC environment if this ran.
```

### Debug an error
```
Getting this error: [paste full error]
Here's the relevant code: [paste code]
```

### Extend a script
```
Add a feature to [script name] that [new behavior].
Keep the same style and comment everything.
```

### Learn a concept
```
Show me an example of [Python concept] in a security context.
Explain why you'd use it over the alternative.
```

### Connect to real work
```
What would this script's output look like as a Helix alert?
What MITRE technique does this map to?
```

---

## Slash Commands

| Command | What it does |
|---|---|
| `/help` | List all available commands |
| `/clear` | Clear conversation context (start fresh) |
| `/compact` | Summarize conversation to save context space |
| `/cost` | Show how many tokens the session has used |

---

## How Claude Code Remembers Context

- **This conversation** — Claude remembers everything said in the current session
- **CLAUDE.md** — Loaded every session automatically. This is your persistent instruction file. Any rule you add there applies forever.
- **memory/ folder** — Stores facts about you across sessions (role, goals, tools, weaknesses to address)
- **When context resets** — Start a new session by opening Claude Code fresh. It re-reads CLAUDE.md and memory automatically.

---

## What to Add to CLAUDE.md

When you find yourself repeating the same instruction to Claude, add it to CLAUDE.md instead.

Examples:
- "Always show benign vs malicious comparison when writing detection scripts"
- "When I say 'build a script', also create sample data to run it against"
- "Always map new scripts to a MITRE ATT&CK technique"

---

## Tips

**Be specific about what you already know**
Instead of: "explain regex"
Say: "explain regex — I know what pattern matching is conceptually but haven't written it in Python"

**Reference your own files**
"Look at ssh_bruteforce_detector.py and add the same threshold logic to this new script"

**Ask for the SOC angle**
"What would an analyst actually do with this output in a real investigation?"

**Ask what you're missing**
"What would a senior detection engineer add to this script that I haven't thought of?"
