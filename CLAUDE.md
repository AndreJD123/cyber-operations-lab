# Project Context

## Who I Am
- Security Operations Intern at Trellix — emerging SME in DLP and Insider Risk
- Masters in Cyber & Information Security (NSA-designated CAE university)
- Daily tools: Trellix Helix (in-house SIEM), Trellix SOAR/IPS, Wiz,
  Okta Admin, Google Admin, AWS GuardDuty, Jira, Admin By Request
- Current cert: Security+. Considering CySA+ or an AI cert next
- Python level: beginner-to-intermediate. Using AI as a vibe coding assistant,
  not a crutch — goal is to understand everything that gets written.

## Strengths
- Attacker mindset — naturally thinks about how things can be abused
- Strong conceptual/theoretical security knowledge (Masters-level)
- DLP and Insider Risk domain expertise

## Weaknesses Claude Should Actively Help Address
- Telemetry and log logic — translate raw logs into plain meaning
- Backend/how things actually work — explain what's happening under the hood,
  not just what the dashboard shows
- Benign vs malicious — call out when something in code or logs would look
  normal vs suspicious in a real environment
- Linux/Windows fundamentals — explain OS concepts when they come up in code
- SIEM query logic — no experience yet; build toward it incrementally

## Career Direction
Long-term (20-25 years): corporate cybersecurity → high-stakes/mission-oriented
work (federal, military, cyber operations, nation-state threat focus).
Not staying in SOC. Considering cloud security, cloud engineering, red team,
or purple team as the next step.

Priority skills to build:
1. Cloud security / cloud engineering (AWS free-tier account available)
2. AI security, agentic workflows, AI-assisted development
3. Red team or purple team capabilities
4. Backend coding fluency — move beyond dashboards and pre-built queries
5. Leverage DLP/Insider Risk SME as a differentiator

## How to Tailor Responses
- Connect projects to real tools already in use (GuardDuty, Wiz, Okta, SIEM)
- Frame new concepts against the conceptual knowledge already there —
  bridge theory to execution
- Favor approaches that build toward cloud engineering or detection engineering
- Always explain the why behind code decisions, not just the what
- When explaining logs or process behavior, anchor to real attacker techniques

# Coding Rules
- Always add inline comments explaining what each line does
- After writing any function, add a short docstring explaining: what it
  does, what arguments it takes, and what Python concept it demonstrates
- Prefer readability over cleverness — I'm here to learn

# Explanation Style
- After generating code, summarize the key Python concepts used
- If you make a design choice, briefly explain why
- Flag anything that could be done multiple ways and note the tradeoff

# File Structure
cyberlab/
├── python/
│   ├── scripts/        # finished security tools (push to GitHub)
│   ├── practice/       # Python learning exercises (push to GitHub)
│   ├── datasets/       # sample logs and data files
│   └── venv/           # local only — never push
├── bash/               # bash scripts
├── powershell/         # powershell scripts
├── sigma/              # sigma detection rules
├── yaml/               # yaml configs
├── docker/             # docker stuff
├── logs/               # raw log samples
├── notes/              # cheatsheets and script summaries (push to GitHub)
└── aws/                # local only — never push

# Placement Rules
- New Python security scripts → python/scripts/
- Learning/practice files    → python/practice/
- Sample data and logs       → python/datasets/
- Cheatsheets and notes      → notes/
- Never push: venv/, aws/, awscliv2.zip, .env files

# Notes Automation Rules
After writing ANY new script in python/scripts/:
1. Add a row to notes/scripts-overview.md with:
   - Script filename
   - One sentence on what it does
   - Key Python concepts it demonstrates
   - MITRE ATT&CK technique if applicable (e.g. T1110 — Brute Force)

After introducing ANY new Python concept in a script or practice file:
2. Add it to notes/python-cheatsheet.md if it isn't already there:
   - Section header matching the concept name
   - Minimal working code example
   - One-line comment explaining why it's useful in security scripting

Do both of these automatically — do not ask, do not wait to be told.
