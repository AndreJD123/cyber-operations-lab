# Security Engineering Roadmap — Annotated Skill Map

Skills get checked off by **shipping project milestones**, not by studying topics.
This tree is the checklist; the project backlog is the actual roadmap.

**Legend**
- ✅ **done** — shipped artifact or daily competence; can defend it in an interview
- 🔨 **in-progress** — an active project is touching it right now
- 🎯 **next** — earned by the next queued milestone
- ⏳ **later** — deliberately deferred; mapped to the future project that earns it
- 🏢 **work** — competence from the day job; counts as experience but needs a
  synthetic/lab replication before it appears in a portfolio repo

**Active projects that earn nodes:**
- **Toolkit** = SOC Automation Toolkit (M1 ✅ · M2 hardening · M3 batch/NDJSON · M4 STIX loader)
- **Lab** = AWS detection lab (Phase 1 deployed ✅ · P2 Athena queries · P3 Sigma · P4 boto3 enrichment)
- **Template** = claude-eng-template (spec/threat-model/decision discipline, reusable skills)
- **Harness** = agent control plane, `~/dev/harness` (spec/threat-model/5 ADRs ✅ · ⏸️ **parked** 2026-08-17, pending Python/REST/Linux fundamentals — no implementation code yet)

---

## Engineering Fundamentals (Build First)

### Programming
- Python — 🔨 Toolkit (1,300 lines, 115 tests) + practice files; walkthrough rounds 1–5 are the "can defend it" gate
- PowerShell — ⏳ needs rebuild from basics; earn via Windows telemetry scripts when Windows-side lab work starts
- Bash — 🔨 picked up incrementally every lab session (WSL is the daily driver)

### Software & Development
- Git / GitHub — ✅ multiple repos, branching, hooks (gitleaks), template repos, credential rotation
- REST APIs — 🔨 GitHub API hands-on (repo creation via curl + token auth); deepens at Lab P4 (boto3, AbuseIPDB/VirusTotal)
- Webhooks — ⏳ Toolkit M3+ / future SOAR-style glue
- JSON — ✅ Toolkit is JSON parsing end-to-end (5 vendor schemas → normalized schema)
- YAML — 🎯 Lab P3 (Sigma rules are YAML)
- Docker — ⏳ future lab services; awareness only for now
- CI/CD fundamentals — ⏳ earn by adding a GitHub Actions pytest workflow to Toolkit (cheap, high-signal — good M2/M3 add-on)

### Authentication & Identity
- OAuth — ✅ 2026-07-07 rotation: OAuth app tokens vs PATs, scopes, revoke-vs-erase, token prefixes
- API Keys / tokens — ✅ same exercise: fine-grained PAT, least privilege, encrypted storage (GCM)
- JWT — ⏳ earn when building an API integration that uses bearer JWTs (Lab P4 candidate)
- SAML — 🏢 Okta admin exposure; lab replication low priority
- OpenID Connect — ⏳ pairs with SAML; awareness level fine

### Systems
- Windows — 🏢 + ⏳ event log fundamentals practiced once; rebuild alongside PowerShell
- Linux — 🔨 every session (WSL, permissions, credential helpers, filesystems)
- macOS basics — ⏳ awareness only; no lab hardware, lowest priority
- Networking fundamentals — 🔨 Lab P1 (VPC, subnets, flow-log design decisions); Security+ theory behind it

### Data
- SQL basics — 🎯 **Lab P2 is literally this**: CREATE EXTERNAL TABLE + first hand-written Athena queries
- Databases — ⏳ comes with SQL depth; partition projection at P2 is the first real concept

---

## Core Identity — Security Engineering

### Detection Engineering
- Detection logic — 🎯 Lab P2 (first hand-written detections: AccessDenied by principal, root usage, console logins)
- Detection-as-Code — ⏳ Lab P3 (Sigma + pySigma, rules in git)
- SIEM content development — ⏳ deferred with the Wazuh decision; Athena queries are the interim equivalent
- Detection tuning / FP reduction / rule optimization — 🎯 sec-review skill's detection mode enforces this framework (logic → evasion → FP profile → cost → testability) on every rule written
- MITRE ATT&CK mapping — 🔨 Toolkit M1 (curated 10-technique DB); deepens with every detection written
- Sigma rules — ⏳ Lab P3
- YARA basics — ⏳ pairs with the parked malware-analysis track, not before

### Telemetry
- Cloud telemetry — 🔨 Lab P1 done (CloudTrail → S3, real events accumulating); P2 queries it
- Windows Event Logs — ⏳ one practice script exists; rebuild deliberately with Sysmon
- Sysmon — ⏳ future Windows telemetry lab (pairs with PowerShell rebuild)
- Linux telemetry — ⏳ auditd/syslog lab candidate after P2 teaches the query layer
- EDR telemetry — 🏢 daily triage + Toolkit parses synthetic EDR; deep-dive later
- Network telemetry — ⏳ VPC flow logs (Lab ephemeral stack candidate)
- macOS telemetry — ⏳ lowest priority

### DLP & Insider Risk (SME differentiator — was missing from the draft)
- DLP detection logic — 🏢 SME at work + Toolkit's DLP parser/scoring (prior-violation factor) is the first lab artifact
- Insider-risk analytics (UEBA concepts) — 🏢 + ⏳ future flagship candidate: synthetic insider-risk detection pipeline — this is the portfolio piece nobody else in the stack of resumes has
- Data-classification-aware detections — ⏳ same future project

### Security Automation (Primary Focus)
- Python automation — 🔨 Toolkit is this; M3 (batch triage queue) is the next rung
- API integrations — 🎯 Lab P4 (boto3 + threat-intel APIs: auth, pagination, rate limits)
- Webhook integrations — ⏳ after P4
- SOAR playbooks — 🏢 work exposure; lab equivalent = Toolkit playbooks + future EventBridge/Lambda glue
- AI agents / LLM workflows — 🔨 daily Claude Code practice (consumer side); ⏳ builder side is lab priority 4 (Claude API triage agent)
- MCP concepts — 🔨 using MCP servers now; building one = later
- Workflow orchestration — ⏳ Toolkit M3 is the seed (batch pipeline)
- Internal security tooling — 🔨 Toolkit *is* internal-tooling-shaped; template repo standardizes how the next ones get built

### Cloud Security
- AWS — 🔨 Lab P1 shipped (Terraform, stack split, force_destroy decisions); P2–P4 queued
- IAM — 🔨 IAM-for-IaC pattern logged in Lab decisions; deepens every phase
- GuardDuty — 🏢 daily use; lab enablement deliberately deferred (logged decision — cost)
- Wiz — 🏢 work only; concepts transfer to any CSPM
- Cloud logging — 🔨 CloudTrail delivering now; Athena reads it at P2
- Containers / Kubernetes fundamentals — ⏳ after Docker; awareness until then
- Azure — ⏳ explicitly later; AWS depth first

---

## Incident Response (Operational Expertise)

Nearly all 🏢 — this is the day job (triage, investigations, containment
coordination, cross-domain IR). The lab's job is not to re-earn these but to
build the **engineering layer under them**:
- Log analysis — 🔨 the stated gap; every Lab phase attacks it (raw CloudTrail → meaning)
- Threat hunting — 🎯 Lab P2 queries are hunting's query-writing muscle
- Timeline reconstruction / RCA / DFIR fundamentals — 🏢 + ⏳ deepen via lab incidents replayed from own telemetry
- Containment / recovery — 🏢

---

## Supporting Knowledge (Become Competent)

### Threat Intelligence
- MITRE ATT&CK — 🔨 Toolkit mapping + every detection tagged
- OSINT / APT & ransomware groups / supply-chain / zero-day tracking — 🏢 awareness via work; no lab artifact needed yet
- Dark web awareness — ⏳ floated 2026-07-07 as personal research; if it becomes real, it gets its own threat model first (isolated VM, Tor, zero real credentials)

### Malware Analysis & Reverse Engineering
**Parked deliberately (2026-07-07)** — purpose when unparked: know what behavior
looks like so detections and tuning are grounded, not folklore.
- Static / dynamic / behavioral analysis, triage — ⏳
- Ghidra, x64dbg, assembly, binary analysis — ⏳ (furthest out)
- On-ramp when ready: analyze one sample's behavior → write the Sigma rule that catches it → validate in lab. Analysis feeds detection; that's the whole loop.

### Red Team Knowledge
- Common TTPs / attack chains — 🔨 passively, via mapping every alert and detection to ATT&CK
- Detection validation / adversary emulation — 🎯 Lab P3 (atomic red team tests against own Sigma rules)
- Vulnerability exploitation concepts — ⏳ knowledge-level only; not the destination

---

## Architectural Awareness (Understand, Don't Specialize)

Masters theory ✅ across the board; the gap is application, which accrues from
projects rather than study:
- Zero Trust / identity / network / endpoint / cloud architecture — 🏢 + theory; cloud architecture gets real via Lab decisions (stack split, trust boundaries)
- Secure software design — 🔨 Toolkit threat model (trust boundaries, untrusted input, accepted risks) is applied secure design
- Risk management — 🔨 accepted-risk sections in threat models are risk management in miniature

---

## Professional Skills (Career Multipliers)

- Technical writing / documentation — 🔨 DECISIONS.md discipline, specs, threat models, eng-docs skill enforcing standards
- STAR interview stories — 🔨 every DECISIONS.md entry ends in an interview talking point by rule; walkthrough gate converts them from written to speakable
- Executive communication / risk-to-business translation — 🏢
- Project ownership — 🔨 the backlog, the gates, the roadmap — this file included
- Presentation / mentoring / cross-functional / requirements gathering — 🏢 accrue at work

---

## AI Throughout Everything

### AI as tool (the draft had this)
- AI-assisted development, documentation, detection engineering, investigations — 🔨 daily; Claude Code + skills workflow is itself a portfolio-visible competency

### AI as attack surface (the draft was missing this — target role is AI *Security*)
- Prompt injection / tool-use exfiltration / excessive agency — 🎯 seeded already: the Toolkit threat model's LLM-stage note; becomes real at lab priority 4–5
- Model / agent threat modeling — ⏳ lab priority 5; the project-init skill already mandates it for any AI-integrated project
- Securing agentic workflows — ⏳ build the triage agent first, then threat-model and harden it — that pairing *is* the AI Security Engineer portfolio story

---

## Certification anchors (missing from the draft)
- Security+ — ✅ 2025-12-12
- CySA+ — 🎯 validates the detection-engineering tier as it completes
- AWS Security Specialty — ⏳ after Lab P3–P4 makes it cheap to earn

---

*Update rule: when a project milestone ships, flip its nodes here in the same
session. A node flips to ✅ only when the artifact exists AND it survives the
walkthrough test — same gate as the resume.*
