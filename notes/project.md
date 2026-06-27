# Project Backlog — AWS-Native Detection & Response Pipeline

These phases build ONE integrated lab, in order. Each maps to a specific skill gap.
**Rule:** ephemeral infra — `terraform up`, work, `terraform destroy`.

---

## Phase 1 — Telemetry Foundation
**Skill gap:** ingestion, APIs, IaC

Terraform an AWS lab: VPC (NO NAT gateway), one EC2, CloudTrail → S3,
VPC Flow Logs + DNS logs. Enable GuardDuty (foundational tier only).

**Goal:** Understand what each log source actually contains and how it flows
through the pipeline before writing a single query or rule.

**Status:** Not started

---

## Phase 2 — Searches from Scratch
**Skill gap:** query building (Athena SQL)

Query CloudTrail in Athena with raw SQL — no copied queries.
Build 5 detections by hand:
- Impossible-travel-ish logins
- New IAM user creation
- Risky API calls
- S3 bucket policy change
- Root account usage

**Goal:** Write a detection search from a blank page and explain every clause.

**Status:** Not started

---

## Phase 3 — Detection-as-Code + Tuning
**Skill gap:** rule logic, FP/FN reasoning, Sigma

Author Sigma rules, convert with pySigma to Athena/SQL backend.
For each rule, document the FP/FN tradeoff and threshold reasoning.

**Goal:** Defend why a rule fires, how you'd tune it down, and what you'd accept
as noise versus what you'd chase.

**Status:** Not started

---

## Phase 4 — Enrichment + Triage
**Skill gap:** APIs, auth, automation (boto3 + requests)

Python script: pull a GuardDuty or Security Hub finding, enrich via
VirusTotal / AbuseIPDB / GreyNoise, score it, output a structured triage summary.

**Goal:** Explain auth flows, rate limits, pagination, and error handling from memory.

**Status:** Not started

---

## Phase 5 — Integration + Dashboards
**Skill gap:** tool-to-tool integration, dashboard design

Route findings: GuardDuty → Security Hub → EventBridge.
Optional SIEM layer: Wazuh on a small EC2 (free, real alerting), build a dashboard.

**Goal:** Explain what each panel surfaces, why it's there, and what alert it would
generate in a real SOC.

**Status:** Not started

---

## Phase 6 — Serverless IR (Capstone)
**Skill gap:** automation, end-to-end pipeline ownership

EventBridge rule triggers a Lambda on a specific finding → auto-enrich or
auto-contain (e.g., tag + quarantine the instance).

**Goal:** Whiteboard the full pipeline end-to-end without notes — from raw event
to automated response.

**Status:** Not started

---

## Rules of Engagement
- Maintain `DECISIONS.md` throughout every phase.
- After each phase, do a no-notes walkthrough out loud before moving on.
- Capture every bug + fix as an interview "war story" — what broke, why, how you found it.
- Ephemeral infra only. `terraform destroy` before closing a session.
- No NAT Gateway. No idle instances. Check AWS Budget before each session.
