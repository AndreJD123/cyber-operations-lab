# Design Decisions — AWS-Native Detection & Response Pipeline

Per CLAUDE.md conventions: log what was chosen vs rejected, why, tradeoff, interview
talking point. Roadmap lives in `notes/project.md`; design review that prompted the
first entries lives in `docs/architecture-review-2026-07.md`.

---

## 2026-07-04 — Persistent/ephemeral stack split (implemented)

**Chose:** Two Terraform stacks in separate directories with independent state files: `aws/detection-lab/persistent/` (CloudTrail trail + evidence bucket, Glue database, Athena results bucket + workgroup — applied once, lives for months) and a future `ephemeral/` (VPC, EC2, flow logs — destroyed every session).
**Rejected:** One stack with `-target` destroys (error-prone, fights the tool); keeping the all-ephemeral rule (session one of Phase 2 would have ~45 minutes of history to query and GuardDuty would baseline an empty account forever).
**Why:** Terraform can only destroy what's in the state file it's pointed at, so a destroy in `ephemeral/` is physically incapable of touching the log archive. The pipeline's value is accumulated history; the compute that generates telemetry is disposable.
**Tradeoff:** Two directories to manage and some duplicated boilerplate (providers, tags). Standing cost of the persistent layer: pennies/month (first trail free, S3 with 90-day expiry).
**Interview talking point:** "I isolate blast radius with state separation — my teardown command is physically unable to delete evidence, not just instructed not to."

---

## 2026-07-04 — force_destroy asymmetry across sibling buckets

**Chose:** `force_destroy = false` on the CloudTrail evidence bucket; `force_destroy = true` on the Athena results bucket.
**Rejected:** Uniform `true` (a `terraform destroy` could vaporize months of evidence as a side effect — watched exactly that happen to the portfolio stack's logs the same morning); uniform `false` (pointless friction on disposable query scratch).
**Why:** The setting should follow the data's role. Evidence deletion must be a deliberate, manual act (empty the bucket yourself, then destroy); scratch CSV results expire in 7 days anyway.
**Tradeoff:** A deliberate teardown of the persistent stack requires one extra manual step. That friction is the feature.
**Interview talking point:** "Same setting, opposite values, each defended — retention posture is a property of the data, not of the stack."

---

## 2026-07-04 — GuardDuty deferred to the Phase 3/4 boundary

**Chose:** No GuardDuty detector in the persistent stack yet; add it (a two-line change) when Phase 3 wraps.
**Rejected:** Enabling now for baseline-building — the one-time, non-resettable 30-day free trial would burn during weeks of Athena/Sigma work that consumes zero findings.
**Why:** Capability should arrive when its consumer exists (same test that cut n8n and deferred CI/CD). The trial window should overlap Phases 4–6, which actually consume findings; `CreateSampleFindings` covers any gap.
**Tradeoff:** No organic anomaly baseline on day one of Phase 4. Acceptable — sample findings and CloudTrail-based detections carry that phase.
**Interview talking point:** "I sequence tooling by named problem, not by resume keyword — three times in one week the same test made the call."

---

## 2026-07-04 — IAM for IaC: service-scoped managed policies + minimal inline patches

**Chose:** For the `cyberlab` CLI group: AWS-managed service-scoped policies (`AmazonEC2FullAccess`, `AWSCloudTrail_FullAccess`, `AmazonAthenaFullAccess`) plus a 3-action inline patch (`glue-tagging`: GetTags/TagResource/UntagResource) where the managed policy has a pothole.
**Rejected:** `AdministratorAccess` (unbounded blast radius on a long-lived credential); hand-rolled minimal policies (Terraform needs symmetric CRUD — the deny→add-one-action→retry loop was measured today at one failed apply per missing service).
**Why:** IaC tooling needs broad rights within the services it manages. Compensating controls: zero-spend budget, short sessions, no other principals. Production answer is a pipeline role with OIDC, permission boundaries, and SCPs — this is the single-human lab approximation.
**Tradeoff:** A leaked `bluelab-cli` key can run arbitrary EC2 compute. Mitigated, not eliminated.
**Interview talking point:** "AmazonAthenaFullAccess famously omits glue:GetTags — Terraform's post-create tag read fails and taints the resource. I read the managed policy's JSON now, not its name."

---

## 2026-07-03 — n8n dropped from pipeline scope

**Chose:** EventBridge + Lambda as the only orchestration/SOAR-lite layer (Phases 4 and 6).
**Rejected:** Self-hosted n8n as a workflow layer in the pipeline.
**Why:** n8n was never a planned design decision — it entered via a work conversation, not the roadmap. The event source (GuardDuty findings) is born in EventBridge; reaching a self-hosted n8n requires a public webhook, a tunnel to a home machine, or polling — each violates the lab's own guardrails (no public exposure, no idle instances) or breaks event-driven design. And the skill gap being closed is the plumbing itself (auth, retries, pagination in the Lambda), which a drag-and-drop node abstracts away.
**Tradeoff:** Lose a GUI for quick workflow prototyping and a résumé keyword. Revisit after Phase 6 as an optional local-Docker comparison piece ("built both, here's the tradeoff") — not as a load-bearing component.
**Interview talking point:** "I cut a tool from the design because the event source lived in AWS and the responder should too — EventBridge to Lambda is one IAM role, zero network exposure, near-zero cost. Every n8n option added attack surface or broke the event-driven model."

---

## 2026-07-03 — Wazuh re-scoped: local Docker manager, cloud agent, post-Phase-6

**Chose:** Wazuh manager/indexer/dashboard in Docker on WSL2 (localhost, $0), lightweight agent enrolled from the lab EC2; sequenced after Phase 6 as a host-telemetry comparison exercise.
**Rejected:** Wazuh all-in-one on an EC2 as the pipeline's "SIEM layer" (original Phase 5 plan); dropping Wazuh entirely.
**Why:** The manager stack wants ~4 vCPU / 8 GB — a ~$30/month instance, not free tier — and its stateful indexer either becomes the idle pet the cost guardrails forbid or gets wiped by the per-session `terraform destroy` rule. Ingesting CloudTrail into it would also duplicate the analytic store (Athena + indexer) with rules in two languages. The local-Docker split keeps every résumé-relevant task — deployment, agent enrollment over the network, decoders, custom rules, dashboards — at zero standing cost, and it's a genuinely distributed deployment (cloud agent → local manager).
**Tradeoff:** Not a cloud-hosted SIEM deployment, and WSL2 must spare ~6 GB RAM while it runs. Acceptable: the differentiator vs. daily Helix work is standing a SIEM up from scratch, which Docker fully delivers.
**Interview talking point:** "Open source means license-free, not cost-free — you pay in compute and operations. I split the deployment so the stateful, memory-hungry part runs where compute is free and the cloud only hosts the lightweight agent. Same configuration experience, zero standing cost, and it honors my own cost guardrails."

---

## Lab-wide tooling decisions (not AWS-pipeline-specific)

This file is titled for the AWS pipeline, but it's the only root-level DECISIONS.md
in the repo, so decisions about lab-wide (non-project-specific) tooling land here too.

---

## 2026-08-11 — Secret-scanning: kept the existing raw pre-commit hook over the pre-commit framework

**Chose:** The existing `~/.git-hooks/pre-commit` script (repo's `core.hooksPath` points there), running `gitleaks protect --staged --redact -v`. Already in place since 2026-07-03; re-verified today by staging a fake AWS key — caught, exit code 1, commit would have been blocked.
**Rejected:** Installing the `pre-commit` framework (Python venv + checked-in `.pre-commit-config.yaml`, local hook wrapping the same `gitleaks` binary). Built it first, then deleted it once the pre-existing hook turned out to do identical work.
**Why:** Same protection, extra dependency surface — a venv, a symlink, and a PATH edit — for zero functional gain over a 6-line script already wired in. Matches this repo's existing bias against adding tooling without a reason (see the toolkit's own stdlib-only decision).
**Tradeoff:** The raw script lives at `~/.git-hooks/pre-commit` — machine-local, not checked into the repo. A fresh clone on another machine gets zero secret-scanning until this hook is manually recreated; the pre-commit-framework config would have traveled with the repo. This is also the argument for still adding gitleaks/trivy to GitHub Actions later — CI-side scanning doesn't depend on any one machine's local hook being present or `--no-verify` not being used.
**Interview talking point:** "Before adding a tool, I checked whether the problem was already solved — it was, from a session a month earlier. Duplicate tooling costs more than the few minutes it took to notice and verify."

---

## Career / learning-direction decisions

Not tooling — these are decisions about the roadmap and target role itself, logged
here because `~/.claude/CLAUDE.md` (where the direction lives) isn't a project and
doesn't carry its own DECISIONS.md.

---

## 2026-08-14 — Career/learning direction reset

**Chose:** SOC as the base, not a permanent destination — Senior Analyst → security engineer for the SOC → open from there. Target shape: a security engineer who codes and works on AI/agent development, shipped through Docker/Kubernetes, then AI-driven automation; cloud security stays a named interest alongside that. Insider-threat detection engineering (DLP/insider-risk background) reframed explicitly as a career differentiator, not a direction being pursued. Learning priority order locked: Python depth (log parsing, dicts/sets, file I/O, APIs, error handling, tests, FastAPI) → LangGraph in depth / LangChain conceptually / MCP+RAG → GitHub Actions as its own session → Docker → Kubernetes only once something needs orchestrating → AWS as the sole portfolio cloud.
**Rejected:** Finance sector and GRC-style risk/compliance work (documentation- and audit-heavy) — both explicitly ruled out. Also rejected: letting insider-risk/DLP expertise pull the roadmap toward more DLP-administration-flavored work — it stays framed as detection engineering, not administration.
**Why:** The prior direction language ("interested in cloud security, AI/agentic development") named no target role and no exclusions, which left room for well-meaning but off-path suggestions to look like progress. Naming what's ruled out is as load-bearing as naming what's chosen.
**Tradeoff:** Locks in an ordered roadmap that resists "shiny new tool" reprioritization — a real cost if, say, a Kubernetes opportunity shows up before Python/LangGraph are done. Mitigated by an explicit rule: new roadmap items must state what they'd displace, not just get appended.
**Interview talking point:** "I hold my own learning roadmap to the same discipline as project design — ordered priorities, explicit exclusions, and a documented reason for the order, not just a wish list."

---

## 2026-08-14 — Same-day refinement: SOC timeline made explicit, IR named as possible interim step

**Chose:** Sharpened the entry above same day — not staying in SOC long term (was previously the softer "not a permanent destination"); Incident Response named as a possible interim step before the security-engineering/AI-agent-development target; the "Senior Analyst → security engineer for the SOC" path language dropped in favor of "SOC now → possibly IR for a while → security engineering with AI/agent development."
**Rejected:** Leaving the original phrasing as-is — "not a permanent destination" was true but vague enough to not actually commit to a timeline or name IR as a real interim possibility.
**Why:** The first pass at today's reset undersold how not-long-term the SOC stay actually is, and left out IR as a concrete interim step the user is actually considering.
**Tradeoff:** None new — this narrows the same-day entry above rather than reversing it.
**Interview talking point:** "Even my own roadmap gets revised same-day when the first draft undersells the timeline — I'd rather correct it in an hour than carry an inaccurate plan for a month."
