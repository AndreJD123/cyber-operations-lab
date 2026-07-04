# Architecture Review — AWS Detection Lab (July 2026)

**Reviewer stance:** skeptical senior detection engineer. Design review only — no code
or Terraform was changed. Written so a future session (or a cheaper model) can execute
against it without needing the original conversation.

**Sources read:**
- `notes/project.md` — the 6-phase AWS-Native Detection & Response Pipeline backlog
- `aws/terraform-vpc-portfolio/` — main.tf, variables.tf, README (the only Terraform in the repo)
- `python/soc-automation-toolkit/DECISIONS.md` — decision-logging style and prior tradeoffs
- `notes/progress-log.md` — sessions 1–8
- Root `README.md`

**Companion file:** a defense worksheet (kept local, untracked) — the owner must attempt
its questions **before** reading Section 5 (reviewer's positions) of this document.

---

## 0. Finding zero: the plan of record does not contain the plan

Before any technical critique — the architecture I was asked to review is not in the repo.

- **n8n** appears in zero files. It exists only in an AI chat conversation.
- **Athena** appears only as a phase title in `notes/project.md`. There is no table DDL,
  no partitioning strategy, no query-results bucket, no statement of how detection queries
  get *executed* (by what, on what schedule, with results going where).
- **Wazuh** is one line: "Optional SIEM layer: Wazuh on a small EC2."
- The Terraform that exists (`terraform-vpc-portfolio`) is a *different project* — a
  portfolio networking piece. It does not implement Phase 1 (no VPC Flow Logs, no DNS
  query logs, no GuardDuty, single-region trail). Nothing in the repo says whether
  Phase 1 extends it or starts fresh.

**Why this bites:** every phase decision currently lives in chat context that evaporates.
When Phase 4 starts in September, "why did we pick n8n?" has no answer on disk, and the
next AI session will happily re-litigate or contradict it. A real detection team would
call this "tribal knowledge in Slack threads" — the thing design docs exist to kill.

**Disposition:** this document and the roadmap updates it recommends *are* the fix.
Rule going forward: **if a tool or architecture choice isn't in the repo, it isn't
decided.** Chat output is a draft until committed.

---

## 1. Is CloudTrail → S3 → Athena wired the way a real detection team would do it?

**Short answer: the storage half is respectable; the detection half doesn't exist yet,
and the plan currently confuses the two.**

### 1.1 What's actually production-shaped in the existing Terraform

Credit where due — these match real practice and are worth defending in interviews:

- Bucket policy with `GetBucketAcl` + scoped `PutObject` under `/AWSLogs/<account>/` with
  the `bucket-owner-full-control` condition — this is the AWS-documented minimum, and the
  `depends_on` ordering (public access block → policy → trail) shows understanding of the
  race condition.
- Log file validation enabled (tamper evidence).
- Full public access block + SSE on the audit bucket.
- No NAT Gateway, no Elastic IP, `my_ip` with no default. Cost discipline is real here.

### 1.2 Where it diverges from how a real team wires it

1. **Athena without partitioning is a full-bucket scan every query.** At lab scale that's
   pennies — the problem isn't the bill, it's that Phase 2's stated goal is "learn Athena
   from a blank page," and the blank page a real team starts from is a `CREATE EXTERNAL
   TABLE` with **partition projection** on `region` and `date`. CloudTrail's key layout
   (`AWSLogs/<account>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/`) exists precisely so query
   engines can prune. Skipping partitioning doesn't simplify the lesson; it teaches the
   anti-pattern that makes real CloudTrail lakes unusably expensive. The partition-projection
   DDL *is* Phase 2, lesson one.

2. **Athena needs its own query-results bucket.** Every Athena query writes results to an
   S3 output location. That's a second bucket, and it needs a lifecycle rule (expire
   results after ~7 days) or it accumulates forever. Not in the plan anywhere.

3. **Batch SQL over S3 is *hunting*, not *detection* — and the plan conflates them.**
   CloudTrail delivers to S3 in batches, typically every ~5 minutes, up to ~15. Athena is
   a query-on-demand engine. Nothing in this pipeline *fires*. A real team splits the
   paths:
   - **Near-real-time detection:** CloudTrail management events → EventBridge rules
     (seconds of latency), or GuardDuty findings → EventBridge. This is where "root
     account usage" and "new IAM user" belong — you do not want to discover root usage
     at the next scheduled Athena run.
   - **Scheduled/retro detection + hunting:** Athena over the S3 archive — impossible
     travel, slow-burn patterns, IR lookback.

   Phase 2's five detections currently all live on the Athena side. At least two of them
   (root usage, IAM user creation) are single-event, zero-aggregation patterns that a real
   team implements as EventBridge rules. Keeping them in Athena is fine *as SQL practice*,
   but the roadmap should name them as hunting queries, not detections, until §1.2.4 exists.

4. **Nothing executes the rules — see Bite #1 in Section 4.** This is the biggest gap and
   gets its own section.

5. **Smaller real-team deltas, acknowledged as acceptable lab scope** (know them for
   interviews):
   - Single-region trail (`is_multi_region_trail = false`) — a real team runs an
     **organization trail** into a dedicated log-archive account. Lab: fine as-is.
   - `force_destroy = true` on the audit bucket — directly contradicts the
     "tamper-evident logs" story in the README. Anyone with Terraform rights can vaporize
     the evidence *and* its digests. Acceptable for a lab, but the README shouldn't claim
     insider-threat relevance without noting this hole.
   - No S3 lifecycle/retention policy on the trail bucket.
   - Athena workgroup with `bytes_scanned_cutoff_per_query` is the AWS-native cost
     guardrail — cheap insurance that fits the existing cost rules.

### 1.3 The portfolio-VPC question nobody has answered

`terraform-vpc-portfolio` is a finished portfolio artifact with its own public repo.
Phase 1 needs Flow Logs, DNS logs, GuardDuty, and (per Section 4, Bite #3) a
persistent/ephemeral split. Bolting all that onto the portfolio project mutates a
published artifact and tangles two different stories. **Recommendation: freeze the
portfolio repo; build the detection lab as a new stack (e.g. `aws/detection-lab/`).**
Reuse the *knowledge*, not the state file.

---

## 2. Where does Wazuh actually fit vs. where it's been assumed to fit?

**Assumed fit (per `notes/project.md` Phase 5):** "SIEM layer" capping the AWS pipeline —
the thing that gives "real alerting" and a dashboard.

**Actual fit: Wazuh is a host-based agent platform** (log collection, FIM, rootkit/vuln
detection) with a manager + indexer + dashboard stack bolted on. Its center of gravity is
*endpoint telemetry*, not cloud-API telemetry.

Three problems with the assumed fit:

1. **It creates a second, parallel analytic store.** Yes, Wazuh's AWS module can pull
   CloudTrail from S3 — but then the same events live in two places (Athena tables and
   the Wazuh indexer), and detection logic lives in two languages (Athena SQL from Phase
   2/3 and Wazuh's XML rules). Phase 3's Sigma investment converts cleanly to *neither*
   Wazuh XML nor Athena without a field-mapping layer (see Bite #1). A real team picks
   one analytic plane per data source; two planes means every tuning decision is made
   twice and drifts.

2. **It cannot honor the lab's own rules of engagement.** Wazuh's all-in-one deployment
   wants roughly 4 vCPU / 8 GB — that is not a free-tier t2.micro; it's a ~$30+/month
   instance. And an indexer is *stateful*: `terraform destroy` every session (the lab's
   own rule) wipes its data, so it either becomes the idle pet instance the guardrails
   explicitly forbid, or it's rebuilt empty every session and never accumulates enough
   data to be interesting.

3. **The phase's actual skill target doesn't need it.** Phase 5's goal is "explain what
   each panel surfaces and why." That's achievable with what's already in the pipeline:
   Security Hub's own views, CloudWatch dashboards, or Athena + a lightweight viewer —
   with zero new infrastructure.

**Where Wazuh legitimately fits, if at all:** as a *host telemetry* source — an agent on
the lab EC2 feeding auth logs and FIM events, i.e. the Linux-side complement to
CloudTrail's control-plane view. That's a genuinely good purple-team exercise (SSH brute
force detected from *both* the host and network angle). But the manager should then run
**locally in Docker on WSL2** (free, survives `terraform destroy`, honors the
bind-to-localhost guardrail), with only the lightweight agent in AWS.

**Verdict:** demote Wazuh from "SIEM layer of the pipeline" to "optional host-telemetry
sidecar, local Docker manager, only if Phase 5's AWS-native path leaves appetite."

---

## 3. Is n8n the right SOAR-lite layer, or a tool before its time?

**Verdict: a tool before its time — and possibly the wrong tool for this event source
even when the time comes.**

1. **The plan already contains a SOAR-lite layer.** Phase 4 is Python enrichment
   (boto3 + requests, auth, rate limits, pagination). Phase 6 is EventBridge → Lambda →
   auto-contain. That *is* the orchestration layer, built from parts you're trying to
   learn. n8n would sit on top of — or worse, replace — the exact plumbing the roadmap
   exists to teach. The root README's own words: "no pre-built rules, no dashboard
   clicks." A drag-and-drop workflow canvas is a dashboard click.

2. **The skill-gap math is backwards.** The CLAUDE.md gap list is APIs, auth, webhooks,
   EventBridge/Lambda glue. Writing the Lambda that calls VirusTotal with backoff and
   pagination closes those gaps. Wiring an n8n HTTP node teaches n8n. The transferable
   asset at work (Trellix SOAR) is understanding *what the boxes do underneath* — which
   is exactly what hand-rolling Phase 4/6 provides.

3. **The event source lives in AWS; the responder should too.** GuardDuty findings are
   born in EventBridge. EventBridge → Lambda is one IAM role, zero network exposure,
   ~zero cost. EventBridge → *self-hosted n8n* requires the finding to leave AWS and
   reach your workflow engine: either n8n runs on an EC2 with a public webhook (violates
   the never-expose-publicly guardrail and the no-idle-instances rule), or it runs
   locally and you tunnel inbound (ngrok-class exposure of your home machine), or you
   poll (now it's not event-driven). Every option is worse than the Lambda.

4. **Credential surface.** n8n stores third-party API keys (VirusTotal, AbuseIPDB) in
   its own credential store — one more stateful secret store to protect, back up, and
   not commit.

**When n8n *would* earn its place:** after Phase 6 works end-to-end, if you want a
capstone-plus demonstrating multi-SaaS orchestration with human-in-the-loop approval
steps (e.g. Slack approve/deny before quarantine) — run locally in Docker, fed by
polling or SQS, as a *comparison piece* against your Lambda ("I built both; here's the
tradeoff"). That's a genuinely strong interview artifact. As a load-bearing pipeline
component in Phases 4–6: no.

---

## 4. Top 3 design decisions most likely to bite in Phases 4–6

### Bite #1 — Detection rules with no execution layer (bites hardest in Phase 5–6)

**The decision as it stands:** Phase 2 writes Athena SQL. Phase 3 authors Sigma and
converts it to Athena SQL. Phase 6 triggers Lambda from *GuardDuty findings only*.
Nothing anywhere schedules, runs, or routes the results of the SQL detections.

**Failure mode, played forward:** Phase 3 ends with a `sigma/` folder of rules and a
pile of converted SQL. In Phase 5 you build a dashboard and realize the only things
*alerting* are GuardDuty's canned findings — your hand-built detections from two phases
of work are inert files. You hastily bolt on a scheduler (EventBridge Scheduler → Lambda
→ `StartQueryExecution`) and immediately hit the problems you never designed for:
Where do query results go? What marks an event as already-alerted, so the same finding
doesn't re-fire on every 15-minute run (dedup/watermark state)? What's the lookback
window per rule? None of that is in the Sigma files because Phase 3 didn't know it was
needed. Best case: a rushed, unloved runner. Worst case: the capstone quietly narrows to
"Lambda reacts to GuardDuty" and the detection-engineering half of the lab never actually
detects anything.

**Secondary failure inside the same decision:** the Sigma → Athena conversion path is
assumed, not verified. pySigma's maintained backends do not obviously include
Athena/Trino SQL; and even where a SQL backend exists, the real work is the **field
mapping** (Sigma's `cloudtrail` logsource taxonomy → your actual table's column names).
If that's discovered mid-Phase-3, the phase stalls.

**Fix (proposed, not applied):**
- Decide *now*, in the roadmap, that the execution layer is: EventBridge Scheduler →
  a single generic "rule-runner" Lambda → Athena `StartQueryExecution` → results to a
  findings S3 prefix / SNS, with a last-run watermark in DynamoDB (or an S3 marker
  object). Total cost: effectively $0. This also *is* the Phase 4 boto3 curriculum —
  pagination, async query polling, error handling — so it replaces contrived exercises
  with a real component.
- Split Phase 2's five detections by latency class: root usage + IAM user creation →
  EventBridge real-time rules; impossible travel, risky API patterns, S3 policy changes →
  scheduled Athena.
- Add rule metadata (schedule, lookback, threshold, dedup key) as custom fields in each
  Sigma rule from day one of Phase 3.
- Before Phase 3 starts, spike one Sigma rule end-to-end through pySigma to confirm the
  backend and field mapping exist. If they don't, the fallback (generic SQL backend +
  hand-maintained mapping file) is chosen *before* the phase, not during it.

### Bite #2 — "Ephemeral everything" vs. a pipeline whose value is accumulated state (bites in Phases 2 and 4)

**The decision as it stands:** rules of engagement say `terraform destroy` before ending
every session — applied to the *entire* stack.

**Failure mode, played forward:** Phase 2, session one: you deploy, wait for CloudTrail
to deliver, and query… 45 minutes of your own Terraform API calls. The impossible-travel
query has one principal, one IP, one region — there is nothing to detect and no way to
reason about false positives, which was the entire point of Phase 3. Meanwhile GuardDuty:
its 30-day free trial is a one-time clock per account/region — destroying and re-enabling
the detector doesn't reset it, so repeated teardowns burn the trial while the detector
spends each session's first hours baselining an empty account. By Phase 4 there are no
organic findings to enrich (workaround exists — `CreateSampleFindings` — but that should
be a *choice*, not a surprise). Athena tables, Glue database, and partitions get rebuilt
every session; historical data — the raw material of every interesting query — never
exceeds a few hours' depth.

**Fix (proposed, not applied):** split the Terraform into two stacks with different
lifecycles:
- **`persistent/`** — CloudTrail + its bucket, Athena/Glue database + results bucket,
  GuardDuty detector, EventBridge rules. Standing cost: realistically under $1/month
  (first trail free, S3 pennies, GuardDuty free-tier then a few dollars for a quiet
  account — check the bill after the trial and decide).
- **`ephemeral/`** — VPC, EC2, security groups, flow logs. Destroyed every session,
  exactly per the existing rule.

Amend the rule of engagement to: "destroy *compute* every session; the data plane
persists." This split is itself an interview-grade pattern (state/lifecycle separation)
and belongs in DECISIONS.md when adopted.

### Bite #3 — Wazuh scoped as the pipeline's SIEM layer (bites in Phase 5)

**The decision as it stands:** Phase 5 lists Wazuh-on-EC2 as the "optional SIEM layer"
providing real alerting and the dashboard.

**Failure mode, played forward:** Phase 5 begins; the t2.micro OOMs the indexer, so a
t3.medium gets spun up "temporarily" (~$30/month if it survives a forgotten destroy —
the exact idle-pet scenario the guardrails prohibit). Weeks go into Wazuh *operations* —
indexer health, agent enrollment, rule syntax — none of which is the phase's stated skill
gap (dashboard design and tool-to-tool integration). CloudTrail gets ingested a second
time into the indexer, and the Phase 2/3 detection logic is either duplicated in Wazuh
XML or abandoned. The phase's calendar box is consumed by a SIEM appliance instead of the
EventBridge → Security Hub integration work that feeds Phase 6. Detection teams have a
name for this: the SIEM migration that ate the roadmap.

**Fix (proposed, not applied):** Phase 5's primary path goes AWS-native — GuardDuty →
Security Hub → EventBridge, dashboard via Security Hub insights and/or CloudWatch
dashboards over the pipeline's own metrics (findings by severity, rule fire counts from
Bite #1's runner, enrichment latency). Wazuh, if kept at all, is re-scoped per Section 2:
manager in local Docker, agent on the lab EC2, as a host-telemetry comparison exercise —
and it moves to a stretch goal *after* Phase 6, alongside n8n in the same "second
implementation for comparison" bucket.

---

## 5. Reviewer's positions (read only after attempting the defense worksheet)

Condensed verdicts, given the defenses I'd expect:

| Question | Position |
|---|---|
| CloudTrail → S3 wiring | Keep. Production-shaped for a single account. Add: partition-projection DDL, results bucket + lifecycle, workgroup scan cap, latency-split of detections. |
| Athena as detection engine | Reframe: Athena = scheduled/hunting plane; EventBridge = real-time plane. Both are needed; the plan currently only has the first and calls it detection. |
| Wazuh | Demote to optional post-Phase-6 host-telemetry exercise, manager local. It is not the pipeline's SIEM layer. |
| n8n | Defer past Phase 6 entirely; then only as a local, comparison-piece orchestrator. Lambda is the SOAR-lite layer of record. |
| Portfolio VPC as Phase 1 base | Freeze it; new `aws/detection-lab/` stack with persistent/ephemeral split. |
| Biggest single risk | Bite #1. A detection lab where nothing executes the detections isn't a detection lab yet — it's a data lake with opinions. |

**Explicitly out of scope for this review:** no Terraform, roadmap, or code files were
modified. Adopting any fix above is a separate, deliberate step that should land in
`notes/project.md` and a DECISIONS.md entry — after the worksheet is done.
