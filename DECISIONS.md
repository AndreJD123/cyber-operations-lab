# Design Decisions — AWS-Native Detection & Response Pipeline

Per CLAUDE.md conventions: log what was chosen vs rejected, why, tradeoff, interview
talking point. Roadmap lives in `notes/project.md`; design review that prompted the
first entries lives in `docs/architecture-review-2026-07.md`.

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
