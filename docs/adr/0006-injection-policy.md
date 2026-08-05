# ADR 0006 — Prompt-injection policy (D4)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r6-injection-detection.md, OWASP LLM01/LLM02

## Decision

**Defense-in-depth stack** (model-independent first; detection is never authorization):
1. Authorization and tenant isolation — deterministic RLS/default-deny (`Allowed(P,T)`).
2. Retrieved content is data — immutable IDs, delimiters; content cannot alter filters, query
   scope, provider destinations, system rules, or citation IDs.
3. Answer model has no tools / no function calling / no code execution.
4. Output constraints — structured, citation-anchored, deterministically validated.
5. Egress containment — only the approved provider endpoint.
6. Ingestion quarantine gate — default-quarantine high-risk versions.
7. Query-time detection on prompt + chunks (defense-in-depth only).
8. Deterministic refusal + human review, immutable audit.
9. Adversarial testing gate (1,200-query suite).

**Detector seam**: `injection-detector` provider interface with (a) a deterministic heuristic
adapter (instruction-like patterns, encoding/unicode tricks, control patterns) used in CI and
demo, and (b) at least one documented real adapter (self-hosted classifier, e.g. Llama Guard /
llm-guard) with the same interface. Turning detection off never weakens authorization.

**Quarantine flow**: scan at ingest (deterministic + classifier) → `QUARANTINED` by default on any
high-risk signal → excluded from index/embeddings/evidence bundles, indistinguishable from foreign
resources → tenant security reviewer may explicitly and audited-ly approve release (new status
`RELEASED`) or keep quarantined; both are immutable Audit Events; re-scan can re-quarantine.
Quarantined versions never become searchable.

## Consequences

- A detector miss or total detection outage leaves tenant isolation intact.
- Quarantine/review is a human gate with full audit trail; UI shows quarantine state and review
  flow.

## Amendment (S5 review) — accepted service-layer gating

- The `document_versions` RLS policy is tenant-scope-only; the reviewer gate (`security_reviewer` role OR tenant admin) is enforced at the service layer with audit + epoch bump, not by a DB policy (a status-transition CHECK is noted for future hardening). Ingest paths must call `reviewQuarantine`/`quarantineVersion` through the core seams so transitions always bump the epoch and audit.
- `quarantineVersion` is intentionally ungated (ingest-worker contract); `reviewQuarantine` is the only reviewer-gated transition.
