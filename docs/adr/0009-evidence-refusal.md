# ADR 0009 — Evidence gate and deterministic refusal (D7)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r4-hybrid-retrieval.md, r6-injection-detection.md

## Decision

- **Evidence gate**: authorized chunks (post-RRF, post-optional-rerank, RLS rehydrated) form the
  Evidence Bundle that may enter answer generation. A bundle enters generation only when it passes
  a calibrated answerability check computed from labeled fixtures (composite: authorized count,
  calibrated relevance, coverage of the query's entities, citation-ability) — never raw scores.
- **Refusal** (stable codes) — deterministic, model cannot override:
  - `INSUFFICIENT_EVIDENCE`: no authorized evidence; only foreign/revoked/expired/PII-blocked
    evidence exists; or evidence below calibrated threshold.
  - `CONFLICTING_EVIDENCE`: authorized evidence materially conflicts and cannot support the claim.
  - `CITATION_UNSUPPORTED`: generated answer makes a material claim without an authorized,
    resolvable citation.
- **Generation contract**: answer model has no general tools; retrieved content cannot alter
  filters, query scope, provider destinations, system rules, or citation IDs. The model never
  answers from memory/general knowledge; it may answer only from the Evidence Bundle. Bounded
  regeneration/review runs at most twice, then refuse.
- **Citation verifier** (deterministic, independent of the generating model): every material claim
  must cite ≥1 bundle chunk (document/version/chunk/span); resolving a citation rechecks current
  authorization and authorization epoch.
- **Before the first response byte**: authorization epoch rechecked. Non-streaming responses are
  the v1 default; any stream rechecks between bounded frames and stops after revocation.
- Audit-write or evidence-gate failure returns no answer.

## Consequences

- "Deny everything" cannot pass the suite: positive controls require ≥95% authorized-answer success
  on answerable fixtures; required-refusal recall is 100% on the labeled refusal set.
