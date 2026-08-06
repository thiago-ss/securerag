# SecureRAG Adversarial Evaluation — v1.0.0

Generated: 2026-08-06T13:03:32.955Z  ·  Corpus version: g4-1  ·  Seed: 1592642302

## Security metrics

| Metric | Value |
| --- | --- |
| Total unique end-to-end cases | 1702 |
| unauthorized_context (model-context events) | 0 |
| unauthorized_disclosures | 0 |
| pii_leaks | 0 |
| audit_isolation_failures | 0 |
| refusal_recall | 1211/1211 |
| authorized_answer_success | 106/106 |

## Category counts (v1 release gate = >=1,200 unique end-to-end queries)

| Category | Count | Minimum |
| --- | --- | --- |
| Cross-tenant retrieval, forged IDs/claims, IDOR | 209 | 200 |
| User/group/document ACL and role boundaries | 280 | 150 |
| Versions, deletion, revocation, retention | 184 | 100 |
| Session, pool, worker, expansion, cache | 184 | 150 |
| Direct/indirect injection, encoding, multi-turn | 208 | 200 |
| Citations, source, preview, download, export, logs, audit | 217 | 100 |
| Browser, cancellation, error, streaming | 200 | 100 |
| PII redaction and provider boundary | 115 | 100 |
| Insufficient/conflicting/foreign-only evidence | 105 | 100 |
| **Total** | **1702** | **1200** |

## Additional gates

- Property gate: 10,000 seeded operation sequences; every retrieved and model-context id is a subset of the independent authorization oracle (zero counterexamples).
- Load gate: 100 concurrent workers × 100 operations on a shared least-privilege pool with mid-run churn; zero cross-tenant bleed.
- Mutation gate: all nine required security mutants make the suite fail (tenant predicate, forced RLS, owner membership, WITH CHECK, epoch state key, citation authorization, stale version vector, raw PII logging, generation without evidence).
- RLS/catalog, direct-policy, two-stage-bootstrap, refusal, PII, citation-verifier, and E2E suites run against real PostgreSQL 18.4 + pgvector 0.8.6 as the actual least-privileged runtime roles.

## Truthful claim

> Zero observed unauthorized disclosures in 1,702 executed adversarial queries for the release commit; image digest, migrations, configuration, model/provider versions, corpus manifest, and seeds are listed in the release report.

This is a finite test executed against a specific build; it is not a mathematical proof and no certification (SOC 2, ISO 27001, HIPAA, GDPR, FedRAMP) is claimed.

## Committed artifacts

- `apps/api/openapi.yaml` — generated OpenAPI 3.1 contract
- `docs/threat-model.md`, `docs/adr/*`, `docs/contracts/*`, `docs/ops/*` — threat model, ADRs, contracts, runbooks
- `CONTEXT.md` — domain language and invariants

The adversarial JSON/Markdown reports are regenerated per run and are gitignored; this sanitized summary is the public evaluation record.
