# SecureRAG

**Production-ready multitenant enterprise knowledge platform.** One shared RAG system for many
companies, where a tenant may retrieve only information authorized for the authenticated principal
inside that tenant — enforced by deterministic identity, authorization, database, and output
controls. **The model never decides authorization.**

## The problem

Retrieval-augmented generation over an org's knowledge base is only useful if it is safe to share
one platform across many tenants. Cross-tenant leakage — through retrieval, citations, previews,
exports, logs, audit views, or the model prompt itself — is a data-loss incident. SecureRAG makes
tenant isolation a **database-enforced invariant**: PostgreSQL row-level security is the security
kernel, not an application convention.

## Security model (the short version)

- Every tenant-owned table has `ENABLE` **and** `FORCE ROW LEVEL SECURITY`; the runtime roles are
  `NOSUPERUSER`/`NOBYPASSRLS`/non-owner, queried only through a verified two-stage bootstrap
  (identity → tenant context, transaction-local, never session-level).
- Default-deny document permissions for principals, groups, and tenant roles — allow-only grants.
- Authorization runs **inside SQL** before any text, embedding, rank, or identifier leaves
  PostgreSQL. Foreign and nonexistent resources are byte-identical.
- Only redacted derivatives enter embeddings, provider payloads, logs, and audit views. The model
  has no tools and never overrides refusal.
- Injection detection, PII redaction, and refusal are defense-in-depth layers; a detector failure
  never weakens authorization.

The full model: [`CONTEXT.md`](CONTEXT.md) (domain + invariants), [`docs/threat-model.md`](docs/threat-model.md)
(declared threat model + explicit exclusions), [`docs/adr/`](docs/adr/) (architecture decisions).

## What it does

1. PostgreSQL RLS on every tenant-owned table, forced on real runtime roles.
2. Default-deny document grants for users, groups, and tenant roles.
3. Hybrid semantic + full-text retrieval with deterministic Reciprocal Rank Fusion.
4. Exact, resolvable citations that re-check authorization.
5. Immutable, versioned documents with atomic publish.
6. Direct/indirect prompt-injection detection with quarantine and audited review.
7. Configurable PII detection/redaction before embedding, generation, logs, and audit views.
8. Tenant-configurable retention, legal hold, and verified deletion across derived data.
9. Complete tenant-isolated retrieval audit trail with a tamper-evident hash chain.
10. Deterministic refusal when authorized evidence is insufficient or conflicting.
11. An adversarial gate of **1,702 unique end-to-end attack queries** with zero observed
    unauthorized disclosures (v1 release gate: ≥1,200).

## Quick start (one command, no paid keys)

```bash
docker compose -f ops/compose.yml up --build
```

This starts PostgreSQL 18 + pgvector, Keycloak (synthetic identities), MinIO (encrypted objects),
the API, the worker, and the console behind a same-origin proxy, seeded with two synthetic tenants.
Log in with the demo users listed in [`ops/keycloak-demo.md`](docs/ops/keycloak-demo.md).

### Run the security suite

```bash
npm install
npm run typecheck
npm run test:security        # adversarial swarm (1,702 cases) + api + security suites
npm run test:db:catalog     # schema/RLS catalog contract (Testcontainers, real PostgreSQL)
```

See [`docs/graph-and-acceptance.md`](docs/graph-and-acceptance.md) for the full evaluation contract
(adversarial, property, load, and mutation gates).

## Architecture

Strict TypeScript modular monolith, three deployables: `api` (Fastify + Zod, committed OpenAPI),
`worker` (PostgreSQL-backed job queue: ingestion, embeddings, purge), `web` (React + Vite console).
PostgreSQL 18 + pgvector is the vector store and the security kernel. No external vector database,
no Redis, no Kafka — by design.

```
Web ──same-origin──► API ──► PostgreSQL (RLS kernel + pgvector + tsvector)
                     │ └─────► Keycloak (OIDC) · MinIO (SSE-S3 objects)
                     └──► Worker ──► jobs queue ──► pipeline (validate → scan → extract → redact → chunk → embed → publish)
```

## Evaluation results (v1.0.0)

- **1,702** unique end-to-end adversarial queries across 9 attack categories — every category
  exceeds its minimum. Zero unauthorized model-context events, zero unauthorized disclosures, zero
  PII leaks, zero audit-isolation failures; 100% required-refusal recall; 100% authorized-answer
  success on answerable fixtures.
- **10,000** seeded property sequences with an independent authorization oracle — zero
  counterexamples.
- **100 × 100** load ops on a shared pool with mid-run churn — zero cross-tenant bleed.
- All **nine** required security mutants make the suite fail.
- Fixture-scale retrieval latency p50 21.5 ms / p99 29.5 ms, recall@20 = 1.0 vs exact search.

Full report: [`docs/evaluation/adversarial-report.md`](docs/evaluation/adversarial-report.md).
Methodology and limitations: [`docs/graph-and-acceptance.md`](docs/graph-and-acceptance.md).

## Repository map

- `CONTEXT.md` — ubiquitous language, core authorization invariant, hard invariants
- `docs/` — threat model, ADRs, contracts, evaluation, operations runbooks
- `packages/db` — migrations, RLS policies, catalog tests
- `packages/security` — two-stage context bootstrap, OIDC/sessions, PII, injection
- `packages/core` — domain (documents, grants, retrieval, evidence, audit, retention)
- `packages/providers` — provider seams + deterministic fakes (extraction, malware, embeddings, answer)
- `packages/eval` — canary corpus, independent oracle, adversarial/property/load gates
- `apps/api` — Fastify REST API (committed OpenAPI at `apps/api/openapi.yaml`)
- `apps/worker` — job consumer
- `apps/web` — accessible enterprise console
- `ops/` — compose, Dockerfiles, mutation harness, seed

## Limitations (honest)

- Prompt-injection detection and PII detection are deterministic heuristics for v1 — defense in
  depth, never authorization. Variant formats and paraphrase conflicts are documented in the ADRs.
- Backup/PITR can resurrect retention-purged data until the backup window expires (documented in
  `docs/ops/backup-restore.md`).
- The adversarial suite proves zero disclosures on **this build, these seeds, this corpus**; it is
  not a mathematical proof, and no security certification is claimed.
- Single region, single deployment envelope (default: 100 tenants / 1M chunks / 25 rps); scale
  limits are documented in `docs/ops/envelope.md`.

## License

MIT — see [`LICENSE`](LICENSE). Copyright 2026 Thiago Schweder Souza.
