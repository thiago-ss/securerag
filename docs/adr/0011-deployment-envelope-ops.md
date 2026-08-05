# ADR 0011 — Deployment envelope and operations (D9)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r3-toolchain-versions.md, r7-otel-release-supplychain.md, r8-extraction-objects-queue.md

## Decision

- **Local demo** (`docker compose up`, one command, no paid keys): PostgreSQL 18.4 with pgvector
  0.8.6 (`pgvector/pgvector:pg18`-line image), Keycloak 26.7.0 (synthetic realm), pinned MinIO
  (SSE-S3), `api`, `worker`, `web`, reverse proxy serving web same-origin behind the API.
- **Production images**: Node 24 LTS base (CI pins Node 24 LTS too), non-root user, dropped
  capabilities, health + readiness endpoints, graceful shutdown on SIGTERM, no dev tools/secrets;
  startup config validation via a Zod env schema; secrets via environment/secret files only;
  TLS/egress/CORS/CSP/rate limits documented and tested.
- **Observability**: `@opentelemetry/sdk-node` 0.221.0 + `@fastify/otel` 0.20.1 +
  `@opentelemetry/instrumentation-pino` 0.67.0 for trace-id-correlated structured logs; attributes
  carry identifiers/status only — never prompts, retrieved text, or document content.
- **Production envelope** (default target, benchmarked before v1): up to 100 tenants, 1M active
  chunks, 25 retrieval requests/second, single region. Publish p50/p95/p99 retrieval latency,
  recall@k vs exact, ingestion throughput, resource use, hardware. Security is a binary gate, never
  traded for performance.
- **Migrations**: explicit SQL, expand/contract where required, idempotent; upgrade/rollback/
  backup/PITR-restore/tenant-offboarding/retention-purge/incident/key-rotation/provider-outage
  rehearsed and documented.
- **CI**: least privileges, third-party actions pinned to immutable commit SHAs (list in
  r7), branch protection with required checks (enforced when repo permissions allow), deterministic
  dependencies, SBOM, provenance.

## Consequences

- One-command demo proves the product to evaluators; production posture is separately hardened and
  rehearsed; observability never leaks content.
