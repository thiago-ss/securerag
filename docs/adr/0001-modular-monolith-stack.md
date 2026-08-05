# ADR 0001 — Modular monolith stack (defaults)

- Status: accepted (construction; exact version pins verified against primary sources in G1)
- Date: 2026-08-05
- Deciders: principal engineer (goal defaults; deviations require a researched ADR)

## Context

SecureRAG must deliver tenant isolation, hybrid retrieval, injection/PII controls, retention/legal
hold, and a complete audit trail as one deployable system with a small team and a single-region
envelope (default: 100 tenants, 1M active chunks, 25 retrieval req/s). The goal prescribes defaults
unless primary-source research proves an incompatibility.

## Decision

- **Architecture**: strict TypeScript modular monolith in one workspace; three deployables:
  `web`, `api`, `worker`.
- **Web**: React + Vite, served same-origin behind the API/reverse proxy; accessible enterprise
  console.
- **API**: Fastify REST API; Zod boundary schemas; generated and committed OpenAPI contract.
- **Database**: PostgreSQL 18 (reference release) + pgvector 0.8.x, explicit SQL migrations,
  Kysely typed SQL.
- **Retrieval**: `tsvector`/GIN keyword + pgvector exact/HNSW semantic + deterministic Reciprocal
  Rank Fusion. No external vector database.
- **Auth**: OIDC Authorization Code + PKCE/JWKS; Keycloak for local/demo identity; conforming OIDC
  providers in production. Server-side secure HTTP-only sessions. No custom IAM.
- **Objects**: S3-compatible encrypted object storage; MinIO locally. No permanent public object
  URLs.
- **Jobs**: PostgreSQL-backed queue, bounded retries, idempotency. No Redis unless measured evidence
  and an ADR justify it.
- **Providers**: small interfaces for extraction, malware scanning, PII detection, injection
  detection, embeddings, reranking, answer generation. Deterministic local fakes/spies in CI; at
  least one documented real adapter per capability.
- **Tests**: Vitest, Testcontainers (real PostgreSQL + pgvector), fast-check, Playwright. Never mock
  RLS.
- **Ops**: Docker Compose one-command demo; hardened OCI images; OpenTelemetry; structured redacted
  logs.
- **Release**: GitHub Actions, GHCR, SBOM, provenance when supported, SemVer, changelog, annotated
  tags, GitHub Releases.
- **License**: MIT, copyright 2026 Thiago Schweder Souza (user may override before publication).
- **Scope exclusions** (v1): Kafka, microservices, Elasticsearch/OpenSearch, Kubernetes/Helm,
  event sourcing, custom model training, multi-region replication, custom agent runtime — unless a
  measured requirement and a new ADR.

## Consequences

- One codebase to secure; cross-tenant hazards concentrate in DB context, RLS policies, session
  handling, object access, job dispatch, and output surfaces.
- PostgreSQL is the security kernel: RLS, forced RLS, least-privilege roles, two-stage context
  bootstrap, security-invoker views.
- Deterministic local providers keep the security gate independent of paid model availability.
