# SecureRAG

Production-ready multitenant enterprise knowledge platform: shared retrieval-augmented generation
where a tenant may retrieve only information authorized for the authenticated principal inside that
tenant — enforced by deterministic identity, authorization, database, and output controls, never by
the model.

Status: **under construction** (0.x). See the roadmap in `docs/graph-and-acceptance.md`.

## What it does

- PostgreSQL row-level security on every tenant-owned table, queried by least-privileged runtime
  roles (`NOBYPASSRLS`, `FORCE ROW LEVEL SECURITY`).
- Default-deny document permissions for users, groups, and tenant roles; immutable, versioned
  documents with exact resolvable citations.
- Hybrid semantic + full-text retrieval with deterministic Reciprocal Rank Fusion.
- Direct/indirect prompt-injection detection and quarantine; configurable PII redaction before
  embedding, generation, logs, and audit views.
- Tenant-configurable retention, legal hold, and verified deletion across derived data.
- Complete tenant-isolated retrieval audit trail; deterministic refusal on insufficient or
  conflicting evidence.
- An adversarial suite of 1,200 unique end-to-end attack queries is the v1 release gate:
  zero observed unauthorized disclosures, zero unauthorized model-context events.

## Security model

See `CONTEXT.md` (domain + core authorization invariant) and `docs/threat-model.md` (declared
threat model, explicit exclusions, truthful claim policy).

## Quick start

```bash
npm install

# One-command local demo (ADR-0011): postgres+pgvector, Keycloak, MinIO,
# API, worker, accessible web console behind a same-origin proxy.
cp ops/.env.example ops/.env
npm run demo              # docker compose -f ops/compose.yml up --build -d
npm run demo:seed         # 2 synthetic tenants + documents (idempotent)
# open http://localhost:8080 — sign in as alice / alice-demo-password
# (see ops/README.md for the full walkthrough and teardown)
```

## Web console (apps/web)

React 19 + Vite 8 accessible enterprise console (`npm run web:dev`). Talks to the
API same-origin via `/api/*` (the compose proxy rewrites it; the dev server proxies
to `http://localhost:3000` — override with `API_PROXY_TARGET`).

Browser tests (real API + real PostgreSQL via Testcontainers, fake OIDC provider —
no mocks of API behavior):

```bash
npx playwright install chromium   # once per machine (browsers are not in npm)
npm run test --workspace @securerag/web
```

## Performance envelope

`docs/ops/envelope.md` declares the v1 target (100 tenants / 1M chunks / 25 rps) and
the harness (`npm run benchmark`; fixture scale in CI, at-scale by the G5 release
agent on recorded hardware).

## Repository map

- `CONTEXT.md` — ubiquitous language, authorization invariant, invariants
- `docs/` — threat model, ADRs, implementation graph, acceptance contract
- `docs/ops/` — runbooks: upgrade, rollback, incident, key rotation, provider
  outage, offboarding, backup/restore, envelope
- `AGENTS.md` — repository rules for agents
- `ops/` — compose stack, demo seed, images, keycloak realm

Detailed architecture, quickstart, evaluation reports, and release artifacts land in `docs/` and
this README as construction proceeds.

## License

MIT — see `LICENSE`.
