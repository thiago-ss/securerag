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

## Repository map

- `CONTEXT.md` — ubiquitous language, authorization invariant, invariants
- `docs/` — threat model, ADRs, implementation graph, acceptance contract
- `AGENTS.md` — repository rules for agents

Detailed architecture, quickstart, evaluation reports, and release artifacts land in `docs/` and
this README as construction proceeds.

## License

MIT — see `LICENSE`.
