# SecureRAG v1 — Canonical Spec (PRD / Security Contract)

Status: accepted (G1 fan-in). Source of truth for implementation tickets. Related: `CONTEXT.md`
(ubiquitous language + invariant), `docs/threat-model.md`, `docs/adr/0003..0012`, research notes in
`docs/research/`.

## 1. Product

Shared RAG knowledge platform for multiple companies. Each tenant retrieves only information
authorized for the authenticated principal inside that tenant. All eleven mission capabilities
(`CONTEXT.md`). UI: accessible enterprise console (document library, versions, grants, search/
answer/citations, refusals, quarantine review, audit, policies). No marketing-only mock.

## 2. Personas and roles

- Tenant principal (read/write/manage grants, `pii:read` capability).
- Tenant admin (membership/group/policy management; no implicit content read).
- Tenant security reviewer (quarantine review/override, audited).
- Platform operator (deployment, observability, runbooks; no implicit content access).
- Service principal (job identity, no broad access).

## 3. API surface (v1) — Fastify + Zod boundary, committed OpenAPI

- Auth: `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/me`.
- Documents: `GET/POST /documents`, `GET /documents/{id}`, `GET/POST /documents/{id}/versions`,
  `GET /documents/{id}/versions/{versionId}` (history requires capability),
  `GET /documents/{id}/source` (authorized stream), citations `GET /citations/{id}`.
- Grants: `GET/POST/DELETE /documents/{id}/grants`.
- Retrieval: `POST /retrieval/query` (returns answer + citations or refusal),
  `GET /retrieval/search` (evidence-only search), refusal `GET /refusals`.
- Admin: `GET/POST /memberships`, `GET/POST/DELETE /groups`, retention `GET/PUT /retention-policy`,
  quarantine `GET/POST /quarantine/{versionId}/review`.
- Audit: `GET /audit/retrieval` (tenant-isolated, RLS).
- Ops: `/healthz`, `/readyz`.
- Consistent errors: typed problem+json; foreign and nonexistent resources indistinguishable
  (same status/schema); no enumeration via errors/counts/constraints.

## 4. Security contract (binding)

1. `Allowed(P,T) = same tenant ∩ active membership ∩ document grant ∩ visible document/version ∩
   unexpired retention ∩ permitted PII scope`. Default deny. Missing/malformed/expired/stale/
   conflicting context → no protected data, indistinguishable foreign/nonexistent behavior.
2. Two-stage bootstrap (`withIdentityContext` → `withSecurityContext`); transaction-local
   `set_config(..., true)` only; runtime roles `NOSUPERUSER`/`NOBYPASSRLS`/non-owner;
   `ENABLE + FORCE RLS` on every tenant table; composite tenant keys; restrictive policies;
   security-invoker views; catalog tests in CI.
3. Authorization executes inside SQL before text/embedding/metadata/rank/count/IDs leave
   PostgreSQL. No app-level post-filtering.
4. Only redacted derivatives enter embeddings, provider payloads, logs, traces, metrics, errors,
   exports, audit views. Raw PII never in model context — even for `pii:read`.
5. Retrieved text is untrusted data; injection detection is defense-in-depth (layer 7 of 9), never
   authorization. Quarantine default; audited review; quarantined versions never searchable.
6. Model has no tools; cannot alter scope/filters/destinations/citation IDs; never answers from
   memory; refusal is deterministic and model-unoverrideable; citation verifier is deterministic
   and independent of the model; auth epoch rechecked before first response byte.
7. Audit insert-only; no runtime role may update/delete; tenant-isolated; retention/legal hold
   enforced; purge by narrow role; deletion proven per storage class.
8. Session: server-side row, `__Host-` cookie, HttpOnly/Secure/SameSite=Lax, CSRF custom-header
   check, revocation epoch.
9. LLM never decides authorization — deterministic identity/authz/database/output controls only.

## 5. Test seams (pre-authorized)

1. REST/OpenAPI boundary (Zod schemas, error semantics).
2. Real PostgreSQL + pgvector via Testcontainers, queried as the actual runtime role (never owner).
3. Public retrieval pipeline with independent fixture oracle + model/provider spy.
4. Browser critical paths via Playwright (a11y, refusal/quarantine states, downloads).
5. OCI image health/readiness + migration/rollback boundary.

## 6. Providers (interfaces + adapters)

`extraction`, `malware-scan`, `pii-detector`, `injection-detector`, `embeddings`, `rerank`
(default off), `answer-generation`. Deterministic local fakes/spies in CI; real adapters:
pdfjs-dist + mammoth; ClamAV; deterministic TS PII detectors; heuristic injection detector (real
classifier adapter documented); OpenAI-compatible embeddings (documented; demo uses deterministic
fake); deterministic generation fake in CI + documented provider adapter. Provider payloads are a
disclosure scan surface.

## 7. Data model (v1, explicit migrations)

`tenants`, `principals`, `tenant_memberships` (role, active, epoch), `groups`,
`group_memberships`, `documents` (tenant_id in PK), `document_versions` (immutable, content hash,
status: PENDING/VALID/QUARANTINED/RELEASED/SUPERSEDED/EXPIRED), `document_grants` (subject_type,
subject_id, capability read|write|manage), `chunks` (immutable, version-bound, redacted text,
search_vec, embedding), `retrieval_runs` (config snapshot), `evidence_bundles`,
`audit_events` (hash-chained), `sessions`, `jobs` (idempotency key, tenant_id in PK),
`retention_policies`, `auth_epoch`. Every tenant-owned table: RLS enforced, composite keys.

## 8. Operations and release

`docker compose up` demo; hardened OCI images; OTel correlation without content; rate limits;
startup validation; migrations expand/contract; runbooks (upgrade, rollback, backup, PITR,
offboarding, purge, incident, key rotation, provider outage); envelope 100 tenants / 1M chunks /
25 rps benchmarked; Release Please v1.0.0-rc.N → v1.0.0; SBOM + provenance; sanitized signed
reports. Publication: private → human checkpoint → public.

## 9. Acceptance (binding gates)

- 1,200 unique end-to-end adversarial queries: 0 unauthorized model-context events, 0 unauthorized
  disclosures, 0 unauthorized citation/source events, 0 cross-tenant session/pool/job/cache, 0 PII
  leaks, audit isolation 100% complete, required-refusal recall 100%, 0 unsupported claims in
  refusal set, authorized-answer success ≥95%, citation precision 100%, required mutants killed
  100%.
- 10,000 seeded property sequences; concurrency/load 100×100; recall@20 ≥0.95 baseline;
  accessibility verified; clean-clone one-command demo.
