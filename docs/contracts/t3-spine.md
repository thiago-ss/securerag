# T3 Contract — RLS Spine End-to-End (issue #22)

Frozen before building. Binding for all T3 work; deviations require an orchestrator decision.

## Scope

Thin end-to-end security spine through API and SQL, keyword-retrieval only:
documents, grants, retrieval, refusal, audit, citations, model spy, independent oracle.

## Domain contracts (packages/core, TS, ESM)

- `retrieval/query.ts`:
  - `runRetrieval(deps, {tenantId, requestId, principalId, question})` → `RetrievalOutcome`
  - Flow: withIdentityContext (list memberships) → caller picks tenant (untrusted candidate) →
    withSecurityContext → keyword arm SQL (below) → evidence bundle (chunk rows) →
    `decide(bundle, question)` → if below threshold → `{decision: 'refused', code: 'INSUFFICIENT_EVIDENCE'}`
    else `{decision: 'answered', answer, citations[]}` via generation provider spy →
    audit event → return. Never answers from memory; model spy is the only generator in this node.
  - Refusal codes (stable): `INSUFFICIENT_EVIDENCE`, `CONFLICTING_EVIDENCE`, `CITATION_UNSUPPORTED`
    (only the first is reachable in T3).
- `grants.ts`: `canRead(deps, documentId)` re-check used by citation/source resolution —
  identical predicate to the retrieval query (single source of truth function).
- `audit.ts`: `appendAudit(deps, event)` insert-only via runtime role; fields per spec §4.7;
  never raw query/PII; `listAudit(deps)` tenant-isolated via RLS.
- `documents.ts`: `getDocument`, `getVersion` (valid/current rules), `resolveCitation`
  (re-checks authorization + returns authorized excerpt only).
- `providers/answer.ts` (packages/providers): `AnswerGenerator` interface
  `generate({question, bundle, citations}) → {answer, citations}`; `SpyGenerator` records
  every payload (question + bundle text + citations) in memory for assertions; deterministic,
  returns a template answer that references the provided citation ids (never fabricates).
  Real adapter documented (deferred; seam is the contract).
- `eval/oracle.ts` (packages/eval): independent authorization oracle. Input: fixture facts
  (plain objects: memberships, grants, group memberships, versions+status). Output: exact
  allowed sets `{documents, versions, chunks}` per (principalId, tenantId) using ONLY fixture
  facts. Must NOT import or reimplement production policy helpers. T3 tests assert
  production results ⊆ oracle sets and oracle ⊆ production results (bidirectional for the
  covered fixtures), plus model-spy payload chunks ⊆ oracle.

## Retrieval keyword arm (binding SQL shape)

Run inside `withSecurityContext`; both arms now = keyword only:

```sql
SELECT c.chunk_id, c.chunk_no, c.text_redacted, c.span_start, c.span_end,
       v.version_id, v.version_no, d.document_id, d.title,
       ts_rank_cd(c.search_vec, q) AS rank
  FROM securerag.chunks c
  JOIN securerag.document_versions v
    ON v.tenant_id = c.tenant_id AND v.version_id = c.version_id
  JOIN securerag.documents d
    ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
 CROSS JOIN LATERAL websearch_to_tsquery('english', $1) q
 WHERE c.search_vec @@ q
   AND v.status IN ('valid','released')
   AND v.is_current
   AND EXISTS (
     SELECT 1 FROM securerag.document_grants g
      WHERE g.tenant_id = c.tenant_id AND g.document_id = d.document_id
        AND (
          (g.subject_type = 'principal'
             AND g.subject_id = securerag.ctx_principal_id()::text)
          OR (g.subject_type = 'group'
             AND EXISTS (SELECT 1 FROM securerag.group_memberships gm
                          WHERE gm.tenant_id = c.tenant_id
                            AND gm.group_id = g.subject_id::uuid
                            AND gm.principal_id = securerag.ctx_principal_id()))
          OR (g.subject_type = 'tenant_role'
             AND g.subject_id = (SELECT tm.role FROM securerag.tenant_memberships tm
                                  WHERE tm.tenant_id = c.tenant_id
                                    AND tm.principal_id = securerag.ctx_principal_id()
                                    AND tm.is_active))
        ))
 ORDER BY rank DESC, c.chunk_id
 LIMIT $2
```

All filters are in SQL; RLS (tenant_isolation) applies to every table including inside the
EXISTS subqueries. No application-side post-filtering ever. Deterministic ordering.

## API (apps/api, Fastify, this node only)

- Transport: Fastify + Zod schemas at the boundary; `@fastify/swagger` generates
  `apps/api/openapi.yaml` committed (script `npm run openapi:gen --workspace @securerag/api`).
- Dev-auth (T3-only, replaced by OIDC in S1): header `X-SecureRAG-Principal: <uuid>` maps
  EXACTLY to `principalId`; tenant is an untrusted candidate from the request body.
  Documented as test-only transport; S1 replaces it.
- Routes:
  - `POST /retrieval/query` body `{tenantId, question}` →
    `{decision:'answered', answer, citations:[{documentId,versionId,chunkId,span:{start,end},excerpt}]}`
    | `{decision:'refused', code, message}`. 404-free; foreign tenant → same refusal shape.
  - `GET /documents/:id` → 200 with allowed title/status | 404 (foreign === nonexistent).
  - `GET /documents/:id/versions/:versionId` → same indistinguishability.
  - `GET /citations/:citationId` → rechecks authz; 404 foreign === nonexistent.
  - `GET /audit/retrieval?limit=50` → tenant-isolated audit list.
  - `GET /healthz`, `GET /readyz`.
- Errors: typed problem+json; NEVER differentiate foreign vs nonexistent (same status/schema).

## Audit events (T3 subset)

`retrieval:allowed`, `retrieval:denied`, `retrieval:refused` + `document:read` +
`citation:resolved`. Fields: tenant_id, event_type, request_id, principal_id, membership_id,
auth_epoch, redacted_query (T3: the question — redaction via provider seam later, S4),
query_hash, candidate_ids (allowed only), selected_ids, scores, evidence_decision,
model_status, citations, refusal_reason, latency_ms, answer_hash. Never foreign ids.

## G2 gate tests (packages/eval/test/spine.test.ts + API E2E)

1. Own authorized keyword retrieval succeeds; citations resolvable; excerpt matches oracle.
2. Foreign tenant / nonexistent doc / nonexistent citation → indistinguishable 404/refusal;
   no counts, no enumerable errors.
3. Principal without grant (member, no grant) → INSUFFICIENT_EVIDENCE; spy payload EMPTY.
4. Model spy: every provider payload chunk id ∈ oracle; zero foreign chunk text anywhere.
5. Revocation: grant revoked mid-suite → new request refuses; audit shows denied/refused.
6. Audit isolation: alice reads only tenant-A events; bob only tenant-B.
7. Denied query (invalid body, malformed uuid) → typed error, no data, audited.
8. Fixtures: ≥2 tenants, grants via principal/group/tenant_role; a revoked grant; a
   superseded version (not current) must NOT appear; a quarantined version must NOT appear.
9. RLS/ACL red-team + oracle approval: independent reviewer re-verifies oracle ⊆ allowed.

## Excluded from T3

Vector arm/RRF (S6), PII (S4), injection (S5), sessions/OIDC (S1), history/source streams
(S3), retention expiry (S9), streaming, rerank. OpenAPI generation may be minimal but real.
