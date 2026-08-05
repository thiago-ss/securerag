# ADR 0008 — Retrieval architecture (D6)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r4-hybrid-retrieval.md, r1-postgres-rls.md

## Decision

Pipeline: `authenticate -> authorize -> redact query -> ACL-constrained keyword/vector arms ->
RRF -> optional authorized rerank -> RLS rehydrate -> evidence gate -> generate ->
citation verify -> audit -> respond/refuse`.

- **Keyword arm**: stored generated `search_vec tsvector` column (`to_tsvector('english', …)`) +
  GIN index; query `search_vec @@ websearch_to_tsquery('english', $1)` ordered
  `ts_rank_cd(…) DESC, id`. Raw user input only through `websearch_to_tsquery` (never user-authored
  tsquery syntax); pinned regconfig.
- **Vector arm**: `embedding vector(384)` + HNSW `vector_cosine_ops` (`<=>`). Exact ground truth
  via `SET LOCAL enable_indexscan = off`. Enable `hnsw.iterative_scan = strict_order` (pgvector
  ≥0.8) so RLS-filtered scans keep exact ordering; size `hnsw.ef_search` by the recall baseline.
  Per-tenant partial HNSW indexes so one tenant cannot degrade another's recall.
- **Both arms** carry the full tenant/RLS/document-grant/current-version/retention/quarantine
  filters inside SQL before rank/limit. Authorization never happens after SQL.
- **RRF**: `sum(1/(k + rank))` with `k = 60`, as an `IMMUTABLE PARALLEL SAFE` SQL function; union
  semantics (never intersect); determinism via `ROW_NUMBER()` per arm and final
  `ORDER BY score DESC, id` in one SQL statement.
- **Recall baseline** (before HNSW in prod): per-tenant labeled fixtures at full/10%/1% grant
  selectivity; exact hybrid = RRF over exact arms (runtime role, RLS on); sweep
  `ef_search ∈ {40,100,200,400}`; gate `recall@20 ≥ 0.95` with 0% result starvation in every
  selectivity bucket; smallest `ef_search` meeting the gate is the default. Re-run after
  fixture/index changes. Partitioning only from measured scale evidence; never replaces RLS.
- **Rerank**: provider seam, default off in v1; when enabled, rerank runs only over already
  authorized candidates and re-checks authorization epoch before use.
- **Scores**: raw similarity/RRF is not confidence; only calibrated evidence-gate output is.

## Consequences

- HNSW+RLS filter starvation (narrow-ACL principals) is a tested footgun: recall@k and result-count
  assertions on 10%/1% selectivity principals.

---

# Amendment 1 (S6) — chosen HNSW strategy, ef_search default, measured recall

- Status: accepted. Supersedes the Decision's "Per-tenant partial HNSW indexes" sentence; confirms
  the strict_order and recall-baseline sentences with measurements.

## Chosen strategy: single shared HNSW index + strict_order

Migration 0004 creates ONE shared index, `chunks_embedding_hnsw` on `(embedding)` with
`vector_cosine_ops` (m=16, ef_construction=64). The per-query settings are transaction-local
`SET LOCAL` statements inside the withSecurityContext transaction (never session-level, never
schema objects):

- `SET LOCAL hnsw.iterative_scan = strict_order` (pgvector 0.8.6): exact distance ordering under
  RLS/ACL filters; the scan overfetches until k rows pass the filter or `hnsw.max_scan_tuples`
  (20 000), so recall@k and result counts do not depend on ef_search for corpora below the cap.
- `SET LOCAL hnsw.ef_search = <default>` — see below.

Rejected alternatives, with reasons:

- **Per-tenant partial HNSW indexes** (original Decision): the tenant set is dynamic (tenants are
  created at runtime), so partial indexes cannot be created from a static SQL migration, and a
  runtime-created index per tenant is unbounded churn. The original rationale (one tenant must not
  degrade another's recall) is neutralized by strict_order: ordering is exact and the scan keeps
  going until k rows pass — shared-graph contents can delay but never starve a filtered search.
  Cross-tenant LATENCY remains a measured-scale partitioning trigger (r4 §2.3), never a recall
  risk.
- **Composite HNSW on (tenant_id, embedding)**: pgvector supports leading non-vector columns, but
  the coarse filter only helps when the tenant predicate appears in the query TEXT — RLS quals are
  invisible to the planner, so the tenant filter would have to be duplicated into SQL (redundant
  with RLS). It also does not address the real starvation driver: ACL-level (grant) selectivity
  within a tenant.

## ef_search default

**`hnsw.ef_search = 40`** (`RETRIEVAL_EF_SEARCH` in packages/core). HONEST LIMITATION (S6 review):
with strict_order, recall and result counts are independent of ef_search at fixture scale
(600 chunks ≪ hnsw.max_scan_tuples 20 000), so the baseline cannot discriminate ef_search values —
the gate passes at every sweep point and the "smallest chosen" is a tie-break, not measurement.
The production planner at fixture scale also prefers the exact grant-driven join over the HNSW
scan, so the baseline exercises the index path only through the test-only forceIndex lever. The
recall gate's genuinely sensitive dimensions are: starvation counts (0 required), the
no-strict_order footgun control (must starve), and determinism. Actionable claims:
strict_order is mandatory; ef_search=40 is the pgvector-recommended floor for this corpus size;
re-run the baseline (packages/eval/test/recall-baseline.test.ts) at production scale before v1
(G5 envelope benchmark) and re-pick ef_search from measured recall@k + p99 latency then.
Re-run after any fixture or index change.

## Arm pools (S6 review fix)

Hybrid arms overfetch: per-arm `LIMIT = max(requested, RETRIEVAL_ARM_LIMIT=60)` (retrievalParams),
so candidates ranked beyond the final result limit can still contribute to fusion; the final
result `LIMIT` is applied after RRF. Ground truth in the recall harness uses the same arm pools,
so pool-induced recall loss is now detectable.

## Measured recall (2026-08-05, 200 docs / 600 chunks / 40 labeled queries, one tenant)

Exact ground truths computed as the least-privilege runtime role with RLS on
(`SET LOCAL enable_indexscan/bitmapscan = off`); principals at 100% / 10% / 1% grant selectivity
(1% = 6 allowed chunks, spread across topics). Full report: `test-results/recall.json`
(gitignored).

| arm (settings) | selectivity | recall@20 (ef 40/100/200/400) | starved queries |
| --- | --- | --- | --- |
| hybrid (production planner settings) | 100% / 10% / 1% | 1.0000 / 1.0000 / 1.0000 each | 0 / 0 / 0 |
| vector (forced HNSW + strict_order) | 100% / 10% / 1% | 1.0000 / 1.0000 / 1.0000 each | 0 / 0 / 0 |

- **Footgun proven and fixed**: the vector arm alone, forced HNSW WITHOUT strict_order,
  ef_search=40, 1% selectivity → **40/40 queries starved** below min(k, allowed)=6 (the
  filtering-after-scan caveat, r4 §2.1). The same runs WITH strict_order → 0% starvation and
  recall 1.0. This is the reason strict_order is mandatory per-query.
- **Determinism**: same query twice → identical ordered id lists (40 queries, both arms).
- **Keyword arm unaffected**: id lists byte-identical with the HNSW settings applied or not.
- Gate: recall@20 ≥ 0.95 at every selectivity with 0% starvation — PASS at ef_search = 40.

## Measurement notes

- At fixture scale the planner prefers the exact grant-driven join + sort over the HNSW scan
  (r4 §2.1 fallback: small authorized sets are scanned exactly). That is correct production
  behavior and is measured as the "hybrid (production planner settings)" row. To characterize the
  genuine approximate-index path, the baseline forces the HNSW scan
  (`SET LOCAL enable_seqscan/sort = off`, a measurement lever exported as
  `RetrievalQuerySettings.forceIndex`, never set in production).
- The CI embedding fake (DeterministicHashEmbedding) spreads each token over ~16 dimensions.
  Sparse one-dimension-per-token hashing was measured to produce a degenerate HNSW graph
  (recall 0.0 at ef_search=40 on the same corpus) — dense-enough vectors are a fixture
  requirement for navigable HNSW graphs, matching real dense models.
- Chunks with NULL embeddings are excluded from the vector arm (`WHERE embedding IS NOT NULL`);
  they are not indexed and cannot be compared.
- `RetrievalParams.mode` ('hybrid' default, 'keyword'|'vector' for tests) is a contract-visible
  seam; the HTTP boundary does not expose it in v1.

