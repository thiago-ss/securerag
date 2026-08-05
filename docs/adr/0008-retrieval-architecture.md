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
