# R4 — Hybrid Retrieval: Keyword (tsvector) + Semantic (pgvector) with Reciprocal Rank Fusion, RLS-Filtered Inside SQL

Status: research (no code committed). Applies to the SecureRAG retrieval pipeline: both retrieval arms execute inside PostgreSQL under FORCE RLS so that **fusion and ranking only ever see authorized rows** (`Allowed(P,T)` invariant, CONTEXT.md).

Findings are grounded in: PostgreSQL 18 text search docs, the pgvector v0.8.6 README, the official `pgvector-python` hybrid-search RRF example (maintainer code), and Jonathan Katz's hybrid-search post (PostgreSQL core team; the canonical pgvector hybrid search write-up).

---

## 1. Keyword arm recipe (tsvector + GIN + ts_rank_cd)

### Index expression — must be exact

GIN index over the `to_tsvector` expression, with an **explicit configuration name**:

```sql
CREATE INDEX chunks_search_vec_idx ON chunks
    USING GIN (to_tsvector('english', chunk_text));
```

- Expression indexes require the 2-argument `to_tsvector('english', ...)`. A 1-argument `to_tsvector(body)` is non-immutable (depends on `default_text_search_config`) and **cannot be indexed**.
- A query only uses the index if it references the identical 2-argument expression with the same config name: `WHERE to_tsvector('english', chunk_text) @@ q` uses the index; `WHERE to_tsvector(chunk_text) @@ q` does not (silent full scan).
- Recommended alternative for a retrieval-hot table: a **stored generated column** so ranking never re-runs `to_tsvector` per matching row and query-side expression mismatch is impossible:

```sql
ALTER TABLE chunks ADD COLUMN search_vec tsvector
    GENERATED ALWAYS AS (to_tsvector('english', coalesce(chunk_text, ''))) STORED;
CREATE INDEX chunks_search_vec_idx ON chunks USING GIN (search_vec);
```

Works well here because chunks are immutable. Use `coalesce` for NULL safety (per docs; `to_tsvector(NULL)` returns NULL). Optionally `setweight`-tag title (A) vs body (D) fields if a chunk ever carries structured fields; for a flat chunk a single weight is fine.

### Query and ranking

```sql
SELECT id
FROM chunks, websearch_to_tsquery('english', $1) q
WHERE search_vec @@ q
ORDER BY ts_rank_cd(search_vec, q) DESC, id
LIMIT 60;
```

- `ts_rank_cd` = cover density (Clarke/Cormack/Tudhope): lexeme frequency **plus proximity** — better than `ts_rank` for phrase-like queries and it is what the pgvector hybrid example uses. It needs positional info, so never `strip()` the indexed vector.
- Rank **normalization**: the integer `normalization` bitmask (0 default; 1 = /(1+log(len)); 2 = /len; 4 = harmonic distance; 8/16 = unique-word terms; 32 = rank/(rank+1) → (0,1)). Docs: normalization never changes result *ordering*; it is cosmetic. For RRF we consume **rank positions**, not raw scores, so normalization is unnecessary — but if scores are ever surfaced, 32 (`rank/(rank+1)`) is the documented scale-to-(0,1) option. Do not chase "fair" 0–1 normalization; the docs state global normalization is impossible.
- Default `ts_rank_cd` weights `{0.1,0.2,0.4,1.0}` (D,C,B,A) apply if `setweight` is used.

---

## 2. Vector arm recipe (pgvector)

### Storage: `vector` vs `halfvec`

- `vector(384)` — float32, `4*dim + 8` bytes/row; up to 2000 dims (16,000 dims via unconstrained type). Full precision — **recommended for v1**.
- `halfvec(384)` — float16, `2*dim + 8` bytes/row; up to 4000 dims; "Use the `halfvec` type instead of `vector` for a smaller working set" (README performance section). Slightly lossy; good as a **scaling step**.
- Half-precision **indexing** over full-precision storage is possible (expression index + re-rank), i.e. keep `vector` column, index `(embedding::halfvec(384)) halfvec_cosine_ops`, re-rank on full vector. Not needed for v1.
- 384-dim `multi-qa-MiniLM-L6-cos-v1` class models: README recommends **inner product** (`<#>`) when vectors are L2-normalized (OpenAI-style), else **cosine distance (`<=>`)**. Use `<=>` unless embeddings are guaranteed normalized — and note `<=>` on zero vectors behaves like L2 in HNSW; `NULL`/zero vectors are not indexed (README troubleshooting).

### Exact search

```sql
SELECT id FROM chunks ORDER BY embedding <=> $1 LIMIT 20;
```

- `ORDER BY <op> LIMIT` is the index-enabling shape (no wrapping expression — `ORDER BY 1 - (embedding <=> $1) DESC` cannot use an index).
- Without an HNSW/IVFFlat index (or with the index disabled) this is an exact scan + sort with **perfect recall**. Fine for small authorized corpora.
- Official recall-baseline trick (README, Monitoring): force the exact path with

```sql
BEGIN;
SET LOCAL enable_indexscan = off;   -- exact nearest-neighbor search
SELECT ... ORDER BY embedding <=> $1 LIMIT 20;
COMMIT;
```

### Approximate search: HNSW

```sql
CREATE INDEX ON chunks USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);          -- defaults
SET hnsw.ef_search = 100;                          -- 40 default; per-query via SET LOCAL
```

- HNSW preferred over IVFFlat (README): better speed–recall tradeoff, no training step (can be built on empty table). IVFFlat recall depends on `lists` + `probes` and "results can be limited by probes"; not recommended for v1.
- `hnsw.ef_search` = dynamic candidate list size; higher = better recall, slower. Per-query: `BEGIN; SET LOCAL hnsw.ef_search = 100; ...; COMMIT;` (documented pattern).
- Build with `maintenance_work_mem` sized to graph, `CREATE INDEX CONCURRENTLY` in production.

### Filtering semantics (WHERE tenant_id + ACL) — known caveat

README, Filtering: "With approximate indexes, filtering is applied *after* the index is scanned. If a condition matches 10% of rows, with HNSW and the default `hnsw.ef_search` of 40, only 4 rows will match on average."

Implications for SecureRAG (RLS quals = filters applied post-HNSW-scan):

1. **Low selectivity → starved results**: a principal authorized for ≪10% of the corpus gets only ~`ef_search × selectivity` candidates; top-k can be far below k, and recall against the authorized subset drops. Mitigations, in order:
   - Raise `hnsw.ef_search` (or scale it by `k / selectivity`).
   - **Iterative index scans** (pgvector ≥ 0.8.0): `SET hnsw.iterative_scan = strict_order` (exact ordering by distance) or `relaxed_order` (better recall, slight disorder — wrap in a MATERIALIZED CTE with an outer `ORDER BY distance + 0` for strict ordering on PG 17+); bounded by `hnsw.max_scan_tuples` (20,000 default) and `hnsw.scan_mem_multiplier`. **strict_order is the strong default for a security-first product**: exact ordering by distance, automatic overfetch until k results or the cap.
   - Fall back to **exact search** (no index / `enable_indexscan=off`) when the authorized set is small — the planner picks exact scan when it is cheaper.
2. **Exact filters, small fanout**: a b-tree index on the filter column gives "fast, exact nearest neighbor search in many cases" (planner interleaves). RLS quals are planner-visible, but per-principal ACL selectivity is variable, so do not rely on this alone.
3. **Multitenancy**: README explicitly warns that sharing one approximate index between tenants lets one tenant's vectors affect another's recall/speed, and recommends **list partitioning by tenant** (`PARTITION BY LIST(tenant_id)`), or separate tables, or partial indexes per tenant (`CREATE INDEX ... WHERE tenant_id = ...`). Partial index per tenant is a strong fit for a finite tenant set; partitioning is the durable answer. Either confines HNSW graphs per tenant. RLS still applies inside each partition (FORCE RLS, runtime role).
4. Security note: filtering-after-scan is a *recall* risk, never a *leak* risk — rows failing RLS are simply not returned.

### Recall measurement baseline procedure (labeled fixtures)

Exactly this procedure belongs in `packages/eval` as the hybrid recall gate; details in Final Notes.

1. **Fixture corpus**: labeled chunk set (e.g., per-tenant synthetic docs with ~50–200 chunks + curated question → expected chunk IDs; or an ANN-style public set) plus a set of principals with distinct grant subsets (full, ~10%, ~1% of corpus) so selectivity is exercised.
2. **Exact ground truths**, run as the runtime role with RLS active:
   - exact vector top-k: `BEGIN; SET LOCAL enable_indexscan = off; SELECT ... ORDER BY embedding <=> $1 LIMIT k; COMMIT;`
   - exact keyword top-k: same query as §1 without the GIN index (or `enable_indexscan=off`).
   - exact hybrid ground truth: RRF over the two exact arms (same k). This is the ceiling.
3. **Approximate runs** at candidate `ef_search ∈ {40, 100, 200, 400}` (and, if used, `iterative_scan` settings) with the same RLS role; also per-selectivity bucket.
4. **Metrics**: `recall@k = |approx ∩ exact| / k` (vector arm vs vector ground truth; hybrid vs hybrid ground truth), plus result-count starvation (`|results|` < k?), latency p50/p95, and determinism (two identical runs → identical ordered ID lists).
5. **Decision rule**: pick the smallest `ef_search` (and mode) meeting the recall target (proposed: recall@20 ≥ 0.95 on the authorized subset) with starvation ≤ 0% for every selectivity bucket. Re-run on fixture change and on index build.

Honest expectation (see §4): the maintainer references publish **no** universal hybrid recall numbers — Katz explicitly notes the lack of a ground-truth hybrid benchmark. Hybrid's benefit is qualitative (his experiment: a true best match ranked 6th by vector-only moved to 1st after fusion).

---

## 3. RRF recipe with determinism

### Formula

```
rrf_score(rank, k) = COALESCE(1.0 / (rank + k), 0.0)     -- 0.0 if item absent from an arm
final(id) = sum over arms of rrf_score(arm_rank(id))
```

- `k = 60` is the value in the **official pgvector-python RRF example** (the maintainer reference) and a common default; Katz's post uses 50 and shows that higher k flattens top-rank dominance (weight table for k=10…100 in his post). Adopt **k=60**; it is a tunable, not a security parameter.
- **Union semantics, boost on overlap**: items found by both arms score `1/(k+r1) + 1/(k+r2)` (higher); items from one arm still score and can win on their own. Implement as `UNION ALL` + `GROUP BY id` (Katz) or `FULL OUTER JOIN` (official example) — semantically identical. **Do not intersect**: intersection-only fusion discards single-arm matches and measurably loses recall; RRF's whole point is the union with overlap boost.
- `rrf_score` must be an `IMMUTABLE PARALLEL SAFE` SQL function (Katz's recipe) — enables parallel plans and index usage.

### Determinism requirements (tested, not assumed)

1. **Per-arm rank ties**: `RANK() OVER (ORDER BY distance)` assigns the *same* rank to ties; combined with `LIMIT`, *which* tied rows enter the arm's top-N is nondeterministic. Use `ROW_NUMBER() OVER (ORDER BY <dist/score>, id)` — or `RANK()` with a deterministic tie-break in the window's `ORDER BY` (`distance, id` / `ts_rank_cd DESC, id`). Distinct ranks → deterministic RRF contributions.
2. **Final order**: `ORDER BY score DESC, id ASC` (score first, then a stable id tie-break). The docs' two-query plan in §5 must apply the same rule.
3. **Arithmetic**: compute `1.0/(rank+k)` in **numeric** (SQL `1.0` is numeric in Katz's function) so scores are exact and platform-stable; avoid float4 `ts_rank_cd` leaking into the score sum. Rounding only at the end if at all.
4. **Single statement** over two statements: one statement = one plan, one snapshot; two statements must still be merged with identical math and tie-breaks (and each statement RLS-filtered independently — see §5). Single-statement is preferred (atomicity, one round trip, no merge code to diverge).
5. **Same-query repeatability**: same inputs → same ordered ID list. Property-test this (see footguns).

---

## 4. Hybrid recall: union vs intersection and measured expectations

- How RRF combines: rank-based (positional), not score-based — this is why fusing `ts_rank_cd` (unbounded, unnormalized, corpus-dependent) with cosine distance (bounded-ish, scale-incomparable) works at all. Each arm contributes `1/(k+rank)`, so a strong-but-lower-ranked hit in one arm can be rescued by a modest rank in the other.
- Union vs intersection: RRF over the union (with FULL OUTER JOIN / GROUP BY-sum semantics) is the standard; intersection is strictly weaker recall and is not used by either maintainer reference.
- Expected benefit: keyword arm catches exact-term/entity matches that embeddings blur (Katz's example: vector-only ranked the true match 6th; hybrid moved it to 1st); vector arm catches paraphrase/synonym matches that lexemes miss (`travel` vs `trip`, stemming failures). Expect a **recall@k lift on the union of both match classes**, with the lift concentrated on entity-heavy and phrase-heavy queries; expect *little* lift for pure-paraphrase queries where FTS contributes nothing (all score comes from one arm).
- No authoritative hybrid-recall numbers exist from the maintainers; Katz: "this doesn't attempt to answer 'should you' — that requires a lot more analysis" and notes the absence of a ground-truth set. Therefore SecureRAG must establish its own ground truth (the §2 baseline procedure) rather than import published numbers.

---

## 5. Combined SQL approach with RLS filters

Invariant (CONTEXT.md): authorization executes inside SQL before any content/rank/count leaves PostgreSQL; fusion happens only over authorized IDs. Both arms are plain SELECTs against RLS-enforced tables executed as the least-privileged runtime role (`NOSUPERUSER`/`NOBYPASSRLS`/non-owner, FORCE RLS), so every row entering either arm is already `Allowed(P,T)`-filtered; the outer fusion operates only on authorized IDs by construction.

### Sketch (single statement)

```sql
-- Runtime role; tenant/membership/grant/epoch context already established via
-- parameterized set_config(..., true). RLS quals do the authorization.
BEGIN;
SET LOCAL hnsw.ef_search = 100;          -- or hnsw.iterative_scan = strict_order
SET LOCAL hnsw.iterative_scan = strict_order;   -- exact ordering under RLS filters

WITH keyword AS MATERIALIZED (           -- arm 1: tsvector
    SELECT c.id,
           row_number() OVER (ORDER BY ts_rank_cd(c.search_vec, q) DESC, c.id) AS rnk
    FROM chunks c, websearch_to_tsquery('english', $1) q
    WHERE c.search_vec @@ q
    ORDER BY ts_rank_cd(c.search_vec, q) DESC, c.id
    LIMIT 60
),
semantic AS MATERIALIZED (               -- arm 2: pgvector
    SELECT c.id,
           row_number() OVER (ORDER BY c.embedding <=> $2, c.id) AS rnk
    FROM chunks c
    ORDER BY c.embedding <=> $2, c.id
    LIMIT 60
),
fused AS (
    SELECT id, sum(1.0 / (60 + rnk)) AS score
    FROM (
        SELECT id, rnk FROM keyword
        UNION ALL
        SELECT id, rnk FROM semantic
    ) arms
    GROUP BY id
)
SELECT f.id, f.score, c.chunk_text, c.citation_span ...
FROM fused f
JOIN chunks c USING (id)          -- second touch of chunks: RLS applies here too
ORDER BY f.score DESC, f.id
LIMIT 20;
COMMIT;
```

Notes:

- `LIMIT 60` per arm (k=60 pool) is the official example's shape (its semantic arm limits 20, keyword 20; Katz used 40 to match default `ef_search`). With filtering, pool size may need to exceed `ef_search`-deliverable candidates — prefer `iterative_scan = strict_order` (auto overfetch to satisfy the LIMIT under filters) over a blind large pool.
- MATERIALIZED CTEs: pgvector README recommends them for strict ordering under relaxed-mode iterative scans and to keep distance filters outside the nearest-neighbor CTE; also prevents the planner from inlining/reordering expensive arms.
- The final join to `chunks` re-applies RLS; ids only exist if authorized. Zero authorized rows → empty result; no foreign/unauthorized ID can appear in the fused set (default-deny, indistinguishable-empty).
- Optional explicit `tenant_id = current_setting('app.tenant_id')::uuid` predicate: redundant with RLS but planner-visible; only meaningful if a b-tree filter index or per-tenant partial/partitioned HNSW exists (§2.3).
- Two-statement variant (allowed): run keyword and semantic statements separately (each with its own LIMIT and RLS), merge in app code with the same numeric RRF math and `ORDER BY score DESC, id`. Invariant still holds because both statements are RLS-filtered and the app can only fuse authorized IDs returned by SQL; but prefer the single statement (atomic, one plan, no divergent merge code).

---

## 6. Safe query construction (keyword arm / tsquery)

- **Use `websearch_to_tsquery(config, $1)` with raw user input — this is the documented safe path.** Docs: "this function will never raise syntax errors, which makes it possible to use raw user-supplied input for search." It recognizes only: unquoted terms (AND), `"quoted phrase"` → `<->` operators, word `or` → `|`, `-` → NOT. All other punctuation is ignored; `tsquery` operators/weight/prefix syntax in input are **not** recognized (e.g. input `&` is discarded, proven by the docs' example `'""" )( dummy \\ query <->'` → `'dummi' & 'queri'`).
- **Never** build queries with `to_tsquery` over raw user text (it raises syntax errors on operator-less input and interprets `& | ! <->` — that's operator injection surface, not SQL injection, but it is user-controlled query semantics; `websearch_to_tsquery` removes it).
- Always pass the input as a **parameterized value** (`$1`); `websearch_to_tsquery` never concatenates into SQL text, so there is no SQL-injection vector here — parameterization is still mandatory practice.
- **Pin the regconfig** (`'english'`) on both index expression and query: matches the index (else no index use), and removes `default_text_search_config` drift across environments. Language selection per tenant is a product decision; if per-tenant configs are supported, use the column-config expression index pattern from the docs (`to_tsvector(config_name, body)`) and match queries identically.
- **Phrase operators**: quoted input produces `<->` (FOLLOWED BY, with `<*N*>` for skipped stop words), i.e. exact lexeme-sequence matching — document that phrase search is thereby exact-sequence, and that `-` yields NOT semantics (a `-` term can exclude documents; harmless to authorization, both arms still RLS-filtered).
- **pg_trgm (typo tolerance) — when needed**: exact-lexeme FTS misses misspelled terms (stemming does not fix typos). `pg_trgm` (trusted contrib) adds trigram similarity: `CREATE EXTENSION pg_trgm; CREATE INDEX ON chunks USING GIN (chunk_text gin_trgm_ops);` then `chunk_text % $1` or `$1 <% chunk_text` (word_similarity, threshold 0.6 default; GUCs `pg_trgm.similarity_threshold` etc.), or `ORDER BY similarity(...)`. Index also accelerates `LIKE/ILIKE`/regex. The docs' spell-correction pattern (a trigram-indexed word table from `ts_stat`) is the canonical typo-tolerant keyword complement. **Trigger**: only add once fixtures show keyword-arm recall loss on typo-bearing queries (a planned eval fixture class); it is a second index and a second query path, and it operates on raw text (different column/index from the tsvector GIN — do not conflate them).
- `ts_headline` output is not XSS-safe per docs — irrelevant here (content never rendered raw by us; still note the docs warning).

---

## 7. Sources (exact URLs)

- PostgreSQL 18 text search control (parsing/ranking/normalization; websearch_to_tsquery safety): https://www.postgresql.org/docs/current/textsearch-controls.html
- PostgreSQL 18 text search tables & indexes (GIN expression index, config-name rule, stored generated column): https://www.postgresql.org/docs/current/textsearch-tables.html
- PostgreSQL 18 pg_trgm (gin_trgm_ops, similarity thresholds, spell-correction pattern): https://www.postgresql.org/docs/current/pgtrgm.html
- pgvector README (master; install pins v0.8.6) — storage vector/halfvec, exact search, HNSW + ef_search, filtering-after-scan caveat, iterative scans, multitenancy partitioning, recall monitoring via `SET LOCAL enable_indexscan = off`, hybrid search section, troubleshooting: https://github.com/pgvector/pgvector
- Official pgvector-python hybrid search example (RRF, k=60, RANK() windows, FULL OUTER JOIN): https://github.com/pgvector/pgvector-python/blob/master/examples/hybrid_search/rrf.py
- Jonathan Katz, "Hybrid search with PostgreSQL and pgvector" (RRF formula, k weighting table, UNION ALL + GROUP BY pattern, recall motivation, EXPLAIN showing both indexes): https://jkatz05.com/post/postgres/hybrid-search-postgres-pgvector/
- RRF origin paper (Cormack, Clarke, Büttcher, SIGIR 2009) — canonical citation; PDF fetch timed out during research, verify before deep-link: https://plg.uwaterloo.ca/~gvcormac/cormacksigir09-rrf.pdf

---

## Final notes for implementation

Recommended retrieval recipe (10 bullets):

1. Keyword arm: stored generated `search_vec tsvector` column (`to_tsvector('english', coalesce(chunk_text,''))`, immutable chunks) + GIN index; query with `websearch_to_tsquery('english', $1)` + `ts_rank_cd` + `ORDER BY rank DESC, id`.
2. Vector arm: `embedding vector(384)` column, cosine `<=>` (or `<#>` only if embeddings are guaranteed L2-normalized), HNSW `vector_cosine_ops` index.
3. Exact search for small authorized sets and as ground truth; `SET LOCAL enable_indexscan = off` for the exact path (README-documented recall baseline).
4. HNSW `hnsw.ef_search` sized by k/selectivity; enable `hnsw.iterative_scan = strict_order` so RLS-filtered scans keep exact distance ordering and auto-overfetch (pgvector ≥ 0.8.0).
5. RLS is the filter on both arms; filtering-after-scan is a recall risk, never a leak — plan ef_search/iterative scans around the ~10%-selectivity rule of thumb.
6. Multitenancy: per-tenant partial HNSW indexes now or tenant list-partitioning; shared HNSW lets one tenant's vectors degrade another's recall (README guidance).
7. RRF: `sum(1/(k+rank))`, k=60 (official example default), numeric arithmetic, `IMMUTABLE PARALLEL SAFE` helper function.
8. Union semantics (UNION ALL + GROUP BY, or FULL OUTER JOIN); overlap items get boosted; never intersect.
9. Determinism: `ROW_NUMBER()` (or rank with tie-break) per arm, final `ORDER BY score DESC, id`; single SQL statement.
10. Safe query construction: raw user input → only through `websearch_to_tsquery` (never `to_tsquery` over raw text); pinned regconfig; pg_trgm gin_trgm_ops only as a later typo-tolerance layer.

Exact recall-baseline procedure: (1) labeled fixtures per tenant incl. principals at full/10%/1% grant selectivity; (2) exact ground truths as the runtime role with RLS on — vector arm via `SET LOCAL enable_indexscan = off`, keyword arm via index-off equivalent, and exact hybrid = RRF over the two exact arms; (3) approximate runs at ef_search ∈ {40,100,200,400} (± iterative_scan modes), same role; (4) compute recall@k = |approx∩exact|/k per arm and for hybrid, plus result-count starvation (<k) and p50/p95 latency per selectivity bucket; (5) pick smallest ef_search meeting recall@20 ≥ 0.95 and 0% starvation in every bucket; re-run after any fixture or index change.

File written: `/Users/thiago/dev/securerag/docs/research/r4-hybrid-retrieval.md` (only file created; nothing else touched; no commits).

**Footgun that must become a test** (highest priority): **HNSW + RLS-filter starvation** — with a principal authorized for ~1–10% of a corpus, a shared HNSW scan with default `ef_search=40` returns far fewer than k authorized results (≈ `ef_search × selectivity`), silently degrading (and with no iterative scans, possibly emptying) retrieval; the test must assert recall and result-count on narrow-ACL principals under the chosen ef_search/iterative-scan configuration. Secondary tests: (a) per-arm and final tie determinism — same query twice yields byte-identical ordered ID lists; (b) empty-authorized-set returns zero rows for both arms regardless of HNSW candidates (indistinguishable-empty); (c) index-expression/config drift (query using a different regconfig than the GIN expression silently loses the index — assert via EXPLAIN or planner flag); (d) RRF score arithmetic stability in numeric (no float drift across platforms/runs).
