-- 0004_hybrid_retrieval.sql
-- Hybrid retrieval (S6, ADR-0008 amendment 1): RRF helper function and the
-- shared HNSW index for the vector arm. The per-query settings
-- (hnsw.iterative_scan = strict_order, hnsw.ef_search) are transaction-local
-- SET LOCAL statements issued by the application inside withSecurityContext,
-- never session-level and never schema objects.
-- Owner: securerag_owner (migration role via SET ROLE, per 0002/0003).

SET ROLE securerag_owner;

-- ---------- RRF helper ----------
-- rrf(k, ranks) = sum(1 / (k + rank)) over the input ranks (research r4 §3,
-- official pgvector hybrid-search example): union semantics with overlap
-- boost. k = 60 is the ADR-0008 default (the official pgvector example value).
-- PostgreSQL forbids a defaulted argument before a non-defaulted one, so the
-- default cannot live in this signature: the retrieval query passes the
-- documented constant 60 (RRF_K in packages/core), which is the single place
-- the default is pinned.
-- Numeric arithmetic (1.0 / integer) keeps the sum exact and platform-stable
-- (no float4 ts_rank_cd leaking into the fused score, research r4 §3.3).
-- IMMUTABLE + PARALLEL SAFE: enables parallel plans and index usage inside
-- the fused query (Katz recipe).
CREATE FUNCTION securerag.rrf(k integer, ranks integer[])
RETURNS numeric
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT COALESCE(SUM(1.0 / (k + rank)), 0)
    FROM unnest(ranks) AS rank
$$;

-- Runtime roles get EXECUTE; PUBLIC never executes it (same hardening as
-- bump_authorization_epoch in 0003).
REVOKE EXECUTE ON FUNCTION securerag.rrf(integer, integer[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securerag.rrf(integer, integer[])
  TO securerag_api, securerag_worker;

-- ---------- HNSW index (vector arm) ----------
-- Single shared HNSW index on embedding (ADR-0008 amendment 1). Rejected
-- alternatives, with reasons:
--  * Per-tenant partial HNSW indexes: the tenant set is dynamic (tenants are
--    created at runtime), so partial indexes cannot be created from a static
--    migration; this would also create unbounded index churn per tenant.
--  * Composite HNSW on (tenant_id, embedding): pgvector supports leading
--    non-vector columns, but the index only helps queries whose text mentions
--    tenant_id, and RLS quals are invisible to the planner — the tenant filter
--    would have to be duplicated into query text (redundant with RLS) and the
--    real starvation driver is grant-level (ACL) selectivity, not tenant.
--  * The chosen approach: HNSW on (embedding) + per-query
--    SET LOCAL hnsw.iterative_scan = strict_order (pgvector >= 0.8). strict
--    order returns results in exact distance order under RLS/ACL filters and
--    overfetches until k rows pass the filter or hnsw.max_scan_tuples, so
--    recall@k and result counts do not depend on ef_search or on other
--    tenants' rows occupying the shared graph. Recall/starvation are proven by
--    the eval recall baseline; cross-tenant latency remains a measured-scale
--    partitioning trigger (research r4 §2.3), never a recall risk.
-- Defaults m = 16, ef_construction = 64 (pgvector defaults). Rows with NULL
-- embeddings are not indexed and are excluded from the vector arm query
-- (WHERE embedding IS NOT NULL).
CREATE INDEX chunks_embedding_hnsw
  ON securerag.chunks USING hnsw (embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

RESET ROLE;
