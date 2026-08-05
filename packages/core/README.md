# @securerag/core

SecureRAG domain layer: identity-scoped retrieval (hybrid keyword + vector),
grants, documents, citations, refusal, audit. All authorization happens inside
SQL under FORCE RLS as the least-privileged runtime role — never after rows
leave PostgreSQL (CONTEXT.md `Allowed(P,T)` invariant).

## Retrieval

`runRetrieval(deps, params)` runs the full pipeline: identity context → (S4:
redaction) → embed question → verified security context → hybrid SQL arms →
evidence gate → generation → audit. `RetrievalParams.mode` selects the arm
shape (`'hybrid'` default, `'keyword'`, `'vector'`); the HTTP boundary exposes
only the default in v1, the other modes are contract-visible test/CI seams.

- **Keyword arm**: `search_vec @@ websearch_to_tsquery('english', $1)` ranked
  by `ts_rank_cd`, exactly the T3 contract shape.
- **Vector arm**: `embedding <=> $query::vector` ordered by distance, the same
  FROM/JOIN/WHERE/EXISTS authorization predicate as the keyword arm, under
  per-query `SET LOCAL hnsw.iterative_scan = strict_order` (ADR-0008
  amendment 1). Chunks with NULL embeddings are excluded from this arm
  (`WHERE embedding IS NOT NULL`).
- **Hybrid**: single SQL statement fusing both arms with
  `securerag.rrf(k, ranks)` (k = 60), `ROW_NUMBER` per arm, union semantics,
  final `ORDER BY score DESC, chunk_id` (deterministic stable ordering).

The arm queries are exported (`retrievalSql`, `retrievalParams`,
`executeRetrievalQuery`, `runRetrievalQuery`) so the eval recall baseline runs
the exact production SQL under the least-privilege role.

## Embedding provider

`EmbeddingProvider.embed(texts)` — the seam for question/chunk embeddings.
`DeterministicHashEmbedding` is the CI/demo fake (stable pseudo-vectors from a
text hash, fixed 384 dims, L2-normalized, no network); it is the default when
no provider is injected. Only redacted derivatives may ever enter a provider
payload — the redaction step lands in S4 and plugs in before `embed()`.

### OpenAI-compatible adapter contract (real adapter deferred)

The production adapter behind this seam must follow the OpenAI Embeddings API
shape so any OpenAI-compatible endpoint can be swapped in:

- Request: `POST {base}/v1/embeddings` with `{ model, input: string[] }`,
  `Authorization: Bearer <key>`; batch size ≤ 64 texts per request, and the
  batch order must be preserved (index-aligned with `data[]`).
- Response: `data[]` items `{ embedding: number[], index }`; map index-aligned
  to `number[][]`; validate `embedding.length === 384` per item (fail closed
  on mismatch — a wrong-dimension vector silently degrades the HNSW index).
- Errors/timeouts: retry idempotently (embedding is deterministic per input),
  surface a typed error to the retrieval pipeline; never embed raw question
  text before S4 redaction, never log prompts or payloads.
- Latency budget: keep the provider call outside the security-context
  transaction (the pipeline already embeds before `withSecurityContext`).

`packages/providers` is the home for provider adapters; the interface lives
here because retrieval owns the embedding contract.
