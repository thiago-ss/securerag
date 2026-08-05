# Performance envelope (ADR-0011) — target, harness, hardware

Version: 0.x (construction). This file is the benchmark contract: the target, the
harness that measures it, and the hardware record. Security is a binary gate and is
never traded for performance.

## Declared envelope (v1 default target)

| Dimension | Target |
| --- | --- |
| Tenants | 100 |
| Active chunks | 1,000,000 |
| Retrieval rate | 25 requests/second sustained |
| Latency (retrieval, HTTP boundary) | publish p50/p95/p99 on recorded hardware |
| recall@20 vs exact | publish mean on recorded hardware |
| Ingestion | publish docs/s and chunks/s on recorded hardware |
| Region | single region |

"Published" means: the numbers appear in this file's **measurement log** (below) with
the exact commit, image digest, corpus manifest, seeds, and hardware. A benchmark
without the hardware record is a guess, and we do not guess in release reports.

## Harness: `packages/eval/src/bench.ts`

Measures the REAL API over HTTP (real Fastify, least-privilege pool, real PostgreSQL
+ pgvector, deterministic providers) — never mocked seams:

- **Retrieval latency p50/p95/p99 + achieved rps**: `POST /retrieval/query` with the
  session cookie + CSRF, round-robin over tenants, after a 2-query-per-tenant cache
  warm-up.
- **recall@20 vs exact**: production hybrid arm vs the exact SQL ground truth
  (`enable_indexscan/bitmapscan = off`) on the narrow-ACL principal (grants on every
  10th document), same methodology as the recall baseline suite.
- **Ingestion throughput**: the worker pipeline seam (`stageUpload` + `runIngestion`,
  deterministic extraction/scan/embedding), docs/s and chunks/s.
- **Resource use**: process RSS/heap before/after; hardware record (CPU model/count,
  RAM, platform, node version).
- Reports are written to `report/benchmark-<ts>.json` (gitignored) and printed.

### Running it

```bash
npm run benchmark                              # CI fixture scale (2×50×3, 30 queries)
BENCH_SCALE=at-scale npm run benchmark         # G5 at-scale run (100×3334×3 ≈ 1M chunks,
                                               # 600 queries) — plan for hours of seeding
# knobs: BENCH_TENANTS BENCH_DOCS_PER_TENANT BENCH_CHUNKS_PER_DOC BENCH_QUERIES
#        BENCH_INGEST_DOCS BENCH_RECALL_TENANTS BENCH_REPORT_DIR
```

### Scale mapping

- CI runs the fixture scale (must complete in CI; correctness of the harness, not a
  performance gate — CI machines are shared and noisy).
- The G5 release agent runs `at-scale` on **recorded, dedicated hardware** and pastes
  the report's summary + hardware into the release evidence. Exact ground-truth
  scans are bounded to 10 tenants at scale (`BENCH_RECALL_TENANTS=10`): exact scans
  over 1M chunks are the honest, expensive path.

## Measurement log

| Date | Commit | Scale | Hardware | p50 | p95 | p99 | rps | recall@20 | ingest docs/s | report |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-08-05 | 7f5dfcb+ (S10 working tree) | ci (2×50×3=300 chunks, 34 queries) | Apple M4, 10 cores, 16 GiB, macOS arm64, node v25.8.0 (docker desktop) | 21.5 ms | 24.3 ms | 29.5 ms | 37.2 | 1.0000 (20 labeled queries) | 69.4 docs/s (5 docs) | `report/benchmark-2026-08-05T20-25-41-183Z.json` |
| — | — | at-scale (100 tenants / 1M chunks / 25 rps) | **pending G5 run** | — | — | — | — | — | — | — |

Fixture-scale numbers are informational only (warm cache, tiny corpus); the release
gate is the at-scale run on recorded hardware.

## Honest limits

- The envelope is a **target to measure before v1**, not a claim. If at-scale misses
  the 25 rps target, the release evidence says so and the plan changes — performance
  is never bought by weakening authorization (ADR-0011).
- HNSW index parameters (`hnsw.ef_search = 40`, strict-order iterative scan) are the
  shipped defaults; the benchmark measures them, it does not tune per-query.
- The demo stack (ops/compose.yml) is not a performance environment: Docker Desktop,
  memory limits, and the deterministic generator make its numbers meaningless for the
  envelope. At-scale runs use dedicated hardware with the same image/migrations.
- Provider latency (real LLM/embedding providers) is excluded by design: the envelope
  measures the retrieval + authorization path; provider adapters are measured
  separately per adapter contract.
