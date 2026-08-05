import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  DETERMINISTIC_EMBEDDING,
  RETRIEVAL_EF_SEARCH,
  retrievalSql,
  runRetrievalQuery,
  toVectorLiteral,
} from '@securerag/core';
import { getTestDb, resetData, type TestDb } from '@securerag/db/src/testkit.js';
import { buildRecallCorpus, type RecallCorpus } from '../src/recall-fixtures.js';

/**
 * Hybrid recall baseline (ADR-0008 "Recall baseline"): labeled corpus (narrow
 * grants spread across topics — the honest 1% selectivity scenario), exact
 * ground truths as the least-privilege runtime role with RLS on, ef_search
 * sweep at 100% / 10% / 1% grant selectivity, gate recall@20 >= 0.95 with 0%
 * result starvation, determinism, keyword-arm non-regression, and the
 * strict_order-vs-filtering footgun demonstration. The report is written to
 * test-results/recall.json (gitignored).
 *
 * Two sweeps, both gated:
 *  - hybrid, PRODUCTION settings (strict_order on, planner default): at
 *    fixture scale the planner prefers exact grant-driven scans (research r4
 *    §2.1 fallback), so this measures real production behavior at this scale.
 *  - vector arm, FORCED HNSW (forceIndex: enable_seqscan/sort off — a
 *    measurement lever, never a production setting): the genuine approximate
 *    index behavior that the baseline exists to characterize.
 */
const K = 20;
const EF_SWEEP = [40, 100, 200, 400];
const SELECTIVITIES = [
  { name: '100%', principal: (c: RecallCorpus) => c.full },
  { name: '10%', principal: (c: RecallCorpus) => c.narrow10 },
  { name: '1%', principal: (c: RecallCorpus) => c.narrow1 },
] as const;

interface Run {
  hits: number;
  expected: number;
  starved: boolean;
  latencyMs: number;
}

interface BucketStats {
  efSearch: number;
  selectivity: string;
  queries: number;
  recallMin: number;
  recallMean: number;
  hits: number;
  expected: number;
  starvedQueries: number;
  latencyMs: number[];
}

function recallStats(efSearch: number, selectivity: string, runs: Run[]): BucketStats {
  const recalls = runs.map((r) => (r.expected === 0 ? 1 : r.hits / r.expected));
  return {
    efSearch,
    selectivity,
    queries: runs.length,
    recallMin: Math.min(...recalls),
    recallMean: recalls.reduce((a, b) => a + b, 0) / recalls.length,
    hits: runs.reduce((a, r) => a + r.hits, 0),
    expected: runs.reduce((a, r) => a + r.expected, 0),
    starvedQueries: runs.filter((r) => r.starved).length,
    latencyMs: runs.map((r) => r.latencyMs).sort((a, b) => a - b),
  };
}

interface RecallReport {
  generatedAt: string;
  k: number;
  corpus: { docs: number; chunks: number; queries: number; narrowMode: string };
  efSearchSweep: number[];
  /** hybrid under production planner settings (exact fallback at fixture scale). */
  hybridProductionBuckets: BucketStats[];
  /** vector arm under forced HNSW + strict_order: genuine approximate-index behavior. */
  vectorForcedHnswBuckets: BucketStats[];
  determinism: { pass: boolean; queries: number };
  keywordUnaffected: { pass: boolean };
  gate: { pass: boolean; worstRecall: number; worstStarvation: number; chosenEfSearch: number };
  footgunWithoutStrictOrder: { starvedQueries: number; observed: string };
}

describe('hybrid recall baseline — ef_search sweep, selectivities, determinism, report', () => {
  let db: TestDb;
  let api: Pool;
  let corpus: RecallCorpus;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    corpus = await buildRecallCorpus(db.superuserPool, { narrowMode: 'spread' });
    api = db.apiPool;
  });

  afterAll(async () => {
    if (db) await db.stop();
  });

  const params = (principalId: string) => ({
    tenantId: corpus.tenantId,
    principalId,
    requestId: randomUUID(),
  });

  const exactHybrid = (principalId: string, question: string, embedding: string) =>
    runRetrievalQuery(api, params(principalId), 'hybrid', { question, embedding, limit: K }, { exact: true });

  const exactVector = (principalId: string, embedding: string) =>
    runRetrievalQuery(api, params(principalId), 'vector', { question: '', embedding, limit: K }, { exact: true });

  const approxHybridProduction = (principalId: string, question: string, embedding: string, efSearch: number) =>
    runRetrievalQuery(
      api,
      params(principalId),
      'hybrid',
      { question, embedding, limit: K },
      { efSearch, strictOrder: true },
    );

  const approxVectorForced = (
    principalId: string,
    embedding: string,
    efSearch: number,
    strictOrder: boolean,
  ) =>
    runRetrievalQuery(
      api,
      params(principalId),
      'vector',
      { question: '', embedding, limit: K },
      { efSearch, strictOrder, forceIndex: true },
    );

  async function sweep(
    mode: 'hybrid-production' | 'vector-forced',
  ): Promise<BucketStats[]> {
    const prepared = await Promise.all(
      corpus.queries.map(async (q) => {
        const [vector] = await DETERMINISTIC_EMBEDDING.embed([q.text]);
        return { q, embedding: toVectorLiteral(vector!) };
      }),
    );
    const buckets: BucketStats[] = [];
    for (const sel of SELECTIVITIES) {
      const principalId = sel.principal(corpus);
      const exactSets = await Promise.all(
        prepared.map(({ q, embedding }) =>
          (mode === 'hybrid-production'
            ? exactHybrid(principalId, q.text, embedding)
            : exactVector(principalId, embedding)
          ).then((rows) => new Set(rows.map((r) => r.chunkId))),
        ),
      );
      for (const efSearch of EF_SWEEP) {
        const runs: Run[] = [];
        for (let i = 0; i < prepared.length; i += 1) {
          const { q, embedding } = prepared[i]!;
          const exact = exactSets[i]!;
          const started = Date.now();
          const approx =
            mode === 'hybrid-production'
              ? await approxHybridProduction(principalId, q.text, embedding, efSearch)
              : await approxVectorForced(principalId, embedding, efSearch, true);
          const latencyMs = Date.now() - started;
          const hits = approx.filter((r) => exact.has(r.chunkId)).length;
          const expected = Math.min(K, exact.size);
          runs.push({ hits, expected, starved: approx.length < expected, latencyMs });
        }
        buckets.push(recallStats(efSearch, sel.name, runs));
      }
    }
    return buckets;
  }

  it('gates recall@20 >= 0.95 at every selectivity with 0% starvation (production hybrid + forced-HNSW vector arm), and writes the report', async () => {
    const hybridBuckets = await sweep('hybrid-production');
    const vectorBuckets = await sweep('vector-forced');
    const allBuckets = [...hybridBuckets, ...vectorBuckets];

    const failing = allBuckets.filter((b) => b.recallMin < 0.95 || b.starvedQueries > 0);
    let chosenEfSearch: number | undefined;
    for (const efSearch of EF_SWEEP) {
      const efBuckets = allBuckets.filter((b) => b.efSearch === efSearch);
      if (efBuckets.every((b) => b.recallMin >= 0.95 && b.starvedQueries === 0)) {
        chosenEfSearch = efSearch;
        break;
      }
    }
    expect(chosenEfSearch, 'no ef_search meets the gate').toBeDefined();
    expect(RETRIEVAL_EF_SEARCH, 'production default must be the chosen ef_search').toBe(chosenEfSearch);
    expect(failing, `gate failed for ${failing.length} buckets`).toEqual([]);

    // determinism: same query twice -> identical ordered id lists (all queries, chosen ef, full grant)
    const prepared = await Promise.all(
      corpus.queries.map(async (q) => {
        const [vector] = await DETERMINISTIC_EMBEDDING.embed([q.text]);
        return { q, embedding: toVectorLiteral(vector!) };
      }),
    );
    const deterministicHybrid = await Promise.all(
      prepared.map(async ({ q, embedding }) => {
        const a = await approxHybridProduction(corpus.full, q.text, embedding, chosenEfSearch!);
        const b = await approxHybridProduction(corpus.full, q.text, embedding, chosenEfSearch!);
        return JSON.stringify(a.map((r) => r.chunkId)) === JSON.stringify(b.map((r) => r.chunkId));
      }),
    );
    const deterministicVector = await Promise.all(
      prepared.map(async ({ embedding }) => {
        const a = await approxVectorForced(corpus.full, embedding, chosenEfSearch!, true);
        const b = await approxVectorForced(corpus.full, embedding, chosenEfSearch!, true);
        return JSON.stringify(a.map((r) => r.chunkId)) === JSON.stringify(b.map((r) => r.chunkId));
      }),
    );
    expect(
      [...deterministicHybrid, ...deterministicVector].every(Boolean),
      'same query twice must yield identical ordered id lists',
    ).toBe(true);

    // keyword-only mode unaffected: index-on and exact (index-off) keyword runs are identical
    const kwQuestion = corpus.queries[0]!.text;
    const kwApprox = await runRetrievalQuery(
      api, params(corpus.full), 'keyword', { question: kwQuestion, limit: K }, { efSearch: 40 },
    );
    const kwExact = await runRetrievalQuery(
      api, params(corpus.full), 'keyword', { question: kwQuestion, limit: K }, { exact: true },
    );
    expect(kwApprox.map((r) => r.chunkId)).toEqual(kwExact.map((r) => r.chunkId));

    // footgun demonstration (ASSERTED, not informational): the vector arm alone,
    // forced HNSW WITHOUT strict_order, ef_search=40, at 1% selectivity — the
    // documented filtering-after-scan starvation (research r4 §2.1:
    // ~ef_search x selectivity candidates). strict_order is the fix the gate
    // proves above.
    const allowed1 = corpus.narrow1ChunkIds.length;
    const footgunRuns = await Promise.all(
      prepared.map(async ({ embedding }) =>
        approxVectorForced(corpus.narrow1, embedding, 40, false),
      ),
    );
    const starvedVector = footgunRuns.filter((r) => r.length < Math.min(K, allowed1)).length;
    expect(
      starvedVector,
      `plain HNSW at 1% selectivity must starve (got ${starvedVector}/${footgunRuns.length} starved of min(k, allowed)=${Math.min(K, allowed1)})`,
    ).toBeGreaterThan(0);

    const worstRecall = Math.min(...allBuckets.map((b) => b.recallMin));
    const worstStarvation = allBuckets.reduce((a, b) => a + b.starvedQueries, 0);
    const report: RecallReport = {
      generatedAt: new Date().toISOString(),
      k: K,
      corpus: {
        docs: corpus.docs,
        chunks: corpus.allChunkIds.length,
        queries: corpus.queries.length,
        narrowMode: 'spread',
      },
      efSearchSweep: EF_SWEEP,
      hybridProductionBuckets: hybridBuckets,
      vectorForcedHnswBuckets: vectorBuckets,
      determinism: { pass: [...deterministicHybrid, ...deterministicVector].every(Boolean), queries: prepared.length },
      keywordUnaffected: { pass: kwApprox.length === kwExact.length },
      gate: {
        pass: worstRecall >= 0.95 && worstStarvation === 0,
        worstRecall,
        worstStarvation,
        chosenEfSearch: chosenEfSearch!,
      },
      footgunWithoutStrictOrder: {
        starvedQueries: starvedVector,
        observed: `vector arm alone, forced HNSW, ef_search=40, strict_order off, 1% selectivity: ${starvedVector}/${footgunRuns.length} queries returned fewer than min(k, allowed)=${Math.min(K, allowed1)} rows`,
      },
    };

    const reportPath = path.resolve(process.cwd(), 'test-results', 'recall.json');
    await mkdir(path.dirname(reportPath), { recursive: true });
    await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  });

  it('labels the corpus: every query has a non-empty topic overlap group covered by exact ground truth', async () => {
    expect(corpus.docs).toBeGreaterThanOrEqual(200);
    expect(corpus.queries.length).toBeGreaterThanOrEqual(30);
    for (const q of corpus.queries) {
      expect(q.topicChunkIds.length, `query ${q.text} has no labeled group`).toBeGreaterThan(0);
    }
    const [vector] = await DETERMINISTIC_EMBEDDING.embed([corpus.queries[0]!.text]);
    const exact = await exactHybrid(corpus.full, corpus.queries[0]!.text, toVectorLiteral(vector!));
    const hits = exact.filter((r) => corpus.queries[0]!.topicChunkIds.includes(r.chunkId)).length;
    expect(hits).toBeGreaterThan(0);
  });

  it('produces stable SQL text per mode (single statement, no user interpolation)', () => {
    const hybrid = retrievalSql('hybrid');
    expect(hybrid).toContain('securerag.rrf(');
    expect(hybrid).toContain('row_number()');
    expect(hybrid).toContain('UNION ALL');
    expect(hybrid).toContain('ORDER BY score DESC, chunk_id');
    for (const mode of ['keyword', 'vector', 'hybrid'] as const) {
      expect(retrievalSql(mode).includes('${')).toBe(false);
    }
  });
});
