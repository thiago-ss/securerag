/**
 * Envelope benchmark (S10, ADR-0011; contract: docs/ops/envelope.md).
 *
 * Measures the REAL API over HTTP against a real PostgreSQL + pgvector
 * corpus, at two scales:
 *
 *  - CI fixture scale (BENCH_SCALE=ci, default): 2 tenants × 50 docs × 3
 *    chunks, 30 queries — a smoke run that must complete in CI.
 *  - At scale (BENCH_SCALE=at-scale): 100 tenants × 3334 docs × 3 chunks
 *    (≈1M chunks) and 600 queries (≥25 rps sustained) — run by the G5
 *    release agent on recorded hardware, never in CI.
 *
 * Measurements: retrieval latency p50/p95/p99 (HTTP boundary), achieved rps,
 * recall@20 vs exact (the production hybrid arm vs the exact SQL ground
 * truth, same methodology as the recall baseline suite), ingestion
 * throughput at the worker pipeline seam (stageUpload + runIngestion),
 * resource use, and the hardware record. Security posture is identical to
 * the adversarial suite: least-privilege runtime pool, deterministic
 * providers, zero content in reports. Reports land in report/ (gitignored)
 * and print to stdout.
 *
 * Usage:
 *   npm run benchmark                      # CI fixture scale
 *   BENCH_SCALE=at-scale npm run benchmark # G5 at-scale run (hours)
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import type { FastifyInstance } from 'fastify';
import {
  DETERMINISTIC_EMBEDDING,
  InMemorySourceObjectStore,
  runIngestion,
  runRetrievalQuery,
  stageUpload,
  toVectorLiteral,
  type EmbeddingProvider,
} from '@securerag/core';
import {
  DETERMINISTIC_MALWARE_SCANNER,
  HEURISTIC_INJECTION_DETECTOR,
  SpyGenerator,
  STANDARD_EXTRACTION,
} from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import {
  getTestDb,
  resetData,
  seedGrant,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { buildRecallCorpus, type RecallCorpus } from './recall-fixtures.js';
import { buildApp, type OidcApiConfig } from '@securerag/api/src/app.js';
import { loginViaOidc } from '@securerag/api/src/testkit.js';

interface BenchEnv {
  scale: 'ci' | 'at-scale';
  tenants: number;
  docsPerTenant: number;
  chunksPerDoc: number;
  queries: number;
  ingestDocs: number;
  recallTenants: number;
  reportDir: string;
}

function readEnv(): BenchEnv {
  const scale = process.env['BENCH_SCALE'] === 'at-scale' ? 'at-scale' : 'ci';
  const presets: Record<BenchEnv['scale'], Omit<BenchEnv, 'scale' | 'reportDir'>> = {
    ci: { tenants: 2, docsPerTenant: 50, chunksPerDoc: 3, queries: 30, ingestDocs: 5, recallTenants: 2 },
    'at-scale': {
      tenants: 100,
      docsPerTenant: 3334,
      chunksPerDoc: 3,
      queries: 600,
      ingestDocs: 100,
      // Exact ground-truth scans are the honest, expensive path: measured on
      // a bounded tenant subset at scale (documented in envelope.md).
      recallTenants: 10,
    },
  };
  const p = presets[scale];
  const num = (key: string, fallback: number): number => {
    const raw = process.env[key];
    return raw === undefined ? fallback : Number(raw);
  };
  return {
    scale,
    tenants: num('BENCH_TENANTS', p.tenants),
    docsPerTenant: num('BENCH_DOCS_PER_TENANT', p.docsPerTenant),
    chunksPerDoc: num('BENCH_CHUNKS_PER_DOC', p.chunksPerDoc),
    queries: num('BENCH_QUERIES', p.queries),
    ingestDocs: num('BENCH_INGEST_DOCS', p.ingestDocs),
    recallTenants: num('BENCH_RECALL_TENANTS', p.recallTenants),
    reportDir: process.env['BENCH_REPORT_DIR'] ?? new URL('../../../report', import.meta.url).pathname,
  };
}

function percentile(sorted: number[], pct: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((pct / 100) * sorted.length) - 1));
  return sorted[idx] ?? 0;
}

function hardware(): Record<string, string | number> {
  const cpus = os.cpus();
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    cpuModel: cpus[0]?.model ?? 'unknown',
    cpuCount: cpus.length,
    totalMemGb: Number((os.totalmem() / 1024 ** 3).toFixed(1)),
    nodeVersion: process.version,
  };
}

interface Session {
  cookieHeader: string;
  csrfToken: string;
}

async function main(db: TestDb): Promise<void> {
  const env = readEnv();
  const startedAt = Date.now();
  const memoryBefore = process.memoryUsage();
  await resetData(db.superuserPool);

  const embedding: EmbeddingProvider = DETERMINISTIC_EMBEDDING;
  const chunksExpected = env.tenants * env.docsPerTenant * env.chunksPerDoc;

  console.log(
    `[bench] scale=${env.scale} tenants=${env.tenants} docs=${env.docsPerTenant}/tenant ` +
      `chunks=${env.chunksPerDoc}/doc (total chunks ≈ ${chunksExpected}) queries=${env.queries}`,
  );

  // ---------- Corpus: one recall corpus per tenant (distinct subjects) ----------
  const corpora: RecallCorpus[] = [];
  const subjects: string[] = [];
  for (let i = 0; i < env.tenants; i += 1) {
    const corpus = await buildRecallCorpus(db.superuserPool, {
      docCount: env.docsPerTenant,
      chunkCount: env.chunksPerDoc,
      subjectPrefix: `bench${i}`,
    });
    corpora.push(corpus);
    subjects.push(`bench${i}-full-sub`);
  }
  const seededAt = Date.now();

  // ---------- Real API over HTTP ----------
  const provider = new FakeOidcProvider({ issuer: 'test-issuer', clientId: 'securerag-api' });
  await provider.start();
  const oidc: OidcApiConfig = {
    issuer: 'test-issuer',
    clientId: 'securerag-api',
    redirectUri: 'http://securerag.test/auth/callback',
    postLogoutRedirectUri: 'http://securerag.test/',
    discoveryUrl: provider.discoveryUrl,
    sessionCookieName: 'securerag_session',
    sessionCookieSecure: false,
    sessionTtlSeconds: 3600,
  };
  const app: FastifyInstance = await buildApp({
    pool: db.apiPool,
    providers: new SpyGenerator(),
    store: new InMemorySourceObjectStore(),
    oidc,
  });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;

  // One session per tenant for the full-grant principal (least-privilege RLS
  // on every request, exactly like the production envelope).
  const sessions: Session[] = [];
  for (const subject of subjects) {
    sessions.push(await loginViaOidc(base, provider, subject));
  }

  const latencyMs: number[] = [];
  let answered = 0;
  let refused = 0;

  const runOne = async (corpusIdx: number, question: string): Promise<void> => {
    const corpus = corpora[corpusIdx]!;
    const session = sessions[corpusIdx]!;
    const t0 = performance.now();
    const res = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: corpus.tenantId, question }),
    });
    latencyMs.push(performance.now() - t0);
    if (res.status !== 200) throw new Error(`retrieval returned ${res.status}`);
    const body = (await res.json()) as { decision: string };
    if (body.decision === 'answered') answered += 1;
    else if (body.decision === 'refused') refused += 1;
  };

  // ---------- Warm cache: 2 queries per tenant (discarded) ----------
  for (let i = 0; i < corpora.length; i += 1) {
    const text = corpora[i]!.queries[0]!.text;
    await runOne(i, text);
    await runOne(i, text);
  }

  // ---------- Latency: BENCH_QUERIES round-robin across tenants ----------
  const questionFor = (i: number): { corpusIdx: number; text: string } => {
    const corpusIdx = i % corpora.length;
    const queries = corpora[corpusIdx]!.queries;
    const text = queries[Math.floor(i / corpora.length) % queries.length]!.text;
    return { corpusIdx, text };
  };
  for (let i = 0; i < env.queries; i += 1) {
    const q = questionFor(i);
    await runOne(q.corpusIdx, q.text);
  }
  const retrievalEndedAt = Date.now();
  const sorted = [...latencyMs].sort((a, b) => a - b);
  const p50 = percentile(sorted, 50);
  const p95 = percentile(sorted, 95);
  const p99 = percentile(sorted, 99);
  const totalSeconds = (retrievalEndedAt - seededAt) / 1000;
  const achievedRps = latencyMs.length / Math.max(totalSeconds, 0.001);

  // ---------- recall@20 vs exact (production hybrid arm vs exact SQL path;
  // selective principal narrow10 so the metric is meaningful). ----------
  const K = 20;
  let recallSum = 0;
  let recallQueries = 0;
  const recallCorpora = corpora.slice(0, Math.min(env.recallTenants, corpora.length));
  for (const corpus of recallCorpora) {
    for (const query of corpus.queries) {
      const vector = (await embedding.embed([query.text]))[0];
      if (vector === undefined) throw new Error('embedding failed');
      const embeddingLiteral = toVectorLiteral(vector);
      const params = { tenantId: corpus.tenantId, principalId: corpus.narrow10, requestId: randomUUID() };
      const [approx, exact] = await Promise.all([
        runRetrievalQuery(db.apiPool, params, 'hybrid', {
          question: query.text,
          embedding: embeddingLiteral,
          limit: K,
        }),
        runRetrievalQuery(db.apiPool, params, 'hybrid', {
          question: query.text,
          embedding: embeddingLiteral,
          limit: K,
        }, { exact: true }),
      ]);
      const exactIds = new Set(exact.map((c) => c.chunkId));
      const hits = approx.filter((c) => exactIds.has(c.chunkId)).length;
      const denominator = Math.min(K, exactIds.size);
      recallSum += denominator > 0 ? hits / denominator : 0;
      recallQueries += 1;
    }
  }
  const recallAt20 = recallSum / Math.max(recallQueries, 1);

  // ---------- Ingestion throughput (worker pipeline seam) ----------
  const store = new InMemorySourceObjectStore();
  const ingestDeps = {
    workerPool: db.workerPool,
    store,
    extractor: STANDARD_EXTRACTION,
    scanner: DETERMINISTIC_MALWARE_SCANNER,
    detector: HEURISTIC_INJECTION_DETECTOR,
    embedding,
  };
  const ingestStart = Date.now();
  let ingestChunks = 0;
  const sampleText = 'Benchmark ingest source document with plenty of synthetic content. '.repeat(8);
  for (let i = 0; i < env.ingestDocs; i += 1) {
    const corpus = corpora[i % corpora.length]!;
    const { rows } = await db.superuserPool.query<{ document_id: string }>(
      `INSERT INTO securerag.documents (tenant_id, title) VALUES ($1, $2) RETURNING document_id`,
      [corpus.tenantId, `bench ingest doc ${i}`],
    );
    const documentId = rows[0]?.document_id;
    if (documentId === undefined) throw new Error('ingest document insert failed');
    // stageUpload is manage-gated: grant the corpus principal manage on the
    // bench document (the same creator-manage flow the console uses).
    await seedGrant(db.superuserPool, {
      tenantId: corpus.tenantId,
      documentId,
      subjectType: 'principal',
      subjectId: corpus.full,
      capability: 'manage',
    });
    const bytes = Buffer.from(sampleText, 'utf8');
    const sha256Hex = createHash('sha256').update(bytes).digest('hex');
    const objectKey = `bench/${documentId}/${sha256Hex}.txt`;
    await store.put(objectKey, bytes);
    const staged = await stageUpload(db.workerPool, {
      tenantId: corpus.tenantId,
      principalId: corpus.full,
      requestId: randomUUID(),
      documentId,
      objectKey,
      sha256Hex,
      filename: `bench-${i}.txt`,
      contentType: 'text/plain',
      sizeBytes: bytes.length,
    });
    if (staged === null) throw new Error('stageUpload returned null');
    const outcome = await runIngestion(ingestDeps, {
      tenantId: corpus.tenantId,
      requestId: randomUUID(),
      documentId,
      versionId: staged.versionId,
      objectKey,
      filename: `bench-${i}.txt`,
      contentType: 'text/plain',
    });
    if (outcome.outcome !== 'published') throw new Error(`ingest outcome ${outcome.outcome}`);
    const { rows: chunkRows } = await db.superuserPool.query<{ n: string }>(
      `SELECT count(*) AS n FROM securerag.chunks WHERE version_id = $1`,
      [staged.versionId],
    );
    ingestChunks += Number(chunkRows[0]?.n ?? 0);
  }
  const ingestSeconds = (Date.now() - ingestStart) / 1000;

  // ---------- Resource use ----------
  const memoryAfter = process.memoryUsage();
  const memUsedMb = (m: NodeJS.MemoryUsage): Record<string, number> => ({
    rssMb: Number((m.rss / 1024 ** 2).toFixed(1)),
    heapUsedMb: Number((m.heapUsed / 1024 ** 2).toFixed(1)),
  });

  const report = {
    generatedAt: new Date().toISOString(),
    scale: env.scale,
    corpus: {
      tenants: env.tenants,
      docsPerTenant: env.docsPerTenant,
      chunksPerDoc: env.chunksPerDoc,
      chunksExpected,
      seedSeconds: Number(((seededAt - startedAt) / 1000).toFixed(1)),
    },
    retrieval: {
      queries: latencyMs.length,
      p50Ms: Number(p50.toFixed(1)),
      p95Ms: Number(p95.toFixed(1)),
      p99Ms: Number(p99.toFixed(1)),
      meanMs: Number((latencyMs.reduce((a, b) => a + b, 0) / Math.max(latencyMs.length, 1)).toFixed(1)),
      achievedRps: Number(achievedRps.toFixed(2)),
      answered,
      refused,
      totalSeconds: Number(totalSeconds.toFixed(1)),
    },
    recall: {
      k: K,
      tenants: recallCorpora.length,
      meanRecallAtK: Number(recallAt20.toFixed(4)),
      labeledQueries: recallQueries,
    },
    ingestion: {
      docs: env.ingestDocs,
      chunks: ingestChunks,
      docsPerSecond: Number((env.ingestDocs / Math.max(ingestSeconds, 0.001)).toFixed(2)),
      chunksPerSecond: Number((ingestChunks / Math.max(ingestSeconds, 0.001)).toFixed(2)),
      totalSeconds: Number(ingestSeconds.toFixed(1)),
    },
    resources: {
      before: memUsedMb(memoryBefore),
      after: memUsedMb(memoryAfter),
    },
    hardware: hardware(),
  };

  await mkdir(env.reportDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = `${env.reportDir}/benchmark-${stamp}.json`;
  await writeFile(file, JSON.stringify(report, null, 2));

  console.log(`[bench] done — report: ${file}`);
  console.log(JSON.stringify(report, null, 2));

  await app.close();
  await provider.stop();
}

async function run(): Promise<void> {
  const db = await getTestDb();
  try {
    await main(db);
  } finally {
    // Never leave the HTTP servers or the container behind (the process would
    // otherwise hang and the container leak).
    await db.stop();
  }
}

run().catch((err: unknown) => {
  console.error('[bench] failed:', err);
  process.exitCode = 1;
});
