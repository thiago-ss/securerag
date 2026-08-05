import type { Pool, PoolClient } from 'pg';
import { MembershipError, withIdentityContext, withSecurityContext } from '@securerag/security';
import {
  HEURISTIC_INJECTION_DETECTOR,
  type AnswerGenerator,
  type InjectionDetector,
} from '@securerag/providers';
import { appendAudit, sha256 } from './audit.js';
import { DETERMINISTIC_EMBEDDING, toVectorLiteral, type EmbeddingProvider } from './embeddings.js';
import { grantPredicateSql } from './grants.js';
import { decide } from './refusal.js';
import type { AuditEvent, Citation, EvidenceChunk, RetrievalOutcome, SecurityParams } from './types.js';

/**
 * Retrieval modes (S6, ADR-0008). 'hybrid' is the production default and the
 * only mode exposed at the HTTP boundary in v1; 'keyword' | 'vector' are
 * contract-visible seams for tests and CI (single-arm diagnosis, recall
 * baselines, keyword regression).
 */
export type RetrievalMode = 'hybrid' | 'keyword' | 'vector';

export interface RetrievalParams extends SecurityParams {
  question: string;
  /** Retrieval mode; defaults to 'hybrid'. */
  mode?: RetrievalMode;
}

export interface RetrievalDeps {
  pool: Pool;
  providers: AnswerGenerator;
  /** Embedding provider for the vector/hybrid arms; defaults to the deterministic CI fake. */
  embeddings?: EmbeddingProvider;
  /** Milliseconds-since-epoch clock for latency_ms; defaults to Date.now. */
  clock?: () => number;
  /** SQL LIMIT; defaults to RETRIEVAL_DEFAULT_LIMIT. */
  limit?: number;
  /**
   * Query-time injection detector (ADR-0006 layer 7 — defense-in-depth ONLY,
   * a signal, never a gate). Defaults to the deterministic heuristic adapter
   * (CI/demo). A detector miss, an outage, or a detector that always says
   * 'none' changes NOTHING about authorization (proven by
   * core/test/detection-off.test.ts). A 'high' result only appends an
   * 'injection:detected' audit event (redacted query hash, never the text)
   * and processing continues unmodified.
   */
  injectionDetector?: InjectionDetector;
}

export const RETRIEVAL_DEFAULT_LIMIT = 10;

/**
 * RRF constant k = 60 (ADR-0008, research r4 §3: the official pgvector
 * hybrid-search example default). Not a security parameter; single place the
 * documented default is pinned, passed to securerag.rrf in the hybrid SQL.
 */
export const RRF_K = 60;

/**
 * hnsw.ef_search default, chosen by the eval recall baseline (ADR-0008
 * amendment 1): the smallest swept value meeting recall@20 >= 0.95 at every
 * grant selectivity with hnsw.iterative_scan = strict_order. strict_order
 * makes recall independent of ef_search for corpora below
 * hnsw.max_scan_tuples, so the baseline default is the smallest sweep value.
 */
export const RETRIEVAL_EF_SEARCH = 40;

/** Arm pool size = final LIMIT (documented in ADR-0008 amendment 1): with
 * strict_order iterative scans the vector arm overfetches exactly as needed,
 * so no blind large pool is required; exact ground truth uses the same SQL so
 * approx/exact stay comparable. */
export const RETRIEVAL_ARM_LIMIT = 60;

/**
 * Keyword arm — EXACTLY the T3 contract §Retrieval keyword arm shape:
 * parameterized websearch query, all filters in SQL (no application-side
 * post-filtering ever), deterministic ORDER BY (rank DESC, chunk_id), LIMIT.
 * The grant EXISTS is the shared single-source-of-truth predicate from
 * grants.ts, composed with the contract's outer aliases (c.tenant_id /
 * d.document_id).
 */
const KEYWORD_SQL = `
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
   AND d.status <> 'deleted'
   AND v.status IN ('valid','released')
   AND v.is_current
   AND ${grantPredicateSql('d.document_id', 'c.tenant_id')}
 ORDER BY rank DESC, c.chunk_id
 LIMIT $2`;

/**
 * Vector arm — the SAME authorization shape as the keyword arm (identical
 * FROM/JOIN/WHERE/EXISTS grant predicate, RLS applies to every relation inside
 * it), with the ordering expression `embedding OPERATOR(public.<=>) $1`
 * (index-usable shape, research r4 §2). The vector type AND its operators live
 * in the `public` schema (pgvector extension) while runtime roles pin
 * search_path = securerag, so both the cast and the operator are
 * schema-qualified (OPERATOR(public.<=>) resolves to the same operator OID as
 * `<=>`, so the HNSW index remains usable). NULL embeddings are excluded (they
 * cannot be compared and are not indexed; documented in ADR-0008). Runs under
 * SET LOCAL hnsw.iterative_scan = strict_order issued by the caller.
 */
const VECTOR_SQL = `
SELECT c.chunk_id, c.chunk_no, c.text_redacted, c.span_start, c.span_end,
       v.version_id, v.version_no, d.document_id, d.title,
       c.embedding OPERATOR(public.<=>) $1::public.vector AS rank
  FROM securerag.chunks c
  JOIN securerag.document_versions v
    ON v.tenant_id = c.tenant_id AND v.version_id = c.version_id
  JOIN securerag.documents d
    ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
 WHERE c.embedding IS NOT NULL
   AND d.status <> 'deleted'
   AND v.status IN ('valid','released')
   AND v.is_current
   AND ${grantPredicateSql('d.document_id', 'c.tenant_id')}
 ORDER BY c.embedding OPERATOR(public.<=>) $1::public.vector, c.chunk_id
 LIMIT $2`;

/**
 * Hybrid arm — single statement (research r4 §5): ROW_NUMBER per arm with
 * deterministic tie-breaks, RRF fusion with numeric arithmetic via
 * securerag.rrf (k = 60), union semantics (UNION ALL + GROUP BY, never
 * intersect), final ORDER BY score DESC, chunk_id (deterministic stable
 * ordering), LIMIT. MATERIALIZED CTEs keep the planner from inlining/reordering
 * the arms. Both arms carry the full authorization predicate inside SQL.
 */
const HYBRID_SQL = `
WITH keyword AS MATERIALIZED (
    SELECT c.chunk_id, c.chunk_no, c.text_redacted, c.span_start, c.span_end,
           v.version_id, v.version_no, d.document_id, d.title,
           row_number() OVER (ORDER BY ts_rank_cd(c.search_vec, q) DESC, c.chunk_id) AS rnk
      FROM securerag.chunks c
      JOIN securerag.document_versions v
        ON v.tenant_id = c.tenant_id AND v.version_id = c.version_id
      JOIN securerag.documents d
        ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
     CROSS JOIN LATERAL websearch_to_tsquery('english', $1) q
     WHERE c.search_vec @@ q
       AND d.status <> 'deleted'
       AND v.status IN ('valid','released')
       AND v.is_current
       AND ${grantPredicateSql('d.document_id', 'c.tenant_id')}
     ORDER BY ts_rank_cd(c.search_vec, q) DESC, c.chunk_id
     LIMIT $3
),
semantic AS MATERIALIZED (
    SELECT c.chunk_id, c.chunk_no, c.text_redacted, c.span_start, c.span_end,
           v.version_id, v.version_no, d.document_id, d.title,
           row_number() OVER (ORDER BY c.embedding OPERATOR(public.<=>) $2::public.vector, c.chunk_id) AS rnk
      FROM securerag.chunks c
      JOIN securerag.document_versions v
        ON v.tenant_id = c.tenant_id AND v.version_id = c.version_id
      JOIN securerag.documents d
        ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
     WHERE c.embedding IS NOT NULL
       AND d.status <> 'deleted'
       AND v.status IN ('valid','released')
       AND v.is_current
       AND ${grantPredicateSql('d.document_id', 'c.tenant_id')}
     ORDER BY c.embedding OPERATOR(public.<=>) $2::public.vector, c.chunk_id
     LIMIT $3
),
fused AS MATERIALIZED (
    SELECT chunk_id, chunk_no, text_redacted, span_start, span_end,
           version_id, version_no, document_id, title,
           SUM(securerag.rrf(${RRF_K}, ARRAY[rnk::integer])) AS score
      FROM (
        SELECT chunk_id, chunk_no, text_redacted, span_start, span_end,
               version_id, version_no, document_id, title, rnk
          FROM keyword
        UNION ALL
        SELECT chunk_id, chunk_no, text_redacted, span_start, span_end,
               version_id, version_no, document_id, title, rnk
          FROM semantic
      ) arms
     GROUP BY chunk_id, chunk_no, text_redacted, span_start, span_end,
              version_id, version_no, document_id, title
)
SELECT chunk_id, chunk_no, text_redacted, span_start, span_end,
       version_id, version_no, document_id, title, score AS rank
  FROM fused
 ORDER BY score DESC, chunk_id
 LIMIT $4`;

/**
 * Per-mode parameter layout. Hybrid takes two limits: $3 = per-arm pool
 * (overfetch so RRF can fuse candidates ranked beyond the final limit; never
 * less than the requested limit) and $4 = the final result limit. Keyword and
 * vector arms have a single limit.
 */
export function retrievalParams(
  mode: RetrievalMode,
  args: { question: string; embedding?: string; limit: number; armLimit?: number },
): (string | number)[] {
  switch (mode) {
    case 'keyword':
      return [args.question, args.limit];
    case 'vector':
      if (args.embedding === undefined) throw new Error('vector mode requires an embedding');
      return [args.embedding, args.limit];
    case 'hybrid': {
      if (args.embedding === undefined) throw new Error('hybrid mode requires an embedding');
      const armLimit = Math.max(args.armLimit ?? RETRIEVAL_ARM_LIMIT, args.limit);
      return [args.question, args.embedding, armLimit, args.limit];
    }
  }
}

export function retrievalSql(mode: RetrievalMode): string {
  switch (mode) {
    case 'keyword':
      return KEYWORD_SQL;
    case 'vector':
      return VECTOR_SQL;
    case 'hybrid':
      return HYBRID_SQL;
  }
}

/**
 * Per-query planner settings for the retrieval arms. The HNSW settings are
 * transaction-local SET LOCAL statements inside the same transaction as the
 * query (the withSecurityContext transaction); `exact` is the ground-truth
 * path (SET LOCAL enable_indexscan/bitmapscan = off, research r4 §2.1) used
 * by the recall baseline.
 *
 * `forceIndex` (SET LOCAL enable_seqscan = off + enable_sort = off) is a
 * MEASUREMENT lever for the recall baseline only: at fixture scale the planner
 * legitimately prefers the exact grant-driven join + sort over the HNSW scan
 * (research r4 §2.1 fallback — small authorized sets are scanned exactly,
 * which is correctness-neutral). Disabling seq scans and sorts leaves the HNSW
 * index scan as the only ordering source for the vector arm, so the baseline
 * measures genuine approximate-index behavior (recall, starvation, ef_search
 * sensitivity). Production never sets it; the planner's exact fallback is a
 * feature.
 */
export interface RetrievalQuerySettings {
  /** hnsw.ef_search; only applied for vector/hybrid modes when not exact. */
  efSearch?: number;
  /** SET LOCAL hnsw.iterative_scan = strict_order; on by default for vector/hybrid. */
  strictOrder?: boolean;
  /** Exact ground truth: disable index scans (incl. HNSW/GIN bitmap) for the query. */
  exact?: boolean;
  /** Measurement only: force the HNSW index path (recall baseline harness). */
  forceIndex?: boolean;
}

/**
 * Run the mode's retrieval SQL on an already-open transaction client (inside
 * withSecurityContext, so RLS + the grant predicate authorize every row).
 * Returns ordered evidence chunks; deterministic ordering per mode.
 */
export async function executeRetrievalQuery(
  client: PoolClient,
  mode: RetrievalMode,
  args: { question: string; embedding?: string; limit: number },
  settings: RetrievalQuerySettings = {},
): Promise<EvidenceChunk[]> {
  if (settings.exact) {
    await client.query('SET LOCAL enable_indexscan = off');
    await client.query('SET LOCAL enable_bitmapscan = off');
  } else {
    if (settings.forceIndex && mode !== 'keyword') {
      await client.query('SET LOCAL enable_seqscan = off');
      await client.query('SET LOCAL enable_sort = off');
    }
    if (mode !== 'keyword') {
      if (settings.strictOrder !== false) {
        await client.query('SET LOCAL hnsw.iterative_scan = strict_order');
      }
      const efSearch = settings.efSearch ?? RETRIEVAL_EF_SEARCH;
      await client.query(`SET LOCAL hnsw.ef_search = ${efSearch}`);
    }
  }
  const { rows } = await client.query<RetrievalRow>(
    retrievalSql(mode),
    retrievalParams(mode, args),
  );
  return rows.map(toEvidenceChunk);
}

/**
 * Full retrieval-query seam for tests/baselines: opens the verified security
 * context and runs executeRetrievalQuery inside it as the least-privilege
 * runtime role. No generation, no refusal gate, no audit — the SQL arms only.
 */
export async function runRetrievalQuery(
  pool: Pool,
  params: SecurityParams,
  mode: RetrievalMode,
  args: { question: string; embedding?: string; limit: number },
  settings: RetrievalQuerySettings = {},
): Promise<EvidenceChunk[]> {
  return withSecurityContext(pool, params, (client) =>
    executeRetrievalQuery(client, mode, args, settings),
  );
}

/**
 * rank is float4/float8 (keyword/vector arms) or numeric text (hybrid fused
 * RRF score); the driver returns numeric as string, so normalize to number.
 */
interface RetrievalRow {
  chunk_id: string;
  chunk_no: number;
  text_redacted: string;
  span_start: number;
  span_end: number;
  version_id: string;
  version_no: number;
  document_id: string;
  title: string;
  rank: string | number;
}

function toEvidenceChunk(row: RetrievalRow): EvidenceChunk {
  return {
    chunkId: row.chunk_id,
    chunkNo: row.chunk_no,
    text: row.text_redacted,
    spanStart: row.span_start,
    spanEnd: row.span_end,
    versionId: row.version_id,
    versionNo: row.version_no,
    documentId: row.document_id,
    title: row.title,
    rank: Number(row.rank),
  };
}

/**
 * Query-time detection, layer 7 of the ADR-0006 stack: run the detector on
 * the QUESTION inside the verified security context and, on any high-risk
 * signal, append 'injection:detected' with the REDACTED query hash only
 * (never the query text; reasons are fixed pattern ids). Detection NEVER
 * blocks or alters processing — not even a throwing detector: an outage must
 * not weaken authorization (threat-model.md: "A detector miss must not
 * weaken tenant/ACL enforcement"). Returns nothing; the caller continues.
 */
async function detectAndAudit(
  client: PoolClient,
  ctx: import('@securerag/security').SecurityContext,
  detector: InjectionDetector,
  params: RetrievalParams,
): Promise<void> {
  try {
    const scan = await detector.scan(params.question);
    if (scan.risk !== 'high') return;
    await appendAudit({
      client,
      event: {
        eventType: 'injection:detected',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: ctx.authEpoch,
        queryHash: sha256(params.question),
        filters: { risk: 'high', reasons: scan.reasons },
      },
    });
  } catch {
    // detector outage: defense-in-depth layer is silent, authorization unchanged
  }
}

/**
 * End-to-end retrieval run (T3 contract §Domain contracts, S6 hybrid upgrade):
 *  1. withIdentityContext — the ONLY identity-context use: list the
 *     principal's active memberships; the requested tenant is an untrusted
 *     candidate, never authority.
 *  2. Embed the question (redaction-free today; S4 plugs in before embed).
 *  3. withSecurityContext — verified tenant/principal/membership/request/epoch
 *     context; hybrid (default) | keyword | vector SQL; evidence bundle
 *     (RLS-filtered rows; authorization never happens after SQL).
 *  4. Layer-7 detection signal: high-risk question -> 'injection:detected'
 *     audit event (query hash only); processing NEVER changes.
 *  5. decide(bundle, question) — below the calibrated threshold (or empty)
 *     yields refused INSUFFICIENT_EVIDENCE, audited, no generation.
 *  6. Otherwise the provider spy generates a deterministic answer that cites
 *     only provided citations; audited as retrieval:allowed.
 * The audit event is written inside the protected transaction. Never answers
 * from memory; never exposes rows to application-side re-filtering.
 */
export async function runRetrieval(
  deps: RetrievalDeps,
  params: RetrievalParams,
): Promise<RetrievalOutcome> {
  const clock = deps.clock ?? Date.now;
  const started = clock();
  const limit = deps.limit ?? RETRIEVAL_DEFAULT_LIMIT;
  const mode = params.mode ?? 'hybrid';
  const embeddings = deps.embeddings ?? DETERMINISTIC_EMBEDDING;
  const injectionDetector = deps.injectionDetector ?? HEURISTIC_INJECTION_DETECTOR;

  const identity = await withIdentityContext(deps.pool, params.principalId, async () => undefined);
  if (!identity.memberships.some((m) => m.tenantId === params.tenantId)) {
    throw new MembershipError();
  }

  let queryEmbedding: string | undefined;
  if (mode !== 'keyword') {
    const [vector] = await embeddings.embed([params.question]);
    if (!vector) throw new Error('embedding provider returned no vector for the question');
    queryEmbedding = toVectorLiteral(vector);
  }
  const queryArgs =
    queryEmbedding === undefined
      ? { question: params.question, limit }
      : { question: params.question, embedding: queryEmbedding, limit };

  return withSecurityContext(deps.pool, params, async (client, ctx) => {
    await detectAndAudit(client, ctx, injectionDetector, params);

    const bundle = await executeRetrievalQuery(
      client,
      mode,
      queryArgs,
      { efSearch: RETRIEVAL_EF_SEARCH, strictOrder: true },
    );

    const baseAudit = {
      requestId: params.requestId,
      principalId: ctx.principalId,
      membershipId: ctx.membershipId,
      authEpoch: ctx.authEpoch,
      redactedQuery: params.question,
      queryHash: sha256(params.question),
      candidateIds: bundle.map((chunk) => chunk.chunkId),
      scores: bundle.map((chunk) => chunk.rank),
      latencyMs: clock() - started,
    } satisfies Partial<AuditEvent>;

    if (decide(bundle, params.question) === 'INSUFFICIENT_EVIDENCE') {
      await appendAudit({
        client,
        event: {
          ...baseAudit,
          eventType: 'retrieval:refused',
          selectedIds: [],
          evidenceDecision: 'refused',
          refusalReason: 'INSUFFICIENT_EVIDENCE',
        },
      });
      return {
        decision: 'refused',
        code: 'INSUFFICIENT_EVIDENCE',
        message: 'No sufficient authorized evidence to answer.',
      };
    }

    const citations: Citation[] = bundle.map((chunk) => ({
      documentId: chunk.documentId,
      versionId: chunk.versionId,
      chunkId: chunk.chunkId,
      span: { start: chunk.spanStart, end: chunk.spanEnd },
      excerpt: chunk.text,
    }));

    const generated = await deps.providers.generate({
      question: params.question,
      bundle: bundle.map((chunk) => ({ chunkId: chunk.chunkId, text: chunk.text })),
      citations,
    });

    await appendAudit({
      client,
      event: {
        ...baseAudit,
        eventType: 'retrieval:allowed',
        selectedIds: generated.citations.map((c) => c.chunkId),
        evidenceDecision: 'answered',
        modelStatus: 'ok',
        citations: generated.citations,
        answerHash: sha256(generated.answer),
      },
    });

    return {
      decision: 'answered',
      answer: generated.answer,
      citations: generated.citations,
    };
  });
}
