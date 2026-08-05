import type { Pool } from 'pg';
import { MembershipError, withIdentityContext, withSecurityContext } from '@securerag/security';
import type { AnswerGenerator } from '@securerag/providers';
import { appendAudit, sha256 } from './audit.js';
import { grantPredicateSql } from './grants.js';
import { decide } from './refusal.js';
import type { AuditEvent, Citation, EvidenceChunk, RetrievalOutcome, SecurityParams } from './types.js';

export interface RetrievalParams extends SecurityParams {
  question: string;
}

export interface RetrievalDeps {
  pool: Pool;
  providers: AnswerGenerator;
  /** Milliseconds-since-epoch clock for latency_ms; defaults to Date.now. */
  clock?: () => number;
  /** SQL LIMIT $2; defaults to RETRIEVAL_DEFAULT_LIMIT. */
  limit?: number;
}

export const RETRIEVAL_DEFAULT_LIMIT = 10;

/**
 * Keyword arm of the retrieval query — EXACTLY the T3 contract §Retrieval
 * keyword arm shape: parameterized websearch query, all filters in SQL (no
 * application-side post-filtering ever), deterministic ORDER BY (rank DESC,
 * chunk_id), LIMIT $2. The grant EXISTS is the shared single-source-of-truth
 * predicate from grants.ts, composed with the contract's outer aliases
 * (c.tenant_id / d.document_id).
 */
const RETRIEVAL_SQL = `
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
   AND ${grantPredicateSql('d.document_id', 'c.tenant_id')}
 ORDER BY rank DESC, c.chunk_id
 LIMIT $2`;

interface KeywordRow {
  chunk_id: string;
  chunk_no: number;
  text_redacted: string;
  span_start: number;
  span_end: number;
  version_id: string;
  version_no: number;
  document_id: string;
  title: string;
  rank: number;
}

function toEvidenceChunk(row: KeywordRow): EvidenceChunk {
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
    rank: row.rank,
  };
}

/**
 * End-to-end retrieval run (T3 contract §Domain contracts):
 *  1. withIdentityContext — the ONLY identity-context use: list the
 *     principal's active memberships; the requested tenant is an untrusted
 *     candidate, never authority.
 *  2. withSecurityContext — verified tenant/principal/membership/request/epoch
 *     context; keyword arm SQL; evidence bundle (RLS-filtered rows).
 *  3. decide(bundle, question) — below the calibrated threshold (or empty)
 *     yields refused INSUFFICIENT_EVIDENCE, audited, no generation.
 *  4. Otherwise the provider spy generates a deterministic answer that cites
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

  const identity = await withIdentityContext(deps.pool, params.principalId, async () => undefined);
  if (!identity.memberships.some((m) => m.tenantId === params.tenantId)) {
    throw new MembershipError();
  }

  return withSecurityContext(deps.pool, params, async (client, ctx) => {
    const { rows } = await client.query<KeywordRow>(RETRIEVAL_SQL, [
      params.question,
      limit,
    ]);
    const bundle = rows.map(toEvidenceChunk);

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
