import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { withSecurityContext } from '@securerag/security';
import type { AuditEvent, AuditRecord, SecurityParams } from './types.js';

/** SHA-256 digest for query_hash/answer_hash (hex-decoded bytea). */
export function sha256(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

export interface AppendAuditParams {
  /** Live client inside a withSecurityContext callback (context GUCs set). */
  client: PoolClient;
  event: AuditEvent;
}

/**
 * Insert-only audit append via the runtime role (no UPDATE/DELETE on
 * audit_events anywhere; RLS WITH CHECK pins tenant_id to the verified
 * context). Single statement; never raw query text or PII — redacted
 * derivatives only.
 */
export async function appendAudit({ client, event }: AppendAuditParams): Promise<void> {
  // jsonb params must be sent as JSON text: node-pg would otherwise serialize
  // JS arrays as PostgreSQL array literals ({...}), which is invalid JSON and
  // silently corrupts empty arrays into '{}' (a JSON object).
  const jsonOrNull = (value: unknown): string | null =>
    value === undefined ? null : JSON.stringify(value);

  await client.query(
    `INSERT INTO securerag.audit_events
       (tenant_id, event_type, request_id, principal_id, membership_id, auth_epoch,
        redacted_query, query_hash, filters, candidate_ids, scores, selected_ids,
        evidence_decision, model_status, citations, refusal_reason, latency_ms, answer_hash)
     VALUES
       (securerag.ctx_tenant_id(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15, $16, $17)`,
    [
      event.eventType,
      event.requestId,
      event.principalId,
      event.membershipId,
      event.authEpoch,
      event.redactedQuery ?? null,
      event.queryHash ?? null,
      jsonOrNull(event.filters),
      jsonOrNull(event.candidateIds),
      jsonOrNull(event.scores),
      jsonOrNull(event.selectedIds),
      event.evidenceDecision ?? null,
      event.modelStatus ?? null,
      jsonOrNull(event.citations),
      event.refusalReason ?? null,
      event.latencyMs ?? null,
      event.answerHash ?? null,
    ],
  );
}

interface AuditRow {
  event_id: string;
  tenant_id: string;
  occurred_at: Date;
  event_type: string;
  request_id: string;
  principal_id: string;
  membership_id: string;
  auth_epoch: string;
  redacted_query: string | null;
  query_hash: Buffer | null;
  filters: unknown;
  candidate_ids: string[] | null;
  scores: number[] | null;
  selected_ids: string[] | null;
  evidence_decision: string | null;
  model_status: string | null;
  citations: unknown;
  refusal_reason: string | null;
  latency_ms: number | null;
  answer_hash: Buffer | null;
}

function toRecord(row: AuditRow): AuditRecord {
  return {
    eventId: row.event_id,
    tenantId: row.tenant_id,
    occurredAt: row.occurred_at,
    eventType: row.event_type as AuditRecord['eventType'],
    requestId: row.request_id,
    principalId: row.principal_id,
    membershipId: row.membership_id,
    authEpoch: row.auth_epoch,
    redactedQuery: row.redacted_query,
    queryHash: row.query_hash,
    filters: (row.filters ?? null) as AuditRecord['filters'],
    candidateIds: row.candidate_ids,
    scores: row.scores,
    selectedIds: row.selected_ids,
    evidenceDecision: row.evidence_decision,
    modelStatus: row.model_status,
    citations: (row.citations ?? null) as AuditRecord['citations'],
    refusalReason: row.refusal_reason,
    latencyMs: row.latency_ms,
    answerHash: row.answer_hash,
  };
}

export interface ListAuditParams extends SecurityParams {
  limit?: number;
}

/**
 * Tenant-isolated audit read-back. Runs inside withSecurityContext: RLS shows
 * ONLY the verified tenant's rows, so the returned records can never carry
 * foreign request ids or identifiers.
 */
export async function listAudit(pool: Pool, params: ListAuditParams): Promise<AuditRecord[]> {
  const limit = params.limit ?? 50;
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<AuditRow>(
      `SELECT event_id, tenant_id, event_type, occurred_at, request_id, principal_id,
              membership_id, auth_epoch, redacted_query, query_hash, filters,
              candidate_ids, scores, selected_ids, evidence_decision, model_status,
              citations, refusal_reason, latency_ms, answer_hash
         FROM securerag.audit_events
        ORDER BY event_id DESC
        LIMIT $1`,
      [limit],
    );
    return rows.map(toRecord);
  });
}
