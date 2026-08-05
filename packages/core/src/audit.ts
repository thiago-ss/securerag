import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { withSecurityContext } from '@securerag/security';
import type { AuditEvent, AuditEventType, AuditRecord, SecurityParams } from './types.js';
import {
  bufferToHex,
  computeEventHashHex,
  type ChainFields,
} from './audit-chain.js';

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
 * context). Builds the per-tenant tamper-evident hash chain (ADR-0010, S8)
 * INSIDE the caller's transaction:
 *
 *   1. take a transaction-scoped advisory lock keyed by the tenant (serializes
 *      concurrent appends so two transactions can never read the same prev
 *      hash and fork the chain);
 *   2. read the tenant's last event_hash as the chain anchor;
 *   3. compute event_hash = sha256(canonicalChainInput(fields + prev hash))
 *      with an explicit occurred_at;
 *   4. INSERT with prev_event_hash + event_hash.
 *
 * Legacy rows (event_hash NULL) are tolerated: the chain starts at the first
 * hashed row after them (prev_event_hash NULL). Never raw query text or PII —
 * redacted derivatives only.
 */
export async function appendAudit({ client, event }: AppendAuditParams): Promise<void> {
  const tenant = await client.query<{ tenant_id: string | null }>(
    'SELECT securerag.ctx_tenant_id() AS tenant_id',
  );
  const tenantId = tenant.rows[0]?.tenant_id ?? null;
  if (tenantId === null) {
    throw new Error('appendAudit requires a verified security context (tenant GUC set)');
  }

  // Per-tenant serialization of the chain anchor (S8): transaction-scoped
  // advisory lock keyed by tenant; a hash collision between two tenants only
  // serializes them, it can never fork a chain (prev is re-read under the lock).
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))', [tenantId]);

  const prev = await client.query<{ event_hash: Buffer | null }>(
    `SELECT event_hash
       FROM securerag.audit_events
      WHERE tenant_id = securerag.ctx_tenant_id()
      ORDER BY event_id DESC
      LIMIT 1`,
  );
  const prevEventHash = prev.rows[0]?.event_hash ?? null;
  // Bind the event_id into the hash BEFORE insert: out-of-order detection is
  // exact (a reordered row recomputes to a different hash). The sequence is
  // allocated under the advisory lock, so ids are gap-free per tenant order.
  const allocated = await client.query<{ event_id: string }>(
    `SELECT nextval('securerag.audit_events_event_id_seq')::text AS event_id`,
  );
  const eventId = allocated.rows[0]?.event_id;
  if (eventId === undefined) throw new Error('audit event id allocation failed');
  const occurredAt = new Date();
  const fields: ChainFields = {
    eventId,
    tenantId,
    eventType: event.eventType,
    occurredAt: occurredAt.toISOString(),
    requestId: event.requestId,
    traceId: null,
    principalId: event.principalId,
    membershipId: event.membershipId,
    authEpoch: event.authEpoch,
    redactedQuery: event.redactedQuery ?? null,
    queryHash: bufferToHex(event.queryHash ?? null),
    filters: event.filters ?? null,
    candidateIds: event.candidateIds ?? null,
    scores: event.scores ?? null,
    selectedIds: event.selectedIds ?? null,
    policyVersions: null,
    evidenceDecision: event.evidenceDecision ?? null,
    modelStatus: event.modelStatus ?? null,
    citations: event.citations ?? null,
    refusalReason: event.refusalReason ?? null,
    latencyMs: event.latencyMs ?? null,
    answerHash: bufferToHex(event.answerHash ?? null),
    prevEventHash: bufferToHex(prevEventHash),
  };
  const eventHash = Buffer.from(computeEventHashHex(fields), 'hex');

  // jsonb params must be sent as JSON text: node-pg would otherwise serialize
  // JS arrays as PostgreSQL array literals ({...}), which is invalid JSON and
  // silently corrupts empty arrays into '{}' (a JSON object).
  const jsonOrNull = (value: unknown): string | null =>
    value === undefined ? null : JSON.stringify(value);

  await client.query(
    `INSERT INTO securerag.audit_events
       (tenant_id, event_id, event_type, occurred_at, request_id, principal_id,
        membership_id, auth_epoch, redacted_query, query_hash, filters,
        candidate_ids, scores, selected_ids, evidence_decision, model_status,
        citations, refusal_reason, latency_ms, answer_hash, prev_event_hash,
        event_hash)
     VALUES
       (securerag.ctx_tenant_id(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
    [
      eventId,
      event.eventType,
      occurredAt,
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
      prevEventHash,
      eventHash,
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
  prev_event_hash: Buffer | null;
  event_hash: Buffer | null;
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
    prevEventHash: row.prev_event_hash,
    eventHash: row.event_hash,
  };
}

export interface ListAuditParams extends SecurityParams {
  limit?: number;
  /** Restrict to one event type. */
  eventType?: AuditEventType;
  /** Inclusive lower bound on occurred_at (ISO-8601 timestamp). */
  from?: string;
  /** Inclusive upper bound on occurred_at (ISO-8601 timestamp). */
  to?: string;
  /** Restrict to events performed by this principal (the context principal
   * may filter for any subject of their own tenant; RLS still scopes rows). */
  forPrincipalId?: string;
  /** Keyset cursor: return only events with event_id < cursor (desc order). */
  cursor?: string;
}

/**
 * Tenant-isolated audit read-back. Runs inside withSecurityContext: RLS shows
 * ONLY the verified tenant's rows, so the returned records can never carry
 * foreign request ids or identifiers. Filters are all optional; eventType /
 * from / to / principalId narrow the set in SQL (never in application code),
 * and cursor pages backward from a previously returned eventId.
 */
export async function listAudit(pool: Pool, params: ListAuditParams): Promise<AuditRecord[]> {
  const limit = params.limit ?? 50;
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<AuditRow>(
      `SELECT event_id, tenant_id, event_type, occurred_at, request_id, principal_id,
              membership_id, auth_epoch, redacted_query, query_hash, filters,
              candidate_ids, scores, selected_ids, evidence_decision, model_status,
              citations, refusal_reason, latency_ms, answer_hash,
              prev_event_hash, event_hash
         FROM securerag.audit_events
        WHERE ($1::text IS NULL OR event_type = $1)
          AND ($2::timestamptz IS NULL OR occurred_at >= $2)
          AND ($3::timestamptz IS NULL OR occurred_at <= $3)
          AND ($4::uuid IS NULL OR principal_id = $4)
          AND ($5::bigint IS NULL OR event_id < $5)
        ORDER BY event_id DESC
        LIMIT $6`,
      [params.eventType ?? null, params.from ?? null, params.to ?? null, params.forPrincipalId ?? null, params.cursor ?? null, limit],
    );
    return rows.map(toRecord);
  });
}
