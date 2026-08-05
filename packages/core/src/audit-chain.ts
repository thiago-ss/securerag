import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { withSecurityContext } from '@securerag/security';
import type { SecurityParams } from './types.js';

/**
 * Per-tenant tamper-evident audit hash chain (ADR-0010, S8).
 *
 * Every audit row carries:
 *   event_hash     = sha256(canonicalChainInput(fields incl. occurred_at + prev hash))
 *   prev_event_hash = event_hash of the tenant's previous event (chain anchor)
 *
 * Runtime roles are insert-only (audit_update_none policy: WITH CHECK false),
 * so hashes can never be patched after the fact. Concurrent appends are
 * serialized per tenant by a transaction-scoped advisory lock
 * (pg_advisory_xact_lock keyed by tenant) inside appendAudit, so two parallel
 * appends can never read the same prev hash and fork the chain.
 *
 * Canonical input (canonicalChainInput): a JSON object of the audit columns
 * that participate in the chain with object keys sorted bytewise (matching
 * PostgreSQL jsonb key normalization), bytea hex-encoded, timestamps ISO-8601
 * UTC with millisecond precision. Both the appender and the verifier produce
 * identical bytes, so verification is exact.
 *
 * Backfill (pre-S8 rows): rows written before the chain existed have
 * event_hash NULL and prev_event_hash NULL. They are not part of the chain:
 * the appender starts a fresh chain at the first hashed row after them
 * (prev_event_hash NULL) and the verifier skips them. No migration rewrites
 * history.
 *
 * Purge gaps (S9): the retention purge may legitimately DELETE expired audit
 * rows (RLS-proven by audit_delete_expiry) and appends a chained
 * 'audit:purged' tombstone whose filters.eventIdRange = { min, max } brackets
 * the deleted ids. A broken prev link is accepted ONLY when a chained
 * tombstone with a higher event_id covers every id strictly between the two
 * surviving rows (or, at chain start, every id below the first survivor).
 * The row after a covered gap cannot be re-hashed (its predecessor hash is
 * gone), so its stored hash is carried forward as a re-seed point; every row
 * after it verifies normally, and the tombstone itself verifies as an
 * ordinary chained row. Any break without tombstone coverage is a violation.
 */

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Bytewise (UTF-8) key order — the same normalization PostgreSQL jsonb applies. */
function bytewiseKeyCompare(a: string, b: string): number {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  const len = Math.min(ab.length, bb.length);
  const cmp = ab.compare(bb, 0, len);
  return cmp !== 0 || ab.length === bb.length ? cmp : ab.length - bb.length;
}

/**
 * Recursively canonicalize a value for hashing: object keys sorted bytewise,
 * arrays in order, everything else as-is. Deterministic for identical values
 * regardless of insertion order.
 */
export function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    const keys = Object.keys(value as Record<string, unknown>).sort(bytewiseKeyCompare);
    for (const key of keys) out[key] = canonicalize((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}

/**
 * The audit columns that participate in the hash chain, in canonical form
 * (bytea as lowercase hex, occurred_at as ISO-8601 UTC with ms precision,
 * auth_epoch as text). eventId binds every hash to its exact position in the
 * tenant's sequence (out-of-order detection is exact); prevEventHash is the
 * previous event's hash (NULL for chain start / legacy predecessor);
 * eventHash itself is NOT an input.
 */
export interface ChainFields {
  eventId: string;
  tenantId: string;
  eventType: string;
  occurredAt: string;
  requestId: string | null;
  traceId: string | null;
  principalId: string | null;
  membershipId: string | null;
  authEpoch: string;
  redactedQuery: string | null;
  queryHash: string | null;
  filters: unknown;
  candidateIds: unknown;
  scores: unknown;
  selectedIds: unknown;
  policyVersions: unknown;
  evidenceDecision: string | null;
  modelStatus: string | null;
  citations: unknown;
  refusalReason: string | null;
  latencyMs: number | null;
  answerHash: string | null;
  prevEventHash: string | null;
}

/** Deterministic JSON text that feeds the hash (exported for consumers). */
export function canonicalChainInput(fields: ChainFields): string {
  return JSON.stringify(canonicalize(fields));
}

export function computeEventHashHex(fields: ChainFields): string {
  return sha256Hex(canonicalChainInput(fields));
}

/** One chain row in verifier form. */
export interface ChainRow {
  eventId: string;
  fields: ChainFields;
  eventHashHex: string | null;
}

export interface ChainVerification {
  valid: boolean;
  /** All rows of the tenant (legacy + chained). */
  totalEvents: number;
  /** Rows carrying an event_hash. */
  chainedEvents: number;
  /** Chained rows after a tombstone-covered purge gap: stored hash carried
   * forward unverified (the predecessor hash was legitimately deleted). */
  reseededEventIds: string[];
  /** Last chained event_id / hash — the anchor an export's envelope carries. */
  anchorEventId: string | null;
  anchorHash: string | null;
  /** Human-readable violation list (empty when valid). */
  failures: string[];
}

interface TombstoneRange {
  eventId: bigint;
  min: bigint;
  max: bigint;
}

function tombstoneRanges(rows: ChainRow[]): TombstoneRange[] {
  const ranges: TombstoneRange[] = [];
  for (const row of rows) {
    if (row.fields.eventType !== 'audit:purged' || row.eventHashHex === null) continue;
    const raw = row.fields.filters as { eventIdRange?: { min?: unknown; max?: unknown } } | null;
    const range = raw?.eventIdRange;
    if (typeof range?.min !== 'string' || typeof range?.max !== 'string') continue;
    const min = BigInt(range.min);
    const max = BigInt(range.max);
    if (min > max) continue;
    ranges.push({ eventId: BigInt(row.eventId), min, max });
  }
  return ranges;
}

/** Pure chain verification over already-fetched rows (exported for consumers
 * verifying an export against its anchor). */
export function verifyChainRows(rows: ChainRow[]): ChainVerification {
  const failures: string[] = [];
  const reseededEventIds: string[] = [];
  const tombstones = tombstoneRanges(rows);
  let totalEvents = 0;
  let chainedEvents = 0;
  let prevEventId: string | null = null;
  let prevHash: string | null = null;
  let legacyBefore = false;
  let anchorEventId: string | null = null;
  let anchorHash: string | null = null;

  const covered = (fromId: bigint, toId: bigint): boolean => {
    if (toId - fromId <= 1n) return false; // nothing deleted between adjacent rows
    return tombstones.some(
      (t) => t.eventId > toId && t.min <= fromId + 1n && t.max >= toId - 1n,
    );
  };

  for (const row of rows) {
    totalEvents += 1;
    if (row.eventHashHex === null) {
      if (row.fields.prevEventHash !== null) {
        failures.push(`event ${row.eventId}: prev_event_hash set but event_hash NULL (unverifiable row)`);
      }
      // Legacy (pre-chain) row: the chain restarts after it (the appender
      // writes prev_event_hash NULL for the next append).
      legacyBefore = true;
      continue;
    }
    chainedEvents += 1;
    const id = BigInt(row.eventId);
    const fromId = prevEventId === null ? 0n : BigInt(prevEventId);

    let prevOk = row.fields.prevEventHash === prevHash;
    let reseeded = false;
    // The appender restarts the chain (prev NULL) when the last row is a
    // legacy row: accept a NULL prev right after legacy rows, recomputing
    // against NULL (the prev the appender actually hashed).
    if (legacyBefore && row.fields.prevEventHash === null) {
      prevOk = true;
    }
    if (!prevOk) {
      if (covered(fromId, id)) {
        prevOk = true;
        reseeded = true;
        reseededEventIds.push(row.eventId);
      } else if (prevEventId === null) {
        failures.push(
          `event ${row.eventId}: chain start carries prev_event_hash ${row.fields.prevEventHash} (missing predecessor)`,
        );
      } else {
        failures.push(
          `event ${row.eventId}: prev_event_hash ${row.fields.prevEventHash} does not link to event ${prevEventId} (missing/tampered/reordered predecessor)`,
        );
      }
    }

    // A reseeded row's stored hash is carried forward unverified (its
    // predecessor was legitimately purged); every other chained row must
    // recompute exactly against the hash the appender actually linked.
    if (prevOk && !reseeded) {
      const recomputePrev = legacyBefore && row.fields.prevEventHash === null ? null : prevHash;
      const expected = computeEventHashHex({ ...row.fields, prevEventHash: recomputePrev });
      if (expected !== row.eventHashHex) {
        failures.push(`event ${row.eventId}: event_hash mismatch (tampered fields)`);
      }
    }

    prevEventId = row.eventId;
    prevHash = row.eventHashHex;
    legacyBefore = false;
    anchorEventId = row.eventId;
    anchorHash = row.eventHashHex;
  }

  return {
    valid: failures.length === 0,
    totalEvents,
    chainedEvents,
    reseededEventIds,
    anchorEventId,
    anchorHash,
    failures,
  };
}

// ---------- SQL row mapping ----------

export interface ChainRowSql {
  event_id: string;
  tenant_id: string;
  event_type: string;
  occurred_at: Date;
  request_id: string;
  trace_id: string | null;
  principal_id: string | null;
  membership_id: string | null;
  auth_epoch: string;
  redacted_query: string | null;
  query_hash: Buffer | null;
  filters: unknown;
  candidate_ids: unknown;
  scores: unknown;
  selected_ids: unknown;
  policy_versions: unknown;
  evidence_decision: string | null;
  model_status: string | null;
  citations: unknown;
  refusal_reason: string | null;
  latency_ms: number | null;
  answer_hash: Buffer | null;
  prev_event_hash: Buffer | null;
  event_hash: Buffer | null;
}

export const CHAIN_SELECT = `SELECT event_id, tenant_id, event_type, occurred_at, request_id,
        trace_id, principal_id, membership_id, auth_epoch, redacted_query, query_hash,
        filters, candidate_ids, scores, selected_ids, policy_versions, evidence_decision,
        model_status, citations, refusal_reason, latency_ms, answer_hash,
        prev_event_hash, event_hash
   FROM securerag.audit_events`;

export function bufferToHex(value: Buffer | null): string | null {
  return value === null ? null : value.toString('hex');
}

export function rowToChainRow(row: ChainRowSql): ChainRow {
  return {
    eventId: row.event_id,
    fields: {
      eventId: row.event_id,
      tenantId: row.tenant_id,
      eventType: row.event_type,
      occurredAt: row.occurred_at.toISOString(),
      requestId: row.request_id,
      traceId: row.trace_id,
      principalId: row.principal_id,
      membershipId: row.membership_id,
      authEpoch: row.auth_epoch,
      redactedQuery: row.redacted_query,
      queryHash: bufferToHex(row.query_hash),
      filters: row.filters,
      candidateIds: row.candidate_ids,
      scores: row.scores,
      selectedIds: row.selected_ids,
      policyVersions: row.policy_versions,
      evidenceDecision: row.evidence_decision,
      modelStatus: row.model_status,
      citations: row.citations,
      refusalReason: row.refusal_reason,
      latencyMs: row.latency_ms,
      answerHash: bufferToHex(row.answer_hash),
      prevEventHash: bufferToHex(row.prev_event_hash),
    },
    eventHashHex: bufferToHex(row.event_hash),
  };
}

/**
 * Recomputed chain verification for one tenant, over real PostgreSQL rows.
 * Runs inside withSecurityContext (RLS): only the verified tenant's rows are
 * ever read, so a foreign tenant yields an empty (valid) chain and never
 * leaks linkage information.
 *
 * Pass a Pool for a fresh verified transaction, or a client that already runs
 * inside a security context (the caller's transaction is then committed at
 * the end, like withSecurityContext).
 */
export async function verifyAuditChain(
  poolOrClient: Pool | PoolClient,
  params: SecurityParams,
): Promise<ChainVerification> {
  return withSecurityContext(poolOrClient, params, async (client) => {
    const { rows } = await client.query<ChainRowSql>(
      `${CHAIN_SELECT} WHERE tenant_id = securerag.ctx_tenant_id() ORDER BY event_id ASC`,
    );
    return verifyChainRows(rows.map(rowToChainRow));
  });
}
