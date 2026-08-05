/**
 * Tenant retention policy + expiry (S9, ADR-0010).
 *
 * Semantics:
 *  - Every tenant has exactly one policy row: seeded on tenant creation by the
 *    0009 AFTER INSERT trigger, and on first access by getRetentionPolicy's
 *    INSERT ON CONFLICT DO NOTHING (covers pre-migration tenants).
 *  - Upserts are ADMIN-ONLY (deterministic ctx_principal_is_admin check),
 *    bump the authorization epoch (retention is an epoch-bumping decision,
 *    ADR-0004) and are audited as 'retention:changed'.
 *  - expireVersionsFor marks a version status='expired' as soon as its
 *    published_at passes LEAST(source_days, derived_days): a version is
 *    non-retrievable once EITHER storage class is past its own retention
 *    (non-retrievability is immediate — retrieval/citation/document surfaces
 *    filter status IN ('valid','released')). Marking is non-destructive, so it
 *    runs even under legal hold; only destructive PURGE is blocked by legal
 *    hold, and destructive deletion additionally waits out the grace window.
 *  - The worker service context (withWorkerContext) is used because the
 *    worker/purge credentials hold no membership rows (documented exception,
 *    packages/security bootstrap).
 */
import type { Pool } from 'pg';
import { withSecurityContext, withWorkerContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import type { SecurityParams } from './types.js';

export interface RetentionPolicy {
  tenantId: string;
  sourceDays: number;
  derivedDays: number;
  auditDays: number;
  graceDays: number;
  legalHold: boolean;
  updatedAt: Date;
}

export interface RetentionPolicyPatch {
  sourceDays?: number;
  derivedDays?: number;
  auditDays?: number;
  graceDays?: number;
  legalHold?: boolean;
}

/** Application-side mirror of the 0002 schema defaults (single source of truth
 * for tests and for paths that must not read the table twice). */
export const DEFAULT_RETENTION_POLICY = {
  sourceDays: 3650,
  derivedDays: 3650,
  auditDays: 1095,
  graceDays: 7,
  legalHold: false,
} as const;

interface RetentionRow {
  tenant_id: string;
  source_days: number;
  derived_days: number;
  audit_days: number;
  grace_days: number;
  legal_hold: boolean;
  updated_at: Date;
}

function toPolicy(row: RetentionRow): RetentionPolicy {
  return {
    tenantId: row.tenant_id,
    sourceDays: row.source_days,
    derivedDays: row.derived_days,
    auditDays: row.audit_days,
    graceDays: row.grace_days,
    legalHold: row.legal_hold,
    updatedAt: row.updated_at,
  };
}

/**
 * Read the tenant's policy; seeds the default row on first access. Runs inside
 * withSecurityContext, so foreign/nonexistent tenants yield null exactly like
 * a denied read (RLS hides the row; the insert's WITH CHECK pins the tenant).
 */
export async function getRetentionPolicy(
  pool: Pool,
  params: SecurityParams,
): Promise<RetentionPolicy | null> {
  return withSecurityContext(pool, params, async (client) => {
    await client.query(
      `INSERT INTO securerag.retention_policies (tenant_id)
       VALUES (securerag.ctx_tenant_id())
       ON CONFLICT DO NOTHING`,
    );
    const { rows } = await client.query<RetentionRow>(
      `SELECT tenant_id, source_days, derived_days, audit_days, grace_days,
              legal_hold, updated_at
         FROM securerag.retention_policies
        WHERE tenant_id = securerag.ctx_tenant_id()`,
    );
    const row = rows[0];
    return row === undefined ? null : toPolicy(row);
  });
}

/**
 * Admin-only policy upsert (partial patch). Returns null for non-admins and
 * foreign tenants alike (indistinguishable, no enumeration). Successful
 * changes bump the authorization epoch and are audited 'retention:changed'
 * with the applied patch as redacted metadata. A patch with no fields is a
 * no-op that returns null (the API schema also refuses it).
 */
export async function upsertRetentionPolicy(
  pool: Pool,
  params: SecurityParams & { patch: RetentionPolicyPatch },
): Promise<RetentionPolicy | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const patch = params.patch;
    const sets: string[] = [];
    const values: unknown[] = [];
    const push = (column: string, value: number | boolean): void => {
      sets.push(`${column} = $${values.length + 1}`);
      values.push(value);
    };
    if (patch.sourceDays !== undefined) push('source_days', patch.sourceDays);
    if (patch.derivedDays !== undefined) push('derived_days', patch.derivedDays);
    if (patch.auditDays !== undefined) push('audit_days', patch.auditDays);
    if (patch.graceDays !== undefined) push('grace_days', patch.graceDays);
    if (patch.legalHold !== undefined) push('legal_hold', patch.legalHold);
    if (sets.length === 0) return null;

    // F9: no-op writes (idempotent client retries) neither bump the epoch nor
    // write audit noise — the UPDATE targets only changed columns.
    const { rows } = await client.query<RetentionRow>(
      `UPDATE securerag.retention_policies
          SET ${sets.join(', ')}, updated_at = now()
        WHERE tenant_id = securerag.ctx_tenant_id()
          AND securerag.ctx_principal_is_admin(securerag.ctx_tenant_id())
        RETURNING tenant_id, source_days, derived_days, audit_days, grace_days,
                  legal_hold, updated_at`,
      values,
    );
    const row = rows[0];
    if (row === undefined) return null;
    // A patch whose values equal the current row is a no-op: skip bump + audit.
    const unchanged = sets.every((setExpr) => {
      const column = setExpr.split(' = ')[0] ?? '';
      const key = columnToPatchKey(column) as keyof RetentionPolicyPatch;
      const desired = patch[key];
      const current = row[key as keyof RetentionRow];
      return desired !== undefined && current !== undefined && String(desired) === String(current);
    });
    if (unchanged) return toPolicy(row);

    const bumped = await client.query<{ epoch: string }>(
      'SELECT securerag.bump_authorization_epoch() AS epoch',
    );
    await appendAudit({
      client,
      event: {
        eventType: 'retention:changed',
        requestId: ctx.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: bumped.rows[0]?.epoch ?? ctx.authEpoch,
        filters: { ...patch },
      },
    });
    return toPolicy(row);
  });
}

function columnToPatchKey(column: string): string {
  switch (column) {
    case 'source_days': return 'sourceDays';
    case 'derived_days': return 'derivedDays';
    case 'audit_days': return 'auditDays';
    case 'grace_days': return 'graceDays';
    case 'legal_hold': return 'legalHold';
    default: return '';
  }
}

export interface ExpireResult {
  /** Versions newly marked expired by this run (idempotent: 0 on re-run). */
  marked: number;
  /** Post-bump epoch when something was marked, else null. */
  epoch: string | null;
}

/**
 * Mark every version whose retention has run out as status='expired'
 * (idempotent; re-runs mark nothing). Expired versions are immediately
 * non-retrievable because every retrieval surface filters
 * status IN ('valid','released'). Non-destructive: runs under legal hold.
 * Bumps the authorization epoch when anything is marked (retention decision,
 * ADR-0004). Runs with the worker service context.
 */
export async function expireVersionsFor(
  pool: Pool,
  params: { tenantId: string; requestId: string },
): Promise<ExpireResult> {
  return withWorkerContext(pool, params, async (client) => {
    const { rows } = await client.query<{ version_id: string }>(
      `UPDATE securerag.document_versions v
          SET status = 'expired'
         FROM securerag.retention_policies p
        WHERE p.tenant_id = v.tenant_id
          AND v.tenant_id = securerag.ctx_tenant_id()
          AND v.published_at IS NOT NULL
          AND v.status IN ('valid', 'released', 'superseded', 'quarantined')
          AND v.published_at + LEAST(p.source_days, p.derived_days) * interval '1 day' < now()
        RETURNING v.version_id`,
    );
    const marked = rows.length;
    if (marked === 0) return { marked, epoch: null };
    const bumped = await client.query<{ epoch: string }>(
      'SELECT securerag.bump_authorization_epoch() AS epoch',
    );
    return { marked, epoch: bumped.rows[0]?.epoch ?? null };
  });
}
