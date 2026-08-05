import type { Pool, PoolClient } from 'pg';
import { withSecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import { DEFAULT_PII_CONFIG, redactForSurface } from './redaction.js';
import type { SecurityParams } from './types.js';

/**
 * Ingestion quarantine + security review (S5, ADR-0006 layers 6/8, research
 * r6 §Quarantine design).
 *
 * Detection is a SIGNAL, never a gate: quarantine is the deterministic
 * policy layer that acts on a high-risk scan; review is the explicit,
 * audited human gate that releases (status 'released' -> searchable) or
 * keeps a quarantined version. Authorization never depends on detection.
 *
 * State machine (document_versions.status, enforced here):
 *   pending|valid|released --quarantineVersion--> quarantined
 *   quarantined --review release--> released
 *   quarantined --review keep--> quarantined (unchanged, audited)
 * superseded/expired versions are never touched (already non-searchable).
 *
 * Both transitions bump the authorization epoch and append an immutable
 * audit event in ONE transaction (same pattern as memberships/groups,
 * ADR-0013); 'keep' writes no state change and does NOT bump the epoch, but
 * the human decision is still audited.
 *
 * Quarantined versions are never searchable: retrieval/citation SQL filters
 * status IN ('valid','released') (packages/core/src/retrieval.ts,
 * documents.ts); release makes a version searchable again WITHOUT any
 * re-index (the chunks were never unindexed — the status filter is the
 * only gate, ADR-0006).
 */

/** Decision a tenant security reviewer can make on a quarantined version. */
export type ReviewDecision = 'release' | 'keep';

export interface QuarantineVersionParams extends SecurityParams {
  versionId: string;
}

export interface ReviewQuarantineParams extends SecurityParams {
  versionId: string;
  decision: ReviewDecision;
  /** Optional human context (ticket id, reason) — redacted into audit filters. */
  reviewerCtx?: string;
}

export interface QuarantineRecord {
  versionId: string;
  documentId: string;
  versionNo: number;
  title: string;
  status: string;
  reviewedBy: string | null;
  reviewedAt: Date | null;
  reviewDecision: ReviewDecision | null;
  createdAt: Date;
}

interface VersionRow {
  document_id: string;
  version_no: number;
  status: string;
  reviewed_by: string | null;
  reviewed_at: Date | null;
  review_decision: string | null;
  created_at: Date;
}

/**
 * Deterministic reviewer gate (ADR-0006: tenant security reviewer explicit
 * approve-release): the context principal may review a tenant's quarantine
 * iff it is an active tenant_admin (ctx_principal_is_admin mirror) OR holds
 * an ACTIVE tenant membership with role 'security_reviewer'. Evaluated
 * inside the verified withSecurityContext transaction (RLS-scoped), so
 * foreign tenants resolve false identically; callers observe no difference
 * from a foreign or nonexistent version.
 */
async function isSecurityReviewer(client: PoolClient): Promise<boolean> {
  const { rows } = await client.query<{ allowed: boolean }>(
    `SELECT (
       EXISTS (SELECT 1 FROM securerag.tenant_memberships tm
                WHERE tm.tenant_id = securerag.ctx_tenant_id()
                  AND tm.principal_id = securerag.ctx_principal_id()
                  AND tm.is_active
                  AND tm.role = 'security_reviewer')
       OR securerag.ctx_principal_is_admin(securerag.ctx_tenant_id())
     ) AS allowed`,
  );
  return rows[0]?.allowed ?? false;
}

async function bumpEpoch(client: PoolClient): Promise<string> {
  const bumped = await client.query<{ epoch: string }>(
    'SELECT securerag.bump_authorization_epoch() AS epoch',
  );
  return bumped.rows[0]?.epoch ?? '';
}

/**
 * Quarantine a version (ingest scan outcome, ADR-0006 layer 6). Moves
 * pending -> quarantined (initial scan) or re-quarantines valid/released
 * versions (re-scan finds high risk -> back to quarantined). Clears the
 * convenience review columns: they describe the CURRENT cycle only (the
 * audit trail preserves the full history). Bumps the epoch + audits
 * 'version:quarantined'. Returns false for foreign/nonexistent versions
 * and for superseded/expired versions (already non-searchable) — no write,
 * no audit, indistinguishable.
 */
export async function quarantineVersion(
  pool: Pool,
  params: QuarantineVersionParams,
): Promise<boolean> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<{ document_id: string }>(
      `UPDATE securerag.document_versions
          SET status = 'quarantined',
              reviewed_by = NULL,
              reviewed_at = NULL,
              review_decision = NULL
        WHERE tenant_id = securerag.ctx_tenant_id()
          AND version_id = $1
          AND status IN ('pending','valid','released')
        RETURNING document_id`,
      [params.versionId],
    );
    const row = rows[0];
    if (row === undefined) return false;
    const epoch = await bumpEpoch(client);
    await appendAudit({
      client,
      event: {
        eventType: 'version:quarantined',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: epoch,
        filters: { versionId: params.versionId, documentId: row.document_id },
      },
    });
    return true;
  });
}

/**
 * Explicit tenant security review (ADR-0006 layer 8). Authorization:
 * active tenant admin OR tenant role 'security_reviewer' (deterministic SQL
 * gate above); any other principal — including a foreign/nonexistent
 * version target — gets the same `false` as a version it cannot see: no
 * write, no audit, no distinguishable error.
 *
 *   release -> status 'released' (searchable again; epoch bumped, audited
 *              'version:review' with decision + reviewer)
 *   keep    -> status stays 'quarantined' (audited 'version:review'; no
 *              epoch bump — nothing authorization-relevant changed)
 *
 * Both set the convenience columns (reviewed_by/reviewed_at/review_decision).
 */
export async function reviewQuarantine(
  pool: Pool,
  params: ReviewQuarantineParams,
): Promise<boolean> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    if (!(await isSecurityReviewer(client))) return false;
    const { rows } = await client.query<VersionRow>(
      `UPDATE securerag.document_versions
          SET reviewed_by = securerag.ctx_principal_id(),
              reviewed_at = now(),
              review_decision = $2,
              status = CASE WHEN $2 = 'release' THEN 'released' ELSE status END
        WHERE tenant_id = securerag.ctx_tenant_id()
          AND version_id = $1
          AND status = 'quarantined'
        RETURNING document_id, version_no, status, reviewed_by, reviewed_at,
                  review_decision, created_at`,
      [params.versionId, params.decision],
    );
    const row = rows[0];
    if (row === undefined) return false;

    const filters: Record<string, unknown> = {
      versionId: params.versionId,
      documentId: row.document_id,
      decision: params.decision,
    };
    if (params.reviewerCtx !== undefined) {
      // ADR-0005: reviewer notes may contain PII; only redacted derivatives
      // enter tenant audit views.
      filters.reviewerCtx = redactForSurface(params.reviewerCtx, DEFAULT_PII_CONFIG, false);
    }

    if (params.decision === 'release') {
      const epoch = await bumpEpoch(client);
      await appendAudit({
        client,
        event: {
          eventType: 'version:review',
          requestId: params.requestId,
          principalId: ctx.principalId,
          membershipId: ctx.membershipId,
          authEpoch: epoch,
          filters,
        },
      });
    } else {
      await appendAudit({
        client,
        event: {
          eventType: 'version:review',
          requestId: params.requestId,
          principalId: ctx.principalId,
          membershipId: ctx.membershipId,
          authEpoch: ctx.authEpoch,
          filters,
        },
      });
    }
    return true;
  });
}

/**
 * Tenant quarantine view (reviewer/admin only). Lists quarantined versions
 * of the verified tenant with the convenience review columns. A principal
 * without the reviewer gate sees an EMPTY list — no signal about whether
 * quarantined versions exist (indistinguishable from a quiet tenant).
 */
export async function listQuarantined(
  pool: Pool,
  params: SecurityParams,
): Promise<QuarantineRecord[]> {
  return withSecurityContext(pool, params, async (client) => {
    if (!(await isSecurityReviewer(client))) return [];
    const { rows } = await client.query<VersionRow & { version_id: string; title: string }>(
      `SELECT v.version_id, v.document_id, v.version_no, d.title, v.status,
              v.reviewed_by, v.reviewed_at, v.review_decision, v.created_at
         FROM securerag.document_versions v
         JOIN securerag.documents d
           ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
        WHERE v.tenant_id = securerag.ctx_tenant_id()
          AND v.status = 'quarantined'
        ORDER BY v.created_at DESC, v.version_id`,
    );
    return rows.map((row) => ({
      versionId: row.version_id,
      documentId: row.document_id,
      versionNo: row.version_no,
      title: row.title,
      status: row.status,
      reviewedBy: row.reviewed_by,
      reviewedAt: row.reviewed_at,
      reviewDecision: row.review_decision as ReviewDecision | null,
      createdAt: row.created_at,
    }));
  });
}
