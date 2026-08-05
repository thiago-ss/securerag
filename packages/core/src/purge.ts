/**
 * Verified destructive purge (S9, ADR-0010).
 *
 * Deletion completion proves EVERY storage class:
 *   - sources:   source objects via the SourceObjectStore seam (in-memory fake
 *                today; S3 adapter lands with S2) — keys collected from
 *                expired versions past source_days + grace.
 *   - chunks:    DB rows of versions past derived_days + grace.
 *   - versions:  rows past MAX(source_days, derived_days) + grace (the row is
 *                the join point between both classes, so it outlives both).
 *   - audit:     rows past audit_days + grace, replaced by a minimal tombstone
 *                ('audit:purged': event range + count) under the tenant's own
 *                audit policy.
 *
 * Role separation (0009): expireVersionsFor runs as securerag_worker (UPDATE
 * on lifecycle state), every destructive DELETE runs as securerag_purge (DELETE
 * granted ONLY on rows proven expired — enforced by role-aware RLS policies
 * AND by the expiry+grace predicates in every query here). Audit events are
 * insert-only; the purge role has no INSERT, so tombstones and completion
 * events go through the worker credential.
 *
 * Legal hold (policy.legal_hold = true): blocks the destructive phase
 * entirely and is audited 'purge:blocked' when anything was eligible.
 * Expiry marking still runs (non-destructive); audit rows under legal hold are
 * never deleted (policy + query predicates). Idempotent: a re-run with nothing
 * eligible deletes nothing and writes no events.
 */
import type { Pool, PoolClient } from 'pg';
import { withWorkerContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import { expireVersionsFor } from './retention.js';
import type { SourceObjectStore } from './storage.js';

/** Documented service identity for worker-written audit events (no FK on
 * audit_events; never read back as a principal). */
export const RETENTION_SERVICE_PRINCIPAL = '00000000-0000-4000-8000-000000000001';
export const RETENTION_SERVICE_MEMBERSHIP = '00000000-0000-4000-8000-000000000002';

export interface PurgeDeps {
  /** securerag_worker pool: expiry marking, audit events, job bookkeeping. */
  workerPool: Pool;
  /** securerag_purge pool: destructive deletion of proven-expired rows. */
  purgePool: Pool;
  /** Source object storage seam (in-memory fake; S3 adapter in S2). */
  store: SourceObjectStore;
}

export interface PurgeCounts {
  sources: number;
  chunks: number;
  versions: number;
  audit: number;
}

export interface PurgeResult {
  tenantId: string;
  /** true when legal hold blocked the destructive phase. */
  blocked: boolean;
  /** Deleted counts (or eligible-but-held counts when blocked). */
  counts: PurgeCounts;
  /** Authorization epoch at completion. */
  epoch: string;
}

interface Eligibility {
  sourceKeys: string[];
  chunks: number;
  versions: number;
  audit: number;
}

interface DeletedAuditRow {
  event_id: string;
}

function totalEligible(e: Eligibility): number {
  return e.chunks + e.versions + e.audit + e.sourceKeys.length;
}

const SELECT_SOURCE_KEYS = `
  SELECT v.source_object_key
    FROM securerag.document_versions v
    JOIN securerag.retention_policies p ON p.tenant_id = v.tenant_id
   WHERE v.tenant_id = securerag.ctx_tenant_id()
     AND v.status = 'expired'
     AND v.published_at + p.source_days * interval '1 day'
                   + p.grace_days * interval '1 day' < now()
   ORDER BY v.source_object_key`;

async function countEligible(client: PoolClient): Promise<Eligibility> {
  const [sources, chunks, versions, audit] = await Promise.all([
    client.query<{ source_object_key: string }>(SELECT_SOURCE_KEYS),
    client.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM securerag.chunks c
         JOIN securerag.document_versions v
           ON v.tenant_id = c.tenant_id AND v.version_id = c.version_id
         JOIN securerag.retention_policies p ON p.tenant_id = c.tenant_id
        WHERE c.tenant_id = securerag.ctx_tenant_id()
          AND v.status = 'expired'
          AND v.published_at + p.derived_days * interval '1 day'
                        + p.grace_days * interval '1 day' < now()`,
    ),
    client.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM securerag.document_versions v
         JOIN securerag.retention_policies p ON p.tenant_id = v.tenant_id
        WHERE v.tenant_id = securerag.ctx_tenant_id()
          AND v.status = 'expired'
          AND v.published_at + GREATEST(p.source_days, p.derived_days) * interval '1 day'
                        + p.grace_days * interval '1 day' < now()`,
    ),
    client.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM securerag.audit_events a
         JOIN securerag.retention_policies p ON p.tenant_id = a.tenant_id
        WHERE a.tenant_id = securerag.ctx_tenant_id()
          AND a.occurred_at + p.audit_days * interval '1 day'
                        + p.grace_days * interval '1 day' < now()`,
    ),
  ]);
  return {
    sourceKeys: sources.rows.map((r) => r.source_object_key),
    chunks: chunks.rows[0]?.n ?? 0,
    versions: versions.rows[0]?.n ?? 0,
    audit: audit.rows[0]?.n ?? 0,
  };
}

/**
 * Run one tenant's retention purge (expire → gate → delete → prove). The
 * destructive phase re-proves eligibility inside its own transaction; every
 * DELETE carries the expiry + grace predicates on top of the RLS expiry proof.
 */
export async function runTenantPurge(
  deps: PurgeDeps,
  params: { tenantId: string; requestId: string },
): Promise<PurgeResult> {
  await expireVersionsFor(deps.workerPool, params);

  const gate = await withWorkerContext(deps.workerPool, params, async (client, ctx) => {
    const policy = await client.query<{ legal_hold: boolean }>(
      `SELECT legal_hold
         FROM securerag.retention_policies
        WHERE tenant_id = securerag.ctx_tenant_id()`,
    );
    const eligibility = await countEligible(client);
    return {
      legalHold: policy.rows[0]?.legal_hold ?? false,
      eligibility,
      epoch: ctx.authEpoch,
    };
  });

  if (gate.legalHold) {
    if (totalEligible(gate.eligibility) > 0) {
      await withWorkerContext(deps.workerPool, params, async (client, ctx) => {
        await appendAudit({
          client,
          event: {
            eventType: 'purge:blocked',
            requestId: params.requestId,
            principalId: RETENTION_SERVICE_PRINCIPAL,
            membershipId: RETENTION_SERVICE_MEMBERSHIP,
            authEpoch: ctx.authEpoch,
            filters: {
              sources: gate.eligibility.sourceKeys.length,
              chunks: gate.eligibility.chunks,
              versions: gate.eligibility.versions,
              audit: gate.eligibility.audit,
              epoch: ctx.authEpoch,
            },
          },
        });
      });
    }
    return {
      tenantId: params.tenantId,
      blocked: true,
      counts: {
        sources: gate.eligibility.sourceKeys.length,
        chunks: gate.eligibility.chunks,
        versions: gate.eligibility.versions,
        audit: gate.eligibility.audit,
      },
      epoch: gate.epoch,
    };
  }

  const deleted = await withWorkerContext(deps.purgePool, params, async (client) => {
    const sourceRows = await client.query<{ source_object_key: string }>(SELECT_SOURCE_KEYS);
    const sources = await deps.store.deleteSources(sourceRows.rows.map((r) => r.source_object_key));

    const chunkRows = await client.query<{ chunk_id: string }>(
      `DELETE FROM securerag.chunks c
         USING securerag.document_versions v,
               securerag.retention_policies p
        WHERE c.tenant_id = securerag.ctx_tenant_id()
          AND v.tenant_id = c.tenant_id AND v.version_id = c.version_id
          AND p.tenant_id = c.tenant_id
          AND v.status = 'expired'
          AND v.published_at + p.derived_days * interval '1 day'
                        + p.grace_days * interval '1 day' < now()
        RETURNING c.chunk_id`,
    );

    const versionRows = await client.query<{ version_id: string }>(
      `DELETE FROM securerag.document_versions v
         USING securerag.retention_policies p
        WHERE v.tenant_id = securerag.ctx_tenant_id()
          AND p.tenant_id = v.tenant_id
          AND v.status = 'expired'
          AND v.published_at + GREATEST(p.source_days, p.derived_days) * interval '1 day'
                        + p.grace_days * interval '1 day' < now()
        RETURNING v.version_id`,
    );

    const auditRows = await client.query<DeletedAuditRow>(
      `DELETE FROM securerag.audit_events a
         USING securerag.retention_policies p
        WHERE a.tenant_id = securerag.ctx_tenant_id()
          AND p.tenant_id = a.tenant_id
          AND a.occurred_at + p.audit_days * interval '1 day'
                        + p.grace_days * interval '1 day' < now()
        RETURNING a.event_id`,
    );

    return {
      sources,
      chunks: chunkRows.rows.length,
      versions: versionRows.rows.length,
      audit: auditRows.rows.map((r) => r.event_id),
    };
  });

  const counts: PurgeCounts = {
    sources: deleted.sources,
    chunks: deleted.chunks,
    versions: deleted.versions,
    audit: deleted.audit.length,
  };

  const epoch = await withWorkerContext(deps.workerPool, params, async (client, ctx) => {
    if (counts.audit > 0) {
      const ids = deleted.audit.map((r) => BigInt(r));
      const min = ids.reduce((a, b) => (b < a ? b : a));
      const max = ids.reduce((a, b) => (b > a ? b : a));
      await appendAudit({
        client,
        event: {
          eventType: 'audit:purged',
          requestId: params.requestId,
          principalId: RETENTION_SERVICE_PRINCIPAL,
          membershipId: RETENTION_SERVICE_MEMBERSHIP,
          authEpoch: ctx.authEpoch,
          filters: {
            eventIdRange: { min: min.toString(), max: max.toString() },
            count: counts.audit,
          },
        },
      });
    }
    if (counts.sources + counts.chunks + counts.versions + counts.audit > 0) {
      await appendAudit({
        client,
        event: {
          eventType: 'purge:completed',
          requestId: params.requestId,
          principalId: RETENTION_SERVICE_PRINCIPAL,
          membershipId: RETENTION_SERVICE_MEMBERSHIP,
          authEpoch: ctx.authEpoch,
          filters: { ...counts, epoch: ctx.authEpoch },
        },
      });
    }
    return ctx.authEpoch;
  });

  return { tenantId: params.tenantId, blocked: false, counts, epoch };
}
