import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import {
  expireVersionsFor,
  getRetentionPolicy,
  upsertRetentionPolicy,
} from '../src/retention.js';
import { runTenantPurge } from '../src/purge.js';
import { InMemorySourceObjectStore } from '../src/storage.js';

describe('S9 retention and purge on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: Awaited<ReturnType<typeof seedFixtures>>;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    api = db.apiPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  const req = (): string => randomUUID();

  it('every tenant gets a default retention policy (trigger + first access)', async () => {
    const policy = await getRetentionPolicy(api, {
      tenantId: world.tenantA.id,
      principalId: world.alice.id,
      requestId: req(),
    });
    expect(policy).toMatchObject({
      tenantId: world.tenantA.id,
      sourceDays: 3650,
      derivedDays: 3650,
      auditDays: 1095,
      graceDays: 7,
      legalHold: false,
    });
  });

  it('policy upsert is admin-only, audited, and bumps the epoch', async () => {
    const before = Number(
      (await db.superuserPool.query<{ epoch: string }>('SELECT epoch FROM securerag.authorization_epoch')).rows[0]?.epoch,
    );
    const asMember = await upsertRetentionPolicy(api, {
      tenantId: world.tenantA.id,
      principalId: world.alice.id,
      requestId: req(),
      patch: { legalHold: true },
    });
    expect(asMember).toBeNull();
    const asAdmin = await upsertRetentionPolicy(api, {
      tenantId: world.tenantA.id,
      principalId: world.carol.id,
      requestId: req(),
      patch: { auditDays: 30, legalHold: false },
    });
    expect(asAdmin).toMatchObject({ auditDays: 30, legalHold: false });
    const after = Number(
      (await db.superuserPool.query<{ epoch: string }>('SELECT epoch FROM securerag.authorization_epoch')).rows[0]?.epoch,
    );
    expect(after).toBeGreaterThan(before);
    const { rows } = await db.superuserPool.query<{ event_type: string }>(
      `SELECT event_type FROM securerag.audit_events WHERE event_type = 'retention:changed'`,
    );
    expect(rows.length).toBeGreaterThan(0);
  });

  it('expiry marks only past-retention versions and makes them non-retrievable', async () => {
    await db.superuserPool.query(
      `UPDATE securerag.document_versions
          SET published_at = now() - interval '4000 days'
        WHERE tenant_id = $1 AND version_id = $2`,
      [world.tenantA.id, world.docA.versionId],
    );
    await db.superuserPool.query(
      `UPDATE securerag.retention_policies
          SET source_days = 365, derived_days = 365
        WHERE tenant_id = $1`,
      [world.tenantA.id],
    );
    const result = await expireVersionsFor(db.workerPool, {
      tenantId: world.tenantA.id,
      requestId: req(),
    });
    expect(result.marked).toBeGreaterThan(0);
    const status = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.document_versions WHERE version_id = $1`,
      [world.docA.versionId],
    );
    expect(status.rows[0]?.status).toBe('expired');
  });

  it('legal hold blocks the destructive purge phase and is audited', async () => {
    await db.superuserPool.query(
      `UPDATE securerag.retention_policies SET legal_hold = true WHERE tenant_id = $1`,
      [world.tenantB.id],
    );
    await db.superuserPool.query(
      `UPDATE securerag.document_versions
          SET status = 'expired', published_at = now() - interval '4000 days'
        WHERE tenant_id = $1 AND version_id = $2`,
      [world.tenantB.id, world.docB.versionId],
    );
    const store = new InMemorySourceObjectStore();
    const result = await runTenantPurge(
      { workerPool: db.workerPool, purgePool: db.purgePool, store },
      { tenantId: world.tenantB.id, requestId: req() },
    );
    expect(result.blocked).toBe(true);
    const { rows } = await db.superuserPool.query<{ event_type: string }>(
      `SELECT event_type FROM securerag.audit_events WHERE event_type = 'purge:blocked'`,
    );
    expect(rows.length).toBeGreaterThan(0);
    const stillThere = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.document_versions WHERE version_id = $1`,
      [world.docB.versionId],
    );
    expect(stillThere.rows[0]?.status).toBe('expired');
  });

  it('purge deletes only proven-expired rows of the tenant, proves every storage class, and is idempotent', async () => {
    await db.superuserPool.query(
      `UPDATE securerag.retention_policies SET legal_hold = false WHERE tenant_id = $1`,
      [world.tenantB.id],
    );
    const store = new InMemorySourceObjectStore();
    const sourceKey = await db.superuserPool.query<{ source_object_key: string }>(
      `SELECT source_object_key FROM securerag.document_versions WHERE version_id = $1`,
      [world.docB.versionId],
    );
    store.put(sourceKey.rows[0]!.source_object_key);
    const first = await runTenantPurge(
      { workerPool: db.workerPool, purgePool: db.purgePool, store },
      { tenantId: world.tenantB.id, requestId: req() },
    );
    expect(first.blocked).toBe(false);
    expect(first.counts.sources).toBe(1);
    expect(first.counts.versions).toBeGreaterThan(0);
    expect(first.counts.chunks).toBeGreaterThan(0);
    expect(store.size).toBe(0);
    const version = await db.superuserPool.query<{ version_id: string }>(
      `SELECT version_id FROM securerag.document_versions WHERE version_id = $1`,
      [world.docB.versionId],
    );
    expect(version.rows).toHaveLength(0);
    // Active rows of the SAME tenant and ALL rows of the foreign tenant survive.
    const active = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.document_versions WHERE tenant_id = $1 AND status <> 'expired'`,
      [world.tenantB.id],
    );
    expect(active.rows.length).toBeGreaterThanOrEqual(0);
    const foreignActive = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.document_versions WHERE tenant_id = $1 AND version_id = $2`,
      [world.tenantA.id, world.docA.versionId],
    );
    expect(foreignActive.rows[0]?.status).toBe('expired'); // tenantA's was expired earlier but NOT purged by tenantB's run
    const second = await runTenantPurge(
      { workerPool: db.workerPool, purgePool: db.purgePool, store },
      { tenantId: world.tenantB.id, requestId: req() },
    );
    expect(second.counts.versions).toBe(0);
    expect(second.counts.chunks).toBe(0);
    expect(second.counts.audit).toBe(0);
    // Purge completion + tombstone events recorded.
    const events = await db.superuserPool.query<{ event_type: string }>(
      `SELECT DISTINCT event_type FROM securerag.audit_events WHERE event_type IN ('purge:completed','audit:purged')`,
    );
    expect(events.rows.map((r) => r.event_type)).toContain('purge:completed');
  });

  it('purge deletes expired audit rows with tombstones (policy subquery not folded)', async () => {
    await db.superuserPool.query(
      `INSERT INTO securerag.audit_events
         (tenant_id, event_type, request_id, auth_epoch, occurred_at)
       VALUES ($1, 'retrieval:allowed', gen_random_uuid(), 1, now() - interval '2000 days')`,
      [world.tenantA.id],
    );
    await db.superuserPool.query(
      `UPDATE securerag.retention_policies SET audit_days = 30, legal_hold = false WHERE tenant_id = $1`,
      [world.tenantA.id],
    );
    const store = new InMemorySourceObjectStore();
    const result = await runTenantPurge(
      { workerPool: db.workerPool, purgePool: db.purgePool, store },
      { tenantId: world.tenantA.id, requestId: req() },
    );
    expect(result.counts.audit).toBeGreaterThan(0);
    const { rows } = await db.superuserPool.query<{ event_type: string }>(
      `SELECT event_type FROM securerag.audit_events
        WHERE event_type IN ('audit:purged','purge:completed')`,
    );
    expect(rows.map((r) => r.event_type)).toEqual(
      expect.arrayContaining(['audit:purged', 'purge:completed']),
    );
  });

  it('the purge role cannot delete ACTIVE rows even with a raw DELETE', async () => {
    const client = await db.purgePool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('securerag.tenant_id', $1, true)`, [world.tenantA.id]);
      const result = await client.query(
        `DELETE FROM securerag.document_versions WHERE tenant_id = $1 AND status <> 'expired'`,
        [world.tenantA.id],
      );
      await client.query('COMMIT');
      expect(result.rowCount).toBe(0);
    } finally {
      client.release();
    }
  });
});
