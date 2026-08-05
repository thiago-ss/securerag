import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import { withSecurityContext } from '@securerag/security';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import { appendAudit } from '../src/audit.js';
import { verifyAuditChain } from '../src/audit-chain.js';
import type { AuditEvent } from '../src/types.js';

describe('S8 per-tenant audit hash chain on real runtime roles', () => {
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

  /** Wipe the tenant's audit rows entirely (test fixture path, superuser). */
  async function wipeTenantAudit(): Promise<void> {
    await db.superuserPool.query(
      `DELETE FROM securerag.audit_events WHERE tenant_id = $1`,
      [world.tenantA.id],
    );
  }

  /** Append an audit event through the runtime api role with a verified context. */
  async function appendEvent(
    overrides: Partial<AuditEvent> = {},
    principalId: string = world.alice.id,
    tenantId: string = world.tenantA.id,
  ): Promise<void> {
    await withSecurityContext(api, { tenantId, principalId, requestId: req() }, async (client, ctx) => {
      await appendAudit({
        client,
        event: {
          eventType: 'retrieval:allowed',
          requestId: ctx.requestId,
          principalId: ctx.principalId,
          membershipId: ctx.membershipId,
          authEpoch: ctx.authEpoch,
          redactedQuery: '[REDACTED] question',
          queryHash: Buffer.from('aabb', 'hex'),
          ...overrides,
        },
      });
    });
  }

  async function chainRows(tenantId: string = world.tenantA.id): Promise<
    { event_id: string; event_type: string; prev_event_hash: Buffer | null; event_hash: Buffer | null }[]
  > {
    const { rows } = await db.superuserPool.query<{
      event_id: string;
      event_type: string;
      prev_event_hash: Buffer | null;
      event_hash: Buffer | null;
    }>(
      `SELECT event_id, event_type, prev_event_hash, event_hash
         FROM securerag.audit_events
        WHERE tenant_id = $1
        ORDER BY event_id ASC`,
      [tenantId],
    );
    return rows;
  }

  const verify = async (): Promise<Awaited<ReturnType<typeof verifyAuditChain>>> =>
    verifyAuditChain(api, {
      tenantId: world.tenantA.id,
      principalId: world.alice.id,
      requestId: req(),
    });

  it('sequential appends build one valid per-tenant chain with exact linkage', async () => {
    await appendEvent({ eventType: 'retrieval:allowed' });
    await appendEvent({ eventType: 'retrieval:refused', refusalReason: 'INSUFFICIENT_EVIDENCE' });
    await appendEvent({ eventType: 'document:read' });

    const rows = await chainRows();
    expect(rows).toHaveLength(3);
    for (const row of rows) expect(row.event_hash).not.toBeNull();
    expect(rows[0]!.prev_event_hash).toBeNull();
    expect(rows[1]!.prev_event_hash).toEqual(rows[0]!.event_hash);
    expect(rows[2]!.prev_event_hash).toEqual(rows[1]!.event_hash);

    const verification = await verify();
    expect(verification.valid).toBe(true);
    expect(verification.totalEvents).toBe(3);
    expect(verification.chainedEvents).toBe(3);
    expect(verification.failures).toEqual([]);
    expect(verification.anchorHash).toEqual(rows[2]!.event_hash!.toString('hex'));
    expect(verification.anchorEventId).toBe(rows[2]!.event_id);
  });

  it('tenant B has its own independent chain (no cross-tenant linkage)', async () => {
    await appendEvent({}, world.bob.id, world.tenantB.id);
    const verification = await verifyAuditChain(api, {
      tenantId: world.tenantB.id,
      principalId: world.bob.id,
      requestId: req(),
    });
    expect(verification.valid).toBe(true);
    expect(verification.chainedEvents).toBe(1);
    const tenantARows = await chainRows();
    expect(verification.anchorHash).not.toBe(tenantARows.at(-1)!.event_hash!.toString('hex'));
  });

  it('legacy rows (NULL hashes) are tolerated: the chain restarts after them', async () => {
    await wipeTenantAudit();
    const legacy = await db.superuserPool.query<{ event_id: string }>(
      `INSERT INTO securerag.audit_events
         (tenant_id, event_type, request_id, auth_epoch)
       VALUES ($1, 'retrieval:allowed', gen_random_uuid(), 1)
       RETURNING event_id`,
      [world.tenantA.id],
    );
    await appendEvent({ eventType: 'retrieval:allowed' });

    const rows = await chainRows();
    const legacyRow = rows.find((r) => r.event_id === legacy.rows[0]!.event_id)!;
    expect(legacyRow.event_hash).toBeNull();
    expect(legacyRow.prev_event_hash).toBeNull();
    const after = rows[rows.length - 1]!;
    // Fresh chain start after the legacy row (prev NULL).
    expect(after.prev_event_hash).toBeNull();

    const verification = await verify();
    expect(verification.valid).toBe(true);
    expect(verification.anchorEventId).toBe(after.event_id);
    expect(verification.totalEvents).toBe(2);
    expect(verification.chainedEvents).toBe(1);
  });

  it('a purge gap covered by a chained tombstone verifies (reseed); the reseed row carries its hash forward', async () => {
    await wipeTenantAudit();
    await appendEvent();
    await appendEvent();
    await appendEvent();
    const rows = await chainRows();
    const victim = rows[1]!;
    const survivor = rows[2]!;

    // Purge flow: DELETE the expired row (superuser stands in for the
    // RLS-proven purge role), then append the chained tombstone.
    await db.superuserPool.query(
      `DELETE FROM securerag.audit_events WHERE tenant_id = $1 AND event_id = $2`,
      [world.tenantA.id, victim.event_id],
    );
    await appendEvent({
      eventType: 'audit:purged',
      filters: { eventIdRange: { min: victim.event_id, max: victim.event_id }, count: 1 },
    });

    const verification = await verify();
    expect(verification.valid).toBe(true);
    expect(verification.reseededEventIds).toContain(survivor.event_id);
    expect(verification.failures).toEqual([]);
  });

  it('deleting the tail event keeps linkage but changes the anchor (documented)', async () => {
    await wipeTenantAudit();
    await appendEvent();
    await appendEvent();
    await appendEvent();
    const before = await verify();
    const rows = await chainRows();
    const tail = rows.at(-1)!;
    await db.superuserPool.query(
      `DELETE FROM securerag.audit_events WHERE tenant_id = $1 AND event_id = $2`,
      [world.tenantA.id, tail.event_id],
    );
    const after = await verify();
    expect(after.valid).toBe(true);
    expect(after.anchorHash).not.toBe(before.anchorHash);
  });

  it('concurrent appends serialize per tenant: two parallel appends produce one valid chain', async () => {
    await wipeTenantAudit();
    await appendEvent();
    const clientA = await api.connect();
    const clientB = await api.connect();
    try {
      const run = async (client: PoolClient): Promise<void> => {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('securerag.tenant_id', $1, true)`, [world.tenantA.id]);
        await appendAudit({
          client,
          event: {
            eventType: 'retrieval:allowed',
            requestId: req(),
            principalId: world.alice.id,
            membershipId: '00000000-0000-4000-8000-000000000010',
            authEpoch: '1',
          },
        });
        await client.query('COMMIT');
      };
      await Promise.all([run(clientA), run(clientB)]);
    } finally {
      clientA.release();
      clientB.release();
    }

    const verification = await verify();
    expect(verification.valid).toBe(true);
    const rows = await chainRows();
    const lastTwo = rows.slice(-2);
    expect(lastTwo).toHaveLength(2);
    expect(lastTwo[1]!.prev_event_hash).toEqual(lastTwo[0]!.event_hash);
    expect(verification.anchorHash).toBe(lastTwo[1]!.event_hash!.toString('hex'));
    expect(verification.totalEvents).toBe(3);
    expect(verification.chainedEvents).toBe(3);
  });

  it('tampering with a stored event field breaks verification (hash mismatch)', async () => {
    await wipeTenantAudit();
    await appendEvent({ eventType: 'retrieval:allowed' });
    await appendEvent({ eventType: 'retrieval:refused' });
    const rows = await chainRows();
    const target = rows.at(-1)!;

    // Superuser tamper (runtime roles have no UPDATE grant at all).
    await db.superuserPool.query(
      `UPDATE securerag.audit_events SET event_type = 'retrieval:denied' WHERE tenant_id = $1 AND event_id = $2`,
      [world.tenantA.id, target.event_id],
    );

    const verification = await verify();
    expect(verification.valid).toBe(false);
    expect(verification.failures.some((f) => f.includes('event_hash mismatch'))).toBe(true);
  });

  it('deleting a middle event breaks the chain (missing predecessor)', async () => {
    await wipeTenantAudit();
    await appendEvent();
    await appendEvent();
    await appendEvent();
    const rows = await chainRows();
    const middle = rows[1]!;
    await db.superuserPool.query(
      `DELETE FROM securerag.audit_events WHERE tenant_id = $1 AND event_id = $2`,
      [world.tenantA.id, middle.event_id],
    );
    const verification = await verify();
    expect(verification.valid).toBe(false);
    expect(verification.failures.some((f) => f.includes('does not link to event'))).toBe(true);
  });

  it('reordering events breaks verification (event_id is bound into each hash)', async () => {
    await wipeTenantAudit();
    await appendEvent({ eventType: 'retrieval:allowed' });
    await appendEvent({ eventType: 'retrieval:refused' });
    const rows = await chainRows();
    const [first, second] = rows;

    // Swap the two rows' ids (superuser), staged via an offset so the PK
    // stays unique at every step.
    await db.superuserPool.query(
      `UPDATE securerag.audit_events SET event_id = event_id + 1000000000000
        WHERE tenant_id = $1 AND event_id IN ($2, $3)`,
      [world.tenantA.id, first!.event_id, second!.event_id],
    );
    await db.superuserPool.query(
      `UPDATE securerag.audit_events
          SET event_id = CASE event_id WHEN $2 THEN $3 WHEN $3 THEN $2 ELSE event_id END
        WHERE tenant_id = $1 AND event_id IN ($2, $3)`,
      [world.tenantA.id, first!.event_id, second!.event_id],
    );
    const verification = await verify();
    expect(verification.valid).toBe(false);
    expect(verification.failures.length).toBeGreaterThan(0);
  });

  it('the runtime api role cannot rewrite an event (insert-only chain) even with a forged context', async () => {
    const client = await api.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('securerag.tenant_id', $1, true)`, [world.tenantA.id]);
      await expect(
        client.query(
          `UPDATE securerag.audit_events SET event_type = 'retrieval:denied' WHERE tenant_id = $1`,
          [world.tenantA.id],
        ),
      ).rejects.toMatchObject({ code: '42501' });
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  });
});
