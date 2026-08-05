import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getTestDb, type TestDb } from './helpers.js';
import { resetData, seedFixtures } from './fixtures.js';
import type { Pool } from 'pg';

describe('RLS isolation on real runtime roles', () => {
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

  async function withContext(
    pool: Pool,
    ctx: Record<string, string>,
    fn: (client: import('pg').PoolClient) => Promise<unknown>,
  ): Promise<unknown> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const [key, value] of Object.entries(ctx)) {
        await client.query(`SELECT set_config($1, $2, true)`, [`securerag.${key}`, value]);
      }
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  it('a tenant member sees only own-tenant documents', async () => {
    const docs = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query<{ title: string }>('SELECT title FROM securerag.documents ORDER BY title'),
    )) as { rows: { title: string }[] };
    expect(docs.rows.map((r) => r.title)).toEqual(['Alpha private doc']);
  });

  it('a foreign tenant returns zero rows even with an explicit tenant filter', async () => {
    const rows = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query('SELECT count(*)::int AS n FROM securerag.documents WHERE tenant_id = $1', [world.tenantB.id]),
    )) as { rows: { n: number }[] };
    expect(rows.rows[0]?.n).toBe(0);
  });

  it('missing context returns zero rows; malformed context fails safely', async () => {
    const noContext = (await withContext(api, {}, async (c) =>
      c.query('SELECT count(*)::int AS n FROM securerag.documents'),
    )) as { rows: { n: number }[] };
    expect(noContext.rows[0]?.n).toBe(0);
    const unknownTenant = (await withContext(api, { tenant_id: '00000000-0000-0000-0000-000000000000', principal_id: world.alice.id }, async (c) =>
      c.query('SELECT count(*)::int AS n FROM securerag.documents'),
    )) as { rows: { n: number }[] };
    expect(unknownTenant.rows[0]?.n).toBe(0);
    await expect(
      withContext(api, { tenant_id: 'not-a-uuid', principal_id: world.alice.id }, (c) =>
        c.query('SELECT count(*)::int AS n FROM securerag.documents'),
      ),
    ).rejects.toThrow(/uuid/);
  });

  it('an insert with a foreign tenant_id fails the WITH CHECK policy', async () => {
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `INSERT INTO securerag.documents (tenant_id, title) VALUES ($1, 'sneaky')`,
          [world.tenantB.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('cross-tenant references are structurally impossible (composite FK)', async () => {
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `INSERT INTO securerag.chunks (tenant_id, version_id, chunk_no, text_redacted, span_start, span_end, content_hash)
           VALUES ($1, $2, 99, 'x', 0, 1, decode('ff', 'hex'))`,
          [world.tenantA.id, world.docB.versionId],
        ),
      ),
    ).rejects.toThrow(/foreign key/);
  });

  it('membership bootstrap reveals only the authenticated principal\'s own memberships', async () => {
    const aliceRows = (await withContext(api, { principal_id: world.alice.id }, async (c) =>
      c.query('SELECT tenant_id, role FROM securerag.tenant_memberships'),
    )) as { rows: { tenant_id: string; role: string }[] };
    expect(aliceRows.rows).toHaveLength(1);
    expect(aliceRows.rows[0]).toMatchObject({ tenant_id: world.tenantA.id, role: 'member' });
    const bobRows = (await withContext(api, { principal_id: world.bob.id }, async (c) =>
      c.query('SELECT tenant_id FROM securerag.tenant_memberships'),
    )) as { rows: { tenant_id: string }[] };
    expect(bobRows.rows.map((r) => r.tenant_id)).toEqual([world.tenantB.id]);
  });

  it('an admin sees tenant membership rows under verified tenant context', async () => {
    const rows = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.carol.id }, async (c) =>
      c.query('SELECT principal_id FROM securerag.tenant_memberships ORDER BY principal_id'),
    )) as { rows: { principal_id: string }[] };
    expect(rows.rows.map((r) => r.principal_id).sort()).toEqual(
      [world.alice.id, world.carol.id].sort(),
    );
  });

  it('a member cannot self-insert a membership, self-promote, or self-deactivate', async () => {
    await expect(
      withContext(api, { tenant_id: world.tenantB.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role)
           VALUES ($1, $2, 'member')`,
          [world.tenantB.id, world.alice.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `UPDATE securerag.tenant_memberships SET role = 'admin'
           WHERE tenant_id = $1 AND principal_id = $2`,
          [world.tenantA.id, world.alice.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `UPDATE securerag.tenant_memberships SET is_active = false
           WHERE tenant_id = $1 AND principal_id = $2`,
          [world.tenantA.id, world.alice.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `INSERT INTO securerag.tenant_admins (tenant_id, principal_id) VALUES ($1, $2)`,
          [world.tenantA.id, world.alice.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('an admin can provision a membership (write path is admin-only)', async () => {
    const inserted = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.carol.id }, async (c) =>
      c.query(
        `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role)
         VALUES ($1, $2, 'member') RETURNING principal_id`,
        [world.tenantA.id, world.dave.id],
      ),
    )) as { rows: { principal_id: string }[] };
    expect(inserted.rows[0]?.principal_id).toBe(world.dave.id);
    const seen = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.dave.id }, async (c) =>
      c.query('SELECT count(*)::int n FROM securerag.tenant_memberships'),
    )) as { rows: { n: number }[] };
    expect(seen.rows[0]?.n).toBe(1);
  });

  it('a non-admin member cannot insert a tenant_admin mirror row', async () => {
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `INSERT INTO securerag.tenant_admins (tenant_id, principal_id) VALUES ($1, $2)`,
          [world.tenantA.id, world.alice.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('tenant registry is not enumerable without verified tenant context', async () => {
    const noCtx = (await withContext(api, {}, async (c) =>
      c.query('SELECT count(*)::int n FROM securerag.tenants'),
    )) as { rows: { n: number }[] };
    expect(noCtx.rows[0]?.n).toBe(0);
    const own = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query('SELECT name FROM securerag.tenants'),
    )) as { rows: { name: string }[] };
    expect(own.rows.map((r) => r.name)).toEqual(['Tenant Alpha']);
  });

  it('runtime roles cannot rewind the authorization epoch directly', async () => {
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(`UPDATE securerag.authorization_epoch SET epoch = 0`),
      ),
    ).rejects.toThrow(/permission denied/);
    const bumped = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query('SELECT securerag.bump_authorization_epoch() AS epoch'),
    )) as { rows: { epoch: string }[] };
    expect(Number(bumped.rows[0]?.epoch)).toBeGreaterThan(0);
  });

  it('audit events are tenant-isolated on read-back', async () => {
    await db.superuserPool.query(
      `INSERT INTO securerag.audit_events (tenant_id, event_type, request_id, auth_epoch, redacted_query) VALUES
         ($1, 'allowed', gen_random_uuid(), 1, 'q-a'),
         ($2, 'denied', gen_random_uuid(), 1, 'q-b')`,
      [world.tenantA.id, world.tenantB.id],
    );
    const aliceRows = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query('SELECT redacted_query FROM securerag.audit_events'),
    )) as { rows: { redacted_query: string }[] };
    expect(aliceRows.rows.map((r) => r.redacted_query)).toEqual(['q-a']);
    const bobRows = (await withContext(api, { tenant_id: world.tenantB.id, principal_id: world.bob.id }, async (c) =>
      c.query('SELECT redacted_query FROM securerag.audit_events'),
    )) as { rows: { redacted_query: string }[] };
    expect(bobRows.rows.map((r) => r.redacted_query)).toEqual(['q-b']);
  });

  it('worker role can produce derived data and audit but never mutate chunks', async () => {
    const worker = db.workerPool;
    const chunks = (await withContext(worker, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query('SELECT chunk_no FROM securerag.chunks ORDER BY chunk_no'),
    )) as { rows: { chunk_no: number }[] };
    expect(chunks.rows.map((r) => r.chunk_no)).toEqual([1, 2]);
    await expect(
      withContext(worker, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(
          `UPDATE securerag.chunks SET text_redacted = 'tampered' WHERE tenant_id = $1`,
          [world.tenantA.id],
        ),
      ),
    ).rejects.toThrow(/permission denied/);
    const inserted = (await withContext(worker, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query(
        `INSERT INTO securerag.audit_events (tenant_id, event_type, request_id, auth_epoch)
         VALUES ($1, 'lifecycle', gen_random_uuid(), 1) RETURNING event_id`,
        [world.tenantA.id],
      ),
    )) as { rows: { event_id: string }[] };
    expect(inserted.rows[0]?.event_id).toBeDefined();
  });

  it('audit events are insertable but never updatable or deletable by runtime roles', async () => {
    const inserted = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query(
        `INSERT INTO securerag.audit_events
           (tenant_id, event_type, request_id, auth_epoch, redacted_query)
         VALUES ($1, 'denied', gen_random_uuid(), 0, 'q')
         RETURNING event_id`,
        [world.tenantA.id],
      ),
    )) as { rows: { event_id: string }[] };
    const eventId = inserted.rows[0]?.event_id;
    expect(eventId).toBeDefined();
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(`UPDATE securerag.audit_events SET event_type = 'allowed' WHERE event_id = $1`, [eventId]),
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, (c) =>
        c.query(`DELETE FROM securerag.audit_events WHERE event_id = $1`, [eventId]),
      ),
    ).rejects.toThrow(/permission denied/);
  });

  it('authorization epoch bumps monotonically for runtime roles', async () => {
    const first = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query('SELECT securerag.bump_authorization_epoch() AS epoch'),
    )) as { rows: { epoch: string }[] };
    const second = (await withContext(api, { tenant_id: world.tenantA.id, principal_id: world.alice.id }, async (c) =>
      c.query('SELECT securerag.bump_authorization_epoch() AS epoch'),
    )) as { rows: { epoch: string }[] };
    expect(Number(second.rows[0]?.epoch)).toBeGreaterThan(Number(first.rows[0]?.epoch));
  });
});
