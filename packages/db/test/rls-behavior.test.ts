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
