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

describe('S1 RLS kernel — sessions, identity, admin-only groups on real runtime roles', () => {
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

  it('sessions are principal-scoped: no context shows nothing; own context shows own rows only', async () => {
    const tokenHash = Buffer.from(
      'a'.repeat(64),
      'hex',
    );
    await db.superuserPool.query(
      `INSERT INTO securerag.sessions (principal_id, csrf_token, token_hash, expires_at)
       VALUES ($1, decode('bb', 'hex'), $2, now() + interval '1 hour')`,
      [world.alice.id, tokenHash],
    );
    const noCtx = (await withContext(api, {}, async (c) =>
      c.query('SELECT count(*)::int n FROM securerag.sessions'),
    )) as { rows: { n: number }[] };
    expect(noCtx.rows[0]?.n).toBe(0);
    const aliceRows = (await withContext(api, { principal_id: world.alice.id }, async (c) =>
      c.query('SELECT principal_id FROM securerag.sessions'),
    )) as { rows: { principal_id: string }[] };
    expect(aliceRows.rows.map((r) => r.principal_id)).toEqual([world.alice.id]);
    const bobRows = (await withContext(api, { principal_id: world.bob.id }, async (c) =>
      c.query('SELECT count(*)::int n FROM securerag.sessions'),
    )) as { rows: { n: number }[] };
    expect(bobRows.rows[0]?.n).toBe(0);
  });

  it('get_session/revoke_session enforce validity inside SQL; foreign and revoked tokens are indistinguishable', async () => {
    const tokenHash = Buffer.from('bb'.repeat(32), 'hex');
    const otherHash = Buffer.from('cc'.repeat(32), 'hex');
    await db.superuserPool.query(
      `INSERT INTO securerag.sessions (principal_id, csrf_token, token_hash, expires_at)
       VALUES ($1, decode('dd', 'hex'), $2, now() + interval '1 hour')`,
      [world.alice.id, tokenHash],
    );
    await db.superuserPool.query(
      `INSERT INTO securerag.sessions (principal_id, csrf_token, token_hash, expires_at, revoked_at)
       VALUES ($1, decode('dd', 'hex'), $2, now() + interval '1 hour', now())`,
      [world.alice.id, otherHash],
    );

    const live = (await withContext(api, {}, async (c) =>
      c.query<{ principal_id: string }>('SELECT principal_id FROM securerag.get_session($1)', [tokenHash]),
    )) as { rows: { principal_id: string }[] };
    expect(live.rows[0]?.principal_id).toBe(world.alice.id);

    const revoked = (await withContext(api, {}, async (c) =>
      c.query('SELECT principal_id FROM securerag.get_session($1)', [otherHash]),
    )) as { rows: unknown[] };
    const foreign = (await withContext(api, {}, async (c) =>
      c.query('SELECT principal_id FROM securerag.get_session($1)', [
        Buffer.from('ee'.repeat(32), 'hex'),
      ]),
    )) as { rows: unknown[] };
    expect(revoked.rows).toEqual([]);
    expect(foreign.rows).toEqual([]);

    const first = (await withContext(api, {}, async (c) =>
      c.query('SELECT securerag.revoke_session($1) AS revoked', [tokenHash]),
    )) as { rows: { revoked: boolean }[] };
    expect(first.rows[0]?.revoked).toBe(true);
    // A second revoke is a silent no-op: a scalar SQL function returning zero
    // rows yields a single NULL row (never an error, never a second effect).
    const second = (await withContext(api, {}, async (c) =>
      c.query('SELECT securerag.revoke_session($1) AS revoked', [tokenHash]),
    )) as { rows: { revoked: boolean | null }[] };
    expect(second.rows[0]?.revoked).toBeNull();
    const after = (await withContext(api, {}, async (c) =>
      c.query('SELECT principal_id FROM securerag.get_session($1)', [tokenHash]),
    )) as { rows: unknown[] };
    expect(after.rows).toEqual([]);
  });

  it('upsert_principal is idempotent and returns a stable id (no existence oracle)', async () => {
    const first = (await withContext(api, {}, async (c) =>
      c.query('SELECT securerag.upsert_principal($1, $2, $3) AS id', [
        'test-issuer',
        'fresh-subject',
        'Fresh Face',
      ]),
    )) as { rows: { id: string }[] };
    const id1 = first.rows[0]?.id;
    expect(id1).toBeTruthy();
    const second = (await withContext(api, {}, async (c) =>
      c.query('SELECT securerag.upsert_principal($1, $2, $3) AS id', [
        'test-issuer',
        'fresh-subject',
        'Fresh Face v2',
      ]),
    )) as { rows: { id: string }[] };
    expect(second.rows[0]?.id).toBe(id1);
    const { rows } = await db.superuserPool.query<{ display_name: string; count: string }>(
      `SELECT display_name, count(*)::int AS count
         FROM securerag.principals WHERE provider = 'test-issuer' AND external_subject = 'fresh-subject'
        GROUP BY display_name`,
    );
    expect(rows[0]).toMatchObject({ display_name: 'Fresh Face v2' });
  });

  it('groups: a member cannot create, delete, or modify groups or memberships; an admin can', async () => {
    const member = { tenant_id: world.tenantA.id, principal_id: world.alice.id };
    const admin = { tenant_id: world.tenantA.id, principal_id: world.carol.id };
    await expect(
      withContext(api, member, (c) =>
        c.query(`INSERT INTO securerag.groups (tenant_id, name) VALUES ($1, 'sneaky')`, [
          world.tenantA.id,
        ]),
      ),
    ).rejects.toThrow(/row-level security/);

    const created = (await withContext(api, admin, async (c) =>
      c.query<{ group_id: string }>(
        `INSERT INTO securerag.groups (tenant_id, name) VALUES ($1, 'Admin Group') RETURNING group_id`,
        [world.tenantA.id],
      ),
    )) as { rows: { group_id: string }[] };
    const groupId = created.rows[0]?.group_id;
    expect(groupId).toBeTruthy();

    await expect(
      withContext(api, member, (c) =>
        c.query(
          `INSERT INTO securerag.group_memberships (tenant_id, group_id, principal_id)
           VALUES ($1, $2, $3)`,
          [world.tenantA.id, groupId, world.alice.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/);

    // DELETE on a policy-invisible row is a silent 0-row no-op (never an
    // error, never a side effect): the member's attempt touches nothing.
    const memberDelete = (await withContext(api, member, async (c) =>
      c.query(`DELETE FROM securerag.groups WHERE tenant_id = $1 AND group_id = $2`, [
        world.tenantA.id,
        groupId,
      ]),
    )) as { rowCount: number };
    expect(memberDelete.rowCount).toBe(0);
    const stillThere = (await db.superuserPool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM securerag.groups WHERE group_id = $1`,
      [groupId],
    )).rows[0]?.n;
    expect(stillThere).toBe(1);

    const added = (await withContext(api, admin, async (c) =>
      c.query<{ principal_id: string }>(
        `INSERT INTO securerag.group_memberships (tenant_id, group_id, principal_id)
         VALUES ($1, $2, $3) RETURNING principal_id`,
        [world.tenantA.id, groupId, world.bob.id],
      ),
    )) as { rows: { principal_id: string }[] };
    expect(added.rows[0]?.principal_id).toBe(world.bob.id);
  });

  it('a member sees only their OWN group membership rows (self-read branch for retrieval)', async () => {
    const member = { tenant_id: world.tenantA.id, principal_id: world.bob.id };
    const rows = (await withContext(api, member, async (c) =>
      c.query('SELECT group_id, principal_id FROM securerag.group_memberships'),
    )) as { rows: { group_id: string; principal_id: string }[] };
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({ principal_id: world.bob.id });
  });
});
