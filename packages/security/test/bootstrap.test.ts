import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  getTestDb,
  resetData,
  seedFixtures,
  TEST_PASSWORDS,
  type TestDb,
  type FixtureWorld,
} from '@securerag/db/src/testkit.js';
import {
  withIdentityContext,
  withSecurityContext,
} from '../src/bootstrap.js';
import { readContext, verifyContext } from '../src/context.js';
import { createRuntimePool } from '../src/db.js';
import { ERROR_CODES, MembershipError, SecurityContextError } from '../src/errors.js';

describe('two-stage security-context bootstrap on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    api = db.apiPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  /** In a NEW transaction on a pooled client, no context GUC may linger. */
  async function expectNoResidualContext(pool: Pool): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // GUCs previously set in this session revert to '' while never-touched
      // GUCs read as NULL; NULLIF normalizes both to null (the "no context"
      // state). A leaked session-level value would surface as non-null text.
      const { rows } = await client.query<{
        tenant_id: string | null;
        principal_id: string | null;
        membership_id: string | null;
        request_id: string | null;
        auth_epoch: string | null;
      }>(
        `SELECT
           NULLIF(current_setting('securerag.tenant_id', true), '')     AS tenant_id,
           NULLIF(current_setting('securerag.principal_id', true), '')  AS principal_id,
           NULLIF(current_setting('securerag.membership_id', true), '') AS membership_id,
           NULLIF(current_setting('securerag.request_id', true), '')    AS request_id,
           NULLIF(current_setting('securerag.auth_epoch', true), '')    AS auth_epoch`,
      );
      expect(rows[0]).toEqual({
        tenant_id: null,
        principal_id: null,
        membership_id: null,
        request_id: null,
        auth_epoch: null,
      });
      await client.query('COMMIT');
    } finally {
      client.release();
    }
  }

  it('withIdentityContext as the api role returns only the principal\'s own memberships', async () => {
    const alice = await withIdentityContext(api, world.alice.id, async (c) => {
      const own = await c.query<{ n: number }>(
        'SELECT count(*)::int AS n FROM securerag.tenant_memberships',
      );
      expect(own.rows[0]?.n).toBe(1);
      return 'alice-done';
    });
    expect(alice.result).toBe('alice-done');
    expect(alice.memberships).toHaveLength(1);
    expect(alice.memberships[0]).toMatchObject({
      tenantId: world.tenantA.id,
      role: 'member',
    });

    const bob = await withIdentityContext(api, world.bob.id, async () => 'bob');
    expect(bob.memberships).toHaveLength(1);
    expect(bob.memberships[0]).toMatchObject({
      tenantId: world.tenantB.id,
      role: 'member',
    });

    const dave = await withIdentityContext(api, world.dave.id, async () => 'dave');
    expect(dave.memberships).toEqual([]);

    await expectNoResidualContext(api);
  });

  it('withSecurityContext on an own tenant scopes the callback to that tenant with a full context', async () => {
    const requestId = randomUUID();
    const epoch = await db.superuserPool.query<{ epoch: string }>(
      'SELECT epoch FROM securerag.authorization_epoch',
    );
    const aliceMembership = await db.superuserPool.query<{ membership_id: string }>(
      `SELECT membership_id FROM securerag.tenant_memberships
        WHERE tenant_id = $1 AND principal_id = $2`,
      [world.tenantA.id, world.alice.id],
    );

    const result = await withSecurityContext(
      api,
      { principalId: world.alice.id, tenantId: world.tenantA.id, requestId },
      async (c, ctx) => {
        const docs = await c.query<{ title: string }>(
          'SELECT title FROM securerag.documents ORDER BY title',
        );
        expect(docs.rows).toHaveLength(1);
        expect(docs.rows[0]?.title).toBe('Alpha private doc');
        expect(ctx).toEqual({
          tenantId: world.tenantA.id,
          principalId: world.alice.id,
          membershipId: aliceMembership.rows[0]?.membership_id,
          requestId,
          authEpoch: epoch.rows[0]?.epoch,
        });
        const read = await readContext(c);
        expect(read).toEqual(ctx);
        return 'contextual-done';
      },
    );
    expect(result).toBe('contextual-done');
    await expectNoResidualContext(api);
  });

  it('foreign, nonexistent, and deactivated tenants throw indistinguishable MembershipErrors', async () => {
    const requests = [randomUUID(), randomUUID(), randomUUID()];
    const errors: unknown[] = [];

    const foreign = await withSecurityContext(
      api,
      { principalId: world.alice.id, tenantId: world.tenantB.id, requestId: requests[0]! },
      async () => 'must not run',
    ).catch((err: unknown) => {
      errors.push(err);
      return null;
    });
    expect(foreign).toBeNull();

    const nonexistent = await withSecurityContext(
      api,
      { principalId: world.alice.id, tenantId: randomUUID(), requestId: requests[1]! },
      async () => 'must not run',
    ).catch((err: unknown) => {
      errors.push(err);
      return null;
    });
    expect(nonexistent).toBeNull();

    await db.superuserPool.query(
      `UPDATE securerag.tenant_memberships SET is_active = false
        WHERE tenant_id = $1 AND principal_id = $2`,
      [world.tenantA.id, world.alice.id],
    );
    const deactivated = await withSecurityContext(
      api,
      { principalId: world.alice.id, tenantId: world.tenantA.id, requestId: requests[2]! },
      async () => 'must not run',
    ).catch((err: unknown) => {
      errors.push(err);
      return null;
    });
    await db.superuserPool.query(
      `UPDATE securerag.tenant_memberships SET is_active = true
        WHERE tenant_id = $1 AND principal_id = $2`,
      [world.tenantA.id, world.alice.id],
    );
    expect(deactivated).toBeNull();
    expect(errors).toHaveLength(3);

    const messages = errors.map((e) => {
      expect(e).toBeInstanceOf(MembershipError);
      expect((e as MembershipError).code).toBe(ERROR_CODES.membership);
      return (e as Error).message;
    });
    expect(new Set(messages)).toEqual(new Set([messages[0]]));
    for (const message of messages) {
      expect(message).toContain('No active membership');
      expect(message).not.toContain(world.tenantA.id);
      expect(message).not.toContain(world.tenantB.id);
    }
    await expectNoResidualContext(api);
  });

  it('one pool reused across tenants never bleeds context between requests', async () => {
    for (let i = 0; i < 20; i += 1) {
      const useTenantA = i % 2 === 0;
      const tenantId = useTenantA ? world.tenantA.id : world.tenantB.id;
      const principalId = useTenantA ? world.alice.id : world.bob.id;
      const foreignTenant = useTenantA ? world.tenantB.id : world.tenantA.id;
      const expectedTitle = useTenantA ? 'Alpha private doc' : 'Beta private doc';
      const requestId = randomUUID();

      const result = await withSecurityContext(
        api,
        { principalId, tenantId, requestId },
        async (c, ctx) => {
          const docs = await c.query<{ tenant_id: string; title: string }>(
            'SELECT tenant_id, title FROM securerag.documents ORDER BY title',
          );
          expect(docs.rows).toHaveLength(1);
          expect(docs.rows[0]?.tenant_id).toBe(tenantId);
          expect(docs.rows[0]?.title).toBe(expectedTitle);
          expect(ctx.tenantId).toBe(tenantId);
          expect(ctx.principalId).toBe(principalId);
          expect(ctx.requestId).toBe(requestId);

          const foreign = await c.query<{ n: number }>(
            'SELECT count(*)::int AS n FROM securerag.documents WHERE tenant_id = $1',
            [foreignTenant],
          );
          expect(foreign.rows[0]?.n).toBe(0);
          return i;
        },
      );
      expect(result).toBe(i);
      await expectNoResidualContext(api);
    }
  });

  it('a throwing callback rolls back DML and leaves no residual context; savepoints keep the context usable', async () => {
    await expect(
      withSecurityContext(
        api,
        { principalId: world.alice.id, tenantId: world.tenantA.id, requestId: randomUUID() },
        async (c) => {
          await c.query(
            `INSERT INTO securerag.documents (tenant_id, title) VALUES ($1, 'must vanish')`,
            [world.tenantA.id],
          );
          throw new Error('boom');
        },
      ),
    ).rejects.toThrow(/boom/);

    const afterRollback = await withSecurityContext(
      api,
      { principalId: world.alice.id, tenantId: world.tenantA.id, requestId: randomUUID() },
      async (c) => {
        const count = await c.query<{ n: number }>(
          'SELECT count(*)::int AS n FROM securerag.documents',
        );
        expect(count.rows[0]?.n).toBe(1);
        return count.rows[0]?.n;
      },
    );
    expect(afterRollback).toBe(1);
    await expectNoResidualContext(api);

    const savepointed = await withSecurityContext(
      api,
      { principalId: world.alice.id, tenantId: world.tenantA.id, requestId: randomUUID() },
      async (c, ctx) => {
        await c.query('SAVEPOINT sp');
        await c.query(
          `INSERT INTO securerag.documents (tenant_id, title) VALUES ($1, 'rolled back to savepoint')`,
          [world.tenantA.id],
        );
        await c.query('ROLLBACK TO SAVEPOINT sp');
        const count = await c.query<{ n: number }>(
          'SELECT count(*)::int AS n FROM securerag.documents',
        );
        expect(count.rows[0]?.n).toBe(1);
        const read = await readContext(c);
        expect(read.tenantId).toBe(ctx.tenantId);
        expect(read.requestId).toBe(ctx.requestId);
        return 'savepoint-ok';
      },
    );
    expect(savepointed).toBe('savepoint-ok');
    await expectNoResidualContext(api);
  });

  it('an early-return callback commits cleanly and the GUCs vanish', async () => {
    const result = await withSecurityContext(
      api,
      { principalId: world.alice.id, tenantId: world.tenantA.id, requestId: randomUUID() },
      async () => 'early-return',
    );
    expect(result).toBe('early-return');
    await expectNoResidualContext(api);
  });

  it('verifyContext throws a typed error for missing or malformed GUCs', async () => {
    const client = await api.connect();
    try {
      await client.query('BEGIN');
      const empty = await readContext(client);
      expect(empty).toEqual({
        tenantId: null,
        principalId: null,
        membershipId: null,
        requestId: null,
        authEpoch: null,
      });
      await expect(verifyContext(client)).rejects.toBeInstanceOf(SecurityContextError);

      await client.query('SELECT set_config($1, $2, true)', [
        'securerag.principal_id',
        world.alice.id,
      ]);
      await client.query('SELECT set_config($1, $2, true)', [
        'securerag.tenant_id',
        'not-a-uuid',
      ]);
      const err = await verifyContext(client).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SecurityContextError);
      expect((err as SecurityContextError).code).toBe(ERROR_CODES.securityContext);
      expect((err as Error).message).toContain('securerag.membership_id');
      expect((err as Error).message).toContain('securerag.request_id');
      expect((err as Error).message).toContain('securerag.auth_epoch');
      expect((err as Error).message).toContain('securerag.tenant_id');
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  });

  it('createRuntimePool connects as the least-privilege role with a pinned application_name', async () => {
    const pool = createRuntimePool('securerag_api', {
      host: db.host,
      port: db.port,
      database: 'securerag',
      password: TEST_PASSWORDS.securerag_api,
      max: 2,
    });
    try {
      const client = await pool.connect();
      try {
        const { rows } = await client.query<{ current_user: string; application_name: string }>(
          `SELECT current_user,
                  current_setting('application_name') AS application_name`,
        );
        expect(rows[0]).toMatchObject({
          current_user: 'securerag_api',
          application_name: 'securerag-securerag_api',
        });
      } finally {
        client.release();
      }
      const seen = await withSecurityContext(
        pool,
        { principalId: world.alice.id, tenantId: world.tenantA.id, requestId: randomUUID() },
        async (c, ctx) => {
          expect(ctx.tenantId).toBe(world.tenantA.id);
          const count = await c.query<{ n: number }>(
            'SELECT count(*)::int AS n FROM securerag.documents',
          );
          return count.rows[0]?.n;
        },
      );
      expect(seen).toBe(1);
    } finally {
      await pool.end();
    }
  });
});
