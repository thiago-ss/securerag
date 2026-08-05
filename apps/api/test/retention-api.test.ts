import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import { buildApp } from '../src/app.js';
import { loginViaOidc } from '../src/testkit.js';

describe('S9 retention policy over HTTP with OIDC sessions', () => {
  let db: TestDb;
  let world: Awaited<ReturnType<typeof seedFixtures>>;
  let records: SpyRecord[];
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    records = [];
    provider = new FakeOidcProvider({ issuer: 'test-issuer', clientId: 'securerag-api' });
    await provider.start();
    app = await buildApp({
      pool: db.apiPool,
      providers: new SpyGenerator(records),
      facts: () => ({ tenants: [], principals: [], memberships: [], groups: [], groupMemberships: [], documents: [], versions: [], chunks: [], grants: [] }),
      oidc: {
        issuer: 'test-issuer',
        clientId: 'securerag-api',
        redirectUri: 'http://securerag.test/auth/callback',
        postLogoutRedirectUri: 'http://securerag.test/',
        discoveryUrl: provider.discoveryUrl,
        sessionCookieName: 'securerag_session',
        sessionCookieSecure: false,
        sessionTtlSeconds: 3600,
        postLoginRedirectPath: '/',
      },
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await app.close();
    await provider.stop();
    await db.stop();
  });

  it('GET returns the tenant policy for members; PUT is admin-only and audited', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const get = await fetch(`${base}/retention-policy?tenantId=${world.tenantA.id}`, {
      headers: { cookie: alice.cookieHeader },
    });
    expect(get.status).toBe(200);
    const policy = (await get.json()) as { sourceDays: number; legalHold: boolean };
    expect(policy.sourceDays).toBe(3650);

    const before = Number(
      (await db.superuserPool.query<{ epoch: string }>('SELECT epoch FROM securerag.authorization_epoch')).rows[0]?.epoch,
    );
    const putAsMember = await fetch(`${base}/retention-policy`, {
      method: 'PUT',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, legalHold: true }),
    });
    expect(putAsMember.status).toBe(404);

    const carol = await loginViaOidc(base, provider, 'carol-sub');
    const putAsAdmin = await fetch(`${base}/retention-policy`, {
      method: 'PUT',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, auditDays: 30 }),
    });
    expect(putAsAdmin.status).toBe(200);
    const after = Number(
      (await db.superuserPool.query<{ epoch: string }>('SELECT epoch FROM securerag.authorization_epoch')).rows[0]?.epoch,
    );
    expect(after).toBeGreaterThan(before);
    const { rows } = await db.superuserPool.query<{ event_type: string }>(
      `SELECT event_type FROM securerag.audit_events WHERE event_type = 'retention:changed'`,
    );
    expect(rows.length).toBeGreaterThan(0);
  });

  it('foreign/nonexistent tenants are indistinguishable', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const foreign = await fetch(`${base}/retention-policy?tenantId=${world.tenantB.id}`, {
      headers: { cookie: alice.cookieHeader },
    });
    const random = await fetch(`${base}/retention-policy?tenantId=${randomUUID()}`, {
      headers: { cookie: alice.cookieHeader },
    });
    expect(foreign.status).toBe(404);
    expect(random.status).toBe(404);
    expect(await foreign.text()).toBe(await random.text());
  });
});
