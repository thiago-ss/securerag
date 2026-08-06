import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { withSecurityContext } from '@securerag/security';
import { appendAudit, InMemorySourceObjectStore, type AuditEvent } from '@securerag/core';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import { buildApp } from '../src/app.js';
import { loginViaOidc, type AuthenticatedSession } from '../src/testkit.js';

const NOT_FOUND_BODY = JSON.stringify({
  code: 'NOT_FOUND',
  message: 'Resource not found',
});

interface ExportEnvelope {
  format: string;
  tenantId: string;
  chainAnchorEventId: string | null;
  chainAnchorHash: string | null;
  eventCount: number;
  generatedAt: string;
  exporter: string;
  exportSha256: string;
  body: string;
}

describe('S8 audit export + filtered retrieval over HTTP with OIDC sessions', () => {
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
      store: new InMemorySourceObjectStore(),
      facts: () => ({ tenants: [], principals: [], memberships: [], groups: [], groupMemberships: [], documents: [], versions: [], chunks: [], grants: [], jobs: [] }),
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

  /** Seed audit events through the real runtime role (verified context). */
  async function seedEvent(
    overrides: Partial<AuditEvent>,
    principalId: string = world.alice.id,
    tenantId: string = world.tenantA.id,
  ): Promise<void> {
    await withSecurityContext(
      db.apiPool,
      { tenantId, principalId, requestId: randomUUID() },
      async (client, ctx) => {
        await appendAudit({
          client,
          event: {
            eventType: 'retrieval:allowed',
            requestId: ctx.requestId,
            principalId: ctx.principalId,
            membershipId: ctx.membershipId,
            authEpoch: ctx.authEpoch,
            redactedQuery: '[REDACTED] http query',
            queryHash: Buffer.from('abcd', 'hex'),
            ...overrides,
          },
        });
      },
    );
  }

  const getExport = (session: AuthenticatedSession, tenantId: string): Promise<Response> =>
    fetch(`${base}/audit/export?tenantId=${tenantId}`, { headers: { cookie: session.cookieHeader } });

  it('a tenant admin can export; the envelope verifies (body hash + chain anchor) and the export is audited', async () => {
    await seedEvent({ eventType: 'retrieval:allowed' });
    await seedEvent({ eventType: 'retrieval:refused', refusalReason: 'INSUFFICIENT_EVIDENCE' });
    const carol = await loginViaOidc(base, provider, 'carol-sub');

    const res = await getExport(carol, world.tenantA.id);
    expect(res.status).toBe(200);
    const doc = (await res.json()) as ExportEnvelope;
    expect(doc.format).toBe('securerag-audit-export/1');
    expect(doc.tenantId).toBe(world.tenantA.id);
    expect(doc.exporter).toMatch(/^[0-9a-f-]{36}$/);
    expect(doc.eventCount).toBe(2);
    expect(doc.chainAnchorHash).toMatch(/^[0-9a-f]{64}$/);
    expect(doc.exportSha256).toMatch(/^[0-9a-f]{64}$/);

    // Consumer verification (docs/ops/audit-export.md): body hash recomputes,
    // lines are ascending, chain links against the anchor.
    const { createHash } = await import('node:crypto');
    expect(createHash('sha256').update(doc.body).digest('hex')).toBe(doc.exportSha256);
    const lines = doc.body.split('\n').map((l) => JSON.parse(l)) as Record<string, unknown>[];
    expect(lines.map((l) => BigInt(l.eventId as string))).toEqual(
      [...lines].map((l) => BigInt(l.eventId as string)).sort((a, b) => (a < b ? -1 : 1)),
    );
    expect((lines.at(-1)!.eventHash as string).length).toBe(64);

    const { rows } = await db.superuserPool.query<{ event_hash: Buffer | null }>(
      `SELECT event_hash FROM securerag.audit_events WHERE tenant_id = $1 AND event_type = 'audit:exported'`,
      [world.tenantA.id],
    );
    expect(rows.length).toBe(1);
    expect(rows[0]!.event_hash).not.toBeNull();
  });

  it('member, foreign-tenant principal, and nonexistent tenant are byte-identical 404s', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const bob = await loginViaOidc(base, provider, 'bob-sub');

    const asMember = await getExport(alice, world.tenantA.id);
    const asForeign = await getExport(bob, world.tenantA.id); // bob belongs to tenant B only
    const asNonexistent = await getExport(alice, randomUUID());

    expect(asMember.status).toBe(404);
    expect(asForeign.status).toBe(404);
    expect(asNonexistent.status).toBe(404);
    expect(await asMember.text()).toBe(NOT_FOUND_BODY);
    expect(await asForeign.text()).toBe(NOT_FOUND_BODY);
    expect(await asNonexistent.text()).toBe(NOT_FOUND_BODY);
  });

  it('an active security_reviewer member can export their tenant', async () => {
    await db.superuserPool.query(
      `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role)
       VALUES ($1, $2, 'security_reviewer')`,
      [world.tenantA.id, world.dave.id],
    );
    const dave = await loginViaOidc(base, provider, 'dave-sub');
    const res = await getExport(dave, world.tenantA.id);
    expect(res.status).toBe(200);
    const doc = (await res.json()) as ExportEnvelope;
    expect(doc.eventCount).toBeGreaterThan(0);
  });

  it('unauthenticated export requests are 401', async () => {
    const res = await fetch(`${base}/audit/export?tenantId=${world.tenantA.id}`);
    expect(res.status).toBe(401);
  });

  it('GET /audit/retrieval filters: eventType, principalId, from/to all narrow in SQL (tenant-isolated)', async () => {
    await seedEvent({ eventType: 'retrieval:allowed' });
    await seedEvent({ eventType: 'retrieval:refused', refusalReason: 'INSUFFICIENT_EVIDENCE' });
    await seedEvent({ eventType: 'document:read' });
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const get = (qs: string): Promise<Response> =>
      fetch(`${base}/audit/retrieval?${qs}`, { headers: { cookie: alice.cookieHeader } });

    const all = await get('limit=100');
    expect(all.status).toBe(200);
    const allBody = (await all.json()) as { events: { eventId: string; prevEventHash: string | null; eventHash: string | null }[] };
    // Chain hashes are exposed on the view; every seeded event is chained.
    expect(allBody.events.length).toBeGreaterThan(3);
    for (const e of allBody.events) {
      expect(e.eventHash).toMatch(/^[0-9a-f]{64}$/);
    }

    const refused = await get('limit=100&eventType=retrieval%3Arefused');
    const refusedBody = (await refused.json()) as { events: { eventType: string }[] };
    expect(refusedBody.events.length).toBeGreaterThan(0);
    expect(refusedBody.events.every((e) => e.eventType === 'retrieval:refused')).toBe(true);

    const byPrincipal = await get(`limit=100&principalId=${world.carol.id}`);
    const byPrincipalBody = (await byPrincipal.json()) as { events: { principalId: string }[] };
    expect(byPrincipalBody.events.length).toBeGreaterThan(0);
    expect(byPrincipalBody.events.every((e) => e.principalId === world.carol.id)).toBe(true);

    const future = await get('limit=100&from=2099-01-01T00%3A00%3A00.000Z');
    expect(((await future.json()) as { events: unknown[] }).events).toHaveLength(0);
    const past = await get('limit=100&to=2020-01-01T00%3A00%3A00.000Z');
    expect(((await past.json()) as { events: unknown[] }).events).toHaveLength(0);
    const wide = await get('limit=100&from=2020-01-01T00%3A00%3A00.000Z&to=2099-01-01T00%3A00%3A00.000Z');
    expect(((await wide.json()) as { events: unknown[] }).events.length).toBeGreaterThan(0);
  });

  it('GET /audit/retrieval paginates with a keyset cursor (disjoint, descending)', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const get = (qs: string): Promise<Response> =>
      fetch(`${base}/audit/retrieval?${qs}`, { headers: { cookie: alice.cookieHeader } });

    const first = await get('limit=2');
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as {
      events: { eventId: string }[];
      nextCursor: string | null;
    };
    expect(firstBody.events).toHaveLength(2);
    expect(firstBody.nextCursor).not.toBeNull();
    expect(BigInt(firstBody.events[0]!.eventId)).toBeGreaterThan(BigInt(firstBody.events[1]!.eventId));

    const second = await get(`limit=2&cursor=${firstBody.nextCursor}`);
    const secondBody = (await second.json()) as {
      events: { eventId: string }[];
      nextCursor: string | null;
    };
    expect(secondBody.events.length).toBeGreaterThan(0);
    const ids = new Set([...firstBody.events, ...secondBody.events].map((e) => e.eventId));
    expect(ids.size).toBe(firstBody.events.length + secondBody.events.length);

    const last = await get(`limit=100&cursor=${secondBody.nextCursor}`);
    const lastBody = (await last.json()) as { events: unknown[]; nextCursor: string | null };
    expect(lastBody.nextCursor).toBeNull();
  });

  it('malformed export query (bad uuid) is a uniform 400', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const res = await fetch(`${base}/audit/export?tenantId=not-a-uuid`, {
      headers: { cookie: alice.cookieHeader },
    });
    expect(res.status).toBe(400);
  });
});
