import type { AddressInfo } from 'node:net';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { InMemorySourceObjectStore } from '@securerag/core';
import {
  getTestDb,
  resetData,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { buildT3Corpus, type T3Corpus } from '@securerag/eval/src/fixtures.js';
import { buildApp, type OidcApiConfig } from '../src/app.js';
import { loginViaOidc } from './auth-helpers.js';

const NOT_FOUND_BODY = JSON.stringify({ code: 'NOT_FOUND', message: 'Resource not found' });

interface Session {
  cookieHeader: string;
  csrfToken: string;
}

/**
 * S10 console support: GET/POST /documents over real HTTP. The library is
 * default-deny (rows only for granted/managed documents; capability flags
 * from the enforcement predicates); create is member-scoped, grants the
 * creator 'manage' (audited + epoch-bumped) so the manage-gated upload flow
 * can proceed; foreign/nonexistent tenants and non-members are the same 404.
 */
describe('S10 document library API — list + create over HTTP', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let corpus: T3Corpus;
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    corpus = await buildT3Corpus(db.superuserPool);
    world = corpus.world;
    api = db.apiPool;
    provider = new FakeOidcProvider({ issuer: 'test-issuer', clientId: 'securerag-api' });
    await provider.start();
    const oidc: OidcApiConfig = {
      issuer: 'test-issuer',
      clientId: 'securerag-api',
      redirectUri: 'http://securerag.test/auth/callback',
      postLogoutRedirectUri: 'http://securerag.test/',
      discoveryUrl: provider.discoveryUrl,
      sessionCookieName: 'securerag_session',
      sessionCookieSecure: false,
      sessionTtlSeconds: 3600,
    };
    app = await buildApp({
      pool: api,
      providers: new SpyGenerator(),
      store: new InMemorySourceObjectStore(),
      oidc,
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await db.stop();
  });

  const epoch = async (): Promise<number> => {
    const { rows } = await db.superuserPool.query<{ epoch: string }>(
      'SELECT epoch FROM securerag.authorization_epoch',
    );
    return Number(rows[0]?.epoch);
  };

  async function login(subject: string): Promise<Session> {
    return loginViaOidc(base, provider, subject);
  }

  it('1. alice lists exactly her granted documents with honest capability flags (member: read-only)', async () => {
    const session = await login('alice-sub');
    const res = await fetch(`${base}/documents?tenantId=${world.tenantA.id}`, {
      headers: { cookie: session.cookieHeader },
    });
    expect(res.status).toBe(200);
    const { documents } = (await res.json()) as {
      documents: { documentId: string; title: string; canRead: boolean; canWrite: boolean; canManage: boolean }[];
    };
    expect(documents.map((d) => d.title).sort()).toEqual(
      ['Alpha private doc', 'Alpha widget doc'].sort(),
    );
    const privateDoc = documents.find((d) => d.title === 'Alpha private doc');
    const widgetDoc = documents.find((d) => d.title === 'Alpha widget doc');
    expect(privateDoc).toMatchObject({ canRead: true, canWrite: false, canManage: false });
    // tenant_role 'member' grant on docA2: read only too.
    expect(widgetDoc).toMatchObject({ canRead: true, canWrite: false, canManage: false });
  });

  it('2. carol (tenant admin, no grants) lists the documents she manages — as manage-only rows', async () => {
    const session = await login('carol-sub');
    const res = await fetch(`${base}/documents?tenantId=${world.tenantA.id}`, {
      headers: { cookie: session.cookieHeader },
    });
    expect(res.status).toBe(200);
    const { documents } = (await res.json()) as {
      documents: { documentId: string; canRead: boolean; canWrite: boolean; canManage: boolean }[];
    };
    // Admin holds NO implicit content read (default deny): rows visible via
    // the manage gate only, with canRead=false.
    expect(documents.length).toBeGreaterThan(0);
    for (const d of documents) {
      expect(d.canRead).toBe(false);
      expect(d.canManage).toBe(true);
    }
  });

  it('3. dave (no membership) and a foreign tenant are indistinguishable 404s', async () => {
    const session = await login('dave-sub');
    const daveRes = await fetch(`${base}/documents?tenantId=${world.tenantA.id}`, {
      headers: { cookie: session.cookieHeader },
    });
    expect(daveRes.status).toBe(404);
    expect(await daveRes.text()).toBe(NOT_FOUND_BODY);

    const alice = await login('alice-sub');
    const foreign = await fetch(`${base}/documents?tenantId=${world.tenantB.id}`, {
      headers: { cookie: alice.cookieHeader },
    });
    expect(foreign.status).toBe(404);
    expect(await foreign.text()).toBe(NOT_FOUND_BODY);
  });

  it('4. an active member creates a document: creator manage grant + audited + epoch bump; then it lists for the creator', async () => {
    const session = await login('alice-sub');
    const before = await epoch();
    const create = await fetch(`${base}/documents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, title: 'Alice new doc' }),
    });
    expect(create.status).toBe(201);
    const { document } = (await create.json()) as { document: { documentId: string; title: string; status: string } };
    expect(document).toMatchObject({ title: 'Alice new doc', status: 'active' });
    expect(await epoch()).toBe(before + 1);

    const list = await fetch(`${base}/documents?tenantId=${world.tenantA.id}`, {
      headers: { cookie: session.cookieHeader },
    });
    const { documents } = (await list.json()) as {
      documents: { documentId: string; canRead: boolean; canManage: boolean }[];
    };
    const created = documents.find((d) => d.documentId === document.documentId);
    expect(created).toMatchObject({ canRead: true, canManage: true });

    // The manage grant is real: the creator can now manage the grants list.
    const grants = await fetch(`${base}/documents/${document.documentId}/grants`, {
      headers: { cookie: session.cookieHeader },
    });
    expect(grants.status).toBe(200);
    const { grants: entries } = (await grants.json()) as {
      grants: { subjectType: string; subjectId: string; capability: string }[];
    };
    expect(entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          subjectType: 'principal',
          subjectId: corpus.world.alice.id,
          capability: 'manage',
        }),
      ]),
    );

    const audit = await fetch(`${base}/audit/retrieval?limit=100`, {
      headers: { cookie: session.cookieHeader },
    });
    const { events } = (await audit.json()) as { events: { eventType: string; filters: unknown }[] };
    const createdEvents = events.filter(
      (e) =>
        (e.eventType === 'document:created' || e.eventType === 'grant:changed') &&
        JSON.stringify(e.filters).includes(document.documentId),
    );
    expect(createdEvents.map((e) => e.eventType).sort()).toEqual(['document:created', 'grant:changed']);
  });

  it('5. non-member and foreign-tenant creates are indistinguishable 404s', async () => {
    const session = await login('dave-sub');
    const nonMember = await fetch(`${base}/documents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, title: 'Sneaky' }),
    });
    expect(nonMember.status).toBe(404);
    expect(await nonMember.text()).toBe(NOT_FOUND_BODY);

    const alice = await login('alice-sub');
    const foreign = await fetch(`${base}/documents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantB.id, title: 'Sneaky' }),
    });
    expect(foreign.status).toBe(404);
    expect(await foreign.text()).toBe(NOT_FOUND_BODY);

    // boundary: empty title is a plain 400
    const bad = await fetch(`${base}/documents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, title: '' }),
    });
    expect(bad.status).toBe(400);
  });

  it('6. the upload flow is reachable on a freshly created document (manage gate) and still gated for others', async () => {
    const alice = await login('alice-sub');
    const carol = await login('carol-sub');
    const create = await fetch(`${base}/documents`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, title: 'Upload target' }),
    });
    const { document } = (await create.json()) as { document: { documentId: string } };

    const form = new FormData();
    form.append('file', new Blob(['upload-me'], { type: 'text/plain' }), 'doc.txt');
    const uploaded = await fetch(`${base}/documents/${document.documentId}/versions/upload`, {
      method: 'POST',
      headers: { cookie: alice.cookieHeader, 'x-csrf-token': alice.csrfToken },
      body: form,
    });
    expect(uploaded.status).toBe(201);

    // carol manages via the admin branch but is not the creator: the manage
    // gate passes for admins too (same gate the console shows).
    const form2 = new FormData();
    form2.append('file', new Blob(['carol-upload'], { type: 'text/plain' }), 'doc2.txt');
    const carolUpload = await fetch(`${base}/documents/${document.documentId}/versions/upload`, {
      method: 'POST',
      headers: { cookie: carol.cookieHeader, 'x-csrf-token': carol.csrfToken },
      body: form2,
    });
    expect(carolUpload.status).toBe(201);
  });
});
