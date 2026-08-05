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
  seedFixtures,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { buildApp, type OidcApiConfig } from '../src/app.js';
import { loginViaOidc } from './auth-helpers.js';

const RATE_LIMITED_BODY = JSON.stringify({ code: 'RATE_LIMITED', message: 'Too many requests' });

/**
 * S10 rate limits (ADR-0011): per principal+IP on /retrieval/query and per IP
 * on the auth endpoints, with a typed 429 problem+json. Tiny limits are
 * injected through the ApiDeps seam so the exhaustion path is cheap.
 */
describe('S10 rate limits — typed 429 on retrieval and auth endpoints', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
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
      rateLimit: { retrievalMax: 3, retrievalWindowMs: 10_000, authMax: 3, authWindowMs: 10_000 },
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await db.stop();
  });

  async function query(session: { cookieHeader: string; csrfToken: string }): Promise<Response> {
    return fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, question: 'secret formula' }),
    });
  }

  it('1. retrieval/query: the 4th request inside the window returns the typed 429; the key binds principal+IP (two principals share no bucket)', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    for (let i = 0; i < 3; i += 1) {
      const res = await query(alice);
      expect(res.status).toBe(200);
    }
    const limited = await query(alice);
    expect(limited.status).toBe(429);
    expect(await limited.text()).toBe(RATE_LIMITED_BODY);
    expect(limited.headers.get('x-ratelimit-remaining')).toBe('0');

    // A DIFFERENT principal from the same IP has its own bucket: 200 again.
    const carol = await loginViaOidc(base, provider, 'carol-sub');
    const other = await query(carol);
    expect(other.status).toBe(200);
  });

  it('2. auth endpoints: /auth/login is rate-limited per IP (typed 429)', async () => {
    for (let i = 0; i < 3; i += 1) {
      const res = await fetch(`${base}/auth/login`, { redirect: 'manual' });
      expect(res.status).toBe(302);
    }
    const limited = await fetch(`${base}/auth/login`, { redirect: 'manual' });
    expect(limited.status).toBe(429);
    expect(await limited.text()).toBe(RATE_LIMITED_BODY);
  });

  it('3. unrelated routes are not rate-limited (healthz unaffected)', async () => {
    for (let i = 0; i < 10; i += 1) {
      const res = await fetch(`${base}/healthz`);
      expect(res.status).toBe(200);
    }
  });
});
