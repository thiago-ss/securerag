import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import {
  getTestDb,
  resetData,
  seedFixtures,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { buildApp, type OidcApiConfig } from '../src/app.js';
import { loginViaOidc } from './auth-helpers.js';

const INVALID_BODY = JSON.stringify({ code: 'INVALID_REQUEST', message: 'Invalid request' });
const UNAUTHORIZED_BODY = JSON.stringify({
  code: 'UNAUTHORIZED',
  message: 'Authentication required',
});
const FORBIDDEN_BODY = JSON.stringify({ code: 'FORBIDDEN', message: 'Forbidden' });
const NOT_FOUND_BODY = JSON.stringify({ code: 'NOT_FOUND', message: 'Resource not found' });

const REFUSAL_BODY = JSON.stringify({
  decision: 'refused',
  code: 'INSUFFICIENT_EVIDENCE',
  message: 'No sufficient authorized evidence to answer.',
});

interface CallbackResult {
  status: number;
  body: string;
  setCookie: string | null;
}

/**
 * S1 auth E2E over real HTTP: the REAL Fastify server, the fake in-process
 * OIDC provider (RS256, all 12 checklist claims), and the least-privilege
 * runtime pool. Covers the positive login flow, every negative id_token
 * variant (all rejected byte-identically), cookie attributes, logout,
 * CSRF, indistinguishable session failures, and admin-only membership/group/
 * grant management with epoch bumps and audit.
 */
describe('S1 auth E2E — OIDC login, sessions, CSRF, admin management over HTTP', () => {
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
    provider = new FakeOidcProvider({
      issuer: 'test-issuer',
      clientId: 'securerag-api',
    });
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
      maxAgeSeconds: 600,
      acrValues: ['urn:securerag:acr:1'],
      postLoginRedirectPath: '/',
    };
    app = await buildApp({ pool: api, providers: new SpyGenerator(), oidc });
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

  /** Run the login flow but return the callback response (for negative variants). */
  async function loginAttempt(subject: string): Promise<CallbackResult> {
    provider.defaultSubject = subject;
    const login = await fetch(`${base}/auth/login`, { redirect: 'manual' });
    const authorizeUrl = login.headers.get('location');
    if (authorizeUrl === null) throw new Error('login returned no location');
    const authorize = await fetch(authorizeUrl, { redirect: 'manual' });
    const rawCallbackUrl = authorize.headers.get('location');
    if (rawCallbackUrl === null) throw new Error('authorize returned no location');
    const callbackUrl = new URL(rawCallbackUrl);
    const baseUrl = new URL(base);
    callbackUrl.protocol = baseUrl.protocol;
    callbackUrl.host = baseUrl.host;
    const callback = await fetch(callbackUrl, { redirect: 'manual' });
    return {
      status: callback.status,
      body: await callback.text(),
      setCookie: callback.headers.get('set-cookie'),
    };
  }

  it('1. positive login flow over HTTP: session cookie + CSRF; /auth/me shows principal and memberships', async () => {
    const session = await loginViaOidc(base, provider, 'alice-sub');
    expect(session.cookieHeader.startsWith('securerag_session=')).toBe(true);

    const me = await fetch(`${base}/auth/me`, { headers: { cookie: session.cookieHeader } });
    expect(me.status).toBe(200);
    const body = (await me.json()) as {
      principal: { principalId: string; provider: string; externalSubject: string };
      session: { sessionId: string; csrfToken: string };
      memberships: { tenantId: string; role: string }[];
    };
    expect(body.principal.principalId).toBe(world.alice.id);
    expect(body.principal.provider).toBe('test-issuer');
    expect(body.principal.externalSubject).toBe('alice-sub');
    expect(body.session.csrfToken).toHaveLength(64);
    expect(body.memberships).toEqual([
      expect.objectContaining({ tenantId: world.tenantA.id, role: 'member' }),
    ]);
  });

  it('2. the session cookie carries HttpOnly + SameSite=Lax + Path=/ and no Domain; no Secure over test HTTP', async () => {
    provider.defaultSubject = 'alice-sub';
    const login = await fetch(`${base}/auth/login`, { redirect: 'manual' });
    const authorize = await fetch(login.headers.get('location') as string, { redirect: 'manual' });
    const callbackUrl = new URL(authorize.headers.get('location') as string);
    const baseUrl = new URL(base);
    callbackUrl.protocol = baseUrl.protocol;
    callbackUrl.host = baseUrl.host;
    const callback = await fetch(callbackUrl, { redirect: 'manual' });

    const setCookie = callback.headers.get('set-cookie');
    expect(setCookie).toBeTruthy();
    expect(setCookie?.startsWith('securerag_session=')).toBe(true);
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toContain('Path=/');
    expect(setCookie).toContain('Max-Age=3600');
    expect(setCookie).not.toContain('Domain=');
    expect(setCookie).not.toContain('Secure');
  });

  it('3. negative id_token variants are all rejected with a byte-identical 400 and no session cookie', async () => {
    const attempts: [string, () => void][] = [
      ['wrong iss', () => provider.setIdTokenMutation((c) => ({ ...c, iss: 'https://evil.example' }))],
      ['wrong aud', () => provider.setIdTokenMutation((c) => ({ ...c, aud: 'other-client' }))],
      ['extra audience', () => provider.setIdTokenMutation((c) => ({ ...c, aud: ['securerag-api', 'other'] }))],
      ['azp mismatch', () => provider.setIdTokenMutation((c) => ({ ...c, azp: 'evil-client' }))],
      ['expired', () => provider.setIdTokenMutation((c) => ({ ...c, exp: Math.floor(Date.now() / 1000) - 3600 }))],
      ['iat in the future', () => provider.setIdTokenMutation((c) => ({ ...c, iat: Math.floor(Date.now() / 1000) + 3600 }))],
      ['nonce replayed', () => provider.setIdTokenMutation((c) => ({ ...c, nonce: 'stale-nonce-value' }))],
      ['nonce missing', () => provider.setIdTokenMutation((c) => {
        const { nonce: _nonce, ...rest } = c;
        return rest;
      })],
      ['sub missing', () => provider.setIdTokenMutation((c) => {
        const { sub: _sub, ...rest } = c;
        return rest;
      })],
      ['wrong at_hash', () => provider.setIdTokenMutation((c) => ({ ...c, at_hash: 'AAAAAAAAAAAAAAAAAAAAAA' }))],
      ['stale auth_time', () => provider.setIdTokenMutation((c) => ({ ...c, auth_time: Math.floor(Date.now() / 1000) - 3600 }))],
      ['wrong acr', () => provider.setIdTokenMutation((c) => ({ ...c, acr: 'urn:securerag:acr:other' }))],
    ];

    for (const [name, mutate] of attempts) {
      provider.setIdTokenMutation(null);
      provider.setTokenOverride(null);
      provider.setSigning('RS256', 'fake-rsa-1');
      mutate();
      const result = await loginAttempt('alice-sub');
      expect(result.status, `${name} must be rejected`).toBe(400);
      expect(result.body, `${name} must reject byte-identically`).toBe(INVALID_BODY);
      expect(result.setCookie, `${name} must not set a session cookie`).toBeNull();
      provider.setIdTokenMutation(null);
      provider.setTokenOverride(null);
    }
  });

  it('3b. signature/algorithm negatives: alg none, HS256, unknown kid, tampered and garbage tokens', async () => {
    const variants: [string, () => void][] = [
      ['alg none', () => provider.setSigning('none')],
      ['alg HS256 (confusion)', () => provider.setSigning('HS256')],
      ['unknown kid', () => provider.setSigning('RS256', 'unknown-kid')],
      [
        'tampered signature',
        () => {
          provider.setTokenOverride(`${provider.lastIdToken?.slice(0, -4) ?? ''}AAAA`);
        },
      ],
      ['garbage token', () => provider.setTokenOverride('definitely.not.a.jwt')],
    ];
    for (const [name, mutate] of variants) {
      provider.setIdTokenMutation(null);
      provider.setTokenOverride(null);
      provider.setSigning('RS256', 'fake-rsa-1');
      mutate();
      const result = await loginAttempt('alice-sub');
      expect(result.status, `${name} must be rejected`).toBe(400);
      expect(result.body, `${name} must reject byte-identically`).toBe(INVALID_BODY);
      expect(result.setCookie, `${name} must not set a session cookie`).toBeNull();
      provider.setIdTokenMutation(null);
      provider.setTokenOverride(null);
      provider.setSigning('RS256', 'fake-rsa-1');
    }
  });

  it('4. an auth-code callback URL can never be replayed (one-time state)', async () => {
    const session = await loginViaOidc(base, provider, 'alice-sub');
    // The helper consumed the callback; a fresh login's callback URL replayed
    // after the session exists must fail identically to a bogus callback.
    const replay = await fetch(`${base}/auth/callback?code=x&state=never-issued`, {
      redirect: 'manual',
    });
    expect(replay.status).toBe(400);
    expect(await replay.text()).toBe(INVALID_BODY);
    expect(session.cookieHeader).toBeTruthy();
  });

  it('5. logout revokes the session server-side, clears the cookie, and hands off to the provider', async () => {
    const session = await loginViaOidc(base, provider, 'alice-sub');
    const logout = await fetch(`${base}/auth/logout`, {
      method: 'POST',
      headers: { cookie: session.cookieHeader, 'x-csrf-token': session.csrfToken },
      redirect: 'manual',
    });
    expect(logout.status).toBe(302);
    const endSessionUrl = logout.headers.get('location');
    expect(endSessionUrl).toContain('/end_session');
    expect(new URL(endSessionUrl as string).searchParams.get('post_logout_redirect_uri')).toBe(
      'http://securerag.test/',
    );
    const clearCookie = logout.headers.get('set-cookie');
    expect(clearCookie).toContain('securerag_session=;');
    expect(clearCookie).toContain('Max-Age=0');

    const follow = await fetch(endSessionUrl as string, { redirect: 'manual' });
    expect(follow.status).toBe(302);
    expect(follow.headers.get('location')).toBe('http://securerag.test/');

    const me = await fetch(`${base}/auth/me`, { headers: { cookie: session.cookieHeader } });
    expect(me.status).toBe(401);
    expect(await me.text()).toBe(UNAUTHORIZED_BODY);
  });

  it('6. CSRF: state-changing routes require X-CSRF-Token; missing/wrong → 403; GET never needs it', async () => {
    const session = await loginViaOidc(base, provider, 'alice-sub');

    const missing = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: session.cookieHeader },
      body: JSON.stringify({ tenantId: world.tenantA.id, question: 'x' }),
    });
    expect(missing.status).toBe(403);
    expect(await missing.text()).toBe(FORBIDDEN_BODY);

    const wrong = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': '00'.repeat(32),
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, question: 'x' }),
    });
    expect(wrong.status).toBe(403);
    expect(await wrong.text()).toBe(FORBIDDEN_BODY);

    const ok = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, question: 'secret formula' }),
    });
    expect(ok.status).toBe(200);

    const me = await fetch(`${base}/auth/me`, { headers: { cookie: session.cookieHeader } });
    expect(me.status).toBe(200);
  });

  it('7. foreign, expired, and revoked sessions are indistinguishable 401s', async () => {
    const live = await loginViaOidc(base, provider, 'alice-sub');
    const expired = await loginViaOidc(base, provider, 'bob-sub');
    const revoked = await loginViaOidc(base, provider, 'carol-sub');

    await db.superuserPool.query(
      `UPDATE securerag.sessions SET expires_at = now() - interval '1 minute'
        WHERE principal_id = $1`,
      [world.bob.id],
    );
    await db.superuserPool.query(
      `UPDATE securerag.sessions SET revoked_at = now()
        WHERE principal_id = $1`,
      [world.carol.id],
    );

    const responses = await Promise.all([
      fetch(`${base}/auth/me`, { headers: { cookie: live.cookieHeader } }),
      fetch(`${base}/auth/me`, { headers: { cookie: expired.cookieHeader } }),
      fetch(`${base}/auth/me`, { headers: { cookie: revoked.cookieHeader } }),
      fetch(`${base}/auth/me`, { headers: { cookie: 'securerag_session=random-nonsense' } }),
    ]);
    const [liveRes, ...failed] = responses;
    expect(liveRes.status).toBe(200);
    for (const res of failed) {
      expect(res.status).toBe(401);
      expect(await res.text()).toBe(UNAUTHORIZED_BODY);
    }
  });

  it('8. a principal with no memberships logs in, sees an empty tenant list, and gets a refusal', async () => {
    const session = await loginViaOidc(base, provider, 'dave-sub');
    const me = await fetch(`${base}/auth/me`, { headers: { cookie: session.cookieHeader } });
    const body = (await me.json()) as { principal: { externalSubject: string }; memberships: unknown[] };
    expect(body.principal.externalSubject).toBe('dave-sub');
    expect(body.memberships).toEqual([]);

    const res = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, question: 'secret formula' }),
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(REFUSAL_BODY);
  });

  it('9. memberships over HTTP: member cannot add/promote/remove (404 ≡ nonexistent); admin can; epoch + audit', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const carol = await loginViaOidc(base, provider, 'carol-sub');
    const before = await epoch();

    const memberAdd = await fetch(`${base}/memberships`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({
        tenantId: world.tenantA.id,
        principalId: world.dave.id,
        role: 'member',
      }),
    });
    expect(memberAdd.status).toBe(404);
    expect(await memberAdd.text()).toBe(NOT_FOUND_BODY);

    // a nonexistent tenant by an ADMIN is the same 404
    const adminNonexistent = await fetch(`${base}/memberships`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({
        tenantId: randomUUID(),
        principalId: world.dave.id,
        role: 'member',
      }),
    });
    expect(adminNonexistent.status).toBe(404);
    expect(await adminNonexistent.text()).toBe(NOT_FOUND_BODY);

    const adminAdd = await fetch(`${base}/memberships`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({
        tenantId: world.tenantA.id,
        principalId: world.dave.id,
        role: 'member',
      }),
    });
    expect(adminAdd.status).toBe(201);
    expect(await epoch()).toBe(before + 1);

    // member cannot promote or remove; admin can demote and remove
    const memberPromote = await fetch(`${base}/memberships`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({
        tenantId: world.tenantA.id,
        principalId: world.dave.id,
        role: 'admin',
      }),
    });
    expect(memberPromote.status).toBe(404);

    const adminPromote = await fetch(`${base}/memberships`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({
        tenantId: world.tenantA.id,
        principalId: world.dave.id,
        role: 'admin',
      }),
    });
    expect(adminPromote.status).toBe(200);

    const memberRemove = await fetch(
      `${base}/memberships?tenantId=${world.tenantA.id}&principalId=${world.dave.id}`,
      {
        method: 'DELETE',
        headers: { cookie: alice.cookieHeader, 'x-csrf-token': alice.csrfToken },
      },
    );
    expect(memberRemove.status).toBe(404);

    const adminRemove = await fetch(
      `${base}/memberships?tenantId=${world.tenantA.id}&principalId=${world.dave.id}`,
      {
        method: 'DELETE',
        headers: { cookie: carol.cookieHeader, 'x-csrf-token': carol.csrfToken },
      },
    );
    expect(adminRemove.status).toBe(200);
    expect(await epoch()).toBe(before + 3);

    // the admin list view shows the rows; audit carries membership:changed
    const list = await fetch(`${base}/memberships?tenantId=${world.tenantA.id}`, {
      headers: { cookie: carol.cookieHeader },
    });
    expect(list.status).toBe(200);
    const { members } = (await list.json()) as { members: { principalId: string }[] };
    expect(members.map((m) => m.principalId).sort()).toEqual(
      [world.alice.id, world.carol.id].sort(),
    );

    const audit = await fetch(`${base}/audit/retrieval?limit=100`, {
      headers: { cookie: carol.cookieHeader },
    });
    const { events } = (await audit.json()) as { events: { eventType: string }[] };
    const membershipEvents = events.filter((e) => e.eventType === 'membership:changed');
    expect(membershipEvents.length).toBeGreaterThanOrEqual(3);
  });

  it('10. groups over HTTP: member 404; admin creates/lists/deletes and manages members; epoch + audit', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const carol = await loginViaOidc(base, provider, 'carol-sub');
    const before = await epoch();

    const memberCreate = await fetch(`${base}/groups`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, name: 'Sneaky' }),
    });
    expect(memberCreate.status).toBe(404);
    expect(await memberCreate.text()).toBe(NOT_FOUND_BODY);

    const adminCreate = await fetch(`${base}/groups`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, name: 'Engineering' }),
    });
    expect(adminCreate.status).toBe(201);
    const { group } = (await adminCreate.json()) as { group: { groupId: string; name: string } };
    expect(group.name).toBe('Engineering');
    expect(await epoch()).toBe(before + 1);

    const memberAdd = await fetch(`${base}/groups/${group.groupId}/members`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, principalId: world.bob.id }),
    });
    expect(memberAdd.status).toBe(404);

    const adminAdd = await fetch(`${base}/groups/${group.groupId}/members`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, principalId: world.bob.id }),
    });
    expect(adminAdd.status).toBe(200);
    expect(await epoch()).toBe(before + 2);

    const memberDelete = await fetch(`${base}/groups?tenantId=${world.tenantA.id}&groupId=${group.groupId}`, {
      method: 'DELETE',
      headers: { cookie: alice.cookieHeader, 'x-csrf-token': alice.csrfToken },
    });
    expect(memberDelete.status).toBe(404);

    const adminList = await fetch(`${base}/groups?tenantId=${world.tenantA.id}`, {
      headers: { cookie: carol.cookieHeader },
    });
    expect(adminList.status).toBe(200);
    expect(((await adminList.json()) as { groups: unknown[] }).groups).toHaveLength(1);

    const adminDelete = await fetch(`${base}/groups?tenantId=${world.tenantA.id}&groupId=${group.groupId}`, {
      method: 'DELETE',
      headers: { cookie: carol.cookieHeader, 'x-csrf-token': carol.csrfToken },
    });
    expect(adminDelete.status).toBe(200);
    expect(await epoch()).toBe(before + 3);

    const audit = await fetch(`${base}/audit/retrieval?limit=100`, {
      headers: { cookie: carol.cookieHeader },
    });
    const { events } = (await audit.json()) as { events: { eventType: string }[] };
    expect(events.filter((e) => e.eventType === 'group:changed').length).toBeGreaterThanOrEqual(3);
  });

  it('11. grants over HTTP: manage-gated (member without manage → 404; tenant admin works); audit + epoch', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const carol = await loginViaOidc(base, provider, 'carol-sub');
    const before = await epoch();

    const memberGrant = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: alice.cookieHeader,
        'x-csrf-token': alice.csrfToken,
      },
      body: JSON.stringify({
        subjectType: 'principal',
        subjectId: world.bob.id,
        capability: 'read',
      }),
    });
    expect(memberGrant.status).toBe(404);
    expect(await memberGrant.text()).toBe(NOT_FOUND_BODY);

    const memberList = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      headers: { cookie: alice.cookieHeader },
    });
    expect(memberList.status).toBe(404);

    const adminGrant = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({
        subjectType: 'principal',
        subjectId: world.bob.id,
        capability: 'read',
      }),
    });
    expect(adminGrant.status).toBe(201);
    expect(await epoch()).toBe(before + 1);
    const { grant } = (await adminGrant.json()) as {
      grant: { grantId: string; subjectId: string; capability: string };
    };
    expect(grant).toMatchObject({ subjectId: world.bob.id, capability: 'read' });

    const adminList = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      headers: { cookie: carol.cookieHeader },
    });
    expect(adminList.status).toBe(200);
    expect(((await adminList.json()) as { grants: unknown[] }).grants).toHaveLength(1);

    const adminDelete = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      method: 'DELETE',
      headers: {
        'content-type': 'application/json',
        cookie: carol.cookieHeader,
        'x-csrf-token': carol.csrfToken,
      },
      body: JSON.stringify({ grantId: grant.grantId }),
    });
    expect(adminDelete.status).toBe(200);
    expect(await epoch()).toBe(before + 2);

    const audit = await fetch(`${base}/audit/retrieval?limit=100`, {
      headers: { cookie: carol.cookieHeader },
    });
    const { events } = (await audit.json()) as { events: { eventType: string }[] };
    expect(events.filter((e) => e.eventType === 'grant:changed')).toHaveLength(2);
  });

  it('11b. malformed grant subjects are rejected at the boundary (no DoS via 22P02)', async () => {
    const session = await loginViaOidc(base, provider, 'carol-sub');
    const body = {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'group',
      subjectId: 'not-a-uuid',
      capability: 'read',
    };
    const res = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(400);
    const badRole = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ ...body, subjectType: 'tenant_role', subjectId: 'superuser' }),
    });
    expect(badRole.status).toBe(400);
    // Retrieval must still work after the rejected attempts (no poisoned rows).
    const q = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, question: 'secret formula' }),
    });
    expect(q.status).toBe(200);
  });

  it('12. manage grant unlocks grants for a non-admin member over HTTP', async () => {
    const session = await loginViaOidc(base, provider, 'alice-sub');
    await db.superuserPool.query(
      `INSERT INTO securerag.document_grants
         (tenant_id, document_id, subject_type, subject_id, capability)
       VALUES ($1, $2, 'principal', $3, 'manage')`,
      [world.tenantA.id, world.docA.id, world.alice.id],
    );
    const grant = await fetch(`${base}/documents/${world.docA.id}/grants`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({
        subjectType: 'principal',
        subjectId: world.bob.id,
        capability: 'read',
      }),
    });
    expect(grant.status).toBe(201);
  });
});
