import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  getTestDb,
  resetData,
  seedFixtures,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import {
  buildSessionCookie,
  createSession,
  csrfMatches,
  expireSessionCookie,
  getSession,
  hashSessionToken,
  parseCookieHeader,
  revokeSession,
  sessionCookieName,
  SESSION_COOKIE_HOST_PREFIX,
  validateSessionCookieConfig,
  withIdentityContext,
} from '../src/index.js';

describe('server-side sessions on real runtime roles', () => {
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

  it('createSession issues a 256-bit token and inserts the row as the principal', async () => {
    const { token, session } = await createSession(api, {
      principalId: world.alice.id,
      ttlSeconds: 3600,
    });
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(session.principalId).toBe(world.alice.id);
    expect(session.revokedAt).toBeNull();
    expect(session.csrfToken).toHaveLength(32);
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('getSession resolves a live token; the database only ever stores the hash', async () => {
    const { token, session } = await createSession(api, { principalId: world.alice.id });
    const found = await getSession(api, token);
    expect(found?.sessionId).toBe(session.sessionId);
    expect(found?.principalId).toBe(world.alice.id);
    expect(found?.csrfToken).toEqual(session.csrfToken);

    const { rows } = await db.superuserPool.query<{ token_hash: Buffer; raw: string }>(
      `SELECT token_hash FROM securerag.sessions WHERE session_id = $1`,
      [session.sessionId],
    );
    const stored = rows[0]?.token_hash;
    expect(stored).toEqual(hashSessionToken(token));
    expect(stored).not.toEqual(Buffer.from(token, 'utf8'));
  });

  it('foreign, expired, and revoked tokens all reject indistinguishably (null)', async () => {
    const { token } = await createSession(api, { principalId: world.alice.id });
    await db.superuserPool.query(
      `UPDATE securerag.sessions SET expires_at = now() - interval '1 minute'
        WHERE principal_id = $1`,
      [world.alice.id],
    );
    const expired = await getSession(api, token);
    expect(expired).toBeNull();

    const other = await createSession(api, { principalId: world.bob.id });
    const revoked = await revokeSession(api, other.token);
    expect(revoked).toBe(true);
    expect(await getSession(api, other.token)).toBeNull();

    expect(await getSession(api, randomBytes(32).toString('base64url'))).toBeNull();
    expect(await getSession(api, 'tampered-token')).toBeNull();
    expect(await revokeSession(api, randomBytes(32).toString('base64url'))).toBe(false);
  });

  it('expired sessions are rejected even before any manual revocation (DB clock)', async () => {
    const { token } = await createSession(api, { principalId: world.carol.id, ttlSeconds: 1 });
    expect(await getSession(api, token)).not.toBeNull();
    await new Promise((r) => setTimeout(r, 1100));
    expect(await getSession(api, token)).toBeNull();
  });

  it('logout revokes server-side; the session row keeps a revoked_at marker', async () => {
    const { token, session } = await createSession(api, { principalId: world.alice.id });
    await revokeSession(api, token);
    expect(await getSession(api, token)).toBeNull();
    const { rows } = await db.superuserPool.query<{ revoked_at: Date | null }>(
      `SELECT revoked_at FROM securerag.sessions WHERE session_id = $1`,
      [session.sessionId],
    );
    expect(rows[0]?.revoked_at).not.toBeNull();
    // revoked rows remain (auditable) but never validate again
    expect(await revokeSession(api, token)).toBe(false);
  });

  it('sessions are principal-scoped through RLS: each principal sees only their own rows', async () => {
    const aliceSees = await withIdentityContext(api, world.alice.id, async (client) => {
      const { rows } = await client.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM securerag.sessions`,
      );
      return rows[0]?.n ?? 0;
    });
    const bobSees = await withIdentityContext(api, world.bob.id, async (client) => {
      const { rows } = await client.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM securerag.sessions`,
      );
      return rows[0]?.n ?? 0;
    });
    const { rows } = await db.superuserPool.query<{ principal_id: string; n: number }>(
      `SELECT principal_id, count(*)::int AS n FROM securerag.sessions
        GROUP BY principal_id ORDER BY principal_id`,
    );
    const byPrincipal = new Map(rows.map((r) => [r.principal_id, r.n]));
    expect(aliceSees.result).toBe(byPrincipal.get(world.alice.id) ?? 0);
    expect(bobSees.result).toBe(byPrincipal.get(world.bob.id) ?? 0);
    expect(aliceSees.result).toBeGreaterThan(0);
    expect(bobSees.result).toBeGreaterThan(0);
    // alice's and bob's views never include each other's (or carol's) sessions
    const carolCount = byPrincipal.get(world.carol.id) ?? 0;
    const total = [...byPrincipal.values()].reduce((a, b) => a + b, 0);
    expect(aliceSees.result + bobSees.result + carolCount).toBe(total);
  });

  it('session tokens are unique and high-entropy (no collisions across 500 sessions)', async () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 500; i += 1) {
      const { token } = await createSession(api, { principalId: world.bob.id });
      tokens.add(token);
    }
    expect(tokens.size).toBe(500);
  });
});

describe('session cookie helpers (pure)', () => {
  it('production name honors the __Host- prefix only under Secure', () => {
    expect(sessionCookieName(true)).toBe(`${SESSION_COOKIE_HOST_PREFIX}securerag_session`);
    expect(sessionCookieName(false)).toBe('securerag_session');
    expect(() => validateSessionCookieConfig('__Host-securerag_session', false)).toThrow(/Secure/);
    expect(() => validateSessionCookieConfig('bad name', true)).toThrow();
    expect(() => validateSessionCookieConfig('a=b', true)).toThrow();
    expect(validateSessionCookieConfig('__Host-securerag_session', true)).toBeUndefined();
    expect(validateSessionCookieConfig('securerag_session', false)).toBeUndefined();
  });

  it('builds HttpOnly + SameSite=Lax + Path=/ + Secure + Max-Age attributes', () => {
    const cookie = buildSessionCookie({
      name: '__Host-securerag_session',
      value: 'token-value',
      secure: true,
      maxAgeSeconds: 3600,
    });
    expect(cookie.startsWith('__Host-securerag_session=token-value; ')).toBe(true);
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('Max-Age=3600');
    expect(cookie).not.toContain('Domain=');
  });

  it('omits Secure over plain HTTP (test/dev localhost exception only)', () => {
    const cookie = buildSessionCookie({ name: 'securerag_session', value: 'v', secure: false });
    expect(cookie).not.toContain('Secure');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
  });

  it('expireSessionCookie clears the value with a past Expires and Max-Age=0', () => {
    const cookie = expireSessionCookie('securerag_session', false);
    expect(cookie).toContain('securerag_session=;');
    expect(cookie).toContain('Max-Age=0');
    expect(cookie).toContain('Expires=Thu, 01 Jan 1970');
  });

  it('parseCookieHeader finds the named cookie among others; missing → null', () => {
    const header = 'other=a; securerag_session=abc123; third=b';
    expect(parseCookieHeader(header, 'securerag_session')).toBe('abc123');
    expect(parseCookieHeader(header, 'missing')).toBeNull();
    expect(parseCookieHeader(undefined, 'securerag_session')).toBeNull();
    expect(parseCookieHeader('securerag_session=', 'securerag_session')).toBeNull();
    expect(parseCookieHeader(['a=1', 'securerag_session=xyz'], 'securerag_session')).toBe('xyz');
  });

  it('csrfMatches is timing-safe and rejects length mismatches, garbage, and absence', () => {
    const expected = randomBytes(32);
    const hex = expected.toString('hex');
    expect(csrfMatches(expected, hex)).toBe(true);
    expect(csrfMatches(expected, hex.toUpperCase())).toBe(true);
    expect(csrfMatches(expected, undefined)).toBe(false);
    expect(csrfMatches(expected, '')).toBe(false);
    expect(csrfMatches(expected, 'not-hex!!')).toBe(false);
    expect(csrfMatches(expected, hex.slice(0, 4))).toBe(false);
    expect(csrfMatches(expected, randomBytes(32).toString('hex'))).toBe(false);
  });
});
