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
import { loginViaOidc, type AuthenticatedSession } from './auth-helpers.js';

const NOT_FOUND_BODY = JSON.stringify({
  code: 'NOT_FOUND',
  message: 'Resource not found',
});

interface VersionListBody {
  versions: {
    versionId: string;
    versionNo: number;
    status: string;
    isCurrent: boolean;
    publishedAt: string | null;
    hash: string;
  }[];
}

interface VersionBody {
  documentId: string;
  versionId: string;
  versionNo: number;
  status: string;
  isCurrent: boolean;
  publishedAt: string | null;
  hash: string;
}

/**
 * S3 ACL + history over real HTTP: the Fastify server, real OIDC login, the
 * least-privilege runtime pool. Covers GET /documents/{id}/grants (manage
 * gated, slim wire shape, byte-identical 404s), GET /documents/{id}/versions
 * (history = manage capability), the single-version endpoint, the authorized
 * source seam, and the resolvable citation flag.
 */
describe('S3 ACL + history endpoints over HTTP', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;
  let versions: { v1: string; v2: string; v3: string; v4: string };

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    api = db.apiPool;
    versions = await seedHistory(db.superuserPool, world);
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
      postLoginRedirectPath: '/',
    };
    app = await buildApp({ pool: api, providers: new SpyGenerator(), oidc });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await db.stop();
  });

  /** docA lifecycle: v1 current valid, v2 superseded, v3 quarantined, v4
   * expired — all with explicit published_at (superuser fixture seeding). */
  async function seedHistory(
    pool: Pool,
    w: FixtureWorld,
  ): Promise<{ v1: string; v2: string; v3: string; v4: string }> {
    await pool.query(
      `UPDATE securerag.document_versions
          SET published_at = now() - interval '90 days'
        WHERE version_id = $1`,
      [w.docA.versionId],
    );
    const { rows } = await pool.query<{ version_id: string; version_no: number }>(
      `INSERT INTO securerag.document_versions
         (tenant_id, document_id, version_no, source_object_key, content_hash,
          status, is_current, published_at)
       VALUES
         ($1, $2, 2, 'tenant-a/hist-v2.txt', decode('aabbcc', 'hex'), 'superseded', false, now() - interval '60 days'),
         ($1, $2, 3, 'tenant-a/hist-v3.txt', decode('aabbcd', 'hex'), 'quarantined', false, now() - interval '30 days'),
         ($1, $2, 4, 'tenant-a/hist-v4.txt', decode('aabbce', 'hex'), 'expired', false, now() - interval '7 days')
       RETURNING version_id, version_no`,
      [w.tenantA.id, w.docA.id],
    );
    const byNo = new Map(rows.map((r) => [r.version_no, r.version_id]));
    const v2 = byNo.get(2);
    const v3 = byNo.get(3);
    const v4 = byNo.get(4);
    if (v2 === undefined || v3 === undefined || v4 === undefined) {
      throw new Error('history fixture insert failed');
    }
    return { v1: w.docA.versionId, v2, v3, v4 };
  }

  async function grant(
    subjectId: string,
    capability: 'read' | 'manage',
  ): Promise<string> {
    const { rows } = await db.superuserPool.query<{ grant_id: string }>(
      `INSERT INTO securerag.document_grants
         (tenant_id, document_id, subject_type, subject_id, capability)
       VALUES ($1, $2, 'principal', $3, $4)
       ON CONFLICT DO NOTHING RETURNING grant_id`,
      [world.tenantA.id, world.docA.id, subjectId, capability],
    );
    const id = rows[0]?.grant_id;
    if (id === undefined) throw new Error('fixture grant insert failed');
    return id;
  }

  async function login(subject: string): Promise<AuthenticatedSession> {
    return loginViaOidc(base, provider, subject);
  }

  function getResource(
    path: string,
    session: AuthenticatedSession | undefined,
  ): Promise<Response> {
    return fetch(`${base}${path}`, {
      headers: session !== undefined ? { cookie: session.cookieHeader } : {},
    });
  }

  describe('GET /documents/{id}/grants', () => {
    it('manage-gated: member without manage → 404; tenant admin lists the slim ACL entries', async () => {
      const alice = await login('alice-sub');
      const carol = await login('carol-sub');

      const denied = await getResource(`/documents/${world.docA.id}/grants`, alice);
      expect(denied.status).toBe(404);
      expect(await denied.text()).toBe(NOT_FOUND_BODY);

      const admin = await getResource(`/documents/${world.docA.id}/grants`, carol);
      expect(admin.status).toBe(200);
      expect(((await admin.json()) as { grants: unknown[] }).grants).toEqual([]);

      // Seed a read grant for bob; the admin list exposes the slim entry.
      await grant(world.bob.id, 'read');
      const listed = await getResource(`/documents/${world.docA.id}/grants`, carol);
      expect(listed.status).toBe(200);
      const body = (await listed.json()) as {
        grants: Record<string, unknown>[];
      };
      expect(body.grants).toHaveLength(1);
      expect(Object.keys(body.grants[0] ?? {}).sort()).toEqual([
        'capability',
        'grantId',
        'subjectId',
        'subjectType',
      ]);
      expect(body.grants[0]).toMatchObject({
        subjectType: 'principal',
        subjectId: world.bob.id,
        capability: 'read',
      });
    });

    it('foreign and nonexistent documents are byte-identical 404s', async () => {
      const carol = await login('carol-sub');
      const foreignDoc = world.docB.id;
      const nonexistent = randomUUID();

      const foreign = await getResource(`/documents/${foreignDoc}/grants`, carol);
      const missing = await getResource(`/documents/${nonexistent}/grants`, carol);
      expect(foreign.status).toBe(404);
      expect(missing.status).toBe(404);
      const foreignBody = await foreign.text();
      const missingBody = await missing.text();
      expect(foreignBody).toBe(NOT_FOUND_BODY);
      expect(missingBody).toBe(foreignBody);
    });
  });

  describe('GET /documents/{id}/versions (history)', () => {
    it('read-grant holder sees only the current version; non-current versions are byte-identical 404s', async () => {
      await grant(world.alice.id, 'read');
      const session = await login('alice-sub');

      const list = await getResource(`/documents/${world.docA.id}/versions`, session);
      expect(list.status).toBe(200);
      const body = (await list.json()) as VersionListBody;
      expect(body.versions).toHaveLength(1);
      expect(body.versions[0]).toMatchObject({
        versionId: versions.v1,
        versionNo: 1,
        status: 'valid',
        isCurrent: true,
        hash: 'aabb',
      });
      expect(body.versions[0]?.publishedAt).not.toBeNull();

      const superseded = await getResource(
        `/documents/${world.docA.id}/versions/${versions.v2}`,
        session,
      );
      expect(superseded.status).toBe(404);
      const missing = await getResource(
        `/documents/${world.docA.id}/versions/${randomUUID()}`,
        session,
      );
      expect(missing.status).toBe(404);
      const supersededBody = await superseded.text();
      const missingBody = await missing.text();
      expect(supersededBody).toBe(NOT_FOUND_BODY);
      expect(missingBody).toBe(supersededBody);

      const current = await getResource(
        `/documents/${world.docA.id}/versions/${versions.v1}`,
        session,
      );
      expect(current.status).toBe(200);
      const version = (await current.json()) as VersionBody;
      expect(version).toMatchObject({ versionNo: 1, status: 'valid', isCurrent: true });
      expect(version.publishedAt).not.toBeNull();
      expect(version.hash).toBe('aabb');
    });

    it('manage-grant holder sees every version with status; single non-current versions resolve', async () => {
      await grant(world.alice.id, 'manage');
      const session = await login('alice-sub');

      const list = await getResource(`/documents/${world.docA.id}/versions`, session);
      expect(list.status).toBe(200);
      const body = (await list.json()) as VersionListBody;
      expect(body.versions.map((v) => v.versionNo)).toEqual([1, 2, 3, 4]);
      expect(body.versions.map((v) => v.status)).toEqual([
        'valid',
        'superseded',
        'quarantined',
        'expired',
      ]);
      expect(body.versions.map((v) => v.isCurrent)).toEqual([true, false, false, false]);
      for (const v of body.versions) {
        expect(v.publishedAt).not.toBeNull();
        expect(v.hash.length).toBeGreaterThan(0);
      }

      const superseded = await getResource(
        `/documents/${world.docA.id}/versions/${versions.v2}`,
        session,
      );
      expect(superseded.status).toBe(200);
      const version = (await superseded.json()) as VersionBody;
      expect(version).toMatchObject({
        versionId: versions.v2,
        versionNo: 2,
        status: 'superseded',
        isCurrent: false,
        hash: 'aabbcc',
      });
      expect(version.publishedAt).not.toBeNull();
    });

    it('tenant admin WITHOUT a manage grant does not get history over HTTP', async () => {
      await grant(world.carol.id, 'read');
      const session = await login('carol-sub');

      const list = await getResource(`/documents/${world.docA.id}/versions`, session);
      expect(list.status).toBe(200);
      expect(((await list.json()) as VersionListBody).versions).toHaveLength(1);

      const superseded = await getResource(
        `/documents/${world.docA.id}/versions/${versions.v2}`,
        session,
      );
      expect(superseded.status).toBe(404);
    });

    it('no grant and foreign documents are indistinguishable 404s', async () => {
      const alice = await login('alice-sub');
      const noGrant = await getResource(`/documents/${world.docA.id}/versions`, alice);
      const foreign = await getResource(`/documents/${world.docB.id}/versions`, alice);
      expect(noGrant.status).toBe(404);
      expect(foreign.status).toBe(404);
      const noGrantBody = await noGrant.text();
      const foreignBody = await foreign.text();
      expect(noGrantBody).toBe(NOT_FOUND_BODY);
      expect(foreignBody).toBe(noGrantBody);
    });

    it('history access is audited over HTTP (document:history visible to the tenant)', async () => {
      await grant(world.alice.id, 'manage');
      const alice = await login('alice-sub');
      const carol = await login('carol-sub');

      await getResource(`/documents/${world.docA.id}/versions`, alice);
      await getResource(
        `/documents/${world.docA.id}/versions/${versions.v3}`,
        alice,
      );

      const audit = await getResource('/audit/retrieval?limit=100', carol);
      const { events } = (await audit.json()) as {
        events: { eventType: string; filters: Record<string, unknown> | null }[];
      };
      const history = events.filter((e) => e.eventType === 'document:history');
      expect(history).toHaveLength(2);
      expect(history[0]?.filters).toMatchObject({
        documentId: world.docA.id,
        versionId: versions.v3,
      });
    });
  });

  describe('GET /documents/{id}/versions/{versionId}/source (authorized seam)', () => {
    it('source resolves only for the current version of a granted document; non-current and foreign are 404', async () => {
      await grant(world.alice.id, 'read');
      const session = await login('alice-sub');

      const current = await getResource(
        `/documents/${world.docA.id}/versions/${versions.v1}/source`,
        session,
      );
      expect(current.status).toBe(200);
      expect(await current.json()).toEqual({
        versionId: versions.v1,
        documentId: world.docA.id,
        contentHash: 'aabb',
      });

      const superseded = await getResource(
        `/documents/${world.docA.id}/versions/${versions.v2}/source`,
        session,
      );
      expect(superseded.status).toBe(404);
      expect(await superseded.text()).toBe(NOT_FOUND_BODY);

      // Even a manage-grant holder never gets non-current source CONTENT
      // (history is metadata only).
      const carol = await login('carol-sub');
      const foreign = await getResource(
        `/documents/${world.docB.id}/versions/${world.docB.versionId}/source`,
        carol,
      );
      expect(foreign.status).toBe(404);
    });
  });

  describe('GET /citations/{id} (resolvable flag)', () => {
    it('a resolvable citation returns the flag; foreign/nonexistent citations stay 404', async () => {
      await grant(world.alice.id, 'read');
      const session = await login('alice-sub');

      const { rows } = await db.superuserPool.query<{ chunk_id: string }>(
        `SELECT chunk_id FROM securerag.chunks
          WHERE tenant_id = $1 AND version_id = $2 ORDER BY chunk_no LIMIT 1`,
        [world.tenantA.id, versions.v1],
      );
      const chunkId = rows[0]?.chunk_id;
      expect(chunkId).toBeTruthy();

      const resolved = await getResource(`/citations/${chunkId}`, session);
      expect(resolved.status).toBe(200);
      const body = (await resolved.json()) as {
        documentId: string;
        versionId: string;
        chunkId: string;
        span: { start: number; end: number };
        excerpt: string;
        resolvable: boolean;
      };
      expect(body).toMatchObject({
        documentId: world.docA.id,
        versionId: versions.v1,
        chunkId,
        resolvable: true,
      });
      expect(body.excerpt).toBeTruthy();

      const missing = await getResource(`/citations/${randomUUID()}`, session);
      expect(missing.status).toBe(404);
      expect(await missing.text()).toBe(NOT_FOUND_BODY);
    });
  });
});
