import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  getTestDb,
  resetData,
  seedFixtures,
  seedGrant,
  seedGroup,
  seedGroupMembership,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import {
  getVersionWithHistory,
  listAudit,
  listVersions,
  type VersionMetadata,
} from '../src/index.js';

/**
 * S3 history capability (ADR-0003 amendment S3): real PostgreSQL, real
 * least-privilege runtime role. History = MANAGE capability: non-current
 * version metadata resolves only for principals with a direct `manage` grant
 * on the document; read/write grants and the tenant-admin role alone never
 * unlock history. Metadata only — never content; current versions stay
 * visible to every grant holder; successful history accesses are audited
 * 'document:history'.
 */
describe('S3 history capability on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let docAVersions: { v1: string; v2: string; v3: string; v4: string };

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    api = db.apiPool;
    docAVersions = await seedHistory(db.superuserPool, world);
  });

  afterAll(async () => {
    await db.stop();
  });

  const requestId = (): string => randomUUID();

  /** Seed docA with a full lifecycle: v1 current valid, v2 superseded, v3
   * quarantined, v4 expired — all with explicit published_at. */
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

  const readGrant = (subjectId: string): Promise<string> =>
    seedGrant(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId,
      capability: 'read',
    });
  const manageGrant = (subjectId: string): Promise<string> =>
    seedGrant(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId,
      capability: 'manage',
    });

  const epoch = async (): Promise<number> => {
    const { rows } = await db.superuserPool.query<{ epoch: string }>(
      'SELECT epoch FROM securerag.authorization_epoch',
    );
    return Number(rows[0]?.epoch);
  };

  const historyEvents = async (): Promise<{ filters: Record<string, unknown> | null }[]> => {
    const audit = await listAudit(api, {
      tenantId: world.tenantA.id,
      principalId: world.carol.id,
      requestId: requestId(),
    });
    return audit
      .filter((e) => e.eventType === 'document:history')
      .map((e) => ({ filters: e.filters }));
  };

  describe('listVersions', () => {
    it('read-grant holder sees ONLY the current version; non-current statuses never listed', async () => {
      await readGrant(world.alice.id);
      const versions = await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      });
      expect(versions).toHaveLength(1);
      expect(versions?.[0]).toMatchObject({
        documentId: world.docA.id,
        versionId: docAVersions.v1,
        versionNo: 1,
        status: 'valid',
        isCurrent: true,
      });
      expect(versions?.[0]?.publishedAt).toBeInstanceOf(Date);
      expect(versions?.[0]?.contentHash.toString('hex')).toBe('aabb');
    });

    it('manage-grant holder sees every version with its status (superseded/quarantined/expired listed)', async () => {
      await manageGrant(world.alice.id);
      const versions = (await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      })) as VersionMetadata[];
      expect(versions.map((v) => v.versionNo)).toEqual([1, 2, 3, 4]);
      expect(versions.map((v) => v.status)).toEqual([
        'valid',
        'superseded',
        'quarantined',
        'expired',
      ]);
      expect(versions.map((v) => v.isCurrent)).toEqual([true, false, false, false]);
      for (const v of versions) {
        expect(v.publishedAt).toBeInstanceOf(Date);
        expect(v.contentHash.length).toBeGreaterThan(0);
      }
    });

    it('tenant-admin role WITHOUT a manage grant does not unlock history (manage grant only)', async () => {
      await readGrant(world.carol.id);
      const versions = await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        documentId: world.docA.id,
      });
      expect(versions).toHaveLength(1);
      expect(versions?.[0]?.versionNo).toBe(1);
    });

    it('manage via group and tenant_role subjects unlocks history (manage_scope view subjects)', async () => {
      const groupId = await seedGroup(db.superuserPool, world.tenantA.id, 'History Group');
      await seedGroupMembership(db.superuserPool, world.tenantA.id, groupId, world.alice.id);
      await seedGrant(db.superuserPool, {
        tenantId: world.tenantA.id,
        documentId: world.docA.id,
        subjectType: 'group',
        subjectId: groupId,
        capability: 'manage',
      });
      const byGroup = await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      });
      expect(byGroup).toHaveLength(4);

      // The tenant_role branch matches the principal's own role: an 'admin'
      // role grant unlocks history for the tenant admin, nothing else.
      await seedGrant(db.superuserPool, {
        tenantId: world.tenantA.id,
        documentId: world.docA.id,
        subjectType: 'tenant_role',
        subjectId: 'admin',
        capability: 'manage',
      });
      const byRole = await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        documentId: world.docA.id,
      });
      expect(byRole).toHaveLength(4);
    });

    it('no grant, foreign document, and nonexistent document are indistinguishable (null)', async () => {
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
      };
      expect(await listVersions(api, { ...params, documentId: world.docA.id })).toBeNull();
      expect(
        await listVersions(api, { ...params, documentId: randomUUID() }),
      ).toBeNull();
      await readGrant(world.alice.id);
      expect(
        await listVersions(api, { ...params, documentId: randomUUID() }),
      ).toBeNull();
    });

    it('manage-path listings are audited document:history; read-path listings write nothing', async () => {
      await readGrant(world.alice.id);
      await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      });
      expect(await historyEvents()).toEqual([]);

      await manageGrant(world.alice.id);
      await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      });
      const events = await historyEvents();
      expect(events).toHaveLength(1);
      expect(events[0]?.filters).toMatchObject({ documentId: world.docA.id });
    });

    it('history reads never bump the authorization epoch', async () => {
      const before = await epoch();
      await manageGrant(world.alice.id);
      await listVersions(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      });
      expect(await epoch()).toBe(before);
    });
  });

  describe('getVersionWithHistory', () => {
    it('current version resolves for a read-holder; non-current versions are null', async () => {
      await readGrant(world.alice.id);
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      const current = await getVersionWithHistory(api, {
        ...params,
        versionId: docAVersions.v1,
      });
      expect(current).toMatchObject({
        documentId: world.docA.id,
        versionId: docAVersions.v1,
        versionNo: 1,
        status: 'valid',
        isCurrent: true,
      });
      for (const id of [docAVersions.v2, docAVersions.v3, docAVersions.v4]) {
        expect(await getVersionWithHistory(api, { ...params, versionId: id })).toBeNull();
      }
    });

    it('manage-grant holder resolves non-current versions (superseded/quarantined/expired) with metadata', async () => {
      await manageGrant(world.alice.id);
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      const superseded = await getVersionWithHistory(api, {
        ...params,
        versionId: docAVersions.v2,
      });
      expect(superseded).toMatchObject({
        versionNo: 2,
        status: 'superseded',
        isCurrent: false,
      });
      expect(superseded?.publishedAt).toBeInstanceOf(Date);
      expect(superseded?.contentHash.toString('hex')).toBe('aabbcc');
      const expired = await getVersionWithHistory(api, {
        ...params,
        versionId: docAVersions.v4,
      });
      expect(expired?.status).toBe('expired');
    });

    it('tenant-admin role WITHOUT a manage grant gets null for non-current versions', async () => {
      await readGrant(world.carol.id);
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      expect(
        await getVersionWithHistory(api, { ...params, versionId: docAVersions.v2 }),
      ).toBeNull();
      expect(
        await getVersionWithHistory(api, { ...params, versionId: docAVersions.v1 }),
      ).not.toBeNull();
    });

    it('cross-document and foreign/nonexistent version ids are indistinguishable (null)', async () => {
      await manageGrant(world.alice.id);
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      // docB's version id with docA's document id: the version lives in
      // tenant B, so the composite must NOT resolve.
      expect(
        await getVersionWithHistory(api, {
          ...params,
          versionId: world.docB.versionId,
        }),
      ).toBeNull();
      expect(
        await getVersionWithHistory(api, { ...params, versionId: randomUUID() }),
      ).toBeNull();
    });

    it('manage-path single-version fetches are audited document:history (with versionId)', async () => {
      await manageGrant(world.alice.id);
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      await getVersionWithHistory(api, { ...params, versionId: docAVersions.v2 });
      const events = await historyEvents();
      expect(events).toHaveLength(1);
      expect(events[0]?.filters).toMatchObject({
        documentId: world.docA.id,
        versionId: docAVersions.v2,
      });
    });

    it('read-path fetches write no history audit events', async () => {
      await readGrant(world.alice.id);
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      await getVersionWithHistory(api, { ...params, versionId: docAVersions.v1 });
      expect(await historyEvents()).toEqual([]);
    });
  });
});
