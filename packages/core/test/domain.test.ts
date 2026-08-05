import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { withSecurityContext } from '@securerag/security';
import {
  getTestDb,
  resetData,
  seedChunk,
  seedFixtures,
  seedGrant,
  seedGroup,
  seedGroupMembership,
  seedVersion,
  revokeGrant,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import {
  canRead,
  getDocument,
  getVersion,
  resolveCitation,
  appendAudit,
  listAudit,
} from '../src/index.js';

describe('domain layer: grants, documents, citations, audit on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let docA2: { id: string; versionId: string };
  let docA3: { id: string; versionId: string };
  let groupA: string;
  let aliceDocAGrant: string;
  let supersededVersion: string;
  let quarantinedVersion: string;
  let chunkA1: string;
  let chunkB1: string;

  async function seed(pool: Pool): Promise<void> {
    world = await seedFixtures(pool);

    groupA = await seedGroup(pool, world.tenantA.id, 'Alpha Domain Group');
    await seedGroupMembership(pool, world.tenantA.id, groupA, world.alice.id);

    aliceDocAGrant = await seedGrant(pool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId: world.alice.id,
      capability: 'read',
    });

    const docs = await pool.query<{ document_id: string }>(
      `INSERT INTO securerag.documents (tenant_id, title) VALUES
         ($1, 'Alpha group doc'),
         ($1, 'Alpha role doc')
       RETURNING document_id`,
      [world.tenantA.id],
    );
    const [d2, d3] = docs.rows;
    if (!d2 || !d3) throw new Error('core fixture doc insert failed');

    const v2 = await seedVersion(pool, {
      tenantId: world.tenantA.id,
      documentId: d2.document_id,
      versionNo: 1,
      sourceObjectKey: 'tenant-a/sha/group-v1.txt',
      contentHash: Buffer.from([1, 2]),
      status: 'valid',
      isCurrent: true,
    });
    const v3 = await seedVersion(pool, {
      tenantId: world.tenantA.id,
      documentId: d3.document_id,
      versionNo: 1,
      sourceObjectKey: 'tenant-a/sha/role-v1.txt',
      contentHash: Buffer.from([3, 4]),
      status: 'valid',
      isCurrent: true,
    });
    docA2 = { id: d2.document_id, versionId: v2 };
    docA3 = { id: d3.document_id, versionId: v3 };

    await seedGrant(pool, {
      tenantId: world.tenantA.id,
      documentId: docA2.id,
      subjectType: 'group',
      subjectId: groupA,
      capability: 'read',
    });
    await seedGrant(pool, {
      tenantId: world.tenantA.id,
      documentId: docA3.id,
      subjectType: 'tenant_role',
      subjectId: 'member',
      capability: 'read',
    });
    const revokedGrant = await seedGrant(pool, {
      tenantId: world.tenantA.id,
      documentId: docA2.id,
      subjectType: 'principal',
      subjectId: world.carol.id,
      capability: 'read',
    });
    await revokeGrant(pool, world.tenantA.id, revokedGrant);

    supersededVersion = await seedVersion(pool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      versionNo: 2,
      sourceObjectKey: 'tenant-a/sha/alpha-v2.txt',
      contentHash: Buffer.from([5, 6]),
      status: 'superseded',
      isCurrent: false,
    });
    quarantinedVersion = await seedVersion(pool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      versionNo: 3,
      sourceObjectKey: 'tenant-a/sha/alpha-v3.txt',
      contentHash: Buffer.from([7, 8]),
      status: 'quarantined',
      isCurrent: false,
    });
    await seedChunk(pool, {
      tenantId: world.tenantA.id,
      versionId: supersededVersion,
      chunkNo: 1,
      text: 'Alpha secret formula superseded',
      spanStart: 0,
      spanEnd: 31,
    });
    await seedChunk(pool, {
      tenantId: world.tenantA.id,
      versionId: quarantinedVersion,
      chunkNo: 1,
      text: 'Alpha secret formula quarantined',
      spanStart: 0,
      spanEnd: 32,
    });
    chunkA1 = await seedChunk(pool, {
      tenantId: world.tenantA.id,
      versionId: world.docA.versionId,
      chunkNo: 3,
      text: 'Alpha secret formula one',
      spanStart: 0,
      spanEnd: 23,
    });
    chunkB1 = await seedChunk(pool, {
      tenantId: world.tenantB.id,
      versionId: world.docB.versionId,
      chunkNo: 2,
      text: 'Beta secret formula two',
      spanStart: 0,
      spanEnd: 23,
    });
  }

  const params = (tenantId: string, principalId: string) => ({
    tenantId,
    principalId,
    requestId: randomUUID(),
  });

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    await seed(db.superuserPool);
    api = db.apiPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  it('canRead honors principal, group, and tenant_role grants; revoked grants grant nothing', async () => {
    expect(
      await canRead(api, { ...params(world.tenantA.id, world.alice.id), documentId: world.docA.id }),
    ).toBe(true);
    expect(await canRead(api, { ...params(world.tenantA.id, world.alice.id), documentId: docA2.id })).toBe(
      true,
    );
    expect(await canRead(api, { ...params(world.tenantA.id, world.alice.id), documentId: docA3.id })).toBe(
      true,
    );
    expect(await canRead(api, { ...params(world.tenantA.id, world.carol.id), documentId: docA2.id })).toBe(
      false,
    );
    expect(await canRead(api, { ...params(world.tenantA.id, world.alice.id), documentId: world.docB.id })).toBe(
      false,
    );
    expect(
      await canRead(api, {
        ...params(world.tenantA.id, world.alice.id),
        documentId: randomUUID(),
      }),
    ).toBe(false);
  });

  it('getDocument returns allowed title/status; foreign and nonexistent are identical nulls', async () => {
    const own = await getDocument(api, {
      ...params(world.tenantA.id, world.alice.id),
      documentId: world.docA.id,
    });
    expect(own).toEqual({ documentId: world.docA.id, title: 'Alpha private doc', status: 'active' });

    const foreign = await getDocument(api, {
      ...params(world.tenantA.id, world.alice.id),
      documentId: world.docB.id,
    });
    const nonexistent = await getDocument(api, {
      ...params(world.tenantA.id, world.alice.id),
      documentId: randomUUID(),
    });
    expect(foreign).toBeNull();
    expect(nonexistent).toBeNull();
  });

  it('getVersion applies valid/current rules; superseded and quarantined versions do not exist', async () => {
    const current = await getVersion(api, {
      ...params(world.tenantA.id, world.alice.id),
      documentId: world.docA.id,
      versionId: world.docA.versionId,
    });
    expect(current).toMatchObject({
      documentId: world.docA.id,
      versionId: world.docA.versionId,
      versionNo: 1,
      status: 'valid',
      isCurrent: true,
    });

    for (const versionId of [supersededVersion, quarantinedVersion]) {
      const hidden = await getVersion(api, {
        ...params(world.tenantA.id, world.alice.id),
        documentId: world.docA.id,
        versionId,
      });
      expect(hidden).toBeNull();
    }
    const foreign = await getVersion(api, {
      ...params(world.tenantA.id, world.alice.id),
      documentId: world.docA.id,
      versionId: world.docB.versionId,
    });
    expect(foreign).toBeNull();
  });

  it('resolveCitation returns the authorized excerpt; foreign and nonexistent are identical nulls', async () => {
    const resolved = await resolveCitation(api, {
      ...params(world.tenantA.id, world.alice.id),
      citationId: chunkA1,
    });
    expect(resolved).toEqual({
      documentId: world.docA.id,
      versionId: world.docA.versionId,
      chunkId: chunkA1,
      span: { start: 0, end: 23 },
      excerpt: 'Alpha secret formula one',
    });

    const foreign = await resolveCitation(api, {
      ...params(world.tenantA.id, world.alice.id),
      citationId: chunkB1,
    });
    const nonexistent = await resolveCitation(api, {
      ...params(world.tenantA.id, world.alice.id),
      citationId: randomUUID(),
    });
    expect(foreign).toBeNull();
    expect(nonexistent).toBeNull();
  });

  it('resolveCitation rechecks authorization: revoked grant makes an own citation vanish', async () => {
    await revokeGrant(db.superuserPool, world.tenantA.id, aliceDocAGrant);
    const resolved = await resolveCitation(api, {
      ...params(world.tenantA.id, world.alice.id),
      citationId: chunkA1,
    });
    expect(resolved).toBeNull();
  });

  it('appendAudit inserts inside the verified context; listAudit is tenant-isolated (alice vs bob)', async () => {
    const aliceReq = randomUUID();
    const bobReq = randomUUID();

    await withSecurityContext(
      api,
      { tenantId: world.tenantA.id, principalId: world.alice.id, requestId: aliceReq },
      async (client, ctx) => {
        await appendAudit({
          client,
          event: {
            eventType: 'retrieval:allowed',
            requestId: aliceReq,
            principalId: ctx.principalId,
            membershipId: ctx.membershipId,
            authEpoch: ctx.authEpoch,
            redactedQuery: 'secret formula',
          },
        });
      },
    );
    await withSecurityContext(
      api,
      { tenantId: world.tenantB.id, principalId: world.bob.id, requestId: bobReq },
      async (client, ctx) => {
        await appendAudit({
          client,
          event: {
            eventType: 'retrieval:allowed',
            requestId: bobReq,
            principalId: ctx.principalId,
            membershipId: ctx.membershipId,
            authEpoch: ctx.authEpoch,
            redactedQuery: 'beta question',
          },
        });
      },
    );

    await getDocument(api, {
      ...params(world.tenantA.id, world.alice.id),
      documentId: world.docA.id,
    });
    await getDocument(api, {
      ...params(world.tenantB.id, world.bob.id),
      documentId: world.docB.id,
    });

    const aliceEvents = await listAudit(api, params(world.tenantA.id, world.alice.id));
    const bobEvents = await listAudit(api, params(world.tenantB.id, world.bob.id));

    expect(aliceEvents.length).toBeGreaterThan(0);
    expect(aliceEvents.some((e) => e.requestId === aliceReq)).toBe(true);
    expect(aliceEvents.some((e) => e.requestId === bobReq)).toBe(false);
    expect(aliceEvents.every((e) => e.tenantId === world.tenantA.id)).toBe(true);
    expect(aliceEvents.some((e) => e.eventType === 'document:read')).toBe(true);

    expect(bobEvents.some((e) => e.requestId === bobReq)).toBe(true);
    expect(bobEvents.some((e) => e.requestId === aliceReq)).toBe(false);
    expect(bobEvents.every((e) => e.tenantId === world.tenantB.id)).toBe(true);
  });
});
