import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';import {
  getTestDb,
  resetData,
  seedChunk,
  seedGrant,
  seedVersion,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import {
  listAudit,
  listQuarantined,
  quarantineVersion,
  reviewQuarantine,
  runRetrievalQuery,
} from '../src/index.js';

/**
 * S5 quarantine domain (ADR-0006 layers 6/8) on REAL PostgreSQL as the
 * least-privilege runtime role:
 *  - quarantineVersion excludes a version from retrieval + audits (epoch bump);
 *  - release makes it searchable again + audits decision and reviewer;
 *  - keep leaves it quarantined + audits without an epoch bump;
 *  - re-scan re-quarantines a released version;
 *  - only tenant admins / security_reviewer role can review; a plain member
 *    gets an indistinguishable failure (no write, no audit), byte-identical
 *    to a foreign or nonexistent version.
 * RLS is never mocked.
 */
describe('S5 injection quarantine domain on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: {
    tenantA: string;
    tenantB: string;
    member: string;
    reviewer: string;
    admin: string;
    outsider: string;
    docQ: string;
    versionQ: string;
    docX: string;
    versionX: string;
  };

  const requestId = (): string => randomUUID();

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    api = db.apiPool;
    world = await seedQuarantineWorld(db.superuserPool);
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

  const statusOf = async (versionId: string): Promise<string> => {
    const { rows } = await db.superuserPool.query<{ status: string }>(
      'SELECT status FROM securerag.document_versions WHERE version_id = $1',
      [versionId],
    );
    return rows[0]?.status ?? 'missing';
  };

  const reviewColumns = async (versionId: string): Promise<{
    reviewed_by: string | null;
    reviewed_at: Date | null;
    review_decision: string | null;
  }> => {
    const { rows } = await db.superuserPool.query<{
      reviewed_by: string | null;
      reviewed_at: Date | null;
      review_decision: string | null;
    }>(
      `SELECT reviewed_by, reviewed_at, review_decision
         FROM securerag.document_versions WHERE version_id = $1`,
      [versionId],
    );
    return rows[0] ?? { reviewed_by: null, reviewed_at: null, review_decision: null };
  };

  const queryAs = (principalId: string, tenantId: string, question: string) =>
    runRetrievalQuery(
      api,
      { tenantId, principalId, requestId: requestId() },
      'keyword',
      { question, limit: 10 },
    );

  const auditFor = async (principalId: string, tenantId: string, eventType: string) => {
    const events = await listAudit(api, {
      tenantId,
      principalId,
      requestId: requestId(),
      limit: 100,
    });
    return events.filter((e) => e.eventType === eventType);
  };

  it('quarantineVersion: pending->quarantined, excludes from retrieval, audits with post-bump epoch', async () => {
    // Seed a PENDING version of the granted doc (initial-scan path).
    const pendingId = await seedVersion(db.superuserPool, {
      tenantId: world.tenantA,
      documentId: world.docX,
      versionNo: 2,
      sourceObjectKey: 'tenant-a/pending.bin',
      contentHash: Buffer.from('aabbccdd', 'hex'),
      status: 'pending',
      isCurrent: false,
    });
    await seedChunk(db.superuserPool, {
      tenantId: world.tenantA,
      versionId: pendingId,
      chunkNo: 1,
      text: 'pending scan topic alpha beta',
      spanStart: 0,
      spanEnd: 24,
    });
    await seedChunk(db.superuserPool, {
      tenantId: world.tenantA,
      versionId: pendingId,
      chunkNo: 2,
      text: 'pending scan topic gamma delta',
      spanStart: 25,
      spanEnd: 49,
    });

    const before = await epoch();
    const quarantined = await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: pendingId,
    });
    expect(quarantined).toBe(true);
    expect(await statusOf(pendingId)).toBe('quarantined');
    expect(await epoch()).toBe(before + 1);

    const events = await auditFor(world.admin, world.tenantA, 'version:quarantined');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      filters: { versionId: pendingId, documentId: world.docX },
    });
    // the event is stamped with the POST-bump epoch
    expect(Number(events[0]?.authEpoch)).toBe(before + 1);
  });

  it('quarantined versions are never searchable; release makes them searchable + audited with reviewer', async () => {
    // Before: the valid version of docQ is searchable by the member (granted).
    const before = await queryAs(world.member, world.tenantA, 'quarantine review topic');
    expect(before.length).toBeGreaterThanOrEqual(2);

    const quarantineApplied = await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
    });
    expect(quarantineApplied).toBe(true);
    expect(await statusOf(world.versionQ)).toBe('quarantined');

    // Excluded from retrieval; version metadata is indistinguishable from
    // nonexistent (getVersion path is covered by the retrieval SQL filter).
    expect(await queryAs(world.member, world.tenantA, 'quarantine review topic')).toEqual([]);

    // Reviewer releases it with a human context; searchable again.
    const epochBeforeRelease = await epoch();
    const released = await reviewQuarantine(api, {
      tenantId: world.tenantA,
      principalId: world.reviewer,
      requestId: requestId(),
      versionId: world.versionQ,
      decision: 'release',
      reviewerCtx: 'ticket-42: false positive reviewed',
    });
    expect(released).toBe(true);
    expect(await statusOf(world.versionQ)).toBe('released');
    expect(await epoch()).toBe(epochBeforeRelease + 1);
    expect(await queryAs(world.member, world.tenantA, 'quarantine review topic')).toHaveLength(
      before.length,
    );

    // Convenience columns mirror the review; audit carries decision + reviewer.
    expect(await reviewColumns(world.versionQ)).toMatchObject({
      reviewed_by: world.reviewer,
      review_decision: 'release',
    });
    const events = await auditFor(world.reviewer, world.tenantA, 'version:review');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      principalId: world.reviewer,
      filters: {
        versionId: world.versionQ,
        documentId: world.docQ,
        decision: 'release',
        reviewerCtx: 'ticket-42: false positive reviewed',
      },
    });
    expect(Number(events[0]?.authEpoch)).toBe(epochBeforeRelease + 1);
  });

  it('keep: stays quarantined, audited, no epoch bump; re-scan re-quarantines after release', async () => {
    await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
    });

    const epochBeforeKeep = await epoch();
    const kept = await reviewQuarantine(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
      decision: 'keep',
      reviewerCtx: 'needs second human review',
    });
    expect(kept).toBe(true);
    expect(await statusOf(world.versionQ)).toBe('quarantined');
    // 'keep' changes no authorization-relevant state: epoch untouched.
    expect(await epoch()).toBe(epochBeforeKeep);
    expect(await queryAs(world.member, world.tenantA, 'quarantine review topic')).toEqual([]);
    expect(await reviewColumns(world.versionQ)).toMatchObject({
      reviewed_by: world.admin,
      review_decision: 'keep',
    });
    const events = await auditFor(world.admin, world.tenantA, 'version:review');
    expect(events).toHaveLength(1);
    expect(events[0]?.filters).toMatchObject({
      decision: 'keep',
      reviewerCtx: 'needs second human review',
    });

    // Re-scan re-quarantines: release first, then quarantineVersion again.
    await reviewQuarantine(api, {
      tenantId: world.tenantA,
      principalId: world.reviewer,
      requestId: requestId(),
      versionId: world.versionQ,
      decision: 'release',
    });
    expect(await statusOf(world.versionQ)).toBe('released');
    const reQuarantined = await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
    });
    expect(reQuarantined).toBe(true);
    expect(await statusOf(world.versionQ)).toBe('quarantined');
    expect(await queryAs(world.member, world.tenantA, 'quarantine review topic')).toEqual([]);
    // stale review decision cleared: the convenience columns reflect the
    // CURRENT (quarantined) cycle, the audit trail keeps the history.
    expect(await reviewColumns(world.versionQ)).toMatchObject({
      reviewed_by: null,
      reviewed_at: null,
      review_decision: null,
    });
  });

  it('a plain member cannot review: indistinguishable from a foreign/nonexistent version, no audit', async () => {
    await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
    });
    const auditCountBefore = (await auditFor(world.member, world.tenantA, 'version:review')).length;
    const epochBefore = await epoch();

    // Member on the tenant's own quarantined version.
    const asMember = await reviewQuarantine(api, {
      tenantId: world.tenantA,
      principalId: world.member,
      requestId: requestId(),
      versionId: world.versionQ,
      decision: 'release',
    });
    // Member on a random (nonexistent) version: identical false, identical shape.
    const asMemberRandom = await reviewQuarantine(api, {
      tenantId: world.tenantA,
      principalId: world.member,
      requestId: requestId(),
      versionId: randomUUID(),
      decision: 'release',
    });
    expect(asMember).toBe(false);
    expect(asMemberRandom).toBe(false);
    expect(await statusOf(world.versionQ)).toBe('quarantined');
    expect(await epoch()).toBe(epochBefore);
    // No audit event for the denied attempt (no enumerable signal).
    expect((await auditFor(world.member, world.tenantA, 'version:review')).length).toBe(
      auditCountBefore,
    );
  });

  it('a security_reviewer member and a tenant admin can review; a foreign-tenant member cannot', async () => {
    await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
    });

    // Foreign-tenant principal: no membership in tenant A -> MembershipError.
    await expect(
      reviewQuarantine(api, {
        tenantId: world.tenantA,
        principalId: world.outsider,
        requestId: requestId(),
        versionId: world.versionQ,
        decision: 'release',
      }),
    ).rejects.toThrow(/membership/i);

    // security_reviewer member works.
    const byReviewer = await reviewQuarantine(api, {
      tenantId: world.tenantA,
      principalId: world.reviewer,
      requestId: requestId(),
      versionId: world.versionQ,
      decision: 'release',
    });
    expect(byReviewer).toBe(true);
    expect(await statusOf(world.versionQ)).toBe('released');

    // Re-quarantine, then admin releases.
    await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
    });
    const byAdmin = await reviewQuarantine(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
      decision: 'release',
    });
    expect(byAdmin).toBe(true);
    expect(await statusOf(world.versionQ)).toBe('released');
  });

  it('listQuarantined: reviewer/admin see the tenant list; plain members see an empty list (no signal)', async () => {
    await quarantineVersion(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
      versionId: world.versionQ,
    });

    const asReviewer = await listQuarantined(api, {
      tenantId: world.tenantA,
      principalId: world.reviewer,
      requestId: requestId(),
    });
    expect(asReviewer).toHaveLength(1);
    expect(asReviewer[0]).toMatchObject({
      versionId: world.versionQ,
      documentId: world.docQ,
      status: 'quarantined',
      reviewDecision: null,
    });
    expect(typeof asReviewer[0]?.title).toBe('string');

    const asAdmin = await listQuarantined(api, {
      tenantId: world.tenantA,
      principalId: world.admin,
      requestId: requestId(),
    });
    expect(asAdmin).toHaveLength(1);

    // Plain member: empty list — identical to a tenant with nothing quarantined.
    const asMember = await listQuarantined(api, {
      tenantId: world.tenantA,
      principalId: world.member,
      requestId: requestId(),
    });
    expect(asMember).toEqual([]);

    // Foreign-tenant list attempt fails identically to no membership.
    await expect(
      listQuarantined(api, {
        tenantId: world.tenantB,
        principalId: world.reviewer,
        requestId: requestId(),
      }),
    ).rejects.toThrow(/membership/i);
  });
});

/** Trusted fixture world for the quarantine domain tests (superuser seeding;
 * RLS applies to the runtime roles under test, never to fixtures). */
async function seedQuarantineWorld(pool: Pool): Promise<{
  tenantA: string;
  tenantB: string;
  member: string;
  reviewer: string;
  admin: string;
  outsider: string;
  docQ: string;
  versionQ: string;
  docX: string;
  versionX: string;
}> {
  const tenantIds = await pool.query<{ tenant_id: string }>(
    `INSERT INTO securerag.tenants (tenant_id, name) VALUES
       (gen_random_uuid(), 'Quarantine Alpha'),
       (gen_random_uuid(), 'Quarantine Beta')
     RETURNING tenant_id`,
  );
  const tenantA = tenantIds.rows[0]?.tenant_id;
  const tenantB = tenantIds.rows[1]?.tenant_id;
  if (!tenantA || !tenantB) throw new Error('tenant seed failed');

  const principalIds = await pool.query<{ principal_id: string }>(
    `INSERT INTO securerag.principals
       (principal_id, provider, external_subject, display_name) VALUES
       (gen_random_uuid(), 'test-issuer', 'q-member-sub', 'Q Member'),
       (gen_random_uuid(), 'test-issuer', 'q-reviewer-sub', 'Q Reviewer'),
       (gen_random_uuid(), 'test-issuer', 'q-admin-sub', 'Q Admin'),
       (gen_random_uuid(), 'test-issuer', 'q-outsider-sub', 'Q Outsider')
     RETURNING principal_id`,
  );
  const [member, reviewer, admin, outsider] = principalIds.rows.map((r) => r.principal_id);
  if (!member || !reviewer || !admin || !outsider) throw new Error('principal seed failed');

  await pool.query(
    `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role) VALUES
       ($1, $2, 'member'),
       ($1, $3, 'security_reviewer'),
       ($1, $4, 'admin'),
       ($5, $6, 'member')`,
    [tenantA, member, reviewer, admin, tenantB, outsider],
  );
  await pool.query(
    `INSERT INTO securerag.tenant_admins (tenant_id, principal_id) VALUES ($1, $2)`,
    [tenantA, admin],
  );

  const docIds = await pool.query<{ document_id: string }>(
    `INSERT INTO securerag.documents (tenant_id, title) VALUES
       ($1, 'Quarantine review doc'),
       ($1, 'Normal working doc')
     RETURNING document_id`,
    [tenantA],
  );
  const docQ = docIds.rows[0]?.document_id;
  const docX = docIds.rows[1]?.document_id;
  if (!docQ || !docX) throw new Error('document seed failed');

  const versionQ = await seedVersion(pool, {
    tenantId: tenantA,
    documentId: docQ,
    versionNo: 1,
    sourceObjectKey: 'tenant-a/quarantine-v1.txt',
    contentHash: Buffer.from('deadbeef', 'hex'),
    status: 'valid',
    isCurrent: true,
  });
  const versionX = await seedVersion(pool, {
    tenantId: tenantA,
    documentId: docX,
    versionNo: 1,
    sourceObjectKey: 'tenant-a/working-v1.txt',
    contentHash: Buffer.from('cafebabe', 'hex'),
    status: 'valid',
    isCurrent: true,
  });

  for (const [versionId, texts] of [
    [versionQ, ['quarantine review topic alpha beta', 'quarantine review topic gamma delta']],
    [versionX, ['normal working topic alpha beta', 'normal working topic gamma delta']],
  ] as const) {
    for (let i = 0; i < texts.length; i += 1) {
      await seedChunk(pool, {
        tenantId: tenantA,
        versionId,
        chunkNo: i + 1,
        text: texts[i] ?? '',
        spanStart: 0,
        spanEnd: (texts[i] ?? '').length,
      });
    }
  }

  // The member can read docQ (and docX); reviewer/admin need no grants.
  for (const documentId of [docQ, docX]) {
    await seedGrant(pool, {
      tenantId: tenantA,
      documentId,
      subjectType: 'principal',
      subjectId: member,
      capability: 'read',
    });
  }

  return { tenantA, tenantB, member, reviewer, admin, outsider, docQ, versionQ, docX, versionX };
}
