import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  getTestDb,
  resetData,
  seedFixtures,
  seedGrant,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import {
  addGrant,
  listAudit,
  listGrants,
  removeGrant,
  toGrantListEntries,
  type GrantListEntry,
  type GrantRecord,
} from '../src/index.js';

/**
 * S3 ACL listing/management semantics (ADR-0003 amendment S3): listGrants is
 * manage-gated (manage grant OR tenant admin); foreign/nonexistent documents
 * are indistinguishable (null); the wire entry shape is the slim
 * {grantId, subjectType, subjectId, capability} entry; grant add/remove stay
 * idempotent, audited, epoch-bumped.
 */
describe('S3 ACL listing/management semantics on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    api = db.apiPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  const requestId = (): string => randomUUID();
  const epoch = async (): Promise<number> => {
    const { rows } = await db.superuserPool.query<{ epoch: string }>(
      'SELECT epoch FROM securerag.authorization_epoch',
    );
    return Number(rows[0]?.epoch);
  };
  const grantEvents = async (): Promise<unknown[]> => {
    const audit = await listAudit(api, {
      tenantId: world.tenantA.id,
      principalId: world.carol.id,
      requestId: requestId(),
    });
    return audit.filter((e) => e.eventType === 'grant:changed');
  };

  const baseParams = () => ({
    tenantId: world.tenantA.id,
    requestId: requestId(),
    documentId: world.docA.id,
  });

  it('listGrants is manage-gated: member without manage → null; read grant does not unlock; tenant admin lists', async () => {
    const member = { ...baseParams(), principalId: world.alice.id };
    expect(await listGrants(api, member)).toBeNull();

    await seedGrant(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId: world.alice.id,
      capability: 'read',
    });
    expect(await listGrants(api, member)).toBeNull();

    // Tenant admin without any manage grant lists (manage gate admin branch).
    const admin = { ...baseParams(), principalId: world.carol.id };
    expect(await listGrants(api, admin)).not.toBeNull();

    // A direct manage grant unlocks listing for a non-admin.
    await seedGrant(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId: world.alice.id,
      capability: 'manage',
    });
    expect(await listGrants(api, member)).not.toBeNull();
  });

  it('foreign and nonexistent documents are indistinguishable from denied (null)', async () => {
    const admin = { ...baseParams(), principalId: world.carol.id };
    const foreign = { ...admin, documentId: randomUUID() };
    const nonexistent = { ...admin, documentId: randomUUID() };
    expect(await listGrants(api, foreign)).toBeNull();
    expect(await listGrants(api, nonexistent)).toBeNull();
    expect(
      await addGrant(api, {
        ...foreign,
        subjectType: 'principal',
        subjectId: world.bob.id,
        capability: 'read',
      }),
    ).toBeNull();
    expect(
      await removeGrant(api, { ...nonexistent, grantId: randomUUID() }),
    ).toBe(false);
    expect(await epoch()).toBe(0);
  });

  it('grant lifecycle is idempotent: add → list → duplicate add (no-op) → remove → remove (false)', async () => {
    const admin = { ...baseParams(), principalId: world.carol.id };
    const before = await epoch();

    const added = (await addGrant(api, {
      ...admin,
      subjectType: 'principal',
      subjectId: world.bob.id,
      capability: 'read',
    })) as GrantRecord;
    expect(added.grantId).toBeTruthy();
    expect(await epoch()).toBe(before + 1);

    const grants = (await listGrants(api, admin)) as GrantRecord[];
    expect(grants).toHaveLength(1);
    expect(grants[0]).toMatchObject({
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId: world.bob.id,
      capability: 'read',
    });

    // Duplicate grant: silent no-op — no bump, no audit event.
    const duplicate = await addGrant(api, {
      ...admin,
      subjectType: 'principal',
      subjectId: world.bob.id,
      capability: 'read',
    });
    expect(duplicate).toBeNull();
    expect(await epoch()).toBe(before + 1);
    expect((await grantEvents()).length).toBe(1);

    expect(await removeGrant(api, { ...admin, grantId: added.grantId })).toBe(true);
    expect(await epoch()).toBe(before + 2);
    expect(await listGrants(api, admin)).toEqual([]);
    expect(await removeGrant(api, { ...admin, grantId: added.grantId })).toBe(false);
    expect((await grantEvents()).length).toBe(2);
  });

  it('toGrantListEntries maps to the slim wire shape (no tenant/document ids, no timestamps)', async () => {
    const admin = { ...baseParams(), principalId: world.carol.id };
    const added = (await addGrant(api, {
      ...admin,
      subjectType: 'principal',
      subjectId: world.bob.id,
      capability: 'read',
    })) as GrantRecord;
    await seedGrant(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'tenant_role',
      subjectId: 'member',
      capability: 'manage',
    });
    const grants = (await listGrants(api, admin)) as GrantRecord[];
    const entries: GrantListEntry[] = toGrantListEntries(grants);
    expect(entries).toHaveLength(2);
    for (const entry of entries) {
      expect(Object.keys(entry).sort()).toEqual([
        'capability',
        'grantId',
        'subjectId',
        'subjectType',
      ]);
    }
    const own = entries.find((e) => e.grantId === added.grantId);
    expect(own).toEqual({
      grantId: added.grantId,
      subjectType: 'principal',
      subjectId: world.bob.id,
      capability: 'read',
    });
  });

  it('a member without manage cannot add/remove/list — identical null/false to a foreign document', async () => {
    const member = { ...baseParams(), principalId: world.alice.id };
    const before = await epoch();
    expect(
      await addGrant(api, {
        ...member,
        subjectType: 'principal',
        subjectId: world.bob.id,
        capability: 'read',
      }),
    ).toBeNull();
    expect(await listGrants(api, member)).toBeNull();
    expect(await removeGrant(api, { ...member, grantId: randomUUID() })).toBe(false);
    expect(await epoch()).toBe(before);
    expect(await grantEvents()).toEqual([]);
  });
});
