import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { withSecurityContext } from '@securerag/security';
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
  addGroupMember,
  addMembership,
  canManage,
  createGroup,
  deleteGroup,
  getPrincipalByExternalId,
  listAudit,
  listGrants,
  listGroups,
  listMemberships,
  listTenantMembers,
  removeGrant,
  removeGroupMember,
  removeMembership,
  setMembershipActive,
  setMembershipRole,
  upsertPrincipal,
} from '../src/index.js';

describe('S1 admin domain: identity, memberships, groups, grants on real runtime roles', () => {
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

  describe('identity', () => {
    it('upsertPrincipal is idempotent on (provider, external_subject) and never exposes existence', async () => {
      const first = await upsertPrincipal(api, {
        provider: 'test-issuer',
        externalSubject: 'fresh-sub',
        displayName: 'Fresh One',
      });
      const second = await upsertPrincipal(api, {
        provider: 'test-issuer',
        externalSubject: 'fresh-sub',
        displayName: 'Fresh Two',
      });
      expect(second).toBe(first);
      const { rows } = await db.superuserPool.query<{ display_name: string; n: number }>(
        `SELECT display_name, count(*)::int AS n FROM securerag.principals
          WHERE provider = 'test-issuer' AND external_subject = 'fresh-sub'
          GROUP BY display_name`,
      );
      expect(rows).toEqual([{ display_name: 'Fresh Two', n: 1 }]);
    });

    it('upsertPrincipal maps the seeded corpus identities to the same principals', async () => {
      const id = await upsertPrincipal(api, {
        provider: 'test-issuer',
        externalSubject: 'alice-sub',
        displayName: 'Alice',
      });
      expect(id).toBe(world.alice.id);
    });

    it('getPrincipalByExternalId resolves ONLY the caller\'s own identity', async () => {
      const own = await getPrincipalByExternalId(
        api,
        { provider: 'test-issuer', externalSubject: 'alice-sub', displayName: 'Alice' },
        { principalId: world.alice.id },
      );
      expect(own?.principalId).toBe(world.alice.id);

      const foreign = await getPrincipalByExternalId(
        api,
        { provider: 'test-issuer', externalSubject: 'bob-sub', displayName: 'Bob' },
        { principalId: world.alice.id },
      );
      expect(foreign).toBeNull();

      const unknown = await getPrincipalByExternalId(
        api,
        { provider: 'test-issuer', externalSubject: 'nobody-sub', displayName: 'N' },
        { principalId: world.alice.id },
      );
      expect(unknown).toBeNull();
    });
  });

  describe('memberships', () => {
    it('listMemberships returns only the principal\'s own active memberships', async () => {
      const alice = await listMemberships(api, world.alice.id);
      expect(alice).toHaveLength(1);
      expect(alice[0]).toMatchObject({ tenantId: world.tenantA.id, role: 'member' });
      expect(await listMemberships(api, world.dave.id)).toEqual([]);
    });

    it('listTenantMembers: admin sees all rows; a plain member sees only their own', async () => {
      const adminView = await listTenantMembers(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
      });
      expect(adminView.map((m) => m.principalId).sort()).toEqual(
        [world.alice.id, world.carol.id].sort(),
      );
      const memberView = await listTenantMembers(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
      });
      expect(memberView.map((m) => m.principalId)).toEqual([world.alice.id]);
    });

    it('admin adds a member: row created, mirror unchanged, epoch bumped, audited', async () => {
      const before = await epoch();
      const added = await addMembership(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
        role: 'member',
      });
      expect(added).toMatchObject({
        tenantId: world.tenantA.id,
        principalId: world.dave.id,
        role: 'member',
        isActive: true,
      });
      expect(await epoch()).toBe(before + 1);

      const dave = await listMemberships(api, world.dave.id);
      expect(dave).toHaveLength(1);
      expect(dave[0]).toMatchObject({ tenantId: world.tenantA.id });

      const audit = await listAudit(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
      });
      const event = audit.find((e) => e.eventType === 'membership:changed');
      expect(event).toBeDefined();
      expect(event?.filters).toMatchObject({
        targetPrincipalId: world.dave.id,
        role: 'member',
      });
      // Stamped with the POST-bump epoch (the era the change produced).
      expect(event?.authEpoch).toBe(String(before + 1));
    });

    it('promotion to admin creates the mirror row; demotion/removal removes it', async () => {
      await addMembership(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
        role: 'member',
      });
      await setMembershipRole(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
        role: 'admin',
      });
      const mirrored = await db.superuserPool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM securerag.tenant_admins
          WHERE tenant_id = $1 AND principal_id = $2`,
        [world.tenantA.id, world.dave.id],
      );
      expect(mirrored.rows[0]?.n).toBe(1);

      const adminContext = await withSecurityContext(
        api,
        { tenantId: world.tenantA.id, principalId: world.dave.id, requestId: requestId() },
        async (c) => {
          const { rows } = await c.query<{ ok: boolean }>(
            `SELECT securerag.ctx_principal_is_admin($1) AS ok`,
            [world.tenantA.id],
          );
          return rows[0]?.ok;
        },
      );
      expect(adminContext).toBe(true);

      await setMembershipRole(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
        role: 'member',
      });
      const unmirrored = await db.superuserPool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM securerag.tenant_admins
          WHERE tenant_id = $1 AND principal_id = $2`,
        [world.tenantA.id, world.dave.id],
      );
      expect(unmirrored.rows[0]?.n).toBe(0);

      await removeMembership(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
      });
      expect(await listMemberships(api, world.dave.id)).toEqual([]);
    });

    it('deactivating an admin removes the mirror row and revokes admin power', async () => {
      await addMembership(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
        role: 'admin',
      });
      await setMembershipActive(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
        isActive: false,
      });
      const mirrored = await db.superuserPool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM securerag.tenant_admins
          WHERE tenant_id = $1 AND principal_id = $2`,
        [world.tenantA.id, world.dave.id],
      );
      expect(mirrored.rows[0]?.n).toBe(0);
    });

    it('a member cannot add, promote, demote, deactivate, or remove (RLS, indistinguishable)', async () => {
      const member = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
      };
      await expect(
        addMembership(api, { ...member, role: 'member' }),
      ).rejects.toThrow(/row-level security/);
      expect(await setMembershipRole(api, { ...member, role: 'admin' })).toBe(false);
      expect(await setMembershipActive(api, { ...member, isActive: false })).toBe(false);
      expect(await removeMembership(api, member)).toBe(false);
      // nothing changed, nothing audited, epoch untouched
      expect(await listMemberships(api, world.dave.id)).toEqual([]);
      expect(await epoch()).toBe(0);
    });

    it('self-targeting is refused (no self-promote / self-deactivate / self-remove)', async () => {
      const carol = {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.carol.id,
      };
      expect(await setMembershipRole(api, { ...carol, role: 'member' })).toBe(false);
      expect(await setMembershipActive(api, { ...carol, isActive: false })).toBe(false);
      expect(await removeMembership(api, carol)).toBe(false);
      expect(await epoch()).toBe(0);
    });

    it('foreign and nonexistent targets are indistinguishable from denied writes', async () => {
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: randomUUID(),
      };
      expect(await setMembershipRole(api, { ...params, role: 'admin' })).toBe(false);
      expect(await removeMembership(api, params)).toBe(false);
      expect(await epoch()).toBe(0);
    });

    it('staleness: a later withSecurityContext call reads the bumped epoch fresh', async () => {
      const before = await epoch();
      const first = await withSecurityContext(
        api,
        { tenantId: world.tenantA.id, principalId: world.carol.id, requestId: requestId() },
        async (_c, ctx) => ctx.authEpoch,
      );
      expect(Number(first)).toBe(before);
      await addMembership(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        targetPrincipalId: world.dave.id,
        role: 'member',
      });
      const second = await withSecurityContext(
        api,
        { tenantId: world.tenantA.id, principalId: world.carol.id, requestId: requestId() },
        async (_c, ctx) => ctx.authEpoch,
      );
      expect(Number(second)).toBe(before + 1);
    });
  });

  describe('groups', () => {
    it('admin creates and lists groups; members see an empty list', async () => {
      const group = await createGroup(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        name: 'Engineering',
      });
      expect(group.name).toBe('Engineering');
      const adminView = await listGroups(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
      });
      expect(adminView.map((g) => g.name)).toEqual(['Engineering']);
      const memberView = await listGroups(api, {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
      });
      expect(memberView).toEqual([]);
    });

    it('group membership add/remove by admin; removal is idempotent-safe', async () => {
      const group = await createGroup(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        name: 'Alpha Group',
      });
      await addGroupMember(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        groupId: group.groupId,
        targetPrincipalId: world.alice.id,
      });
      const { rows } = await db.superuserPool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM securerag.group_memberships
          WHERE tenant_id = $1 AND group_id = $2`,
        [world.tenantA.id, group.groupId],
      );
      expect(rows[0]?.n).toBe(1);
      expect(
        await removeGroupMember(api, {
          tenantId: world.tenantA.id,
          principalId: world.carol.id,
          requestId: requestId(),
          groupId: group.groupId,
          targetPrincipalId: world.alice.id,
        }),
      ).toBe(true);
      expect(
        await removeGroupMember(api, {
          tenantId: world.tenantA.id,
          principalId: world.carol.id,
          requestId: requestId(),
          groupId: group.groupId,
          targetPrincipalId: world.alice.id,
        }),
      ).toBe(false);
    });

    it('members cannot create groups, add members, or delete groups (RLS, audited silence)', async () => {
      const before = await epoch();
      const member = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
      };
      await expect(
        createGroup(api, { ...member, name: 'Sneaky' }),
      ).rejects.toThrow(/row-level security/);
      const group = await createGroup(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        name: 'Legit',
      });
      await expect(
        addGroupMember(api, {
          ...member,
          groupId: group.groupId,
          targetPrincipalId: world.bob.id,
        }),
      ).rejects.toThrow(/row-level security/);
      expect(
        await deleteGroup(api, {
          ...member,
          groupId: group.groupId,
        }),
      ).toBe(false);
      const audit = await listAudit(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
      });
      expect(audit.filter((e) => e.eventType === 'group:changed')).toHaveLength(1);
      expect(await epoch()).toBe(before + 1);
    });

    it('group writes bump the epoch and are audited with redacted metadata', async () => {
      const before = await epoch();
      const group = await createGroup(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        name: 'Audited Group',
      });
      expect(await epoch()).toBe(before + 1);
      expect(await deleteGroup(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        groupId: group.groupId,
      })).toBe(true);
      expect(await epoch()).toBe(before + 2);
      const audit = await listAudit(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
      });
      const events = audit.filter((e) => e.eventType === 'group:changed');
      expect(events).toHaveLength(2);
      expect(events[1]?.filters).toMatchObject({ groupId: group.groupId });
      // Newest-first ordering: the most recent write carries before+2.
      expect(events[0]?.authEpoch).toBe(String(before + 2));
      expect(events[1]?.authEpoch).toBe(String(before + 1));
    });
  });

  describe('grants', () => {
    it('canManage: tenant admin without any grant manages; plain member without manage cannot', async () => {
      expect(
        await canManage(api, {
          tenantId: world.tenantA.id,
          principalId: world.carol.id,
          requestId: requestId(),
          documentId: world.docA.id,
        }),
      ).toBe(true);
      expect(
        await canManage(api, {
          tenantId: world.tenantA.id,
          principalId: world.alice.id,
          requestId: requestId(),
          documentId: world.docA.id,
        }),
      ).toBe(false);
    });

    it('a manage grant unlocks management for a non-admin; read/write grants do not', async () => {
      await seedGrant(db.superuserPool, {
        tenantId: world.tenantA.id,
        documentId: world.docA.id,
        subjectType: 'principal',
        subjectId: world.alice.id,
        capability: 'read',
      });
      expect(
        await canManage(api, {
          tenantId: world.tenantA.id,
          principalId: world.alice.id,
          requestId: requestId(),
          documentId: world.docA.id,
        }),
      ).toBe(false);
      await seedGrant(db.superuserPool, {
        tenantId: world.tenantA.id,
        documentId: world.docA.id,
        subjectType: 'principal',
        subjectId: world.alice.id,
        capability: 'manage',
      });
      expect(
        await canManage(api, {
          tenantId: world.tenantA.id,
          principalId: world.alice.id,
          requestId: requestId(),
          documentId: world.docA.id,
        }),
      ).toBe(true);
    });

    it('addGrant/listGrants/removeGrant are manage-gated, bumped, and audited', async () => {
      const before = await epoch();
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      expect(
        await addGrant(api, {
          ...params,
          subjectType: 'principal',
          subjectId: world.bob.id,
          capability: 'read',
        }),
      ).toBeTruthy();
      expect(await epoch()).toBe(before + 1);

      const grants = await listGrants(api, params);
      expect(grants).toHaveLength(1);
      expect(grants?.[0]).toMatchObject({
        documentId: world.docA.id,
        subjectType: 'principal',
        subjectId: world.bob.id,
        capability: 'read',
      });

      expect(
        await removeGrant(api, { ...params, grantId: grants?.[0]?.grantId as string }),
      ).toBe(true);
      expect(await epoch()).toBe(before + 2);
      expect(await listGrants(api, params)).toEqual([]);

      const audit = await listAudit(api, {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
      });
      expect(audit.filter((e) => e.eventType === 'grant:changed')).toHaveLength(2);
    });

    it('a non-manager gets the same false/null as a foreign document (no oracle)', async () => {
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      expect(
        await addGrant(api, {
          ...params,
          subjectType: 'principal',
          subjectId: world.bob.id,
          capability: 'read',
        }),
      ).toBeNull();
      expect(await listGrants(api, params)).toBeNull();
      expect(
        await removeGrant(api, { ...params, grantId: randomUUID() }),
      ).toBe(false);
      expect(await epoch()).toBe(0);

      const foreignDoc = {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        documentId: randomUUID(),
      };
      expect(
        await addGrant(api, {
          ...foreignDoc,
          subjectType: 'principal',
          subjectId: world.bob.id,
          capability: 'read',
        }),
      ).toBeNull();
      expect(await listGrants(api, foreignDoc)).toBeNull();
    });

    it('duplicate grants are a silent no-op (no bump, no audit)', async () => {
      const params = {
        tenantId: world.tenantA.id,
        principalId: world.carol.id,
        requestId: requestId(),
        documentId: world.docA.id,
      };
      const write = {
        ...params,
        subjectType: 'principal' as const,
        subjectId: world.bob.id,
        capability: 'read' as const,
      };
      expect(await addGrant(api, write)).toBeTruthy();
      const before = await epoch();
      expect(await addGrant(api, write)).toBeNull();
      expect(await epoch()).toBe(before);
    });
  });
});
