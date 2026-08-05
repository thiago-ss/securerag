import type { Pool, PoolClient } from 'pg';
import { withSecurityContext, type SecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import type { SecurityParams } from './types.js';

/**
 * Tenant-scoped group management (S1). Writes are ADMIN-ONLY, enforced by the
 * groups_admin_scope / group_memberships_scope RLS policies (migration 0005):
 * members cannot create, rename, delete, or modify groups or group memberships
 * — a member's write matches zero rows or fails WITH CHECK, indistinguishable
 * from a foreign or nonexistent target. A member may read ONLY their own
 * group_membership rows (the retrieval grant predicate resolves through the
 * self branch). Every successful write bumps the authorization epoch and
 * appends a group:changed audit event in the same transaction.
 */

export interface GroupRecord {
  tenantId: string;
  groupId: string;
  name: string;
  createdAt: Date;
}

export interface GroupMembershipRecord {
  tenantId: string;
  groupId: string;
  principalId: string;
}

interface GroupRow {
  tenant_id: string;
  group_id: string;
  name: string;
  created_at: Date;
}

function toGroup(row: GroupRow): GroupRecord {
  return { tenantId: row.tenant_id, groupId: row.group_id, name: row.name, createdAt: row.created_at };
}

/** Groups of the verified tenant; RLS shows them only to active admins. */
export async function listGroups(pool: Pool, params: SecurityParams): Promise<GroupRecord[]> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<GroupRow>(
      `SELECT tenant_id, group_id, name, created_at
         FROM securerag.groups
        WHERE tenant_id = securerag.ctx_tenant_id()
        ORDER BY name, group_id`,
    );
    return rows.map(toGroup);
  });
}

export interface GroupParams extends SecurityParams {
  groupId: string;
}

/** Admin-only: create a group in the verified tenant. */
export async function createGroup(
  pool: Pool,
  params: SecurityParams & { name: string },
): Promise<GroupRecord> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<GroupRow>(
      `INSERT INTO securerag.groups (tenant_id, name)
       VALUES (securerag.ctx_tenant_id(), $1)
       RETURNING tenant_id, group_id, name, created_at`,
      [params.name],
    );
    const row = rows[0];
    if (row === undefined) throw new Error('createGroup returned no row');
    await bumpAndAudit(client, ctx, { groupId: row.group_id, name: row.name });
    return toGroup(row);
  });
}

/** Admin-only: delete a group and its memberships. False for invisible groups. */
export async function deleteGroup(pool: Pool, params: GroupParams): Promise<boolean> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    await client.query(
      `DELETE FROM securerag.group_memberships
        WHERE tenant_id = securerag.ctx_tenant_id() AND group_id = $1`,
      [params.groupId],
    );
    const { rows } = await client.query<{ group_id: string }>(
      `DELETE FROM securerag.groups
        WHERE tenant_id = securerag.ctx_tenant_id() AND group_id = $1
        RETURNING group_id`,
      [params.groupId],
    );
    if (rows[0] === undefined) return false;
    await bumpAndAudit(client, ctx, { groupId: params.groupId });
    return true;
  });
}

export interface GroupMemberParams extends GroupParams {
  targetPrincipalId: string;
}

/** Admin-only: add a principal to a group (FK violations propagate — foreign
 * principals/groups fail identically to invisible ones at the API). */
export async function addGroupMember(pool: Pool, params: GroupMemberParams): Promise<void> {
  await withSecurityContext(pool, params, async (client, ctx) => {
    await client.query(
      `INSERT INTO securerag.group_memberships (tenant_id, group_id, principal_id)
       VALUES (securerag.ctx_tenant_id(), $1, $2)`,
      [params.groupId, params.targetPrincipalId],
    );
    await bumpAndAudit(client, ctx, {
      groupId: params.groupId,
      principalId: params.targetPrincipalId,
    });
  });
}

/** Admin-only: remove a principal from a group. False when not a member. */
export async function removeGroupMember(pool: Pool, params: GroupMemberParams): Promise<boolean> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<{ principal_id: string }>(
      `DELETE FROM securerag.group_memberships
        WHERE tenant_id = securerag.ctx_tenant_id()
          AND group_id = $1 AND principal_id = $2
        RETURNING principal_id`,
      [params.groupId, params.targetPrincipalId],
    );
    if (rows[0] === undefined) return false;
    await bumpAndAudit(client, ctx, {
      groupId: params.groupId,
      principalId: params.targetPrincipalId,
    });
    return true;
  });
}

async function bumpAndAudit(
  client: PoolClient,
  ctx: SecurityContext,
  filters: Record<string, unknown>,
): Promise<void> {
  await client.query('SELECT securerag.bump_authorization_epoch()');
  await appendAudit({
    client,
    event: {
      eventType: 'group:changed',
      requestId: ctx.requestId,
      principalId: ctx.principalId,
      membershipId: ctx.membershipId,
      authEpoch: ctx.authEpoch,
      filters,
    },
  });
}
