import type { Pool } from 'pg';
import { withIdentityContext, withSecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import type { SecurityParams } from './types.js';

/**
 * Tenant membership management (S1). Writes are ADMIN-ONLY, enforced
 * deterministically by the memberships_access RLS policy (WITH CHECK requires
 * ctx_principal_is_admin; ADR-0003/0013) — a member's write matches zero rows
 * or fails the policy and the caller observes no difference from a foreign or
 * nonexistent target. Every successful write: maintains the tenant_admins
 * mirror atomically, bumps the authorization epoch (ADR-0013) and appends a
 * membership:changed audit event, all in ONE transaction.
 *
 * Self-targeting is refused at the service seam for role/active/removal
 * writes (no principal may self-promote, self-deactivate, or self-remove —
 * the RLS kernel already blocks members; this closes the admin self-demote
 * path deterministically).
 */

export type TenantRole = 'admin' | 'member' | 'security_reviewer';

export interface MembershipRecord {
  tenantId: string;
  membershipId: string;
  principalId: string;
  role: TenantRole;
  isActive: boolean;
  joinedAt: Date;
}

export interface MembershipListRecord {
  tenantId: string;
  membershipId: string;
  role: TenantRole;
}

interface MembershipRow {
  tenant_id: string;
  membership_id: string;
  principal_id: string;
  role: string;
  is_active: boolean;
  joined_at: Date;
}

function toRecord(row: MembershipRow): MembershipRecord {
  return {
    tenantId: row.tenant_id,
    membershipId: row.membership_id,
    principalId: row.principal_id,
    role: row.role as TenantRole,
    isActive: row.is_active,
    joinedAt: row.joined_at,
  };
}

/** The principal's own active memberships (identity bootstrap, RLS-scoped). */
export async function listMemberships(pool: Pool, principalId: string): Promise<MembershipListRecord[]> {
  const identity = await withIdentityContext(pool, principalId, async () => undefined);
  return identity.memberships.map((m) => ({ ...m, role: m.role as TenantRole }));
}

/**
 * Tenant membership view. RLS shows other principals' rows ONLY to an active
 * admin of the tenant; a plain member sees exactly their own row. Never an
 * enumeration surface (default deny).
 */
export async function listTenantMembers(pool: Pool, params: SecurityParams): Promise<MembershipRecord[]> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<MembershipRow>(
      `SELECT tenant_id, membership_id, principal_id, role, is_active, joined_at
         FROM securerag.tenant_memberships
        WHERE tenant_id = securerag.ctx_tenant_id()
        ORDER BY principal_id`,
    );
    return rows.map(toRecord);
  });
}

export interface MembershipChangeParams extends SecurityParams {
  targetPrincipalId: string;
}

/** Admin-only: provision a membership (role admin/member/security_reviewer). */
export async function addMembership(
  pool: Pool,
  params: MembershipChangeParams & { role: TenantRole },
): Promise<MembershipRecord> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<MembershipRow>(
      `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role)
       VALUES (securerag.ctx_tenant_id(), $1, $2)
       RETURNING tenant_id, membership_id, principal_id, role, is_active, joined_at`,
      [params.targetPrincipalId, params.role],
    );
    const row = rows[0];
    if (row === undefined) throw new Error('addMembership returned no row');
    await syncAdminMirror(client, params.targetPrincipalId, params.role === 'admin');
    await bumpAndAudit(client, ctx, {
      targetPrincipalId: params.targetPrincipalId,
      role: params.role,
    });
    return toRecord(row);
  });
}

/** Admin-only: change a membership's role (promote/demote). Returns false for
 * invisible targets and for self-targeting (no self-promote/self-demote). */
export async function setMembershipRole(
  pool: Pool,
  params: MembershipChangeParams & { role: TenantRole },
): Promise<boolean> {
  if (params.targetPrincipalId === params.principalId) return false;
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<MembershipRow>(
      `UPDATE securerag.tenant_memberships SET role = $1
        WHERE tenant_id = securerag.ctx_tenant_id() AND principal_id = $2
        RETURNING tenant_id, membership_id, principal_id, role, is_active, joined_at`,
      [params.role, params.targetPrincipalId],
    );
    const row = rows[0];
    if (row === undefined) return false;
    await syncAdminMirror(client, params.targetPrincipalId, params.role === 'admin');
    await bumpAndAudit(client, ctx, {
      targetPrincipalId: params.targetPrincipalId,
      role: params.role,
    });
    return true;
  });
}

/** Admin-only: activate/deactivate a membership. Returns false for invisible
 * targets and for self-targeting (no self-deactivation). */
export async function setMembershipActive(
  pool: Pool,
  params: MembershipChangeParams & { isActive: boolean },
): Promise<boolean> {
  if (params.targetPrincipalId === params.principalId) return false;
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<MembershipRow>(
      `UPDATE securerag.tenant_memberships SET is_active = $1
        WHERE tenant_id = securerag.ctx_tenant_id() AND principal_id = $2
        RETURNING tenant_id, membership_id, principal_id, role, is_active, joined_at`,
      [params.isActive, params.targetPrincipalId],
    );
    const row = rows[0];
    if (row === undefined) return false;
    await syncAdminMirror(client, params.targetPrincipalId, row.role === 'admin' && params.isActive);
    await bumpAndAudit(client, ctx, {
      targetPrincipalId: params.targetPrincipalId,
      isActive: params.isActive,
    });
    return true;
  });
}

/** Admin-only: remove a membership. Returns false for invisible targets and
 * for self-targeting (no self-removal). */
export async function removeMembership(
  pool: Pool,
  params: MembershipChangeParams,
): Promise<boolean> {
  if (params.targetPrincipalId === params.principalId) return false;
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<{ principal_id: string }>(
      `DELETE FROM securerag.tenant_memberships
        WHERE tenant_id = securerag.ctx_tenant_id() AND principal_id = $1
        RETURNING principal_id`,
      [params.targetPrincipalId],
    );
    if (rows[0] === undefined) return false;
    await syncAdminMirror(client, params.targetPrincipalId, false);
    await bumpAndAudit(client, ctx, { targetPrincipalId: params.targetPrincipalId });
    return true;
  });
}

/**
 * Maintain the tenant_admins mirror atomically with the membership change
 * (ADR-0003): a row exists iff the principal is an active admin. INSERT is
 * idempotent; DELETE is a no-op when absent. Both are RLS-gated for the
 * acting admin (tenant_admin_scope policy, no recursion).
 */
async function syncAdminMirror(
  client: import('pg').PoolClient,
  targetPrincipalId: string,
  isAdmin: boolean,
): Promise<void> {
  if (isAdmin) {
    await client.query(
      `INSERT INTO securerag.tenant_admins (tenant_id, principal_id)
       VALUES (securerag.ctx_tenant_id(), $1)
       ON CONFLICT DO NOTHING`,
      [targetPrincipalId],
    );
  } else {
    await client.query(
      `DELETE FROM securerag.tenant_admins
        WHERE tenant_id = securerag.ctx_tenant_id() AND principal_id = $1`,
      [targetPrincipalId],
    );
  }
}

/** Epoch bump + audited membership:changed event in the SAME transaction.
 * The audit event is stamped with the POST-bump epoch so epoch-correlated
 * reconstruction attributes the change to the era it produced. */
async function bumpAndAudit(
  client: import('pg').PoolClient,
  ctx: import('@securerag/security').SecurityContext,
  filters: Record<string, unknown>,
): Promise<void> {
  const bumped = await client.query<{ epoch: string }>(
    'SELECT securerag.bump_authorization_epoch() AS epoch',
  );
  await appendAudit({
    client,
    event: {
      eventType: 'membership:changed',
      requestId: ctx.requestId,
      principalId: ctx.principalId,
      membershipId: ctx.membershipId,
      authEpoch: bumped.rows[0]?.epoch ?? ctx.authEpoch,
      filters,
    },
  });
}
