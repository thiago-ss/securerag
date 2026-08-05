import type { Pool, PoolClient } from 'pg';
import {
  GUC_PRINCIPAL_ID,
  type SecurityContext,
  setContext,
  verifyContext,
} from './context.js';
import { MembershipError } from './errors.js';

export interface Membership {
  tenantId: string;
  membershipId: string;
  role: string;
}

export interface IdentityResult<T> {
  result: T;
  memberships: Membership[];
}

export interface SecurityContextParams {
  principalId: string;
  tenantId: string;
  requestId: string;
}

interface AcquiredClient {
  client: PoolClient;
  release: () => void;
}

/**
 * Check out a client when given a Pool, or use the caller's client as-is.
 * A caller-owned client is never released here; a pooled client is always
 * released in the caller's finally block.
 */
async function acquire(poolOrClient: Pool | PoolClient): Promise<AcquiredClient> {
  if (typeof (poolOrClient as Pool).connect === 'function') {
    const client = await (poolOrClient as Pool).connect();
    return { client, release: () => client.release() };
  }
  return { client: poolOrClient as PoolClient, release: () => {} };
}

/**
 * Stage 1 of the two-stage bootstrap (ADR-0003): verify the authenticated
 * principal transaction-locally. Sets ONLY `securerag.principal_id` via
 * parameterized `set_config(..., true)`; the membership-scoped RLS policy then
 * reveals that principal's own rows and nothing else. NOTE (S1): the policy's
 * USING contains an admin OR-branch (needed by admin management flows), which
 * would surface other principals' rows in the bootstrap listing for admins —
 * so the bootstrap query pins `principal_id = ctx_principal_id()` itself.
 * This is identity bootstrap (the documented stage-1 exception), deterministic,
 * and keeps the admin view intact for stage-2 withSecurityContext flows.
 * A requested tenant is an untrusted candidate, never authority — membership
 * metadata is returned to the caller so it can pick a tenant, but no tenant
 * context is established.
 *
 * Returns the callback's value plus the principal's active memberships
 * (SELECT tenant_id, membership_id, role FROM tenant_memberships WHERE
 * is_active, filtered by RLS). Commit on success, rollback on error; the raw
 * client never escapes the callback.
 */
export async function withIdentityContext<T>(
  poolOrClient: Pool | PoolClient,
  principalId: string,
  fn: (client: PoolClient) => Promise<T>,
): Promise<IdentityResult<T>> {
  const { client, release } = await acquire(poolOrClient);
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1, $2, true)', [GUC_PRINCIPAL_ID, principalId]);
    const result = await fn(client);
    const { rows } = await client.query<{
      tenant_id: string;
      membership_id: string;
      role: string;
    }>(
      `SELECT tenant_id, membership_id, role
         FROM securerag.tenant_memberships
        WHERE is_active
          AND principal_id = securerag.ctx_principal_id()`,
    );
    const memberships = rows.map((r) => ({
      tenantId: r.tenant_id,
      membershipId: r.membership_id,
      role: r.role,
    }));
    await client.query('COMMIT');
    return { result, memberships };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    release();
  }
}

/**
 * Stage 2 of the two-stage bootstrap (ADR-0003): establish the full verified
 * security context inside one transaction. Flow:
 *
 * 1. BEGIN; set `securerag.principal_id` transaction-locally.
 * 2. VERIFY an ACTIVE membership for `tenantId` through the membership-scoped
 *    RLS policy. Foreign, nonexistent, and deactivated tenants all yield zero
 *    rows and an indistinguishable MembershipError (no tenant enumeration).
 * 3. Set tenant_id, membership_id, request_id, and auth_epoch (read from
 *    authorization_epoch) via parameterized `set_config(..., true)`.
 * 4. verifyContext: all five GUCs must be set and well-formed.
 * 5. Run fn(client, ctx); COMMIT on success, ROLLBACK on any error.
 *
 * The pooled client is never exposed outside the callback; the raw client is
 * always released. Nothing is ever set at session level.
 */
export async function withSecurityContext<T>(
  poolOrClient: Pool | PoolClient,
  params: SecurityContextParams,
  fn: (client: PoolClient, ctx: SecurityContext) => Promise<T>,
): Promise<T> {
  const { client, release } = await acquire(poolOrClient);
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1, $2, true)', [
      GUC_PRINCIPAL_ID,
      params.principalId,
    ]);

    const membership = await client.query<{
      tenant_id: string;
      membership_id: string;
    }>(
      `SELECT tenant_id, membership_id
         FROM securerag.tenant_memberships
        WHERE tenant_id = $1 AND is_active
        LIMIT 1`,
      [params.tenantId],
    );
    const row = membership.rows[0];
    if (!row) throw new MembershipError();

    const epoch = await client.query<{ epoch: string }>(
      `SELECT epoch FROM securerag.authorization_epoch`,
    );
    const epochValue = epoch.rows[0]?.epoch;
    if (epochValue === undefined) {
      throw new Error('authorization_epoch is uninitialized');
    }

    await setContext(client, {
      tenantId: params.tenantId,
      principalId: params.principalId,
      membershipId: row.membership_id,
      requestId: params.requestId,
      authEpoch: epochValue,
    });

    const ctx = await verifyContext(client);
    const result = await fn(client, ctx);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    release();
  }
}
