import type { Pool, PoolClient } from 'pg';
import { SecurityContextError } from './errors.js';

/**
 * Verified, transaction-local security context. All values are strings because
 * PostgreSQL returns bigint (authEpoch) and uuid values as text over the wire;
 * cast at the use site (e.g. `Number(authEpoch)`).
 */
export interface SecurityContext {
  tenantId: string;
  principalId: string;
  membershipId: string;
  requestId: string;
  authEpoch: string;
}

export const GUC_TENANT_ID = 'securerag.tenant_id';
export const GUC_PRINCIPAL_ID = 'securerag.principal_id';
export const GUC_MEMBERSHIP_ID = 'securerag.membership_id';
export const GUC_REQUEST_ID = 'securerag.request_id';
export const GUC_AUTH_EPOCH = 'securerag.auth_epoch';

export const CONTEXT_GUCS = [
  GUC_TENANT_ID,
  GUC_PRINCIPAL_ID,
  GUC_MEMBERSHIP_ID,
  GUC_REQUEST_ID,
  GUC_AUTH_EPOCH,
] as const;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const EPOCH_RE = /^\d+$/;

/**
 * Set the full verified context transaction-locally. `set_config(..., true)`
 * scopes every value to the current transaction; nothing ever reaches the
 * session level. Must run inside an open transaction on a single connection
 * (a Pool may be passed, but the settings only survive within one transaction
 * on the checked-out client).
 */
export async function setContext(
  client: PoolClient | Pool,
  ctx: SecurityContext,
): Promise<void> {
  await client.query('SELECT set_config($1, $2, true)', [GUC_TENANT_ID, ctx.tenantId]);
  await client.query('SELECT set_config($1, $2, true)', [GUC_PRINCIPAL_ID, ctx.principalId]);
  await client.query('SELECT set_config($1, $2, true)', [GUC_MEMBERSHIP_ID, ctx.membershipId]);
  await client.query('SELECT set_config($1, $2, true)', [GUC_REQUEST_ID, ctx.requestId]);
  await client.query('SELECT set_config($1, $2, true)', [GUC_AUTH_EPOCH, ctx.authEpoch]);
}

export interface ReadSecurityContext {
  tenantId: string | null;
  principalId: string | null;
  membershipId: string | null;
  requestId: string | null;
  authEpoch: string | null;
}

/**
 * Read the current transaction's security context. Unset custom GUCs surface
 * as '' from current_setting(..., true), so NULLIF normalizes them to null
 * (default deny) instead of failing a uuid cast.
 */
export async function readContext(
  client: PoolClient | Pool,
): Promise<ReadSecurityContext> {
  const { rows } = await client.query<{ name: string; value: string | null }>(
    `SELECT s.name, NULLIF(current_setting(s.name, true), '') AS value
       FROM unnest($1::text[]) AS s(name)`,
    [[...CONTEXT_GUCS]],
  );
  const byName = new Map(rows.map((r) => [r.name, r.value]));
  return {
    tenantId: byName.get(GUC_TENANT_ID) ?? null,
    principalId: byName.get(GUC_PRINCIPAL_ID) ?? null,
    membershipId: byName.get(GUC_MEMBERSHIP_ID) ?? null,
    requestId: byName.get(GUC_REQUEST_ID) ?? null,
    authEpoch: byName.get(GUC_AUTH_EPOCH) ?? null,
  };
}

/**
 * Assert that all five context GUCs are set and well-formed (uuids for the four
 * identity fields, a non-negative integer for the epoch). Throws a typed
 * SecurityContextError naming the offending settings; never leaks values.
 */
export async function verifyContext(
  client: PoolClient | Pool,
): Promise<SecurityContext> {
  const ctx = await readContext(client);
  const invalid: string[] = [];
  if (!ctx.tenantId || !UUID_RE.test(ctx.tenantId)) invalid.push(GUC_TENANT_ID);
  if (!ctx.principalId || !UUID_RE.test(ctx.principalId)) invalid.push(GUC_PRINCIPAL_ID);
  if (!ctx.membershipId || !UUID_RE.test(ctx.membershipId)) invalid.push(GUC_MEMBERSHIP_ID);
  if (!ctx.requestId || !UUID_RE.test(ctx.requestId)) invalid.push(GUC_REQUEST_ID);
  if (!ctx.authEpoch || !EPOCH_RE.test(ctx.authEpoch)) invalid.push(GUC_AUTH_EPOCH);
  if (invalid.length > 0) {
    throw new SecurityContextError(
      `security context missing or malformed: ${invalid.join(', ')}`,
    );
  }
  return {
    tenantId: ctx.tenantId as string,
    principalId: ctx.principalId as string,
    membershipId: ctx.membershipId as string,
    requestId: ctx.requestId as string,
    authEpoch: ctx.authEpoch as string,
  };
}
