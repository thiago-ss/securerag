import type { Pool } from 'pg';
import { withIdentityContext } from '@securerag/security';

/**
 * Identity mapping (S1): an OIDC id_token's (issuer, sub) pair anchors a
 * principal row through the idempotent securerag.upsert_principal definer
 * (ADR-0014). The upsert NEVER distinguishes existing vs new callers (always
 * returns a principal_id, never a unique-violation or existence signal), so
 * the login flow exposes no existence oracle.
 */

export interface UpsertPrincipalParams {
  /** The verified OIDC issuer (exact string). */
  provider: string;
  externalSubject: string;
  displayName: string;
}

/** Idempotent upsert keyed on (provider, external_subject). Returns the
 * principal id, creating or updating the row as needed. */
export async function upsertPrincipal(pool: Pool, params: UpsertPrincipalParams): Promise<string> {
  const { rows } = await pool.query<{ upsert_principal: string }>(
    `SELECT upsert_principal FROM securerag.upsert_principal($1, $2, $3)`,
    [params.provider, params.externalSubject, params.displayName],
  );
  const principalId = rows[0]?.upsert_principal;
  if (principalId === undefined) throw new Error('upsert_principal returned no row');
  return principalId;
}

export interface PrincipalIdentity {
  principalId: string;
  provider: string;
  externalSubject: string;
  displayName: string;
}

/**
 * Resolve a principal by (provider, externalSubject) STRICTLY as the caller's
 * own identity: RLS (principals.principal_scope) shows only the context
 * principal's own row, so a foreign or nonexistent identity returns null
 * exactly like a principal the caller is not. Never an existence oracle.
 */
export async function getPrincipalByExternalId(
  pool: Pool,
  params: UpsertPrincipalParams,
  opts: { principalId: string },
): Promise<PrincipalIdentity | null> {
  const result = await withIdentityContext(pool, opts.principalId, async (client) => {
    const { rows } = await client.query<{
      principal_id: string;
      provider: string;
      external_subject: string;
      display_name: string;
    }>(
      `SELECT principal_id, provider, external_subject, display_name
         FROM securerag.principals
        WHERE provider = $1 AND external_subject = $2`,
      [params.provider, params.externalSubject],
    );
    const row = rows[0];
    if (row === undefined) return null;
    return {
      principalId: row.principal_id,
      provider: row.provider,
      externalSubject: row.external_subject,
      displayName: row.display_name,
    };
  });
  return result.result;
}
