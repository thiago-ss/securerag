import pg from 'pg';
import type { PoolConfig } from 'pg';

export type RuntimeRole = 'securerag_api' | 'securerag_worker';

/**
 * Create a least-privilege runtime connection pool for the given role.
 *
 * The pool always connects AS the runtime role (never the owner or superuser):
 * PostgreSQL enforces RLS + the catalog-proven grants for that role. The
 * application_name is pinned per role for observability.
 *
 * Passwords MUST come from environment variables / a secret manager at
 * deployment time — never from code, config files, or the repository
 * (AGENTS.md: never commit secrets). Host/port/database come from the
 * deployment envelope (ADR-0011).
 */
export function createRuntimePool(
  role: RuntimeRole,
  config: PoolConfig,
): pg.Pool {
  return new pg.Pool({
    ...config,
    user: role,
    application_name: `securerag-${role}`,
  });
}
