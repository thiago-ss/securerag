import type { Pool } from 'pg';
import { withSecurityContext } from '@securerag/security';
import type { SecurityParams } from './types.js';

/**
 * Single source of truth for the document-read grant predicate (T3 contract
 * §Retrieval keyword arm, ADR-0003). One ACL governs all retained versions of
 * a document; read/write/manage grants all imply read (the binding SQL shape
 * applies no capability filter).
 *
 * The same fragment composes into every authorization decision:
 *  - canRead:            documentRef '$1', tenantRef 'securerag.ctx_tenant_id()'
 *  - retrieval keyword:  documentRef 'd.document_id', tenantRef 'c.tenant_id'
 *  - citation/source:    documentRef 'd.document_id', tenantRef 'securerag.ctx_tenant_id()'
 *
 * `documentRef`/`tenantRef` are caller-supplied SQL expressions (a parameter
 * reference or an aliased column), never user text. Subject matching uses the
 * security-context functions so the predicate is identical under RLS in every
 * embedding.
 */
export function grantPredicateSql(documentRef: string, tenantRef: string): string {
  return `EXISTS (
    SELECT 1 FROM securerag.document_grants g
     WHERE g.tenant_id = ${tenantRef}
       AND g.document_id = ${documentRef}
       AND (
         (g.subject_type = 'principal'
            AND g.subject_id = securerag.ctx_principal_id()::text)
         OR (g.subject_type = 'group'
            AND EXISTS (SELECT 1 FROM securerag.group_memberships gm
                         WHERE gm.tenant_id = g.tenant_id
                           AND gm.group_id = g.subject_id::uuid
                           AND gm.principal_id = securerag.ctx_principal_id()))
         OR (g.subject_type = 'tenant_role'
            AND g.subject_id = (SELECT tm.role FROM securerag.tenant_memberships tm
                                 WHERE tm.tenant_id = g.tenant_id
                                   AND tm.principal_id = securerag.ctx_principal_id()
                                   AND tm.is_active))
       ))`;
}

export interface CanReadParams extends SecurityParams {
  documentId: string;
}

/**
 * Re-check used by citation/source resolution: true iff the context principal
 * holds any grant on the document inside the verified tenant. Runs inside
 * withSecurityContext; foreign/nonexistent documents both return false.
 */
export async function canRead(pool: Pool, params: CanReadParams): Promise<boolean> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<{ allowed: boolean }>(
      `SELECT ${grantPredicateSql('$1', 'securerag.ctx_tenant_id()')} AS allowed`,
      [params.documentId],
    );
    return rows[0]?.allowed ?? false;
  });
}
