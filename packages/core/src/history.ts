import type { Pool } from 'pg';
import { withSecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import { grantPredicateSql } from './grants.js';
import type { SecurityParams } from './types.js';

/**
 * History capability (S3, ADR-0003 amendment 2026-08-05 S3).
 *
 * History = MANAGE capability, deterministically: a principal may observe
 * NON-CURRENT version metadata of a document iff it holds a direct `manage`
 * grant on that document (the manage_scope security_invoker view, migration
 * 0010). Read/write grants and the tenant-admin role alone do NOT enable
 * history. All authorization executes inside SQL within the verified
 * security context; foreign and nonexistent documents are indistinguishable
 * (null). History is METADATA ONLY — it never returns content of non-current
 * versions, and citations/source continue to resolve only CURRENT
 * valid/released versions.
 *
 * Every successful history-capability access (manage path) is audited as
 * `document:history`; the read-only path (current versions under any grant)
 * writes nothing, mirroring getVersion.
 */

export interface VersionMetadata {
  documentId: string;
  versionId: string;
  versionNo: number;
  status: string;
  isCurrent: boolean;
  publishedAt: Date | null;
  contentHash: Buffer;
}

export interface HistoryParams extends SecurityParams {
  documentId: string;
}

export interface HistoryVersionParams extends HistoryParams {
  versionId: string;
}

interface VersionRow {
  document_id: string;
  version_id: string;
  version_no: number;
  status: string;
  is_current: boolean;
  published_at: Date | null;
  content_hash: Buffer;
}

function toMetadata(row: VersionRow): VersionMetadata {
  return {
    documentId: row.document_id,
    versionId: row.version_id,
    versionNo: row.version_no,
    status: row.status,
    isCurrent: row.is_current,
    publishedAt: row.published_at,
    contentHash: row.content_hash,
  };
}

/**
 * The history gate: a direct manage grant on the document (manage_scope, RLS
 * scoped to the verified tenant) AND the document itself still exists
 * (status <> 'deleted'). Caller-supplied SQL expressions, never user text.
 */
export function historyCapabilitySql(documentRef: string, tenantRef: string): string {
  return `EXISTS (
    SELECT 1 FROM securerag.manage_scope ms
     WHERE ms.tenant_id = ${tenantRef}
       AND ms.document_id = ${documentRef})
   AND EXISTS (
    SELECT 1 FROM securerag.documents dd
     WHERE dd.tenant_id = ${tenantRef}
       AND dd.document_id = ${documentRef}
       AND dd.status <> 'deleted')`;
}

const HISTORY_SELECT = `SELECT v.document_id, v.version_id, v.version_no, v.status,
                               v.is_current, v.published_at, v.content_hash
                          FROM securerag.document_versions v
                          JOIN securerag.documents d
                            ON d.tenant_id = v.tenant_id
                           AND d.document_id = v.document_id`;

/**
 * Version metadata list (GET /documents/:id/versions, S3). Manage-grant
 * holders see EVERY version (valid/released/superseded/quarantined/expired/
 * pending, with status); everyone else sees only the current valid/released
 * version. Null — exactly like a foreign or nonexistent document — when the
 * caller holds no grant on the document or no current visible version exists.
 * The manage path is audited 'document:history'.
 */
export async function listVersions(
  pool: Pool,
  params: HistoryParams,
): Promise<VersionMetadata[] | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<VersionRow>(
      `${HISTORY_SELECT}
        WHERE v.document_id = $1
          AND ${historyCapabilitySql('v.document_id', 'securerag.ctx_tenant_id()')}
        ORDER BY v.version_no`,
      [params.documentId],
    );
    if (rows.length > 0) {
      await appendAudit({
        client,
        event: {
          eventType: 'document:history',
          requestId: params.requestId,
          principalId: ctx.principalId,
          membershipId: ctx.membershipId,
          authEpoch: ctx.authEpoch,
          filters: { documentId: params.documentId },
        },
      });
      return rows.map(toMetadata);
    }

    const { rows: current } = await client.query<VersionRow>(
      `${HISTORY_SELECT}
        WHERE v.document_id = $1
          AND v.status IN ('valid','released')
          AND v.is_current
          AND ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}`,
      [params.documentId],
    );
    return current.length === 0 ? null : current.map(toMetadata);
  });
}

/**
 * Single-version fetch (GET /documents/:id/versions/:versionId, S3). A
 * non-current versionId resolves ONLY for manage-grant holders (history =
 * manage capability); everyone else observes null for non-current versions
 * exactly like foreign or nonexistent ones. Current valid/released versions
 * resolve for any grant holder. The manage path is audited 'document:history'.
 */
export async function getVersionWithHistory(
  pool: Pool,
  params: HistoryVersionParams,
): Promise<VersionMetadata | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<VersionRow>(
      `${HISTORY_SELECT}
        WHERE v.version_id = $1
          AND v.document_id = $2
          AND ${historyCapabilitySql('v.document_id', 'securerag.ctx_tenant_id()')}`,
      [params.versionId, params.documentId],
    );
    const row = rows[0];
    if (row !== undefined) {
      await appendAudit({
        client,
        event: {
          eventType: 'document:history',
          requestId: params.requestId,
          principalId: ctx.principalId,
          membershipId: ctx.membershipId,
          authEpoch: ctx.authEpoch,
          filters: { documentId: params.documentId, versionId: params.versionId },
        },
      });
      return toMetadata(row);
    }

    const { rows: current } = await client.query<VersionRow>(
      `${HISTORY_SELECT}
        WHERE v.version_id = $1
          AND v.document_id = $2
          AND v.status IN ('valid','released')
          AND v.is_current
          AND ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}`,
      [params.versionId, params.documentId],
    );
    const currentRow = current[0];
    return currentRow === undefined ? null : toMetadata(currentRow);
  });
}
