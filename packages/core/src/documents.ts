import type { Pool } from 'pg';
import { withSecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import { grantPredicateSql } from './grants.js';
import { DEFAULT_PII_CONFIG, redactForSurface, type PiiConfig } from './redaction.js';
import type { Citation, SecurityParams } from './types.js';

export interface DocumentInfo {
  documentId: string;
  title: string;
  status: string;
}

export interface VersionInfo {
  documentId: string;
  versionId: string;
  versionNo: number;
  status: string;
  isCurrent: boolean;
  title: string;
}

export interface GetDocumentParams extends SecurityParams {
  documentId: string;
}

/**
 * Authorized document metadata (title/status only — never content). Foreign
 * and nonexistent documents are indistinguishable: both return null, and no
 * audit event is written for a denial (no enumerable signal).
 */
export async function getDocument(
  pool: Pool,
  params: GetDocumentParams,
): Promise<DocumentInfo | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<{
      document_id: string;
      title: string;
      status: string;
    }>(
      `SELECT d.document_id, d.title, d.status
         FROM securerag.documents d
        WHERE d.document_id = $1
          AND ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}`,
      [params.documentId],
    );
    const row = rows[0];
    if (!row) return null;
    await appendAudit({
      client,
      event: {
        eventType: 'document:read',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: ctx.authEpoch,
      },
    });
    return { documentId: row.document_id, title: row.title, status: row.status };
  });
}

export interface GetVersionParams extends SecurityParams {
  documentId: string;
  versionId: string;
}

/**
 * Authorized version metadata under the valid/current rules: only
 * status IN ('valid','released') AND is_current versions of a granted
 * document exist; superseded/quarantined/pending/expired versions return
 * null exactly like foreign or nonexistent ones.
 */
export async function getVersion(
  pool: Pool,
  params: GetVersionParams,
): Promise<VersionInfo | null> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<{
      document_id: string;
      version_id: string;
      version_no: number;
      status: string;
      is_current: boolean;
      title: string;
    }>(
      `SELECT v.document_id, v.version_id, v.version_no, v.status, v.is_current, d.title
         FROM securerag.document_versions v
         JOIN securerag.documents d
           ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
        WHERE v.version_id = $1
          AND v.document_id = $2
          AND v.status IN ('valid','released')
          AND v.is_current
          AND ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}`,
      [params.versionId, params.documentId],
    );
    const row = rows[0];
    if (!row) return null;
    return {
      documentId: row.document_id,
      versionId: row.version_id,
      versionNo: row.version_no,
      status: row.status,
      isCurrent: row.is_current,
      title: row.title,
    };
  });
}

export interface ResolveCitationParams extends SecurityParams {
  citationId: string;
}

/**
 * Resolve a citation to its authorized excerpt. Re-checks CURRENT
 * authorization (grant predicate) plus valid/current version visibility
 * inside a fresh withSecurityContext (ADR-0009 epoch recheck). Foreign and
 * nonexistent citations are indistinguishable: null. A citation resolving
 * success is recorded as citation:resolved; denials write nothing.
 *
 * The excerpt is a HUMAN surface: principals with `pii:read` see the original
 * text for documents they are already authorized to read; everyone else gets
 * the redacted derivative (ADR-0005). The `pii:read` flag is read from the
 * principal's own row inside the verified context (RLS-scoped, default deny).
 */
export async function resolveCitation(
  pool: Pool,
  params: ResolveCitationParams,
  pii: PiiConfig = DEFAULT_PII_CONFIG,
): Promise<Citation | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const principal = await client.query<{ pii_read: boolean }>(
      `SELECT pii_read
         FROM securerag.principals
        WHERE principal_id = securerag.ctx_principal_id()`,
    );
    const piiRead = principal.rows[0]?.pii_read ?? false;

    const { rows } = await client.query<{
      chunk_id: string;
      chunk_no: number;
      text_redacted: string;
      span_start: number;
      span_end: number;
      version_id: string;
      version_no: number;
      document_id: string;
    }>(
      `SELECT c.chunk_id, c.chunk_no, c.text_redacted, c.span_start, c.span_end,
              v.version_id, v.version_no, d.document_id
         FROM securerag.chunks c
         JOIN securerag.document_versions v
           ON v.tenant_id = c.tenant_id AND v.version_id = c.version_id
         JOIN securerag.documents d
           ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
        WHERE c.chunk_id = $1
          AND v.status IN ('valid','released')
          AND v.is_current
          AND ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}`,
      [params.citationId],
    );
    const row = rows[0];
    if (!row) return null;
    await appendAudit({
      client,
      event: {
        eventType: 'citation:resolved',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: ctx.authEpoch,
        candidateIds: [row.chunk_id],
      },
    });
    return {
      documentId: row.document_id,
      versionId: row.version_id,
      chunkId: row.chunk_id,
      span: { start: row.span_start, end: row.span_end },
      excerpt: redactForSurface(row.text_redacted, pii, piiRead),
    };
  });
}
