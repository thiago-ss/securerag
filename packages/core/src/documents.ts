import type { Pool, PoolClient } from 'pg';
import { withSecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import { grantPredicateSql, grantSubjectMatchSql, manageGateSql } from './grants.js';
import { DEFAULT_PII_CONFIG, redactForSurface, type PiiConfig } from './redaction.js';
import type { Citation, SecurityParams } from './types.js';

export interface DocumentInfo {
  documentId: string;
  title: string;
  status: string;
}

/** One document-library row: metadata plus the requesting principal's
 * deterministic capabilities (default-deny: the row only exists when the
 * principal holds at least one grant, or manages it as tenant admin). */
export interface DocumentListItem extends DocumentInfo {
  canRead: boolean;
  canWrite: boolean;
  canManage: boolean;
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
 * audit event is written for a denial (no enumerable signal). Retention
 * visibility (S9, ADR-0010): a document any of whose versions is NOT expired
 * stays visible; a fully retention-expired document returns null exactly like
 * a foreign one. A freshly created document (no versions yet) is visible —
 * it carries no content to leak, and the console's create → upload flow
 * depends on it (S10).
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
          AND NOT EXISTS (
            SELECT 1 FROM securerag.document_versions v
             WHERE v.tenant_id = d.tenant_id
               AND v.document_id = d.document_id
               AND v.status = 'expired')
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

export interface ListDocumentsParams extends SecurityParams {}

/**
 * Document library listing (S10 console). Default-deny: a row is visible only
 * when the principal holds ANY grant on the document (read/write/manage all
 * imply read per ADR-0003) or manages it as an active tenant admin; the
 * capability flags are computed with the same SQL predicates used by every
 * other surface, so the library can never drift from the enforcement path.
 * Retention visibility (S9): a document any of whose versions is NOT expired
 * stays visible; a fully expired document is absent from the library (and a
 * freshly created zero-version document is visible — it carries no content).
 * Metadata only — never content. Foreign and nonexistent tenants surface as
 * an empty list plus a MembershipError for non-members (indistinguishable
 * 404 at the API).
 */
export async function listDocuments(
  pool: Pool,
  params: ListDocumentsParams,
): Promise<DocumentListItem[]> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<{
      document_id: string;
      title: string;
      status: string;
      can_read: boolean;
      can_write: boolean;
      can_manage: boolean;
    }>(
      `SELECT d.document_id, d.title, d.status,
              ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')} AS can_read,
              EXISTS (
                SELECT 1 FROM securerag.document_grants g
                 WHERE g.tenant_id = securerag.ctx_tenant_id()
                   AND g.document_id = d.document_id
                   AND g.capability IN ('write','manage')
                   AND ${grantSubjectMatchSql('g')}) AS can_write,
              ${manageGateSql('d.document_id', 'securerag.ctx_tenant_id()')} AS can_manage
         FROM securerag.documents d
        WHERE d.tenant_id = securerag.ctx_tenant_id()
          AND (
            ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}
            OR ${manageGateSql('d.document_id', 'securerag.ctx_tenant_id()')})
          AND NOT EXISTS (
            SELECT 1 FROM securerag.document_versions v
             WHERE v.tenant_id = d.tenant_id
               AND v.document_id = d.document_id
               AND v.status = 'expired')
        ORDER BY d.title`,
    );
    return rows.map((row) => ({
      documentId: row.document_id,
      title: row.title,
      status: row.status,
      canRead: row.can_read,
      canWrite: row.can_write,
      canManage: row.can_manage,
    }));
  });
}

export interface CreateDocumentParams extends SecurityParams {
  title: string;
}

/**
 * Create a document inside the verified tenant (S10 console). Any active
 * member may create (the RLS WITH CHECK pins tenant_id to the verified
 * context); the creator immediately receives a 'manage' grant on the new
 * document so the console's upload flow (manage-gated) can proceed, exactly
 * like a grant written through addGrant: audited 'grant:changed', epoch
 * bumped. The creation itself is audited 'document:created'. A non-member /
 * foreign tenant surfaces as null via MembershipError (indistinguishable).
 */
export async function createDocument(
  pool: Pool,
  params: CreateDocumentParams,
): Promise<DocumentInfo | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const { rows } = await client.query<{ document_id: string; status: string }>(
      `INSERT INTO securerag.documents (tenant_id, title)
       VALUES (securerag.ctx_tenant_id(), $1)
       RETURNING document_id, status`,
      [params.title],
    );
    const row = rows[0];
    if (row === undefined) return null;
    await client.query(
      `INSERT INTO securerag.document_grants
         (tenant_id, document_id, subject_type, subject_id, capability)
       VALUES (securerag.ctx_tenant_id(), $1, 'principal',
               securerag.ctx_principal_id()::text, 'manage')
       ON CONFLICT DO NOTHING`,
      [row.document_id],
    );
    const bumped = await client.query<{ epoch: string }>(
      'SELECT securerag.bump_authorization_epoch() AS epoch',
    );
    const epoch = bumped.rows[0]?.epoch ?? ctx.authEpoch;
    await appendAudit({
      client,
      event: {
        eventType: 'document:created',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: epoch,
        filters: { documentId: row.document_id },
      },
    });
    await appendAudit({
      client,
      event: {
        eventType: 'grant:changed',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: epoch,
        filters: {
          documentId: row.document_id,
          subjectType: 'principal',
          subjectId: ctx.principalId,
          capability: 'manage',
        },
      },
    });
    return { documentId: row.document_id, title: params.title, status: row.status };
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

export interface SourceInfo {
  versionId: string;
  documentId: string;
  contentHash: Buffer;
}

export interface SourceParams extends GetVersionParams {}

/**
 * Authorized source accessor (S3, GET /documents/:id/versions/:versionId/source).
 * The gate is byte-identical to getVersion: source CONTENT is only ever
 * disclosed for CURRENT valid/released versions of a granted document
 * (history is metadata-only; citations/source never resolve non-current
 * versions). Runs inside withSecurityContext, so foreign/nonexistent versions
 * return null exactly like denied ones. This is the minimal authorized stream
 * seam: S2's object-store route replaces the handler while keeping this
 * per-request SQL authorization.
 */
export async function getAuthorizedSource(
  pool: Pool,
  params: SourceParams,
): Promise<SourceInfo | null> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<{
      version_id: string;
      document_id: string;
      content_hash: Buffer;
    }>(
      `SELECT v.version_id, v.document_id, v.content_hash
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
    return { versionId: row.version_id, documentId: row.document_id, contentHash: row.content_hash };
  });
}

export interface ResolveCitationParams extends SecurityParams {
  citationId: string;
}

/**
 * Resolve a citation to its authorized excerpt on an ALREADY-OPEN verified
 * security-context client (S7). Re-checks CURRENT authorization (grant
 * predicate) plus valid/current version visibility inside the caller's
 * transaction — the retrieval pipeline uses this as the post-generation
 * citation-resolution recheck (ADR-0009 §Citation verifier) without nesting a
 * second transaction. Foreign and nonexistent citations are
 * indistinguishable: null. Shared implementation with resolveCitation() so the
 * two paths can never drift; the citation:resolved audit event is written
 * exactly as in the pooled path.
 */
export async function resolveCitationOn(
  client: PoolClient,
  params: ResolveCitationParams,
  ctx: import('@securerag/security').SecurityContext,
  pii: PiiConfig = DEFAULT_PII_CONFIG,
): Promise<Citation | null> {
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
  return withSecurityContext(pool, params, (client, ctx) =>
    resolveCitationOn(client, params, ctx, pii),
  );
}
