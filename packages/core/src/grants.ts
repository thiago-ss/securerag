import type { Pool, PoolClient } from 'pg';
import { withSecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
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
 *  - manage gate (S1):   managePredicateSql with the same refs + capability
 *
 * `documentRef`/`tenantRef` are caller-supplied SQL expressions (a parameter
 * reference or an aliased column), never user text. Subject matching uses the
 * security-context functions so the predicate is identical under RLS in every
 * embedding.
 */

/** The 3-way subject-match fragment (principal / group / tenant_role) shared by
 * every grant predicate. `g` must be the document_grants alias. */
export function grantSubjectMatchSql(g: string): string {
  return `(${g}.subject_type = 'principal'
     AND ${g}.subject_id = securerag.ctx_principal_id()::text
   OR ${g}.subject_type = 'group'
     AND EXISTS (SELECT 1 FROM securerag.group_memberships gm
                  WHERE gm.tenant_id = ${g}.tenant_id
                    AND gm.group_id = ${g}.subject_id::uuid
                    AND gm.principal_id = securerag.ctx_principal_id())
   OR ${g}.subject_type = 'tenant_role'
     AND ${g}.subject_id = (SELECT tm.role FROM securerag.tenant_memberships tm
                             WHERE tm.tenant_id = ${g}.tenant_id
                               AND tm.principal_id = securerag.ctx_principal_id()
                               AND tm.is_active))`;
}

export function grantPredicateSql(documentRef: string, tenantRef: string): string {
  return `EXISTS (
    SELECT 1 FROM securerag.document_grants g
     WHERE g.tenant_id = ${tenantRef}
       AND g.document_id = ${documentRef}
       AND ${grantSubjectMatchSql('g')})
   AND EXISTS (
    SELECT 1 FROM securerag.documents dd
     WHERE dd.tenant_id = ${tenantRef}
       AND dd.document_id = ${documentRef}
       AND dd.status <> 'deleted')`;
}

/** Manage-capability predicate: a direct manage grant matching the context
 * principal (read/write grants do NOT imply manage). */
export function managePredicateSql(documentRef: string, tenantRef: string): string {
  return `EXISTS (
    SELECT 1 FROM securerag.document_grants g
     WHERE g.tenant_id = ${tenantRef}
       AND g.document_id = ${documentRef}
       AND g.capability = 'manage'
       AND ${grantSubjectMatchSql('g')})`;
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

/**
 * The full manage gate (G2 watch item, S1): the context principal may manage a
 * document's ACL iff it holds a direct manage grant on the document OR is an
 * active admin of the tenant WHOSE DOCUMENT EXISTS in the verified tenant
 * (the admin branch is itself RLS-scoped, so foreign/nonexistent documents
 * resolve false identically and the caller never reaches FK-error paths).
 *
 * NOTE (S3): this gate lives in the application service layer because a
 * policy-level manage check on document_grants cannot be expressed without
 * self-recursion; S3 closes the gap with a security_invoker manage view.
 */
export function manageGateSql(documentRef: string, tenantRef: string): string {
  return `(
    ${managePredicateSql(documentRef, tenantRef)}
    OR (
      EXISTS (SELECT 1 FROM securerag.documents d
               WHERE d.tenant_id = ${tenantRef}
                 AND d.document_id = ${documentRef})
      AND securerag.ctx_principal_is_admin(${tenantRef})
    )
  )`;
}

export interface CanManageParams extends SecurityParams {
  documentId: string;
}

/** Deterministic manage gate for grant management; foreign and nonexistent
 * documents both return false (RLS hides foreign rows). */
export async function canManage(pool: Pool, params: CanManageParams): Promise<boolean> {
  return withSecurityContext(pool, params, async (client) => {
    return manageAllowed(client, params.documentId);
  });
}

/** Same manage gate on the caller's open transaction (used by the management
 * functions below so the check and the write share one context). Also used
 * by the S2 upload stage (ingestion.ts) on its own transaction. */
export async function manageAllowed(client: PoolClient, documentId: string): Promise<boolean> {
  const { rows } = await client.query<{ allowed: boolean }>(
    `SELECT ${manageGateSql('$1', 'securerag.ctx_tenant_id()')} AS allowed`,
    [documentId],
  );
  return rows[0]?.allowed ?? false;
}

export type GrantSubjectType = 'principal' | 'group' | 'tenant_role';
export type GrantCapability = 'read' | 'write' | 'manage';

export interface GrantRecord {
  tenantId: string;
  documentId: string;
  grantId: string;
  subjectType: GrantSubjectType;
  subjectId: string;
  capability: GrantCapability;
  createdAt: Date;
}

export interface GrantParams extends SecurityParams {
  documentId: string;
}

export interface GrantWriteParams extends GrantParams {
  subjectType: GrantSubjectType;
  subjectId: string;
  capability: GrantCapability;
}

interface GrantRow {
  tenant_id: string;
  document_id: string;
  grant_id: string;
  subject_type: string;
  subject_id: string;
  capability: string;
  created_at: Date;
}

function toGrant(row: GrantRow): GrantRecord {
  return {
    tenantId: row.tenant_id,
    documentId: row.document_id,
    grantId: row.grant_id,
    subjectType: row.subject_type as GrantSubjectType,
    subjectId: row.subject_id,
    capability: row.capability as GrantCapability,
    createdAt: row.created_at,
  };
}

/**
 * Manage-gated ACL listing (G2 watch item): visible only to principals with a
 * manage grant on the document or tenant admins; null exactly like a foreign
 * or nonexistent document otherwise.
 */
export async function listGrants(pool: Pool, params: GrantParams): Promise<GrantRecord[] | null> {
  return withSecurityContext(pool, params, async (client) => {
    if (!(await manageAllowed(client, params.documentId))) return null;
    const { rows } = await client.query<GrantRow>(
      `SELECT tenant_id, document_id, grant_id, subject_type, subject_id, capability, created_at
         FROM securerag.document_grants
        WHERE tenant_id = securerag.ctx_tenant_id() AND document_id = $1
        ORDER BY subject_type, subject_id, capability`,
      [params.documentId],
    );
    return rows.map(toGrant);
  });
}

/**
 * Manage-gated grant insert (idempotent). Null when the principal cannot
 * manage the document OR the grant already exists (no write, no bump, no
 * audit — indistinguishable from a foreign document at the API).
 */
export async function addGrant(pool: Pool, params: GrantWriteParams): Promise<GrantRecord | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    if (!(await manageAllowed(client, params.documentId))) return null;
    const { rows } = await client.query<GrantRow>(
      `INSERT INTO securerag.document_grants
         (tenant_id, document_id, subject_type, subject_id, capability)
       VALUES (securerag.ctx_tenant_id(), $1, $2, $3, $4)
       ON CONFLICT DO NOTHING
       RETURNING tenant_id, document_id, grant_id, subject_type, subject_id, capability, created_at`,
      [params.documentId, params.subjectType, params.subjectId, params.capability],
    );
    const row = rows[0];
    if (row === undefined) return null;
    const bumped = await client.query<{ epoch: string }>(
      'SELECT securerag.bump_authorization_epoch() AS epoch',
    );
    await appendAudit({
      client,
      event: {
        eventType: 'grant:changed',
        requestId: ctx.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: bumped.rows[0]?.epoch ?? ctx.authEpoch,
        filters: {
          documentId: params.documentId,
          subjectType: params.subjectType,
          subjectId: params.subjectId,
          capability: params.capability,
        },
      },
    });
    return toGrant(row);
  });
}

/** Manage-gated grant revocation. False when the principal cannot manage the
 * document or no such grant exists. */
export async function removeGrant(
  pool: Pool,
  params: GrantParams & { grantId: string },
): Promise<boolean> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    if (!(await manageAllowed(client, params.documentId))) return false;
    const { rows } = await client.query<{ grant_id: string }>(
      `DELETE FROM securerag.document_grants
        WHERE tenant_id = securerag.ctx_tenant_id()
          AND document_id = $1 AND grant_id = $2
        RETURNING grant_id`,
      [params.documentId, params.grantId],
    );
    if (rows[0] === undefined) return false;
    const bumped = await client.query<{ epoch: string }>(
      'SELECT securerag.bump_authorization_epoch() AS epoch',
    );
    await appendAudit({
      client,
      event: {
        eventType: 'grant:changed',
        requestId: ctx.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: bumped.rows[0]?.epoch ?? ctx.authEpoch,
        filters: { documentId: params.documentId, grantId: params.grantId },
      },
    });
    return true;
  });
}
