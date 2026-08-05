/**
 * Independent authorization oracle (T3 contract §eval/oracle.ts).
 *
 * Input: plain fixture facts. Output: the exact allowed
 * {documents, versions, chunks} sets for a (principalId, tenantId) pair.
 *
 * Pure set logic over the fixture facts: NO production imports, NO SQL, no
 * reimplementation of production policy helpers. It mirrors the T3 contract's
 * authorization predicate (active membership ∩ grant via principal/group/
 * tenant_role ∩ visible version status ∩ is_current) as a separate,
 * independently derived reference so tests can compare production ⊆ oracle
 * and oracle ⊆ production.
 */

export interface OracleTenant {
  id: string;
}

export interface OraclePrincipal {
  id: string;
}

export interface OracleMembership {
  tenantId: string;
  principalId: string;
  role: string;
  isActive: boolean;
}

export interface OracleGroup {
  tenantId: string;
  groupId: string;
}

export interface OracleGroupMembership {
  tenantId: string;
  groupId: string;
  principalId: string;
}

export interface OracleDocument {
  tenantId: string;
  documentId: string;
  title: string;
  status: string;
}

export interface OracleVersion {
  tenantId: string;
  documentId: string;
  versionId: string;
  versionNo: number;
  status: string;
  isCurrent: boolean;
}

export interface OracleChunk {
  tenantId: string;
  versionId: string;
  chunkId: string;
  chunkNo: number;
  text: string;
}

export interface OracleGrant {
  tenantId: string;
  documentId: string;
  subjectType: 'principal' | 'group' | 'tenant_role';
  subjectId: string;
  capability: string;
  /** Row was inserted then revoked (deleted) at seed time. */
  revoked: boolean;
}

export interface OracleFacts {
  tenants: OracleTenant[];
  principals: OraclePrincipal[];
  memberships: OracleMembership[];
  groups: OracleGroup[];
  groupMemberships: OracleGroupMembership[];
  documents: OracleDocument[];
  versions: OracleVersion[];
  chunks: OracleChunk[];
  grants: OracleGrant[];
}

export interface AllowedSets {
  documents: Set<string>;
  versions: Set<string>;
  chunks: Set<string>;
}

const VISIBLE_VERSION_STATUSES = new Set(['valid', 'released']);

/**
 * Exact allowed sets for (principalId, tenantId):
 *  - membership: active membership in the tenant (any role)
 *  - documents: any grant (principal / group / tenant_role) that is not revoked
 *  - versions: visible status (valid|released) AND is_current
 *  - chunks: chunks of allowed versions
 * Default deny: any missing fact yields empty sets.
 */
export function computeAllowed(
  facts: OracleFacts,
  principalId: string,
  tenantId: string,
): AllowedSets {
  const membership = facts.memberships.find(
    (m) => m.tenantId === tenantId && m.principalId === principalId && m.isActive,
  );
  if (!membership) return { documents: new Set(), versions: new Set(), chunks: new Set() };

  const groupIds = new Set(
    facts.groupMemberships
      .filter((gm) => gm.tenantId === tenantId && gm.principalId === principalId)
      .map((gm) => gm.groupId),
  );

  const grantedDocumentIds = new Set<string>();
  for (const grant of facts.grants) {
    if (grant.tenantId !== tenantId || grant.revoked) continue;
    const subjectMatches =
      grant.subjectType === 'principal'
        ? grant.subjectId === principalId
        : grant.subjectType === 'group'
          ? groupIds.has(grant.subjectId)
          : grant.subjectType === 'tenant_role'
            ? grant.subjectId === membership.role
            : false;
    if (subjectMatches) grantedDocumentIds.add(grant.documentId);
  }

  const documents = new Set(
    facts.documents
      .filter((d) => d.tenantId === tenantId && grantedDocumentIds.has(d.documentId))
      .map((d) => d.documentId),
  );

  const versions = new Set(
    facts.versions
      .filter(
        (v) =>
          v.tenantId === tenantId &&
          grantedDocumentIds.has(v.documentId) &&
          VISIBLE_VERSION_STATUSES.has(v.status) &&
          v.isCurrent,
      )
      .map((v) => v.versionId),
  );

  const chunks = new Set(
    facts.chunks
      .filter((c) => c.tenantId === tenantId && versions.has(c.versionId))
      .map((c) => c.chunkId),
  );

  return { documents, versions, chunks };
}
