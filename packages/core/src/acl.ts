/**
 * ACL listing/management semantics (S3, ADR-0003 amendment 2026-08-05 S3).
 *
 * GET /documents/{id}/grants — manage-gated (S1): visible only to principals
 * with a manage grant on the document or tenant admins. Foreign/nonexistent/
 * unmanageable documents are indistinguishable (listGrants returns null and
 * the API emits the same 404). The wire response shape is the slim
 * {grants: [{grantId, subjectType, subjectId, capability}]} entry — no tenant
 * or document ids echoed, no creation timestamps.
 *
 * Grant add/remove (addGrant/removeGrant) are S1 and unchanged: manage-gated,
 * idempotent, audited 'grant:changed', epoch-bumped.
 */
import type {
  GrantCapability,
  GrantRecord,
  GrantSubjectType,
} from './grants.js';

export interface GrantListEntry {
  grantId: string;
  subjectType: GrantSubjectType;
  subjectId: string;
  capability: GrantCapability;
}

/** Map full grant records to the wire entry shape (no tenant/document ids,
 * no timestamps). */
export function toGrantListEntries(grants: readonly GrantRecord[]): GrantListEntry[] {
  return grants.map((g) => ({
    grantId: g.grantId,
    subjectType: g.subjectType,
    subjectId: g.subjectId,
    capability: g.capability,
  }));
}

export {
  addGrant,
  canManage,
  canRead,
  grantPredicateSql,
  listGrants,
  managePredicateSql,
  removeGrant,
  type CanManageParams,
  type CanReadParams,
  type GrantCapability,
  type GrantParams,
  type GrantRecord,
  type GrantSubjectType,
  type GrantWriteParams,
} from './grants.js';
