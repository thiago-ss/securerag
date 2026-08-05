export {
  appendAudit,
  listAudit,
  sha256,
  type AppendAuditParams,
  type ListAuditParams,
} from './audit.js';
export {
  getDocument,
  getVersion,
  resolveCitation,
  type DocumentInfo,
  type GetDocumentParams,
  type GetVersionParams,
  type ResolveCitationParams,
  type VersionInfo,
} from './documents.js';
export {
  DEFAULT_PII_CONFIG,
  redactBundleChunks,
  redactForSurface,
  redactQuestion,
  type PiiConfig,
} from './redaction.js';
export { canRead, grantPredicateSql, type CanReadParams } from './grants.js';
export {
  addGrant,
  canManage,
  listGrants,
  managePredicateSql,
  removeGrant,
  type CanManageParams,
  type GrantCapability,
  type GrantParams,
  type GrantRecord,
  type GrantSubjectType,
  type GrantWriteParams,
} from './grants.js';
export {
  addGroupMember,
  createGroup,
  deleteGroup,
  listGroups,
  removeGroupMember,
  type GroupMemberParams,
  type GroupParams,
  type GroupRecord,
} from './groups.js';
export {
  addMembership,
  listMemberships,
  listTenantMembers,
  removeMembership,
  setMembershipActive,
  setMembershipRole,
  type MembershipChangeParams,
  type MembershipListRecord,
  type MembershipRecord,
  type TenantRole,
} from './memberships.js';
export {
  getPrincipalByExternalId,
  upsertPrincipal,
  type PrincipalIdentity,
  type UpsertPrincipalParams,
} from './identity.js';
export {
  DETERMINISTIC_EMBEDDING,
  DeterministicHashEmbedding,
  EMBEDDING_DIM,
  toVectorLiteral,
  type EmbeddingProvider,
} from './embeddings.js';
export {
  decide,
  EVIDENCE_MIN_CHUNKS,
  type EvidenceDecision,
} from './refusal.js';
export {
  RETRIEVAL_ARM_LIMIT,
  RETRIEVAL_DEFAULT_LIMIT,
  RETRIEVAL_EF_SEARCH,
  RRF_K,
  executeRetrievalQuery,
  retrievalParams,
  retrievalSql,
  runRetrieval,
  runRetrievalQuery,
  type RetrievalDeps,
  type RetrievalMode,
  type RetrievalParams,
  type RetrievalQuerySettings,
} from './retrieval.js';
export type {
  AnsweredOutcome,
  AuditEvent,
  AuditEventType,
  AuditRecord,
  Citation,
  EvidenceChunk,
  RefusedOutcome,
  RefusalCode,
  RetrievalOutcome,
  SecurityParams,
} from './types.js';
