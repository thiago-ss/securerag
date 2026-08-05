export {
  appendAudit,
  listAudit,
  sha256,
  type AppendAuditParams,
  type ListAuditParams,
} from './audit.js';
export {
  getAuthorizedSource,
  getDocument,
  getVersion,
  resolveCitation,
  type DocumentInfo,
  type GetDocumentParams,
  type GetVersionParams,
  type ResolveCitationParams,
  type SourceInfo,
  type SourceParams,
  type VersionInfo,
} from './documents.js';
export {
  DEFAULT_PII_CONFIG,
  redactBundleChunks,
  redactForSurface,
  redactQuestion,
  type PiiConfig,
} from './redaction.js';
export {
  addGrant,
  canManage,
  canRead,
  grantPredicateSql,
  listGrants,
  managePredicateSql,
  removeGrant,
  toGrantListEntries,
  type CanManageParams,
  type CanReadParams,
  type GrantCapability,
  type GrantListEntry,
  type GrantParams,
  type GrantRecord,
  type GrantSubjectType,
  type GrantWriteParams,
} from './acl.js';
export {
  getVersionWithHistory,
  historyCapabilitySql,
  listVersions,
  type HistoryParams,
  type HistoryVersionParams,
  type VersionMetadata,
} from './history.js';
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
  listQuarantined,
  quarantineVersion,
  reviewQuarantine,
  type QuarantineRecord,
  type QuarantineVersionParams,
  type ReviewDecision,
  type ReviewQuarantineParams,
} from './quarantine.js';
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
export {
  expireVersionsFor,
  getRetentionPolicy,
  upsertRetentionPolicy,
  DEFAULT_RETENTION_POLICY,
  type ExpireResult,
  type RetentionPolicy,
  type RetentionPolicyPatch,
} from './retention.js';
export {
  RETENTION_SERVICE_MEMBERSHIP,
  RETENTION_SERVICE_PRINCIPAL,
  runTenantPurge,
  type PurgeCounts,
  type PurgeDeps,
  type PurgeResult,
} from './purge.js';
export {
  InMemorySourceObjectStore,
  type SourceObjectStore,
} from './storage.js';
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
