/** Wire DTOs mirroring the committed API shapes (apps/api/openapi.yaml). */

export interface Principal {
  principalId: string;
  provider: string;
  externalSubject: string;
  displayName: string;
}

export interface MembershipSummary {
  tenantId: string;
  membershipId: string;
  role: string;
}

export interface Me {
  principal: Principal;
  session: { sessionId: string; expiresAt: string; csrfToken: string };
  memberships: MembershipSummary[];
}

export interface DocumentListItem {
  documentId: string;
  title: string;
  status: string;
  canRead: boolean;
  canWrite: boolean;
  canManage: boolean;
}

export interface DocumentInfo {
  documentId: string;
  title: string;
  status: string;
}

export interface VersionMetadata {
  documentId: string;
  versionId: string;
  versionNo: number;
  status: string;
  isCurrent: boolean;
  publishedAt: string | null;
  hash: string;
}

export interface GrantEntry {
  grantId: string;
  subjectType: 'principal' | 'group' | 'tenant_role';
  subjectId: string;
  capability: 'read' | 'write' | 'manage';
}

export interface Citation {
  documentId: string;
  versionId: string;
  chunkId: string;
  span: { start: number; end: number };
  excerpt: string;
}

export type RefusalCode = 'INSUFFICIENT_EVIDENCE' | 'CONFLICTING_EVIDENCE' | 'CITATION_UNSUPPORTED';

export type RetrievalOutcome =
  | { decision: 'answered'; answer: string; citations: Citation[] }
  | { decision: 'refused'; code: RefusalCode; message: string };

export interface QuarantineRecord {
  versionId: string;
  documentId: string;
  versionNo: number;
  title: string;
  status: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewDecision: string | null;
  createdAt: string;
}

export interface AuditRecord {
  eventId: string;
  tenantId: string;
  occurredAt: string;
  eventType: string;
  requestId: string;
  principalId: string;
  membershipId: string;
  authEpoch: string;
  redactedQuery: string | null;
  queryHash: string | null;
  candidateIds: string[] | null;
  scores: number[] | null;
  selectedIds: string[] | null;
  evidenceDecision: string | null;
  modelStatus: string | null;
  citations: Citation[] | null;
  refusalReason: string | null;
  latencyMs: number | null;
  answerHash: string | null;
}

export interface RetentionPolicy {
  tenantId: string;
  sourceDays: number;
  derivedDays: number;
  auditDays: number;
  graceDays: number;
  legalHold: boolean;
  updatedAt: string;
}

export interface MembershipRecord {
  tenantId: string;
  membershipId: string;
  principalId: string;
  role: string;
  isActive: boolean;
  joinedAt: string;
}

export interface GroupRecord {
  tenantId: string;
  groupId: string;
  name: string;
  createdAt: string;
}

export interface JobStatus {
  jobId: string;
  jobType: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export interface Problem {
  code: string;
  message: string;
}
