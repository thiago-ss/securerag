import type { ProviderCitation } from '@securerag/providers';

/** Stable refusal codes (T3: only INSUFFICIENT_EVIDENCE is reachable). */
export type RefusalCode =
  | 'INSUFFICIENT_EVIDENCE'
  | 'CONFLICTING_EVIDENCE'
  | 'CITATION_UNSUPPORTED';

/** Exact document/version/chunk/span reference supporting a material claim. */
export type Citation = ProviderCitation;

/** One authorized chunk row allowed to enter answer generation. */
export interface EvidenceChunk {
  chunkId: string;
  chunkNo: number;
  text: string;
  spanStart: number;
  spanEnd: number;
  versionId: string;
  versionNo: number;
  documentId: string;
  title: string;
  rank: number;
}

export interface AnsweredOutcome {
  decision: 'answered';
  answer: string;
  citations: Citation[];
}

export interface RefusedOutcome {
  decision: 'refused';
  code: RefusalCode;
  message: string;
}

export type RetrievalOutcome = AnsweredOutcome | RefusedOutcome;

/** Verified security-context parameters shared by every domain operation. */
export interface SecurityParams {
  tenantId: string;
  principalId: string;
  requestId: string;
}

/** T3 audit subset (contract §Audit events) extended by S1 admin and S9 retention/purge events. */
export type AuditEventType =
  | 'retrieval:allowed'
  | 'retrieval:denied'
  | 'retrieval:refused'
  | 'document:read'
  | 'citation:resolved'
  | 'membership:changed'
  | 'group:changed'
  | 'grant:changed'
  | 'retention:changed'
  | 'purge:completed'
  | 'purge:blocked'
  | 'audit:purged';

/**
 * Audit event payload. tenant_id and occurred_at come from the database; never
 * store foreign ids, raw PII, or full candidate text (redacted derivatives
 * only, CONTEXT.md).
 */
export interface AuditEvent {
  eventType: AuditEventType;
  requestId: string;
  principalId: string;
  membershipId: string;
  authEpoch: string;
  redactedQuery?: string;
  queryHash?: Buffer;
  /** Admin events: redacted change metadata (target uuids / roles / names). */
  filters?: Record<string, unknown>;
  candidateIds?: string[];
  scores?: number[];
  selectedIds?: string[];
  evidenceDecision?: string;
  modelStatus?: string;
  citations?: Citation[];
  refusalReason?: string;
  latencyMs?: number;
  answerHash?: Buffer;
}

/** Audit row as read back by listAudit (tenant-isolated via RLS). */
export interface AuditRecord {
  eventId: string;
  tenantId: string;
  occurredAt: Date;
  eventType: AuditEventType;
  requestId: string;
  principalId: string;
  membershipId: string;
  authEpoch: string;
  redactedQuery: string | null;
  queryHash: Buffer | null;
  filters: Record<string, unknown> | null;
  candidateIds: string[] | null;
  scores: number[] | null;
  selectedIds: string[] | null;
  evidenceDecision: string | null;
  modelStatus: string | null;
  citations: Citation[] | null;
  refusalReason: string | null;
  latencyMs: number | null;
  answerHash: Buffer | null;
}
