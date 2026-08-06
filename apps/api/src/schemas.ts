import { z } from 'zod';

/**
 * Zod boundary schemas (T3 contract §API). Every body/params/query at the
 * API edge is validated here; the parsed values are the ONLY values the
 * handlers touch. All schemas are uuid-typed where the domain expects uuids
 * (PostgreSQL returns uuid/bigint as text over the wire, so the API keeps
 * them as strings and never numeric-casts ids).
 *
 * Failure handling is uniform: any boundary violation yields the constant
 * problem+json body INVALID_REQUEST — no field-level detail is ever echoed
 * to clients (no enumerable errors, no internal text).
 */

export const uuidSchema = z.string().uuid();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const retrievalQuerySchema = z.object({
  tenantId: uuidSchema,
  question: z.string().min(1).max(500),
});
export type RetrievalQuery = z.infer<typeof retrievalQuerySchema>;

export const documentParamsSchema = z.object({ id: uuidSchema });
export type DocumentParams = z.infer<typeof documentParamsSchema>;

export const versionParamsSchema = z.object({
  id: uuidSchema,
  versionId: uuidSchema,
});
export type VersionParams = z.infer<typeof versionParamsSchema>;

export const citationParamsSchema = z.object({ citationId: uuidSchema });
export type CitationParams = z.infer<typeof citationParamsSchema>;

// ---------- S2 ingestion boundaries (ADR-0007) ----------

/** Multipart upload target: document + file part. Size is bounded by
 * @fastify/multipart limits (50 MB) before the handler runs. */
export const uploadParamsSchema = z.object({ id: uuidSchema });
export type UploadParams = z.infer<typeof uploadParamsSchema>;

export const uploadResponseSchema = z.object({
  jobId: z.string(),
  documentId: z.string(),
  versionId: z.string(),
  status: z.string(),
});

/** Authorized source stream target: document + version. */
export const sourceParamsSchema = z.object({
  id: uuidSchema,
  versionId: uuidSchema,
});
export type SourceParams = z.infer<typeof sourceParamsSchema>;

export const jobParamsSchema = z.object({ jobId: uuidSchema });
export type JobParams = z.infer<typeof jobParamsSchema>;

/** Opaque job status (own tenant only): ids + lifecycle state, no payload. */
export const jobStatusSchema = z.object({
  jobId: z.string(),
  jobType: z.string(),
  status: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/** Stable audit event type list (T3 + S1/S5/S8/S9 extensions). */
export const auditEventTypeSchema = z.enum([
  'retrieval:allowed',
  'retrieval:denied',
  'retrieval:refused',
  'document:read',
  'document:history',
  'citation:resolved',
  'membership:changed',
  'group:changed',
  'grant:changed',
  'version:quarantined',
  'version:review',
  'injection:detected',
  'retention:changed',
  'purge:completed',
  'purge:blocked',
  'audit:purged',
  'audit:exported',
  'ingest:received',
  'ingest:scanned',
  'ingest:extracted',
  'ingest:redacted',
  'ingest:chunked',
  'ingest:verified',
  'ingest:published',
  'ingest:rejected',
]);
export type AuditEventTypeParam = z.infer<typeof auditEventTypeSchema>;

export const auditQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  eventType: auditEventTypeSchema.optional(),
  /** Inclusive occurred_at lower bound (ISO-8601). */
  from: z.string().datetime().optional(),
  /** Inclusive occurred_at upper bound (ISO-8601). */
  to: z.string().datetime().optional(),
  principalId: uuidSchema.optional(),
  /** Keyset cursor: only events with event_id < cursor (from a previous page). */
  cursor: z.string().regex(/^\d+$/).optional(),
});
export type AuditQuery = z.infer<typeof auditQuerySchema>;

/** Export request: the explicit tenant the principal exports (admin / security_reviewer gate in core). */
export const auditExportQuerySchema = z.object({ tenantId: uuidSchema });
export type AuditExportQuery = z.infer<typeof auditExportQuerySchema>;

// ---------- S1 auth / admin boundaries ----------

export const tenantQuerySchema = z.object({ tenantId: uuidSchema });
export type TenantQuery = z.infer<typeof tenantQuerySchema>;

export const callbackQuerySchema = z.object({
  code: z.string().min(1).max(1000),
  state: z.string().min(1).max(500),
  iss: z.string().optional(),
});
export type CallbackQuery = z.infer<typeof callbackQuerySchema>;

export const membershipCreateSchema = z.object({
  tenantId: uuidSchema,
  principalId: uuidSchema,
  role: z.enum(['admin', 'member', 'security_reviewer']),
});
export type MembershipCreate = z.infer<typeof membershipCreateSchema>;

export const membershipUpdateSchema = z
  .object({
    tenantId: uuidSchema,
    principalId: uuidSchema,
    role: z.enum(['admin', 'member', 'security_reviewer']).optional(),
    isActive: z.boolean().optional(),
  })
  .refine((v) => v.role !== undefined || v.isActive !== undefined, {
    message: 'role or isActive required',
  });
export type MembershipUpdate = z.infer<typeof membershipUpdateSchema>;

export const membershipRemoveQuerySchema = z.object({
  tenantId: uuidSchema,
  principalId: uuidSchema,
});
export type MembershipRemoveQuery = z.infer<typeof membershipRemoveQuerySchema>;

export const groupCreateSchema = z.object({
  tenantId: uuidSchema,
  name: z.string().min(1).max(200),
});
export type GroupCreate = z.infer<typeof groupCreateSchema>;

export const groupRemoveQuerySchema = z.object({
  tenantId: uuidSchema,
  groupId: uuidSchema,
});
export type GroupRemoveQuery = z.infer<typeof groupRemoveQuerySchema>;

export const groupMemberBodySchema = z.object({
  tenantId: uuidSchema,
  principalId: uuidSchema,
});
export type GroupMemberBody = z.infer<typeof groupMemberBodySchema>;

export const groupMemberRemoveQuerySchema = z.object({
  tenantId: uuidSchema,
  principalId: uuidSchema,
});
export type GroupMemberRemoveQuery = z.infer<typeof groupMemberRemoveQuerySchema>;

export const grantBodySchema = z.object({
  subjectType: z.enum(['principal', 'group', 'tenant_role']),
  subjectId: z.string().min(1).max(200),
  capability: z.enum(['read', 'write', 'manage']),
}).superRefine((v, ctx) => {
  if (v.subjectType === 'principal' || v.subjectType === 'group') {
    if (!UUID_RE.test(v.subjectId)) {
      ctx.addIssue({ code: 'custom', path: ['subjectId'], message: 'must be a uuid for principal/group grants' });
    }
  } else if (!['admin', 'member', 'security_reviewer'].includes(v.subjectId)) {
    ctx.addIssue({ code: 'custom', path: ['subjectId'], message: 'must be a tenant role for tenant_role grants' });
  }
});
export type GrantBody = z.infer<typeof grantBodySchema>;

export const grantRemoveBodySchema = z.object({ grantId: uuidSchema });
export type GrantRemoveBody = z.infer<typeof grantRemoveBodySchema>;

// ---------- S5 injection quarantine boundaries ----------

export const quarantineListQuerySchema = z.object({ tenantId: uuidSchema });
export type QuarantineListQuery = z.infer<typeof quarantineListQuerySchema>;

export const quarantineReviewParamsSchema = z.object({ versionId: uuidSchema });
export type QuarantineReviewParams = z.infer<typeof quarantineReviewParamsSchema>;

export const quarantineReviewBodySchema = z.object({
  tenantId: uuidSchema,
  decision: z.enum(['release', 'keep']),
  /** Optional human context (ticket id / reason); stored redacted in audit filters. */
  reviewerCtx: z.string().min(1).max(500).optional(),
});
export type QuarantineReviewBody = z.infer<typeof quarantineReviewBodySchema>;

// ---------- response shapes (also drive the committed OpenAPI) ----------

export const spanSchema = z.object({
  start: z.number().int(),
  end: z.number().int(),
});

export const citationSchema = z.object({
  documentId: z.string(),
  versionId: z.string(),
  chunkId: z.string(),
  span: spanSchema,
  excerpt: z.string(),
});

export const answeredOutcomeSchema = z.object({
  decision: z.literal('answered'),
  answer: z.string(),
  citations: z.array(citationSchema),
});

/** Stable refusal codes (ADR-0009): S7 adds CONFLICTING_EVIDENCE and CITATION_UNSUPPORTED. */
export const refusalCodeSchema = z.enum([
  'INSUFFICIENT_EVIDENCE',
  'CONFLICTING_EVIDENCE',
  'CITATION_UNSUPPORTED',
]);
export type RefusalCode = z.infer<typeof refusalCodeSchema>;

export const refusedOutcomeSchema = z.object({
  decision: z.literal('refused'),
  code: refusalCodeSchema,
  message: z.string(),
});

export const retrievalOutcomeSchema = z.union([
  answeredOutcomeSchema,
  refusedOutcomeSchema,
]);

export const documentInfoSchema = z.object({
  documentId: z.string(),
  title: z.string(),
  status: z.string(),
});

/** Document-library row (S10 console): metadata + the requesting principal's
 * deterministic capability flags (default-deny; rows only exist for granted
 * or admin-managed documents). */
export const documentListItemSchema = z.object({
  documentId: z.string(),
  title: z.string(),
  status: z.string(),
  canRead: z.boolean(),
  canWrite: z.boolean(),
  canManage: z.boolean(),
});

export const documentListSchema = z.object({
  documents: z.array(documentListItemSchema),
});

export const documentCreateSchema = z.object({
  tenantId: uuidSchema,
  title: z.string().min(1).max(200),
});
export type DocumentCreate = z.infer<typeof documentCreateSchema>;

export const documentCreateResponseSchema = z.object({ document: documentInfoSchema });

export const versionInfoSchema = z.object({
  documentId: z.string(),
  versionId: z.string(),
  versionNo: z.number().int(),
  status: z.string(),
  isCurrent: z.boolean(),
  title: z.string(),
});

export const auditRecordSchema = z.object({
  eventId: z.string(),
  tenantId: z.string(),
  occurredAt: z.string(),
  eventType: z.string(),
  requestId: z.string(),
  principalId: z.string(),
  membershipId: z.string(),
  authEpoch: z.string(),
  redactedQuery: z.string().nullable(),
  queryHash: z.string().nullable(),
  candidateIds: z.array(z.string()).nullable(),
  scores: z.array(z.number()).nullable(),
  selectedIds: z.array(z.string()).nullable(),
  evidenceDecision: z.string().nullable(),
  modelStatus: z.string().nullable(),
  citations: z.array(citationSchema).nullable(),
  refusalReason: z.string().nullable(),
  latencyMs: z.number().nullable(),
  answerHash: z.string().nullable(),
  prevEventHash: z.string().nullable(),
  eventHash: z.string().nullable(),
});

export const auditListSchema = z.object({
  events: z.array(auditRecordSchema),
  nextCursor: z.string().nullable(),
});

/** WORM export envelope (docs/ops/audit-export.md). */
export const auditExportResponseSchema = z.object({
  format: z.literal('securerag-audit-export/1'),
  tenantId: z.string(),
  chainAnchorEventId: z.string().nullable(),
  chainAnchorHash: z.string().nullable(),
  eventCount: z.number(),
  generatedAt: z.string(),
  exporter: z.string(),
  exportSha256: z.string(),
  body: z.string(),
});

export const membershipRecordSchema = z.object({
  tenantId: z.string(),
  membershipId: z.string(),
  principalId: z.string(),
  role: z.string(),
  isActive: z.boolean(),
  joinedAt: z.string(),
});
export type MembershipRecord = z.infer<typeof membershipRecordSchema>;

export const membershipListSchema = z.object({ members: z.array(membershipRecordSchema) });

export const membershipCreateResponseSchema = z.object({
  membership: membershipRecordSchema,
});

export const groupRecordSchema = z.object({
  tenantId: z.string(),
  groupId: z.string(),
  name: z.string(),
  createdAt: z.string(),
});
export type GroupRecord = z.infer<typeof groupRecordSchema>;

export const groupListSchema = z.object({ groups: z.array(groupRecordSchema) });

export const groupCreateResponseSchema = z.object({ group: groupRecordSchema });

export const grantRecordSchema = z.object({
  tenantId: z.string(),
  documentId: z.string(),
  grantId: z.string(),
  subjectType: z.string(),
  subjectId: z.string(),
  capability: z.string(),
  createdAt: z.string(),
});
export type GrantRecord = z.infer<typeof grantRecordSchema>;

/** S3 wire entry for GET /documents/{id}/grants: the slim ACL entry
 * (grantId/subjectType/subjectId/capability) — no tenant/document echo, no
 * timestamps (ADR-0003 amendment S3). */
export const grantListEntrySchema = z.object({
  grantId: z.string(),
  subjectType: z.string(),
  subjectId: z.string(),
  capability: z.string(),
});
export type GrantListEntry = z.infer<typeof grantListEntrySchema>;

export const grantListSchema = z.object({ grants: z.array(grantListEntrySchema) });

export const grantCreateResponseSchema = z.object({ grant: grantRecordSchema });

// ---------- S3 history / source / citation boundaries ----------

/** Version metadata entry (S3, ADR-0003 amendment): versionNo/status/
 * publishedAt/hash — NEVER content. publishedAt is ISO-8601 or null; hash is
 * the hex-encoded content fingerprint. */
export const versionMetadataSchema = z.object({
  documentId: z.string(),
  versionId: z.string(),
  versionNo: z.number().int(),
  status: z.string(),
  isCurrent: z.boolean(),
  publishedAt: z.string().nullable(),
  hash: z.string(),
});
export type VersionMetadata = z.infer<typeof versionMetadataSchema>;

export const versionListSchema = z.object({ versions: z.array(versionMetadataSchema) });

/** Minimal authorized source seam (S3): the version fingerprint only; S2's
 * object-store stream replaces the handler while keeping this shape. */
export const sourceInfoSchema = z.object({
  versionId: z.string(),
  documentId: z.string(),
  contentHash: z.string(),
});
export type SourceInfo = z.infer<typeof sourceInfoSchema>;

/** Resolved-citation response (S3 hardening): the citation fields plus the
 * `resolvable` flag — always true on 200 (unresolvable citations are
 * indistinguishable 404s); clients can distinguish resolution-time validity
 * from stale references carried in earlier answers. */
export const resolvedCitationSchema = citationSchema.extend({
  resolvable: z.literal(true),
});
export type ResolvedCitation = z.infer<typeof resolvedCitationSchema>;

export const quarantineRecordSchema = z.object({
  versionId: z.string(),
  documentId: z.string(),
  versionNo: z.number().int(),
  title: z.string(),
  status: z.string(),
  reviewedBy: z.string().nullable(),
  reviewedAt: z.string().nullable(),
  reviewDecision: z.string().nullable(),
  createdAt: z.string(),
});
export type QuarantineRecord = z.infer<typeof quarantineRecordSchema>;

export const quarantineListSchema = z.object({ versions: z.array(quarantineRecordSchema) });

export const retentionPolicyBodySchema = z
  .object({
    tenantId: uuidSchema,
    sourceDays: z.number().int().min(0).optional(),
    derivedDays: z.number().int().min(0).optional(),
    auditDays: z.number().int().min(0).optional(),
    graceDays: z.number().int().min(0).optional(),
    legalHold: z.boolean().optional(),
  })
  .refine((v) => Object.keys(v).filter((k) => k !== 'tenantId').length > 0, {
    message: 'empty patch',
  });
export type RetentionPolicyBody = z.infer<typeof retentionPolicyBodySchema>;

export const retentionPolicyQuerySchema = z.object({ tenantId: uuidSchema });
export type RetentionPolicyQuery = z.infer<typeof retentionPolicyQuerySchema>;

export const retentionPolicySchema = z.object({
  tenantId: z.string(),
  sourceDays: z.number(),
  derivedDays: z.number(),
  auditDays: z.number(),
  graceDays: z.number(),
  legalHold: z.boolean(),
  updatedAt: z.string(),
});
export type RetentionPolicyRecord = z.infer<typeof retentionPolicySchema>;

export const okSchema = z.object({ ok: z.literal(true) });

export const meSchema = z.object({
  principal: z.object({
    principalId: z.string(),
    provider: z.string(),
    externalSubject: z.string(),
    displayName: z.string(),
  }),
  session: z.object({
    sessionId: z.string(),
    expiresAt: z.string(),
    csrfToken: z.string(),
  }),
  memberships: z.array(
    z.object({
      tenantId: z.string(),
      membershipId: z.string(),
      role: z.string(),
    }),
  ),
});
export type Me = z.infer<typeof meSchema>;

export const problemSchema = z.object({
  code: z.string(),
  message: z.string(),
});

export const statusSchema = z.object({ status: z.string() });

// ---------- runtime environment (server.ts entrypoint) ----------

export const envSchema = z.object({
  PGHOST: z.string().min(1).default('localhost'),
  PGPORT: z.coerce.number().int().min(1).max(65535).default(5432),
  PGUSER: z.string().min(1).default('securerag_api'),
  PGPASSWORD: z.string().min(1),
  PGDATABASE: z.string().min(1).default('securerag'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().min(1).default('0.0.0.0'),
  OIDC_ISSUER: z.string().min(1),
  OIDC_CLIENT_ID: z.string().min(1),
  OIDC_REDIRECT_URI: z.string().min(1),
  OIDC_ALLOW_INSECURE_HTTP: z.coerce.boolean().default(false),
  OIDC_TOKEN_ENDPOINT_INTERNAL: z.string().optional(),
  OIDC_JWKS_URI_INTERNAL: z.string().optional(),
  OIDC_POST_LOGOUT_REDIRECT_URI: z.string().optional(),
  OIDC_DISCOVERY_URL: z.string().optional(),
  /** __Host- prefix rules: Secure is REQUIRED in production (default true);
   * tests over plain HTTP set it to false and use the unprefixed cookie. */
  SESSION_COOKIE_SECURE: z
    .string()
    .default('true')
    .transform((v) => v === 'true' || v === '1'),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(60).max(31_536_000).default(28_800),
  /** S2 object storage seam (ADR-0007): memory for CI/demo; s3 behind S3_* config. */
  SOURCE_STORE: z.enum(['memory', 's3']).default('memory'),
  S3_ENDPOINT: z.string().optional(),
  S3_REGION: z.string().default('us-east-1'),
  S3_BUCKET: z.string().default('securerag-objects'),
  S3_ACCESS_KEY_ID: z.string().optional(),
  S3_SECRET_ACCESS_KEY: z.string().optional(),
  S3_FORCE_PATH_STYLE: z
    .string()
    .default('true')
    .transform((v) => v === 'true' || v === '1'),
});
export type Env = z.infer<typeof envSchema>;
