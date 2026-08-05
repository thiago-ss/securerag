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

export const auditQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
});
export type AuditQuery = z.infer<typeof auditQuerySchema>;

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

export const refusedOutcomeSchema = z.object({
  decision: z.literal('refused'),
  code: z.string(),
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
});

export const auditListSchema = z.object({ events: z.array(auditRecordSchema) });

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

export const grantListSchema = z.object({ grants: z.array(grantRecordSchema) });

export const grantCreateResponseSchema = z.object({ grant: grantRecordSchema });

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
  OIDC_POST_LOGOUT_REDIRECT_URI: z.string().optional(),
  OIDC_DISCOVERY_URL: z.string().optional(),
  /** __Host- prefix rules: Secure is REQUIRED in production (default true);
   * tests over plain HTTP set it to false and use the unprefixed cookie. */
  SESSION_COOKIE_SECURE: z
    .string()
    .default('true')
    .transform((v) => v === 'true' || v === '1'),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(60).max(31_536_000).default(28_800),
});
export type Env = z.infer<typeof envSchema>;
