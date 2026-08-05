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
});
export type Env = z.infer<typeof envSchema>;
