import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import Fastify, {
  type FastifyError,
  type FastifyInstance,
  type FastifyRequest,
} from 'fastify';
import fastifySwagger from '@fastify/swagger';
import fastifyMultipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import type { FastifyOtelInstrumentation } from '@fastify/otel';
import { ZodError, z } from 'zod';
import {
  InMemoryLoginStore,
  InvalidIdTokenError,
  MembershipError,
  OidcClient,
  OidcProviderError,
  buildSessionCookie,
  createSession,
  csrfMatches,
  expireSessionCookie,
  getSession,
  parseCookieHeader,
  revokeSession,
  validateSessionCookieConfig,
  withIdentityContext,
  type SessionRow,
} from '@securerag/security';
import {
  addGrant,
  addGroupMember,
  addMembership,
  canManage,
  createDocument,
  createGroup,
  DEFAULT_PII_CONFIG,
  deleteGroup,
  exportAudit,
  getDocument,
  getJobStatus,
  getRetentionPolicy,
  getSourceObjectKey,
  getVersionWithHistory,
  listAudit,
  listDocuments,
  listGrants,
  listGroups,
  listQuarantined,
  listTenantMembers,
  listVersions,
  removeGrant,
  removeGroupMember,
  removeMembership,
  resolveCitation,
  reviewQuarantine,
  runRetrieval,
  setMembershipActive,
  setMembershipRole,
  sourceObjectKey,
  stageUpload,
  toGrantListEntries,
  upsertPrincipal,
  upsertRetentionPolicy,
  type AuditRecord,
  type PiiConfig,
  type SourceObjectStore,
  type VersionMetadata,
} from '@securerag/core';
import type { AnswerGenerator } from '@securerag/providers';
import type { OracleFacts } from '@securerag/eval/src/oracle.js';
import {
  auditExportQuerySchema,
  auditExportResponseSchema,
  auditListSchema,
  auditQuerySchema,
  callbackQuerySchema,
  citationParamsSchema,
  documentCreateResponseSchema,
  documentCreateSchema,
  documentInfoSchema,
  documentListSchema,
  documentParamsSchema,
  grantBodySchema,
  grantCreateResponseSchema,
  grantListSchema,
  grantRemoveBodySchema,
  groupCreateResponseSchema,
  groupCreateSchema,
  groupListSchema,
  groupMemberBodySchema,
  groupMemberRemoveQuerySchema,
  groupRemoveQuerySchema,
  jobParamsSchema,
  jobStatusSchema,
  meSchema,
  membershipCreateResponseSchema,
  membershipCreateSchema,
  membershipListSchema,
  membershipRemoveQuerySchema,
  membershipUpdateSchema,
  okSchema,
  problemSchema,
  quarantineListQuerySchema,
  quarantineListSchema,
  quarantineReviewBodySchema,
  quarantineReviewParamsSchema,
  resolvedCitationSchema,
  retentionPolicyBodySchema,
  retentionPolicyQuerySchema,
  retentionPolicySchema,
  retrievalOutcomeSchema,
  retrievalQuerySchema,
  sourceParamsSchema,
  statusSchema,
  tenantQuerySchema,
  uploadParamsSchema,
  uploadResponseSchema,
  uuidSchema,
  versionListSchema,
  versionMetadataSchema,
  versionParamsSchema,
} from './schemas.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Principal id resolved from the verified session cookie (S1). */
    principalId: string;
    /** The verified session row (validity enforced in SQL). */
    session: SessionRow;
    /** The raw opaque cookie token (needed by /auth/logout). */
    sessionToken: string;
  }
  interface FastifyInstance {
    /** The injected dependencies, exposed for tests (e.g. the oracle facts accessor). */
    secureRag: ApiDeps;
  }
}

/**
 * DI seam: pool is the least-privilege runtime role; oidc carries the real
 * OIDC client configuration (issuer is the trust anchor).
 */
export interface ApiDeps {
  pool: Pool;
  providers: AnswerGenerator;
  oidc: OidcApiConfig;
  /** Oracle facts accessor for tests (cross-check seam; never used for authorization). */
  facts?: () => OracleFacts;
  /** Injectable request-id generator; defaults to randomUUID. */
  requestId?: () => string;
  /**
   * PII redaction config (S4, ADR-0005). Defaults to the deterministic
   * detector with the feature enabled: the query question is redacted before
   * embedding/payload/audit, model context never carries raw PII (even for
   * pii:read), and citation excerpts honor pii:read on human surfaces.
   */
  pii?: PiiConfig;
  /**
   * Source object store (S2, ADR-0007): the upload route writes objects
   * (SSE-S3 via the S3 adapter; in-memory in CI) and the source stream route
   * reads them. The worker processes the same store the API wrote to.
   */
  store: SourceObjectStore;
  /**
   * Rate limits (S10, ADR-0011): per principal+IP on /retrieval/query, per IP
   * on the auth endpoints. Defaults match the ADR envelope target (25 rps
   * retrieval) and the documented auth limit (10/min); tests override to
   * tiny values to exercise the 429 path cheaply.
   */
  rateLimit?: {
    retrievalMax?: number;
    retrievalWindowMs?: number;
    authMax?: number;
    authWindowMs?: number;
  };
  /**
   * OTel wiring (S10, ADR-0011): the started FastifyOtelInstrumentation from
   * src/otel.ts. Span attributes carry identifiers/status only — never
   * prompts, retrieved text, or document content (enforced by test).
   */
  otel?: { instrumentation: FastifyOtelInstrumentation };
  /**
   * pino logger for the instance (default false). Enabling it AFTER the pino
   * OTel instrumentation is active correlates log records with traces
   * (instrumentation-pino). Tests keep it off.
   */
  logger?: boolean;
}

export interface OidcApiConfig {
  /** Exact issuer identifier; MUST match the provider's discovery `issuer`. */
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri?: string;
  discoveryUrl?: string;
  /** Cookie name honors the __Host- prefix under Secure (prefix rules validated at startup). */
  sessionCookieName: string;
  sessionCookieSecure: boolean;
  sessionTtlSeconds?: number;
  postLoginRedirectPath?: string;
  postLogoutRedirectPath?: string;
  maxAgeSeconds?: number;
  acrValues?: string[];
  /** Opt-in for demo/deployment-internal issuers on plain HTTP (see OidcClientConfig). */
  allowInsecureEndpoints?: boolean;
  /** Internal token endpoint for server-side exchanges (compose networks). */
  internalTokenEndpoint?: string;
  /** Internal JWKS URI override for server-side key fetches (compose networks). */
  internalJwksUri?: string;
  httpFetch?: typeof fetch;
}

/**
 * Stable problem+json bodies. NEVER differentiate foreign vs nonexistent and
 * never echo internal text: every 4xx/5xx body is one of these constants, so
 * responses are byte-identical across indistinguishable cases.
 */
const UNAUTHORIZED = { code: 'UNAUTHORIZED', message: 'Authentication required' };
const FORBIDDEN = { code: 'FORBIDDEN', message: 'Forbidden' };
const INVALID_REQUEST = { code: 'INVALID_REQUEST', message: 'Invalid request' };
const NOT_FOUND = { code: 'NOT_FOUND', message: 'Resource not found' };
const INTERNAL_ERROR = { code: 'INTERNAL_ERROR', message: 'Internal server error' };
const NOT_READY = { code: 'UNAVAILABLE', message: 'Service not ready' };
const RATE_LIMITED = { code: 'RATE_LIMITED', message: 'Too many requests' };

/** Documented rate limits (ADR-0011 §rate limits, docs/ops/envelope.md). */
export const DEFAULT_RATE_LIMITS = {
  /** Retrieval: the ADR envelope target (25 requests/second per principal+IP). */
  retrievalMax: 25,
  retrievalWindowMs: 1_000,
  /** Auth endpoints: login/callback brute-force guard (per IP). */
  authMax: 30,
  authWindowMs: 60_000,
} as const;

/** Typed 429 body; also thrown by the rate-limit plugin's error builder so
 * Fastify routes it through the error handler (which emits RATE_LIMITED). */
function rateLimitError(): Error & { statusCode: number; code: string } {
  const err = new Error('Too many requests') as Error & { statusCode: number; code: string };
  err.statusCode = 429;
  err.code = 'RATE_LIMITED';
  return err;
}

/**
 * Refusal shape for a foreign/unknown tenant. MUST stay byte-identical to the
 * genuine INSUFFICIENT_EVIDENCE refusal produced by packages/core
 * (packages/core/src/retrieval.ts: message 'No sufficient authorized evidence
 * to answer.'), so a foreign tenant and an authorized-but-insufficient one are
 * indistinguishable over the wire. The E2E suite asserts byte-equality.
 */
const REFUSED_INSUFFICIENT_EVIDENCE = {
  decision: 'refused',
  code: 'INSUFFICIENT_EVIDENCE',
  message: 'No sufficient authorized evidence to answer.',
} as const;

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Denied admin writes are indistinguishable across RLS violations, foreign
 * keys, unique conflicts, and missing memberships: the same 404 body.
 */
/** Server-detected content type from magic bytes (S2 review 6). */
function sniffContentType(bytes: Buffer, fallback: string): string {
  if (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    return 'application/pdf';
  }
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
    return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return 'text/plain';
  }
  return fallback;
}

function isIndistinguishableDenial(err: unknown): boolean {
  if (err instanceof MembershipError) return true;
  const code = (err as { code?: string }).code;
  return code === '42501' || code === '23503' || code === '23505';
}

/** zod 4 toJSONSchema output adapted for fastify/ajv (strip $schema; drop required keys that carry a default). */
function toFastifyJsonSchema(schema: z.ZodType): Record<string, unknown> {
  const json = schema.toJSONSchema() as Record<string, unknown>;
  delete json.$schema;
  const props = json.properties as Record<string, unknown> | undefined;
  if (json.type === 'object' && Array.isArray(json.required) && props) {
    json.required = (json.required as string[]).filter(
      (key) =>
        !(props[key] && typeof props[key] === 'object' && 'default' in (props[key] as object)),
    );
  }
  return json;
}

/**
 * Resolve a resource across the principal's own tenants (the session carries
 * no tenant; the principal's active memberships define their scope).
 * Deterministic probe order; foreign and nonexistent both yield null, so
 * callers emit the same 404. Denials write nothing (B1 decision).
 */
async function acrossTenants<T>(
  pool: Pool,
  principalId: string,
  probe: (tenantId: string) => Promise<T | null>,
): Promise<T | null> {
  const identity = await withIdentityContext(pool, principalId, async () => undefined);
  const tenantIds = identity.memberships.map((m) => m.tenantId).sort();
  for (const tenantId of tenantIds) {
    const found = await probe(tenantId);
    if (found !== null) return found;
  }
  return null;
}

function toAuditRecordDto(record: AuditRecord): unknown {
  return {
    eventId: record.eventId,
    tenantId: record.tenantId,
    occurredAt: record.occurredAt.toISOString(),
    eventType: record.eventType,
    requestId: record.requestId,
    principalId: record.principalId,
    membershipId: record.membershipId,
    authEpoch: record.authEpoch,
    redactedQuery: record.redactedQuery ?? null,
    queryHash: record.queryHash ? record.queryHash.toString('hex') : null,
    filters: record.filters ?? null,
    candidateIds: record.candidateIds ?? null,
    scores: record.scores ?? null,
    selectedIds: record.selectedIds ?? null,
    evidenceDecision: record.evidenceDecision ?? null,
    modelStatus: record.modelStatus ?? null,
    citations: record.citations ?? null,
    refusalReason: record.refusalReason ?? null,
    latencyMs: record.latencyMs ?? null,
    answerHash: record.answerHash ? record.answerHash.toString('hex') : null,
    prevEventHash: record.prevEventHash ? record.prevEventHash.toString('hex') : null,
    eventHash: record.eventHash ? record.eventHash.toString('hex') : null,
  };
}

/** History version metadata → wire DTO: publishedAt ISO-8601 or null, content
 * hash hex-encoded; never content. */
function toVersionMetadataDto(version: VersionMetadata): unknown {
  return {
    documentId: version.documentId,
    versionId: version.versionId,
    versionNo: version.versionNo,
    status: version.status,
    isCurrent: version.isCurrent,
    publishedAt: version.publishedAt === null ? null : version.publishedAt.toISOString(),
    hash: version.contentHash.toString('hex'),
  };
}

/** Display-name mapping from validated id_token claims (never raw sub as the
 * only name; never untrusted free text beyond the provider's own claims). */
function displayNameFromClaims(claims: { name?: unknown; preferred_username?: unknown; sub: string }): string {
  if (typeof claims.preferred_username === 'string' && claims.preferred_username.length > 0) {
    return claims.preferred_username.slice(0, 200);
  }
  if (typeof claims.name === 'string' && claims.name.length > 0) {
    return claims.name.slice(0, 200);
  }
  return claims.sub;
}

export async function buildApp(deps: ApiDeps): Promise<FastifyInstance> {
  const { pool, providers } = deps;
  const pii = deps.pii ?? DEFAULT_PII_CONFIG;
  const newRequestId = deps.requestId ?? randomUUID;
  const oidcCfg = deps.oidc;
  const oidcClient = new OidcClient({
    issuer: oidcCfg.issuer,
    clientId: oidcCfg.clientId,
    redirectUri: oidcCfg.redirectUri,
    ...(oidcCfg.postLogoutRedirectUri !== undefined
      ? { postLogoutRedirectUri: oidcCfg.postLogoutRedirectUri }
      : {}),
    ...(oidcCfg.discoveryUrl !== undefined ? { discoveryUrl: oidcCfg.discoveryUrl } : {}),
    ...(oidcCfg.maxAgeSeconds !== undefined ? { maxAgeSeconds: oidcCfg.maxAgeSeconds } : {}),
    ...(oidcCfg.acrValues !== undefined ? { acrValues: oidcCfg.acrValues } : {}),
    ...(oidcCfg.allowInsecureEndpoints !== undefined
      ? { allowInsecureEndpoints: oidcCfg.allowInsecureEndpoints }
      : {}),
    ...(oidcCfg.internalTokenEndpoint !== undefined
      ? { internalTokenEndpoint: oidcCfg.internalTokenEndpoint }
      : {}),
    ...(oidcCfg.internalJwksUri !== undefined
      ? { internalJwksUri: oidcCfg.internalJwksUri }
      : {}),
    ...(oidcCfg.httpFetch !== undefined ? { httpFetch: oidcCfg.httpFetch } : {}),
  });
  const loginStore = new InMemoryLoginStore();
  validateSessionCookieConfig(oidcCfg.sessionCookieName, oidcCfg.sessionCookieSecure);

  const app = Fastify({ logger: deps.logger ?? false });
  app.decorate('secureRag', deps);

  // S10 OTel (ADR-0011): route spans carry identifiers/status only. The
  // instrumentation must be started (SDK) before the plugin registration.
  if (deps.otel !== undefined) {
    await app.register(deps.otel.instrumentation.plugin());
  }

  // S10 rate limits (ADR-0011): registered AFTER the session onRequest hook
  // (defined below) so this plugin's onRequest runs after session resolution
  // and its key can bind to the verified principal. Per-route overrides set
  // the documented limits; the typed 429 body comes from the error handler.
  const rateLimitCfg = deps.rateLimit ?? {};

  await app.register(fastifySwagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'SecureRAG API',
        version: '0.1.0',
        description:
          'Tenant-isolated RAG retrieval with default-deny authorization enforced in SQL. ' +
          'Foreign and nonexistent resources are indistinguishable (same status and schema).',
      },
      components: {
        securitySchemes: {
          sessionCookie: {
            type: 'apiKey',
            in: 'cookie',
            name: oidcCfg.sessionCookieName,
            description:
              'OIDC session cookie (HttpOnly, Secure, SameSite=Lax). State-changing requests must ' +
              'also send the X-CSRF-Token header (from /auth/me).',
          },
        },
      },
    },
  });

  // S2 uploads: bounded multipart (50 MB cap, single file part). Violations
  // surface as the generic 400 INVALID_REQUEST via the error handler.
  await app.register(fastifyMultipart, {
    limits: { fileSize: 50 * 1024 * 1024, files: 1, parts: 2, fields: 0 },
  });

  // Responses are plain JSON.stringify of handler values: no schema-driven
  // stripping, no fast-json-stringify constraints on union response shapes.
  app.setSerializerCompiler(() => (data: unknown) => JSON.stringify(data));

  app.setNotFoundHandler((_request, reply) => reply.code(404).send(NOT_FOUND));

  app.setErrorHandler((err: FastifyError, request, reply) => {
    if (err instanceof ZodError || err.validation) {
      return reply.code(400).send(INVALID_REQUEST);
    }
    if (err.statusCode === 429) {
      return reply.code(429).send(RATE_LIMITED);
    }
    if (err.statusCode !== undefined && err.statusCode >= 400 && err.statusCode < 500) {
      return reply.code(err.statusCode).send(INVALID_REQUEST);
    }
    request.log.error({ err }, 'unhandled error');
    return reply.code(500).send(INTERNAL_ERROR);
  });

  // ---------- Session middleware (S1): cookie → session → principal + CSRF ----------
  app.addHook('onRequest', async (request, reply) => {
    const path = (request.raw.url ?? '').split('?')[0];
    if (path === '/healthz' || path === '/readyz') return;
    if (path === '/auth/login' || path === '/auth/callback') return;

    const token = parseCookieHeader(request.headers.cookie, oidcCfg.sessionCookieName);
    const session = token === null ? null : await getSession(pool, token);
    // Foreign, expired, and revoked sessions are indistinguishable: 401.
    if (session === null || token === null) {
      return reply.code(401).send(UNAUTHORIZED);
    }
    request.session = session;
    request.sessionToken = token;
    request.principalId = session.principalId;

    if (STATE_CHANGING_METHODS.has(request.method)) {
      const header = request.headers['x-csrf-token'];
      if (!csrfMatches(session.csrfToken, typeof header === 'string' ? header : undefined)) {
        return reply.code(403).send(FORBIDDEN);
      }
    }
  });

  // Rate limiting (S10, ADR-0011): registered here, AFTER the session hook,
  // so the key generator sees the verified principal. Per-principal+IP for
  // retrieval, per-IP for the auth endpoints (no session yet at /auth/*).
  await app.register(rateLimit, {
    global: false,
    keyGenerator: (request: FastifyRequest): string => {
      const ip = request.ip;
      const principal = request.principalId;
      return principal === undefined ? `ip:${ip}` : `p:${principal}:${ip}`;
    },
    errorResponseBuilder: rateLimitError,
    timeWindow: 60_000,
    max: 60,
  });

  // ---------- Auth (S1) ----------

  app.get(
    '/auth/login',
    { config: { rateLimit: { max: rateLimitCfg.authMax ?? DEFAULT_RATE_LIMITS.authMax, timeWindow: rateLimitCfg.authWindowMs ?? DEFAULT_RATE_LIMITS.authWindowMs } } },
    async (_request, reply) => {
      const flow = oidcClient.createLoginFlow();
      loginStore.add(flow);
      const url = await oidcClient.buildAuthorizationUrl(flow);
      return reply.code(302).header('location', url).send();
    },
  );

  app.get(
    '/auth/callback',
    { schema: { querystring: toFastifyJsonSchema(callbackQuerySchema) }, config: { rateLimit: { max: rateLimitCfg.authMax ?? DEFAULT_RATE_LIMITS.authMax, timeWindow: rateLimitCfg.authWindowMs ?? DEFAULT_RATE_LIMITS.authWindowMs } } },
    async (request, reply) => {
      const query = callbackQuerySchema.parse(request.query);
      // One-time state consumption (RFC 9700 §4.2.4): replay of the callback
      // URL fails here before any provider interaction.
      const flow = loginStore.consume(query.state);
      if (flow === null) return reply.code(400).send(INVALID_REQUEST);
      // RFC 9207: validate the issuer identification parameter when present.
      if (query.iss !== undefined && query.iss !== oidcCfg.issuer) {
        return reply.code(400).send(INVALID_REQUEST);
      }
      try {
        const exchanged = await oidcClient.exchangeCode(flow, query.code);
        const principalId = await upsertPrincipal(pool, {
          provider: oidcCfg.issuer,
          externalSubject: exchanged.claims.sub,
          displayName: displayNameFromClaims(exchanged.claims),
        });
        const ttlSeconds = oidcCfg.sessionTtlSeconds ?? 8 * 3600;
        const { token } = await createSession(pool, {
          principalId,
          ttlSeconds,
        });
        void reply.header(
          'set-cookie',
          buildSessionCookie({
            name: oidcCfg.sessionCookieName,
            value: token,
            secure: oidcCfg.sessionCookieSecure,
            maxAgeSeconds: ttlSeconds,
          }),
        );
        return reply.code(302).header('location', oidcCfg.postLoginRedirectPath ?? '/').send();
      } catch (err) {
        // EVERY id_token / token-exchange failure is the same 400: no
        // validation oracle (which check failed, whether the principal
        // exists, whether the provider rejected the code).
        if (err instanceof InvalidIdTokenError || err instanceof OidcProviderError) {
          return reply.code(400).send(INVALID_REQUEST);
        }
        throw err;
      }
    },
  );

  app.post(
    '/auth/logout',
    { config: { rateLimit: { max: 30, timeWindow: 60_000 } } },
    async (request, reply) => {
      // Session exists (hook verified it). Revoke server-side FIRST, then
      // clear the cookie and hand the user agent to the provider's
      // end_session_endpoint (id_token_hint omitted: the raw id_token is not
      // retained; documented in ADR-0004/S1 notes).
      await revokeSession(pool, request.sessionToken);
      void reply.header(
        'set-cookie',
        expireSessionCookie(oidcCfg.sessionCookieName, oidcCfg.sessionCookieSecure),
      );
      let endSession: string | null = null;
      try {
        endSession = await oidcClient.endSessionUrl();
      } catch {
        // provider unreachable: local logout already happened; redirect home.
      }
      return reply
        .code(302)
        .header('location', endSession ?? oidcCfg.postLogoutRedirectPath ?? '/')
        .send();
    },
  );

  app.get(
    '/auth/me',
    { schema: { response: { 200: toFastifyJsonSchema(meSchema), 401: toFastifyJsonSchema(problemSchema) } } },
    async (request) => {
      const identity = await withIdentityContext(pool, request.principalId, async (client) => {
        const { rows } = await client.query<{
          principal_id: string;
          provider: string;
          external_subject: string;
          display_name: string;
        }>(
          `SELECT principal_id, provider, external_subject, display_name
             FROM securerag.principals
            WHERE principal_id = securerag.ctx_principal_id()`,
        );
        const row = rows[0];
        if (row === undefined) throw new Error('principal not found for session');
        return {
          principalId: row.principal_id,
          provider: row.provider,
          externalSubject: row.external_subject,
          displayName: row.display_name,
        };
      });
      return {
        principal: identity.result,
        session: {
          sessionId: request.session.sessionId,
          expiresAt: request.session.expiresAt.toISOString(),
          csrfToken: request.session.csrfToken.toString('hex'),
        },
        memberships: identity.memberships,
      };
    },
  );

  // ---------- Admin: memberships (S1) ----------

  app.get(
    '/memberships',
    {
      schema: {
        querystring: toFastifyJsonSchema(tenantQuerySchema),
        response: {
          200: toFastifyJsonSchema(membershipListSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = tenantQuerySchema.parse(request.query);
      try {
        const members = await listTenantMembers(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
        });
        return { members: members.map((m) => ({ ...m, joinedAt: m.joinedAt.toISOString() })) };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.post(
    '/memberships',
    {
      schema: {
        body: toFastifyJsonSchema(membershipCreateSchema),
        response: {
          201: toFastifyJsonSchema(membershipCreateResponseSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const body = membershipCreateSchema.parse(request.body);
      try {
        const membership = await addMembership(pool, {
          tenantId: body.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          targetPrincipalId: body.principalId,
          role: body.role,
        });
        return reply.code(201).send({
          membership: { ...membership, joinedAt: membership.joinedAt.toISOString() },
        });
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.patch(
    '/memberships',
    {
      schema: {
        body: toFastifyJsonSchema(membershipUpdateSchema),
        response: {
          200: toFastifyJsonSchema(okSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const body = membershipUpdateSchema.parse(request.body);
      try {
        const base = {
          tenantId: body.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          targetPrincipalId: body.principalId,
        };
        const changed =
          body.role !== undefined
            ? await setMembershipRole(pool, { ...base, role: body.role })
            : await setMembershipActive(pool, { ...base, isActive: body.isActive as boolean });
        if (!changed) return reply.code(404).send(NOT_FOUND);
        return { ok: true };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.delete(
    '/memberships',
    {
      schema: {
        querystring: toFastifyJsonSchema(membershipRemoveQuerySchema),
        response: {
          200: toFastifyJsonSchema(okSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = membershipRemoveQuerySchema.parse(request.query);
      try {
        const removed = await removeMembership(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          targetPrincipalId: query.principalId,
        });
        if (!removed) return reply.code(404).send(NOT_FOUND);
        return { ok: true };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  // ---------- Admin: groups (S1) ----------

  app.get(
    '/groups',
    {
      schema: {
        querystring: toFastifyJsonSchema(tenantQuerySchema),
        response: {
          200: toFastifyJsonSchema(groupListSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = tenantQuerySchema.parse(request.query);
      try {
        const groups = await listGroups(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
        });
        return { groups: groups.map((g) => ({ ...g, createdAt: g.createdAt.toISOString() })) };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.post(
    '/groups',
    {
      schema: {
        body: toFastifyJsonSchema(groupCreateSchema),
        response: {
          201: toFastifyJsonSchema(groupCreateResponseSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const body = groupCreateSchema.parse(request.body);
      try {
        const group = await createGroup(pool, {
          tenantId: body.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          name: body.name,
        });
        return reply.code(201).send({ group: { ...group, createdAt: group.createdAt.toISOString() } });
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.delete(
    '/groups',
    {
      schema: {
        querystring: toFastifyJsonSchema(groupRemoveQuerySchema),
        response: {
          200: toFastifyJsonSchema(okSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = groupRemoveQuerySchema.parse(request.query);
      try {
        const removed = await deleteGroup(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          groupId: query.groupId,
        });
        if (!removed) return reply.code(404).send(NOT_FOUND);
        return { ok: true };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.post(
    '/groups/:groupId/members',
    {
      schema: {
        params: toFastifyJsonSchema(z.object({ groupId: uuidSchema })),
        body: toFastifyJsonSchema(groupMemberBodySchema),
        response: {
          200: toFastifyJsonSchema(okSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = z.object({ groupId: uuidSchema }).parse(request.params);
      const body = groupMemberBodySchema.parse(request.body);
      try {
        await addGroupMember(pool, {
          tenantId: body.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          groupId: params.groupId,
          targetPrincipalId: body.principalId,
        });
        return { ok: true };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.delete(
    '/groups/:groupId/members',
    {
      schema: {
        params: toFastifyJsonSchema(z.object({ groupId: uuidSchema })),
        querystring: toFastifyJsonSchema(groupMemberRemoveQuerySchema),
        response: {
          200: toFastifyJsonSchema(okSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = z.object({ groupId: uuidSchema }).parse(request.params);
      const query = groupMemberRemoveQuerySchema.parse(request.query);
      try {
        const removed = await removeGroupMember(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          groupId: params.groupId,
          targetPrincipalId: query.principalId,
        });
        if (!removed) return reply.code(404).send(NOT_FOUND);
        return { ok: true };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  // ---------- Admin: document grants (S1, manage-gated; S3 closes policy gap) ----------

  app.get(
    '/documents/:id/grants',
    {
      schema: {
        params: toFastifyJsonSchema(documentParamsSchema),
        response: {
          200: toFastifyJsonSchema(grantListSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = documentParamsSchema.parse(request.params);
      const requestId = newRequestId();
      // The document is resolved across the principal's own tenants; the
      // manage gate inside listGrants makes foreign/nonexistent/unmanageable
      // documents all yield null (404).
      const grants = await acrossTenants(pool, request.principalId, (tenantId) =>
        listGrants(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
        }),
      );
      if (grants === null) return reply.code(404).send(NOT_FOUND);
      return { grants: toGrantListEntries(grants) };
    },
  );

  app.post(
    '/documents/:id/grants',
    {
      schema: {
        params: toFastifyJsonSchema(documentParamsSchema),
        body: toFastifyJsonSchema(grantBodySchema),
        response: {
          201: toFastifyJsonSchema(grantCreateResponseSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = documentParamsSchema.parse(request.params);
      const body = grantBodySchema.parse(request.body);
      const requestId = newRequestId();
      const grant = await acrossTenants(pool, request.principalId, (tenantId) =>
        addGrant(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
          subjectType: body.subjectType,
          subjectId: body.subjectId,
          capability: body.capability,
        }),
      );
      if (grant === null) return reply.code(404).send(NOT_FOUND);
      return reply.code(201).send({ grant: { ...grant, createdAt: grant.createdAt.toISOString() } });
    },
  );

  app.delete(
    '/documents/:id/grants',
    {
      schema: {
        params: toFastifyJsonSchema(documentParamsSchema),
        body: toFastifyJsonSchema(grantRemoveBodySchema),
        response: {
          200: toFastifyJsonSchema(okSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = documentParamsSchema.parse(request.params);
      const body = grantRemoveBodySchema.parse(request.body);
      const requestId = newRequestId();
      try {
        const removed = await acrossTenants(pool, request.principalId, (tenantId) =>
          removeGrant(pool, {
            tenantId,
            principalId: request.principalId,
            requestId,
            documentId: params.id,
            grantId: body.grantId,
          }),
        );
        if (!removed) return reply.code(404).send(NOT_FOUND);
        return { ok: true };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  // ---------- Admin: injection quarantine (S5, ADR-0006 layers 6/8) ----------
  // Detection is a signal, never a gate: these routes manage the quarantine
  // STATE (default on high-risk ingest scans) via the explicit, audited
  // tenant security review. Review authorization is deterministic
  // (admin OR tenant role 'security_reviewer', in SQL); any other caller —
  // and any foreign/nonexistent version — observes the same 404.

  app.get(
    '/quarantine',
    {
      schema: {
        querystring: toFastifyJsonSchema(quarantineListQuerySchema),
        response: {
          200: toFastifyJsonSchema(quarantineListSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = quarantineListQuerySchema.parse(request.query);
      try {
        const versions = await listQuarantined(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
        });
        return {
          versions: versions.map((v) => ({
            ...v,
            reviewedBy: v.reviewedBy ?? null,
            reviewedAt: v.reviewedAt === null ? null : v.reviewedAt.toISOString(),
            reviewDecision: v.reviewDecision ?? null,
            createdAt: v.createdAt.toISOString(),
          })),
        };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.post(
    '/quarantine/:versionId/review',
    {
      schema: {
        params: toFastifyJsonSchema(quarantineReviewParamsSchema),
        body: toFastifyJsonSchema(quarantineReviewBodySchema),
        response: {
          200: toFastifyJsonSchema(okSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = quarantineReviewParamsSchema.parse(request.params);
      const body = quarantineReviewBodySchema.parse(request.body);
      try {
        const reviewed = await reviewQuarantine(pool, {
          tenantId: body.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          versionId: params.versionId,
          decision: body.decision,
          ...(body.reviewerCtx !== undefined ? { reviewerCtx: body.reviewerCtx } : {}),
        });
        if (!reviewed) return reply.code(404).send(NOT_FOUND);
        return { ok: true };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  // ---------- Admin: tenant retention policy (S9, ADR-0010) ----------
  // GET: members of the tenant may read their policy; PUT: tenant admins only,
  // audited 'retention:changed' with an epoch bump (enforced in core).

  app.get(
    '/retention-policy',
    {
      schema: {
        querystring: toFastifyJsonSchema(retentionPolicyQuerySchema),
        response: {
          200: toFastifyJsonSchema(retentionPolicySchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = retentionPolicyQuerySchema.parse(request.query);
      try {
        const policy = await getRetentionPolicy(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
        });
        if (policy === null) return reply.code(404).send(NOT_FOUND);
        return {
          ...policy,
          updatedAt: policy.updatedAt.toISOString(),
        };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.put(
    '/retention-policy',
    {
      schema: {
        body: toFastifyJsonSchema(retentionPolicyBodySchema),
        response: {
          200: toFastifyJsonSchema(retentionPolicySchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const body = retentionPolicyBodySchema.parse(request.body);
      try {
        const policy = await upsertRetentionPolicy(pool, {
          tenantId: body.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          patch: {
            ...(body.sourceDays !== undefined ? { sourceDays: body.sourceDays } : {}),
            ...(body.derivedDays !== undefined ? { derivedDays: body.derivedDays } : {}),
            ...(body.auditDays !== undefined ? { auditDays: body.auditDays } : {}),
            ...(body.graceDays !== undefined ? { graceDays: body.graceDays } : {}),
            ...(body.legalHold !== undefined ? { legalHold: body.legalHold } : {}),
          },
        });
        if (policy === null) return reply.code(404).send(NOT_FOUND);
        return {
          ...policy,
          updatedAt: policy.updatedAt.toISOString(),
        };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  // ---------- S2 ingestion: upload -> job -> authorized source stream (ADR-0007) ----------
  // The upload route stores the object (SSE-S3, tenant-prefixed
  // content-addressed key) and stages the PENDING version + ingest job; the
  // worker runs the pipeline. The source route streams the object through
  // the API after a per-request RLS + grant re-check — no public URLs ever.

  app.post(
    '/documents/:id/versions/upload',
    {
      schema: {
        params: toFastifyJsonSchema(uploadParamsSchema),
        response: {
          201: toFastifyJsonSchema(uploadResponseSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = uploadParamsSchema.parse(request.params);
      const part = await request.file();
      if (part === undefined) return reply.code(400).send(INVALID_REQUEST);
      // Bounded by the multipart plugin (50 MB); toBuffer honors the cap.
      const bytes = await part.toBuffer();
      if (bytes.length === 0) return reply.code(400).send(INVALID_REQUEST);
      const requestId = newRequestId();
      const sha256Hex = createHash('sha256').update(bytes).digest('hex');
      const filename = part.filename ?? 'document';
      // Magic-byte sniffing (S2 review 6): the client-supplied mimetype is
      // advisory; the pipeline type is derived from the bytes.
      const contentType = sniffContentType(bytes, part.mimetype ?? '');
      const staged = await acrossTenants(pool, request.principalId, async (tenantId) => {
        // Manage gate first (the owning tenant's probe passes; all others
        // return null identically), then store the object, then stage the
        // version + job. A DB failure deletes the object best-effort.
        const manageable = await canManage(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
        });
        if (!manageable) return null;
        const key = sourceObjectKey(tenantId, sha256Hex, filename);
        await deps.store.put(key, bytes);
        try {
          return await stageUpload(pool, {
            tenantId,
            principalId: request.principalId,
            requestId,
            documentId: params.id,
            objectKey: key,
            sha256Hex,
            filename,
            contentType,
            sizeBytes: bytes.length,
          });
        } catch (err) {
          await deps.store.deleteSources([key]).catch(() => {});
          throw err;
        }
      });
      if (staged === null) return reply.code(404).send(NOT_FOUND);
      return reply.code(201).send({
        jobId: staged.jobId,
        documentId: params.id,
        versionId: staged.versionId,
        status: 'pending',
      });
    },
  );

  app.get(
    '/documents/:id/versions/:versionId/source',
    {
      schema: {
        params: toFastifyJsonSchema(sourceParamsSchema),
        response: {
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = sourceParamsSchema.parse(request.params);
      const requestId = newRequestId();
      void reply.header('x-request-id', requestId);
      const key = await acrossTenants(pool, request.principalId, (tenantId) =>
        getSourceObjectKey(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
          versionId: params.versionId,
        }),
      );
      // Foreign/nonexistent/not-published versions AND missing objects share
      // the same 404 body (no enumeration).
      if (key === null) return reply.code(404).send(NOT_FOUND);
      const bytes = await deps.store.get(key);
      if (bytes === null) return reply.code(404).send(NOT_FOUND);
      return reply
        .header('content-type', 'application/octet-stream')
        .header('content-length', String(bytes.length))
        .send(bytes);
    },
  );

  app.get(
    '/jobs/:jobId',
    {
      schema: {
        params: toFastifyJsonSchema(jobParamsSchema),
        response: {
          200: toFastifyJsonSchema(jobStatusSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = jobParamsSchema.parse(request.params);
      const requestId = newRequestId();
      void reply.header('x-request-id', requestId);
      const job = await acrossTenants(pool, request.principalId, (tenantId) =>
        getJobStatus(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          jobId: params.jobId,
        }),
      );
      if (job === null) return reply.code(404).send(NOT_FOUND);
      return {
        jobId: job.jobId,
        jobType: job.jobType,
        status: job.status,
        createdAt: job.createdAt.toISOString(),
        updatedAt: job.updatedAt.toISOString(),
      };
    },
  );

  // ---------- Document library (S10 console, spec §3 GET/POST /documents) ----------
  // The list is default-deny: rows exist only for documents the principal can
  // read (any grant) or manages (grant or active tenant admin); capability
  // flags come from the same SQL predicates as every enforcement path.
  // Foreign tenants and non-members are indistinguishable 404s. Create is
  // member-scoped (RLS WITH CHECK pins tenant_id to the verified context) and
  // grants the creator 'manage' (audited, epoch-bumped) so upload can proceed.

  app.get(
    '/documents',
    {
      schema: {
        querystring: toFastifyJsonSchema(tenantQuerySchema),
        response: {
          200: toFastifyJsonSchema(documentListSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = tenantQuerySchema.parse(request.query);
      try {
        const documents = await listDocuments(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
        });
        return { documents };
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.post(
    '/documents',
    {
      schema: {
        body: toFastifyJsonSchema(documentCreateSchema),
        response: {
          201: toFastifyJsonSchema(documentCreateResponseSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const body = documentCreateSchema.parse(request.body);
      try {
        const document = await createDocument(pool, {
          tenantId: body.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          title: body.title,
        });
        if (document === null) return reply.code(404).send(NOT_FOUND);
        return reply.code(201).send({ document });
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  // ---------- Retrieval + documents (T3 semantics unchanged; session-auth now) ----------

  app.post(
    '/retrieval/query',
    {
      config: { rateLimit: { max: rateLimitCfg.retrievalMax ?? DEFAULT_RATE_LIMITS.retrievalMax, timeWindow: rateLimitCfg.retrievalWindowMs ?? DEFAULT_RATE_LIMITS.retrievalWindowMs } },
      schema: {
        body: toFastifyJsonSchema(retrievalQuerySchema),
        response: {
          200: toFastifyJsonSchema(retrievalOutcomeSchema),
          400: toFastifyJsonSchema(problemSchema),
          401: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const body = retrievalQuerySchema.parse(request.body);
      const requestId = newRequestId();
      void reply.header('x-request-id', requestId);
      try {
        return await runRetrieval(
          { pool, providers, pii },
          {
            tenantId: body.tenantId,
            principalId: request.principalId,
            requestId,
            question: body.question,
          },
        );
      } catch (err) {
        if (err instanceof MembershipError) return REFUSED_INSUFFICIENT_EVIDENCE;
        throw err;
      }
    },
  );

  app.get(
    '/documents/:id',
    {
      schema: {
        params: toFastifyJsonSchema(documentParamsSchema),
        response: {
          200: toFastifyJsonSchema(documentInfoSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = documentParamsSchema.parse(request.params);
      const requestId = newRequestId();
      void reply.header('x-request-id', requestId);
      const document = await acrossTenants(pool, request.principalId, (tenantId) =>
        getDocument(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
        }),
      );
      if (document === null) return reply.code(404).send(NOT_FOUND);
      return document;
    },
  );

  app.get(
    '/documents/:id/versions',
    {
      schema: {
        params: toFastifyJsonSchema(documentParamsSchema),
        response: {
          200: toFastifyJsonSchema(versionListSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = documentParamsSchema.parse(request.params);
      const requestId = newRequestId();
      void reply.header('x-request-id', requestId);
      // S3 history capability (ADR-0003 amendment): manage-grant holders see
      // every version's metadata (incl. non-current); all other grant holders
      // see only the current version. Foreign/nonexistent/unmanageable
      // documents yield the same 404.
      const versions = await acrossTenants(pool, request.principalId, (tenantId) =>
        listVersions(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
        }),
      );
      if (versions === null) return reply.code(404).send(NOT_FOUND);
      return { versions: versions.map(toVersionMetadataDto) };
    },
  );

  app.get(
    '/documents/:id/versions/:versionId',
    {
      schema: {
        params: toFastifyJsonSchema(versionParamsSchema),
        response: {
          200: toFastifyJsonSchema(versionMetadataSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = versionParamsSchema.parse(request.params);
      const requestId = newRequestId();
      void reply.header('x-request-id', requestId);
      // S3: a non-current versionId resolves ONLY for manage-grant holders
      // (history = manage capability); everyone else observes the same 404 as
      // foreign/nonexistent versions.
      const version = await acrossTenants(pool, request.principalId, (tenantId) =>
        getVersionWithHistory(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
          versionId: params.versionId,
        }),
      );
      if (version === null) return reply.code(404).send(NOT_FOUND);
      return toVersionMetadataDto(version);
    },
  );

  app.get(
    '/citations/:citationId',
    {
      schema: {
        params: toFastifyJsonSchema(citationParamsSchema),
        response: {
          200: toFastifyJsonSchema(resolvedCitationSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const params = citationParamsSchema.parse(request.params);
      const requestId = newRequestId();
      void reply.header('x-request-id', requestId);
      const citation = await acrossTenants(pool, request.principalId, (tenantId) =>
        resolveCitation(
          pool,
          {
            tenantId,
            principalId: request.principalId,
            requestId,
            citationId: params.citationId,
          },
          pii,
        ),
      );
      if (citation === null) return reply.code(404).send(NOT_FOUND);
      // S3 hardening: the resolved response carries the `resolvable` flag
      // (always true on 200 — unresolvable citations are indistinguishable
      // 404s), so clients can detect stale references from earlier answers.
      return { ...citation, resolvable: true };
    },
  );

  app.get(
    '/audit/retrieval',
    {
      schema: {
        querystring: toFastifyJsonSchema(auditQuerySchema),
        response: {
          200: toFastifyJsonSchema(auditListSchema),
          400: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request) => {
      const query = auditQuerySchema.parse(request.query);
      const requestId = newRequestId();
      const identity = await withIdentityContext(pool, request.principalId, async () => undefined);
      const tenantIds = identity.memberships.map((m) => m.tenantId).sort();
      // Filters and the keyset cursor are evaluated per tenant in SQL (RLS
      // keeps every list tenant-isolated); event_id is a single global
      // sequence, so the cursor is comparable across tenants after merging.
      const lists = await Promise.all(
        tenantIds.map((tenantId) =>
          listAudit(pool, {
            tenantId,
            principalId: request.principalId,
            requestId,
            // One extra row per tenant detects "more pages" for the cursor;
            // the final page is sliced below.
            limit: query.limit + 1,
            ...(query.eventType !== undefined ? { eventType: query.eventType } : {}),
            ...(query.from !== undefined ? { from: query.from } : {}),
            ...(query.to !== undefined ? { to: query.to } : {}),
            ...(query.principalId !== undefined ? { forPrincipalId: query.principalId } : {}),
            ...(query.cursor !== undefined ? { cursor: query.cursor } : {}),
          }),
        ),
      );
      const events = lists.flat().sort((a, b) => (BigInt(a.eventId) > BigInt(b.eventId) ? -1 : 1));
      const dtos = events.slice(0, query.limit).map(toAuditRecordDto);
      const nextCursor = events.length > query.limit ? (events[query.limit - 1]?.eventId ?? null) : null;
      return { events: dtos, nextCursor };
    },
  );

  // ---------- S8: WORM audit export (ADR-0010) ----------
  // Tenant admins AND active 'security_reviewer' members may export; any
  // other caller — including members, foreign principals, and nonexistent
  // tenants — observes the same 404 (no enumeration, no gate oracle). The
  // successful export is itself audited ('audit:exported') inside the export
  // transaction, and every export carries a self-verifying body hash + chain
  // anchor (docs/ops/audit-export.md).

  app.get(
    '/audit/export',
    {
      schema: {
        querystring: toFastifyJsonSchema(auditExportQuerySchema),
        response: {
          200: toFastifyJsonSchema(auditExportResponseSchema),
          400: toFastifyJsonSchema(problemSchema),
          404: toFastifyJsonSchema(problemSchema),
          500: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (request, reply) => {
      const query = auditExportQuerySchema.parse(request.query);
      try {
        const doc = await exportAudit(pool, {
          tenantId: query.tenantId,
          principalId: request.principalId,
          requestId: newRequestId(),
          exporter: request.principalId,
        });
        if (doc === null) return reply.code(404).send(NOT_FOUND);
        return reply.code(200).send(doc);
      } catch (err) {
        if (isIndistinguishableDenial(err)) return reply.code(404).send(NOT_FOUND);
        throw err;
      }
    },
  );

  app.get(
    '/healthz',
    { schema: { response: { 200: toFastifyJsonSchema(statusSchema) } } },
    async () => ({ status: 'ok' }),
  );

  app.get(
    '/readyz',
    {
      schema: {
        response: {
          200: toFastifyJsonSchema(statusSchema),
          503: toFastifyJsonSchema(problemSchema),
        },
      },
    },
    async (_request, reply) => {
      try {
        await pool.query('SELECT 1');
        return { status: 'ready' };
      } catch {
        return reply.code(503).send(NOT_READY);
      }
    },
  );

  return app;
}
