import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import Fastify, {
  type FastifyError,
  type FastifyInstance,
} from 'fastify';
import fastifySwagger from '@fastify/swagger';
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
  createGroup,
  deleteGroup,
  getDocument,
  getVersion,
  listAudit,
  listGrants,
  listGroups,
  listTenantMembers,
  removeGrant,
  removeGroupMember,
  removeMembership,
  resolveCitation,
  runRetrieval,
  setMembershipActive,
  setMembershipRole,
  upsertPrincipal,
  type AuditRecord,
} from '@securerag/core';
import type { AnswerGenerator } from '@securerag/providers';
import type { OracleFacts } from '@securerag/eval/src/oracle.js';
import {
  auditListSchema,
  auditQuerySchema,
  callbackQuerySchema,
  citationParamsSchema,
  citationSchema,
  documentInfoSchema,
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
  meSchema,
  membershipCreateResponseSchema,
  membershipCreateSchema,
  membershipListSchema,
  membershipRemoveQuerySchema,
  membershipUpdateSchema,
  okSchema,
  problemSchema,
  retrievalOutcomeSchema,
  retrievalQuerySchema,
  statusSchema,
  tenantQuerySchema,
  uuidSchema,
  versionInfoSchema,
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
    ...(oidcCfg.httpFetch !== undefined ? { httpFetch: oidcCfg.httpFetch } : {}),
  });
  const loginStore = new InMemoryLoginStore();
  validateSessionCookieConfig(oidcCfg.sessionCookieName, oidcCfg.sessionCookieSecure);

  const app = Fastify({ logger: false });
  app.decorate('secureRag', deps);

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

  // Responses are plain JSON.stringify of handler values: no schema-driven
  // stripping, no fast-json-stringify constraints on union response shapes.
  app.setSerializerCompiler(() => (data: unknown) => JSON.stringify(data));

  app.setNotFoundHandler((_request, reply) => reply.code(404).send(NOT_FOUND));

  app.setErrorHandler((err: FastifyError, request, reply) => {
    if (err instanceof ZodError || err.validation) {
      return reply.code(400).send(INVALID_REQUEST);
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

  // ---------- Auth (S1) ----------

  app.get(
    '/auth/login',
    async (_request, reply) => {
      const flow = oidcClient.createLoginFlow();
      loginStore.add(flow);
      const url = await oidcClient.buildAuthorizationUrl(flow);
      return reply.code(302).header('location', url).send();
    },
  );

  app.get(
    '/auth/callback',
    { schema: { querystring: toFastifyJsonSchema(callbackQuerySchema) } },
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
      return {
        grants: grants.map((g) => ({ ...g, createdAt: g.createdAt.toISOString() })),
      };
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

  // ---------- Retrieval + documents (T3 semantics unchanged; session-auth now) ----------

  app.post(
    '/retrieval/query',
    {
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
          { pool, providers },
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
    '/documents/:id/versions/:versionId',
    {
      schema: {
        params: toFastifyJsonSchema(versionParamsSchema),
        response: {
          200: toFastifyJsonSchema(versionInfoSchema),
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
      const version = await acrossTenants(pool, request.principalId, (tenantId) =>
        getVersion(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          documentId: params.id,
          versionId: params.versionId,
        }),
      );
      if (version === null) return reply.code(404).send(NOT_FOUND);
      return version;
    },
  );

  app.get(
    '/citations/:citationId',
    {
      schema: {
        params: toFastifyJsonSchema(citationParamsSchema),
        response: {
          200: toFastifyJsonSchema(citationSchema),
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
        resolveCitation(pool, {
          tenantId,
          principalId: request.principalId,
          requestId,
          citationId: params.citationId,
        }),
      );
      if (citation === null) return reply.code(404).send(NOT_FOUND);
      return citation;
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
      const lists = await Promise.all(
        tenantIds.map((tenantId) =>
          listAudit(pool, {
            tenantId,
            principalId: request.principalId,
            requestId,
            limit: query.limit,
          }),
        ),
      );
      const events = lists
        .flat()
        .sort((a, b) => b.eventId.localeCompare(a.eventId))
        .slice(0, query.limit)
        .map(toAuditRecordDto);
      return { events };
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
