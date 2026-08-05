import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import Fastify, {
  type FastifyError,
  type FastifyInstance,
} from 'fastify';
import fastifySwagger from '@fastify/swagger';
import { ZodError, z } from 'zod';
import { MembershipError, withIdentityContext } from '@securerag/security';
import {
  getDocument,
  getVersion,
  listAudit,
  resolveCitation,
  runRetrieval,
  type AuditRecord,
} from '@securerag/core';
import type { AnswerGenerator } from '@securerag/providers';
import type { OracleFacts } from '@securerag/eval/src/oracle.js';
import {
  auditListSchema,
  auditQuerySchema,
  citationParamsSchema,
  citationSchema,
  documentInfoSchema,
  documentParamsSchema,
  problemSchema,
  retrievalOutcomeSchema,
  retrievalQuerySchema,
  statusSchema,
  uuidSchema,
  versionInfoSchema,
  versionParamsSchema,
} from './schemas.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Verified dev-auth principal id (X-SecureRag-Principal), set by the auth hook. */
    principalId: string;
  }
  interface FastifyInstance {
    /** The injected dependencies, exposed for tests (e.g. the oracle facts accessor). */
    secureRag: ApiDeps;
  }
}

/** DI seam (T3 contract §API): pool is the least-privilege runtime role. */
export interface ApiDeps {
  pool: Pool;
  providers: AnswerGenerator;
  /** Oracle facts accessor for tests (cross-check seam; never used for authorization). */
  facts?: () => OracleFacts;
  /** Injectable request-id generator; defaults to randomUUID. */
  requestId?: () => string;
}

/**
 * Stable problem+json bodies. NEVER differentiate foreign vs nonexistent and
 * never echo internal text: every 4xx/5xx body is one of these constants, so
 * responses are byte-identical across indistinguishable cases.
 */
const UNAUTHORIZED = { code: 'UNAUTHORIZED', message: 'Authentication required' };
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

const DEV_AUTH_HEADER = 'x-securerag-principal';

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
 * Resolve a resource across the principal's own tenants (dev-auth carries no
 * tenant; the principal's active memberships define their scope). Deterministic
 * probe order; foreign and nonexistent both yield null, so callers emit the
 * same 404. Denials write nothing (B1 decision: denials write no audit).
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

export async function buildApp(deps: ApiDeps): Promise<FastifyInstance> {
  const { pool, providers } = deps;
  const newRequestId = deps.requestId ?? randomUUID;

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
          devPrincipal: {
            type: 'apiKey',
            in: 'header',
            name: 'X-SecureRag-Principal',
            description:
              'T3-only test transport: the header value maps EXACTLY to the principal id. ' +
              'No other authentication exists in T3; OIDC replaces this in S1.',
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

  app.addHook('onRequest', async (request, reply) => {
    const path = (request.raw.url ?? '').split('?')[0];
    if (path === '/healthz' || path === '/readyz') return;
    const header = request.headers[DEV_AUTH_HEADER];
    if (header === undefined) {
      return reply.code(401).send(UNAUTHORIZED);
    }
    const parsed = uuidSchema.safeParse(header);
    if (!parsed.success) {
      return reply.code(400).send(INVALID_REQUEST);
    }
    request.principalId = parsed.data;
  });

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
