import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { FastifyInstance } from 'fastify';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { InMemorySpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { PinoInstrumentation } from '@opentelemetry/instrumentation-pino';
import fastifyOtel from '@fastify/otel';
import { trace } from '@opentelemetry/api';
import { SpyGenerator } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { InMemorySourceObjectStore } from '@securerag/core';
import {
  getTestDb,
  resetData,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { buildT3Corpus } from '@securerag/eval/src/fixtures.js';
import { buildApp, type OidcApiConfig } from '../src/app.js';
import { loginViaOidc } from './auth-helpers.js';

const { FastifyOtelInstrumentation } = fastifyOtel;
const require = createRequire(import.meta.url);

/**
 * S10 OTel attribute safety (ADR-0011): a test hook captures the spans
 * produced during a real retrieval and asserts ZERO content in span
 * attributes — no question text, no retrieved chunk text, no answer text, no
 * citation excerpts. Only identifiers/status-style attributes may appear.
 * Also asserts instrumentation-pino correlates log records with the active
 * trace (trace_id/span_id fields). One SDK + app for the whole suite (a
 * second NodeSDK after shutdown() emits no spans in-process).
 */
describe('S10 OTel — no content in span attributes; pino trace correlation', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;
  let sdk: NodeSDK;
  let exporter: InMemorySpanExporter;

  // Distinctive markers that must NEVER appear in span attributes or pino
  // records: the question, the retrieved chunk texts, the generated answer.
  const QUESTION = 'securerag otel safety marker query Q9F3-QUERY';
  const ANSWER_MARKER = 'Synthesis of authorized evidence';
  const CHUNK_MARKER = 'Alpha secret formula';

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = (await buildT3Corpus(db.superuserPool)).world;
    api = db.apiPool;
    provider = new FakeOidcProvider({ issuer: 'test-issuer', clientId: 'securerag-api' });
    await provider.start();

    exporter = new InMemorySpanExporter();
    const instrumentation = new FastifyOtelInstrumentation();
    sdk = new NodeSDK({
      serviceName: 'securerag-api-test',
      instrumentations: [instrumentation, new PinoInstrumentation()],
      spanProcessor: new SimpleSpanProcessor(exporter),
    });
    sdk.start();

    const oidc: OidcApiConfig = {
      issuer: 'test-issuer',
      clientId: 'securerag-api',
      redirectUri: 'http://securerag.test/auth/callback',
      postLogoutRedirectUri: 'http://securerag.test/',
      discoveryUrl: provider.discoveryUrl,
      sessionCookieName: 'securerag_session',
      sessionCookieSecure: false,
      sessionTtlSeconds: 3600,
    };
    app = await buildApp({
      pool: api,
      providers: new SpyGenerator(),
      store: new InMemorySourceObjectStore(),
      oidc,
      otel: { instrumentation },
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await app.close();
    await sdk.shutdown();
    await provider.stop();
    await db.stop();
  });

  async function runRetrieval(subject: string): Promise<Response> {
    const session = await loginViaOidc(base, provider, subject);
    return fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId: world.tenantA.id, question: QUESTION }),
    });
  }

  /** The root SERVER span for the retrieval route (hook spans carry http.route
   * too, but only the root span carries the response status). */
  function requestSpans() {
    return exporter.getFinishedSpans().filter((s) => s.name === 'request');
  }

  function assertNoContent(spanName: string, attributes: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(attributes)) {
      const serialized = JSON.stringify(value);
      expect(serialized, `${spanName} attribute ${key} leaked the question`).not.toContain(QUESTION);
      expect(serialized, `${spanName} attribute ${key} leaked the answer`).not.toContain(ANSWER_MARKER);
      expect(serialized, `${spanName} attribute ${key} leaked chunk content`).not.toContain(CHUNK_MARKER);
      // identifiers/status only: no content-bearing keys
      expect(key.toLowerCase(), `${spanName} content-bearing attribute key`).not.toMatch(
        /content|body|payload|prompt|answer|text|query|question|excerpt/i,
      );
    }
  }

  it('1. spans captured during an answered retrieval carry identifiers/status only — zero content attributes', async () => {
    exporter.reset();
    const res = await runRetrieval('alice-sub');
    expect(res.status).toBe(200);

    const spans = requestSpans();
    const route = spans.find((s) => s.attributes['http.route'] === '/retrieval/query');
    expect(route).toBeDefined();
    expect(route?.attributes['http.response.status_code']).toBe(200);
    expect(route?.attributes['http.request.method']).toBe('POST');

    for (const span of spans) {
      expect(span.status.code, span.name).toBe(0);
      assertNoContent(span.name, span.attributes);
    }
  });

  it('2. a refusal spans too — still no content attributes', async () => {
    exporter.reset();
    const res = await runRetrieval('carol-sub');
    expect(res.status).toBe(200);

    const spans = requestSpans();
    const route = spans.find((s) => s.attributes['http.route'] === '/retrieval/query');
    expect(route).toBeDefined();
    expect(route?.attributes['http.response.status_code']).toBe(200);
    for (const span of spans) {
      assertNoContent(span.name, span.attributes);
    }
  });

  it('3. instrumentation-pino: a log record inside an active span carries the trace identifiers', async () => {
    // pino is only loaded AFTER the SDK started (fastify runs logger:false),
    // so the instrumentation patch applies to this native require.
    const lines: string[] = [];
    const { pino } = require('pino') as typeof import('pino');
    const logger = pino(
      { level: 'info', base: null, formatters: { level: (level) => ({ level }) } },
      {
        write: (line: string) => {
          lines.push(line);
        },
      },
    );

    const tracer = trace.getTracer('securerag-api-test');
    await tracer.startActiveSpan('pino.correlation.test', async (span) => {
      logger.info({ status: 'ok' }, 'correlation log record');
      span.end();
    });

    expect(lines.length).toBeGreaterThan(0);
    const record = JSON.parse(lines[0] ?? '{}') as {
      trace_id?: string;
      span_id?: string;
      msg?: string;
    };
    expect(record.trace_id).toBeDefined();
    expect(record.span_id).toBeDefined();
    // the record itself never carries content either
    expect(lines.join('')).not.toContain(ANSWER_MARKER);
    expect(record.msg).toBe('correlation log record');
  });
});
