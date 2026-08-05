/**
 * S4 API E2E: HTTP retrieval of the pii-doc by a member (piiRead=false)
 * answers with a REDACTED context — the response citations carry canonical
 * replacement tokens and never raw PII; the citation surface is redacted too.
 * Uses the ST canary corpus so the oracle facts and the seeded pii_read flags
 * (admins true, members false) are the real ST shapes.
 */
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { InMemorySourceObjectStore } from '@securerag/core';
import { getTestDb, resetData, type TestDb } from '@securerag/db/src/testkit.js';
import { buildApp } from '../src/app.js';
import { loginViaOidc, type AuthenticatedSession } from './auth-helpers.js';
import { buildCanaryCorpus, type CanaryWorld } from '@securerag/eval/src/canary-corpus.js';

// The same shapes the ST harness scans: raw PII must never survive any surface.
const RAW_PII_RE =
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b|\b4\d{3} \d{4} \d{4} \d{4}\b/;

describe('S4 API E2E — pii-doc retrieval is answered with a redacted context', () => {
  let db: TestDb;
  let api: Pool;
  let world: CanaryWorld;
  let records: SpyRecord[];
  let spy: SpyGenerator;
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await buildCanaryCorpus(db.superuserPool);
    api = db.apiPool;
    records = [];
    spy = new SpyGenerator(records);
    provider = new FakeOidcProvider({ issuer: 'test-issuer', clientId: 'securerag-api' });
    await provider.start();
    app = await buildApp({
      pool: api,
      providers: spy,
      store: new InMemorySourceObjectStore(),
      facts: () => world.facts,
      oidc: {
        issuer: 'test-issuer',
        clientId: 'securerag-api',
        redirectUri: 'http://securerag.test/auth/callback',
        postLogoutRedirectUri: 'http://securerag.test/',
        discoveryUrl: provider.discoveryUrl,
        sessionCookieName: 'securerag_session',
        sessionCookieSecure: false,
        sessionTtlSeconds: 3600,
        postLoginRedirectPath: '/',
      },
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await app.close();
    await provider.stop();
    await db.stop();
  });

  it('member-0 (piiRead=false) queries the pii-doc: answered, citations redacted, zero raw PII', async () => {
    const tenantId = world.facts.tenants[0]!.id;
    const piiChunk = world.facts.chunks.find((c) => c.tenantId === tenantId && c.hasPii);
    expect(piiChunk).toBeDefined();

    const session: AuthenticatedSession = await loginViaOidc(base, provider, 'member-0-sub');
    const res = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
      },
      body: JSON.stringify({ tenantId, question: 'client contact' }),
    });
    expect(res.status).toBe(200);
    const outcome = (await res.json()) as {
      decision: string;
      citations: { chunkId: string; excerpt: string }[];
    };
    expect(outcome.decision).toBe('answered');
    expect(outcome.citations.map((c) => c.chunkId)).toContain(piiChunk!.chunkId);

    // the model payload that was sent carries tokens, not values
    expect(records.length).toBeGreaterThan(0);
    const payloadText = records.flatMap((r) => r.bundle.map((b) => b.text)).join('\n');
    expect(payloadText).not.toMatch(RAW_PII_RE);
    expect(payloadText).toContain('[EMAIL]');
    expect(payloadText).toContain('[SSN]');
    expect(payloadText).toContain('[CREDIT_CARD]');

    // the response citations are redacted derivatives
    const piiCitation = outcome.citations.find((c) => c.chunkId === piiChunk!.chunkId);
    expect(piiCitation).toBeDefined();
    expect(piiCitation!.excerpt).not.toMatch(RAW_PII_RE);
    expect(piiCitation!.excerpt).toContain('[EMAIL]');
    expect(piiCitation!.excerpt).toContain('[PHONE]');
    expect(piiCitation!.excerpt).toContain('[SSN]');
    expect(piiCitation!.excerpt).toContain('[CREDIT_CARD]');
  });

  it('member-0 resolves the pii citation over HTTP: excerpt is redacted', async () => {
    const tenantId = world.facts.tenants[0]!.id;
    const piiChunk = world.facts.chunks.find((c) => c.tenantId === tenantId && c.hasPii);
    expect(piiChunk).toBeDefined();

    const session = await loginViaOidc(base, provider, 'member-0-sub');
    const res = await fetch(`${base}/citations/${piiChunk!.chunkId}`, {
      headers: { cookie: session.cookieHeader },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { chunkId: string; excerpt: string };
    expect(body.chunkId).toBe(piiChunk!.chunkId);
    expect(body.excerpt).not.toMatch(RAW_PII_RE);
    expect(body.excerpt).not.toContain(world.piiValues.email);
    expect(body.excerpt).toContain('[EMAIL]');
    expect(body.excerpt).toContain('[SSN]');
  });

  it('admin-0 (piiRead=true, no pii-doc grant) still cannot read the pii citation (authorization, not redaction)', async () => {
    const tenantId = world.facts.tenants[0]!.id;
    const piiChunk = world.facts.chunks.find((c) => c.tenantId === tenantId && c.hasPii);
    expect(piiChunk).toBeDefined();

    const session = await loginViaOidc(base, provider, 'admin-0-sub');
    const res = await fetch(`${base}/citations/${piiChunk!.chunkId}`, {
      headers: { cookie: session.cookieHeader },
    });
    // indistinguishable denial: 404 problem+json, no content
    expect(res.status).toBe(404);
    const body = await res.text();
    expect(body).not.toContain(piiChunk!.chunkId);
    expect(body).not.toContain(world.piiValues.email);
  });
});
