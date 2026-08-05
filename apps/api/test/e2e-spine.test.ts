import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import {
  getTestDb,
  resetData,
  revokeGrant,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { buildT3Corpus, type T3Corpus } from '@securerag/eval/src/fixtures.js';
import { computeAllowed, type AllowedSets } from '@securerag/eval/src/oracle.js';
import { buildApp } from '../src/app.js';
import { loginViaOidc, type AuthenticatedSession } from './auth-helpers.js';

const REFUSAL_BODY = JSON.stringify({
  decision: 'refused',
  code: 'INSUFFICIENT_EVIDENCE',
  message: 'No sufficient authorized evidence to answer.',
});

const NOT_FOUND_BODY = JSON.stringify({
  code: 'NOT_FOUND',
  message: 'Resource not found',
});

const INVALID_BODY = JSON.stringify({
  code: 'INVALID_REQUEST',
  message: 'Invalid request',
});

const UNAUTHORIZED_BODY = JSON.stringify({
  code: 'UNAUTHORIZED',
  message: 'Authentication required',
});

/**
 * T3-B2 API E2E (contract §G2 gate tests, apps/api deliverable), migrated to
 * the S1 REAL OIDC login flow: the Fastify server over HTTP (fetch) with the
 * least-privilege runtime pool (securerag_api), Testcontainers PostgreSQL,
 * the in-process fake OIDC provider (issuer 'test-issuer' matching the seeded
 * corpus principals), the shared SpyGenerator, and the independent oracle.
 *
 * Every request rides a session cookie obtained through a full browser-like
 * login; state-changing requests carry the X-CSRF-Token from /auth/me.
 */
describe('T3-B2 API E2E over real HTTP with OIDC sessions', () => {
  let db: TestDb;
  let api: Pool;
  let corpus: T3Corpus;
  let records: SpyRecord[];
  let spy: SpyGenerator;
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    corpus = await buildT3Corpus(db.superuserPool);
    api = db.apiPool;
    records = [];
    spy = new SpyGenerator(records);
    provider = new FakeOidcProvider({
      issuer: 'test-issuer',
      clientId: 'securerag-api',
    });
    await provider.start();
    app = await buildApp({
      pool: api,
      providers: spy,
      facts: () => corpus.facts,
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

  afterEach(async () => {
    await app.close();
    await provider.stop();
  });

  afterAll(async () => {
    await db.stop();
  });

  async function login(subject: string): Promise<AuthenticatedSession> {
    return loginViaOidc(base, provider, subject);
  }

  function postRetrieval(session: AuthenticatedSession | undefined, body: unknown): Promise<Response> {
    return fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(session !== undefined
          ? { cookie: session.cookieHeader, 'x-csrf-token': session.csrfToken }
          : {}),
      },
      body: JSON.stringify(body),
    });
  }

  function getResource(
    path: string,
    session: AuthenticatedSession | undefined,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return fetch(`${base}${path}`, {
      headers: {
        ...(session !== undefined ? { cookie: session.cookieHeader } : {}),
        ...headers,
      },
    });
  }

  const alice = () => corpus.world.alice.id;
  const bob = () => corpus.world.bob.id;
  const tenantA = () => corpus.world.tenantA.id;
  const tenantB = () => corpus.world.tenantB.id;

  const allowedTexts = (oracle: AllowedSets): Set<string> =>
    new Set(
      corpus.facts.chunks.filter((c) => oracle.chunks.has(c.chunkId)).map((c) => c.text),
    );

  it('1. authorized retrieval answers over HTTP; citations resolve via the API; excerpts match the oracle', async () => {
    // the injected oracle-facts accessor (test seam) exposes the same facts
    expect(app.secureRag.facts?.()?.chunks).toHaveLength(corpus.facts.chunks.length);

    const session = await login('alice-sub');
    const res = await postRetrieval(session, { tenantId: tenantA(), question: 'secret formula' });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-request-id')).toBeTruthy();
    const outcome = (await res.json()) as {
      decision: string;
      answer: string;
      citations: {
        documentId: string;
        versionId: string;
        chunkId: string;
        span: { start: number; end: number };
        excerpt: string;
      }[];
    };
    expect(outcome.decision).toBe('answered');
    expect(outcome.citations.length).toBeGreaterThan(0);

    const oracle = computeAllowed(corpus.facts, alice(), tenantA());
    const produced = new Set(outcome.citations.map((c) => c.chunkId));
    for (const id of produced) expect(oracle.chunks.has(id)).toBe(true);
    for (const id of oracle.chunks) expect(produced.has(id)).toBe(true);
    expect(outcome.answer).toContain(outcome.citations.map((c) => c.chunkId).join(','));

    for (const citation of outcome.citations) {
      const factChunk = corpus.facts.chunks.find((c) => c.chunkId === citation.chunkId);
      expect(factChunk).toBeDefined();
      expect(citation.excerpt).toBe(factChunk?.text);

      const resolved = await getResource(`/citations/${citation.chunkId}`, session);
      expect(resolved.status).toBe(200);
      const body = (await resolved.json()) as { chunkId: string; excerpt: string };
      expect(body.chunkId).toBe(citation.chunkId);
      expect(body.excerpt).toBe(citation.excerpt);
    }
    expect(records).toHaveLength(1);
  });

  it('2. foreign tenant refusal is byte-identical to a genuine INSUFFICIENT_EVIDENCE refusal', async () => {
    const aliceSession = await login('alice-sub');
    const carolSession = await login('carol-sub');
    const daveSession = await login('dave-sub');
    const foreign = await postRetrieval(aliceSession, { tenantId: tenantB(), question: 'secret formula' });
    const genuine = await postRetrieval(carolSession, { tenantId: tenantA(), question: 'secret formula' });
    const noMembership = await postRetrieval(daveSession, { tenantId: tenantA(), question: 'secret formula' });
    const unknownTenant = await postRetrieval(aliceSession, {
      tenantId: randomUUID(),
      question: 'secret formula',
    });

    for (const res of [foreign, genuine, noMembership, unknownTenant]) {
      expect(res.status).toBe(200);
      expect(await res.text()).toBe(REFUSAL_BODY);
    }
  });

  it('3. foreign and nonexistent documents/versions/citations are byte-identical 404s', async () => {
    const session = await login('alice-sub');
    const daveSession = await login('dave-sub');
    const foreignDoc = await getResource(`/documents/${corpus.world.docB.id}`, session);
    const nonexistentDoc = await getResource(`/documents/${randomUUID()}`, session);
    const noMembershipDoc = await getResource(`/documents/${corpus.world.docA.id}`, daveSession);
    for (const res of [foreignDoc, nonexistentDoc, noMembershipDoc]) {
      expect(res.status).toBe(404);
      expect(await res.text()).toBe(NOT_FOUND_BODY);
    }

    const foreignVersion = await getResource(
      `/documents/${corpus.world.docB.id}/versions/${corpus.world.docB.versionId}`,
      session,
    );
    const nonexistentVersion = await getResource(
      `/documents/${corpus.world.docA.id}/versions/${randomUUID()}`,
      session,
    );
    for (const res of [foreignVersion, nonexistentVersion]) {
      expect(res.status).toBe(404);
      expect(await res.text()).toBe(NOT_FOUND_BODY);
    }

    const foreignCitation = await getResource(`/citations/${corpus.world.chunks.betaOne}`, session);
    const nonexistentCitation = await getResource(`/citations/${randomUUID()}`, session);
    for (const res of [foreignCitation, nonexistentCitation]) {
      expect(res.status).toBe(404);
      expect(await res.text()).toBe(NOT_FOUND_BODY);
    }
  });

  it('4. member without grant refuses with an EMPTY spy payload', async () => {
    const session = await login('carol-sub');
    const res = await postRetrieval(session, { tenantId: tenantA(), question: 'secret formula' });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(REFUSAL_BODY);
    expect(records).toEqual([]);
  });

  it('5. spy payload: every chunk id ∈ oracle; zero foreign text anywhere', async () => {
    const aliceSession = await login('alice-sub');
    const bobSession = await login('bob-sub');
    const aliceRes = await postRetrieval(aliceSession, { tenantId: tenantA(), question: 'secret formula' });
    const bobRes = await postRetrieval(bobSession, { tenantId: tenantB(), question: 'secret formula' });
    expect(aliceRes.status).toBe(200);
    expect(bobRes.status).toBe(200);

    const aliceOracle = computeAllowed(corpus.facts, alice(), tenantA());
    const bobOracle = computeAllowed(corpus.facts, bob(), tenantB());

    expect(records).toHaveLength(2);
    for (const record of records) {
      // each payload belongs to exactly one tenant's oracle (sets are disjoint)
      const inAlice = record.citations.some((c) => aliceOracle.chunks.has(c.chunkId));
      const inBob = record.citations.some((c) => bobOracle.chunks.has(c.chunkId));
      expect(inAlice !== inBob).toBe(true);
      const oracle = inAlice ? aliceOracle : bobOracle;
      for (const chunk of record.bundle) {
        expect(oracle.chunks.has(chunk.chunkId)).toBe(true);
        expect(allowedTexts(oracle).has(chunk.text)).toBe(true);
      }
      for (const citation of record.citations) {
        expect(oracle.chunks.has(citation.chunkId)).toBe(true);
      }
    }

    // zero foreign text anywhere in what the pipeline sent to the "model"
    const alicePayloads = records.filter((r) =>
      r.citations.some((c) => aliceOracle.chunks.has(c.chunkId)),
    );
    const bobPayloads = records.filter((r) =>
      r.citations.some((c) => bobOracle.chunks.has(c.chunkId)),
    );
    expect(alicePayloads.length).toBeGreaterThan(0);
    expect(bobPayloads.length).toBeGreaterThan(0);
    expect(JSON.stringify(alicePayloads)).not.toContain('Beta');
    expect(JSON.stringify(bobPayloads)).not.toContain('Alpha');

    for (const id of aliceOracle.chunks) expect(bobOracle.chunks.has(id)).toBe(false);
  });

  it('6. grant revoked mid-suite → next request refuses; audit shows retrieval:refused', async () => {
    const session = await login('alice-sub');
    const first = await postRetrieval(session, { tenantId: tenantA(), question: 'secret formula' });
    expect(first.status).toBe(200);
    expect((await first.json()) as { decision: string }).toMatchObject({ decision: 'answered' });
    const firstRequestId = first.headers.get('x-request-id');
    expect(firstRequestId).toBeTruthy();

    await revokeGrant(db.superuserPool, tenantA(), corpus.world.aliceDocAGrant);

    const second = await postRetrieval(session, { tenantId: tenantA(), question: 'secret formula' });
    expect(second.status).toBe(200);
    expect(await second.text()).toBe(REFUSAL_BODY);
    const secondRequestId = second.headers.get('x-request-id');
    expect(secondRequestId).toBeTruthy();

    const audit = await getResource('/audit/retrieval?limit=50', session);
    expect(audit.status).toBe(200);
    const { events } = (await audit.json()) as {
      events: {
        requestId: string;
        eventType: string;
        refusalReason: string | null;
        evidenceDecision: string | null;
      }[];
    };
    expect(
      events.some(
        (e) =>
          e.requestId === secondRequestId &&
          e.eventType === 'retrieval:refused' &&
          e.refusalReason === 'INSUFFICIENT_EVIDENCE',
      ),
    ).toBe(true);
    expect(
      events.some(
        (e) => e.requestId === firstRequestId && e.eventType === 'retrieval:allowed',
      ),
    ).toBe(true);
  });

  it('7. audit isolation via the API: alice sees only tenant-A events, bob only tenant-B', async () => {
    const aliceSession = await login('alice-sub');
    const bobSession = await login('bob-sub');
    const carolSession = await login('carol-sub');
    const aliceReq = await postRetrieval(aliceSession, { tenantId: tenantA(), question: 'secret formula' });
    const bobReq = await postRetrieval(bobSession, { tenantId: tenantB(), question: 'secret formula' });
    const carolReq = await postRetrieval(carolSession, { tenantId: tenantA(), question: 'secret formula' });
    expect(aliceReq.status).toBe(200);
    expect(bobReq.status).toBe(200);
    expect(carolReq.status).toBe(200);
    const aliceRequestId = aliceReq.headers.get('x-request-id');
    const bobRequestId = bobReq.headers.get('x-request-id');
    const carolRequestId = carolReq.headers.get('x-request-id');

    const aliceAudit = await getResource('/audit/retrieval?limit=50', aliceSession);
    const aliceEvents = ((await aliceAudit.json()) as { events: { tenantId: string; requestId: string; eventType: string }[] })
      .events;
    expect(aliceEvents.length).toBeGreaterThan(0);
    expect(aliceEvents.every((e) => e.tenantId === tenantA())).toBe(true);
    expect(aliceEvents.some((e) => e.requestId === aliceRequestId && e.eventType === 'retrieval:allowed')).toBe(true);
    expect(aliceEvents.some((e) => e.requestId === carolRequestId && e.eventType === 'retrieval:refused')).toBe(true);
    expect(aliceEvents.some((e) => e.requestId === bobRequestId)).toBe(false);

    const bobAudit = await getResource('/audit/retrieval?limit=50', bobSession);
    const bobEvents = ((await bobAudit.json()) as { events: { tenantId: string; requestId: string; eventType: string }[] })
      .events;
    expect(bobEvents.length).toBeGreaterThan(0);
    expect(bobEvents.every((e) => e.tenantId === tenantB())).toBe(true);
    expect(bobEvents.some((e) => e.requestId === bobRequestId && e.eventType === 'retrieval:allowed')).toBe(true);
    expect(bobEvents.some((e) => e.requestId === aliceRequestId || e.requestId === carolRequestId)).toBe(false);

    const limited = await getResource('/audit/retrieval?limit=1', aliceSession);
    expect(((await limited.json()) as { events: unknown[] }).events).toHaveLength(1);
  });

  it('8. malformed body / malformed uuid → 400 problem+json, no data, audit silence; no cookie → 401', async () => {
    const session = await login('alice-sub');
    const before = await getResource('/audit/retrieval?limit=100', session);
    const beforeCount = ((await before.json()) as { events: unknown[] }).events.length;

    const badBody = await postRetrieval(session, { tenantId: 'not-a-uuid', question: 'x' });
    expect(badBody.status).toBe(400);
    const badBodyText = await badBody.text();
    expect(badBodyText).toBe(INVALID_BODY);

    const missingQuestion = await postRetrieval(session, { tenantId: tenantA() });
    expect(missingQuestion.status).toBe(400);
    expect(await missingQuestion.text()).toBe(INVALID_BODY);

    // the T3 dev-auth header no longer authenticates: without a session cookie
    // even a well-formed header yields the same 401 as no cookie at all
    const noCookie = await postRetrieval(undefined, { tenantId: tenantA(), question: 'x' });
    expect(noCookie.status).toBe(401);
    expect(await noCookie.text()).toBe(UNAUTHORIZED_BODY);

    const spoofedHeader = await postRetrieval(undefined, { tenantId: tenantA(), question: 'x' });
    const withSpoofedHeader = await fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-securerag-principal': alice(),
      },
      body: JSON.stringify({ tenantId: tenantA(), question: 'x' }),
    });
    void spoofedHeader;
    expect(withSpoofedHeader.status).toBe(401);
    expect(await withSpoofedHeader.text()).toBe(UNAUTHORIZED_BODY);

    const unknownRoute = await getResource('/definitely/not/a/route', session);
    expect(unknownRoute.status).toBe(404);
    expect(await unknownRoute.text()).toBe(NOT_FOUND_BODY);

    // boundary denials carry no candidate data in the response
    expect(badBodyText).not.toContain('secret');
    expect(badBodyText).not.toContain('formula');

    // denials write nothing (B1): the audit trail is untouched by 4xx errors
    const after = await getResource('/audit/retrieval?limit=100', session);
    const afterCount = ((await after.json()) as { events: unknown[] }).events.length;
    expect(afterCount).toBe(beforeCount);
  });

  it('9. own documents/versions resolve; superseded + quarantined versions are invisible', async () => {
    const session = await login('alice-sub');
    const doc = await getResource(`/documents/${corpus.world.docA.id}`, session);
    expect(doc.status).toBe(200);
    expect(await doc.text()).toBe(
      JSON.stringify({
        documentId: corpus.world.docA.id,
        title: 'Alpha private doc',
        status: 'active',
      }),
    );

    const version = await getResource(
      `/documents/${corpus.world.docA.id}/versions/${corpus.world.docA.versionId}`,
      session,
    );
    expect(version.status).toBe(200);
    expect((await version.json()) as { versionNo: number; isCurrent: boolean }).toMatchObject({
      versionNo: 1,
      isCurrent: true,
    });

    // superseded/quarantined versions exist in the corpus but must NOT resolve
    const superseded = await getResource(
      `/documents/${corpus.world.docA.id}/versions/${corpus.world.supersededVersion.id}`,
      session,
    );
    const quarantined = await getResource(
      `/documents/${corpus.world.docA.id}/versions/${corpus.world.quarantinedVersion.id}`,
      session,
    );
    expect(superseded.status).toBe(404);
    expect(quarantined.status).toBe(404);
  });

  it('10. healthz and readyz are 200 and unauthenticated', async () => {
    const healthz = await getResource('/healthz', undefined);
    expect(healthz.status).toBe(200);
    expect((await healthz.json()) as { status: string }).toEqual({ status: 'ok' });

    const readyz = await getResource('/readyz', undefined);
    expect(readyz.status).toBe(200);
    expect((await readyz.json()) as { status: string }).toEqual({ status: 'ready' });
  });
});
