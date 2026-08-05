import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import {
  getTestDb,
  resetData,
  revokeGrant,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { buildT3Corpus, type T3Corpus } from '@securerag/eval/src/fixtures.js';
import { computeAllowed, type AllowedSets } from '@securerag/eval/src/oracle.js';
import { buildApp } from '../src/app.js';

const DEV_AUTH_HEADER = 'x-securerag-principal';

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

/**
 * T3-B2 API E2E (contract §G2 gate tests, apps/api deliverable): the REAL
 * Fastify server over HTTP (fetch) with the real least-privilege runtime pool
 * (securerag_api), Testcontainers PostgreSQL, the shared SpyGenerator, and the
 * independent oracle for cross-checks.
 *
 * Note on the "audited" expectation for malformed requests: client-side 4xx
 * boundary errors have no verified tenant to establish a security context in,
 * so per the B1 decision (denials write nothing) they leave the audit trail
 * untouched; the suite asserts that silence.
 */
describe('T3-B2 API E2E — G2 security spine over real HTTP', () => {
  let db: TestDb;
  let api: Pool;
  let corpus: T3Corpus;
  let records: SpyRecord[];
  let spy: SpyGenerator;
  let app: FastifyInstance;
  let base: string;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    corpus = await buildT3Corpus(db.superuserPool);
    api = db.apiPool;
    records = [];
    spy = new SpyGenerator(records);
    app = await buildApp({ pool: api, providers: spy, facts: () => corpus.facts });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterEach(async () => {
    await app.close();
  });

  afterAll(async () => {
    await db.stop();
  });

  function postRetrieval(principalId: string | undefined, body: unknown): Promise<Response> {
    return fetch(`${base}/retrieval/query`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(principalId !== undefined ? { [DEV_AUTH_HEADER]: principalId } : {}),
      },
      body: JSON.stringify(body),
    });
  }

  function getResource(
    path: string,
    principalId: string | undefined,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return fetch(`${base}${path}`, {
      headers: {
        ...(principalId !== undefined ? { [DEV_AUTH_HEADER]: principalId } : {}),
        ...headers,
      },
    });
  }

  const alice = () => corpus.world.alice.id;
  const bob = () => corpus.world.bob.id;
  const carol = () => corpus.world.carol.id;
  const dave = () => corpus.world.dave.id;
  const tenantA = () => corpus.world.tenantA.id;
  const tenantB = () => corpus.world.tenantB.id;

  const allowedTexts = (oracle: AllowedSets): Set<string> =>
    new Set(
      corpus.facts.chunks.filter((c) => oracle.chunks.has(c.chunkId)).map((c) => c.text),
    );

  it('1. authorized retrieval answers over HTTP; citations resolve via the API; excerpts match the oracle', async () => {
    // the injected oracle-facts accessor (test seam) exposes the same facts
    expect(app.secureRag.facts?.()?.chunks).toHaveLength(corpus.facts.chunks.length);

    const res = await postRetrieval(alice(), { tenantId: tenantA(), question: 'secret formula' });
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

      const resolved = await getResource(`/citations/${citation.chunkId}`, alice());
      expect(resolved.status).toBe(200);
      const body = (await resolved.json()) as { chunkId: string; excerpt: string };
      expect(body.chunkId).toBe(citation.chunkId);
      expect(body.excerpt).toBe(citation.excerpt);
    }
    expect(records).toHaveLength(1);
  });

  it('2. foreign tenant refusal is byte-identical to a genuine INSUFFICIENT_EVIDENCE refusal', async () => {
    const foreign = await postRetrieval(alice(), { tenantId: tenantB(), question: 'secret formula' });
    const genuine = await postRetrieval(carol(), { tenantId: tenantA(), question: 'secret formula' });
    const noMembership = await postRetrieval(dave(), { tenantId: tenantA(), question: 'secret formula' });
    const unknownTenant = await postRetrieval(alice(), {
      tenantId: randomUUID(),
      question: 'secret formula',
    });

    for (const res of [foreign, genuine, noMembership, unknownTenant]) {
      expect(res.status).toBe(200);
      expect(await res.text()).toBe(REFUSAL_BODY);
    }
  });

  it('3. foreign and nonexistent documents/versions/citations are byte-identical 404s', async () => {
    const foreignDoc = await getResource(`/documents/${corpus.world.docB.id}`, alice());
    const nonexistentDoc = await getResource(`/documents/${randomUUID()}`, alice());
    const noMembershipDoc = await getResource(`/documents/${corpus.world.docA.id}`, dave());
    for (const res of [foreignDoc, nonexistentDoc, noMembershipDoc]) {
      expect(res.status).toBe(404);
      expect(await res.text()).toBe(NOT_FOUND_BODY);
    }

    const foreignVersion = await getResource(
      `/documents/${corpus.world.docB.id}/versions/${corpus.world.docB.versionId}`,
      alice(),
    );
    const nonexistentVersion = await getResource(
      `/documents/${corpus.world.docA.id}/versions/${randomUUID()}`,
      alice(),
    );
    for (const res of [foreignVersion, nonexistentVersion]) {
      expect(res.status).toBe(404);
      expect(await res.text()).toBe(NOT_FOUND_BODY);
    }

    const foreignCitation = await getResource(`/citations/${corpus.world.chunks.betaOne}`, alice());
    const nonexistentCitation = await getResource(`/citations/${randomUUID()}`, alice());
    for (const res of [foreignCitation, nonexistentCitation]) {
      expect(res.status).toBe(404);
      expect(await res.text()).toBe(NOT_FOUND_BODY);
    }
  });

  it('4. member without grant refuses with an EMPTY spy payload', async () => {
    const res = await postRetrieval(carol(), { tenantId: tenantA(), question: 'secret formula' });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(REFUSAL_BODY);
    expect(records).toEqual([]);
  });

  it('5. spy payload: every chunk id ∈ oracle; zero foreign text anywhere', async () => {
    const aliceRes = await postRetrieval(alice(), { tenantId: tenantA(), question: 'secret formula' });
    const bobRes = await postRetrieval(bob(), { tenantId: tenantB(), question: 'secret formula' });
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
    const first = await postRetrieval(alice(), { tenantId: tenantA(), question: 'secret formula' });
    expect(first.status).toBe(200);
    expect((await first.json()) as { decision: string }).toMatchObject({ decision: 'answered' });
    const firstRequestId = first.headers.get('x-request-id');
    expect(firstRequestId).toBeTruthy();

    await revokeGrant(db.superuserPool, tenantA(), corpus.world.aliceDocAGrant);

    const second = await postRetrieval(alice(), { tenantId: tenantA(), question: 'secret formula' });
    expect(second.status).toBe(200);
    expect(await second.text()).toBe(REFUSAL_BODY);
    const secondRequestId = second.headers.get('x-request-id');
    expect(secondRequestId).toBeTruthy();

    const audit = await getResource('/audit/retrieval?limit=50', alice());
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
    const aliceReq = await postRetrieval(alice(), { tenantId: tenantA(), question: 'secret formula' });
    const bobReq = await postRetrieval(bob(), { tenantId: tenantB(), question: 'secret formula' });
    const carolReq = await postRetrieval(carol(), { tenantId: tenantA(), question: 'secret formula' });
    expect(aliceReq.status).toBe(200);
    expect(bobReq.status).toBe(200);
    expect(carolReq.status).toBe(200);
    const aliceRequestId = aliceReq.headers.get('x-request-id');
    const bobRequestId = bobReq.headers.get('x-request-id');
    const carolRequestId = carolReq.headers.get('x-request-id');

    const aliceAudit = await getResource('/audit/retrieval?limit=50', alice());
    const aliceEvents = ((await aliceAudit.json()) as { events: { tenantId: string; requestId: string; eventType: string }[] })
      .events;
    expect(aliceEvents.length).toBeGreaterThan(0);
    expect(aliceEvents.every((e) => e.tenantId === tenantA())).toBe(true);
    expect(aliceEvents.some((e) => e.requestId === aliceRequestId && e.eventType === 'retrieval:allowed')).toBe(true);
    expect(aliceEvents.some((e) => e.requestId === carolRequestId && e.eventType === 'retrieval:refused')).toBe(true);
    expect(aliceEvents.some((e) => e.requestId === bobRequestId)).toBe(false);

    const bobAudit = await getResource('/audit/retrieval?limit=50', bob());
    const bobEvents = ((await bobAudit.json()) as { events: { tenantId: string; requestId: string; eventType: string }[] })
      .events;
    expect(bobEvents.length).toBeGreaterThan(0);
    expect(bobEvents.every((e) => e.tenantId === tenantB())).toBe(true);
    expect(bobEvents.some((e) => e.requestId === bobRequestId && e.eventType === 'retrieval:allowed')).toBe(true);
    expect(bobEvents.some((e) => e.requestId === aliceRequestId || e.requestId === carolRequestId)).toBe(false);

    const limited = await getResource('/audit/retrieval?limit=1', alice());
    expect(((await limited.json()) as { events: unknown[] }).events).toHaveLength(1);
  });

  it('8. malformed body / malformed uuid → 400 problem+json, no data, audit silence', async () => {
    const before = await getResource('/audit/retrieval?limit=100', alice());
    const beforeCount = ((await before.json()) as { events: unknown[] }).events.length;

    const badBody = await postRetrieval(alice(), { tenantId: 'not-a-uuid', question: 'x' });
    expect(badBody.status).toBe(400);
    const badBodyText = await badBody.text();
    expect(badBodyText).toBe(INVALID_BODY);

    const missingQuestion = await postRetrieval(alice(), { tenantId: tenantA() });
    expect(missingQuestion.status).toBe(400);
    expect(await missingQuestion.text()).toBe(INVALID_BODY);

    const badUuidHeader = await postRetrieval('definitely-not-a-uuid', {
      tenantId: tenantA(),
      question: 'x',
    });
    expect(badUuidHeader.status).toBe(400);
    expect(await badUuidHeader.text()).toBe(INVALID_BODY);

    const noHeader = await postRetrieval(undefined, { tenantId: tenantA(), question: 'x' });
    expect(noHeader.status).toBe(401);
    expect(await noHeader.text()).toBe(
      JSON.stringify({ code: 'UNAUTHORIZED', message: 'Authentication required' }),
    );

    const unknownRoute = await getResource('/definitely/not/a/route', alice());
    expect(unknownRoute.status).toBe(404);
    expect(await unknownRoute.text()).toBe(NOT_FOUND_BODY);

    // boundary denials carry no candidate data in the response
    expect(badBodyText).not.toContain('secret');
    expect(badBodyText).not.toContain('formula');

    // denials write nothing (B1): the audit trail is untouched by 4xx errors
    const after = await getResource('/audit/retrieval?limit=100', alice());
    const afterCount = ((await after.json()) as { events: unknown[] }).events.length;
    expect(afterCount).toBe(beforeCount);
  });

  it('9. own documents/versions resolve; superseded + quarantined versions are invisible', async () => {
    const doc = await getResource(`/documents/${corpus.world.docA.id}`, alice());
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
      alice(),
    );
    expect(version.status).toBe(200);
    expect((await version.json()) as { versionNo: number; isCurrent: boolean }).toMatchObject({
      versionNo: 1,
      isCurrent: true,
    });

    // superseded/quarantined versions exist in the corpus but must NOT resolve
    const superseded = await getResource(
      `/documents/${corpus.world.docA.id}/versions/${corpus.world.supersededVersion.id}`,
      alice(),
    );
    const quarantined = await getResource(
      `/documents/${corpus.world.docA.id}/versions/${corpus.world.quarantinedVersion.id}`,
      alice(),
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
