import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { MembershipError } from '@securerag/security';
import { listAudit, resolveCitation, runRetrieval, type RefusedOutcome, type RetrievalOutcome } from '@securerag/core';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import {
  getTestDb,
  resetData,
  revokeGrant,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import { computeAllowed, type AllowedSets } from '../src/oracle.js';
import { buildT3Corpus, type T3Corpus } from '../src/fixtures.js';

describe('T3 G2 gate — domain layer (real PostgreSQL, least-privilege role, oracle cross-check)', () => {
  let db: TestDb;
  let api: Pool;
  let corpus: T3Corpus;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    corpus = await buildT3Corpus(db.superuserPool);
    api = db.apiPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  function expectRefused(outcome: RetrievalOutcome): asserts outcome is RefusedOutcome {
    expect(outcome.decision).toBe('refused');
  }

  /** Bidirectional check: production ⊆ oracle AND oracle ⊆ production. */
  function assertMatchesOracleExactly(produced: Set<string>, oracle: AllowedSets): void {
    for (const id of produced) expect(oracle.chunks.has(id)).toBe(true);
    for (const id of oracle.chunks) expect(produced.has(id)).toBe(true);
    expect(produced.size).toBe(oracle.chunks.size);
  }

  const alice = () => corpus.world.alice.id;
  const bob = () => corpus.world.bob.id;
  const carol = () => corpus.world.carol.id;
  const tenantA = () => corpus.world.tenantA.id;
  const tenantB = () => corpus.world.tenantB.id;

  it('1. own authorized keyword retrieval returns exactly the oracle-allowed chunks (bidirectional); citations resolvable with oracle excerpts', async () => {
    const records: SpyRecord[] = [];
    const spy = new SpyGenerator(records);
    const requestId = randomUUID();

    const outcome = await runRetrieval(
      { pool: api, providers: spy },
      {
        tenantId: tenantA(),
        principalId: alice(),
        requestId,
        question: 'secret formula',
      },
    );
    expect(outcome.decision).toBe('answered');

    const produced = new Set(
      outcome.decision === 'answered' ? outcome.citations.map((c) => c.chunkId) : [],
    );
    const oracle = computeAllowed(corpus.facts, alice(), tenantA());
    assertMatchesOracleExactly(produced, oracle);
    expect(produced.size).toBeGreaterThan(0);

    for (const citation of outcome.decision === 'answered' ? outcome.citations : []) {
      const factChunk = corpus.facts.chunks.find((c) => c.chunkId === citation.chunkId);
      expect(factChunk).toBeDefined();
      expect(citation.excerpt).toBe(factChunk?.text);

      const resolved = await resolveCitation(api, {
        tenantId: tenantA(),
        principalId: alice(),
        requestId: randomUUID(),
        citationId: citation.chunkId,
      });
      expect(resolved).toEqual(citation);
    }
    expect(records).toHaveLength(1);
  });

  it('2. a principal without any grant (member, no grant) gets INSUFFICIENT_EVIDENCE and an EMPTY spy payload', async () => {
    const oracle = computeAllowed(corpus.facts, carol(), tenantA());
    expect(oracle.chunks.size).toBe(0);

    const records: SpyRecord[] = [];
    const spy = new SpyGenerator(records);
    const outcome = await runRetrieval(
      { pool: api, providers: spy },
      {
        tenantId: tenantA(),
        principalId: carol(),
        requestId: randomUUID(),
        question: 'secret formula',
      },
    );
    expectRefused(outcome);
    expect(outcome.code).toBe('INSUFFICIENT_EVIDENCE');
    expect(records).toEqual([]);
  });

  it('2b. a principal with NO membership gets a typed MembershipError (foreign tenant indistinguishable)', async () => {
    const records: SpyRecord[] = [];
    const spy = new SpyGenerator(records);
    await expect(
      runRetrieval(
        { pool: api, providers: spy },
        {
          tenantId: tenantA(),
          principalId: corpus.world.dave.id,
          requestId: randomUUID(),
          question: 'secret formula',
        },
      ),
    ).rejects.toBeInstanceOf(MembershipError);
    await expect(
      runRetrieval(
        { pool: api, providers: spy },
        {
          tenantId: tenantB(),
          principalId: alice(),
          requestId: randomUUID(),
          question: 'secret formula',
        },
      ),
    ).rejects.toBeInstanceOf(MembershipError);
    expect(records).toEqual([]);
  });

  it('3. model spy: every payload chunk id ∈ oracle; zero foreign chunk text anywhere', async () => {
    const aliceRecords: SpyRecord[] = [];
    const bobRecords: SpyRecord[] = [];

    const aliceOutcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(aliceRecords) },
      {
        tenantId: tenantA(),
        principalId: alice(),
        requestId: randomUUID(),
        question: 'secret formula',
      },
    );
    const bobOutcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(bobRecords) },
      {
        tenantId: tenantB(),
        principalId: bob(),
        requestId: randomUUID(),
        question: 'secret formula',
      },
    );
    expect(aliceOutcome.decision).toBe('answered');
    expect(bobOutcome.decision).toBe('answered');

    const aliceOracle = computeAllowed(corpus.facts, alice(), tenantA());
    const bobOracle = computeAllowed(corpus.facts, bob(), tenantB());
    const allowedTexts = (oracle: AllowedSets): Set<string> =>
      new Set(
        corpus.facts.chunks.filter((c) => oracle.chunks.has(c.chunkId)).map((c) => c.text),
      );

    for (const record of aliceRecords) {
      for (const chunk of record.bundle) {
        expect(aliceOracle.chunks.has(chunk.chunkId)).toBe(true);
        expect(allowedTexts(aliceOracle).has(chunk.text)).toBe(true);
      }
      for (const citation of record.citations) {
        expect(aliceOracle.chunks.has(citation.chunkId)).toBe(true);
        expect(citation.excerpt).not.toContain('Beta');
      }
    }
    for (const record of bobRecords) {
      for (const chunk of record.bundle) {
        expect(bobOracle.chunks.has(chunk.chunkId)).toBe(true);
        expect(allowedTexts(bobOracle).has(chunk.text)).toBe(true);
      }
      for (const citation of record.citations) {
        expect(bobOracle.chunks.has(citation.chunkId)).toBe(true);
        expect(citation.excerpt).not.toContain('Alpha');
      }
    }
    expect(aliceRecords.length).toBeGreaterThan(0);
    expect(bobRecords.length).toBeGreaterThan(0);

    // no overlap between tenants' allowed sets: zero bleed by construction
    for (const id of aliceOracle.chunks) expect(bobOracle.chunks.has(id)).toBe(false);
    for (const id of bobOracle.chunks) expect(aliceOracle.chunks.has(id)).toBe(false);
  });

  it('4. revoked grant → refusal with audited retrieval:refused; superseded + quarantined versions never appear', async () => {
    const spy = new SpyGenerator();
    const first = await runRetrieval(
      { pool: api, providers: spy },
      {
        tenantId: tenantA(),
        principalId: alice(),
        requestId: randomUUID(),
        question: 'secret formula',
      },
    );
    expect(first.decision).toBe('answered');
    const firstIds = new Set(
      first.decision === 'answered' ? first.citations.map((c) => c.chunkId) : [],
    );
    expect(firstIds.has(corpus.world.chunks.superseded)).toBe(false);
    expect(firstIds.has(corpus.world.chunks.quarantined)).toBe(false);

    const oracle = computeAllowed(corpus.facts, alice(), tenantA());
    expect(oracle.chunks.has(corpus.world.chunks.superseded)).toBe(false);
    expect(oracle.chunks.has(corpus.world.chunks.quarantined)).toBe(false);

    // red-team sanity: the hidden chunks DO match the question text, so their
    // absence proves the visibility filter (status + is_current), not the query.
    const supersededText = corpus.facts.chunks.find(
      (c) => c.chunkId === corpus.world.chunks.superseded,
    )?.text;
    const quarantinedText = corpus.facts.chunks.find(
      (c) => c.chunkId === corpus.world.chunks.quarantined,
    )?.text;
    expect(supersededText).toContain('secret formula');
    expect(quarantinedText).toContain('secret formula');

    // mid-suite revocation: grant deleted -> new request refuses
    await revokeGrant(db.superuserPool, tenantA(), corpus.world.aliceDocAGrant);
    const refusedRequest = randomUUID();
    const second = await runRetrieval(
      { pool: api, providers: spy },
      {
        tenantId: tenantA(),
        principalId: alice(),
        requestId: refusedRequest,
        question: 'secret formula',
      },
    );
    expectRefused(second);
    expect(second.code).toBe('INSUFFICIENT_EVIDENCE');

    const events = await listAudit(api, {
      tenantId: tenantA(),
      principalId: alice(),
      requestId: randomUUID(),
    });
    expect(
      events.some(
        (e) =>
          e.requestId === refusedRequest &&
          e.eventType === 'retrieval:refused' &&
          e.refusalReason === 'INSUFFICIENT_EVIDENCE',
      ),
    ).toBe(true);
  });

  it('5. audit: allowed/refused events written; tenant-isolated read-back (alice vs bob)', async () => {
    const aliceReq = randomUUID();
    const bobReq = randomUUID();
    const carolReq = randomUUID();

    const spy = new SpyGenerator();
    const aliceOutcome = await runRetrieval(
      { pool: api, providers: spy },
      {
        tenantId: tenantA(),
        principalId: alice(),
        requestId: aliceReq,
        question: 'secret formula',
      },
    );
    const bobOutcome = await runRetrieval(
      { pool: api, providers: spy },
      {
        tenantId: tenantB(),
        principalId: bob(),
        requestId: bobReq,
        question: 'secret formula',
      },
    );
    const carolOutcome = await runRetrieval(
      { pool: api, providers: spy },
      {
        tenantId: tenantA(),
        principalId: carol(),
        requestId: carolReq,
        question: 'secret formula',
      },
    );
    expect(aliceOutcome.decision).toBe('answered');
    expect(bobOutcome.decision).toBe('answered');
    expect(carolOutcome.decision).toBe('refused');

    const aliceEvents = await listAudit(api, {
      tenantId: tenantA(),
      principalId: alice(),
      requestId: randomUUID(),
    });
    const bobEvents = await listAudit(api, {
      tenantId: tenantB(),
      principalId: bob(),
      requestId: randomUUID(),
    });

    // alice sees her own allowed event AND carol's refused event (same tenant)
    expect(aliceEvents.some((e) => e.requestId === aliceReq && e.eventType === 'retrieval:allowed')).toBe(true);
    expect(
      aliceEvents.some(
        (e) =>
          e.requestId === carolReq &&
          e.eventType === 'retrieval:refused' &&
          e.refusalReason === 'INSUFFICIENT_EVIDENCE',
      ),
    ).toBe(true);
    // never bob's tenant-B events
    expect(aliceEvents.some((e) => e.requestId === bobReq)).toBe(false);
    expect(aliceEvents.every((e) => e.tenantId === tenantA())).toBe(true);

    expect(bobEvents.some((e) => e.requestId === bobReq && e.eventType === 'retrieval:allowed')).toBe(true);
    expect(bobEvents.some((e) => e.requestId === aliceReq || e.requestId === carolReq)).toBe(false);
    expect(bobEvents.every((e) => e.tenantId === tenantB())).toBe(true);

    const allowed = aliceEvents.find((e) => e.requestId === aliceReq);
    expect(allowed?.candidateIds?.length).toBe(3);
    expect(allowed?.selectedIds?.length).toBe(3);
    expect(allowed?.scores?.length).toBe(3);
    expect(allowed?.citations?.length).toBe(3);
    expect(allowed?.evidenceDecision).toBe('answered');
    expect(allowed?.answerHash).toBeInstanceOf(Buffer);
  });

  it('6. resolveCitation rechecks authorization; foreign and nonexistent are identical nulls', async () => {
    const own = await resolveCitation(api, {
      tenantId: tenantA(),
      principalId: alice(),
      requestId: randomUUID(),
      citationId: corpus.world.chunks.alphaOne,
    });
    expect(own).not.toBeNull();
    expect(own?.excerpt).toBe('Alpha secret formula one');

    const foreign = await resolveCitation(api, {
      tenantId: tenantA(),
      principalId: alice(),
      requestId: randomUUID(),
      citationId: corpus.world.chunks.betaOne,
    });
    const nonexistent = await resolveCitation(api, {
      tenantId: tenantA(),
      principalId: alice(),
      requestId: randomUUID(),
      citationId: randomUUID(),
    });
    expect(foreign).toBeNull();
    expect(nonexistent).toBeNull();

    // recheck: revoke ONLY the docA grant; the own docA citation vanishes
    // while the still-granted docA2 citation remains resolvable.
    await revokeGrant(db.superuserPool, tenantA(), corpus.world.aliceDocAGrant);
    const afterRevoke = await resolveCitation(api, {
      tenantId: tenantA(),
      principalId: alice(),
      requestId: randomUUID(),
      citationId: corpus.world.chunks.alphaOne,
    });
    expect(afterRevoke).toBeNull();
    const stillGranted = await resolveCitation(api, {
      tenantId: tenantA(),
      principalId: alice(),
      requestId: randomUUID(),
      citationId: corpus.world.chunks.alphaWidget,
    });
    expect(stillGranted?.chunkId).toBe(corpus.world.chunks.alphaWidget);
  });

  it('7. grants via group membership and tenant_role both work; cross-tenant grants never match', async () => {
    // bob reads docB ONLY through group 'Beta Group'
    const bobOutcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      {
        tenantId: tenantB(),
        principalId: bob(),
        requestId: randomUUID(),
        question: 'secret formula',
      },
    );
    expect(bobOutcome.decision).toBe('answered');
    const bobProduced = new Set(
      bobOutcome.decision === 'answered' ? bobOutcome.citations.map((c) => c.chunkId) : [],
    );
    assertMatchesOracleExactly(bobProduced, computeAllowed(corpus.facts, bob(), tenantB()));
    expect(bobProduced.has(corpus.world.chunks.betaOne)).toBe(true);

    // alice reads docA2 ONLY through tenant_role 'member'
    const aliceOutcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      {
        tenantId: tenantA(),
        principalId: alice(),
        requestId: randomUUID(),
        question: 'secret formula',
      },
    );
    expect(aliceOutcome.decision).toBe('answered');
    const aliceProduced = new Set(
      aliceOutcome.decision === 'answered' ? aliceOutcome.citations.map((c) => c.chunkId) : [],
    );
    expect(aliceProduced.has(corpus.world.chunks.alphaWidget)).toBe(true);

    // carol is an ADMIN of tenant A, but admins hold no implicit document
    // access and her role ('admin') does not match the 'member' role grant.
    const carolOracle = computeAllowed(corpus.facts, carol(), tenantA());
    expect(carolOracle.chunks.size).toBe(0);

    // tenant_role 'member' grant does not leak to tenant B principals.
    expect(aliceProduced.has(corpus.world.chunks.betaOne)).toBe(false);
    expect(bobProduced.has(corpus.world.chunks.alphaWidget)).toBe(false);
  });

  it('8. authorized-but-below-threshold bundle refuses (INSUFFICIENT_EVIDENCE) without generation', async () => {
    const oracle = computeAllowed(corpus.facts, alice(), tenantA());
    expect(oracle.chunks.has(corpus.world.chunks.alphaWidget)).toBe(true);

    const records: SpyRecord[] = [];
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(records) },
      {
        tenantId: tenantA(),
        principalId: alice(),
        requestId: randomUUID(),
        question: 'widget',
      },
    );
    expectRefused(outcome);
    expect(outcome.code).toBe('INSUFFICIENT_EVIDENCE');
    expect(records).toEqual([]);
  });

  it('9. concurrency: alice and bob alternate on the SAME pool 10x with zero bleed', async () => {
    for (let i = 0; i < 10; i += 1) {
      const isAlice = i % 2 === 0;
      const principalId = isAlice ? alice() : bob();
      const tenantId = isAlice ? tenantA() : tenantB();
      const records: SpyRecord[] = [];

      const outcome = await runRetrieval(
        { pool: api, providers: new SpyGenerator(records) },
        {
          tenantId,
          principalId,
          requestId: randomUUID(),
          question: 'secret formula',
        },
      );
      expect(outcome.decision).toBe('answered');

      const produced = new Set(
        outcome.decision === 'answered' ? outcome.citations.map((c) => c.chunkId) : [],
      );
      const oracle = computeAllowed(corpus.facts, principalId, tenantId);
      for (const id of produced) expect(oracle.chunks.has(id)).toBe(true);
      expect(records).toHaveLength(1);
      expect(new Set(records[0]?.bundle.map((b) => b.chunkId) ?? [])).toEqual(produced);

      const otherOracle = computeAllowed(
        corpus.facts,
        isAlice ? bob() : alice(),
        isAlice ? tenantB() : tenantA(),
      );
      for (const id of produced) expect(otherOracle.chunks.has(id)).toBe(false);
    }
  });
});
