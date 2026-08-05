import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { runRetrieval, type RetrievalOutcome } from '@securerag/core';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import { getTestDb, resetData, type TestDb } from '@securerag/db/src/testkit.js';
import { computeAllowed } from '../src/oracle.js';
import { buildT3Corpus, type T3Corpus } from '../src/fixtures.js';
import { buildRecallCorpus, type RecallCorpus } from '../src/recall-fixtures.js';

/**
 * S6 authorization-preservation gate: the hybrid default (and the vector arm)
 * must carry the EXACT T3 authorization predicate inside SQL for both arms —
 * hybrid results ⊆ oracle (subset + same refusal semantics is the security
 * property), oracle ⊆ production for the full-grant principal, spy payloads
 * ⊆ oracle, zero foreign text, and narrow-ACL principals experience no HNSW
 * filter starvation (everything they are allowed, up to the limit).
 */
describe('hybrid retrieval preserves authorization (S6)', () => {
  let db: TestDb;
  let api: Pool;
  let t3: T3Corpus;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    t3 = await buildT3Corpus(db.superuserPool);
    api = db.apiPool;
  });

  afterAll(async () => {
    if (db) await db.stop();
  });

  const alice = () => t3.world.alice.id;
  const carol = () => t3.world.carol.id;
  const tenantA = () => t3.world.tenantA.id;

  it('T3 corpus: hybrid (default) results are exactly the oracle-allowed chunks; vector mode refuses; keyword mode unchanged', async () => {
    const hybrid = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      { tenantId: tenantA(), principalId: alice(), requestId: randomUUID(), question: 'secret formula' },
    );
    expect(hybrid.decision).toBe('answered');
    const produced = new Set(
      hybrid.decision === 'answered' ? hybrid.citations.map((c) => c.chunkId) : [],
    );
    const oracle = computeAllowed(t3.facts, alice(), tenantA());
    // subset (security property) AND oracle ⊆ production (full-grant principal):
    // on the T3 corpus the vector arm is empty (no embeddings) so hybrid ≡ keyword.
    for (const id of produced) expect(oracle.chunks.has(id)).toBe(true);
    for (const id of oracle.chunks) expect(produced.has(id)).toBe(true);
    expect(produced.size).toBe(3);

    const keyword = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      {
        tenantId: tenantA(), principalId: alice(), requestId: randomUUID(),
        question: 'secret formula', mode: 'keyword',
      },
    );
    expect(keyword.decision).toBe('answered');
    const kwIds =
      keyword.decision === 'answered' ? keyword.citations.map((c) => c.chunkId) : [];
    expect([...kwIds].sort()).toEqual([...produced].sort());

    // vector arm on a corpus without embeddings: empty -> same refusal semantics
    const vector = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      {
        tenantId: tenantA(), principalId: alice(), requestId: randomUUID(),
        question: 'secret formula', mode: 'vector',
      },
    );
    expect(vector.decision).toBe('refused');
    if (vector.decision === 'refused') expect(vector.code).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('hybrid spy payload ⊆ oracle; zero foreign text; refusal semantics unchanged for no-grant principals', async () => {
    const aliceRecords: SpyRecord[] = [];
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(aliceRecords) },
      { tenantId: tenantA(), principalId: alice(), requestId: randomUUID(), question: 'secret formula' },
    );
    expect(outcome.decision).toBe('answered');
    const oracle = computeAllowed(t3.facts, alice(), tenantA());
    const allowedTexts = new Set(
      t3.facts.chunks.filter((c) => oracle.chunks.has(c.chunkId)).map((c) => c.text),
    );
    for (const record of aliceRecords) {
      for (const chunk of record.bundle) {
        expect(oracle.chunks.has(chunk.chunkId)).toBe(true);
        expect(allowedTexts.has(chunk.text)).toBe(true);
        expect(chunk.text).not.toContain('Beta');
      }
      for (const citation of record.citations) {
        expect(oracle.chunks.has(citation.chunkId)).toBe(true);
        expect(citation.excerpt).not.toContain('Beta');
      }
    }
    expect(aliceRecords.length).toBeGreaterThan(0);

    const refused = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      { tenantId: tenantA(), principalId: carol(), requestId: randomUUID(), question: 'secret formula' },
    );
    expect(refused.decision).toBe('refused');
    if (refused.decision === 'refused') expect(refused.code).toBe('INSUFFICIENT_EVIDENCE');
  });

  it('hybrid deterministic ordering: two identical requests produce identical ordered id lists', async () => {
    const ids = async (): Promise<string[]> => {
      const outcome = await runRetrieval(
        { pool: api, providers: new SpyGenerator() },
        { tenantId: tenantA(), principalId: alice(), requestId: randomUUID(), question: 'secret formula' },
      );
      return outcome.decision === 'answered' ? outcome.citations.map((c) => c.chunkId) : [];
    };
    expect(await ids()).toEqual(await ids());
  });

  it('narrow-ACL principals on an embedded corpus: every allowed chunk is returned up to the limit; nothing foreign', async () => {
    await resetData(db.superuserPool);
    const corpus: RecallCorpus = await buildRecallCorpus(db.superuserPool, { docCount: 20 });
    const allowedOf = (principalId: string): Set<string> => {
      if (principalId === corpus.narrow10) return new Set(corpus.narrow10ChunkIds);
      if (principalId === corpus.narrow1) return new Set(corpus.narrow1ChunkIds);
      return new Set(corpus.allChunkIds);
    };
    // 'quantum' (topic 0's word) lexically and vectorially matches every topic-0
    // chunk, so the hybrid pipeline must surface ALL of a principal's allowed
    // chunks for that topic — the HNSW strict_order scan must not starve.
    const question = corpus.queries[0]!.text.split(' ')[0]!;
    const runs = [
      { name: '1%', principalId: corpus.narrow1 },
      { name: '10%', principalId: corpus.narrow10 },
    ];
    for (const { name, principalId } of runs) {
      const records: SpyRecord[] = [];
      const outcome: RetrievalOutcome = await runRetrieval(
        { pool: api, providers: new SpyGenerator(records) },
        { tenantId: corpus.tenantId, principalId, requestId: randomUUID(), question },
      );
      const allowed = allowedOf(principalId);
      const produced = new Set(
        outcome.decision === 'answered' ? outcome.citations.map((c) => c.chunkId) : [],
      );
      // no starvation: everything the principal is allowed shows up (allowed <= limit here)
      for (const id of allowed) expect(produced.has(id), `${name}: missing allowed chunk`).toBe(true);
      // nothing foreign
      for (const id of produced) expect(allowed.has(id), `${name}: foreign chunk leaked`).toBe(true);
      if (outcome.decision === 'answered') {
        for (const record of records) {
          for (const chunk of record.bundle) {
            expect(allowed.has(chunk.chunkId)).toBe(true);
          }
        }
      }
      expect(outcome.decision).toBe('answered');
    }

    // full-grant principal: result count hits the limit and stays inside the allowed set
    const fullOutcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      { tenantId: corpus.tenantId, principalId: corpus.full, requestId: randomUUID(), question },
    );
    expect(fullOutcome.decision).toBe('answered');
    const allAllowed = new Set(corpus.allChunkIds);
    if (fullOutcome.decision === 'answered') {
      expect(fullOutcome.citations).toHaveLength(10); // default limit
      for (const c of fullOutcome.citations) expect(allAllowed.has(c.chunkId)).toBe(true);
    }
  });

  it('audited refusal keeps the T3 shape under hybrid (below-threshold bundle)', async () => {
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      { tenantId: tenantA(), principalId: alice(), requestId: randomUUID(), question: 'widget' },
    );
    expect(outcome.decision).toBe('refused');
    if (outcome.decision === 'refused') expect(outcome.code).toBe('INSUFFICIENT_EVIDENCE');
  });
});
