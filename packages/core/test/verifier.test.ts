import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import { SpyGenerator, type AnswerGenerator, type GenerationRequest, type SpyRecord } from '@securerag/providers';
import { getTestDb, resetData, seedChunk, seedFixtures, seedGrant, type FixtureWorld, type TestDb } from '@securerag/db/src/testkit.js';
import {
  MAX_GENERATION_ATTEMPTS,
  StaleEpochError,
  assertEpochCurrent,
  generateWithGuarantee,
  isClaimSentence,
  runRetrieval,
  splitSentences,
  verifyCitations,
  type Citation,
} from '../src/index.js';

/**
 * S7 citation-verifier + generation-contract tests (ADR-0009):
 *  - Pure, deterministic verifier unit tests (claim detection fixtures,
 *    membership, claims-to-citations).
 *  - Bounded regeneration (max 2) at the generation seam.
 *  - End-to-end over the REAL pipeline: fabricated foreign citations ->
 *    CITATION_UNSUPPORTED with exactly MAX_GENERATION_ATTEMPTS generate
 *    calls; a failing audit appender -> refusal, never an answer. RLS is real.
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function uuidLike(value: string): boolean {
  return UUID_RE.test(value);
}

function ids(): { id1: string; id2: string; id3: string } {
  return {
    id1: randomUUID(),
    id2: randomUUID(),
    id3: randomUUID(),
  };
}

function cite(id: string): Citation {
  return {
    documentId: randomUUID(),
    versionId: randomUUID(),
    chunkId: id,
    span: { start: 0, end: 10 },
    excerpt: 'excerpt',
  };
}

// ------------------------- pure verifier unit tests -------------------------

describe('citation verifier (deterministic, model-independent, S7)', () => {

  it('claim-detection fixtures: verb-bearing sentences are material claims, meta sentences are not', () => {
    const claims = [
      'The response rate was 5% in the survey.',
      'Revenue reached 12 million last quarter.',
      'The policy states that refunds are allowed after 30 days.',
      'Headcount amounts to 40 employees.',
    ];
    const meta = [
      'Synthesis of authorized evidence [uuid]',
      'Based on the provided documents, findings follow below.',
      'Summary of findings.',
      'A summarized answer follows below.',
    ];
    for (const sentence of claims) expect(isClaimSentence(sentence), sentence).toBe(true);
    for (const sentence of meta) expect(isClaimSentence(sentence), sentence).toBe(false);
  });

  it('sentence splitting is deterministic on .!? boundaries', () => {
    expect(splitSentences('One. Two! Three? Four')).toEqual(['One.', 'Two!', 'Three?', 'Four']);
  });

  it('accepts an answer whose claims cite bundle ids present in the returned citation list', () => {
    const { id1, id2 } = ids();
    const verification = verifyCitations({
      answer: `The response rate was 5% [${id1}] in the last survey [${id2}].`,
      citations: [cite(id1), cite(id2)],
      bundleChunkIds: new Set([id1, id2]),
    });
    expect(verification.ok).toBe(true);
    expect(verification.issues).toEqual([]);
    expect(verification.claims).toHaveLength(1);
  });

  it('rejects fabricated/foreign citation ids (not in the bundle)', () => {
    const { id1 } = ids();
    const foreign = randomUUID();
    const verification = verifyCitations({
      answer: `Synthesis of authorized evidence [${id1},${foreign}]`,
      citations: [cite(id1), cite(foreign)],
      bundleChunkIds: new Set([id1]),
    });
    expect(verification.ok).toBe(false);
    expect(verification.issues.some((i) => i.includes(foreign))).toBe(true);
  });

  it('rejects a material claim sentence that cites nothing', () => {
    const { id1 } = ids();
    const verification = verifyCitations({
      answer: `The response rate was 5% in the last survey. See ${id1} for details.`,
      citations: [cite(id1)],
      bundleChunkIds: new Set([id1]),
    });
    expect(verification.ok).toBe(false);
    expect(verification.issues.some((i) => i.includes('claim sentence cites nothing'))).toBe(true);
  });

  it('rejects claims with zero returned citations', () => {
    const { id1 } = ids();
    const verification = verifyCitations({
      answer: `The response rate was 5% in the last survey [${id1}].`,
      citations: [],
      bundleChunkIds: new Set([id1]),
    });
    expect(verification.ok).toBe(false);
    expect(verification.issues.some((i) => i.includes('returns no citations'))).toBe(true);
  });

  it('rejects an in-sentence citation id that is not in the returned citation list', () => {
    const { id1, id2 } = ids();
    const verification = verifyCitations({
      answer: `The response rate was 5% [${id1}] in the last survey.`,
      citations: [cite(id2)],
      bundleChunkIds: new Set([id1, id2]),
    });
    expect(verification.ok).toBe(false);
    expect(verification.issues.some((i) => i.includes('not in the returned citation list'))).toBe(true);
  });

  it('accepts a meta-only answer (no claim verbs) even without in-sentence ids', () => {
    const { id1 } = ids();
    const verification = verifyCitations({
      answer: 'Synthesis of authorized evidence.',
      citations: [cite(id1)],
      bundleChunkIds: new Set([id1]),
    });
    expect(verification.ok).toBe(true);
    expect(verification.claims).toEqual([]);
  });
});

// ------------------------- bounded regeneration (unit) -------------------------

describe('generateWithGuarantee (bounded regeneration, max 2)', () => {
  it('regenerates once when verification fails, then refuses with CITATION_UNSUPPORTED', async () => {
    let calls = 0;
    const generator: AnswerGenerator = {
      generate: async () => {
        calls += 1;
        return { answer: 'claim without citation', citations: [] };
      },
    };
    const outcome = await generateWithGuarantee(
      {
        providers: generator,
        verify: async () => ({ ok: false, issues: ['no citations'] }),
      },
      { question: 'q', bundle: [], citations: [] },
    );
    expect(outcome.decision).toBe('refused');
    if (outcome.decision === 'refused') {
      expect(outcome.code).toBe('CITATION_UNSUPPORTED');
      expect(outcome.attempts).toBe(MAX_GENERATION_ATTEMPTS);
    }
    expect(calls).toBe(MAX_GENERATION_ATTEMPTS);
  });

  it('answers when the retry (2nd attempt) verifies cleanly', async () => {
    let calls = 0;
    const id = randomUUID();
    const citation = cite(id);
    const generator: AnswerGenerator = {
      generate: async () => {
        calls += 1;
        return { answer: `The rate was 5% [${id}]`, citations: [citation] };
      },
    };
    const outcome = await generateWithGuarantee(
      {
        providers: generator,
        verify: async () => (calls === 1 ? { ok: false, issues: ['fabricated id'] } : { ok: true }),
      },
      { question: 'q', bundle: [], citations: [] },
    );
    expect(outcome.decision).toBe('answered');
    if (outcome.decision === 'answered') expect(outcome.attempts).toBe(2);
    expect(calls).toBe(2);
  });
});

// ------------------------- epoch guard (unit) -------------------------

describe('assertEpochCurrent (ADR-0009 stale-epoch guard)', () => {
  const fakeClient = (epoch: string): PoolClient =>
    ({
      query: async () => ({ rows: [{ epoch }] }),
    }) as unknown as PoolClient;

  it('passes when the re-read epoch equals the transaction-start epoch', async () => {
    await expect(assertEpochCurrent(fakeClient('42'), '42')).resolves.toBeUndefined();
  });

  it('throws StaleEpochError when the epoch changed mid-transaction', async () => {
    await expect(assertEpochCurrent(fakeClient('43'), '42')).rejects.toBeInstanceOf(StaleEpochError);
  });
});

// ------------------------- end-to-end over the real pipeline -------------------------

describe('retrieval pipeline: citation verification, regeneration bound, audit-write failure (S7)', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let chunkA: string;
  let chunkB: string;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    await seedGrant(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId: world.alice.id,
      capability: 'read',
    });
    chunkA = await seedChunk(db.superuserPool, {
      tenantId: world.tenantA.id,
      versionId: world.docA.versionId,
      chunkNo: 3,
      text: 'Alpha revenue growth forecast for Q3',
      spanStart: 0,
      spanEnd: 35,
    });
    chunkB = await seedChunk(db.superuserPool, {
      tenantId: world.tenantA.id,
      versionId: world.docA.versionId,
      chunkNo: 4,
      text: 'Alpha revenue growth review notes',
      spanStart: 40,
      spanEnd: 72,
    });
    api = db.apiPool;
  });

  afterAll(async () => {
    if (db) await db.stop();
  });

  const params = () => ({
    tenantId: world.tenantA.id,
    principalId: world.alice.id,
    requestId: randomUUID(),
    question: 'revenue growth',
  });

  it('accepts a bundle-cited answer: SpyGenerator answer verifies and resolves', async () => {
    const records: SpyRecord[] = [];
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(records) },
      params(),
    );
    expect(outcome.decision).toBe('answered');
    if (outcome.decision === 'answered') {
      expect(outcome.citations.map((c) => c.chunkId).sort()).toEqual([chunkA, chunkB].sort());
      for (const citation of outcome.citations) expect(uuidLike(citation.chunkId)).toBe(true);
    }
    expect(records).toHaveLength(1);
  });

  it('rejects a fabricated citation: foreign chunk id -> CITATION_UNSUPPORTED, generation bounded at 2', async () => {
    const foreignId = randomUUID();
    let calls = 0;
    const fabricating: AnswerGenerator = {
      generate: async (request: GenerationRequest) => {
        calls += 1;
        const legit = request.citations[0]!;
        return {
          answer: `Synthesis of authorized evidence [${legit.chunkId},${foreignId}]`,
          citations: [
            legit,
            {
              documentId: randomUUID(),
              versionId: randomUUID(),
              chunkId: foreignId,
              span: { start: 0, end: 8 },
              excerpt: 'foreign excerpt',
            },
          ],
        };
      },
    };
    const outcome = await runRetrieval({ pool: api, providers: fabricating }, params());
    expect(outcome.decision).toBe('refused');
    if (outcome.decision === 'refused') {
      expect(outcome.code).toBe('CITATION_UNSUPPORTED');
    }
    // bounded regeneration: exactly 2 generate calls, then refuse
    expect(calls).toBe(MAX_GENERATION_ATTEMPTS);
  });

  it('audit-write failure returns a refusal, never the answer', async () => {
    const failingAudit = async (): Promise<void> => {
      throw new Error('audit backend unavailable');
    };
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(), auditAppend: failingAudit },
      params(),
    );
    expect(outcome.decision).toBe('refused');
    if (outcome.decision === 'refused') {
      expect(outcome.message).toContain('Audit-write failed');
    }
  });
});
