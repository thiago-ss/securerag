import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import { DETERMINISTIC_EMBEDDING, runRetrieval } from '../src/index.js';
import {
  DeterministicPiiDetector,
  HEURISTIC_INJECTION_DETECTOR,
  SpyGenerator,
} from '@securerag/providers';

/**
 * Mutation-gate seam (ADR-0012 "allow generation without evidence"): a
 * retrieval with NO authorized evidence must refuse INSUFFICIENT_EVIDENCE and
 * never reach the generator. If the calibrated evidence gate is removed, this
 * test fails.
 */
describe('refusal e2e: no authorized evidence never answers', () => {
  let db: TestDb;
  let world: Awaited<ReturnType<typeof seedFixtures>>;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
  });

  afterAll(async () => {
    await db.stop();
  });

  it('a principal with no grant gets INSUFFICIENT_EVIDENCE and an empty generator payload', async () => {
    const spy = new SpyGenerator();
    const outcome = await runRetrieval(
      {
        pool: db.apiPool,
        providers: spy,
        injectionDetector: HEURISTIC_INJECTION_DETECTOR,
        embeddings: DETERMINISTIC_EMBEDDING,
        pii: { detector: new DeterministicPiiDetector(), enabled: true },
        limit: 10,
      },
      {
        tenantId: world.tenantA.id,
        principalId: world.alice.id,
        requestId: randomUUID(),
        question: 'Alpha secret formula',
      },
    );
    expect(outcome.decision).toBe('refused');
    expect((outcome as { code?: string }).code).toBe('INSUFFICIENT_EVIDENCE');
    // The generator must never be invoked without authorized evidence.
    expect(spy.records).toHaveLength(0);
  });
});
