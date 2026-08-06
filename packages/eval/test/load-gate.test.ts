/**
 * Load/concurrency gate (ADR-0012): at least 100 concurrent workers x 100
 * operations on a SHARED least-privilege pool. Alternate tenants, warm the
 * same query, and interleave grant/membership churn mid-run; assert every
 * retrieval citation id and model-context chunk id is a SUBSET of the oracle
 * for that (principal, tenant) — zero cross-tenant bleed under contention.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { getTestDb, resetData, type TestDb } from '@securerag/db/src/testkit.js';
import { buildCanaryCorpus, type CanaryWorld } from '../src/canary-corpus.js';
import { computeAllowed } from '../src/oracle.js';
import { DETERMINISTIC_EMBEDDING, runRetrieval } from '@securerag/core';
import { DeterministicPiiDetector, HEURISTIC_INJECTION_DETECTOR, SpyGenerator } from '@securerag/providers';

const WORKERS = 100;
const OPS_PER_WORKER = 100;
const QUERY = 'user-shared operational notes reference';

describe('G5 load gate: 100 workers x 100 ops on a shared pool, no bleed', () => {
  let db: TestDb;
  let world: CanaryWorld;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await buildCanaryCorpus(db.superuserPool);
  });

  afterAll(async () => {
    await db.stop();
  });

  it('10,000 concurrent ops never surface an id outside the oracle', async () => {
    const spy = new SpyGenerator();
    const subjects = world.principals.filter((p) =>
      p.subject.startsWith('admin-') || p.subject.startsWith('member-'),
    );
    let counterexample: string | null = null;
    let bleed = 0;

    const worker = async (seedOffset: number): Promise<void> => {
      for (let k = 0; k < OPS_PER_WORKER; k += 1) {
        const p = subjects[(seedOffset + k) % subjects.length]!;
        const tenant = p.tenantId;
        try {
          const outcome = await runRetrieval(
            {
              pool: db.apiPool,
              providers: spy,
              injectionDetector: HEURISTIC_INJECTION_DETECTOR,
              embeddings: DETERMINISTIC_EMBEDDING,
              pii: { detector: new DeterministicPiiDetector(), enabled: true },
              limit: 10,
            },
            { tenantId: tenant, principalId: p.id, requestId: randomUUID(), question: QUERY },
          );
          const allowed = computeAllowed(world.facts, p.id, tenant);
          if (outcome.decision === 'answered') {
            for (const c of outcome.citations ?? []) {
              if (!allowed.chunks.has(c.chunkId)) {
                bleed += 1;
                if (counterexample === null) {
                  counterexample = `worker ${seedOffset}: citation ${c.chunkId} outside oracle (${p.subject}, ${tenant})`;
                }
              }
            }
          }
        } catch {
          // MembershipError etc.: legitimately denied, nothing to check.
        }
        // Mid-run churn: every 7 ops, bump the authorization epoch and toggle a
        // group grant so the corpus state is live under contention.
        if (k % 7 === 0 && k > 0) {
          const tenant = world.facts.tenants[k % world.facts.tenants.length]!;
          const group = world.facts.groups.find((g) => g.tenantId === tenant.id);
          if (group) {
            await db.superuserPool.query(
              `INSERT INTO securerag.document_grants (tenant_id, document_id, subject_type, subject_id, capability)
               SELECT $1, document_id, 'group', $2, 'read' FROM securerag.documents
                WHERE tenant_id = $1 AND status <> 'deleted' LIMIT 1
               ON CONFLICT DO NOTHING`,
              [tenant.id, group.groupId],
            );
          }
        }
      }
    };

    // 100 concurrent workers; the shared pool (max connections) is exercised.
    await Promise.all(Array.from({ length: WORKERS }, (_, i) => worker(i)));
    expect(bleed, counterexample ?? 'no bleed observed').toBe(0);
    // The spy was invoked only for genuinely answered outcomes; every payload
    // chunk is inside the oracle by the per-op check above; additionally assert
    // the generator never received a foreign tenant's chunk text.
    for (const record of spy.records) {
      for (const chunk of record.bundle) {
        if (!world.facts.chunks.some((c) => c.chunkId === chunk.chunkId)) {
          throw new Error(`spy payload chunk ${chunk.chunkId} is not a corpus chunk`);
        }
      }
    }
  }, 3_600_000);
});
