import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import {
  DETERMINISTIC_EMBEDDING,
  InMemorySourceObjectStore,
} from '@securerag/core';
import {
  DETERMINISTIC_MALWARE_SCANNER,
  HEURISTIC_INJECTION_DETECTOR,
  STANDARD_EXTRACTION,
} from '@securerag/providers';
import { runWorkerOnce, type WorkerDeps } from '../src/index.js';
import { claimJobs } from '../src/queue.js';

const ingestSeams = {
  extractor: STANDARD_EXTRACTION,
  scanner: DETERMINISTIC_MALWARE_SCANNER,
  detector: HEURISTIC_INJECTION_DETECTOR,
  embedding: DETERMINISTIC_EMBEDDING,
} as const;

describe('S9 worker: queue claim loop and purge jobs on real runtime roles', () => {
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

  async function enqueuePurgeJob(tenantId: string, idempotencyKey: string): Promise<string> {
    const { rows } = await db.superuserPool.query<{ job_id: string }>(
      `INSERT INTO securerag.jobs (tenant_id, idempotency_key, job_type, payload_key)
       VALUES ($1, $2, 'purge', NULL) RETURNING job_id`,
      [tenantId, idempotencyKey],
    );
    return rows[0]!.job_id;
  }

  it('SKIP LOCKED prevents double-claim across concurrent consumers', async () => {
    const jobId = await enqueuePurgeJob(world.tenantA.id, `claim-${Date.now()}`);
    const [a, b] = await Promise.all([
      claimJobs(db.workerPool, { jobTypes: ['purge'], limit: 10 }),
      claimJobs(db.workerPool, { jobTypes: ['purge'], limit: 10 }),
    ]);
    const claimed = [...a, ...b].filter((j) => j.job_id === jobId);
    expect(claimed).toHaveLength(1);
    const { rows } = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.jobs WHERE job_id = $1`,
      [jobId],
    );
    expect(rows[0]?.status).toBe('running');
    await db.superuserPool.query(`UPDATE securerag.jobs SET status = 'pending', next_attempt_at = now() WHERE job_id = $1`, [jobId]);
  });

  it('a purge job succeeds end-to-end and marks/removes expired data', async () => {
    await db.superuserPool.query(
      `UPDATE securerag.document_versions
          SET status = 'expired', published_at = now() - interval '4000 days'
        WHERE tenant_id = $1 AND version_id = $2`,
      [world.tenantB.id, world.docB.versionId],
    );
    await db.superuserPool.query(
      `UPDATE securerag.retention_policies SET source_days = 365, derived_days = 365 WHERE tenant_id = $1`,
      [world.tenantB.id],
    );
    const store = new InMemorySourceObjectStore();
    const key = await db.superuserPool.query<{ source_object_key: string }>(
      `SELECT source_object_key FROM securerag.document_versions WHERE version_id = $1`,
      [world.docB.versionId],
    );
    store.put(key.rows[0]!.source_object_key);
    const jobId = await enqueuePurgeJob(world.tenantB.id, `purge-e2e-${Date.now()}`);
    const result = await runWorkerOnce({
      workerPool: db.workerPool,
      purgePool: db.purgePool,
      store,
      ...ingestSeams,
    } as WorkerDeps, { limit: 10 });
    expect(result.claimed).toBeGreaterThanOrEqual(1);
    expect(result.failed).toBe(0);
    const { rows } = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.jobs WHERE job_id = $1`,
      [jobId],
    );
    expect(rows[0]?.status).toBe('succeeded');
    const gone = await db.superuserPool.query(
      `SELECT version_id FROM securerag.document_versions WHERE version_id = $1`,
      [world.docB.versionId],
    );
    expect(gone.rows).toHaveLength(0);
    expect(store.size).toBe(0);
  });

  it('a failing handler backoffs retryably and permanently fails at max_attempts', async () => {
    // An unknown job type has no handler: pickHandler throws inside the
    // transaction -> the failure path. Drive to max_attempts (5) to prove the
    // terminal transition, not just the first backoff.
    const { rows: inserted } = await db.superuserPool.query<{ job_id: string }>(
      `INSERT INTO securerag.jobs (tenant_id, idempotency_key, job_type, max_attempts)
       VALUES ($1, $2, 'bogus-type', 3) RETURNING job_id`,
      [world.tenantA.id, `bogus-${Date.now()}`],
    );
    const jobId = inserted[0]!.job_id;
    const deps: WorkerDeps = {
      workerPool: db.workerPool,
      purgePool: db.purgePool,
      store: new InMemorySourceObjectStore(),
      ...ingestSeams,
      jobTypes: ['purge', 'bogus-type'],
    };
    for (let i = 0; i < 5; i += 1) {
      await runWorkerOnce(deps, { limit: 10 });
      const { rows } = await db.superuserPool.query<{ status: string; attempts: number }>(
        `SELECT status, attempts FROM securerag.jobs WHERE job_id = $1`,
        [jobId],
      );
      if (rows[0]?.status === 'permanent_failed') break;
      // Backoff puts the next attempt in the future; reset so the loop can
      // drive it (the backoff itself is covered by the queue unit semantics).
      await db.superuserPool.query(
        `UPDATE securerag.jobs SET next_attempt_at = now() WHERE job_id = $1`,
        [jobId],
      );
    }
    const { rows } = await db.superuserPool.query<{ status: string; attempts: number }>(
      `SELECT status, attempts FROM securerag.jobs WHERE job_id = $1`,
      [jobId],
    );
    expect(rows[0]?.attempts).toBe(3);
    expect(rows[0]?.status).toBe('permanent_failed');
  });

  it('a crashed running job is reclaimed after its lease expires', async () => {
    const { rows: inserted } = await db.superuserPool.query<{ job_id: string }>(
      `INSERT INTO securerag.jobs (tenant_id, idempotency_key, job_type, status, next_attempt_at)
       VALUES ($1, $2, 'purge', 'running', now() - interval '10 minutes') RETURNING job_id`,
      [world.tenantA.id, `crashed-${Date.now()}`],
    );
    const jobId = inserted[0]!.job_id;
    const claimed = await claimJobs(db.workerPool, { jobTypes: ['purge'], limit: 10 });
    expect(claimed.some((j) => j.job_id === jobId)).toBe(true);
    const { rows } = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.jobs WHERE job_id = $1`,
      [jobId],
    );
    expect(rows[0]?.status).toBe('running');
    await db.superuserPool.query(`UPDATE securerag.jobs SET status = 'pending', next_attempt_at = now() WHERE job_id = $1`, [jobId]);
  });
});
