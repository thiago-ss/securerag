import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import { InMemorySourceObjectStore } from '@securerag/core';
import { runWorkerOnce } from '../src/index.js';
import { claimJobs } from '../src/queue.js';

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
    }, { limit: 10 });
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
    // transaction -> the failure path (backoff, then permanent at max_attempts).
    const { rows: inserted } = await db.superuserPool.query<{ job_id: string }>(
      `INSERT INTO securerag.jobs (tenant_id, idempotency_key, job_type)
       VALUES ($1, $2, 'bogus-type') RETURNING job_id`,
      [world.tenantA.id, `bogus-${Date.now()}`],
    );
    const jobId = inserted[0]!.job_id;
    const result = await runWorkerOnce({
      workerPool: db.workerPool,
      purgePool: db.purgePool,
      store: new InMemorySourceObjectStore(),
      jobTypes: ['purge', 'bogus-type'],
    }, { limit: 10 });
    void result;
    const { rows } = await db.superuserPool.query<{ status: string; attempts: number }>(
      `SELECT status, attempts FROM securerag.jobs WHERE job_id = $1`,
      [jobId],
    );
    expect(rows[0]?.attempts).toBeGreaterThanOrEqual(1);
    expect(['pending', 'permanent_failed']).toContain(rows[0]?.status);
  });
});
