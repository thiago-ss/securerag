/**
 * Worker daemon (S9, ADR-0010): the purge pipeline's PRODUCER + consumer loop.
 *
 * The queue machinery alone is inert without a producer (S9 review F1):
 * this daemon
 *   1. SCHEDULES purge jobs — enumerates tenants through the worker-visible
 *      retention_policies table and enqueues one purge job per tenant with a
 *      daily idempotency key (unique (tenant_id, idempotency_key) makes the
 *      schedule idempotent; a job already queued/running/succeeded for today
 *      is never duplicated).
 *   2. CONSUMES claimable jobs (pending or lease-expired running) with SKIP
 *      LOCKED and runs the purge handler.
 *   3. Graceful shutdown on SIGTERM/SIGINT.
 *
 * Config comes from the environment (Zod-validated): PGHOST/PGPORT/PGDATABASE
 * plus WORKER_USER/WORKER_PASSWORD and PURGE_USER/PURGE_PASSWORD for the two
 * narrow credentials. No secrets in code.
 */
import { createRuntimePool } from '@securerag/security';
import { InMemorySourceObjectStore, type SourceObjectStore } from '@securerag/core';
import type { Pool } from 'pg';
import { z } from 'zod';
import { runWorkerOnce, type WorkerDeps } from './index.js';

const envSchema = z.object({
  PGHOST: z.string().default('localhost'),
  PGPORT: z.coerce.number().default(5432),
  PGDATABASE: z.string().default('securerag'),
  WORKER_USER: z.string().default('securerag_worker'),
  WORKER_PASSWORD: z.string(),
  PURGE_USER: z.string().default('securerag_purge'),
  PURGE_PASSWORD: z.string(),
  POLL_INTERVAL_MS: z.coerce.number().default(10_000),
  CLAIM_LIMIT: z.coerce.number().default(10),
  /** Object storage seam: v1 in-memory; an S3 adapter replaces it with S2. */
  SOURCE_STORE: z.enum(['memory']).default('memory'),
});

export function buildDeps(env: z.infer<typeof envSchema>): WorkerDeps {
  const base = {
    host: env.PGHOST,
    port: env.PGPORT,
    database: env.PGDATABASE,
    max: 5,
  };
  const workerPool: Pool = createRuntimePool('securerag_worker', {
    ...base,
    user: env.WORKER_USER,
    password: env.WORKER_PASSWORD,
  });
  const purgePool: Pool = createRuntimePool('securerag_purge', {
    ...base,
    user: env.PURGE_USER,
    password: env.PURGE_PASSWORD,
  });
  const store: SourceObjectStore = env.SOURCE_STORE === 'memory'
    ? new InMemorySourceObjectStore()
    : new InMemorySourceObjectStore();
  return { workerPool, purgePool, store };
}

const DAILY_KEY = (now: Date): string => `purge:${now.toISOString().slice(0, 10)}`;

/** Producer: enqueue one purge job per tenant per day (idempotency key). */
export async function enqueueDuePurgeJobs(
  workerPool: Pool,
  now: Date,
  limit = 500,
): Promise<number> {
  const key = DAILY_KEY(now);
  const { rows } = await workerPool.query<{ tenant_id: string }>(
    `INSERT INTO securerag.jobs (tenant_id, idempotency_key, job_type)
     SELECT rp.tenant_id, $1, 'purge'
       FROM securerag.retention_policies rp
      WHERE NOT EXISTS (
        SELECT 1 FROM securerag.jobs j
         WHERE j.tenant_id = rp.tenant_id AND j.idempotency_key = $1
      )
      LIMIT $2
     RETURNING tenant_id`,
    [key, limit],
  );
  return rows.length;
}

/** One daemon pass: schedule due purge jobs, then run a claim/execute round. */
export async function daemonPass(deps: WorkerDeps, now: Date): Promise<{
  scheduled: number;
  worker: Awaited<ReturnType<typeof runWorkerOnce>>;
}> {
  const scheduled = await enqueueDuePurgeJobs(deps.workerPool, now);
  const worker = await runWorkerOnce(deps, { limit: 10 });
  return { scheduled, worker };
}

export async function main(): Promise<void> {
  const env = envSchema.parse(process.env);
  const deps = buildDeps(env);
  const intervalMs = env.POLL_INTERVAL_MS;
  let shuttingDown = false;

  const stop = (): void => {
    shuttingDown = true;
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);

  // eslint-disable-next-line no-console
  console.log(`worker daemon starting (poll ${intervalMs}ms)`);
  while (!shuttingDown) {
    try {
      const pass = await daemonPass(deps, new Date());
      if (pass.scheduled > 0 || pass.worker.claimed > 0) {
        // eslint-disable-next-line no-console
        console.log(
          `pass: scheduled=${pass.scheduled} claimed=${pass.worker.claimed} ok=${pass.worker.succeeded} failed=${pass.worker.failed}`,
        );
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`daemon pass failed: ${String(err)}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  // eslint-disable-next-line no-console
  console.log('worker daemon stopping');
  await Promise.allSettled([deps.workerPool.end(), deps.purgePool.end()]);
}
