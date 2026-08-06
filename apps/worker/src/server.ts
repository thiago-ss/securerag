/**
 * Worker daemon (S9/S2; ADR-0010, ADR-0007): the purge + ingest pipelines'
 * PRODUCER + consumer loop.
 *
 * The queue machinery alone is inert without a producer (S9 review F1):
 * this daemon
 *   1. SCHEDULES purge jobs — enumerates tenants through the worker-visible
 *      retention_policies table and enqueues one purge job per tenant with a
 *      daily idempotency key (unique (tenant_id, idempotency_key) makes the
 *      schedule idempotent; a job already queued/running/succeeded for today
 *      is never duplicated).
 *   2. CONSUMES claimable jobs (pending or lease-expired running) with SKIP
 *      LOCKED and runs the purge or ingest handler.
 *   3. Graceful shutdown on SIGTERM/SIGINT.
 *
 * Config comes from the environment (Zod-validated): PGHOST/PGPORT/PGDATABASE
 * plus WORKER_USER/WORKER_PASSWORD and PURGE_USER/PURGE_PASSWORD for the two
 * narrow credentials. No secrets in code.
 *
 * S2 seams: SOURCE_STORE selects the object adapter ('memory' for CI/demo,
 * 's3' for S3/MinIO with SSE-S3); CLAMAV_HOST selects the real clamd adapter
 * (unset → the deterministic fake). The real adapters are never exercised in
 * CI without their containers (ADR-0007; r8 §1/§2).
 */
import { createRuntimePool } from '@securerag/security';
import {
  DETERMINISTIC_EMBEDDING,
  InMemorySourceObjectStore,
  S3SourceObjectStore,
  type SourceObjectStore,
} from '@securerag/core';
import {
  ClamavClamdAdapter,
  DETERMINISTIC_MALWARE_SCANNER,
  HEURISTIC_INJECTION_DETECTOR,
  STANDARD_EXTRACTION,
} from '@securerag/providers';
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
  /** Object storage seam (ADR-0007): memory for CI/demo; s3 behind S3_* config. */
  SOURCE_STORE: z.enum(['memory', 's3']).default('memory'),
  S3_ENDPOINT: z.string().optional(),
  S3_REGION: z.string().default('us-east-1'),
  S3_BUCKET: z.string().default('securerag-objects'),
  S3_ACCESS_KEY_ID: z.string().optional(),
  S3_SECRET_ACCESS_KEY: z.string().optional(),
  S3_FORCE_PATH_STYLE: z
    .string()
    .default('true')
    .transform((v) => v === 'true' || v === '1'),
  /** clamd adapter (r8 §2): only built when CLAMAV_HOST is set. */
  CLAMAV_HOST: z.string().optional(),
  CLAMAV_PORT: z.coerce.number().default(3310),
});

function buildStore(env: z.infer<typeof envSchema>): SourceObjectStore {
  if (env.SOURCE_STORE === 's3') {
    return new S3SourceObjectStore({
      bucket: env.S3_BUCKET,
      ...(env.S3_ENDPOINT !== undefined ? { endpoint: env.S3_ENDPOINT } : {}),
      region: env.S3_REGION,
      forcePathStyle: env.S3_FORCE_PATH_STYLE,
      ...(env.S3_ACCESS_KEY_ID !== undefined && env.S3_SECRET_ACCESS_KEY !== undefined
        ? { accessKeyId: env.S3_ACCESS_KEY_ID, secretAccessKey: env.S3_SECRET_ACCESS_KEY }
        : {}),
    });
  }
  return new InMemorySourceObjectStore();
}

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
  const store = buildStore(env);
  const scanner = env.CLAMAV_HOST !== undefined
    ? new ClamavClamdAdapter({ host: env.CLAMAV_HOST, port: env.CLAMAV_PORT })
    : DETERMINISTIC_MALWARE_SCANNER;
  return {
    workerPool,
    purgePool,
    store,
    extractor: STANDARD_EXTRACTION,
    scanner,
    detector: HEURISTIC_INJECTION_DETECTOR,
    embedding: DETERMINISTIC_EMBEDDING,
  };
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

main().catch((err: unknown) => {
  // eslint-disable-next-line no-console
  console.error(`worker daemon failed: ${String(err)}`);
  process.exitCode = 1;
});
