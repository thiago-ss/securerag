/**
 * Worker entry: claim -> execute -> complete/fail. Handlers re-enter the
 * verified tenant context (worker credential) before touching payloads; the
 * purge handler delegates to core runTenantPurge (expiry marking via the
 * worker credential, destructive deletes via the narrow purge credential).
 */
import type { Pool, PoolClient } from 'pg';
import { runTenantPurge, type PurgeDeps } from '@securerag/core';
import { claimJobs, completeJob, failJob, type JobRow } from './queue.js';

export interface WorkerDeps extends PurgeDeps {
  /** securerag_worker pool (queue claims + worker-context work). */
  workerPool: Pool;
  jobTypes?: readonly string[];
}

export interface WorkerRunResult {
  claimed: number;
  succeeded: number;
  failed: number;
}

export type JobHandler = (client: PoolClient, job: JobRow) => Promise<void>;

const JOB_TYPES = ['purge'] as const;

/** Purge handler: runs the tenant's retention purge (idempotent by design). */
export function purgeHandler(deps: WorkerDeps): JobHandler {
  return async (_client, job) => {
    await runTenantPurge(
      { workerPool: deps.workerPool, purgePool: deps.purgePool, store: deps.store },
      { tenantId: job.tenant_id, requestId: job.job_id },
    );
  };
}

/**
 * One worker pass: claim up to `limit` jobs and execute them. Handler
 * failures are retryable by default (backoff) unless permanent. Returns
 * per-class counts. Used by tests and by the daemon loop.
 */
export async function runWorkerOnce(
  deps: WorkerDeps,
  opts: { limit?: number } = {},
): Promise<WorkerRunResult> {
  const jobTypes = deps.jobTypes ?? JOB_TYPES;
  const claimed = await claimJobs(deps.workerPool, {
    jobTypes,
    limit: opts.limit ?? 1,
  });
  let succeeded = 0;
  let failed = 0;

  for (const job of claimed) {
    const client = await deps.workerPool.connect();
    try {
      await client.query('BEGIN');
      const handler = pickHandler(deps, job.job_type);
      await handler(client, job);
      await completeJob(client, job);
      await client.query('COMMIT');
      succeeded += 1;
    } catch {
      await client.query('ROLLBACK').catch(() => {});
      await client.query('BEGIN');
      await failJob(client, job, { retryable: true });
      await client.query('COMMIT');
      failed += 1;
    } finally {
      client.release();
    }
  }

  return { claimed: claimed.length, succeeded, failed };
}

function pickHandler(deps: WorkerDeps, jobType: string): JobHandler {
  switch (jobType) {
    case 'purge':
      return purgeHandler(deps);
    default:
      throw new Error(`unknown job type: ${jobType}`);
  }
}
