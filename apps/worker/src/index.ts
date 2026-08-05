/**
 * Worker entry: claim -> execute -> complete/fail. Handlers re-enter the
 * verified tenant context (worker credential) before touching payloads; the
 * purge handler delegates to core runTenantPurge (expiry marking via the
 * worker credential, destructive deletes via the narrow purge credential);
 * the ingest handler delegates to core runIngestion (S2 pipeline, ADR-0007).
 */
import type { Pool, PoolClient } from 'pg';
import {
  runTenantPurge,
  runIngestion,
  parsePayload,
  IngestPermanentFailure,
  type PurgeDeps,
} from '@securerag/core';
import type {
  ExtractionProvider,
  InjectionDetector,
  MalwareScanner,
} from '@securerag/providers';
import type { EmbeddingProvider } from '@securerag/core';
import { claimJobs, completeJob, failJob, type JobRow } from './queue.js';

export interface WorkerDeps extends PurgeDeps {
  /** securerag_worker pool (queue claims + worker-context work). */
  workerPool: Pool;
  /** S2 pipeline seams (ADR-0007). */
  extractor: ExtractionProvider;
  scanner: MalwareScanner;
  detector: InjectionDetector;
  embedding: EmbeddingProvider;
  jobTypes?: readonly string[];
}

export interface WorkerRunResult {
  claimed: number;
  succeeded: number;
  failed: number;
}

export type JobHandler = (client: PoolClient, job: JobRow) => Promise<void>;

const JOB_TYPES = ['purge', 'ingest'] as const;

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
 * Ingest handler (S2): runs the ingestion pipeline for the claimed job. The
 * job payload holds ONLY opaque ids + object metadata (r8 §4); the pipeline
 * re-enters the tenant context and re-reads the version + object — the DB is
 * the authority, never the payload.
 */
export function ingestHandler(deps: WorkerDeps): JobHandler {
  return async (_client, job) => {
    const payload = parsePayload(job.payload_key);
    if (payload === null) {
      throw new IngestPermanentFailure('invalid-job-payload');
    }
    await runIngestion(
      {
        workerPool: deps.workerPool,
        store: deps.store,
        extractor: deps.extractor,
        scanner: deps.scanner,
        detector: deps.detector,
        embedding: deps.embedding,
      },
      {
        tenantId: job.tenant_id,
        requestId: job.job_id,
        ...payload,
      },
    );
  };
}

/**
 * One worker pass: claim up to `limit` jobs and execute them. Handler
 * failures are retryable by default (backoff) unless permanent
 * (IngestPermanentFailure from the S2 pipeline). Returns per-class counts.
 * Used by tests and by the daemon loop.
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
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      await client.query('BEGIN');
      await failJob(client, job, { retryable: !(err instanceof IngestPermanentFailure) });
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
    case 'ingest':
      return ingestHandler(deps);
    default:
      throw new Error(`unknown job type: ${jobType}`);
  }
}
