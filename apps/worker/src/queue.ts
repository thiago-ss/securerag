/**
 * PostgreSQL-backed job queue (research r8 §4): claim via
 * `UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED LIMIT n)`
 * inside a job transaction; retry with exponential backoff; idempotency keys
 * unique (tenant_id, idempotency_key); terminal outcome rows in the same
 * transaction. The worker role sees every job row (opaque ids + tenant only,
 * policy in 0009); payloads are re-entered through the verified tenant
 * context inside the handler.
 */
import type { Pool, PoolClient } from 'pg';

export interface JobRow {
  tenant_id: string;
  job_id: string;
  job_type: string;
  idempotency_key: string;
  status: string;
  attempts: number;
  max_attempts: number;
  payload_key: string | null;
}

export interface ClaimOptions {
  jobTypes: readonly string[];
  limit: number;
  now?: () => Date;
}

const BACKOFF_BASE_MS = 30_000;

/**
 * Claim up to `limit` pending jobs of the given types with SKIP LOCKED.
 * Returns the claimed rows with attempts incremented and a lease on
 * next_attempt_at. Idempotent callers: the same job can never be claimed by
 * two consumers (row lock + status transition are atomic).
 */
export async function claimJobs(pool: Pool, opts: ClaimOptions): Promise<JobRow[]> {
  const now = opts.now?.() ?? new Date();
  const { rows } = await pool.query<JobRow>(
    `UPDATE securerag.jobs j
        SET status = 'running',
            attempts = j.attempts + 1,
            next_attempt_at = $2::timestamptz
      WHERE j.job_id IN (
        SELECT j2.job_id
          FROM securerag.jobs j2
         WHERE j2.status = 'pending'
           AND j2.next_attempt_at <= $2::timestamptz
           AND j2.job_type = ANY($3::text[])
         ORDER BY j2.job_id
         FOR UPDATE SKIP LOCKED
         LIMIT $1
      )
      RETURNING tenant_id, job_id, job_type, idempotency_key, status,
                attempts, max_attempts, payload_key`,
    [opts.limit, now, [...opts.jobTypes]],
  );
  return rows;
}

export interface CompleteOptions {
  retryable: boolean;
}

/** Terminal success: status succeeded, outcome recorded atomically. */
export async function completeJob(
  client: PoolClient,
  job: JobRow,
): Promise<void> {
  await client.query(
    `UPDATE securerag.jobs
        SET status = 'succeeded', updated_at = now()
      WHERE tenant_id = $1 AND job_id = $2`,
    [job.tenant_id, job.job_id],
  );
}

/**
 * Failure: retryable failures back off 30s * 2^(attempts-1) + jitter and
 * return to pending; permanent failures (attempts >= max_attempts) are
 * terminal. Callers wrap their work in a transaction with this update.
 */
export async function failJob(
  client: PoolClient,
  job: JobRow,
  opts: CompleteOptions,
): Promise<void> {
  const attempts = job.attempts;
  const permanent = attempts >= job.max_attempts || !opts.retryable;
  if (permanent) {
    await client.query(
      `UPDATE securerag.jobs
          SET status = 'permanent_failed', updated_at = now()
        WHERE tenant_id = $1 AND job_id = $2`,
      [job.tenant_id, job.job_id],
    );
    return;
  }
  const backoffMs = BACKOFF_BASE_MS * 2 ** Math.max(0, attempts - 1);
  const next = new Date(Date.now() + backoffMs);
  await client.query(
    `UPDATE securerag.jobs
        SET status = 'pending', next_attempt_at = $3::timestamptz, updated_at = now()
      WHERE tenant_id = $1 AND job_id = $2`,
    [job.tenant_id, job.job_id, next],
  );
}
