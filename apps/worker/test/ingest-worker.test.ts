import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  getTestDb,
  resetData,
  seedFixtures,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import {
  DETERMINISTIC_EMBEDDING,
  InMemorySourceObjectStore,
  sourceObjectKey,
  type IngestJobPayload,
} from '@securerag/core';
import {
  DETERMINISTIC_MALWARE_SCANNER,
  EICAR_STRING,
  HEURISTIC_INJECTION_DETECTOR,
  STANDARD_EXTRACTION,
} from '@securerag/providers';
import { runWorkerOnce, type WorkerDeps } from '../src/index.js';

function sha256(bytes: Buffer): Buffer {
  return createHash('sha256').update(bytes).digest();
}

describe('S2 worker: ingest job claim + pipeline run end to end', () => {
  let db: TestDb;
  let world: Awaited<ReturnType<typeof seedFixtures>>;
  let store: InMemorySourceObjectStore;

  const deps = (): WorkerDeps => ({
    workerPool: db.workerPool,
    purgePool: db.purgePool,
    store,
    extractor: STANDARD_EXTRACTION,
    scanner: DETERMINISTIC_MALWARE_SCANNER,
    detector: HEURISTIC_INJECTION_DETECTOR,
    embedding: DETERMINISTIC_EMBEDDING,
  });

  /** The API-side upload path, mirrored: object put + pending version + job. */
  async function stageIngestJob(
    bytes: Buffer,
    filename: string,
    contentType: string,
  ): Promise<{ jobId: string; versionId: string }> {
    const key = sourceObjectKey(world.tenantA.id, sha256(bytes).toString('hex'), filename);
    await store.put(key, bytes);
    const { rows } = await db.superuserPool.query<{ version_id: string }>(
      `INSERT INTO securerag.document_versions
         (tenant_id, document_id, version_no, source_object_key, content_hash, status, is_current)
       SELECT $1, $2, COALESCE(MAX(version_no), 0) + 1, $3, $4, 'pending', false
         FROM securerag.document_versions WHERE tenant_id = $1 AND document_id = $2
       RETURNING version_id`,
      [world.tenantA.id, world.docA.id, key, sha256(bytes)],
    );
    const versionId = rows[0]!.version_id;
    const payload: IngestJobPayload = {
      documentId: world.docA.id,
      versionId,
      objectKey: key,
      filename,
      contentType,
    };
    const job = await db.superuserPool.query<{ job_id: string }>(
      `INSERT INTO securerag.jobs (tenant_id, idempotency_key, job_type, payload_key)
       VALUES ($1, $2, 'ingest', $3) RETURNING job_id`,
      [world.tenantA.id, `ingest:${randomUUID()}`, JSON.stringify(payload)],
    );
    return { jobId: job.rows[0]!.job_id, versionId };
  }

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    store = new InMemorySourceObjectStore();
  });

  afterAll(async () => {
    await db.stop();
  });

  it('claims an ingest job, runs the pipeline, and completes it (version valid + chunks)', async () => {
    const bytes = Buffer.from('Worker e2e ingestion content.', 'utf8');
    const { jobId, versionId } = await stageIngestJob(bytes, 'worker-e2e.txt', 'text/plain');
    const result = await runWorkerOnce(deps(), { limit: 10 });
    expect(result.claimed).toBeGreaterThanOrEqual(1);
    expect(result.failed).toBe(0);

    const job = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.jobs WHERE job_id = $1`,
      [jobId],
    );
    expect(job.rows[0]?.status).toBe('succeeded');

    const version = await db.superuserPool.query<{ status: string; is_current: boolean }>(
      `SELECT status, is_current FROM securerag.document_versions WHERE version_id = $1`,
      [versionId],
    );
    expect(version.rows[0]).toMatchObject({ status: 'valid', is_current: true });

    const chunks = await db.superuserPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM securerag.chunks WHERE version_id = $1`,
      [versionId],
    );
    expect(Number(chunks.rows[0]?.n ?? 0)).toBeGreaterThan(0);
  });

  it('a malware-infected ingest job permanently fails (never retried) and never publishes', async () => {
    const bytes = Buffer.from(`x ${EICAR_STRING} y`, 'utf8');
    const { jobId, versionId } = await stageIngestJob(bytes, 'eicar.txt', 'text/plain');
    const result = await runWorkerOnce(deps(), { limit: 10 });
    expect(result.failed).toBe(1);
    const job = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.jobs WHERE job_id = $1`,
      [jobId],
    );
    expect(job.rows[0]?.status).toBe('permanent_failed');
    const version = await db.superuserPool.query<{ status: string }>(
      `SELECT status FROM securerag.document_versions WHERE version_id = $1`,
      [versionId],
    );
    expect(version.rows[0]?.status).toBe('pending');
  });

  it('replays converge: a succeeded ingest job never double-publishes', async () => {
    const bytes = Buffer.from('Replay convergence content.', 'utf8');
    const { versionId } = await stageIngestJob(bytes, 'replay.txt', 'text/plain');
    await runWorkerOnce(deps(), { limit: 10 });
    const chunkCount = await db.superuserPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM securerag.chunks WHERE version_id = $1`,
      [versionId],
    );
    const before = Number(chunkCount.rows[0]?.n ?? 0);
    expect(before).toBeGreaterThan(0);
    // Second pass with nothing new claims nothing and changes nothing.
    const replay = await runWorkerOnce(deps(), { limit: 10 });
    expect(replay.claimed).toBe(0);
    const after = await db.superuserPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM securerag.chunks WHERE version_id = $1`,
      [versionId],
    );
    expect(Number(after.rows[0]?.n ?? 0)).toBe(before);
  });
});
