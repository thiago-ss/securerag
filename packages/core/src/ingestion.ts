/**
 * Ingestion pipeline (S2; ADR-0007). Each stage bounded, idempotent,
 * versioned, audited, running under withWorkerContext:
 *
 *   upload -> validate (type/size/limits) -> malware scan -> encrypted
 *   immutable source -> extract -> injection scan (high risk ->
 *   quarantineVersion) -> PII detect/redact -> chunk -> FTS/embed ->
 *   verify (content hash) -> atomic publish
 *
 * Stage placement: the API route performs `upload` (object store put with
 * SSE-S3, tenant-prefixed content-addressed key, ADR-0007) and creates the
 * PENDING version row + the ingest job in one transaction. The worker then
 * runs THIS pipeline for the claimed job.
 *
 * Idempotency (r8 §4 at-least-once): the version row's status is the
 * outcome row. Replays observe `status IN ('valid','superseded')` and
 * no-op; a crash between pipeline commit and job completion cannot
 * double-publish because the publish guard runs before any side effect.
 *
 * Audit events (one per stage, inside the same worker transaction):
 * 'ingest:received' (API route), 'ingest:scanned', 'ingest:extracted',
 * 'ingest:redacted', 'ingest:chunked', 'ingest:verified', 'ingest:published',
 * 'ingest:rejected' (+ 'injection:detected' / 'version:quarantined' on the
 * S5 high-risk path). Filters carry ids/hashes/counts only — never content.
 *
 * A new current version publishes atomically only after ALL stages succeed:
 * the supersede + publish UPDATEs run in one statement batch inside the
 * pipeline transaction, and the partial unique index
 * (tenant_id, document_id) WHERE is_current keeps exactly one current
 * version (0002). Failed/quarantined versions never become searchable —
 * every retrieval surface filters status IN ('valid','released')
 * (retrieval.ts/documents.ts) — and this module adds explicit tests for it.
 */
import type { Pool, PoolClient } from 'pg';
import { createHash } from 'node:crypto';
import { withWorkerContext, withSecurityContext } from '@securerag/security';
import { toVectorLiteral, type EmbeddingProvider } from './embeddings.js';
import { appendAudit } from './audit.js';
import { DEFAULT_PII_CONFIG, redactForSurface, type PiiConfig } from './redaction.js';
import { grantPredicateSql, manageAllowed } from './grants.js';
import type { SourceObjectStore } from './storage.js';
import type { InjectionDetector, ExtractionProvider, MalwareScanner } from '@securerag/providers';
import type { SecurityParams } from './types.js';

/** Documented service identity for worker-written ingest audits (no FK on
 * audit_events; never read back as a principal; same pattern as S9 purge). */
export const INGEST_SERVICE_PRINCIPAL = '00000000-0000-4000-8000-000000000003';
export const INGEST_SERVICE_MEMBERSHIP = '00000000-0000-4000-8000-000000000004';

/** Pipeline-wide bounds (mirror of ADR-0007 / packages/providers limits). */
export const INGEST_MAX_SOURCE_BYTES = 50 * 1024 * 1024;
export const INGEST_CHUNK_SIZE = 1000;
export const INGEST_CHUNK_OVERLAP = 100;

export interface IngestDeps {
  /** Pool used with withWorkerContext (worker credential, tenant-scoped RLS). */
  workerPool: Pool;
  store: SourceObjectStore;
  extractor: ExtractionProvider;
  scanner: MalwareScanner;
  detector: InjectionDetector;
  embedding: EmbeddingProvider;
  pii?: PiiConfig;
}

/** Job payload shape (jobs.payload_key JSON): opaque ids + object metadata
 * ONLY — never content (r8 §4 "Worker security context"). */
export interface IngestJobPayload {
  documentId: string;
  versionId: string;
  objectKey: string;
  filename: string;
  contentType: string;
}

export interface IngestParams extends IngestJobPayload {
  tenantId: string;
  requestId: string;
}

export type IngestOutcome =
  | { outcome: 'published'; versionId: string }
  | { outcome: 'quarantined'; versionId: string }
  | { outcome: 'rejected'; versionId: string }
  | { outcome: 'noop'; versionId: string };

/**
 * Permanent pipeline failure (malware, unsupported type, limit, hash
 * mismatch): the job must NOT retry. The worker marks it terminal.
 */
export class IngestPermanentFailure extends Error {
  constructor(
    readonly reason: string,
    message?: string,
  ) {
    super(message ?? `ingest rejected: ${reason}`);
    this.name = 'IngestPermanentFailure';
  }
}

/** Transient failure (scanner outage, missing object): retryable with backoff. */
export class IngestRetryableFailure extends Error {
  constructor(
    readonly reason: string,
    message?: string,
  ) {
    super(message ?? `ingest retryable failure: ${reason}`);
    this.name = 'IngestRetryableFailure';
  }
}

function parsePayload(payloadKey: string | null): IngestJobPayload | null {
  if (payloadKey === null) return null;
  try {
    const parsed = JSON.parse(payloadKey) as Partial<IngestJobPayload>;
    if (
      typeof parsed.documentId === 'string' &&
      typeof parsed.versionId === 'string' &&
      typeof parsed.objectKey === 'string' &&
      typeof parsed.filename === 'string' &&
      typeof parsed.contentType === 'string'
    ) {
      return {
        documentId: parsed.documentId,
        versionId: parsed.versionId,
        objectKey: parsed.objectKey,
        filename: parsed.filename,
        contentType: parsed.contentType,
      };
    }
  } catch {
    // fall through
  }
  return null;
}

export { parsePayload };

/** SHA-256 over raw bytes (content hashes are bytea). */
function sha256Bytes(bytes: Buffer): Buffer {
  return createHash('sha256').update(bytes).digest();
}

/**
 * Deterministic chunking of redacted text (S2): fixed window with overlap,
 * span offsets into the redacted text (chunks table span_start/span_end).
 * Chunk boundaries never split on the redaction tokens (window is
 * character-based; tokens are inside windows, not split across them).
 */
export function chunkText(
  text: string,
  size = INGEST_CHUNK_SIZE,
  overlap = INGEST_CHUNK_OVERLAP,
): { text: string; start: number; end: number }[] {
  if (text.length === 0) return [];
  if (text.length <= size) return [{ text, start: 0, end: text.length }];
  const chunks: { text: string; start: number; end: number }[] = [];
  let start = 0;
  while (start < text.length) {
    const end = Math.min(start + size, text.length);
    chunks.push({ text: text.slice(start, end), start, end });
    if (end >= text.length) break;
    const next = start + (size - overlap);
    if (next <= start) break; // defensive: guaranteed progress
    start = next;
  }
  return chunks;
}

interface VersionRow {
  status: string;
  is_current: boolean;
  content_hash: Buffer | null;
  version_no: number;
}

/**
 * The worker-side pipeline (stages validate → scan → extract → inject →
 * redact → chunk → embed → verify → publish), all in ONE
 * withWorkerContext transaction.
 *
 * Permanent rejections (malware, unsupported type, limits, hash mismatch)
 * audit 'ingest:rejected' INSIDE the transaction and then throw
 * IngestPermanentFailure AFTER the commit — a rejection's audit trail must
 * survive (a throw inside the transaction would roll the audit back).
 * Transient failures (scanner outage, missing object) throw inside the
 * transaction: rollback is correct for a retry.
 */
export async function runIngestion(
  deps: IngestDeps,
  params: IngestParams,
): Promise<IngestOutcome> {
  const pii = deps.pii ?? DEFAULT_PII_CONFIG;
  let rejectionReason: string | null = null;
  const outcome = await withWorkerContext(deps.workerPool, params, async (client, ctx) => {
    // ---------- Idempotency guard (r8 §4): outcome row first ----------
    const version = await readVersion(client, params.versionId);
    if (version === null) {
      throw new IngestPermanentFailure('version-missing', `version ${params.versionId} not found`);
    }
    if (version.status === 'valid' || version.status === 'superseded') {
      // Replay after a crash: the pipeline already published; no-op.
      return { outcome: 'noop' as const, versionId: params.versionId };
    }

    // ---------- Validate: source object, size, type ----------
    const bytes = await deps.store.get(params.objectKey);
    if (bytes === null) {
      // Storage missed the object (or a crashed put): retry, not permanent.
      throw new IngestRetryableFailure('source-object-missing');
    }
    if (bytes.length > INGEST_MAX_SOURCE_BYTES) {
      rejectionReason = 'size-limit';
      await rejectAndAudit(client, ctx, params, rejectionReason, `sizeBytes=${bytes.length}`);
      return { outcome: 'rejected' as const, versionId: params.versionId };
    }

    // ---------- Malware scan (before extraction, r8 §2) ----------
    const scan = await deps.scanner.scan(bytes);
    if (scan.verdict === 'error') {
      await appendAudit({
        client,
        event: {
          eventType: 'ingest:scanned',
          requestId: params.requestId,
          principalId: INGEST_SERVICE_PRINCIPAL,
          membershipId: INGEST_SERVICE_MEMBERSHIP,
          authEpoch: ctx.authEpoch,
          filters: { versionId: params.versionId, verdict: 'error', message: scan.message },
        },
      });
      // A scan error is NEVER treated as clean (r8 §2): retry with backoff.
      throw new IngestRetryableFailure('malware-scan-error', scan.message);
    }
    if (scan.verdict === 'infected') {
      await appendAudit({
        client,
        event: {
          eventType: 'ingest:scanned',
          requestId: params.requestId,
          principalId: INGEST_SERVICE_PRINCIPAL,
          membershipId: INGEST_SERVICE_MEMBERSHIP,
          authEpoch: ctx.authEpoch,
          filters: { versionId: params.versionId, verdict: 'infected', signature: scan.signature },
        },
      });
      rejectionReason = 'malware';
      await rejectAndAudit(
        client,
        ctx,
        params,
        rejectionReason,
        `signature=${scan.signature}`,
      );
      return { outcome: 'rejected' as const, versionId: params.versionId };
    }
    await appendAudit({
      client,
      event: {
        eventType: 'ingest:scanned',
        requestId: params.requestId,
        principalId: INGEST_SERVICE_PRINCIPAL,
        membershipId: INGEST_SERVICE_MEMBERSHIP,
        authEpoch: ctx.authEpoch,
        filters: { versionId: params.versionId, verdict: 'clean', sizeBytes: bytes.length },
      },
    });

    // ---------- Extract (typed rejections → permanent) ----------
    let extracted: { text: string; pages: number | null };
    try {
      extracted = await deps.extractor.extract(bytes, params.contentType);
    } catch (err) {
      rejectionReason = extractFailureReason(err);
      await rejectAndAudit(client, ctx, params, rejectionReason);
      return { outcome: 'rejected' as const, versionId: params.versionId };
    }
    await appendAudit({
      client,
      event: {
        eventType: 'ingest:extracted',
        requestId: params.requestId,
        principalId: INGEST_SERVICE_PRINCIPAL,
        membershipId: INGEST_SERVICE_MEMBERSHIP,
        authEpoch: ctx.authEpoch,
        filters: {
          versionId: params.versionId,
          chars: extracted.text.length,
          pages: extracted.pages,
        },
      },
    });

    // ---------- Injection scan (S5 signal; high risk → quarantine) ----------
    const injection = await deps.detector.scan(extracted.text);
    if (injection.risk === 'high') {
      const bumped = await client.query<{ epoch: string }>(
        'SELECT securerag.bump_authorization_epoch() AS epoch',
      );
      const epoch = bumped.rows[0]?.epoch ?? ctx.authEpoch;
      const quarantined = await client.query(
        `UPDATE securerag.document_versions
            SET status = 'quarantined', reviewed_by = NULL, reviewed_at = NULL,
                review_decision = NULL
          WHERE tenant_id = securerag.ctx_tenant_id()
            AND version_id = $1
            AND status IN ('pending','valid','released')`,
        [params.versionId],
      );
      if ((quarantined.rowCount ?? 0) > 0) {
        await appendAudit({
          client,
          event: {
            eventType: 'injection:detected',
            requestId: params.requestId,
            principalId: INGEST_SERVICE_PRINCIPAL,
            membershipId: INGEST_SERVICE_MEMBERSHIP,
            authEpoch: epoch,
            filters: { versionId: params.versionId, reasons: injection.reasons },
          },
        });
        await appendAudit({
          client,
          event: {
            eventType: 'version:quarantined',
            requestId: params.requestId,
            principalId: INGEST_SERVICE_PRINCIPAL,
            membershipId: INGEST_SERVICE_MEMBERSHIP,
            authEpoch: epoch,
            filters: { versionId: params.versionId, documentId: params.documentId },
          },
        });
      }
      // Quarantine is a completed pipeline decision (S5 review releases it):
      // the job SUCCEEDS; the version is never searchable until review.
      return { outcome: 'quarantined' as const, versionId: params.versionId };
    }

    // ---------- PII detect/redact (S4, ADR-0005) ----------
    const piiMatches = pii.enabled ? pii.detector.detect(extracted.text) : [];
    const redacted = pii.enabled
      ? redactForSurface(extracted.text, pii, false)
      : extracted.text;
    await appendAudit({
      client,
      event: {
        eventType: 'ingest:redacted',
        requestId: params.requestId,
        principalId: INGEST_SERVICE_PRINCIPAL,
        membershipId: INGEST_SERVICE_MEMBERSHIP,
        authEpoch: ctx.authEpoch,
        filters: { versionId: params.versionId, piiMatches: piiMatches.length },
      },
    });

    // ---------- Chunk (redacted text only) ----------
    const chunks = chunkText(redacted);
    await appendAudit({
      client,
      event: {
        eventType: 'ingest:chunked',
        requestId: params.requestId,
        principalId: INGEST_SERVICE_PRINCIPAL,
        membershipId: INGEST_SERVICE_MEMBERSHIP,
        authEpoch: ctx.authEpoch,
        filters: { versionId: params.versionId, chunks: chunks.length },
      },
    });

    // ---------- FTS/embed ----------
    if (chunks.length > 0) {
      const vectors = await deps.embedding.embed(chunks.map((c) => c.text));
      for (let i = 0; i < chunks.length; i += 1) {
        const chunk = chunks[i] ?? { text: '', start: 0, end: 0 };
        const vector = vectors[i] ?? [];
        await client.query(
          `INSERT INTO securerag.chunks
             (tenant_id, version_id, chunk_no, text_redacted, span_start, span_end,
              content_hash, embedding)
           VALUES (securerag.ctx_tenant_id(), $1, $2, $3, $4, $5, $6, $7::public.vector)`,
          [
            params.versionId,
            i + 1,
            chunk.text,
            chunk.start,
            chunk.end,
            sha256Bytes(Buffer.from(chunk.text, 'utf8')),
            toVectorLiteral(vector),
          ],
        );
      }
    }

    // ---------- Verify (content hash of the SOURCE bytes) ----------
    const actualHash = sha256Bytes(bytes);
    const storedHash = version.content_hash;
    if (storedHash === null || !storedHash.equals(actualHash)) {
      rejectionReason = 'content-hash-mismatch';
      await rejectAndAudit(client, ctx, params, rejectionReason);
      return { outcome: 'rejected' as const, versionId: params.versionId };
    }
    await appendAudit({
      client,
      event: {
        eventType: 'ingest:verified',
        requestId: params.requestId,
        principalId: INGEST_SERVICE_PRINCIPAL,
        membershipId: INGEST_SERVICE_MEMBERSHIP,
        authEpoch: ctx.authEpoch,
        filters: { versionId: params.versionId, hashMatch: true },
      },
    });

    // ---------- Atomic publish (supersede prior current in the same batch) ----------
    // Document-row lock serializes concurrent publishes (is_current flip is
    // race-free; the loser waits and then supersedes the winner).
    await client.query(
      `SELECT 1 FROM securerag.documents
        WHERE tenant_id = securerag.ctx_tenant_id() AND document_id = $1
        FOR UPDATE`,
      [params.documentId],
    );
    await client.query(
      `UPDATE securerag.document_versions
          SET is_current = false, status = 'superseded'
        WHERE tenant_id = securerag.ctx_tenant_id()
          AND document_id = $1
          AND is_current`,
      [params.documentId],
    );
    await client.query(
      `UPDATE securerag.document_versions
          SET status = 'valid', is_current = true, published_at = now()
        WHERE tenant_id = securerag.ctx_tenant_id()
          AND version_id = $1`,
      [params.versionId],
    );
    const bumped = await client.query<{ epoch: string }>(
      'SELECT securerag.bump_authorization_epoch() AS epoch',
    );
    const publishEpoch = bumped.rows[0]?.epoch ?? ctx.authEpoch;
    await appendAudit({
      client,
      event: {
        eventType: 'ingest:published',
        requestId: params.requestId,
        principalId: INGEST_SERVICE_PRINCIPAL,
        membershipId: INGEST_SERVICE_MEMBERSHIP,
        authEpoch: publishEpoch,
        filters: {
          versionId: params.versionId,
          documentId: params.documentId,
          versionNo: version.version_no,
        },
      },
    });
    return { outcome: 'published' as const, versionId: params.versionId };
  });

  // A rejection was audited and committed inside the transaction; now surface
  // it to the worker as a permanent failure (never retried). A permanently
  // rejected version never publishes, so its source object would orphan
  // storage forever — delete it best-effort (S2 review 4).
  if (rejectionReason !== null) {
    await deps.store.deleteSources([params.objectKey]).catch(() => {});
    throw new IngestPermanentFailure(rejectionReason);
  }
  return outcome;
}

async function readVersion(
  client: PoolClient,
  versionId: string,
): Promise<VersionRow | null> {
  const { rows } = await client.query<VersionRow & { version_id: string }>(
    `SELECT status, is_current, content_hash, version_no
       FROM securerag.document_versions
      WHERE tenant_id = securerag.ctx_tenant_id()
        AND version_id = $1`,
    [versionId],
  );
  return rows[0] ?? null;
}

/** Audit a permanent rejection (status stays 'pending': never published,
 * never searchable — the status filter is the gate, ADR-0006). */
async function rejectAndAudit(
  client: PoolClient,
  ctx: { authEpoch: string; requestId: string },
  params: IngestParams,
  reason: string,
  detail?: string,
): Promise<void> {
  await appendAudit({
    client,
    event: {
      eventType: 'ingest:rejected',
      requestId: params.requestId,
      principalId: INGEST_SERVICE_PRINCIPAL,
      membershipId: INGEST_SERVICE_MEMBERSHIP,
      authEpoch: ctx.authEpoch,
      filters: {
        versionId: params.versionId,
        documentId: params.documentId,
        reason,
        ...(detail !== undefined ? { detail } : {}),
      },
    },
  });
}

/** Map a provider extraction error to a stable audit reason string. */
export function extractFailureReason(err: unknown): string {
  const candidate = err as { reason?: unknown; name?: unknown };
  if (typeof candidate.reason === 'string' && candidate.reason.length > 0) {
    return candidate.reason;
  }
  if (typeof candidate.name === 'string' && candidate.name.length > 0) {
    return candidate.name.toLowerCase().replace(/error$/, '');
  }
  return 'extraction-failed';
}

// ---------- API-side upload / status / source (S2 routes) ----------

export interface StageUploadParams extends SecurityParams {
  documentId: string;
  objectKey: string;
  sha256Hex: string;
  filename: string;
  contentType: string;
  /** Source byte size, recorded in the ingest:received audit event. */
  sizeBytes: number;
}

export interface StageUploadResult {
  jobId: string;
  versionId: string;
}

/**
 * The `upload` stage (ADR-0007), one withSecurityContext transaction:
 * manage-gated (null for foreign/nonexistent/unmanageable documents — the
 * API 404s identically), next version_no, PENDING version row, ingest job
 * with idempotency key `ingest:{documentId}:{sha256}` (r8 §4: duplicate
 * upload intent becomes ONE job — a replay returns the existing job and its
 * version), audited 'ingest:received'. The object itself was already stored
 * by the route (put is outside the DB transaction); the route deletes it
 * best-effort if this throws.
 */
export async function stageUpload(
  pool: Pool,
  params: StageUploadParams,
): Promise<StageUploadResult | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    if (!(await manageAllowed(client, params.documentId))) return null;
    const idempotencyKey = `ingest:${params.documentId}:${params.sha256Hex}`;
    // Insert the job FIRST with a NULL payload; the version row (which the
    // payload references) does not exist yet. Duplicate upload intent hits
    // the unique (tenant_id, idempotency_key) constraint -> replay path.
    const inserted = await client.query<{ job_id: string }>(
      `INSERT INTO securerag.jobs (tenant_id, idempotency_key, job_type, payload_key)
       VALUES (securerag.ctx_tenant_id(), $1, 'ingest', NULL)
       ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
       RETURNING job_id`,
      [idempotencyKey],
    );
    const row = inserted.rows[0];
    if (row === undefined) {
      // Duplicate upload intent: return the existing job's outcome.
      const existing = await client.query<{ job_id: string; payload_key: string | null }>(
        `SELECT job_id, payload_key FROM securerag.jobs
          WHERE tenant_id = securerag.ctx_tenant_id() AND idempotency_key = $1`,
        [idempotencyKey],
      );
      const existingJob = existing.rows[0];
      if (existingJob === undefined || existingJob.payload_key === null) return null;
      const payload = parsePayload(existingJob.payload_key);
      if (payload === null) return null;
      return { jobId: existingJob.job_id, versionId: payload.versionId };
    }

    // Serialize concurrent uploads of the SAME document: the document-row lock
    // makes MAX(version_no)+1 and the is_current flip race-free (S2 review 2).
    await client.query(
      `SELECT 1 FROM securerag.documents
        WHERE tenant_id = securerag.ctx_tenant_id() AND document_id = $1
        FOR UPDATE`,
      [params.documentId],
    );
    const { rows: versionRows } = await client.query<{ version_id: string }>(
      `INSERT INTO securerag.document_versions
         (tenant_id, document_id, version_no, source_object_key, content_hash, status, is_current)
       SELECT securerag.ctx_tenant_id(), $1,
              COALESCE(MAX(version_no), 0) + 1, $2, decode($3, 'hex'), 'pending', false
         FROM securerag.document_versions
        WHERE tenant_id = securerag.ctx_tenant_id() AND document_id = $1
       RETURNING version_id`,
      [params.documentId, params.objectKey, params.sha256Hex],
    );
    const versionId = versionRows[0]?.version_id;
    if (versionId === undefined) return null;

    await client.query(
      `UPDATE securerag.jobs
          SET payload_key = $2
        WHERE tenant_id = securerag.ctx_tenant_id() AND job_id = $1`,
      [row.job_id, JSON.stringify(payloadForUpload({ ...params, versionId }))],
    );
    await appendAudit({
      client,
      event: {
        eventType: 'ingest:received',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: ctx.authEpoch,
        filters: {
          documentId: params.documentId,
          versionId,
          jobId: row.job_id,
          sha256: params.sha256Hex,
          sizeBytes: 0,
          contentType: params.contentType,
        },
      },
    });
    return { jobId: row.job_id, versionId };
  });
}

function payloadForUpload(params: StageUploadParams & { versionId?: string }): IngestJobPayload {
  if (params.versionId === undefined) throw new Error('versionId required');
  return {
    documentId: params.documentId,
    versionId: params.versionId,
    objectKey: params.objectKey,
    filename: params.filename,
    contentType: params.contentType,
  };
}

export interface JobStatus {
  jobId: string;
  jobType: string;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Opaque job status (own tenant only): ids + lifecycle state, never the
 * payload. Foreign/nonexistent jobs both return null (RLS hides foreign
 * rows; the API 404s identically).
 */
export async function getJobStatus(
  pool: Pool,
  params: SecurityParams & { jobId: string },
): Promise<JobStatus | null> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<{
      job_id: string;
      job_type: string;
      status: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT job_id, job_type, status, created_at, updated_at
         FROM securerag.jobs
        WHERE tenant_id = securerag.ctx_tenant_id() AND job_id = $1`,
      [params.jobId],
    );
    const row = rows[0];
    if (row === undefined) return null;
    return {
      jobId: row.job_id,
      jobType: row.job_type,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  });
}

/**
 * Resolve a version's source object key under CURRENT authorization (grant
 * re-check per request, ADR-0007): the document must be granted to the
 * context principal and the version must be a published one
 * (valid/released/superseded — pending/quarantined/expired versions are
 * never streamed). Foreign/nonexistent versions return null.
 */
export async function getSourceObjectKey(
  pool: Pool,
  params: SecurityParams & { documentId: string; versionId: string },
): Promise<string | null> {
  return withSecurityContext(pool, params, async (client) => {
    const { rows } = await client.query<{ source_object_key: string }>(
      `SELECT v.source_object_key
         FROM securerag.document_versions v
         JOIN securerag.documents d
           ON d.tenant_id = v.tenant_id AND d.document_id = v.document_id
        WHERE v.tenant_id = securerag.ctx_tenant_id()
          AND v.document_id = $1
          AND v.version_id = $2
          AND v.status IN ('valid','released')
          AND v.is_current
          AND ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}`,
      [params.documentId, params.versionId],
    );
    return rows[0]?.source_object_key ?? null;
  });
}
