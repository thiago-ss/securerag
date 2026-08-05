# ADR 0007 — Object encryption and ingestion pipeline (D5)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r8-extraction-objects-queue.md

## Decision

- **Objects**: one S3-compatible bucket; prefix-per-tenant (`tenant-{id}/`); content-addressed,
  immutable keys (`{prefix}/{version_sha256}/{filename}`); SSE-S3 automatic bucket-default
  encryption (MinIO KMS as key manager in demo; production KMS adapter documented). No broad
  `ListBucket`. **No presigned or permanent public URLs** — object reads stream through an
  authorized API route that re-checks RLS/grants per request. MinIO image pinned (OSS repo
  unmaintained; successor AIStor noted in ops docs).
- **Pipeline** (each stage bounded, idempotent, versioned, audited):

  `upload -> validate (type/size/limits) -> malware scan -> encrypted immutable source ->
   extract -> injection scan -> PII detect/redact -> chunk -> FTS/embed -> verify ->
   atomic publish`

  - Limits: 50 MB, 1k pages, 10 MB extracted text, 60 s parse timeout; worker subprocess isolation.
  - Extraction: `pdfjs-dist` 6.2.x (PDF, Apache-2.0), `mammoth` 1.12.x (DOCX, BSD-2-Clause),
    UTF-8 text/Markdown. **OCR is not in v1**; scanned PDFs/images are explicitly unsupported
    types with structured rejection.
  - Malware: ClamAV (`clamav/clamav` container, clamd TCP) with timeout; documented honest
    limitation — AV is not the RAG security boundary.
  - A new current version publishes atomically only after ALL stages succeed; failed/quarantined
    versions never become searchable.
- **Queue**: PostgreSQL-backed; claim via `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED
  LIMIT n) RETURNING *` in a job transaction; retries `30s·2^(n-1)` + jitter, `max_attempts=5`,
  permanent vs retryable split; idempotency keys unique `(tenant_id, idempotency_key)` with
  terminal-state outcome rows in the same transaction; `NOTIFY` wakeups. No Redis in v1. Workers
  re-enter verified tenant security context before reading any payload/object; cross-tenant
  dispatch exposes only opaque job id, tenant id, schedule, state.

## Consequences

- Immutable sources + content-addressed keys make "verified deletion" enumerable across storage
  classes; no public URL surface exists at all.
