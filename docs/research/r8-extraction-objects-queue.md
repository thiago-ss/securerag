# R8 — Document Ingestion: Extraction Adapters, Malware Scan Gate, Encrypted Object Storage, PostgreSQL Job Queue

Status: research (Aug 2026), primary sources only. No code. Feeds ADR for ingestion pipeline (ADR 0003+) and the explicit document-types/sizes/parser-limits/OCR section the goal requires.

---

## 1. Extraction adapter recommendations

All adapters run in the `worker` process. Extracted text is untrusted input to everything downstream (prompt-injection detection, embeddings) — parse defensively and declare limits explicitly.

### PDF — `pdfjs-dist` (Mozilla PDF.js)

- **Recommendation**: `pdfjs-dist` directly (npm `pdfjs-dist`, currently **6.2.108**, published 2026-07-28).
- **License**: Apache-2.0 (Mozilla PDF.js; `mozilla/pdf.js` repo, pushed 2026-08-04, ~53.7k stars — actively maintained, monthly releases).
- **Engines**: `>=22.13.0 || >=24` (Node 22+ required — fine for the worker).
- **API**: `getDocument({ data })` → `page.getTextContent()` (text items + `str` fields). Node text extraction uses the `pdfjs-dist/legacy/build/pdf.mjs` entry (legacy build verified present in 6.2.108). No worker/`DOMMatrix` gymnastics needed for `getTextContent`.
- **Why not pdf-parse**: the original `pdf-parse` (kevinschaich, MIT, wraps pdf.js 1.x) is abandoned — its repo now 404s. The npm name is currently held by a TypeScript rewrite (`pdf-parse@2.4.5`, Apache-2.0, single maintainer mehmet-kozan, 211 stars, depends on **`@napi-rs/canvas` native binary** and an old `pdfjs-dist@5.4.296`, Node `>=20.16.0 <21 || >=22.3.0`). Native dep + small maintainer bus + lagging pdf.js → supply-chain and maintenance risk for zero API gain. Skip it.
- **Limits (explicit, tested)**: PDF is a container format with decompression-bomb and resource-exhaustion surface. Enforce before/while parsing: max file size (e.g. 50 MB), max pages (e.g. 1,000), max extracted text length (e.g. 10 MB), hard worker-side parse timeout (e.g. 60 s). `getTextContent()` throws on malformed/encrypted PDFs — catch, classify, emit structured `parse_failed` result, never crash the worker.
- **Sandboxing**: pdf.js is JS; the real resource risk is CPU/memory from hostile streams. For v1: worker subprocess isolation + limits above. If measured evidence later demands it, move extraction to a separate container.

### DOCX — `mammoth`

- **Recommendation**: `mammoth` (npm **1.12.0**, published 2026-03-12).
- **License**: BSD-2-Clause (`mwilliamson/mammoth.js`, pushed 2026-05-24, 6.3k stars). Single maintainer but the project is small, stable, and alive.
- **API**: `mammoth.extractRawText({ buffer })` — CJS, Node `>=12`. Docx-only (no legacy `.doc`).
- **Limits**: same max-size + timeout envelope as PDF. `extractRawText` on huge documents is CPU-bound; cap and timeout.

### Plain text / Markdown

- **Recommendation**: no library. Read bytes → decode with `TextDecoder('utf-8', { fatal: true })` (reject invalid UTF-8 rather than silently replacing), strip BOM, enforce max size (e.g. 10 MB) and max length.
- Markdown is ingested as plain text (v1 chunks are text; no markdown parsing).

### OCR — NOT needed for v1; explicit unsupported types instead

- **Decision**: OCR is out of scope for v1. Scanned/image-only PDFs (no text layer → empty `getTextContent()`) and image files are **explicitly unsupported**: return a structured `unsupported_document_type` result that names the reason ("no extractable text layer / OCR not supported"), never a silent empty ingestion.
- This satisfies the goal's requirement that OCR behavior be explicit: v1 declares OCR = unsupported, and the supported-type list + limits are tested invariants (adversarial suite probes unsupported types and expects deterministic, indistinguishable-safe rejection).
- **If needed later**: `tesseract.js` (Apache-2.0, v7.0.0, updated 2025-12) is the maintained wasm OCR option — but it ships multi-MB wasm + traineddata per language, is slow in JS, and needs real sandboxing. Requires an ADR before v2.

### Summary table (v1)

| Type | Adapter | License | Maintenance (Aug 2026) |
|---|---|---|---|
| PDF | `pdfjs-dist` 6.2.x | Apache-2.0 | Active (Mozilla, monthly releases) |
| DOCX | `mammoth` 1.12.x | BSD-2-Clause | Active (single maintainer, stable) |
| TXT / MD | none (stdlib decode) | — | — |
| Scanned PDF / images | unsupported (explicit) | — | OCR deferred; `tesseract.js` Apache-2.0 if later |

---

## 2. Malware scan gate (ClamAV)

### Deployment

- **Image**: `clamav/clamav` (official, Cisco-Talos). Pin a feature tag (`1.4` / `1.4_base` style); prefer `_base` + persistent volume for `/var/lib/clamav` to avoid re-downloading signatures. Container runs both `clamd` (TCP 3310) and `freshclam` by default.
- **RAM**: docs require ~3 GiB minimum, **4 GiB recommended**; ~2.4 GiB transient spike on signature reload (concurrent reload). Budget the worker host accordingly.
- **Exposure**: `clamd` TCP is **unencrypted and unauthenticated** — docs: "Extreme caution… all traffic is un-encrypted." Bind `TCPAddr` to the internal Docker network only; never publish 3310. Keep `EnableShutdownCommand no`.

### Protocol (clamd TCP, INSTREAM)

- Framed command `zINSTREAM\0` (NUL-terminated is recommended), then chunks: **4-byte big-endian length + bytes**, terminated by a zero-length chunk.
- Total stream must be ≤ `StreamMaxLength` (default 100M) or clamd replies `INSTREAM size limit exceeded`.
- Reply: `stream: OK` / `stream: <Signature> FOUND` / error. `PING`→`PONG` for health; `VERSIONCOMMANDS` to probe support.
- Node client: raw `net` socket, no package needed (or a thin wrapper kept in-repo).

### Config limits (clamd.conf.sample defaults)

| Option | Default | Note |
|---|---|---|
| `StreamMaxLength` | 100M | INSTREAM cap |
| `MaxFileSize` | 100M | larger files skipped as clean; 2 GB hard design limit |
| `MaxScanSize` | 400M | decompressed/container scanning budget |
| `MaxScanTime` | 120000 ms | scan duration cap (zip-oriented) |
| `MaxRecursion` / `MaxFiles` | 17 / 10000 | archive bomb guards |
| `ReadTimeout` / `CommandReadTimeout` | 120 s / 30 s | client-side timeouts |
| `AlertExceedsMax` | no | flag limit-exceeded as `Heuristics.Limits.Exceeded` — enable |

### Scan gate placement and timeouts

- Pipeline: **upload → object store (encrypted, content-addressed) → scan gate → extraction → chunk/embed → publish**. Scan before extraction so malicious payloads never touch the parser.
- Worker-level timeout (e.g. 60–90 s) around the INSTREAM call, shorter than clamd `ReadTimeout`; on timeout, fail the job with a bounded retry (queue recipe below) — a scanner outage must degrade ingestion, not block it silently.
- Verdict handling: `FOUND` → quarantine the object version (`rejected` state, object kept for audit or lifecycle-expired), audit event, no extraction. `OK` → proceed. Scanner error → retry with backoff; never treat scan errors as "clean".

### The honest limit (write this into the ADR)

- **AV is not a security boundary for tenant isolation — RLS is.** ClamAV sits inside the declared threat-model exclusions ("uploaded documents: malware, injection, PII") as defense-in-depth: it protects operators/hosts from hosting malware and other tenants' extracted malware re-entering the platform, and it catches known signatures at rest. A signature miss changes nothing about the isolation guarantee, which is deterministic SQL enforcement.
- Consequences: the scan gate is a quality/ops control, not a security invariant; its failure mode must be `INVALID` in the adversarial suite (per threat model: infrastructure failure is INVALID, never PASS).

---

## 3. MinIO encryption design (as of Aug 2026)

### Critical market note

- The open-source `minio/minio` GitHub repo now declares **"THIS REPOSITORY IS NO LONGER MAINTAINED"** (README, Feb 2026): community edition is source-only (`go install`), last binary release `RELEASE.2025-10-15T17-29-55Z` (Oct 2025); `minio/minio:latest` on Docker Hub last updated **2025-09-07**.
- Successor product: **MinIO AIStor** — "AIStor Free" (community, standalone, free license) and "AIStor Enterprise" (distributed, commercial). Docs moved to `docs.min.io/aistor/`.
- Implication for SecureRAG: keep "S3-compatible API" as the abstraction (ADR 0001 already does); pin the last `minio/minio` image for local demo, and evaluate AIStor Free / a real S3 provider for production. No code changes should ever depend on MinIO-only behavior.

### How SSE works (primary source)

- **Envelope encryption**: a master/external key lives in a key manager (never on MinIO disk); per object, MinIO asks the key manager for a unique data key, encrypts the object with it, stores only the encrypted data key in object metadata. Controlling the key manager = controlling the objects → secure lock/erase.
- **Key managers**: MinIO KMS (recommended, default for new deployments), **KES (legacy** — third-party KMS path, migrate to MinIO KMS), static key `MINIO_KMS_SECRET_KEY` (testing only, not production).
- **Encryption types**: **SSE-KMS** (recommended; bucket-default key or per-write key; granular, per-bucket keys) · **SSE-S3** (automatic encryption; **one external key for the entire deployment**) · SSE-C (client-supplied keys, requires TLS, client does key management — not for us).
- Once enabled: backend (IAM/config) is encrypted too, MinIO **cannot start without the key manager**, and SSE cannot be disabled/reset.

### Recommendation

- **SSE-S3 (automatic, bucket-default encryption) with MinIO KMS as the key manager, for v1.**
- Rationale: the goal asks for "encrypted object storage" — SSE-S3 gives automatic at-rest encryption of every object with zero per-request key plumbing; SSE-KMS's per-tenant key granularity buys nothing for v1 because tenant isolation is enforced by the application (RLS + IAM-scoped service account + unguessable content-addressed keys), not by object keys. `MINIO_KMS_SECRET_KEY` static key is explicitly "not for production" per docs — do not ship it.
- Upgrade path: SSE-KMS with per-tenant keys later (MinIO multi-tenancy best practice lists "per-tenant encryption keys with KMS integration") if a requirement appears (e.g. tenant-scoped crypto erase) — an ADR with measured need first.
- Operational notes for the runbook: startup requires KMS reachability; key loss = data loss (irreversible); batch key rotation exists (`mc admin kms key`); MinIO KMS itself must be a named dependency in compose.

### Presigned URLs — avoid for v1

- Presigned URLs embed credentials for anyone holding them and cannot be revoked before expiry (`mc share download` default expiry 168 h; S3 spec: bearer-capability until expiration). Risks: leakage via logs, referrers, browser history, copy-paste across tenants; a leaked presigned URL is a permanent-read bearer token that RLS never sees.
- Decision: **no permanent or long-lived public URLs ever** (matches threat model "no permanent public object URLs"); for v1, downloads/previews stream **through the API** (`GetObject` with the worker/API service account) after the RLS/authorization check — the DB is the gate, the object store never issues URLs. If a browser-direct flow is ever needed, short-TTL (≤ 60 s) presigned URLs generated server-side after authz, and never logged.

### Bucket-per-tenant vs prefix-per-tenant

- MinIO docs recommend IAM-based multi-tenancy: dedicated bucket per tenant + scoped policy (`arn:aws:s3:::tenant-alpha` and `arn:aws:s3:::tenant-alpha/*`), "supports thousands of tenants"; prefix-based sharing needs `s3:ListBucket` with `StringLike s3:prefix` conditions.
- **Recommendation for v1: one bucket, prefix-per-tenant** (`{tenant_id}/{sha256}` keys, section 5). Why safe here: keys are content-addressed and unguessable; the app service account gets `s3:GetObject`/`s3:PutObject` on the single bucket with no broad `ListBucket`; listing across tenants is impossible without ListBucket, and authorization is enforced in PostgreSQL before any key leaves the DB. S3 listing implication: if a listing feature is ever needed, it must be scoped by `prefix={tenant_id}/` under a narrowly-granted ListBucket with the `s3:prefix` condition, and its output treated as protected data. Bucket-per-tenant is the documented "recommended" pattern if per-tenant crypto keys/quotas/replication become requirements (ADR + measured need).

---

## 4. PostgreSQL job queue recipe

### Primary-source anchor (PG 18 docs)

- `SELECT ... FOR UPDATE ... SKIP LOCKED` (SQL docs, Locking Clause): with `SKIP LOCKED`, "any selected rows that cannot be immediately locked are skipped. Skipping locked rows provides an inconsistent view of the data, so this is not suitable for general purpose work, but can be used to avoid lock contention with multiple consumers accessing a queue-like table." Requires `UPDATE` privilege on selected tables.
- `NOTIFY`/`LISTEN`: wake-up channel; notifications deliver **only on commit**; payload is a string (not structured data — "higher-level mechanisms … pass additional data … using tables"). Use it only to wake workers, never to carry payload.

### Schema sketch

```sql
-- jobs table (tenant-owned; RLS forced; tenant_id in every key)
CREATE TABLE ingestion_jobs (
  tenant_id        uuid NOT NULL,
  id               bigint GENERATED ALWAYS AS IDENTITY,
  idempotency_key  text NOT NULL,          -- e.g. 'upload:' || version_id
  kind             text NOT NULL,          -- 'scan' | 'extract' | 'embed'
  payload          jsonb NOT NULL,         -- opaque IDs only, no content
  status           text NOT NULL DEFAULT 'pending',  -- pending|claimed|done|failed|dead
  attempts         int  NOT NULL DEFAULT 0,
  max_attempts     int  NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  claimed_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key)      -- idempotency guard
);
```

### Claim (atomic, SKIP LOCKED)

```sql
UPDATE ingestion_jobs j
SET status = 'claimed', claimed_by = $worker, attempts = j.attempts + 1
WHERE (j.tenant_id, j.id) IN (
  SELECT tenant_id, id FROM ingestion_jobs
  WHERE status = 'pending' AND next_attempt_at <= now()
  ORDER BY next_attempt_at, id
  FOR UPDATE SKIP LOCKED
  LIMIT $batch_size
)
RETURNING tenant_id, id, kind, payload;
```

Run inside a transaction that spans the whole job (claim → work → terminal state commit), so a crash rolls back the claim and the job is re-visible.

### Retry with exponential backoff + jitter

- On failure: `status='pending'`, `next_attempt_at = now() + base * 2^(attempts-1) + jitter` (e.g. base 30 s → 30s/60s/120s/240s/480s). On `attempts >= max_attempts`: `status='failed'` (or `dead`), audit event, alert.
- Distinguish retryable (scan timeout, S3 5xx, KMS outage) from permanent (parse failure, unsupported type, malware FOUND) — permanent failures go terminal immediately.

### Idempotency (at-least-once semantics)

- Delivery is **at-least-once**: a worker can crash after doing work but before commit, so any job may execute twice. Workers must be idempotent:
  - **Enqueue**: unique constraint `(tenant_id, idempotency_key)`; enqueue with `ON CONFLICT DO NOTHING` / ignore dup error — duplicate upload intent becomes one job.
  - **Execute**: before applying side effects, check outcome rows (e.g. `document_versions.sha256` already stored, `chunks` exist for that version) and skip if present; write outcomes in the same transaction as the job's terminal status; never perform side effects before the side-effect transaction commits.
  - Replays then converge: second run observes the outcome and no-ops.
- Poison jobs (repeated failure of the same key) are bounded by `max_attempts` + backoff; a poison-queue alarm comes from `failed`/`dead` counts.

### Why no Redis for v1

- ADR 0001: "No Redis unless measured evidence and an ADR justify it." PostgreSQL is already the security kernel and is in every data path; a second store adds a new failure/consistency domain, cross-tenant caching surface, and ops burden. At the target envelope (100 tenants, 1M chunks, 25 req/s) a single PG queue with SKIP LOCKED comfortably handles ingestion throughput. Revisit only with measured saturation evidence.
- Wake-ups: `NOTIFY ingestion_ready` on enqueue (committed transaction); workers also poll on a short timer as ground truth (NOTIFY is not guaranteed-delivery; SKIP LOCKED claim is the only authoritative read).

### Worker security context (non-negotiable)

- Job rows carry only opaque IDs (`tenant_id` + id + object key + version id) — **no document content in the payload** (threat model: "cross-tenant dispatch shows only opaque IDs").
- The worker **re-enters the tenant security context before reading anything**: same two-stage bootstrap as the API — verify the tenant's existence/membership transaction-locally, then `set_config('tenant.id', ..., true)` (transaction-local, parameterized), then read the object/payload through RLS-enforced SQL. A worker must never act on a job using ambient/global state, and must never trust job payload for authorization — the DB is the authority (core invariant: the LLM never decides authorization; neither does the queue).

---

## 5. Object naming scheme

- **Key format**: `{tenant_id}/{sha256-hex-of-bytes}` — e.g. `0189abcd-ef01-…/3f7b…c9a2`.
  - Content-addressed (sha256 of the exact bytes) gives: **immutability** (any byte change → new key; fits "immutable, versioned documents"), **automatic dedup** (identical uploads across tenants share one object — acceptable and desirable; the app still records per-tenant version rows), and **unguessable keys** (no enumeration; protects against listing-based leaks even if ListBucket were mis-granted).
- **Tenant prefix first** so prefix-scoped IAM policies and lifecycle rules can be expressed; no per-tenant bucket in v1 (section 3).
- **Never put the original filename or extension in the key** (path-traversal/sniffing surface, tenant-visible naming leaks). Store `original_filename`, `mime_type` (server-detected, never client-supplied), `size_bytes`, `sha256`, `page_count` etc. in object metadata (`x-amz-meta-*`) and in the DB version row.
- **Write path**: bytes → sha256 → key; upload once (`PutObject`); a second upload of identical bytes is the same key (idempotent). Versioning on the bucket is optional given content-addressing (a new version is a new key); keep bucket versioning enabled anyway as a safety net and to satisfy any legal-hold flows.
- **Deletion**: never in-place overwrite; deletion flows go through lifecycle policies or the narrow purge role (legal hold must block it) — mirroring the audit/retention design in CONTEXT.md.

---

## Sources (exact URLs)

**Extraction**
- https://registry.npmjs.org/pdfjs-dist — 6.2.108, Apache-2.0, engines node >=22.13 (checked 2026-08-05)
- https://github.com/mozilla/pdf.js — Apache-2.0, pushed 2026-08-04, 53.7k stars
- https://registry.npmjs.org/pdf-parse — 2.4.5, Apache-2.0, repo git+https://github.com/mehmet-kozan/pdf-parse.git, deps pdfjs-dist 5.4.296 + @napi-rs/canvas 0.1.80
- https://github.com/mehmet-kozan/pdf-parse — pushed 2026-05-04, 211 stars, "Pure TypeScript … PDFs"
- https://registry.npmjs.org/mammoth — 1.12.0, BSD-2-Clause, modified 2026-03-12
- https://github.com/mwilliamson/mammoth.js — BSD-2-Clause, pushed 2026-05-24, 6.3k stars
- https://registry.npmjs.org/tesseract.js — 7.0.0, Apache-2.0, modified 2025-12-15 (future OCR option)

**Malware scan**
- https://docs.clamav.net/manual/Installing/Docker.html — image tags, RAM (3 GiB min / 4 GiB preferred), TCP 3310, unencrypted-TCP warning, freshclam/clamd env controls
- https://docs.clamav.net/manual/Usage/Scanning.html — clamd/clamdscan, TCP mode streams contents (INSTREAM), `--stream` semantics
- https://raw.githubusercontent.com/Cisco-Talos/clamav/main/etc/clamd.conf.sample — defaults: StreamMaxLength 100M, MaxFileSize 100M (2 GB design limit), MaxScanSize 400M, MaxScanTime 120000, MaxRecursion 17, MaxFiles 10000, ReadTimeout 120, CommandReadTimeout 30, AlertExceedsMax
- https://docs.clamav.net/print.html (ClamD Protocol chapter) — zINSTREAM framing, 4-byte BE chunk lengths, zero-chunk terminator, `INSTREAM size limit exceeded`, VERSIONCOMMANDS, IDSESSION, TCP limits; "clamd … not encrypted or authenticated … do not expose a TCP socket to untrusted networks"

**MinIO / AIStor**
- https://raw.githubusercontent.com/minio/minio/master/README.md — "THIS REPOSITORY IS NO LONGER MAINTAINED", source-only community edition, AIStor Free/Enterprise alternatives (verified 2026-08-05)
- https://github.com/minio/minio/releases — last release RELEASE.2025-10-15T17-29-55Z
- https://hub.docker.com/v2/repositories/minio/minio/tags/ — `latest` last updated 2025-09-07
- https://min.io/download — AIStor Free ($0, standalone) / AIStor Enterprise trial
- https://docs.min.io/aistor/installation/linux/server-side-encryption/ — envelope encryption (master key in key manager, per-object data key, encrypted DEK in metadata), key-manager choices (MinIO KMS recommended / KES legacy / static key testing-only), SSE-KMS (recommended) vs SSE-S3 (one deployment-wide key) vs SSE-C (TLS required), backend encryption irreversible, startup requires key manager
- https://docs.min.io/aistor/installation/linux/server-side-encryption/aistor-keymanager/ — MinIO KMS env (`MINIO_KMS_SERVER`, `MINIO_KMS_SSE_KEY`, `MINIO_KMS_ENCLAVE`, `MINIO_KMS_API_KEY`), `mc encrypt set sse-kms`
- https://docs.min.io/aistor/installation/linux/server-side-encryption/minio-key-encryption-service/ — KES marked legacy; migrate without re-encryption
- https://docs.min.io/aistor/administration/multi-tenancy/ — IAM-based multi-tenancy recommended (bucket-per-tenant policies), prefix-based variant with `s3:prefix` condition, "per-tenant encryption keys with KMS integration" best practice
- https://docs.min.io/aistor/reference/cli/mc-share/mc-share-download/ — presigned URL semantics, default expiry 168 h

**PostgreSQL queue**
- https://www.postgresql.org/docs/current/sql-select.html — Locking Clause: FOR UPDATE … SKIP LOCKED ("…skipping locked rows … can be used to avoid lock contention with multiple consumers accessing a queue-like table"), UPDATE privilege requirement; docs confirm current = PG 18, PG 19 beta (2026-07-16)
- https://www.postgresql.org/docs/current/sql-notify.html — NOTIFY delivers on commit, payload string limits, table-based payload passing pattern
