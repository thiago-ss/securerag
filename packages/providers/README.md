# @securerag/providers

Provider seams and deterministic adapters for SecureRAG (ADR-0007, r8).

## Extraction (`src/extraction.ts`)

| Type | Adapter | Library | License |
|---|---|---|---|
| PDF | `PdfExtractor` | `pdfjs-dist` 6.2.x (legacy build) | Apache-2.0 |
| DOCX | `DocxExtractor` | `mammoth` 1.12.x | BSD-2-Clause |
| TXT / MD | `TextExtractor` | stdlib UTF-8 decode (`fatal: true`) | — |

Limits (ADR-0007): **50 MB** input, **1 000 pages**, **10 MB** extracted text,
**60 s** parse timeout. Violations are typed errors
(`SizeLimitError` / `PageLimitError` / `TextSizeLimitError` /
`ExtractionTimeoutError`) so the pipeline classifies deterministically.

**OCR is not in v1.** Scanned/image-only PDFs (empty text layer) and every
other unsupported type produce `UnsupportedTypeError` naming the reason —
never a silent empty ingestion (r8 §1). Extracted text is untrusted input to
everything downstream; the worker subprocess isolation is the resource
backstop, the timeout the deterministic job-level bound.

## Malware scan gate (`src/malware.ts`)

Contract: `MalwareScanner.scan(buffer): Promise<ScanVerdict>` with
`'clean' | 'infected' | 'error'`. The scan runs BEFORE extraction so
malicious payloads never touch the parser.

- `DeterministicFakeMalwareScanner` — CI/demo: infected iff the buffer
  contains the marker (default EICAR). Deterministic, no network.
- `ClamavClamdAdapter` — real ClamAV via clamd TCP (`zINSTREAM` framing,
  r8 §2). **Container-gated**: the worker builds it only when `CLAMAV_HOST`
  is set; CI never exercises it without the container. clamd is
  unencrypted/unauthenticated — bind it to an internal network only, never
  publish port 3310.

Verdict semantics: `infected` → permanent rejection (never a retry);
`error` → retryable backoff; a scan error is **never** treated as clean.

### The honest limitation

**AV is not the RAG security boundary — RLS is.** ClamAV is defense-in-depth
protecting operators/hosts from hosted malware and cross-tenant malware
re-entry; a signature miss changes nothing about the tenant-isolation
guarantee, which is deterministic SQL enforcement. The scan gate is a
quality/ops control, not a security invariant (threat model: scanner failure
is `INVALID` in the adversarial suite, never `PASS`).
