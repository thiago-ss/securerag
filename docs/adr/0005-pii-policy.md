# ADR 0005 — PII engine and policy (D3)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r5-pii-redaction.md, NIST SP 800-122

## Decision

- **v1 PII classes** (deterministic, NIST SP 800-122-aligned): `EMAIL`, `PHONE`, `SSN`,
  `CREDIT_CARD` (Luhn-verified). Tenant-configurable enablement per class.
- **Detectors**: pure TypeScript deterministic detectors behind the `pii-detector` provider seam
  (`email-regex`, `libphonenumber-js`, own SSN regex, `card-validator` Luhn). No Python Presidio
  sidecar in v1 (extra runtime/attack surface; NER classes not needed). At least one documented
  real adapter per required capability — here the deterministic detectors ARE production adapters;
  a future NER adapter (worker-side transformers) is documented in the provider contract.
- **Redaction model**: replacement class tokens (`[EMAIL]`, `[PHONE]`, `[SSN]`, `[CREDIT_CARD]`) —
  one-way, preserves retrieval alignment. Uniform masking as a tenant policy variant. Hashing
  rejected (destroys embeddings, enables cross-document linkage).
- **Pipeline placement** (all before downstream exposure): source content pre-chunk; metadata;
  filename; query before any provider payload; generated answer post-check (defense-in-depth).
  Only redacted derivatives enter embeddings, provider/model payloads, normal logs, traces,
  metrics, errors, exports, and tenant audit views.
- **`pii:read`**: a principal capability (grant) that allows viewing original (unredacted) text on
  human surfaces (preview/source/export) for documents the principal is otherwise authorized to
  read. The model/provider context NEVER receives unredacted text, even for `pii:read` principals.
- No reversible replacement maps in v1; redaction is one-way.

## Consequences

- Embeddings and provider payloads are safe-by-construction; `pii:read` widens only human
  surfaces; leakage of raw PII into logs/audit is a test-failing defect.
