# SecureRAG — Declared Threat Model

Version: 0.x. Reviewed at every phase; final release must include the sanitized version.

## Scope and spirit

This threat model defines the adversary classes SecureRAG defends against and what is explicitly
outside the application's control. It is the contract for the adversarial evaluation suite
(`docs/graph-and-acceptance.md`). Platform operators and tenant administrators receive no implicit
document-content access. Any break-glass capability is out of v1 unless separately specified,
narrowly authorized, time-bound, and fully audited.

## Adversaries

- **Malicious tenants** attempting to read, infer, enumerate, or exfiltrate another tenant's data.
- **Malicious users / principals** inside a tenant attempting to read beyond their grants, history
  capability, retention expiry, or PII scope, or to escalate tenant role.
- **Malicious tenant admins**: manage membership and policy but must not automatically read document
  content.
- **Malicious service principals** (jobs, integrations) attempting unauthorized dispatch, payload
  access, or audit tampering.
- **Uploaded documents**: crafted content, metadata, or filenames (malware, injection, PII).
- **Malicious prompts**: direct/indirect prompt injection, RAG poisoning, query expansion attacks,
  reranker attacks, citation attacks, multi-turn exfiltration.
- **Untrusted route/header/body values**: forged tenant/document/version/chunk IDs, forged or stale
  claims, malformed types, oversized inputs.
- **Stale state**: stale membership, ACL, document, version, session, job, and cache state that
  could disclose after revocation/expiry.
- **Side-channel surfaces**: error messages, counts, timing, constraint violations, URLs, filenames,
  titles, facets, stream frames, audit views, logs, traces, metrics, exports, previews, downloads.

## Attack surfaces enforced

- REST/OpenAPI boundary (input validation, indistinguishable foreign/nonexistent behavior).
- Real PostgreSQL queried as the actual least-privileged runtime role (RLS enforced, never mocked).
- Public retrieval pipeline with independent auth oracle and model/provider spy.
- Browser critical paths (Playwright) incl. DOM, downloads, errors, refusal states.
- OCI image health/readiness and migration/rollback boundary.
- Object storage (encrypted at rest; no permanent public object URLs).
- Job queue (cross-tenant dispatch shows only opaque IDs; workers re-enter verified context).

## Explicit exclusions

Total compromise of the following trusted infrastructure is excluded from the application-code
guarantee (mitigated operationally, never pretended away):

- PostgreSQL database superuser.
- KMS / root encryption keys.
- Host root / container runtime escape.
- OIDC signing keys / identity provider compromise.
- An approved model/provider endpoint (trusted under contractual terms).

Operational mitigations (documented, exercised in runbooks, not represented as app-level proofs):
least privilege, secret management, encryption, egress controls, audit, rotation, backups, incident
runbooks.

## Defense-in-depth policy

- Retrieval and authorization are deterministic and database-enforced; the LLM never decides
  authorization.
- Prompt-injection detection, PII redaction, and refusal are defense-in-depth layers. A detector
  miss must not weaken tenant/ACL enforcement.
- A security event in the adversarial suite fails the run; infrastructure failure is `INVALID`,
  never `PASS`.
