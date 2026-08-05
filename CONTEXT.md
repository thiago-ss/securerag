# SecureRAG — Context, Domain, and Security Invariants

Version: 0.x (construction). See `docs/` for threat model, ADRs, and the implementation graph.

## Mission

SecureRAG is a shared RAG (retrieval-augmented generation) knowledge platform for multiple companies.
A tenant may retrieve only information authorized for the authenticated principal inside that tenant.
No tenant may retrieve, infer, cite, preview, stream, export, log, audit, cache, or send to a model
another tenant's protected information.

Security is enforced by deterministic identity, authorization, database, and output controls.
**The LLM never decides authorization.**

## Product capabilities

1. PostgreSQL row-level security on every tenant-owned table.
2. Default-deny document permissions for users, groups, and tenant roles.
3. Hybrid semantic and PostgreSQL full-text retrieval.
4. Exact, resolvable citations.
5. Immutable, versioned documents.
6. Direct and indirect prompt-injection detection and quarantine/refusal.
7. Configurable PII detection/redaction before embedding, generation, logs, and audit views.
8. Tenant-configurable retention, legal hold, and verified deletion across derived data.
9. Complete, tenant-isolated retrieval audit trail.
10. Deterministic refusal when authorized evidence is insufficient or conflicting.
11. Adversarial test suite with zero observed unauthorized disclosures across at least 1,200 unique
    end-to-end attack queries as the v1 release gate.

## Ubiquitous language

Use these terms consistently everywhere (code, schema, docs, tests, UI). Do not overload
"user", "account", "organization", "source", "version", or "permission".

- **Tenant**: one company's hard isolation boundary.
- **Principal**: authenticated human or service identity.
- **Tenant Membership**: principal's active association and role in one tenant.
- **Group**: tenant-local set of principals used by permissions.
- **Document**: stable logical knowledge item.
- **Document Version**: immutable source snapshot; one published current version per active document.
- **Chunk**: immutable, redacted retrieval unit tied to one exact version.
- **Document Grant**: allow-only `read`, `write`, or `manage` capability for one principal, group, or
  approved tenant role. Default deny.
- **Retrieval Run**: authenticated question plus immutable identity, policy, and retrieval
  configuration snapshot.
- **Evidence Bundle**: authorized chunks allowed to enter answer generation.
- **Citation**: exact document/version/chunk/span reference supporting a material claim.
- **Audit Event**: immutable security metadata for one authorization, retrieval, lifecycle, refusal,
  or disclosure decision.
- **Retention Policy**: tenant lifecycle rules for source, derived data, and audit metadata.
- **Authorization Epoch**: monotonic version changed by membership, group, grant, document, or
  retention decisions; used to prevent stale disclosure.

## Core authorization invariant

For principal `P` at disclosure time `T`, every retrieved chunk, model-bound fact, generated fact,
citation, title, filename, identifier, URL, count, facet, audit record, cache entry, log/trace field,
stream frame, download, preview, and export must derive only from:

```
Allowed(P,T) = same tenant
             ∩ active membership
             ∩ document grant
             ∩ visible document/version
             ∩ unexpired retention
             ∩ permitted PII scope
```

- Default deny. Missing, malformed, expired, stale, or conflicting security context returns no
  protected data.
- A foreign and nonexistent resource must have indistinguishable safe status/schema behavior.
- Any unauthorized content or identifier entering a model/provider payload is already a security
  disclosure even when the final answer hides it.

## Truthful security claim

The product goal states companies "can never retrieve each other's information." That is implemented
as a hard data-plane invariant inside the declared threat model (`docs/threat-model.md`), then proven
aggressively on the tested build. A finite test is never marketed as mathematical proof.

Release language must be:

> Zero observed unauthorized disclosures in N executed adversarial queries for commit SHA, image
> digest, migrations, configuration, model/provider versions, corpus manifest, and seeds listed in
> the report.

Never say "zero risk", "formally proven secure", or claim SOC 2, ISO 27001, HIPAA, GDPR, FedRAMP, or
other certification without a real audit and authorization.

## Hard architectural invariants (summary)

Full detail in the goal graph and ADRs; enforced by tests, never by convention:

- Every tenant-owned row has non-null `tenant_id`; every tenant-data PK/unique/FK includes `tenant_id`.
- Every tenant table has `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`; runtime roles
  are `NOSUPERUSER`, `NOBYPASSRLS`, non-owners, without audit mutation.
- Two-stage bootstrap: verify OIDC principal transaction-locally (membership-scoped policy only),
  then establish full verified tenant/membership/request/authorization-epoch context via
  parameterized `set_config(..., true)`. Never session-level settings.
- Authorization executes inside SQL before any text, embedding, metadata, rank, count, or ID leaves
  PostgreSQL.
- Default private. Allow-only grants. One ACL governs all retained versions of a document.
- Only redacted derivatives enter embeddings, provider payloads, normal logs, tenant audit views.
- Retrieved text is untrusted data; detection is defense-in-depth, never authorization.
- Answer model has no general tools; retrieved content cannot alter filters, scope, or citation IDs.
- Audit events are insert-only for the runtime role; a separate narrow role handles proven-expired
  retention purge and legal hold blocks it.
