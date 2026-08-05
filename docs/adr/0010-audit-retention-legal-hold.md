# ADR 0010 — Audit, retention, legal hold (D8)

- Status: accepted
- Date: 2026-08-05

## Decision

- **Audit events**: append-only table(s). API/general worker roles have no UPDATE/DELETE/TRUNCATE.
  RLS isolates tenant audit readers to their own tenant. Events cover allowed, denied, failed, and
  refused retrieval/lifecycle decisions.
  - Fields: request/trace id; tenant; principal; membership/auth epoch; redacted query + hash;
    filters; accessible candidate ids + lexical/vector/fused scores; selected version/chunk ids;
    policy/detector/parser/prompt/retrieval/model versions; evidence decision; model-call status;
    citations; refusal/error reason; latency/cost; answer hash.
  - Never record: inaccessible candidate ids/content, raw secrets, raw PII, auth tokens, raw
    source, full unredacted prompts.
- **Tamper evidence**: per-tenant hash chain over audit events (prev-hash linkage); WORM export
  format documented and testable.
- **Retention policy** (per tenant): separate rules for sources, versions/derived data,
  query/audit metadata, deletion grace days, legal hold flag.
- **Expiry**: content immediately becomes non-retrievable (RLS visibility), then an idempotent
  purge worker (narrow `securerag_purge` role) removes objects, extracted text, chunks,
  FTS/vectors, previews, prompts, temporary files, jobs, and cache within a documented SLA.
- **Legal hold** blocks destructive purge; audit keeps only a minimal redacted tombstone under its
  own policy. Deletion completion proves every storage class handled. Backup/PITR retention and
  restore behavior documented honestly (PITR may resurrect deleted objects until backup expiry).

## Consequences

- Runtime roles can write audit but never rewrite history; retention purge is provable per storage
  class; legal hold is an explicit, tested override.
