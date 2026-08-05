# ADR 0003 — RLS and ACL semantics (D1)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r1-postgres-rls.md, r4-hybrid-retrieval.md

## Decision

**Roles** (all in one database `securerag`):
- `securerag_migration` — ephemeral DDL role; owns no tenant data; used only by migration tooling.
- `securerag_owner` — `NOLOGIN`; owns tenant tables, views, functions. Never a runtime role.
- `securerag_api`, `securerag_worker` — runtime roles: `NOSUPERUSER`, `NOBYPASSRLS`, non-owners, no
  DDL, no `TRUNCATE`, no `REFERENCES`, no audit-table mutation, no unrestricted `SET ROLE`, no broad
  schema privileges.
- `securerag_audit_retention` — narrow: may delete only audit rows proven expired and not held.
- `securerag_purge` — narrow: may delete only expired derived data/objects. General roles never get
  bypass access.

**Two-stage bootstrap** (in `packages/security`):
1. `withIdentityContext(fn)`: sets only the verified OIDC principal transaction-locally
   (`set_config('securerag.principal_id', $1, true)`); may read only that principal's own active
   membership metadata through a principal-scoped RLS policy. A requested tenant is an untrusted
   candidate, never authority.
2. `withSecurityContext(tenantId, fn)`: after an active membership is found, begins the protected
   transaction, sets tenant, principal, membership, request id, and authorization epoch via
   parameterized `set_config(..., true)`, verifies them, runs `fn`, and commits/rolls back without
   exposing the pooled client.
- Never session-level settings. Missing/malformed context → zero rows or safe generic error.

**Every tenant table**: non-null `tenant_id`; PK/unique/FK include `tenant_id` (no cross-tenant
references structurally); `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`; policies are
restrictive, combined with AND semantics (never permissive OR that weakens isolation); explicit
`USING` (read) and `WITH CHECK` (write).
- Constraint checks/`REFERENCES`/`TRUNCATE` bypass RLS → composite tenant keys + generic external
  errors + explicit enumeration/covert-channel tests.
- Views over protected tables use `security_invoker`. No `SECURITY DEFINER` without dedicated ADR +
  exploit tests.

**Authorization epoch**: monotonic value bumped by membership, group, grant, document, or retention
decisions; carried in the verified context; rechecked immediately before the first response byte.

## Amendment 2026-08-05 — single-policy-per-table invariant (PostgreSQL 18.4 bug workaround)

Reproduced on stock `postgres:18.4` and `pgvector/pgvector:0.8.6-pg18`: a table with
`AS RESTRICTIVE` policies returns **zero rows for non-superusers even with
`USING (true)`**; permissive policies behave correctly. This is an upstream
PostgreSQL 18.4 defect (plan-time folding of restrictive security quals to false).

Workaround: exactly **one** policy per RLS table, declared `AS PERMISSIVE`,
whose expression carries the complete isolation predicate (`tenant_id = context`
or the membership/admin predicate). With exactly one policy per table there is no
permissive OR-combination to weaken isolation, so restrictive/AND semantics are
preserved. The catalog test now asserts **exactly one policy per RLS table** and
that its USING expression references the security-context GUCs; any second policy
fails CI. Revisit and restore `AS RESTRICTIVE` when the upstream fix ships
(tracked in the risk register).

## Amendment 2026-08-05 (S9) — command-disjoint policy sets

S9 splits policies per command (FOR SELECT/INSERT/UPDATE/DELETE) on
`retention_policies` and `audit_events` so that (a) insert-only audit and
(b) expiry-proofed purge deletes can each carry their own WITH CHECK/USING
without blocking the others (e.g. tombstones are INSERTs by the purge role;
the audit expiry proof must gate DELETE only). Disjoint command policies
cannot OR-weaken any single command; the catalog test asserts at most one
policy per (table, command).

Additional PostgreSQL 18.4 planner note: a FOR UPDATE policy whose USING is
omitted (defaulting to the WITH CHECK expression) folds to constant false at
plan time when the expression contains stable calls/subqueries — the same
upstream folding defect as AS RESTRICTIVE. Explicit subquery-free USING
expressions are therefore mandatory; WITH CHECK (execution-time) may carry
subqueries (admin mirror, expiry proofs).

## Amendment 2026-08-05 (S3) — history capability, ACL listing, citation/source semantics

**History = manage capability.** A principal may observe NON-CURRENT version
metadata of a document iff it holds a direct `manage` grant on that document
(principal / group / tenant_role subject). This is enforced deterministically
in SQL via the new `securerag.manage_scope` security_invoker view (migration
0010) inside the verified security context, and audited as `document:history`.
Read/write grants do not enable history; the tenant-admin role alone does NOT
enable history — an admin who wants history grants themself manage (audited,
epoch-bumped). This keeps history orthogonal to role escalation and preserves
the adversarial gate (read-grant holders, including admins without a manage
grant, never observe non-current versions).

History is METADATA ONLY: version entries carry `versionNo`/`status`/
`publishedAt`/`hash` (no title, no content). Citations and the source stream
never resolve non-current versions — they stay bound to CURRENT valid/released
versions under the unchanged grant predicate. History surfaces:

- `GET /documents/{id}/versions` — manage-grant holders see every version with
  its status (valid/released/superseded/quarantined/expired/pending); everyone
  else sees only the current valid/released version; null like a foreign/
  nonexistent document otherwise.
- `GET /documents/{id}/versions/{versionId}` — non-current versionIds resolve
  only for manage-grant holders; everyone else observes the same 404 as
  foreign/nonexistent versions. Current versions resolve for any grant holder.

The manage_scope view also closes the S1 note in packages/core/src/grants.ts
(a policy-level manage check on document_grants cannot be expressed without
self-recursion): the manage-GRANT side is now reusable SQL; the manage gate's
tenant-admin fallback remains application-layer (canManage).

**ACL listing.** `GET /documents/{id}/grants` returns the slim entry shape
`{grants: [{grantId, subjectType, subjectId, capability}]}` — no tenant/
document id echo, no timestamps. Manage-gated exactly like grant writes
(manage grant OR tenant admin); foreign/nonexistent/unmanageable documents are
byte-identical 404s. Grant add/remove stay idempotent, audited
`grant:changed`, epoch-bumped (S1 unchanged).

**Citation hardening.** `GET /citations/{id}` responses carry a `resolvable`
flag (always true on 200 — unresolvable citations are indistinguishable 404s),
so clients can detect stale references from earlier answers. Authorization is
re-checked per request inside a fresh security context (ADR-0009 epoch
recheck), unchanged.

**Authorized source seam.** `GET /documents/{id}/versions/{versionId}/source`
is authorized per request with the byte-identical getVersion gate: source
CONTENT is only disclosed for CURRENT valid/released versions of a granted
document. S3 ships the minimal seam (version fingerprint response); S2's
object-store stream replaces the handler while keeping this SQL gate.

## Consequences

- Catalog tests enumerate every tenant table, policy, owner, role attribute, grant, view, function;
  schema drift without RLS fails CI.
- RLS is the security kernel; application code never re-filters tenant after SQL returns.
