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

## Consequences

- Catalog tests enumerate every tenant table, policy, owner, role attribute, grant, view, function;
  schema drift without RLS fails CI.
- RLS is the security kernel; application code never re-filters tenant after SQL returns.
