# ADR 0013 — Authorization-epoch write path and tenant onboarding

- Status: accepted
- Date: 2026-08-05
- Sources: T1 review (independent PostgreSQL/RLS reviewer), ADR-0003

## Context

Review found runtime roles held direct `UPDATE` on `authorization_epoch`, letting any tenant member
rewind the epoch (defeating stale-disclosure protection), and the membership policy's WITH CHECK
self-branch allowed a principal to insert itself as admin of any tenant (cross-tenant bootstrap
forgery). Tenant registry rows were also unguarded (cross-tenant name enumeration, rogue inserts).

## Decision

- **Epoch**: runtime roles hold only `SELECT` on `authorization_epoch`. The sole write path is
  `securerag.bump_authorization_epoch()` — `SECURITY DEFINER`, owned by the NOLOGIN
  `securerag_owner`, zero arguments, `SET search_path = securerag, pg_catalog`, PUBLIC execute
  revoked, EXECUTE granted to api/worker only. This is the documented, ADR-carrying exception to
  the no-SECURITY-DEFINER rule (AGENTS.md), justified by the tiny interface and dedicated
  catalog/exploit tests (no args to inject, pinned search_path, function-owned table access).
- **Membership writes are admin-only**: `memberships_access` WITH CHECK requires
  `ctx_principal_is_admin(tenant_id)`; the self branch exists only in USING (bootstrap read).
  No principal can self-insert, self-promote, or self-deactivate.
- **Tenant onboarding**: creating a tenant and provisioning its first admin is a platform
  bootstrap operation (migration/bootstrap path, audited), not a tenant self-serve API. Runtime
  roles hold `SELECT, UPDATE` on `tenants` (no INSERT/DELETE) with RLS `tenant_isolation`, so the
  tenant registry is not enumerable without a verified tenant context.
- **Trust boundary statement**: the DB kernel enforces row predicates against transaction-local
  context GUCs set by the application after verification (two-stage bootstrap, ADR-0003). A
  runtime-role credential holder IS the application backend; the model assumes runtime-role
  secrets are never exposed to tenant principals. The kernel's guarantee is: given a context,
  every disclosure surface is constrained to `Allowed(P,T)`; the application's guarantee is: it
  only ever sets contexts it verified. Neither alone is the whole boundary.

## Consequences

- Epoch monotonicity is enforced in the database (no rewinding); bump is an auditable, atomic op.
- Membership escalation requires an existing admin (or the audited bootstrap path).
- Catalog tests assert: no runtime-role membership in `securerag_owner`; no UPDATE on
  `authorization_epoch`; exactly-one-policy per RLS table with context-guarded USING and WITH
  CHECK; bump function attributes (definer, pinned search_path, owner, zero args).
