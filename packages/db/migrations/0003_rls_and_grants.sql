-- 0003_rls_and_grants.sql
-- Row-level security: ENABLE + FORCE on every table; restrictive policies only.
-- Runtime roles get table-level grants (RLS gates rows); NEVER TRUNCATE/REFERENCES.
-- Missing security context makes current_setting(..., true) return NULL -> policies
-- evaluate false -> zero rows (default deny).

SET ROLE securerag_owner;

-- ---------- Row-level security ----------

ALTER TABLE securerag.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.tenant_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.tenant_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.tenant_admins FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.groups FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.group_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.group_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.documents FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.document_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.document_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.document_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.document_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.chunks FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.retention_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE securerag.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE securerag.audit_events FORCE ROW LEVEL SECURITY;

-- ---------- Policies ----------
-- Exactly ONE policy per RLS table, carrying the full isolation predicate.
-- Multiple policies OR-combine (permissive semantics), which would weaken
-- isolation; the catalog test forbids more than one policy per table.
-- NOTE (ADR-0003 amendment): PostgreSQL 18.4 upstream bug filters ALL rows for
-- non-superusers under AS RESTRICTIVE (reproduced on stock postgres:18.4 and
-- pgvector 0.8.6-pg18; permissive policies are unaffected). Single-policy
-- permissive tables preserve restrictive/AND isolation semantics. Revisit and
-- restore AS RESTRICTIVE when the upstream fix ships.
-- Missing context -> current_setting(..., true) -> NULL -> false -> zero rows.

CREATE POLICY tenant_isolation ON securerag.tenants AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.groups AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.group_memberships AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.documents AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.document_versions AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.document_grants AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.chunks AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.jobs AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.retention_policies AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

CREATE POLICY tenant_isolation ON securerag.audit_events AS PERMISSIVE
  FOR ALL USING (tenant_id = securerag.ctx_tenant_id())
             WITH CHECK (tenant_id = securerag.ctx_tenant_id());

-- Membership bootstrap: the authenticated principal reads ONLY its own membership
-- metadata (narrow exception: no tenant context needed, reveals no other
-- principal's rows). Active admins (mirrored in tenant_admins) additionally see
-- and may write that tenant's membership rows. WRITES are admin-only: the self
-- branch appears in USING (bootstrap read) but NOT in WITH CHECK, so no principal
-- can self-insert, self-promote, or self-deactivate. The admin check reads the
-- mirror table, never tenant_memberships itself, so the policy cannot recurse.
CREATE POLICY memberships_access ON securerag.tenant_memberships AS PERMISSIVE
  FOR ALL
  USING (principal_id = securerag.ctx_principal_id()
         OR securerag.ctx_principal_is_admin(tenant_id))
  WITH CHECK (securerag.ctx_principal_is_admin(tenant_id));

-- Admin mirror: visible to the owning principal and (for admin management flows)
-- within a verified tenant context; rows may only be created/removed by an active
-- admin of the tenant, proven via tenant_memberships (no recursion: different
-- relation).
CREATE POLICY tenant_admin_scope ON securerag.tenant_admins AS PERMISSIVE
  FOR ALL
  USING (principal_id = securerag.ctx_principal_id()
         OR tenant_id = securerag.ctx_tenant_id())
  WITH CHECK (tenant_id = securerag.ctx_tenant_id()
              AND securerag.ctx_principal_is_admin(tenant_id));

CREATE POLICY principal_scope ON securerag.principals AS PERMISSIVE
  FOR ALL USING (principal_id = securerag.ctx_principal_id())
             WITH CHECK (principal_id = securerag.ctx_principal_id());

CREATE POLICY principal_scope ON securerag.sessions AS PERMISSIVE
  FOR ALL USING (principal_id = securerag.ctx_principal_id())
             WITH CHECK (principal_id = securerag.ctx_principal_id());

-- ---------- Privileges ----------
-- RLS gates rows; these grants gate operations. No TRUNCATE, no REFERENCES, no
-- broad schema privileges for runtime roles. Database-level hardening and
-- search_path live in the bootstrap migration (superuser-only).

REVOKE ALL ON SCHEMA securerag FROM PUBLIC;
GRANT USAGE ON SCHEMA securerag TO securerag_api, securerag_worker,
  securerag_audit_retention, securerag_purge, securerag_migration;

-- Migration runner bookkeeping (schema + table owned by securerag_owner).
GRANT SELECT, INSERT, UPDATE ON securerag.migrations TO securerag_migration;

-- API: full row operations on tenant tables (RLS + policies decide rows).
-- tenants: registry reads/updates only (creation/deletion are bootstrap paths);
-- chunks: insert-only (immutable once published); document_versions: no DELETE
-- (purge role owns deletion in S9).
GRANT SELECT, UPDATE ON securerag.tenants TO securerag_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  securerag.principals, securerag.sessions,
  securerag.tenant_memberships, securerag.tenant_admins,
  securerag.groups, securerag.group_memberships,
  securerag.documents, securerag.document_grants, securerag.jobs,
  securerag.retention_policies
  TO securerag_api;
GRANT SELECT, INSERT, UPDATE ON securerag.document_versions TO securerag_api;
GRANT SELECT, INSERT ON securerag.chunks TO securerag_api;

-- Worker (job consumer): no identity/session access, no grant management,
-- no deletion; writes lifecycle state and derived data only.
GRANT SELECT ON securerag.tenants, securerag.principals, securerag.sessions,
  securerag.tenant_memberships, securerag.tenant_admins,
  securerag.groups, securerag.group_memberships, securerag.document_grants
  TO securerag_worker;
GRANT SELECT, INSERT, UPDATE ON
  securerag.documents, securerag.document_versions, securerag.jobs,
  securerag.retention_policies
  TO securerag_worker;
GRANT SELECT, INSERT ON securerag.chunks TO securerag_worker;

GRANT EXECUTE ON FUNCTION
  securerag.ctx_tenant_id(), securerag.ctx_principal_id(),
  securerag.ctx_principal_is_admin(uuid)
  TO securerag_api, securerag_worker, securerag_audit_retention, securerag_purge;

-- Admin management flows (S1) list tenants they administer through this view.
GRANT SELECT ON securerag.admin_scope TO securerag_api, securerag_worker;

-- Audit events: insert-only for runtime roles (no UPDATE/DELETE/TRUNCATE anywhere).
GRANT SELECT, INSERT ON securerag.audit_events TO securerag_api, securerag_worker;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA securerag TO securerag_api, securerag_worker;

-- Authorization epoch: runtime roles may only READ the counter and bump it
-- through the SECURITY DEFINER function (ADR-0013); direct UPDATE is revoked so
-- the monotonic guarantee cannot be rewound. PUBLIC never executes the function.
REVOKE EXECUTE ON FUNCTION securerag.bump_authorization_epoch() FROM PUBLIC;
GRANT SELECT ON securerag.authorization_epoch TO securerag_api, securerag_worker;
GRANT EXECUTE ON FUNCTION securerag.bump_authorization_epoch()
  TO securerag_api, securerag_worker;

-- Audit retention: delete only proven-expired audit rows (granted in S9 with the
-- expiry proof view); for now only read access for validation.
GRANT SELECT ON securerag.audit_events TO securerag_audit_retention;

-- Purge role: granted targeted DELETE privileges in S9 (retention/legal hold).

RESET ROLE;
