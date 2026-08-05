-- 0010_history_manage_scope.sql
-- S3: history capability + ACL semantics (ADR-0003 amendment 2026-08-05 S3).
--
-- The document-level MANAGE GRANT becomes a reusable SQL surface via a
-- security_invoker view (the S1 note in packages/core/src/grants.ts: a
-- policy-level manage check on document_grants cannot be expressed without
-- self-recursion; the view closes the gap). security_invoker means the
-- base-table RLS (tenant_isolation, memberships_access, principal_scope)
-- applies with the CALLER's verified security context, so the view can never
-- widen visibility outside the verified tenant.
--
-- Semantics (history = manage capability): a principal may access non-current
-- version METADATA of a document iff it holds a direct manage grant on that
-- document (principal / group / tenant_role subject, matched exactly like the
-- S1 manage predicate). The tenant-admin role alone does NOT enable history:
-- an admin who wants history grants themself manage (audited, epoch-bumped).
-- This keeps history orthogonal to role escalation and preserves the
-- adversarial gate: read-grant holders (including tenant admins without a
-- manage grant) never observe non-current versions.

SET ROLE securerag_owner;

CREATE VIEW securerag.manage_scope
WITH (security_invoker) AS
SELECT DISTINCT g.tenant_id, g.document_id
  FROM securerag.document_grants g
 WHERE g.capability = 'manage'
   AND (
     (g.subject_type = 'principal'
        AND g.subject_id = securerag.ctx_principal_id()::text)
     OR (g.subject_type = 'group'
        AND EXISTS (SELECT 1 FROM securerag.group_memberships gm
                     WHERE gm.tenant_id = g.tenant_id
                       AND gm.group_id = g.subject_id::uuid
                       AND gm.principal_id = securerag.ctx_principal_id()))
     OR (g.subject_type = 'tenant_role'
        AND g.subject_id = (SELECT tm.role FROM securerag.tenant_memberships tm
                             WHERE tm.tenant_id = g.tenant_id
                               AND tm.principal_id = securerag.ctx_principal_id()
                               AND tm.is_active))
   );

GRANT SELECT ON securerag.manage_scope TO securerag_api, securerag_worker;

RESET ROLE;
