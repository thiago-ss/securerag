-- 0009_retention.sql
-- Retention/legal-hold/purge (S9, ADR-0010):
--  * policy row seeded on tenant creation (AFTER INSERT trigger) + first access
--    (INSERT ON CONFLICT DO NOTHING in getRetentionPolicy); defaults live in
--    0002 (source 3650 / derived 3650 / audit 1095 / grace 7 / legal_hold false).
--  * the purge worker is a separate narrow credential (securerag_purge):
--    DELETE only on rows PROVEN expired — enforced TWICE: role-aware RLS
--    policies below (the "expiry proof" from ADR-0003) AND expiry predicates
--    in every purge query. Runtime roles never get DELETE on active data.
--  * the audit-retention role deletes only expired audit rows (policy-gated).
--  * jobs/retention_policies RLS gains a securerag_worker branch: the worker
--    claims jobs across tenants (SKIP LOCKED loop, r8 §4) and schedules purge
--    sweeps from the policy table. Job rows carry only opaque ids and policy
--    rows carry no content, so cross-tenant worker visibility is safe by
--    construction (r8 §4 "Worker security context").
-- Owner: securerag_owner (migration role via SET ROLE, per 0002/0003).

SET ROLE securerag_owner;

-- ---------- Policy seeding ----------
-- Invoker-rights trigger function (never SECURITY DEFINER): every tenant gets
-- a retention_policies row with DB defaults at creation time. Tenant inserts
-- only ever happen on bootstrap/fixture paths, where the inserting role passes
-- RLS on retention_policies; pre-existing tenants are covered by first-access
-- seeding in the application layer.
CREATE FUNCTION securerag.seed_retention_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO securerag.retention_policies (tenant_id)
  SELECT NEW.tenant_id
   WHERE NOT EXISTS (
     SELECT 1 FROM securerag.retention_policies
      WHERE tenant_id = NEW.tenant_id
   );
  RETURN NEW;
END;
$$;

CREATE TRIGGER tenants_retention_policy_seed
AFTER INSERT ON securerag.tenants
FOR EACH ROW EXECUTE FUNCTION securerag.seed_retention_policy();

-- ---------- RLS: job queue (worker claim loop) ----------
-- The worker role (trusted service credential, opaque job payloads only) may
-- see and update every job row so the SKIP LOCKED claim loop works without a
-- tenant context; all other roles keep the strict tenant_isolation branch.
DROP POLICY tenant_isolation ON securerag.jobs;
CREATE POLICY tenant_isolation ON securerag.jobs AS PERMISSIVE
  FOR ALL
  USING (tenant_id = securerag.ctx_tenant_id()
         OR current_user = 'securerag_worker')
  WITH CHECK (tenant_id = securerag.ctx_tenant_id()
              OR current_user = 'securerag_worker');

-- Claim index for the SKIP LOCKED loop (r8 §4): pending + lease-expired first.
CREATE INDEX jobs_claim_idx ON securerag.jobs (status, next_attempt_at);

-- ---------- RLS: retention policies (purge scheduling + admin writes) ----------
-- The worker enumerates tenants to schedule purge jobs from the policy table
-- (tenant ids + retention settings only, no content). WRITES are gated:
--   INSERT is allowed only as first-access seeding (no row for the tenant yet,
--     proven via a FOR-SELECT-scoped subquery — disjoint command policies, so
--     no permissive OR-weakening for any single command; ADR-0003 amendment);
--   UPDATE is tenant-admin-only (admin mirror, no recursion);
--   DELETE is impossible for every runtime role (FOR DELETE WITH CHECK false;
--     api also has no DELETE grant).
DROP POLICY tenant_isolation ON securerag.retention_policies;
CREATE POLICY retention_select ON securerag.retention_policies AS PERMISSIVE
  FOR SELECT
  USING (tenant_id = securerag.ctx_tenant_id()
         OR current_user = 'securerag_worker');
CREATE POLICY retention_insert_seed ON securerag.retention_policies AS PERMISSIVE
  FOR INSERT
  WITH CHECK (tenant_id = securerag.ctx_tenant_id());
-- Explicit USING without subqueries: PostgreSQL 18.4 folds plan-time security
-- quals containing subqueries/stable calls to false (the same upstream defect
-- as the AS RESTRICTIVE folding, ADR-0003); WITH CHECK evaluates at execution
-- time and is safe. The admin gate therefore lives in BOTH the app WHERE
-- (zero-rows for non-admins) and the WITH CHECK (hard rejection).
CREATE POLICY retention_update_admin ON securerag.retention_policies AS PERMISSIVE
  FOR UPDATE
  USING (tenant_id = securerag.ctx_tenant_id())
  WITH CHECK (tenant_id = securerag.ctx_tenant_id()
              AND securerag.ctx_principal_is_admin(securerag.ctx_tenant_id()));
CREATE POLICY retention_delete_none ON securerag.retention_policies AS PERMISSIVE
  FOR DELETE
  USING (false);

-- ---------- RLS: expiry proof for the purge role ----------
-- The purge role sees ONLY expired versions of the tenant and ONLY chunks of
-- expired versions, so its DELETE cannot touch active data even with a raw
-- query (ADR-0003: "narrow: may delete only expired derived data/objects").
DROP POLICY tenant_isolation ON securerag.document_versions;
CREATE POLICY tenant_isolation ON securerag.document_versions AS PERMISSIVE
  FOR ALL
  USING (tenant_id = securerag.ctx_tenant_id()
         AND (current_user <> 'securerag_purge' OR status = 'expired'))
  WITH CHECK (tenant_id = securerag.ctx_tenant_id()
              AND (current_user <> 'securerag_purge' OR status = 'expired'));

DROP POLICY tenant_isolation ON securerag.chunks;
CREATE POLICY tenant_isolation ON securerag.chunks AS PERMISSIVE
  FOR ALL
  USING (tenant_id = securerag.ctx_tenant_id()
         AND (current_user <> 'securerag_purge'
              OR EXISTS (SELECT 1 FROM securerag.document_versions v
                          WHERE v.tenant_id = securerag.chunks.tenant_id
                            AND v.version_id = securerag.chunks.version_id
                            AND v.status = 'expired')))
  WITH CHECK (tenant_id = securerag.ctx_tenant_id()
              AND (current_user <> 'securerag_purge'
                   OR EXISTS (SELECT 1 FROM securerag.document_versions v
                               WHERE v.tenant_id = securerag.chunks.tenant_id
                                 AND v.version_id = securerag.chunks.version_id
                                 AND v.status = 'expired')));

-- ---------- RLS: audit expiry proof ----------
-- The purge and audit-retention roles may delete ONLY audit rows past their
-- tenant's audit_days AND not under legal hold (both re-proven in the purge
-- WHERE clause; the policy is the SQL-level proof). All other roles keep the
-- insert-only/read-only branch (no UPDATE/DELETE grants anywhere, 0003).
-- Command-disjoint policies (no permissive OR-weakening for any single
-- command; ADR-0003 amendment): SELECT/INSERT stay tenant-scoped and
-- insert-only-by-grant; the expiry proof applies ONLY to DELETE by the
-- purge/audit-retention roles, so tombstones (INSERT by the purge role,
-- F4) are not blocked by the expiry predicate.
DROP POLICY tenant_isolation ON securerag.audit_events;
CREATE POLICY audit_select ON securerag.audit_events AS PERMISSIVE
  FOR SELECT
  USING (tenant_id = securerag.ctx_tenant_id());
CREATE POLICY audit_insert ON securerag.audit_events AS PERMISSIVE
  FOR INSERT
  WITH CHECK (tenant_id = securerag.ctx_tenant_id());
CREATE POLICY audit_update_none ON securerag.audit_events AS PERMISSIVE
  FOR UPDATE
  WITH CHECK (false);
CREATE POLICY audit_delete_expiry ON securerag.audit_events AS PERMISSIVE
  FOR DELETE
  USING (tenant_id = securerag.ctx_tenant_id()
         AND current_user IN ('securerag_purge', 'securerag_audit_retention')
         AND occurred_at + COALESCE(
               (SELECT audit_days FROM securerag.retention_policies rp
                 WHERE rp.tenant_id = securerag.audit_events.tenant_id), 1095
             ) * interval '1 day' < now()
         AND NOT COALESCE(
               (SELECT legal_hold FROM securerag.retention_policies rp
                 WHERE rp.tenant_id = securerag.audit_events.tenant_id), false));

-- Audit purge scan index (occurred_at ordering of the expiry predicate).
CREATE INDEX audit_events_occurred_idx ON securerag.audit_events (occurred_at);

-- ---------- Grants ----------
-- Purge role: read policy + expired rows; DELETE on proven-expired rows ONLY
-- (RLS above decides which rows are visible/deletable; the purge queries add
-- the grace predicates). No UPDATE anywhere, no DELETE on documents/grants/
-- tenants — the role never touches active data.
GRANT SELECT ON
  securerag.document_versions,
  securerag.chunks,
  securerag.retention_policies,
  securerag.audit_events
  TO securerag_purge;
GRANT DELETE ON
  securerag.document_versions,
  securerag.chunks,
  securerag.audit_events
  TO securerag_purge;

-- Audit-retention role: DELETE on expired audit rows only (same RLS proof;
-- retention_policies SELECT needed for the policy subquery, which executes
-- with invoker privileges).
GRANT SELECT ON securerag.retention_policies TO securerag_audit_retention;
GRANT DELETE ON securerag.audit_events TO securerag_audit_retention;

-- S9 review fixes: no runtime role may DELETE the policy row (F3); the purge
-- role may append audit events so tombstones + completion are written in the
-- SAME transaction as the destructive deletes (F4 — no crash window).
REVOKE DELETE ON securerag.retention_policies FROM securerag_api, securerag_worker;
GRANT INSERT ON securerag.audit_events TO securerag_purge;

-- Service roles read the authorization epoch inside withWorkerContext (they
-- never bump it: bump EXECUTE stays api/worker-only).
GRANT SELECT ON securerag.authorization_epoch
  TO securerag_purge, securerag_audit_retention;

RESET ROLE;
