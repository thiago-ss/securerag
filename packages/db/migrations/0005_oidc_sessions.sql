-- 0005_oidc_sessions.sql
-- S1 (issue #23): OIDC session store, identity upsert, and admin-scoped
-- group policies. Owner: securerag_owner (migration role via SET ROLE, per 0002/0003).

SET ROLE securerag_owner;

-- ---------- Session bearer tokens ----------
-- The session cookie carries an opaque 256-bit random token; the database
-- stores ONLY sha256(token) so a database leak never yields live session
-- credentials. The uuid session_id remains the internal primary key; the
-- token hash is a secondary lookup key (ADR-0014).
ALTER TABLE securerag.sessions ADD COLUMN token_hash bytea;
CREATE UNIQUE INDEX sessions_token_hash_unique ON securerag.sessions (token_hash);

-- ---------- Identity upsert / session lookup (SECURITY DEFINER, ADR-0014) ----------
-- RLS cannot express first login: principals.principal_scope WITH CHECK
-- requires the ctx principal to exist already (chicken-and-egg), and session
-- lookup happens before any identity is known. The three functions below run
-- as the NOLOGIN securerag_session_lookup role (BYPASSRLS, created in the
-- bootstrap, granted to NOBODY at runtime) — the ONLY path by which its RLS
-- bypass reaches sessions/principals. Each function is tiny and typed,
-- search_path is pinned, PUBLIC execute is revoked, EXECUTE goes to the api
-- role only.
GRANT USAGE ON SCHEMA securerag TO securerag_session_lookup;
GRANT SELECT, INSERT, UPDATE ON securerag.principals TO securerag_session_lookup;
GRANT SELECT, INSERT, UPDATE ON securerag.sessions TO securerag_session_lookup;
-- DDL-time schema access for the migration to CREATE the functions as this
-- role (via SET ROLE through the owner membership granted in the bootstrap);
-- revoked immediately after creation.
GRANT CREATE ON SCHEMA securerag TO securerag_session_lookup;

SET ROLE securerag_session_lookup;

-- Idempotent ON CONFLICT upsert on (provider, external_subject). Never throws
-- on existing-vs-new (no existence oracle): RETURNING principal_id either way.
CREATE FUNCTION securerag.upsert_principal(
  p_provider text,
  p_external_subject text,
  p_display_name text
)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = securerag, pg_catalog
PARALLEL SAFE
AS $$
  INSERT INTO securerag.principals (provider, external_subject, display_name)
  VALUES (p_provider, p_external_subject, p_display_name)
  ON CONFLICT (provider, external_subject)
  DO UPDATE SET display_name = EXCLUDED.display_name
  RETURNING principal_id
$$;

-- Session lookup by token hash with validity (expiry + revocation) enforced
-- INSIDE the SQL: foreign, nonexistent, expired, and revoked tokens all
-- return zero rows, so the API rejects them byte-identically (default deny).
CREATE FUNCTION securerag.get_session(p_token_hash bytea)
RETURNS TABLE (
  session_id  uuid,
  principal_id uuid,
  csrf_token  bytea,
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = securerag, pg_catalog
STABLE
AS $$
  SELECT s.session_id, s.principal_id, s.csrf_token, s.expires_at, s.revoked_at, s.created_at
    FROM securerag.sessions s
   WHERE s.token_hash = p_token_hash
     AND s.expires_at > now()
     AND s.revoked_at IS NULL
$$;

-- Idempotent logout: returns true only when a live session was revoked.
CREATE FUNCTION securerag.revoke_session(p_token_hash bytea)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = securerag, pg_catalog
AS $$
  UPDATE securerag.sessions
     SET revoked_at = now()
   WHERE token_hash = p_token_hash
     AND revoked_at IS NULL
  RETURNING true
$$;

-- EXECUTE rights are managed by the function owner (a non-owner REVOKE would
-- silently no-op against the owner's grants). PUBLIC never executes the
-- definers; the api role alone may call them.
REVOKE EXECUTE ON FUNCTION securerag.upsert_principal(text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION securerag.get_session(bytea) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION securerag.revoke_session(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securerag.upsert_principal(text, text, text) TO securerag_api;
GRANT EXECUTE ON FUNCTION securerag.get_session(bytea) TO securerag_api;
GRANT EXECUTE ON FUNCTION securerag.revoke_session(bytea) TO securerag_api;

SET ROLE securerag_owner;

REVOKE CREATE ON SCHEMA securerag FROM securerag_session_lookup;

-- ---------- Group management is admin-only (S1) ----------
-- groups: members never read or write group rows through any member-facing
-- surface (the retrieval grant predicate reads group_memberships only), so
-- the single-policy per table invariant (catalog contract) is preserved with
-- an all-admin policy. The admin check reads the tenant_admins mirror table
-- (different relation) — no recursion (ADR-0003 pattern).
DROP POLICY tenant_isolation ON securerag.groups;
CREATE POLICY groups_admin_scope ON securerag.groups AS PERMISSIVE
  FOR ALL
  USING (tenant_id = securerag.ctx_tenant_id()
         AND securerag.ctx_principal_is_admin(tenant_id))
  WITH CHECK (tenant_id = securerag.ctx_tenant_id()
              AND securerag.ctx_principal_is_admin(tenant_id));

-- group_memberships: members may read ONLY their own membership rows (the
-- retrieval grant predicate's EXISTS resolves through the self branch), and
-- writes are admin-only. A member can never add themselves to a group with
-- grants (self-escalation is blocked by WITH CHECK).
DROP POLICY tenant_isolation ON securerag.group_memberships;
CREATE POLICY group_memberships_scope ON securerag.group_memberships AS PERMISSIVE
  FOR ALL
  USING (tenant_id = securerag.ctx_tenant_id()
         AND (principal_id = securerag.ctx_principal_id()
              OR securerag.ctx_principal_is_admin(tenant_id)))
  WITH CHECK (tenant_id = securerag.ctx_tenant_id()
              AND securerag.ctx_principal_is_admin(tenant_id));

RESET ROLE;
