-- 0001_roles_and_extensions.sql
-- Bootstrap roles and extensions. Runs as the ephemeral securerag_migration role.
-- SECURITY MODEL: runtime roles are NOSUPERUSER/NOBYPASSRLS/non-owner; table owner is NOLOGIN.
-- The migration role may SET ROLE to the owner to perform DDL; this is the only documented
-- exception to the no-unrestricted-SET-ROLE rule and is never granted to runtime roles.
-- Passwords are NEVER stored here: demo/compose/tests assign generated passwords via
-- ALTER ROLE ... PASSWORD. Production assigns via secret manager in the same way.

CREATE EXTENSION IF NOT EXISTS vector;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securerag_owner') THEN
    CREATE ROLE securerag_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securerag_migration') THEN
    CREATE ROLE securerag_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securerag_api') THEN
    CREATE ROLE securerag_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securerag_worker') THEN
    CREATE ROLE securerag_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securerag_audit_retention') THEN
    CREATE ROLE securerag_audit_retention LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securerag_purge') THEN
    CREATE ROLE securerag_purge LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  -- Function-owner role for the S1 session/identity SECURITY DEFINER functions
  -- (ADR-0014): NOLOGIN, NOINHERIT, and granted to NOBYPASSRLS-checking nobody,
  -- so its BYPASSRLS reaches the sessions/principals tables ONLY through the
  -- three tiny, EXECUTE-gated functions it owns. The api role never holds
  -- membership and cannot SET ROLE to it. See ADR-0014 and migration 0005.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securerag_session_lookup') THEN
    CREATE ROLE securerag_session_lookup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS;
  END IF;
END
$$;

-- Migration role may impersonate the owner for DDL (policies are owner-only).
GRANT securerag_owner TO securerag_migration;
-- The owner may impersonate the session-lookup role so the migration can
-- create the S1 SECURITY DEFINER functions owned by it (ADR-0014). Only the
-- migration (which can already perform arbitrary DDL as owner) can reach this
-- role; runtime roles hold no membership anywhere on this chain.
GRANT securerag_session_lookup TO securerag_owner;

-- PostgreSQL 18 grants no CREATE on databases to PUBLIC by default; the migration
-- role and the NOLOGIN owner (via SET ROLE) need CREATE to bootstrap the schema.
GRANT CREATE ON DATABASE securerag TO securerag_migration;
GRANT CREATE ON DATABASE securerag TO securerag_owner;
GRANT CONNECT ON DATABASE securerag TO securerag_migration;

-- Database-level hardening (requires superuser; runs once in the bootstrap).
REVOKE ALL ON DATABASE securerag FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
-- The pgvector extension lives in public; roles need USAGE to resolve the vector
-- type (tables themselves live in the securerag schema).
GRANT USAGE ON SCHEMA public TO securerag_owner, securerag_migration, securerag_api,
  securerag_worker, securerag_audit_retention, securerag_purge;
GRANT CONNECT ON DATABASE securerag TO securerag_api, securerag_worker,
  securerag_audit_retention, securerag_purge;

-- Lock search_path to the securerag schema for every runtime role.
ALTER ROLE securerag_api SET search_path = securerag;
ALTER ROLE securerag_worker SET search_path = securerag;
ALTER ROLE securerag_audit_retention SET search_path = securerag;
ALTER ROLE securerag_purge SET search_path = securerag;

-- Runtime roles never hold membership in the owner role.
