-- 0006_security_invariants.sql
-- Review-driven hardening (S1/S6 reviews): DB-level invariants that kill
-- availability/DoS classes even when a runtime role writes raw SQL.

SET ROLE securerag_owner;

-- Grant subject format: principal/group subjects are uuids; tenant_role subjects
-- are one of the three roles. Prevents a malformed subject from raising a uuid
-- cast error inside the shared grant predicate (tenant-wide DoS via 22P02).
ALTER TABLE securerag.document_grants
  ADD CONSTRAINT document_grants_subject_format CHECK (
    (subject_type IN ('principal', 'group')
       AND subject_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    OR (subject_type = 'tenant_role'
       AND subject_id IN ('admin', 'member', 'security_reviewer'))
  );

-- Sessions always carry the sha256 of the cookie token (256-bit random ->
-- exactly 32 bytes).
ALTER TABLE securerag.sessions
  ALTER COLUMN token_hash SET NOT NULL;
ALTER TABLE securerag.sessions
  ADD CONSTRAINT sessions_token_hash_len CHECK (octet_length(token_hash) = 32);

RESET ROLE;
