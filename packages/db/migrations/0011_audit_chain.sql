-- 0011_audit_chain.sql
-- S8 per-tenant audit hash chain (ADR-0010): appendAudit allocates the
-- event_id explicitly (SELECT nextval) so every hash binds its exact position
-- in the tenant's sequence (exact out-of-order detection). The identity
-- sequence usage already granted to securerag_api/securerag_worker (0003)
-- must extend to securerag_purge: the purge role appends chained
-- 'audit:purged' tombstones + 'purge:completed' in the SAME transaction as
-- the destructive deletes (0009 F4) and now needs the explicit nextval.
-- No schema change: prev_event_hash / event_hash columns exist since 0002.

SET ROLE securerag_owner;

GRANT USAGE ON SEQUENCE securerag.audit_events_event_id_seq TO securerag_purge;

RESET ROLE;
