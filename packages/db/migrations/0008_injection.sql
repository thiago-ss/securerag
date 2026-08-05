-- 0008_injection.sql
-- Injection quarantine review (S5, ADR-0006): convenience audit columns on
-- document_versions. The AUTHORITATIVE record is the immutable audit trail
-- ('version:quarantined' / 'version:review' events carry the same facts);
-- these columns mirror the latest review decision of the CURRENT quarantine
-- cycle for UI/ops (reviewed_by = reviewing principal, reviewed_at, and the
-- release/keep decision). Cleared by (re-)quarantine so they never claim a
-- stale decision for a re-quarantined version.
-- Owner: securerag_owner (migration role via SET ROLE, per 0002/0003).
-- RLS: existing tenant_isolation policy on document_versions applies; the
-- review gate is the deterministic service-layer role check in
-- packages/core/src/quarantine.ts (admin OR tenant role 'security_reviewer').

SET ROLE securerag_owner;

ALTER TABLE securerag.document_versions
  ADD COLUMN reviewed_by     uuid REFERENCES securerag.principals (principal_id),
  ADD COLUMN reviewed_at     timestamptz,
  ADD COLUMN review_decision text CHECK (review_decision IN ('release', 'keep'));

RESET ROLE;
