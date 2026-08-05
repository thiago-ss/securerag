-- 0007_pii.sql
-- PII scope (S4, ADR-0005): principals.pii_read widens ONLY human surfaces
-- (citation excerpts, preview/source/export). Derived data — embeddings,
-- provider/model payloads, normal logs, audit views — stays uniformly
-- redacted for every principal, including pii:read holders. Default deny:
-- principals without the flag see redacted derivatives everywhere.

SET ROLE securerag_owner;

ALTER TABLE securerag.principals
  ADD COLUMN pii_read boolean NOT NULL DEFAULT false;

RESET ROLE;
