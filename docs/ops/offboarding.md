# Tenant offboarding runbook — verified deletion across every storage class

Version: 0.x (construction). Rehearsed at G5 before release. Cross-links:
[backup-restore.md](backup-restore.md) (resurrection windows are ITS honest limits),
[incident.md](incident.md), [docs/ops/backup-restore.md §Tenant offboarding].

## Contract

Offboarding deletes a tenant's data across every storage class: PostgreSQL rows,
derived data (chunks/embeddings/audit), and object-store prefixes. The delete must be
**proven per storage class** (ADR-0010: `purge:completed` counts; legal hold blocks).

## Procedure (rehearsed)

```bash
# 0. Prerequisites: the tenant id, the operator's narrow credential
#    (securerag_purge), legal-hold status (offboarding blocks until the hold lifts).

# 1. Freeze the tenant: deactivate memberships (admin console or direct):
PGPASSWORD=… psql -h db -U securerag_api -d securerag -c \
  "UPDATE securerag.tenant_memberships SET is_active = false WHERE tenant_id = '<T>';"
#    Sessions of the tenant's principals remain valid for OTHER tenants.

# 2. Confirm the retention policy; a legal hold (legal_hold = true) BLOCKS
#    deletion — resolve the hold first (policy change is audited, epoch bumps).

# 3. Run the purge (the worker schedules it daily; force one pass):
docker compose -f ops/compose.yml exec -T worker node -e "…"  # demo: wait for the
#    next poll (2s). Production: run the purge CLI/job for the tenant:
#    (worker enqueues purge:{date} per tenant with an idempotency key)

# 4. PROVE deletion per storage class:
#    - PostgreSQL: counts per tenant-owned table return 0 (query as the
#      least-privilege role, never owner):
PGPASSWORD=… psql -h db -U securerag_purge -d securerag -c \
  "SELECT 'documents' t, count(*) FROM securerag.documents WHERE tenant_id='<T>'
   UNION ALL SELECT 'chunks', count(*) FROM securerag.chunks WHERE tenant_id='<T>'
   UNION ALL SELECT 'audit', count(*) FROM securerag.audit_events WHERE tenant_id='<T>';"
#    - audit: the tenant's last rows are purge:completed (with counts) and the
#      legal-hold blocks are recorded as purge:blocked.
#    - object store: remove the tenant prefix after the DB purge proves complete:
docker compose -f ops/compose.yml run --rm mc-init mc rm --recursive --force \
  local/securerag-objects/<tenant-prefix>
#    - verify the prefix is gone:
docker compose -f ops/compose.yml run --rm mc-init mc ls local/securerag-objects/<tenant-prefix>

# 5. Remove the tenant row itself (registry cleanup — bootstrap path, superuser):
PGPASSWORD=… psql -h db -U postgres -d securerag -c \
  "DELETE FROM securerag.tenants WHERE tenant_id = '<T>';"
```

## Honest limits (must be stated to the requesting tenant)

- **Backups resurrect deleted data.** A logical backup or PITR restore to a point
  before the purge returns the tenant's rows (backup-restore.md documents the window;
  `purge:completed` + `restore:executed` audit events make resurrection detectable).
- **Object-store snapshots** replicate this resurrection risk per the storage
  operator's snapshot policy; prefix deletion only affects the live bucket.
- Offboarding is **not reversible**: re-onboarding creates a new tenant identity;
  ids are never reused.
- The purge role cannot delete audit rows it did not prove expired; the audit trail
  of the offboarding itself is retained per the retention policy.
