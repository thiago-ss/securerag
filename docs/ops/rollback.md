# Rollback runbook — restore a known-good state

Version: 0.x (construction). Rehearsed at G5 before release; this file is the contract.
Cross-links: [backup-restore.md](backup-restore.md), [upgrade.md](upgrade.md), [incident.md](incident.md).

## What rollback means here

- **Code rollback:** point the deployment at the previous image digest. Always possible.
- **Data rollback:** restore the last logical backup (`pg_dump -Fc`). Schema downgrade is
  **not** supported — migrations never un-apply. If the new schema breaks old code, you
  restore a pre-upgrade backup and run the old image; you do not "roll back" migrations.
- **Config rollback:** re-apply the previous `.env`/secret set from the secret manager.

## Decision tree

1. API/worker misbehaving with the NEW image but DB fine → **code rollback only**
   (fastest; data intact; upgrades are expand-first so old code stays compatible).
2. Data corruption / bad migration / restore rehearsal failure → **data rollback**
   (restore backup, then code rollback if needed).
3. Partial upgrade (API on new, DB still old) → finish the migration (upgrade.md), then
   roll code back; a half-applied data plane is worse than either end state.

## Procedure (rehearsed)

```bash
# 1. Stop write traffic (keep reads if the outage demands it).
docker compose -f ops/compose.yml stop api worker

# 2. Code rollback: pin the previous image digest (recorded in the release note).
docker compose -f ops/compose.yml up -d api worker web
#    production: deploy the previous image tag/digest through your pipeline.

# 3. Data rollback (only when the DB itself must return to a known point).
#    Restore into a FRESH database first (rehearsal), then switch:
pg_restore -d securerag_stage --clean --if-exists backup-$(date +%F).dump
npm run migration:up   # idempotent, checksum-verified (upgrade.md)
#    verify health/readiness + a retrieval, then point traffic at the restored DB.

# 4. Write the restore:executed audit event (operator runbook step, contract:
#    backup-restore.md §Procedures) so the resurrected window is detectable.

# 5. Post-rollback verification gate:
curl -fsS http://localhost:8080/api/readyz
#    + one retrieval returns pre-rollback data (documented expectation, not a bug)
#    + audit trail shows restore:executed
```

## Honest limits

- **PITR/backup restore resurrects deleted data.** A retention purge at time T is
  undone by a restore to a point before T; the backup window per tenant is documented
  in the retention policy contract (backup-restore.md). Detectable via `purge:completed`
  + `restore:executed` audit events — not hidden.
- **Legal hold** protects the running system; a pre-hold restore bypasses it identically.
- Rollback rehearsals are only as good as their data: rehearse with the actual backup
  artifacts, not a synthetic dump.
- Sessions are server-side rows: after a restore, all sessions may be invalidated by
  the epoch/revocation state of the restored DB — users re-login (expected).
