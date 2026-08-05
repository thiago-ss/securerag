# Upgrade runbook — migrations, expand/contract, image rollout

Version: 0.x (construction). Rehearsed before every release (G5 gate); this file is the contract.
Cross-links: [backup-restore.md](backup-restore.md), [rollback.md](rollback.md), [incident.md](incident.md).

## Migration model (recap)

- Explicit SQL in `packages/db/migrations/` (lexical order `0002_schema.sql` … `0010_…`);
  bootstrap (roles/extensions) lives in `migrations/bootstrap/` and runs as superuser.
- The runner (`packages/db/src/migrate.ts`, CLI `packages/db/src/cli.ts`) applies pending
  files one transaction each, checksum-verifies every applied file, and **fails loudly on
  drift** (a released migration file may never be edited — add a new file instead).
- Runtime roles (`securerag_api`, `securerag_worker`, …) never run DDL; the migration
  role (`securerag_migration`) runs the CLI. RLS is applied by the migrations themselves.

## Rules that make upgrades safe

1. **Expand first, contract later (two releases).** Adding a column/table/policy is
   expand (safe with old code running); dropping/renaming/constraining is contract —
   ship it only after the previous release's code no longer reads the old shape.
2. **Never edit an applied migration.** Append `0011_…`. The checksum guard will reject
   edits anyway — that is the point.
3. **Backup before, verify after** (`backup-restore.md`): `pg_dump -Fc` before, and
   `migration:status` + the restore rehearsal after.
4. Every migration must be idempotent (`IF NOT EXISTS`, `ON CONFLICT`), because the
   same file may run on a partially-upgraded replica.

## Procedure (rehearsed)

```bash
# 0. Freeze the release: branch from main at the target commit.
# 1. Backup (contract: backup-restore.md).
pg_dump -Fc -d securerag -f backup-$(date +%F).dump

# 2. Run pending migrations against the DATABASE (not the API).
#    Compose demo:
docker compose -f ops/compose.yml exec -T migrate npx tsx packages/db/src/cli.ts status
docker compose -f ops/compose.yml run --rm migrate
#    Production (secret-managed env):
PGHOST=… PGPORT=5432 PGDATABASE=securerag PGUSER=securerag_migration PGPASSWORD=… \
  npx tsx packages/db/src/cli.ts up

# 3. Verify: checksums stored == files on disk, zero pending.
PGHOST=… PGPASSWORD=… npx tsx packages/db/src/cli.ts status

# 4. Roll the API image forward (expand phase is code-compatible with old code).
docker compose -f ops/compose.yml up -d api worker web

# 5. Health/readiness gates:
curl -fsS http://localhost:8080/api/healthz && curl -fsS http://localhost:8080/api/readyz
#    readyz runs SELECT 1 on the least-privilege pool; a 503 means the DB is
#    not reachable and the API must not serve traffic.

# 6. Contract phase (NEXT release): remove old columns/tables/policies, rerun 1–5.
```

## Honest limits

- **The API is not migration-versioned.** The readiness probe proves DB connectivity,
  not schema compatibility; compatibility is a review discipline (expand/contract).
- **Backup/restore of data, not state:** in-flight jobs are not snapshotted; the worker's
  idempotency keys make re-runs safe (`ingest:{documentId}:{sha}`), but a failed upgrade
  may leave jobs in `running` until their lease expires (`claim` skips locked rows).
- **Keycloak schema is out of scope** here; the Keycloak image version is upgraded per
  its own supported-upgrade path (demo: wipe and re-import the realm; production:
  Keycloak's operator runbook).
- Downgrade of data (schema) is not supported: rollback restores a pre-upgrade backup
  (`rollback.md`), it does not "un-apply" migrations.
