# Backup, PITR, and Restore (honest documentation, ADR-0010)

Version: 0.x (construction). Rehearsed at G5; this file is the contract.

## What is backed up

- **PostgreSQL** (`securerag` database): `pg_dump` logical backups (scheduled) plus
  WAL archiving for point-in-time recovery (PITR) where the deployment enables it.
- **Source objects** (MinIO/S3, SSE-S3-encrypted): bucket replication / snapshot
  per the object-storage operator (tenant-prefixed keys, content-addressed).
- **Secrets**: never in backups; restored from the secret manager.

## Honest limits (never pretend otherwise)

- **PITR resurrects deleted data.** A tenant whose retention purge deleted rows
  at time T can see those rows again if the database is restored to a point
  before T. This is inherent to PITR: the retention policy's guarantees apply
  to the *running* system; backup windows are documented per tenant in the
  retention policy contract. The purge worker records `purge:completed` audit
  events, and a restore audit (`restore:executed`) is written by the operator
  runbook, so a resurrected window is detectable.
- **Legal hold** protects the running system; a restore to a pre-hold snapshot
  bypasses it identically to PITR above. Documented, not hidden.
- **Encryption**: backups inherit SSE-S3 encryption at rest; logical dumps are
  encrypted at rest by the storage tier; KMS keys are the trust root
  (threat-model exclusions).

## Procedures

### Logical backup (scheduled)
```
pg_dump -Fc -d securerag -f backup-$(date +%F).dump
```
Restore: `pg_restore -d securerag --clean --if-exists backup.dump` followed by
`npm run migration:up` (idempotent; checksum-verified).

### PITR (WAL archiving)
- `archive_mode = on`, `archive_command` shipping to the object store.
- Recover to time T: restore base backup, apply WAL to T, then run
  `npm run migration:up` and the post-restore audit step (`restore:executed`).

### Restore rehearsal (performed at G5 and before any release)
1. Fresh container from backups at T-7d.
2. Apply migrations; verify checksums (drift detection fails loudly).
3. Start API + worker against the restored database.
4. Health/readiness pass; retrieval returns pre-T data (documented expectation).
5. Audit trail contains `restore:executed`.

### Tenant offboarding
Purge per retention policy; legal hold honored; bucket prefix removed after
purge completion proves every storage class (see `purge:completed` counts).

## Observability
`restore:executed` and `purge:completed` audit events correlate restore and
purge windows; retention-policy metadata records the documented window per
tenant so operators can reason about resurrectable ranges.
