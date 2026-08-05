# Incident runbook — triage, containment, evidence

Version: 0.x (construction). Cross-links: [backup-restore.md](backup-restore.md),
[rollback.md](rollback.md), [key-rotation.md](key-rotation.md),
[provider-outage.md](provider-outage.md), [offboarding.md](offboarding.md).

## Principles

- **Security is a binary gate, never traded for performance** (ADR-0011). If an incident
  touches authorization, quarantine or refuse — do not "keep serving".
- **Evidence first**: collect before you change anything that destroys it (logs, traces,
  audit rows, object store, container state).
- Every decision is written down with the exact commands used; a post-mortem follows
  within 5 business days (G5 discipline).

## Severity triage

| Sev | Definition | First action |
| --- | --- | --- |
| S1 | suspected unauthorized disclosure, cross-tenant leak, PII in model context | freeze the tenant's traffic; collect evidence; page |
| S2 | availability or data integrity degraded for a tenant | isolate the tenant; start runbook |
| S3 | non-availability bug, no data impact | normal queue; incident page for visibility |

## Procedure

```bash
# 1. COLLECT (before changing anything):
docker compose -f ops/compose.yml logs --tail=5000 api worker keycloak > incident-$(date +%s).log
#    traces/metrics: pull the OTel exporter target; keep the window.

# 2. CLASSIFY the blast radius — every check is a tenant-isolated query as the
#    least-privilege role (never as owner):
PGPASSWORD=… psql -h db -U securerag_api -d securerag -c \
  'SELECT event_type, count(*) FROM securerag.audit_events GROUP BY 1;'
#    Look for: foreign tenant_ids in audit rows (isolation), refusal anomalies,
#    unexpected ingestion outcomes, session revocation waves.

# 3. CONTAIN:
#    - suspected disclosure -> immediately re-verify authz invariants:
#      run the adversarial suite against the RUNNING image+DB (npm run test:security),
#      revoke the affected sessions (narrow role):
PGPASSWORD=… psql -h db -U securerag_purge -d securerag -c \
  'UPDATE securerag.sessions SET revoked_at = now() WHERE principal_id = $1;'
#    - availability -> code rollback (rollback.md) or provider-outage.md.

# 4. RESTORE service per rollback.md; write restore:executed.

# 5. POST-MORTEM (all agents): timeline, root cause, evidence refs, the exact
#    failed command or decision, prevention items, and who owns each.
```

## Where the evidence lives

- `securerag.audit_events` — insert-only, hash-chained, tenant-isolated (ADR-0010);
  retrieval decisions, refusals, grant/membership/policy changes, purge windows.
- OTel spans/logs — identifiers/status only (ADR-0011): they prove *what happened and
  when*, never content; content-level questions go to audit + object store.
- The object store — content-addressed, SSE-S3-encrypted (operator snapshot per
  backup-restore.md).

## Honest limits

- **The OTel attribute policy is a feature, not a gap**: traces cannot contain prompts
  or content by design, so a content-leak investigation uses audit + provider logs,
  not traces.
- **No runtime role can delete audit rows**; if a purge ran, `purge:completed`/
  `audit:purged` mark the window (backup-restore.md explains the resurrectable range).
- We cannot prove a negative. "No unauthorized disclosure observed" is the honest claim
  (CONTEXT.md release language), backed by the adversarial suite run for the exact
  commit/image/migrations in the report.
