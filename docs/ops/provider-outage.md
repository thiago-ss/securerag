# Provider outage runbook — OIDC / model / storage / clamd outages

Version: 0.x (construction). Cross-links: [incident.md](incident.md),
[key-rotation.md](key-rotation.md), [backup-restore.md](backup-restore.md).

## Providers in the envelope (ADR-0011)

- **OIDC (Keycloak in the demo, any conforming provider in production)** — login only.
- **Answer generation** — the demo runs the deterministic `SpyGenerator`; a real
  adapter is a provider seam (spec §6).
- **Object storage (MinIO/S3)** — source objects, SSE-S3.
- **ClamAV (clamd)** — malware scan during ingest (optional in the demo).

## OIDC provider outage

Impact: **no NEW logins**; existing sessions keep working (server-side session rows,
no provider round-trip on API calls — ADR-0004). Retrieval continues.

```bash
# Verify scope:
curl -fsS http://localhost:8180/realms/securerag-demo/.well-known/openid-configuration
# (demo: the keycloak container; production: the IdP endpoint)

# Demo recovery (compose):
docker compose -f ops/compose.yml logs --tail=200 keycloak
docker compose -f ops/compose.yml up -d keycloak
# Production: IdP incident per the IdP operator; SecureRAG needs nothing
# while sessions are alive. When the IdP returns, users re-login normally.
```

Honest limits: we cannot mint sessions during an IdP outage (that is the point of the
IdP), and we never fall back to a weaker auth path.

## Object-store (MinIO/S3) outage

Impact: **uploads fail** (the API stores the object before staging the version and
deletes it on failure), **source previews fail** (authorized stream reads), **ingest
fails** (worker reads objects). Retrieval of already-published chunks keeps working
(chunks live in PostgreSQL, not the object store).

```bash
docker compose -f ops/compose.yml logs --tail=200 minio
docker compose -f ops/compose.yml up -d minio
docker compose -f ops/compose.yml run --rm mc-init   # re-create bucket if the volume is fresh
# After recovery, re-run failed ingest jobs: worker claims retryable jobs
# automatically (backoff); permanent failures (IngestPermanentFailure) need
# a re-upload of the source object.
```

Honest limits: uploads during the window are lost (client sees 404/500); no queue
drains into the object store — the API is synchronous about object writes.

## Answer-generation provider outage (production adapters)

Impact: retrieval refuses to answer while the provider is down — the refusal path is
deterministic and model-unoverrideable (ADR-0009); there is **no degraded-mode answer
without evidence**.

```bash
# The API returns refused outcomes with INSUFFICIENT_EVIDENCE/CITATION_UNSUPPORTED
# style codes rather than 5xx (generation failure is a refusal, not a crash).
# Restore the adapter (provider credentials, endpoint) and verify:
curl -fsS -X POST http://localhost:8080/api/retrieval/query -H 'Content-Type: application/json' \
  -d '{"tenantId":"…","question":"…"}' -H "Cookie: …" -H "X-CSRF-Token: …"
```

## ClamAV outage (production ingest)

Impact: ingest pipeline marks scan-dependent jobs retryable; **quarantine-default
semantics never loosen** — a version that cannot be scanned is not published.

## Cross-cutting

- Readiness stays green for retrieval during provider outages (provider reachability
  is not part of `/readyz`; the DB is). Documented behavior, not a bug.
- Every recovery ends with a retrieval + an audit check
  (`GET /audit/retrieval`) proving the window is accounted for.
