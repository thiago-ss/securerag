# SecureRAG demo stack (ADR-0011)

One-command local demo: PostgreSQL 18.4 + pgvector, Keycloak 26.7.0 (synthetic realm),
MinIO (SSE-S3 via the demo KMS key), API, worker, web console, and a Caddy reverse
proxy serving everything same-origin. **No paid keys, no real data.**

## Quick start

```bash
cp ops/.env.example ops/.env        # demo passwords — NEVER commit a real .env
docker compose -f ops/compose.yml up --build -d     # or: npm run demo
npm run demo:seed                   # 2 synthetic tenants + documents (idempotent)
open http://localhost:8080          # sign in as alice / alice-demo-password
```

Demo identities (ops/keycloak-realm.json, pinned ids so the seed links principals):

| User | Password | Tenant role |
| --- | --- | --- |
| alice | alice-demo-password | member of Acme Corp (manage on the demo docs) |
| carol | carol-demo-password | admin of Acme Corp, member of Globex Inc |

What to try: browse the document library, create a document and upload a `.txt`
(worker ingests within ~2 s), search/answer with citations, ask something with no
evidence to see a refusal, review quarantine, export the audit log, edit the
retention policy as carol.

Useful endpoints: console `http://localhost:8080`, Keycloak admin `http://localhost:8180`
(admin / admin-demo), MinIO console `http://localhost:9001` (minioadmin / minio-demo-password),
PostgreSQL on host `localhost:55432`.

## Layout

```
ops/compose.yml              stack definition (images pinned by tag)
ops/.env.example             demo env — copy to ops/.env, never commit real values
ops/keycloak-realm.json      demo realm (pinned user ids; see docs/ops/keycloak-demo.md)
ops/postgres/init-db.sh      first-boot bootstrap: roles+extensions, passwords, keycloak DB
ops/docker/Dockerfile.{api,worker,web}   demo images (node:24.11.0-alpine, non-root)
ops/Caddyfile                same-origin proxy: /api/* → api, everything else → web
ops/seed-demo.ts             synthetic tenants/documents (npm run demo:seed)
```

## Production posture (this stack is a DEMO)

- Demo images run the repo through `tsx`; production images compile and strip
  tooling (G5 hardening runbook, ADR-0011).
- `SESSION_COOKIE_SECURE=false` and HTTP are localhost-only; production requires
  Secure cookies + TLS (the `__Host-` prefix rules are enforced at startup).
- MinIO uses a **static demo KMS key** (`MINIO_KMS_SECRET_KEY`) so SSE-S3 works
  without KES; production uses KES + an operator-managed key.
- Keycloak is demo-only (ADR-0004); production uses any conforming OIDC provider.
- Runbooks: `docs/ops/{upgrade,rollback,incident,key-rotation,provider-outage,
  offboarding,backup-restore,envelope}.md`.

## Teardown

```bash
docker compose -f ops/compose.yml down -v     # -v wipes demo data volumes
```

## Troubleshooting

- **Playwright**: the console's browser tests need `npx playwright install chromium`
  (see README.md §Web console).
- **Seed fails to connect**: the DB port is `55432` on the host (compose), and the
  seed reads `PGPASSWORD` — source `ops/.env` first: `set -a; . ops/.env; set +a`.
- **Login loops**: check `OIDC_ISSUER`/`OIDC_REDIRECT_URI` in ops/.env match the
  realm (`http://localhost:8180/realms/securerag-demo`, redirect
  `http://localhost:8080/api/auth/callback`) — the API validates `iss` exactly.
