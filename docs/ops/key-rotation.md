# Key rotation runbook — OIDC signing keys, session HMAC, object-store keys

Version: 0.x (construction). Cross-links: [incident.md](incident.md),
[provider-outage.md](provider-outage.md), [backup-restore.md](backup-restore.md).

## What rotates (and what it breaks)

| Secret | Owner | Rotation effect |
| --- | --- | --- |
| OIDC provider signing key (Keycloak realm key) | IdP operator | NO session impact: id_tokens are verified against the JWKS **at login time**; existing server-side sessions are unaffected. Users may need to re-login only if the provider forces it. |
| Session token HMAC secret (`SESSION_HMAC_SECRET`, packages/security) | platform operator | **All sessions invalid**: users must re-login. Budget this. |
| Object-store credentials (MinIO/S3 access key) | platform operator | API+worker keep serving with the new key after rollout; old objects stay readable (they are keyed by the bucket, not by the credential). |
| DB role passwords (securerag_*) | platform operator | **No session impact** but pool restarts: rollout api+worker, then migrate/purge jobs resume. |
| KMS/SSE-S3 key (KES, production) | object-storage operator | New writes use the new key; existing objects remain readable (key versioning) — verify per the storage operator's rotation contract. |

## Rules

1. Rotate one secret at a time; rehearse the exact sequence in a staging clone first.
2. **Never rotate through file edits in the running container** — change the secret
   manager value, then redeploy so the process reads it at startup (startup env
   validation fails loudly on a missing/blank value).
3. Sessions are server-side rows: rotation of the session HMAC invalidates them
   deterministically (they fail signature verification); there is no partial window.
4. After rotating DB passwords, `pg_isready` + `/readyz` (SELECT 1) prove connectivity
   for each role before traffic returns.

## Procedure (rehearsed)

```bash
# 1. Stage: write the new values to the secret manager (never to git; the
#    committed .env.example holds demo placeholders only).

# 2. Object-store credentials (no downtime):
docker compose -f ops/compose.yml up -d --force-recreate api worker
#    (services read MINIO_ROOT_USER/MINIO_ROOT_PASSWORD at startup)

# 3. DB role passwords (drain then switch; worker idempotency keys make
#    interrupted jobs safe):
docker compose -f ops/compose.yml exec -T db psql -U postgres -c \
  "ALTER ROLE securerag_api LOGIN PASSWORD '…new…';"
docker compose -f ops/compose.yml up -d --force-recreate api worker
curl -fsS http://localhost:8080/api/readyz   # SELECT 1 via the NEW credential

# 4. Session HMAC (announce re-login):
#    - update SESSION_HMAC_SECRET in the secret manager
#    - redeploy api (all sessions now 401; console shows the login page)
#    - verify: one login, /auth/me 200, then readiness sweep

# 5. IdP signing key: rotate in Keycloak (realm keys tab). The API re-fetches
#    the JWKS lazily; no restart needed. Verify a fresh login immediately.

# 6. Post-rotation evidence: audit shows a fresh login wave (expected); no
#    session errors in traces beyond the invalidation instant; run the
#    adversarial suite (npm run test:security) on the same image.
```

## Honest limits

- **Session HMAC rotation = mass re-login.** There is no grace period by design
  (a compromised HMAC grants session forgery; the narrow fix is total invalidation).
- **id_token secrets are never retained** (ADR-0004): RP-initiated logout omits
  `id_token_hint`, so provider-side rotation cannot affect us beyond login.
- Keycloak realm key rotation is a provider-side procedure; SecureRAG's contract is
  only "JWKS must stay reachable" (provider-outage.md).
- Demo KMS key (`MINIO_KMS_SECRET_KEY` in ops/.env.example) is a **static demo key**;
  production rotates through KES. Its exposure is contained to the demo stack.
