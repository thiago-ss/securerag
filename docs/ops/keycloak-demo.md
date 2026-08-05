# Keycloak demo realm — SecureRAG OIDC (S1, compose wiring S10)

Keycloak is DEMO-ONLY (ADR-0004): `quay.io/keycloak/keycloak:26.7.0` (research r2), used by the `docker
compose` demo (`ops/compose.yml`). CI never runs Keycloak — tests use the deterministic in-process
fake provider (`packages/security/src/testkit.ts`), which implements the same contract asserted here.
Production uses any conforming OIDC provider.

## Realm configuration (import file `ops/keycloak-realm.json`)

The committed realm (S10) matches the shape below, with two changes that make the
demo deterministic:

1. **Pinned user ids** — Keycloak preserves user ids on realm import, so the demo
   seed (`ops/seed-demo.ts`) can pre-create principals with
   `external_subject = <pinned id>` and `provider = OIDC_ISSUER`:
   - alice: `00000000-0000-4000-8000-000000000001` (alice-demo-password)
   - carol: `00000000-0000-4000-8000-000000000002` (carol-demo-password)
2. **Proxy redirect URIs** — the console and the API are same-origin behind the
   Caddy proxy (`ops/Caddyfile`): `http://localhost:8080/api/auth/callback`
   (plus `http://localhost:3000/auth/callback` for local dev runs).

```jsonc
{
  "realm": "securerag-demo",
  "enabled": true,
  "registrationAllowed": false,
  "sslRequired": "external",            // compose dev: Keycloak behind the API on localhost
  "accessTokenLifespan": 300,
  "accessCodeLifespan": 300,
  "clients": [
    {
      "clientId": "securerag-api",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,            // confidential web client (the Fastify API is the RP/BFF)
      "standardFlowEnabled": true,      // Authorization Code flow only
      "implicitFlowEnabled": false,     // OAuth 2.1: no implicit grant
      "directAccessGrantsEnabled": false, // no password grant (OAuth 2.1 removed)
      "serviceAccountsEnabled": false,
      "redirectUris": ["http://localhost:8080/api/auth/callback", "http://localhost:3000/auth/callback"],
      "webOrigins": ["http://localhost:8080", "http://localhost:3000"],
      "postLogoutRedirectUris": ["http://localhost:8080/", "http://localhost:3000/"],
      "attributes": {
        "pkce.code.challenge.method": "S256",   // RFC 7636 S256 is mandatory (research r2 §PKCE)
        "pkce.not.confidential": "false",       // confidential client still REQUIRES PKCE per RFC 9700 §2.1.1
        "backchannel.logout.session.required": "false"
      },
      "protocolMappers": [
        { "name": "preferred_username", "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-attribute-mapper",
          "config": { "user.attribute": "username", "claim.name": "preferred_username",
                      "access.token.claim": "true", "id.token.claim": "true" } },
        { "name": "full_name", "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-attribute-mapper",
          "config": { "user.attribute": "firstName", "claim.name": "name",
                      "access.token.claim": "true", "id.token.claim": "true" } }
      ]
    }
  ],
  "idTokenSignedResponseAlg": "RS256",          // SecureRAG allowlist: RS256/ES256 only
  "idTokenEncryptionAlgValuesSupported": [],    // no encryption negotiated → nested JWTs rejected
  "users": [
    { "id": "00000000-0000-4000-8000-000000000001", "username": "alice", "enabled": true,
      "emailVerified": true, "email": "alice@securerag.example", "firstName": "Alice",
      "credentials": [{ "type": "password", "value": "alice-demo-password", "temporary": false }] },
    { "id": "00000000-0000-4000-8000-000000000002", "username": "carol", "enabled": true,
      "emailVerified": true, "email": "carol@securerag.example", "firstName": "Carol",
      "credentials": [{ "type": "password", "value": "carol-demo-password", "temporary": false }] }
  ]
}
```

## Container (ops/compose.yml, S10)

```yaml
keycloak:
  image: quay.io/keycloak/keycloak:26.7.0
  command: ["start-dev", "--import-realm"]
  environment:
    KEYCLOAK_ADMIN: admin
    KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD:-admin-demo}
    KC_DB: postgres
    KC_DB_URL: jdbc:postgresql://db:5432/keycloak
    KC_DB_USERNAME: keycloak
    KC_DB_PASSWORD: ${KEYCLOAK_DB_PASSWORD}
    KC_BOOTSTRAP_ADMIN_USERNAME: admin
    KC_BOOTSTRAP_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD:-admin-demo}
  volumes:
    - ./keycloak-realm.json:/opt/keycloak/data/import/securerag-demo.json:ro
  ports: ["8180:8080"]        # management console http://localhost:8180 (dev mode)
  mem_limit: 2g               # research r2: Java heap sizing requires a memory limit
```

Note: the management port moved from 8080 to **8180** in S10 — the Caddy proxy
owns 8080 for the same-origin console/API.

## SecureRAG API environment for the demo

```
OIDC_ISSUER=http://localhost:8180/realms/securerag-demo
OIDC_CLIENT_ID=securerag-api
OIDC_REDIRECT_URI=http://localhost:8080/api/auth/callback
OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:8080/
OIDC_DISCOVERY_URL=http://localhost:8180/realms/securerag-demo/.well-known/openid-configuration
SESSION_COOKIE_SECURE=false   # localhost demo only; production MUST be true (__Host- prefix)
```

Notes:

- The API requests `openid profile` scope; `displayName` maps `preferred_username` → `name` → `sub`.
- RP-initiated logout redirects to `end_session_endpoint?post_logout_redirect_uri=...` (no `id_token_hint`,
  the raw id_token is not retained).
- Principal provisioning in the demo: the realm user's `sub` becomes `external_subject` with
  `provider = OIDC_ISSUER`; tenant membership/role assignment is a SecureRAG admin operation
  (POST /memberships), never a Keycloak role.
