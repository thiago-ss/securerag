# Keycloak demo realm — SecureRAG OIDC (S1)

Keycloak is DEMO-ONLY (ADR-0004): `quay.io/keycloak/keycloak:26.7.0` (research r2), used by the `docker
compose` demo (ops compose lands in S10). CI never runs Keycloak — tests use the deterministic in-process
fake provider (`packages/security/src/testkit.ts`), which implements the same contract asserted here.
Production uses any conforming OIDC provider.

## Realm configuration (import file `realm-securerag-demo.json`)

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
      "redirectUris": ["http://localhost:3000/auth/callback", "https://securerag.example/auth/callback"],
      "webOrigins": ["http://localhost:3000"],
      "postLogoutRedirectUris": ["http://localhost:3000/", "https://securerag.example/"],
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
    { "username": "alice", "enabled": true, "emailVerified": true,
      "email": "alice@securerag.example", "firstName": "Alice",
      "credentials": [{ "type": "password", "value": "alice-demo-password", "temporary": false }] },
    { "username": "carol", "enabled": true, "emailVerified": true,
      "email": "carol@securerag.example", "firstName": "Carol",
      "credentials": [{ "type": "password", "value": "carol-demo-password", "temporary": false }] }
  ]
}
```

## Container (ops compose, S10)

```yaml
keycloak:
  image: quay.io/keycloak/keycloak:26.7.0
  command: ["start-dev", "--import-realm", "--hostname=localhost"]
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
    - ./ops/keycloak/realm-securerag-demo.json:/opt/keycloak/data/import/realm-securerag-demo.json:ro
  ports: ["8080:8080"]        # management console http://localhost:8080 (dev mode)
  mem_limit: 2g               # research r2: Java heap sizing requires a memory limit
```

## SecureRAG API environment for the demo

```
OIDC_ISSUER=http://localhost:8080/realms/securerag-demo
OIDC_CLIENT_ID=securerag-api
OIDC_REDIRECT_URI=http://localhost:3000/auth/callback
OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:3000/
OIDC_DISCOVERY_URL=http://localhost:8080/realms/securerag-demo/.well-known/openid-configuration
SESSION_COOKIE_SECURE=false   # localhost demo only; production MUST be true (__Host- prefix)
```

Notes:

- The API requests `openid profile` scope; `displayName` maps `preferred_username` → `name` → `sub`.
- RP-initiated logout redirects to `end_session_endpoint?post_logout_redirect_uri=...` (no `id_token_hint`,
  the raw id_token is not retained).
- Principal provisioning in the demo: the realm user's `sub` becomes `external_subject` with
  `provider = OIDC_ISSUER`; tenant membership/role assignment is a SecureRAG admin operation
  (POST /memberships), never a Keycloak role.
