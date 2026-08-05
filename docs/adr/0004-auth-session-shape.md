# ADR 0004 — Auth and session shape (D2)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r2-oidc-session.md

## Decision

- **OIDC**: Authorization Code + PKCE (RFC 7636) for web clients; JWKS-based signature verification.
  Provider interface: discovery document, authorization URL, token exchange, JWKS, userinfo,
  RP-initiated logout. Local/demo identity: Keycloak 26.7.0 with a synthetic realm. Production:
  any conforming OIDC provider (documented requirements).
- **id_token validation checklist** (12 items, from research): nested-JWT handling; `iss` exact
  match; `aud` contains client_id; `azp` = client_id when present; signature via JWKS (no code-flow
  TLS exemption); `alg` allowlist RS256/ES256 (reject `none`, `HS*`); `exp`; `iat` skew; `nonce`
  presence + equality + replay; `auth_time`/`max_age`; `acr` when requested; `at_hash`/`c_hash`.
- **Session**: server-side session row in PostgreSQL (principal, csrf_token, expires_at,
  revoked_at). Cookie `__Host-securerag_session`, `HttpOnly`, `Secure`, `SameSite=Lax`. CSRF
  defense via same-site cookie + custom header check on state-changing routes. Logout deletes the
  session row and performs RP-initiated logout.
- **Revocation epoch**: monotonic counter bumped on membership/group/grant/document/retention
  changes; checked at disclosure time (before the first response byte of any authorized surface).

## Consequences

- No custom IAM; session row is auditable; revocation is epoch-based and testable for staleness.
- Keycloak is demo-only (Java/Quarkus, ~1–2 GB container) — documented, not part of production
  deployment envelope.
