# R2 — OIDC / PKCE / JWKS / Keycloak / Session Security (Research Findings)

Research-only document for SecureRAG's identity layer. Primary sources only (openid.net specs, IETF RFCs, keycloak.org docs). No code decisions made here.

## Verified versions (as of 2026-08-05)

| Artifact | Version | Date / status |
|---|---|---|
| OpenID Connect Core 1.0 | Final, incorporating **errata set 2** | December 15, 2023 (current; supersedes errata set 1 of Nov 2014) |
| OIDC RP-Initiated Logout 1.0 | Final | September 12, 2022 |
| RFC 7636 (PKCE) | Proposed Standard | September 2015 (no errata affecting this research) |
| RFC 9700 (OAuth 2.0 Security BCP) | **BCP 240**, Best Current Practice | May 2025 |
| RFC 9325 (TLS/DTLS recommendations) | **BCP 195**, Best Current Practice | November 2022 (obsoletes RFC 7525; updated by RFC 9852, RFC 10015) |
| RFC 7517 (JWK) | Proposed Standard | May 2015 |
| RFC 9207 (iss in authorization response) | Proposed Standard | March 2022 |
| RFC 9126 (PAR) | Proposed Standard | September 2021 |
| RFC 8414 (Authorization Server Metadata) | Proposed Standard | June 2018 |
| RFC 6265 (cookies) / draft-ietf-httpbis-rfc6265bis-22 | RFC 6265 (2011) is still the RFC; 6265bis (defines SameSite, `__Host-`/`__Secure-`) is in the **RFC Editor queue** (draft -22, Dec 1, 2025, expires June 4, 2026). Browsers already implement its semantics. | |
| OAuth 2.1 | Internet-Draft `draft-ietf-oauth-v2-1` (latest **-15**; -11 published May 15, 2024, expired & archived). Will obsolete RFC 6749/6750 when published. | Work in progress |
| Keycloak | **26.7.0** (Docker `quay.io/keycloak/keycloak:26.7.0`) | GitHub release 2026-07-09; downloads page shows 26.7.0 |

**Correction to the research task brief:** the brief said "BCP 195 RFC 9700". RFC 9700 is **BCP 240** (OAuth 2.0 Security). **BCP 195 is RFC 9325**, the TLS/DTLS recommendations (the TLS BCP that RFC 7636 §7.5 points to). Both are cited below under their correct numbers.

## id_token validation checklist

From OIDC Core §3.1.3.7 (Authorization Code Flow — the flow SecureRAG uses), §3.2.2.11 / §3.3.2.12 (implicit/hybrid), §2 (claims), §10.1 (signing). A client MUST validate the ID Token as follows:

1. **Encryption/decryption first**: if the ID Token is encrypted (nested JWT, signed-then-encrypted per §2), decrypt with the keys/algorithms negotiated at registration; if encryption was negotiated and the token is not encrypted, SHOULD reject it.
2. **iss**: MUST exactly match the issuer identifier obtained from Discovery (string comparison); reject otherwise.
3. **aud**: MUST contain the client's `client_id` as an audience; MUST reject if the client is not listed as an audience **or** if the token contains additional audiences not trusted by the client. (`aud` may be a single string or an array.)
4. **azp**: if present (extensions only), SHOULD validate per the extension; when `azp` is present the client SHOULD verify `client_id` equals the `azp` value.
5. **Signature**: MUST validate the JWS signature using the algorithm in the JWT `alg` header and the keys provided by the issuer (`jwks_uri`), per JWS. (OIDC Core §3.1.3.7 permits skipping signature validation when the token arrives over direct TLS from the Token Endpoint — **do not rely on that exemption**; RFC 9700 §2.1.1/§4.5.3 and OAuth 2.1 require signature verification, and it defeats the `none`/alg-confusion attacks below.)
6. **alg**: default is `RS256` (or the registered `id_token_signed_response_alg`). Reject `none` (OIDC Core §2 allows `none` only for code flow when explicitly requested at registration — never acceptable in SecureRAG). Reject MAC-based algorithms (`HS256/384/512`) for public clients — OIDC Core §3.1.3.7 defines HS* verification using the `client_secret` as the key, which is an alg-confusion vector unless the key is confidential (pin the allowlist to asymmetric `RS256`/`ES256`).
7. **exp**: current time MUST be before `exp` (small leeway for clock skew only, typically a few minutes at most).
8. **iat**: SHOULD reject tokens issued too far from the current time; the acceptable range is client-specific and also bounds how long nonces must be stored for replay protection.
9. **nonce**: if a `nonce` was sent in the Authentication Request, the `nonce` claim MUST be present and MUST equal the value sent; SHOULD check the nonce for replay (one-time use); nonces MUST have sufficient entropy (§3.1.2.1).
10. **auth_time**: if requested (or `max_age` used), SHOULD check it and require re-authentication if too much time elapsed.
11. **acr**: if requested, SHOULD check the asserted value is appropriate.
12. **at_hash / c_hash**: if present in the code flow, MAY validate `at_hash` against the access token (§3.1.3.8); in hybrid flows `c_hash`/`at_hash` MUST be validated.

**When the ID Token is required vs optional:** the ID Token is the authentication artifact. With `openid` scope in the Authorization Code Flow, the Token Endpoint response **MUST include an `id_token`** (OIDC Core §3.1.3.3) and the RP authenticates the user only after validating it. In plain OAuth 2.0 (no `openid` scope) no ID Token exists; without it there is **no** authentication, only authorization — SecureRAG must always request `openid` and treat a missing/unvalidatable ID Token as "no authenticated principal" (default deny).

## PKCE / CSRF notes

- **RFC 7636 mechanics**: client generates a fresh `code_verifier` (43–128 unreserved characters, **minimum 256 bits of entropy** — a 32-octet random value, base64url-encoded), sends `code_challenge = BASE64URL(SHA256(code_verifier))` with `code_challenge_method=S256` in the authorization request, and sends the raw `code_verifier` at the token endpoint. Server MUST compare `BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge` before issuing tokens; mismatch = `invalid_grant`. `S256` is Mandatory To Implement; `plain` MUST NOT be used in new implementations and MUST NOT be downgraded to after trying S256 (§7.2).
- **Who must use it**: PKCE was designed for public/native clients (authorization code interception attack, §1) and is REQUIRED for public clients per RFC 9700 §2.1.1. For **confidential web clients** (SecureRAG API): **RECOMMENDED** by RFC 9700 §2.1.1 — it additionally prevents authorization code injection and CSRF even against strong attackers. OAuth 2.1 will require PKCE for all public clients and includes it in the code flow. So: PKCE mandatory for the SPA/browser clients; strongly recommended for the confidential web app too.
- **Server-side obligations** (RFC 9700 §2.1.1, §4.8.2): servers MUST support PKCE; if a `code_challenge` was sent, the server MUST enforce `code_verifier`; servers MUST mitigate the **PKCE downgrade attack** (reject a token request carrying `code_verifier` when no `code_challenge` was in the authorization request). Keycloak does this.
- **CSRF via state + nonce**: `state` is RECOMMENDED (OIDC Core §3.1.2.1) as an opaque value cryptographically bound to a browser cookie — the classic CSRF mitigation. RFC 9700 §4.7.1: if the AS supports PKCE, **PKCE or the OIDC `nonce` provides the CSRF protection** (this is why the nonce must be checked even when the ID Token arrives via the token endpoint); otherwise one-time CSRF tokens in `state` bound to the user-agent session MUST be used. State must be **one-time use and invalidated after first use** (§4.2.4) and, if it carries application state, MUST be protected against tampering/swapping (bind to session and/or sign/encrypt, §4.7.1). The nonce binds the ID Token to the client session and mitigates replay (OIDC Core §15.5.2); `state` also mitigates login CSRF (RFC 6749 §10.12).
- **Code binding**: the PKCE challenge or OIDC nonce MUST be transaction-specific and securely bound to the client and the user agent that started the transaction (RFC 9700 §2.1.1). Keycloak rejects constant/non-random challenges as a policy option.

## JWKS notes

- **Format**: RFC 7517 defines the JWK and JWK Set (`{"keys": [...]}`). The RP fetches the issuer's public keys from the `jwks_uri` discovered via OIDC Discovery / RFC 8414 metadata (must be https, hostname-verified).
- **kid/alg handling (alg confusion)**: the JWS `alg` header is attacker-visible and MUST be validated against a fixed allowlist — pin `RS256`/`ES256` (asymmetric), **reject `none` and all HMAC (`HS*`) algs** (an HMAC "HS256" token signed with an exposed public key is a classic forgery vector; per OIDC Core §3.1.3.7 HS* keys derive from `client_secret`, which for a public client is not a secret at all). Select the key by `kid`; if `kid` is missing or unknown, reject or re-fetch once. Validate `kty`/`use`/`alg` consistency of the chosen key.
- **Fetching/caching**: fetch over TLS from the issuer's own metadata. RFC 7517 itself does not prescribe caching; OIDC Core §10.1.1 ("Rotation of Asymmetric Signing Keys") prescribes the operational model: signer publishes keys at `jwks_uri`, signals the active key via `kid` in each JOSE header, rolls by adding new keys to the set, and the verifier **re-fetches on an unfamiliar `kid`**; the set SHOULD retain recently decommissioned keys for a reasonable period for smooth transition. §10.2.1 additionally recommends the `jwks_uri` response carry `Cache-Control: max-age=...` so the set can be cached and the cache duration coordinated with key rotation (i.e., cache the JWK set with a TTL, re-fetch on unknown `kid`, never fetch per-request in hot paths, never cache beyond the rotation overlap window).

## Keycloak demo notes

- **Current version**: 26.7.0 (released 2026-07-09; keycloak.org/downloads and GitHub releases agree). Docker image `quay.io/keycloak/keycloak:26.7.0` (also on Docker Hub).
- **Default ports** (keycloak.org server container guide, "Running Keycloak in a container"): server listens on **8080 (HTTP) and 8443 (HTTPS)** by default; the management interface (health/metrics, when `KC_HEALTH_ENABLED`/`KC_METRICS_ENABLED`) is on **9000** (`/health`, `/health/ready`, `/health/live`, `/metrics`). Dev mode (`start-dev`) serves the admin console at `http://localhost:8080/` (root context); in dev mode Keycloak binds to all interfaces (0.0.0.0) — bind to `127.0.0.1` in compose. Bootstrap admin in the container via `KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD`; demo realms can be auto-imported with `--import-realm` from `/opt/keycloak/data/import` (realm = SecureRAG "tenant" analog).
- **Java-based resource use**: Keycloak is a Java 25+ / Quarkus application (getting-started OpenJDK guide requires OpenJDK 25; container image ships its own JRE). Heap is sized as a percentage of container memory (`-XX:MaxRAMPercentage=70`), so the container memory limit must be set; Keycloak docs recommend a minimum of ~750 MB limit, ~2 GB for small production deployments. This is heavier than a Go/Rust identity layer but **acceptable for a Docker-based local/demo identity provider** (SecureRAG's OIDC signing keys remain excluded from the app-level guarantee per the threat model).
- **Relevant capabilities**: supports PKCE (`code_challenge_methods_supported` in its OIDC discovery document), PAR (feature `par:v1`), RS256/ES256 signing, RP-initiated logout (`end_session_endpoint`), and standard flow (Authorization Code) for browser clients. For the demo: one realm, `openid` scope, public client with PKCE for the SPA, confidential client with PKCE for the API, `start-dev` + PostgreSQL backend matching the existing compose stack.

## Session cookie security notes

- **Cookie spec state**: RFC 6265 (2011) is still the published RFC; draft-ietf-httpbis-rfc6265bis (-22, Dec 2025) is in the RFC Editor queue and is the de-facto standard implemented by browsers. It standardizes `SameSite`, `__Host-`/`__Secure-` prefixes, and defaults.
- **Required attributes for a session cookie**: `Secure` (only over HTTPS) + `HttpOnly` (never exposed to JS). **`__Host-` prefix** (§4.1.3.2): a cookie named `__Host-*` is only accepted by user agents if it was set **with `Secure`, `Path=/`, and no `Domain` attribute** — this pins the cookie to a single host (host-only), eliminating subdomain leakage; it is the recommended hardening for SecureRAG's session cookie. Note the same `__Host-` cookie is shared across ports.
- **SameSite**: `Lax` is the default enforcement when the attribute is absent or invalid (§4.1.2.7). Trade-offs: `Lax` sends the cookie on same-site requests and cross-site **top-level navigations** — precisely what the OIDC redirect back to the RP's callback is — while still blocking cross-site subresource/CSRF requests. `Strict` blocks cookies on all cross-site top-level navigations, which would break the OIDC redirect callback (the callback would arrive without the session cookie) — `Strict` is NOT appropriate for an RP that receives OIDC redirects. Use `SameSite=Lax` (never `None` — `None` requires `Secure` and defeats CSRF defense). CSRF on the callback is then handled at the application layer by the `state`/`nonce` binding (see above).
- **Session fixation**: issue a fresh session ID (and rotate any `state`/nonce) at the start of every OIDC flow; the `state` value must be bound to the pre-login user-agent session and invalidated on first use (RFC 9700 §4.2.4), so a pre-injected session cannot be "fixed" by the attacker's response.
- **Logout**: use **OIDC RP-Initiated Logout 1.0** — RP redirects the user agent to the OP's `end_session_endpoint` with `id_token_hint` (RECOMMENDED; OP validates it issued the token, §2), optional `post_logout_redirect_uri` (MUST be pre-registered via `post_logout_redirect_uris`, and `state` is used for the post-logout callback), §3. Local session must be destroyed server-side (delete session row + expire the `__Host-` cookie) regardless of OP outcome; logout requests without a valid `id_token_hint` are a DoS vector and the OP should confirm with the user (§6). For OP-initiated logout of other sessions, OIDC Back-Channel Logout 1.0 (uses the `sid` claim) or Front-Channel Logout 1.0 exist as companion specs.
- **Expiry vs revocation**: the ID Token `exp` is unrelated to the RP session lifetime (OIDC Core §2 explicit NOTE; §16.18 "Lifetimes of Access Tokens and Refresh Tokens" — access tokens are short-lived, refresh tokens longer, and both SHOULD be revocable). The RP session must have its own expiry and be terminated on logout; revocation of the OP-side session/refresh tokens is an OP concern (RP-initiated logout, plus RFC 7009 token revocation where supported). Access-token expiry bounds the RP's own "stale session" window; the RP must never treat an unexpired ID Token as proof the user is still logged in — re-validate (or re-authenticate) per policy.

## OAuth 2.1 pointers

- **OAuth 2.1** (`draft-ietf-oauth-v2-1`, latest -15) will obsolete RFC 6749/6750 and consolidates the security BCPs. Key deltas for SecureRAG: implicit grant removed; resource-owner-password grant removed; **PKCE required** for public clients and included in the code flow; **exact redirect-URI matching** required; sender-constrained tokens (DPoP RFC 9449, mTLS RFC 8705) recommended; refresh-token rotation recommended for public clients.
- **BCP 240 (RFC 9700)** is the current published guidance and the practical target: PKCE (REQUIRED public, RECOMMENDED confidential), exact redirect URI matching, no open redirectors, issuer identification (**RFC 9207** `iss` parameter — validate it in the authorization response), prevent mix-up attacks, no tokens in URLs, `state`/`nonce` CSRF rules, authorization-code one-time use, audience-restricted access tokens, end-to-end TLS per BCP 195 (RFC 9325).
- **PAR (RFC 9126)**: push the authorization request directly to the AS via POST (client authenticated) in exchange for a one-time, short-lived `request_uri` used at the authorization endpoint — removes request parameters from the browser URL/logs (privacy + integrity). Advertised via metadata `pushed_authorization_request_endpoint` / `require_pushed_authorization_requests` (§5). Optional for SecureRAG demo (Keycloak has the feature), recommended for production hardening.
- **Authorization Server Metadata (RFC 8414)**: the AS publishes `issuer`, endpoint URLs, `jwks_uri`, `code_challenge_methods_supported`, `authorization_response_iss_parameter_supported` (RFC 9207 §3), PAR metadata. RP MUST consume this via OIDC Discovery instead of hard-coding endpoints — this is also how the `jwks_uri` for signature verification is anchored.

## Sources

- OpenID Connect Core 1.0 incorporating errata set 2 (final, 2023-12-15): https://openid.net/specs/openid-connect-core-1_0.html (§2 ID Token; §3.1.2.1 auth request incl. state/nonce; §3.1.3.3 successful token response; §3.1.3.7 ID Token validation; §3.1.3.8 at_hash; §3.2.2.11 / §3.3.2.12; §10.1.1 key rotation; §15.5.2 nonce notes; §16.18 token lifetimes)
- OpenID Connect RP-Initiated Logout 1.0 (final, 2022-09-12): https://openid.net/specs/openid-connect-rpinitiated-1_0.html
- RFC 7636 — Proof Key for Code Exchange (PKCE), Sept 2015: https://www.rfc-editor.org/rfc/rfc7636 (§4.1–4.6 protocol; §7 security incl. S256 MTI, no downgrade, entropy)
- RFC 9700 — Best Current Practice for OAuth 2.0 Security, BCP 240, May 2025: https://www.rfc-editor.org/rfc/rfc9700 (§2.1.1 code grant + PKCE; §2.6 metadata; §4.2.4 state invalidation; §4.5.3 code injection countermeasures; §4.7.1 CSRF countermeasures; §4.8 PKCE downgrade)
- RFC 9325 — Recommendations for Secure Use of TLS and DTLS, BCP 195, Nov 2022 (obsoletes RFC 7525): https://www.rfc-editor.org/rfc/rfc9325
- RFC 7517 — JSON Web Key (JWK), May 2015: https://www.rfc-editor.org/rfc/rfc7517 (§4.5 kid; §5 JWK Set; §9.1 key provenance)
- RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification, Mar 2022: https://www.rfc-editor.org/rfc/rfc9207 (§2.4 validation; §3 metadata flag)
- RFC 9126 — OAuth 2.0 Pushed Authorization Requests, Sept 2021: https://www.rfc-editor.org/rfc/rfc9126 (§2 endpoint; §5 metadata)
- RFC 8414 — OAuth 2.0 Authorization Server Metadata, June 2018: https://www.rfc-editor.org/rfc/rfc8414
- RFC 6265 — HTTP State Management Mechanism, Apr 2011: https://www.rfc-editor.org/rfc/rfc6265 ; successor draft-ietf-httpbis-rfc6265bis-22 (RFC Ed Queue, 2025-12-01): https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/ (§4.1.2.7 SameSite incl. Lax default; §4.1.3.2 __Host-; §5.6.7)
- OAuth 2.1 draft (latest -15; -11 = May 2024): https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/ (§10 differences from 2.0; §2.3 redirect/CSRF; §4.1 code grant; §7.9 CSRF)
- Keycloak downloads (26.7.0): https://www.keycloak.org/downloads ; GitHub release: https://github.com/keycloak/keycloak/releases (26.7.0, 2026-07-09)
- Keycloak "Running Keycloak in a container" guide (ports 8080/8443/9000; JVM heap sizing; admin bootstrap; import-realm): https://www.keycloak.org/server/containers
- Keycloak "OpenJDK" getting-started guide (OpenJDK 25 prerequisite; admin console at http://localhost:8080/; realm setup): https://www.keycloak.org/getting-started/getting-started-zip
