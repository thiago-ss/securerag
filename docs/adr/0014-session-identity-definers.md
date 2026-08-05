# ADR 0014 — Session/identity SECURITY DEFINER functions (S1)

- Status: accepted
- Date: 2026-08-05
- Sources: ADR-0004 (auth + session shape), ADR-0013 (epoch write path precedent), research r2

## Context

S1 ships real OIDC login. Three database operations cannot be expressed through the RLS policies as the
runtime role:

1. **`upsert_principal`** — `principals.principal_scope` has `WITH CHECK (principal_id = ctx_principal_id())`,
   but a first-time login has no principal id yet (chicken-and-egg). The upsert must also be idempotent on
   `(provider, external_subject)` and must never reveal whether a principal already existed (no existence
   oracle).
2. **`get_session`** — sessions are RLS-scoped to the owning principal, but session lookup happens from the
   opaque bearer cookie BEFORE any identity is known. The bearer token is the credential; validity (expiry +
   revocation) is enforced inside SQL so foreign/expired/revoked lookups are byte-identical at the API.
3. **`revoke_session`** — logout must be idempotent and reachable without a principal context.

A plain `SECURITY DEFINER` function owned by `securerag_owner` does NOT solve this: the owner is
`NOBYPASSRLS` (bootstrap 0001), so the definer's own SELECT/INSERT/UPDATE would still be filtered by the
same policies with no context set. The owner must also stay `NOBYPASSRLS` because the migration role holds
owner membership.

## Decision

- New NOLOGIN role **`securerag_session_lookup`**: `NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  BYPASSRLS`. It is granted to **nobody at runtime** (only to the NOLOGIN `securerag_owner` so the
  migration can create functions owned by it). The api/worker roles hold no membership anywhere on that
  chain, cannot `SET ROLE` to it, and reach it ONLY through the three functions it owns.
- Three `SECURITY DEFINER` functions owned by `securerag_session_lookup` (migration 0005), all with pinned
  `search_path = securerag, pg_catalog`, PUBLIC execute revoked, EXECUTE granted to `securerag_api` only:
  - `upsert_principal(provider, external_subject, display_name) RETURNS uuid` — `INSERT ... ON CONFLICT
    (provider, external_subject) DO UPDATE SET display_name = EXCLUDED.display_name RETURNING principal_id`.
    Always returns the id; existing-vs-new is indistinguishable to callers.
  - `get_session(token_hash bytea) RETURNS TABLE(...)` — lookup by sha256(token) with
    `expires_at > now() AND revoked_at IS NULL` inside the WHERE clause. Zero rows for foreign/expired/
    revoked alike.
  - `revoke_session(token_hash bytea) RETURNS boolean` — idempotent `UPDATE ... WHERE revoked_at IS NULL`.
- This is the documented, catalog-tested exception to the no-SECURITY-DEFINER rule (AGENTS.md), extending
  ADR-0013's precedent: tiny typed interfaces, no injection surface, DDL-time schema `CREATE` for the
  function-owner role is revoked immediately after creation in 0005.
- `bump_authorization_epoch` remains owner-owned (unchanged).

## Threat-model notes

- A database leak yields only token hashes (sessions.token_hash), never live credentials; the 256-bit
  token itself lives only in the `__Host-` cookie.
- The BYPASSRLS role can read sessions/principals only through the three functions; the api role can call
  them only with the exact signatures; `get_session`'s lookup key is the unforgeable token hash.
- The migration role can transitively `SET ROLE securerag_session_lookup` (via owner membership) — it can
  already perform arbitrary DDL as owner (including dropping policies), so this adds no new capability.

## Consequences

- Catalog tests assert the exact definer set (`bump_authorization_epoch` owner-owned; the three S1
  definers session-lookup-owned), pinned search_path, PUBLIC revocation, api-only EXECUTE, the
  session-lookup role attributes, and that no runtime role can reach it.
- RLS still governs ALL direct runtime-role access to sessions/principals; the definers are the sole
  bypass surface and are audited by the catalog/exploit tests (rls-behavior).
