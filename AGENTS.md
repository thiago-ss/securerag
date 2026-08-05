# AGENTS.md — SecureRAG repository rules

This is a security-critical repository. Every agent (human or AI) must follow these rules.

## Never

- Never `git add .` or `git add -A` in a nested/dirty repo. Stage explicit paths only.
- Never commit secrets, `.env`, local data, agent scratch logs, build output, canary values,
  reports containing canaries, or generated secrets. `gitignore` covers common paths; verify
  staged content before every commit.
- Never mock RLS. RLS tests always run against real PostgreSQL with the actual least-privileged
  runtime role (Testcontainers).
- Never read or print secret file contents into logs/commits/discussion.
- Never commit a failing test suite or broken build. TDD red states stay local.
- Never use session-level tenant settings; never let application code filter by tenant after SQL
  returned rows.
- Never use `SECURITY DEFINER` without a dedicated ADR and exploit tests; prefer
  `security_invoker` views/functions.
- Never commit placeholders, disabled/skipped/focused tests, unreviewed snapshots.
- Never amend published commits, force-push, `reset --hard`, `clean`, or delete user work.

## Domain and security invariants

- Read `CONTEXT.md` for the ubiquitous language and the core authorization invariant
  `Allowed(P,T) = tenant ∩ membership ∩ grant ∩ visible version ∩ retention ∩ PII scope`.
- Default deny. Foreign and nonexistent resources are indistinguishable (same status/schema).
- The LLM never decides authorization. Deterministic controls enforce it inside SQL before any
  content/IDs leave PostgreSQL.
- Two-stage bootstrap: verify principal transaction-locally (membership-scoped RLS), then establish
  verified tenant/membership/request/authorization-epoch context with parameterized
  `set_config(..., true)`. Runtime roles are `NOSUPERUSER`/`NOBYPASSRLS`/non-owner.
- Only redacted derivatives enter embeddings, provider payloads, normal logs, tenant audit views.

## Test seams (pre-authorized, highest)

1. REST/OpenAPI boundary.
2. Real PostgreSQL queried as the actual least-privileged runtime role.
3. Public retrieval pipeline with independent auth oracle + model/provider spy.
4. Browser critical paths through Playwright.
5. OCI image health/readiness and migration/rollback boundary.

## Workflow

- Trunk-based; short feature branches/worktrees; `main` always deployable.
- Conventional Commits (`feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `build`, `perf`).
- One behavior test first at an agreed seam (prove it fails for the intended reason), then smallest
  correct green behavior, then targeted checks, then independent review, then commit the verified
  green result.
- Target ~100 changed lines per commit (≤300 for one indivisible slice, excluding lockfiles/generated
  OpenAPI/migrations). Separate behavior, refactor, generated artifact, formatting.
- Never integrate an unverified node. Integrate in topological order; run the integration gate after
  each wave.
- Blocked? Persist exact failed command, attempts, evidence, smallest next action; ask one precise
  question. Same failure twice → diagnostic agent before more guesses.

## Verification commands (will grow as toolchains land; always confirm in package.json)

- `npm test` — unit + integration (Vitest)
- `npm run test:security` — deterministic adversarial suite (1,200 queries)
- `npm run test:property` — property/concurrency/mutation gates
- `npm run typecheck` / `npm run lint`
- `docker compose up` — local demo (Keycloak + PostgreSQL/pgvector + MinIO + api + worker + web)
- `npm run migration:up` / `migration:down` — explicit SQL migrations

## Repo layout (target)

```
apps/web        React + Vite console
apps/api        Fastify REST API (Zod boundary, committed OpenAPI)
apps/worker     queue consumer (extraction, embeddings, purge, audit expiry)
packages/db     migrations, RLS policies, seed, catalog tests
packages/core   domain: identity, grants, documents, retrieval, evidence, audit, retention
packages/security  two-stage context, PII, injection, redaction
packages/providers provider interfaces + local fakes + real adapters
packages/eval   fixtures, oracle, adversarial suite, reports
ops/            compose, OCI images, runbooks, backup/restore scripts
docs/           threat model, ADRs, OpenAPI, ERD, runbooks, evaluation
```
