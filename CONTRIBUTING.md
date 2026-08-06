# Contributing

Thank you for contributing to SecureRAG. This is a security-critical repository; review
`AGENTS.md` before anything else — the rules there apply to every contributor.

## Ground rules

- **Never commit secrets, canary values, or real data.** The `.env.example` is the only env file.
- **Never weaken isolation.** Every change to queries, policies, or the pipeline must keep
  authorization inside SQL; foreign and nonexistent resources stay indistinguishable.
- **Every security-relevant change ships with a test** that runs against real PostgreSQL as the
  actual least-privileged role (Testcontainers). RLS is never mocked.
- Trunk-based: short branches, `main` always deployable, Conventional Commits
  (`feat`/`fix`/`refactor`/`test`/`docs`/`chore`/`ci`/`build`/`perf`, optional `(security)` scope).

## Workflow

1. Pick an issue (or file one). State the intended behavior + the security invariant it touches.
2. Write one behavior test at an agreed seam and watch it fail for the intended reason.
3. Implement the smallest correct green change; run the targeted workspace suite.
4. Open a PR. CI runs unit, schema/RLS catalog, direct-policy, model-spy, PII, refusal,
   property-seed, and the full adversarial suite.

## Verification commands

```bash
npm install
npm run typecheck
npm run test:security      # adversarial swarm + api + security suites
npm run test:db:catalog    # RLS/role/policy contract
npm run test:property      # property + load gates (eval)
npm run test:mutations     # required security mutants caught
```

## Adding an attack case

Extend `packages/eval` (corpus facts + `buildCases`/`buildG4Cases`). Each case must be a unique
tuple: (principal, authorization state, corpus state, prompt/sequence, retrieval mode, surface).
The independent oracle must be able to compute the allowed set for it.

## Releasing

SemVer via Release Please (Conventional Commits). `v1.0.0-rc.N` after a complete RC pass
(fresh-clone reproduction of all gates); `v1.0.0` only after the final clean-clone release
evidence passes. See `docs/ops/` for runbooks.
