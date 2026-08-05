# ADR 0002 — Release tooling and version discipline

- Status: accepted (tool wiring lands in G5; skeleton in G0)
- Date: 2026-08-05

## Context

The repository needs SemVer releases, a changelog, annotated tags, and GitHub Releases driven by
Conventional Commits, with honest `0.x` construction versions and an `rc` gate before `v1.0.0`.

## Decision

- Use **Release Please** (Google's officially maintained action) to drive SemVer, changelog, and
  release PRs; fall back to a smaller officially maintained equivalent only if Release Please proves
  incompatible. Third-party actions pinned to verified immutable commit SHAs.
- Trunk-based development; short-lived feature branches/worktrees; `main` always deployable.
- Conventional Commits: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `build`, `perf`;
  a `(security)` scope is available; do not invent release types the automation cannot parse.
- `0.x` during construction. `v1.0.0-rc.N` only after complete RC gates; `v1.0.0` only after final
  clean-clone/release evidence passes.
- Target ~100 changed lines per commit (up to 300 for one indivisible logical slice, excluding
  lockfiles/generated OpenAPI/migrations). TDD red states remain local; never commit a failing
  suite.

## Consequences

- Commit history is the release ledger: no broken commit on `main`, no placeholders, no skipped
  tests, no unreviewed snapshots, no generated secrets.
- The release agent reproduces evidence from a fresh clone before each tag.
