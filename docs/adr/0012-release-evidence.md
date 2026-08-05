# ADR 0012 — Release evidence set (D10)

- Status: accepted
- Date: 2026-08-05
- Sources: docs/research/r7-otel-release-supplychain.md, docs/graph-and-acceptance.md

## Decision

- **Release automation**: Release Please v5.0.0 pinned to commit SHA
  `45996ed1f6d02564a971a2fa1b5860e934307cf7`; `release-please-config.json` +
  `.release-please-manifest.json` (`node` release type, `include-component-in-tag: false`,
  bootstrap `0.1.0`); Conventional Commits drive SemVer; `0.x` during construction;
  `v1.0.0-rc.N` only after complete RC gates; `v1.0.0` only after final clean-clone evidence.
- **RC gate checklist**: fresh-clone install/migrate/seed/demo; full test suites (unit, schema/RLS
  catalog, direct policy, model-spy, PII, refusal, property, concurrency, mutation, 1,200-query
  adversarial); container/secret/SAST/license scans; SBOM + provenance; backup/restore +
  upgrade/rollback rehearsals; independent review board; release report signed.
- **Required security mutants** (must make the suite fail): remove tenant predicate; disable forced
  RLS; run as owner/BYPASSRLS; remove WITH CHECK; omit tenant/principal/auth epoch from state key;
  skip citation/source authorization; leave stale version/vector/object; log raw PII; allow
  generation without evidence.
- **Property/concurrency**: fixed seed in CI (persisted + shrunk counterexamples), rotating seeds
  nightly; 10,000 seeded operation sequences; 100 workers × 100 ops release load.
- **Sanitized reports** (JSON/JUnit/Markdown, signed checksum): Git SHA, image digest, migration
  checksum, prompt/retriever/reranker/embedding/provider versions, corpus manifest hashes, seeds,
  category counts, metric numerators/denominators, environment, timing. Never expose canaries or
  raw PII.
- **Pipeline**: buildx `provenance: mode=max` + `sbom: true`; GHCR login via GITHUB_TOKEN
  (`packages: write`); keyless `cosign sign` with OIDC; syft SBOM + grype scan as gates; actions
  pinned per r7 table.
- **Branch protection**: main requires status checks + linear history, when repo permissions allow.

## Consequences

- Release evidence is deterministic, signed, and reproducible from a fresh clone; the publication
  manifest is a single document.
