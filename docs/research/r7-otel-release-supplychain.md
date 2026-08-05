# R7 — OTel Observability, Release Please Automation, GHCR/SBOM/Provenance, Hardened CI

Research agent findings (2026-08-05). All versions and SHAs verified live from official
sources: npm registry, GitHub `git ls-remote`, and official docs. RESEARCH ONLY — no code,
no commits. Repo context: `CONTEXT.md`, `docs/adr/0002-release-versioning-tooling.md`,
`.github/workflows/ci.yml` (currently only a skeleton CI; no root `package.json` yet, so the
monorepo structure below is the *target* layout from `AGENTS.md`).

---

## 1. OTel stack + versions (OpenTelemetry JavaScript)

Verified from registry.npmjs.org (dist-tags.latest) on 2026-08-05:

| Package | Latest | Notes |
|---|---|---|
| `@opentelemetry/sdk-node` | **0.221.0** | engines `^18.19.0 \|\| >=20.6.0` |
| `@fastify/otel` | **0.20.1** | Official Fastify instrumentation (fastify/otel org). Peer dep `@opentelemetry/api ^1.9.0`; deps `@opentelemetry/core ^2.0.0`, `@opentelemetry/instrumentation ^0.219.0`, `@opentelemetry/semantic-conventions ^1.28.0` |
| `@opentelemetry/instrumentation-fastify` | 0.57.0 | Alternative (open-telemetry/opentelemetry-js-contrib) |
| `@opentelemetry/instrumentation-pino` | 0.67.0 | Log correlation + log sending for pino (`pino >=5.14.0 <11`) |
| `@opentelemetry/api` | peer `^1.9.0` | Required peer for `@fastify/otel` |

### Fastify instrumentation — official choice

Use `@fastify/otel` (maintained by the Fastify org, "Official Fastify OpenTelemetry
Instrumentation"). Key usage facts from its README:

- Register the plugin (`fastifyOtelInstrumentation.plugin()`) **before** routes/hooks are
  defined so all routes and lifecycle hooks (`onRequest`, `preParsing`, `preValidation`,
  `preHandler`, `preSerialization`, `onSend`, `onResponse`, `onError`) are covered.
- `new NodeSDK({ instrumentations: [new FastifyOtelInstrumentation({ registerOnInitialization: true }), ...] })`
  auto-registers; service name comes from OTel resources / `OTEL_SERVICE_NAME`.
- Requires `@opentelemetry/instrumentation-http` for end-to-end propagation to upstream.
- Per-request context: `request.opentelemetry()` → `FastifyOtelRequestContext`
  (`span`, `context`, `tracer`, `inject`, `extract`).
- Options: `ignorePaths`, `requestHook`, `lifecycleHook`, `instrumentHooks` (per-route
  override via `config.otel`), `recordExceptions` (default true).

### Trace/metric/log correlation (trace_id into pino)

`@opentelemetry/instrumentation-pino` implements both mechanisms, per its README:

- **Log correlation**: pino records logged inside an active span get `trace_id`, `span_id`,
  `trace_flags` fields injected (spec: "Logs Correlation" — W3C trace context fields).
  Configure via `logKeys` (`{traceId, spanId, traceFlags}`), disable via
  `disableLogCorrelation: true`, extend via `logHook(span, record)`.
- **Log sending**: a pino destination forwards records to the OTel Logs SDK
  (`logRecordProcessors`), e.g. to an OTLP collector; disable via `disableLogSending: true`.

So the pipeline is: traces + metrics via `NodeSDK` (`@fastify/otel` + http/pino
instrumentations) → logs keep `trace_id`/`span_id` so logs, metrics, and traces correlate
with the same trace context in the backend. OTel "log correlation" spec reference:
<https://opentelemetry.io/docs/specs/otel/logs/#log-correlation> and
<https://opentelemetry.io/docs/specs/otel/compatibility/logging_trace_context/>.

### Requirement: no content/PII in attributes

Official basis (OpenTelemetry semantic conventions, stable):

- *Attribute requirement levels*: attributes that "might pose a security or privacy risk"
  must be `Opt-In` (never emitted by default) — `Recommended` attributes that raise
  security/privacy concerns can be dropped and replaced by opt-in.
  <https://opentelemetry.io/docs/specs/semconv/general/attribute-requirement-level/>
- `enduser.id` registry entry: "This field contains sensitive (PII) information."
- `gen_ai` registry attributes (e.g. gen_ai usage / prompt data): "This attribute is likely
  to contain sensitive information including user/PII data." — for a RAG product this is
  the critical one: do **not** put prompts, retrieved text, citations, or document content
  into span attributes.
- DB semconv: attribute values for query text "may contain PII or sensitive details".

This aligns with SecureRAG invariants (CONTEXT.md #7, #9): only redacted derivatives enter
embeddings, provider payloads, **normal logs**, and tenant audit views. Practical rule for
SecureRAG: attributes may carry identifiers/tenants/status codes (`tenant.id`,
`http.route`, `db.system.name`), never query text, prompts, chunk text, document titles,
filenames, or user content; the `@fastify/otel` `requestHook` README example setting
`user.id` from a header must be treated as PII and redacted/omitted.

---

## 2. release-please-action — config recipe + pinned SHA

Official repo: `googleapis/release-please-action`. Verified via `git ls-remote`:

- **Pin: `v5.0.0` → commit `45996ed1f6d02564a971a2fa1b5860e934307cf7`**
  (tag `v5.0.0` dereferences to that commit; `v5` also points there).

Current major is v5 (README at the pinned tag documents v4→v5 behavior; v4+ removed the
`command` input — manifest mode is the default unless `release-type` is set).

### Config file format (manifest-driven, official docs)

Two source-controlled files at repo root:

`release-please-config.json` — single package at repo root (`.`, node type):

```json
{
  "packages": {
    ".": {
      "release-type": "node"
    }
  },
  "bootstrap-sha": "<full-sha>",
  "include-component-in-tag": false
}
```

For a **Node monorepo** (SecureRAG target: `packages/core`, `packages/db`, `packages/api`,
…): one entry per package + the `node-workspace` plugin so local dependency bumps cascade:

```json
{
  "packages": {
    ".": { "release-type": "node" },
    "packages/core": { "release-type": "node" },
    "packages/db": { "release-type": "node" },
    "packages/api": { "release-type": "node" },
    "packages/worker": { "release-type": "node" }
  },
  "plugins": ["node-workspace"],
  "include-component-in-tag": false,
  "bump-minor-pre-major": true
}
```

`.release-please-manifest.json` — version tracking; bootstrap for `0.x` construction
phase (per ADR 0002):

```json
{
  ".": "0.1.0",
  "packages/core": "0.1.0"
}
```

Notes from official docs (`docs/manifest-releaser.md`):

- `bootstrap-sha` limits the first changelog to commits after that SHA; remove it after the
  first release PR merges.
- Set the starting version by editing the manifest on the default branch **before** the
  first run; defaults to `0.1.0` for node otherwise.
- `include-component-in-tag: false` produces plain `vX.Y.Z` tags (matches ADR 0002).
- `node-workspace` plugin bumps inter-package dependency ranges in lockstep; breaking
  bumps always included unless `always-link-local: false`.
- The action defaults to `config-file: release-please-config.json` and
  `manifest-file: .release-please-manifest.json`; with v4+ you do **not** set
  `command: manifest`.

### Workflow shape

```yaml
on:
  push:
    branches: [main]
permissions:
  contents: write
  issues: write
  pull-requests: write
jobs:
  release-please:
    runs-on: ubuntu-latest
    steps:
      - uses: googleapis/release-please-action@45996ed1f6d02564a971a2fa1b5860e934307cf7
        id: release
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          default-branch: main
```

Outputs: `releases_created`, `tag_name`, `version`, `sha`, `release_created`,
`<path>--release_created` per package. Downstream publish/build steps gate on
`steps.release.outputs.releases_created`. Two official caveats: (1) with the default
`GITHUB_TOKEN`, events triggered by release-please PRs/Releases do **not** start new
workflow runs — use a PAT secret if CI must run on release PRs; (2) the org must allow
GitHub Actions to create and approve PRs.

---

## 3. GHCR / SBOM / provenance recipe

Pinned SHAs verified via `git ls-remote` (all lightweight tags → commit; dereferenced
commits for annotated tags):

| Action | Tag | Commit SHA |
|---|---|---|
| `docker/build-push-action` | v7.3.0 | `53b7df96c91f9c12dcc8a07bcb9ccacbed38856a` |
| `docker/login-action` | v4.6.0 | `dbcb813823bdd20940b903addbd779551569679f` |
| `docker/setup-buildx-action` | v4.2.0 | `bb05f3f5519dd87d3ba754cc423b652a5edd6d2c` |
| `docker/metadata-action` | v6.2.0 | `dc802804100637a589fabce1cb79ff13a1411302` |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/attest` | v4.2.2 | `1e69f48acb82d1966a394da916b4c1698aa569d6` |
| `sigstore/cosign-installer` | v4.1.2 | `6f9f17788090df1f26f669e9d70d6ae9567deba6` |
| `googleapis/release-please-action` | v5.0.0 | `45996ed1f6d02564a971a2fa1b5860e934307cf7` |

### Build + attestations (official Docker docs)

- `provenance` input: build-push-action v4+ emits provenance **by default** —
  `mode=max` for public repos, `mode=min` for private repos; override explicitly with
  `provenance: mode=max` (recommended). SBOM is **not** automatic: set `sbom: true`.
- Attestations require pushing directly to the registry (`push: true`) — `load: true` /
  docker exporter drop attestations.
- **Security warning (official)**: in public repos, `mode=max` provenance includes the
  values of build arguments — never pass secrets via build-args; use secret mounts.
- GitHub-side `actions/attest` (`push-to-registry: true`) adds an unforgeable GitHub
  artifact attestation for the image digest (alternative/addition to BuildKit provenance).

```yaml
permissions:
  contents: read
  packages: write
  attestations: write
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}   # packages: write
      - uses: docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c
      - uses: docker/metadata-action@dc802804100637a589fabce1cb79ff13a1411302
        id: meta
        with:
          images: ghcr.io/${{ github.repository }}
      - uses: docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a
        with:
          context: .
          push: true
          provenance: mode=max
          sbom: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
      - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true
```

GHCR login with `GITHUB_TOKEN` is official: `docker/login-action` with
`registry: ghcr.io`, `username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}`;
GitHub's docs recommend `contents: read` + `packages: write` scopes for that token.

### Cosign keyless signing

- **cosign current: v3.1.2** → commit `193d2153431f8bb0d945a4c1ee721872f73add67`
  (verified via `git ls-remote`; dereferenced commit of the annotated tag).
- Keyless flow (sigstore docs): ephemeral keys + OIDC (GitHub identity) —
  `cosign sign $IMAGE` with the workflow granted `id-token: write`; no stored private key.
  Verify with `cosign verify` / `cosign verify-attestation` against the OIDC
  certificate identity (issuer `https://token.actions.githubusercontent.com`, expected
  subject `https://github.com/<owner>/<repo>/.github/workflows/<file>@refs/heads/main`).
- Install via `sigstore/cosign-installer` pinned to v4.1.2
  (`6f9f17788090df1f26f669e9d70d6ae9567deba6`).

### syft / grype

- **syft v1.50.0** → commit `453be0744f58d693e37ffd0cc5303e6c15bdd074` (SBOM generation,
  e.g. `syft <image> -o cyclonedx-json`).
- **grype v0.116.1** → commit `afc922d7f967fcf643580208f619335d1c80f1eb` (vulnerability
  scanning against the syft SBOM or the image directly).
- Scan in CI as a quality gate on tagged pushes/PRs; gate on failure (`--fail-on` severity).

---

## 4. CI least-privilege checklist

Per GitHub's official "Security for GitHub Actions" / "Secure use reference" pages:

- **Least privilege**: keep `GITHUB_TOKEN` at read-only by default (repo setting), elevate
  per job: `permissions:` blocks — `contents: read` for CI; `contents: write` +
  `pull-requests: write` (+ `issues: write` for release-please); `packages: write` +
  `attestations: write` + `id-token: write` only on the release/build job.
- **Pin third-party actions to full-length commit SHAs** — the only immutable pin;
  never moving tags; verify the SHA belongs to the action's own repo, not a fork. Keep a
  `# <tag>` comment for audit; Dependabot can bump SHA pins (it updates tag-or-SHA refs).
- **Avoid `pull_request_target` / `workflow_run`** with untrusted PR content; never check
  out untrusted code in privileged workflows.
- **Script injection**: pass untrusted context via `env:` intermediate variables (or an
  action input), not direct interpolation into `run:`.
- **OIDC**: use `id-token: write` + OIDC federation instead of long-lived secrets where
  possible (also required for keyless cosign).
- **Secrets**: never plaintext in workflows; `::add-mask::` for derived values; rotate
  exposed secrets and delete affected logs; don't use structured data (JSON blobs) as
  secrets; register derived secrets.
- **Secret scanning**: enable push protection + custom patterns; CI secret-pattern scan
  (ci.yml already greps for `ghp_`/`github_pat_`/`AKIA`/private keys — keep it).
- **Dependency security**: Dependabot alerts + security updates; dependency review action
  on PRs; enable CodeQL default setup to flag vulnerable workflow patterns; consider
  OpenSSF Scorecards; note Dependabot does **not** alert on SHA-pinned actions (use
  version updates for those).
- **Branch protection**: require status checks to pass before merge (CI, lint, typecheck,
  security suite) on `main`; require CODEOWNERS review for `.github/workflows/` changes
  and enforce admins/linear history.
- **Self-hosted runners**: only ephemeral JIT runners; never for public repos.

Current `ci.yml` already implements several: `contents: read` global permission and a
SHA-pinned `actions/checkout`. Note the existing checkout pin
(`fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09`) is an older checkout version; current stable
is v7.0.1 (SHA above).

---

## Sources (exact URLs)

**OpenTelemetry JS**
- <https://registry.npmjs.org/@opentelemetry/sdk-node/latest>
- <https://registry.npmjs.org/@fastify/otel> (README: <https://github.com/fastify/otel#readme>)
- <https://raw.githubusercontent.com/fastify/otel/main/README.md>
- <https://registry.npmjs.org/@opentelemetry/instrumentation-pino>
- <https://raw.githubusercontent.com/open-telemetry/opentelemetry-js-contrib/main/packages/instrumentation-pino/README.md>
- <https://registry.npmjs.org/@opentelemetry/instrumentation-fastify>
- <https://opentelemetry.io/docs/specs/semconv/general/attribute-requirement-level/>
- <https://opentelemetry.io/docs/specs/semconv/attributes-registry/enduser/>
- <https://opentelemetry.io/docs/specs/semconv/attributes-registry/gen-ai/>
- <https://opentelemetry.io/docs/specs/otel/logs/#log-correlation>
- <https://opentelemetry.io/docs/specs/otel/compatibility/logging_trace_context/>

**Release Please**
- <https://github.com/googleapis/release-please-action> (verified v5.0.0 SHA via `git ls-remote`)
- <https://raw.githubusercontent.com/googleapis/release-please-action/v5.0.0/README.md>
- <https://raw.githubusercontent.com/googleapis/release-please/main/docs/manifest-releaser.md>

**Supply chain / Docker / Sigstore**
- <https://docs.docker.com/build/ci/github-actions/attestations/>
- <https://raw.githubusercontent.com/docker/build-push-action/v7.3.0/README.md>
- <https://raw.githubusercontent.com/docker/login-action/v4.6.0/README.md>
- <https://docs.github.com/en/packages/managing-github-packages-using-github-actions-workflows/publishing-and-installing-a-package-with-github-actions>
- <https://docs.sigstore.dev/cosign/signing/signing_with_containers/>
- <https://github.com/sigstore/cosign/releases> (v3.1.2; SHA verified via `git ls-remote`)
- <https://github.com/anchore/syft/releases> (v1.50.0; SHA verified via `git ls-remote`)
- <https://github.com/anchore/grype/releases> (v0.116.1; SHA verified via `git ls-remote`)

**CI hardening**
- <https://docs.github.com/en/actions/how-tos/secure-your-work>
- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- <https://docs.github.com/en/actions/tutorials/authenticate-with-github_token>
- <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches>

**Repo context**
- `CONTEXT.md`, `docs/adr/0002-release-versioning-tooling.md`, `.github/workflows/ci.yml`
