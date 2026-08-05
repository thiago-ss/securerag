# SecureRAG — Implementation Graph and Acceptance Contract

This file persists the phase graph, the adversarial evaluation contract, the budgets, and the
Definition of Done. Graph node state lives in GitHub Issues (tracker: `thiago-ss/securerag`) with
blocking edges; the root orchestrator maintains the frontier.

## Phase graph

- **G0 — Safe repository bootstrap**: dedicated repo, ignore rules, private remote, Matt skill
  setup, domain docs, exact commands, CI skeleton. Gate: dedicated clean repo; nothing parent/private
  stageable; basic checks green in CI.
- **G1 — Parallel wayfinding and primary research**: fan out read-only research/product agents
  (auth/session, RLS/ACL, ingestion/PII/injection, retrieval/citation/refusal, audit/retention,
  threat model, deployment/observability, adversarial evaluation); fan in through architecture,
  security, simplicity, operability reviewers; canonical spec + threat model + ADRs + test seams +
  deployment envelope + risk register; `/to-tickets` with explicit blockers. Gate: no unresolved
  security-critical decision; requirements measurable; frontier computable.
- **G2 — Risk-first isolation tracer bullet**: two tenants, real runtime role + RLS + two-stage
  context, one immutable document/version, one grant, keyword retrieval, authorized citation OK,
  foreign/nonexistent indistinguishable, insufficient-evidence refusal, tenant-isolated audit,
  model spy proves no foreign chunk reaches generation. RLS/ACL red team + independent oracle
  approval required. Gate: deterministic tenant-isolation proof on real PostgreSQL as the actual
  least-privileged role.
- **G3 — Parallel vertical frontier** (10 slices, security-test lane shadows every slice):
  1. OIDC sessions + membership/group management + revocation epoch
  2. Upload/extraction/source encryption + immutable version publishing
  3. ACL management + authorized source/history/citation endpoints
  4. PII policy, redaction, provider-boundary spy, tenant-visible behavior
  5. Injection detection, quarantine, review, indirect-injection defenses
  6. Hybrid FTS/vector retrieval, RRF, reranking, recall benchmark, stable ordering
  7. Evidence calibration, refusal, answer generation, citation verification
  8. Append-only retrieval/lifecycle audit views + export
  9. Retention/legal hold/purge across PostgreSQL, objects, jobs, temp/derived data, backups
  10. Accessible console + health/readiness/OTel/rate limits/runbooks
  Gate: every slice verified; integration graph green; no security invariant deferred.
- **G4 — Adversarial security swarm**: parallel attack leads (RLS/IDOR, ACL/revocation,
  retrieval/model context, pool/session/job, lifecycle, injection/poisoning, PII/provider/log/audit,
  browser surfaces, evidence/refusal). Deterministic aggregator builds ranked repair graph; every
  repair wave re-runs affected attacks + full suite. Gate: all security metrics pass; negative
  controls prove suite sensitivity.
- **G5 — Production hardening and RC loop**: fresh independent reviews (Standards, Spec, threat
  model, RLS/ACL, API/auth, RAG/evidence, injection/PII, audit/retention, UX/a11y, performance,
  supply chain, docs, ops); fresh-clone reproduction of install/migrate/seed/demo/tests/adversarial/
  property/concurrency/mutation/build/images/SBOM/backup/restore/upgrade/rollback/health/observability.
  `v1.0.0-rc.N` only after a complete pass; max 3 RC attempts. Gate: exact release commit/image/
  config independently reproduced; no blocker.
- **G6 — GitHub portfolio publication**: history/`git ls-files` audit, secret/PII/canary scan,
  portfolio README, published artifacts, exact publication manifest, one final human checkpoint
  before private→public; then make public, push `main` + annotated `v1.0.0`, publish GHCR/SBOM/
  attestations + GitHub Release, verify unauthenticated clean checkout. Gate: public repository/
  release reproducible, or all work complete and blocked only on the single external publication
  action.

## Adversarial evaluation contract (v1 release gate)

- Fixtures: ≥8 tenants with users, tenant admins, service principals, colliding external IDs,
  groups, membership churn, overlapping names; private/user-shared/group-shared/role-shared/revoked/
  deleted/superseded/expired/quarantined/retained documents with multiple immutable versions;
  near-identical cross-tenant documents where unauthorized ones intentionally rank first; unique
  high-entropy literal canaries and structured synthetic secret facts in every document version,
  title, filename, metadata field, and supported derived surface (raw values never published);
  synthetic PII; direct/indirect injections in text/Markdown/HTML/tables/metadata/filenames.
- Independent fixture oracle computes allowed IDs without production policy code. Model spy records
  authorized chunk/version manifest and all provider-bound payloads.
- **1,200 unique end-to-end queries**, minimums: cross-tenant/forged-ID/IDOR 200; ACL/role 150;
  versions/deletion/revocation/retention 100; session/pool/worker/expansion/cache 150; injection/
  poisoning/encoding/multi-turn 200; citations/source/preview/download/export/logs/audit 100;
  browser/cancellation/error/stream 100; PII/provider boundary 100; evidence insufficiency 100.
  Unique = principal + authorization state + corpus state + prompt/sequence + retrieval mode +
  target surface tuple. Scan every serialized response field, header, error, count, citation, title,
  filename, ID, URL, preview, download, export, browser DOM, attempted remote render request,
  provider payload, log, audit view, trace, metric label, job result, stream frame/overlapping
  window. Unauthorized resource in model context fails even with clean output.
- Metrics: unauthorized model-context 0; unauthorized disclosures 0/≥1200; unauthorized citation/
  source 0; cross-tenant session/pool/job/cache 0; PII leakage 0; audit isolation failures 0,
  completeness 100%; required-refusal recall 100%; unsupported claims in refusal set 0; authorized
  answer success ≥95%; citation authorization/resolution/fixture-support precision 100%; required
  security mutants killed 100%. Positive controls prevent deny-everything from passing. One
  security event fails the run; infrastructure failure is `INVALID`, never `PASS`. No retry-to-
  green, skipped attacks, quarantine, or snapshot approval.
- Property/concurrency/mutation gates: ≥10,000 seeded operation sequences asserting retrieved and
  model-context IDs ⊆ oracle, seed + shrunk counterexample persisted; release load 100 workers × 100
  ops on shared pools with churn/injection/rollback/expiry during retrieval; required mutants must
  make the suite fail (remove tenant predicate; disable forced RLS; run as owner/BYPASSRLS; remove
  WITH CHECK; omit tenant/principal/auth epoch from state key; skip citation/source authorization;
  leave stale version/vector/object; log raw PII; allow generation without evidence). Include one
  intentionally leaky fixture proving canary scanner sensitivity.
- CI: every PR runs unit, schema/RLS catalog, direct policy, deterministic model-spy, PII, refusal,
  fixed property-seed, and full 1,200-query deterministic suite with production code paths and
  fake/local providers. Nightly/release: rotating seeds, concurrency/load, mutations, container/
  security scans, live provider smoke when authorized. Publish sanitized JSON/JUnit/Markdown reports
  with SHA, image digest, migration checksum, model/retriever/reranker/embedding/provider versions,
  manifest hashes, seeds, category counts, metric numerators/denominators, environment, timing,
  signed checksum. Never expose canaries or raw PII.

## Budgets

`MAX_PARALLEL = min(slots, 8)`, `MAX_SPAWN_DEPTH = 3`, `MAX_REVIEWERS_PER_NODE = 7`,
`MAX_AGENT_RUNS_PER_WAVE = 48`, `MAX_REPAIR_ATTEMPTS = 3`, `MAX_RC_ATTEMPTS = 3`.

A node is verified only when every criterion has evidence, declared checks exit zero, diff is
scoped, mandatory independent review passes, no blocker/secret/skip/placeholder remains, and an
atomic commit SHA exists. Continue while any ready or repair node exists and budget remains. Block
only for missing external credentials/authority, a hard legal/publication choice, irreconcilable
requirements, or exhausted bounded diagnostics; persist graph state, last green SHA, exact failed
command, attempts, evidence, and smallest next action; ask one precise question.

## Definition of Done (summary)

All eleven capabilities work through API and accessible UI; the core authorization invariant is
executable and tested at every disclosure boundary; RLS/catalog tests use real non-owner
`NOBYPASSRLS` roles on real PostgreSQL + pgvector; foreign/missing resources safely indistinguishable;
full adversarial/property/concurrency/mutation metrics pass; canonical spec + typed OpenAPI +
consistent errors; risk-based coverage with explicit behavior tests at every authorization/lifecycle/
evidence/redaction/audit branch; a11y verified (keyboard, screen reader, focus, errors, states);
clean-clone demo in one command with no paid keys; hardened OCI images; validated config at startup;
idempotent expand/contract migrations with rehearsed upgrade/rollback/backup/PITR/offboarding/
retention/incident/key-rotation/provider-outage runbooks; OpenTelemetry proves correlation without
content leakage; declared and benchmarked production envelope (default: 100 tenants, 1M chunks,
25 rps) with published p50/p95/p99, recall@k, throughput, resources, hardware; scans pass with no
reachable critical/high without approved time-bounded exception; CI least-privilege, immutable
SHAs, branch protection, required checks, deterministic deps, SBOM, provenance; clean atomic
Conventional Commits, README/demo/screenshots with synthetic tenants showing own-tenant success and
blocked cross-tenant attack; diagrams/glossary/threat model/ADRs/OpenAPI/ERD/RLS/evaluation/security
policy/contributing/runbooks/limitations/license complete; fresh independent release agent
reproduces all evidence from clean checkout; `v1.0.0` commit, image digests, migrations, reports,
changelog, annotated tag, GHCR artifacts, GitHub Release agree; history scan contains no secret,
real tenant data, real PII, raw canary, local environment, or unrelated parent-workspace artifact;
public repo/release works unauthenticated after final visibility approval. Only direct evidence
closes the goal.
