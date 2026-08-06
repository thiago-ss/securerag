# Changelog

## [0.2.0](https://github.com/thiago-ss/securerag/compare/v0.1.0...v0.2.0) (2026-08-06)


### Features

* **api:** ACL listing, history capability, citation/source hardening (S3) ([ad488e2](https://github.com/thiago-ss/securerag/commit/ad488e27240d4ad43ff1c48e18bf0657f7f08c2e))
* **api:** add Fastify spine API with committed OpenAPI and HTTP E2E gate ([c3ba213](https://github.com/thiago-ss/securerag/commit/c3ba213bf3eedc39994407966d35257c066828de))
* **eval:** adversarial security-test lane (ST) — canary corpus, harness, 216-case gate ([3b1dc86](https://github.com/thiago-ss/securerag/commit/3b1dc86af66aa96337fe5e19c4d4da45a82f1e9b))
* **eval:** G4 adversarial swarm — 1,700-case gate with zero disclosures ([6f95c24](https://github.com/thiago-ss/securerag/commit/6f95c24df8c4b5917942ac9e7915ed498ea9b44a))
* G3 wave 1 — OIDC sessions (S1) and hybrid retrieval (S6) ([f0d65e9](https://github.com/thiago-ss/securerag/commit/f0d65e9ed824aa96b53f716051e3499ba8c9c767))
* **g5:** mutation gate, property gate, load gate, release wiring ([a7536db](https://github.com/thiago-ss/securerag/commit/a7536dbfda185001ddf86c214e8306d6317b70a3))
* **ingest:** upload, extraction, malware scan, immutable publish pipeline (S2) ([32e917d](https://github.com/thiago-ss/securerag/commit/32e917d787e9b10285c6b330c42200e69317b8be))
* **ops:** accessible console, compose demo, OTel, rate limits, runbooks (S10) ([157338d](https://github.com/thiago-ss/securerag/commit/157338d5aa95d57aa44da24df6b781131fd383bd))
* **security:** add retrieval/audit/citation domain layer, provider spy, and independent oracle ([545e88a](https://github.com/thiago-ss/securerag/commit/545e88aa68841148be2176128614c81fa6458e7e))
* **security:** add RLS kernel schema, roles, policies, and catalog tests ([99c54f6](https://github.com/thiago-ss/securerag/commit/99c54f6c67f7632506e7c6ec09df347745ab25c1))
* **security:** add two-stage security-context bootstrap and runtime pool ([6af34a0](https://github.com/thiago-ss/securerag/commit/6af34a0179dc325bca2561231c97340b01c11604))
* **security:** calibrated evidence gate, conflict refusal, citation verification (S7) ([eab8bba](https://github.com/thiago-ss/securerag/commit/eab8bba6e4331d7c79bdbe34ec979c762908bdfa))
* **security:** complete S9 — retention API, purge worker, verified deletion, ST alignment ([de0ff27](https://github.com/thiago-ss/securerag/commit/de0ff278ce7740e72e066e13e4661220b8e9dda4))
* **security:** configurable PII detection and redaction (S4) ([f508b68](https://github.com/thiago-ss/securerag/commit/f508b68ffc22ccd0867033ea305f0d4e0b4d329b))
* **security:** injection detection, quarantine, and review flow (S5) ([3be29e6](https://github.com/thiago-ss/securerag/commit/3be29e64eb7bd85af05b703f38c7d6cba6ef5ab9))
* **security:** retention core, expiry, purge, worker context, migration 0009 (S9 partial) ([5ea1ce5](https://github.com/thiago-ss/securerag/commit/5ea1ce5eb45fa2330b30a1bc096038fc6ddcfb69))
* **security:** tamper-evident audit hash chain and WORM export (S8) ([9e0ae37](https://github.com/thiago-ss/securerag/commit/9e0ae3758fe3277bb308bef9b80261a420ee81e5))


### Bug Fixes

* **eval:** ST review hardening ([471a44c](https://github.com/thiago-ss/securerag/commit/471a44ca843205d42fc10f5708709d1e4bd641a8))
* **security:** admin-only membership writes, protected epoch, least-privilege grants ([eb6f929](https://github.com/thiago-ss/securerag/commit/eb6f929db1853a7f685a32af57f73bc1d6e322df))
* **security:** review-driven hardening of S1/S6 slices ([3095fb9](https://github.com/thiago-ss/securerag/commit/3095fb9b7affa35fec4904e8d4a4e62ef57e7761))
* **security:** S2/S3/S7 review hardening ([7f5dfcb](https://github.com/thiago-ss/securerag/commit/7f5dfcb2ab8d4274d6a3f3a07dbbe1d9563675f2))
* **security:** S4/S5 review hardening ([274123d](https://github.com/thiago-ss/securerag/commit/274123d014068ca4bc8dc959a4f884678b5a7f7f))
* **security:** S9 review hardening (blocker/highs resolved) ([f0fd701](https://github.com/thiago-ss/securerag/commit/f0fd70147d51b4296eb8a59100af0d628a17b40f))


### Documentation

* add implementation graph and acceptance tests ([d4abd41](https://github.com/thiago-ss/securerag/commit/d4abd412f990a48ee2f9171deb184d958d7f3e81))
* add primary-source research notes for SecureRAG decisions ([22d3295](https://github.com/thiago-ss/securerag/commit/22d3295b777a3e1c55ae8b8d4323399d812e7445))
* add threat model and architecture decisions ([e0d62be](https://github.com/thiago-ss/securerag/commit/e0d62beb2c20428f8e3a4c60117bcbf42087a35c))
* define SecureRAG domain and security invariants ([5bd617d](https://github.com/thiago-ss/securerag/commit/5bd617d4db9ea81af0d35bb1703c1c9eaf2db204))
* **eval:** correct corpus comment (bob allowed set is 3 chunks) ([c6b5222](https://github.com/thiago-ss/securerag/commit/c6b52220cdc6cfeb8b5862e6f435cec6b5b95b14))
* freeze T3 spine contract ([d56d009](https://github.com/thiago-ss/securerag/commit/d56d009ef51caa2b17e50564e1354cc816b1cfcc))
* **release:** portfolio README, security policy, contributing guide, sanitized evaluation report ([5e385e0](https://github.com/thiago-ss/securerag/commit/5e385e0c15d0eca7d81cd4f01e85fc4ee8c30fb9))
* resolve wayfinder decisions with ADRs and canonical spec ([64e5f29](https://github.com/thiago-ss/securerag/commit/64e5f294e88b0d05d18ca42506dda77f9a6d046b))
* **security:** amend ADR-0003 with PG18 restrictive-policy workaround ([b8cb39c](https://github.com/thiago-ss/securerag/commit/b8cb39cfaa27e3eda7f0b7ced91db23c54808c76))
