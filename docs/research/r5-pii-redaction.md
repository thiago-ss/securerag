# R5 — PII Detection & Redaction Research

Research agent output. Task: NIST SP 800-122 PII classes and safeguards relevant to redaction; OWASP
LLM02:2025 controls for RAG; detector options for a TypeScript monolith; redaction strategy analysis
(masking vs class tokens vs hashing); pipeline placement; `pii:read` grant semantics. Research only —
no code, no commits. Sources verified by direct fetch on 2026-08-05.

Applies to SecureRAG invariants in `CONTEXT.md` (only redacted derivatives enter embeddings, provider
payloads, normal logs, tenant audit views) and `docs/threat-model.md` (PII redaction is
defense-in-depth, never authorization).

---

## 1. NIST SP 800-122 — PII classes and handling principles (as relevant to redaction)

Publication: *Guide to Protecting the Confidentiality of Personally Identifiable Information (PII)*,
McCallister, Grance, Scarfone, NIST SP 800-122 Final, April 2010.

### 1.1 PII definition (two-part, category-based)

> "PII is 'any information about an individual maintained by an agency, including (1) any information
> that can be used to distinguish or trace an individual's identity, such as name, social security
> number, date and place of birth, mother's maiden name, or biometric records; and (2) any other
> information that is linked or linkable to an individual, such as medical, educational, financial, and
> employment information.'" (ES / §2.2; GAO expression of OMB M-07-16 and M-06-19 amalgam)

The standard's own example catalog (ES, §2.2):

- **Names**: full name, maiden name, mother's maiden name, alias.
- **Personal identification numbers**: SSN, passport number, driver's license number, taxpayer
  identification number, financial account number, credit card number.
- **Address information**: street address, **email address**.
- **Personal characteristics**: photographic image (especially face), fingerprints, handwriting, other
  biometrics (retina scan, voice signature, facial geometry).
- **Linked/linkable**: date of birth, place of birth, race, religion, weight, activities, geographical
  indicators, employment information, medical information, education information, financial information.

Key consequence for detection design: NIST classifies by **category**, not by legal-regime field lists.
Any NIST-aligned detector class list can be derived from these categories; there is no fixed official
"the list" to import. v1 selects the categories that are (a) named in NIST's catalog and (b)
detectable deterministically (see §4.1).

### 1.2 Confidentiality risk considerations (§3, PII confidentiality impact level)

Impact levels low / moderate / high follow FIPS 199 definitions (limited / serious / severe adverse
effect). The standard adds four **PII-specific factors** (§3.2) that are directly useful as
SecureRAG tenant-policy inputs:

- **Identifiability** — how directly the data identifies an individual. "A SSN uniquely and directly
  identifies an individual, whereas a telephone area code identifies a set of people." Zip + date of
  birth can be enough to re-identify (~97% of a voting list per Sweeney study cited in §3.2.1).
- **Quantity of PII** — breach of 25 records vs 25 million records. "The PII confidentiality impact
  level should only be raised and not lowered based on this factor" — relevant to audit/detection
  counting (redaction events should be countable and batch-reportable).
- **Data Field Sensitivity** — SSN, medical history, financial account > phone number, ZIP code.
  Combinations matter: "name and credit card number" is more sensitive than either alone. Also,
  "background information, such as place of birth or parent's middle name, is often used as an
  authentication factor" — data can be sensitive out of its intended context.
- **Context of Use** — the same datum can have different sensitivity depending on purpose.

### 1.3 Safeguards relevant to redaction (ES §, §4.2, §4.4)

- **Minimize use, collection, and retention of PII** (§ ES): "Organizations should minimize the use,
  collection, and retention of PII to what is strictly necessary to accomplish their business purpose
  and mission." — maps to: never store raw PII in derived stores; retention/legal hold covers derived
  redacted copies.
- **De-identifying PII** (§ ES and §4.2.3): "remove or obscure, also referred to as masked or
  obfuscated, enough PII such that the remaining information does not identify an individual and there
  is no reasonable basis to believe that the information can be used to identify an individual."
  - De-identified records can be assigned a **low** impact level only if (1) the re-identification
    algorithm/code/pseudonym is maintained in a **separate system** with appropriate controls and
    (2) the data elements are not linkable via public or reasonably available external records.
  - De-identification techniques named: one-way hash functions; pseudo-random pseudonyms associated
    with a cross-reference table **in a separate system**; suppression; generalization; noise.
  - **Warning (footnote 56)**: "Hashing may not be appropriate for de-identifying information covered
    by HIPAA" — hash-derived codes are excluded by 45 C.F.R. § 164.514(c)(1). General lesson: hashing
    is not a free de-identification technique (see §4.2).
- **Access Enforcement (AC-3)**: role-based access control where "each user can access only the pieces
  of data necessary for the user's role"; only permit access through applications that restrict access
  instead of direct database access.
- **Least Privilege (AC-6)**: "users who must access records containing PII only have access to the
  minimum amount of PII, along with only those privileges... necessary to perform their job duties."
- **Separation of Duties (AC-5)**: "the users of de-identified PII data would not also be in roles
  that permit them to access the information needed to re-identify the records."
- **Auditable Events (AU-2)**: monitor events affecting PII confidentiality, such as unauthorized
  access.

---

## 2. OWASP LLM02:2025 — Sensitive Information Disclosure, controls for RAG

Source: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/ (2025 edition),
markdown at `OWASP/www-project-top-10-for-large-language-model-applications` `2_0_vulns/LLM02_...md`.

Scope: sensitive information includes "personal identifiable information (PII), financial details,
health records, confidential business data, security credentials, and legal documents" — both in the
model and in the application context (i.e., RAG context is explicitly in scope).

**Critical baseline claim** (description section): adding system-prompt restrictions about data types
the LLM should not return "may not always be honored and could be bypassed via prompt injection or
other methods." Therefore redaction must be deterministic and outside the model — never prompt-based.
This matches SecureRAG's invariant "The LLM never decides authorization."

Controls mapped to a RAG pipeline:

| LLM02:2025 control | RAG application in SecureRAG |
|---|---|
| Data sanitization — "scrubbing or masking sensitive content before it is used" | Ingest-time redaction before chunking and before embedding |
| Robust input validation — detect and filter harmful/sensitive inputs | Redact the query before embedding and before the model payload |
| Enforce strict access controls — least privilege, "only grant access to data that is necessary for the specific user or process" (need-to-know) | `pii:read` grant semantics (§6); document grants already default-deny |
| Restrict data sources — "limit model access to external data sources" | Evidence Bundle is the only model source; chunks are redacted, immutable |
| Tokenization and redaction — "pattern matching can detect and redact confidential content before processing" | Deterministic regex/Luhn/phonenumber detector pipeline (§4) |
| Differential privacy / homomorphic encryption ("Advanced Techniques") | Out of scope for v1 (operational cost, no tenant-facing gain) |
| User education / transparency | Terms of use note: raw PII never used for model training; retention/opt-out surfaces |

Adjacent control: **LLM05:2025 Improper Output Handling**
(https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) — "treat the model as any other
user, adopting a zero-trust approach, and apply proper input validation on responses coming from the
model" — plus scenario LLM02 Scenario #2 ("attacker bypasses input filters to extract sensitive
information"). Both argue for **output filtering**: post-hoc scan of the generated answer with the
same detector set, redacting or refusing before the answer is rendered/streamed. Output handling is
the one layer that protects against model regurgitation of training-data PII that never passed through
our inputs.

---

## 3. Detector options (OSS, license, language, maintenance as of Aug 2026)

### 3.1 Landscape table

| Name | License | Language | Maintenance (verified 2026-08-05) | Fit for TS monolith |
|---|---|---|---|---|
| **Presidio** (`presidio-analyzer` + `presidio-anonymizer`) | MIT | Python ≥3.10 (spaCy/transformers NER + regex recognizers) | **Active.** v2.2.364 on PyPI released Jul 22, 2026; monthly-ish cadence (Feb/Mar/Jun/Jul 2026). Project **transitioned from `microsoft/presidio` to community org `data-privacy-stack/presidio`**; Docker images now `ghcr.io/data-privacy-stack/presidio-*` (MCR legacy tags frozen). 10.3k stars, ~1.6k commits. Governance now community TSC. | **Poor directly** (Python), **good as optional sidecar**: analyzer+anonymizer expose REST; but adds a second runtime + new attack surface to a TS monolith, and hashing is not its default answer. Value-add is NER classes (names, addresses) that regex cannot do |
| **redact-pii** (solvvy) | MIT | TypeScript (Node ≥8, sync + async API) | **Moderate.** v3.4.0; npm `time.modified` Nov 2024 (≈21 months quiet at check). US-English built-in rules: credentials, creditCardNumber, emailAddress, ipAddress, names, password, phoneNumber, streetAddress, username, usSocialSecurityNumber, zipcode, url, digits; per-class custom `replaceWith`; optional Google Cloud DLP integration (external service — introduces cloud data egress; out of v1) | **Good baseline.** Pure JS/TS, per-class replacement tokens supported, no runtime |
| **pii-redact** | MIT | TypeScript, zero-dependency core | **Active.** v1.1.1, npm modified Mar 2026. Matchers: email, phone, credit card, SSN, IP, physical address, zip, coordinates, passport, driver's license; strategies Replace / Mask / Hash; optional NLP via `compromise` (PERSON/ORG/LOCATION). **Single maintainer** (`neenakrishnan1501-bit`) — small bus factor; would need pinning/vendoring review | **Good.** TS-native, strategy model matches our needs; supply-chain caution on a 1-maintainer lib |
| `pii` (npm) | Apache-2.0 | JS | **Dead**: v0.0.0, last modified 2022 | Not fit |
| `pii-detector` (npm) | — | JS | **Deprecated marker**: version `0.0.1-security` (npm security-flag rename) | **Avoid** — supply-chain warning |
| Deterministic primitives (in-house composition) | MIT | TypeScript | `card-validator` (Braintree) v10.0.4, Jan 2026 (active; Luhn); `luhn` v2.4.1, 2022; `libphonenumber-js` v1.13.10, Jul 2026 (active); `email-regex` v6.1.0, Aug 2025 (active). SSN has no good MIT package (npm `ssn` is GPL) — own regex | **Excellent.** Zero new runtime, fully deterministic and testable; matches the "deterministic controls" philosophy; composition over adoption |
| `@huggingface/transformers` + `onnxruntime-node` | Apache-2.0 / MIT | TS/JS (WASM/ONNX in-process) | **Active** (4.2.0 Apr 2026 / 1.27.0 Jul 2026) | **Medium.** TS-native NER (e.g., PII NER models) — an in-process alternative to Presidio for NAME/ADDRESS classes; cost: model download/pinning, CPU in worker. v2 candidate |
| Cloud DLP-style services (Google Cloud DLP, AWS Macie, Azure AI Language PII) | proprietary SaaS | API | Active | Not fit for v1: data egress to third party + per-tenant cost; contradicts "no data leaves except to approved model" posture (CONTEXT.md); possible future optional adapter |

### 3.2 Adapter recommendation

- **v1: pure-TS deterministic detectors, composed in-house.** Build the four core detectors (email,
  phone, SSN, credit card) on small MIT primitives (`email-regex`, `libphonenumber-js`, Luhn via
  `card-validator` or a 10-line implementation, own SSN regex with area/group validation) behind the
  `packages/security` PII provider interface (per ADR 0001 "providers: ... PII detection").
  Rationale: zero new runtime, no Python, deterministic → property-testable against the adversarial
  suite; all four classes are structurally defined; false positives are controllable.
- **Python sidecar (Presidio): NOT worth it for v1.** Reasons: (a) the four v1 classes are
  deterministic — Presidio's incremental value is NER entity classes (names/addresses) that v1 does
  not need; (b) a Python FastAPI service is a second runtime, second supply chain, and second attack
  surface inside a TS monolith; (c) Presidio is mid-transition (microsoft → data-privacy-stack) —
  maintained and MIT, but org/registry churn is ongoing; (d) same NLP capability is available
  TS-native later via `@huggingface/transformers` if NAME/ADDRESS become required.
- **v1.1 (optional, behind the same adapter interface):** NER-based NAME detection in the worker
  process via `@huggingface/transformers` (TS-native), or a pinned Presidio sidecar for tenants that
  demand it. The provider seam keeps both open.
- Supply-chain notes: avoid `pii-detector` (security-flagged); `pii` is dead; `pii-redact` is
  single-maintainer — acceptable only pinned and reviewed; `redact-pii` is quieter (last change
  Nov 2024) — prefer composing primitives over adopting either wholesale.

---

## 4. Redaction strategy for RAG — masking vs replacement tokens vs one-way hashing

### 4.1 The three strategies

| Strategy | Example | Retrieval quality | Leakage/consistency | Verdict for v1 |
|---|---|---|---|---|
| **Masking** | `call me at 555-555-5555` → `call me at [REDACTED]` | Worst. Single generic token erases class signal; embeddings of every masked span collapse toward the same point; queries like "email" no longer align with masked spans; cross-class collisions | Class of the data is hidden too; no value linkage | Reject for content pipelines; acceptable for diagnostics where class must not be revealed |
| **Replacement class tokens** | → `call me at [PHONE]`; `write to [EMAIL]` | Good. Token preserves class semantics; deterministic token sets are identical in corpus and query, so redacted queries still retrieve redacted chunks ("sent an email to [EMAIL]" keeps its embedding shape); answers remain readable | Reveals that a class exists (class ≠ value; NIST de-identification bars identification of individuals, not disclosure of class presence); no cross-value linkage; value-exact search (looking up a specific email) no longer works | **Recommended** (see 4.3) |
| **One-way hashing** | → `call me at a3b8d…` | Worst. Hash tokens are gibberish to embedding models; retrieval degrades sharply; answers become noise | **Dangerous**: same value → same hash across documents enables cross-document value linkage (correlation/tracking of an individual) and frequency analysis; NIST footnote 56 warns hash-derived codes can be legally inappropriate for de-identification (HIPAA 45 C.F.R. § 164.514(c)(1)); hashes also leak equality into audit if logged | Reject for RAG text. NIST's own de-identification guidance keeps re-identification means (cross-reference/pseudonym table) **in a separate system** — that is the only acceptable hashing shape, and only for analytics, not for content |

### 4.2 Why not hashing (RAG-specific)

SP 800-122 itself says re-identification codes must live in a separate system, and hashing is excluded
for some regulated data. For SecureRAG the extra RAG-specific problems are: (1) embedding a hash
destroys semantics; (2) deterministic unsalted hashes are a stable identifier of a value across the
whole corpus — that is *more* trackable than the token model, i.e., a privacy regression; (3) an
answer containing hashes is useless to the user.

### 4.3 Recommendation

**Class replacement tokens as the default redaction model for v1**, with:

- a **canonical, reserved token vocabulary** — `[EMAIL]`, `[PHONE]`, `[SSN]`, `[CREDIT_CARD]`
  (extensible: `[NAME]`, `[DATE_OF_BIRTH]`, `[ADDRESS]`, `[PASSPORT]`…) — identical in every
  pipeline stage (ingest, query, evidence, answer), so embeddings align across corpus and query;
- a **deterministic, pure function**: `redact(text, policy) → { text, findings[] }` where findings
  carry start/end spans + class, enabling citations to reference redacted chunk spans and enabling
  render-time `pii:read` substitution (§6);
- the **masking** form (`[REDACTED]`) reserved as a tenant-configurable policy for contexts where
  class presence itself is sensitive (e.g., error responses, diagnostics) — a policy variant, not the
  default;
- an explicit documented trade-off: PII-bearing content is no longer **value-exact** searchable via
  embeddings (queries must be redacted to match); tenants needing value search use the raw source
  view under `read` + `pii:read` grants. A keyed, per-tenant reversible tokenization map (NIST
  pseudonym pattern: cross-reference table in a separate system) is a v2 option;
- **no raw PII ever enters** embeddings, provider payloads, logs, or audit views — invariant
  unchanged by redaction strategy (CONTEXT.md).

---

## 5. Pipeline placement — where redaction must apply

1. **Ingestion — source content pre-chunk.** Detect + redact full document text *before* chunking.
   The Chunk is defined in CONTEXT.md as "immutable, redacted retrieval unit" — the redacted form is
   the only form ever chunked/embedded.
2. **Ingestion — metadata.** Filename, title, description, author, tags run through the same detector
   set. PII in filenames/titles is a listed side-channel surface in the threat model (lists, facets,
   URLs, previews).
3. **Storage — embeddings.** Embedding model input is redacted chunk text only. Raw source stays in
   encrypted object storage behind document grants, never in the vector store.
4. **Query path — before embedding and before the model payload.** Redact the query with the same
   token set (corpus↔query token alignment, §4.3). The redacted query is what gets embedded and what
   is sent to the provider; the raw query never reaches either.
5. **Evidence Bundle.** Only redacted chunks; citation spans resolve to spans inside redacted chunks.
6. **Generation — provider payload.** System prompt, query, and evidence contain only redacted
   derivatives (LLM02: prompt restrictions are bypassable; nothing to leak = nothing to bypass).
7. **Output — generated answer, post-hoc (defense-in-depth).** Scan the model's answer with the same
   detector set before rendering/streaming (LLM05 zero-trust output handling). Model can regurgitate
   PII from training data that never entered our pipeline. On detection: redact the span or refuse
   (tenant-configurable), and audit the event.
8. **Audit / logs / traces / metrics / stream frames / exports / previews.** Redacted derivatives
   only; audit events record detection counts, redaction policy version, and class stats — never
   values. Retention/legal hold must cover derived redacted copies (they are derived data).

Ordering principle: redaction is applied at every boundary where content leaves a trust domain
(store → chunk, chunk → embedding service, chunk/query → model provider, model → UI/stream, runtime →
log/audit), even though the earliest placement (1–2) is the primary control and the rest are
defense-in-depth.

---

## 6. `pii:read` grant semantics

`Allowed(P,T) = same tenant ∩ membership ∩ document grant ∩ visible version ∩ retention ∩ permitted
PII scope` (CONTEXT.md). `pii:read` is the capability that satisfies the PII-scope term for a
principal.

- **Grant model.** `pii:read` is a document-level grant capability (tenant-default configurable),
  orthogonal to `read/write/manage`. It authorizes a principal to see original PII **values within
  documents they can already read**. Default deny — without it, every surface shows redacted
  derivatives only.
- **Derived data is redacted for everyone, always** — including `pii:read` holders: embeddings,
  normal logs, audit views, and provider payloads stay uniformly redacted. Rationale: LLM02 warns
  prompt restrictions are bypassable; the model never needs raw values; a single redacted corpus
  avoids per-principal vector copies; NIST AC-5 separation of duties (users of de-identified data are
  not the re-identifiers).
- **What `pii:read` grants in v1:**
  1. **Source-level visibility**: original document text in preview/export/download (bounded by
     grant, membership, tenant, retention, legal hold).
  2. **Render-time span substitution in answers**: when the generated answer contains a replacement
     token whose span maps 1:1 to an authorized, in-evidence raw value, the presentation layer may
     substitute the value for `pii:read` holders. The substitution is deterministic, span-scoped,
     performed only at render time, applied to a transient in-memory map derived from the authorized
     evidence — never persisted, never logged, never sent to the model.
- **Explicitly not granted** by `pii:read`: exceeding tenant/membership/grant/retention; any
  write/manage implication; visibility of *other* principals' PII outside granted documents;
  exemption from audit. Access by `pii:read` principals is itself an auditable event (AU-2).
- **Re-identification separation (NIST §4.2.3 / AC-5):** the token→value mapping for substitution is
  derived per request from authorized source chunks and is destroyed after render; no cross-reference
  store of raw values persists in derived systems.
- Redaction remains defense-in-depth, not authorization: a detector miss never weakens ACL/RLS
  enforcement (threat-model policy).

---

## 7. Recommended v1 decisions (summary)

1. **PII classes (NIST-aligned, deterministic):** `EMAIL` (NIST: address information), `PHONE`
   (linked/linkable), `SSN` (personal identification number), `CREDIT_CARD` (financial account/credit
   card number). Tenant-configurable on/off. Optional v1.1: `NAME`, `DATE_OF_BIRTH`, `ADDRESS`
   (higher false-positive; NER-backed).
2. **Detector adapter:** pure-TS deterministic detectors composed from MIT primitives
   (`email-regex`, `libphonenumber-js`, Luhn via `card-validator`, own SSN regex) behind the provider
   interface; **no Python sidecar in v1** (Presidio is actively maintained under
   data-privacy-stack, but its value is NER classes v1 doesn't need; TS-native NER via
   `@huggingface/transformers` is the v1.1 path).
3. **Redaction model:** replacement class tokens (`[EMAIL]`, `[PHONE]`, `[SSN]`, `[CREDIT_CARD]`) as
   the default; uniform masking only as a tenant policy variant; hashing rejected for RAG content.
4. **Placement:** source pre-chunk → metadata → embeddings (redacted text only) → query (pre-embed,
   pre-payload) → evidence bundle → provider payload → post-hoc answer scan → logs/audit/streams.
5. **`pii:read`:** default-deny document-level capability; derived data always redacted; grants raw
   source views + render-time span substitution; audited; never crosses tenant/ACL bounds.

---

## Sources (exact URLs, fetched 2026-08-05)

- NIST SP 800-122 (Final, April 2010) publication page: https://csrc.nist.gov/publications/detail/sp/800-122/final
- NIST SP 800-122 PDF (primary text for §1): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-122.pdf
- NIST SP 800-122 DOI: https://doi.org/10.6028/NIST.SP.800-122
- OWASP LLM02:2025 Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
- OWASP LLM02 markdown (exact quotes): https://raw.githubusercontent.com/OWASP/www-project-top-10-for-large-language-model-applications/main/2_0_vulns/LLM02_SensitiveInformationDisclosure.md
- OWASP LLM05:2025 Improper Output Handling: https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
- Presidio repository (new home, community org): https://github.com/data-privacy-stack/presidio
- Presidio project-transition note (microsoft → data-privacy-stack): https://github.com/data-privacy-stack/presidio/blob/main/docs/project_transition.md
- presidio-analyzer on PyPI (release history/maintenance): https://pypi.org/project/presidio-analyzer/
- redact-pii (solvvy) on npm: https://www.npmjs.com/package/redact-pii — repo: https://github.com/solvvy/redact-pii
- pii-redact on npm: https://www.npmjs.com/package/pii-redact — repo: https://github.com/neenakrishnan1501-bit/pii-redact
- card-validator (Braintree, Luhn): https://www.npmjs.com/package/card-validator
- libphonenumber-js: https://www.npmjs.com/package/libphonenumber-js
- email-regex: https://www.npmjs.com/package/email-regex
- @huggingface/transformers: https://www.npmjs.com/package/@huggingface/transformers
- onnxruntime-node: https://www.npmjs.com/package/onnxruntime-node

*Package maintenance facts above (versions, licenses, npm `time.modified`, PyPI release dates) were
read live from npm registry and PyPI on 2026-08-05.*
