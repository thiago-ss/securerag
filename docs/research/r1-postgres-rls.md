# Research R1 — PostgreSQL 18 / pgvector 0.8 / RLS, security_invoker, set_config, vector & text search primitives

Research agent output. Primary sources only (official PostgreSQL docs, pgvector GitHub repo).
No code changes. Verification date: 2026-08-05.

## Verified versions (as of 2026-08-05)

| Component | Exact version | Status | Source |
|---|---|---|---|
| PostgreSQL | **18.4** (current minor of major 18) | Stable current. 18.0 released 2025-09-25; 18 supported until 2030-11-14. **PostgreSQL 19 is NOT stable** — 19 Beta 2 released 2026-07-16 | https://www.postgresql.org/support/versioning/ |
| pgvector | **v0.8.6** (tagged 2026-07-29) | Current release; README's install instructions pin `--branch v0.8.6`; supports PostgreSQL 13+; Docker tags `0.8.6-pg18-*` exist | https://github.com/pgvector/pgvector/tags |

- PostgreSQL download URL: https://www.postgresql.org/download/ — docs URL: https://www.postgresql.org/docs/18/
- pgvector repo URL: https://github.com/pgvector/pgvector (release tag v0.8.6: https://github.com/pgvector/pgvector/releases/tag/v0.8.6)

**Conclusion for the goal's default (PostgreSQL 18 + pgvector 0.8.x): both confirmed correct as of today.**
Use minor 18.4 (community policy: always run the current minor). pgvector 0.8.6 is the newest 0.8.x; pin it.

---

## RLS facts with exact caveats that must become tests

Source: https://www.postgresql.org/docs/current/ddl-rowsecurity.html (PostgreSQL 18.4 docs)

1. **Owner vs BYPASSRLS vs FORCE.** "Superusers and roles with the `BYPASSRLS` attribute always bypass the row security system when accessing a table. Table owners normally bypass row security as well, though a table owner can choose to be subject to row security with `ALTER TABLE ... FORCE ROW LEVEL SECURITY`." `FORCE` **does apply to the table owner** — it is the only way to make an owner subject to policies. Superusers and BYPASSRLS are never subject, FORCE or not. Enabling/disabling RLS and adding policies is a **table-owner-only** privilege.
   - Caveat to test: runtime role must be `NOSUPERUSER`/`NOBYPASSRLS`/non-owner; owner must be forced; verify `relforcerowsecurity` is set on every tenant table (migration gate).
2. **Default deny.** With RLS enabled, if no policy exists for a table, "a default-deny policy is used, meaning that no rows are visible or can be modified." Disabling RLS ignores (does not drop) policies.
3. **Permissive vs restrictive.** Permissive policies (default) combine with **OR**; restrictive policies (`AS RESTRICTIVE`) combine with **AND** and must be passed in addition to permissive ones. Multiple permissive OR together, multiple restrictive AND together. Used to make a deny-in-list override allow-in-list. Restrictive AND-combining is the tool for "default allow via permissive policies, hard deny via restrictive" designs.
4. **USING vs WITH CHECK.** `USING` = rows visible to SELECT / modifiable base rows of UPDATE / DELETEd rows; `WITH CHECK` = rows that may be **created** by INSERT or **created/kept** by UPDATE. If `WITH CHECK` is omitted it is implicitly equal to `USING`. Consequence (must be a test): an UPDATE whose *new* row fails WITH CHECK raises an error ("new row violates WITH CHECK OPTION"), while an UPDATE whose *old* row fails USING silently updates 0 rows. Distinguishable error vs silence is an existence/timing side channel.
5. **Constraints bypass RLS (covert channel).** "Referential integrity checks, such as unique or primary key constraints and foreign key references, always bypass row security to ensure that data integrity is maintained. Care must be taken when developing schemas and row level policies to avoid 'covert channel' leaks of information through such referential integrity checks." Also: "Operations that apply to the whole table, such as `TRUNCATE` and `REFERENCES`, are not subject to row security."
   - Caveat to test: a FK or unique/PK violation against a **foreign tenant's** row is observable as success/failure even though RLS would hide the row — cross-tenant FK references must be impossible (every FK/PK/unique includes `tenant_id`), and any uniqueness/insert behavior must be identical for foreign vs nonexistent targets.
6. **Policy expression evaluation order.** Policy expressions "will be evaluated for each row prior to any conditions or functions coming from the user's query. (The only exceptions to this rule are `leakproof` functions, which are guaranteed to not leak information; the optimizer may choose to apply such functions ahead of the row-security check.)" Policy expressions run with the privileges of the user running the query.
   - Caveat to test: user-query predicates must never run before RLS unless leakproof; error-producing user functions cannot be used as an existence oracle.
7. **Sub-selects in policies race.** Policies that consult other rows/tables via sub-SELECTs "can create race conditions that could allow information leakage." Documented example: under READ COMMITTED, a `FOR UPDATE` row fetch gets the post-commit row, but a policy sub-SELECT without locking is read from the query-start snapshot — mallory can see the updated row with the old (more permissive) privilege value. Fixes: `FOR SHARE` in the policy sub-SELECT, `ACCESS EXCLUSIVE` lock on the referenced table during updates, or draining concurrent transactions.
   - Caveat to test: authorization-epoch / membership revocation must be effective for in-flight queries; policy reads of membership tables must be lock-consistent or epoch-checked.
8. **`row_security = off`** does not bypass — it errors if any query would be filtered by a policy. For backup paths; not a bypass.
9. **Privilege interplay.** RLS is applied on top of the standard GRANT system; both must pass. The docs example shows a role with `SELECT` on columns only (column-level GRANT) still fully constrained by RLS.
10. **Policy expression may reference functions/sub-SELECTs** — those accesses can themselves leak or race (see 7); security-definer functions can be used to access data not available to the calling user inside a policy.

---

## security_invoker views/functions notes

Source: https://www.postgresql.org/docs/current/sql-createview.html

- `security_invoker = true`: "the underlying base relations [are] checked against the privileges of the user of the view rather than the view owner"; if base relations have RLS, "the policies and permissions of the invoking user are used instead, as if the base relations had been referenced directly from the query using the view."
- Transitivity caveat: a security_invoker view accessed **from a non-invoker view is still treated as if accessed directly from the original query** — it always checks as the current user. Non-invoker (default) views are checked against the **view owner's** RLS policies, and relations referred to by those policies are resolved under the **view owner's** permissions — that is the classic "grant on view without access to base" pattern, and the docs warn not all views are secure against tampering (see rules-privileges / security_barrier).
- `security_invoker = false` is **not** equivalent to `SECURITY DEFINER` functions — don't confuse them.
- Functions inside views run as their own definition (INVOKER or DEFINER); `CURRENT_USER` in a view always returns the invoking user regardless of the view's `security_invoker` setting.
- Users of a security_invoker view must hold the relevant privileges **on the view and on the underlying base relations**.
- Schema `USAGE`: only needed on referenced schemas at view **creation**; view users only need USAGE on the view's own schema, even for security_invoker views.
- `security_barrier` (separate option): forces the view's WHERE conditions (and leakproof-operator conditions) to be evaluated before any user-added conditions — "should be used if the view is intended to provide row-level security." Rows locked by pre-filtering are locked even if ultimately not returned (EXPLAIN shows which conditions apply at relation level).
- Updatable-view caveats: an auto-updatable view with a WHERE clause allows UPDATE/MERGE to move a row out of view visibility, and INSERT to add invisible rows, unless `WITH [CASCADED|LOCAL] CHECK OPTION` is used (CASCADED is the default when bare `CHECK OPTION`). With `security_invoker`, the **performing user** (not the view owner) must hold the needed privileges on base relations.
- All view options are PostgreSQL extensions (not SQL standard).

## set_config notes

Sources: https://www.postgresql.org/docs/current/functions-admin.html (9.28.1) and https://www.postgresql.org/docs/current/sql-set.html

- `set_config(setting_name, new_value, is_local)` — `is_local = true` → "the new value will only apply during the current transaction"; `false` → applies "for the rest of the current session". Returns the new value. Passing `NULL` as `new_value` = reset the setting to its default.
- `current_setting(setting_name [, missing_ok])` — returns current value; errors if the setting doesn't exist unless `missing_ok = true`, then returns NULL. Corresponds to `SHOW`.
- **Rollback semantics (SET docs):** plain `SET`/`SET SESSION` issued inside a transaction that later aborts: effects disappear on rollback; after commit they persist until end of session. `SET LOCAL`: effects last only until end of the current transaction, **whether committed or not**. `SET LOCAL` outside a transaction block emits a warning and has no effect. Special case: `SET` followed by `SET LOCAL` in one transaction → `SET LOCAL` value visible until end of transaction, then the `SET` value takes effect. Rolling back to a savepoint earlier than the command cancels both `SET` and `SET LOCAL` effects. `SET LOCAL` inside a function that has a `SET` option for the same variable disappears at function exit.
- Some parameters require superuser or granted `SET` privilege; some cannot be changed after session start.
- Caveats to test for SecureRAG's two-stage bootstrap: (a) transaction-local `set_config(..., true)` must **not** be visible to a subsequent independent transaction in the same pooled session — connection pooling must not reuse leaked settings (test with two transactions on one connection); (b) `current_setting(name, true)` returning NULL (unknown GUC) is distinguishable from the default — use a custom `securerag.*` GUC with no default so "unset" is NULL, and test that unset → default-deny behavior; (c) rollback of the bootstrap transaction must clear the context (test aborted transaction leaves no readable rows); (d) `SET LOCAL` outside a transaction silently no-ops (warning) — test the bootstrap errors rather than silently proceeding.

## pgvector search notes

Source: https://github.com/pgvector/pgvector (README, master, v0.8.6)

- **Exact search is the default** (no index): perfect recall. Approximate indexes (HNSW, IVFFlat) trade recall for speed, and "you will see different results for queries after adding an approximate index."
- **HNSW** (multilayer graph): better speed/recall tradeoff than IVFFlat; slower build, more memory; no training step (can index an empty table). Params: `m` (16 default), `ef_construction` (64 default). Query: `hnsw.ef_search` (40 default) — higher = better recall, slower. Build in one pass after loading data; `maintenance_work_mem` notice when graph exceeds memory.
- **IVFFlat** (lists + k-means): faster build, less memory, lower speed/recall tradeoff; **must be created after the table has data** (training step; an index trained on too little data permanently limits recall). `lists` ≈ `rows/1000` up to 1M rows, `sqrt(rows)` beyond; query `ivfflat.probes` (1 default), start `sqrt(lists)`; probes = lists gives exact behavior but the planner won't use the index then.
- **Filtering caveats (critical for RLS-scoped queries):** the index is only used for `ORDER BY <dist-op> LIMIT` (expression in ORDER BY disables it). "With approximate indexes, filtering is applied *after* the index is scanned. If a condition matches 10% of rows, with HNSW and the default `hnsw.ef_search` of 40, only 4 rows will match on average." Options: plain index on the filter column (fast exact NN for low-selectivity filters), multicolumn indexes, **partial indexes** (few distinct filter values), **partitioning** (many values), and **iterative index scans** (since 0.8.0: `hnsw.iterative_scan = strict_order|relaxed_order`, `hnsw.max_scan_tuples` default 20,000, `ivfflat.max_probes`; relaxed order needs a materialized CTE for strict ordering; distance filters should go outside a materialized CTE).
- **Multitenancy (repo's own guidance):** "For applications with multiple tenants, sharing an approximate index between tenants means vectors from one tenant can affect recall (and speed) for other tenants. For tenant isolation, use list partitioning or separate tables." — Tenant-filtered approximate search on a shared index is officially discouraged for isolation AND recall.
- **Recall measurement (official method):** "Monitor recall by comparing results from approximate search with exact search" — run the query with `SET LOCAL enable_indexscan = off` in a transaction for the exact baseline, compare result sets.
- `NULL` vectors are not indexed (nor zero vectors for cosine); vector dims: `vector` ≤ 2,000, `halfvec` ≤ 4,000; all elements must be finite.
- Hybrid search: FTS `@@` + `ORDER BY ts_rank_cd(...) DESC LIMIT`, combined via RRF or cross-encoder (official examples).

## tsquery notes

Source: https://www.postgresql.org/docs/current/textsearch-controls.html (+ GIN notes from https://www.postgresql.org/docs/current/textsearch-tables.html)

- **`websearch_to_tsquery` is the safe entry point for raw user input**: "this function will never raise syntax errors, which makes it possible to use raw user-supplied input for search." Syntax: unquoted text → AND terms; `"quoted text"` → phrase (`<->`); `or` → `|`; `-` → `!` (NOT); all other punctuation ignored; it does **not** recognize tsquery operators/weight/prefix labels. (Examples: `'"supernovae stars" -crab'` → `'supernova' <-> 'star' & !'crab'`.)
- `to_tsquery` requires valid tsquery syntax (`& | ! <->`, parens) and **raises syntax errors** on arbitrary input — never call it with raw user text. `plainto_tsquery` ANDs all words, ignores operators; `phraseto_tsquery` uses `<->` and encodes stop words as `<N>`.
- **`ts_rank_cd`**: cover-density ranking (Clarke, Cormack, Tudhope 1999) — proximity-aware, unlike `ts_rank`. Requires lexeme positional info: "it ignores any 'stripped' lexemes in the tsvector. If there are no unstripped lexemes in the input, the result will be zero" — stripped/position-less tsvectors silently rank 0. Weights order `{D,C,B,A}` default `{0.1,0.2,0.4,1.0}`; normalization is a bitmask (0 none; 1 /log(len); 2 /len; 4 mean harmonic distance of extents — ts_rank_cd only; 8 /unique words; 16 /log(unique words); 32 rank/(rank+1) scales to 0..1 cosmetically). Ranking uses **no global information** (no fair cross-query comparison) and is expensive — "it requires consulting the tsvector of each matching document, which can be I/O bound."
- **GIN**: preferred index type for FTS (https://www.postgresql.org/docs/current/textsearch-indexes.html). Expression indexes must use the two-argument `to_tsvector('english', body)` (config must be pinned, else index contents could differ); queries must reference the same config string to use the index. Alternative: a stored generated `tsvector` column (`GENERATED ALWAYS AS (to_tsvector('english', coalesce(...))) STORED`) — config-independent querying and faster verification.
- **`ts_headline` XSS warning**: output "is not guaranteed to be safe for direct inclusion in web pages" — HTML must be stripped from input or output sanitized. Relevant to citation/preview rendering.

---

## Sources

- https://www.postgresql.org/support/versioning/ — PostgreSQL versioning policy, 18.4 current minor, 18.0 released 2025-09-25, supported to 2030-11-14; 19 Beta 2 (2026-07-16) not stable
- https://www.postgresql.org/download/ — download page
- https://www.postgresql.org/docs/18/ — PostgreSQL 18 documentation (all doc URLs above are the `/current/` (18) edition)
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html — RLS semantics
- https://www.postgresql.org/docs/current/sql-createview.html — security_invoker / security_barrier / CHECK OPTION
- https://www.postgresql.org/docs/current/functions-admin.html — set_config / current_setting (9.28.1)
- https://www.postgresql.org/docs/current/sql-set.html — SET / SET LOCAL scope and rollback
- https://www.postgresql.org/docs/current/textsearch-controls.html — websearch_to_tsquery, ts_rank_cd, ts_headline
- https://www.postgresql.org/docs/current/textsearch-tables.html — GIN expression indexes and generated tsvector columns
- https://www.postgresql.org/docs/current/textsearch-indexes.html — GIN preferred for FTS
- https://github.com/pgvector/pgvector — README (indexing, filtering, multitenancy, iterative scans, recall measurement)
- https://github.com/pgvector/pgvector/tags — v0.8.6 (2026-07-29) current release
