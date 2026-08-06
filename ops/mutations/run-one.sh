#!/usr/bin/env bash
# Run ONE security mutation: apply it, run the targeted test, require FAILURE
# (the mutant must be caught), then revert. Exit 0 iff the test failed.
# Usage: ops/mutations/run-one.sh <id>
set -u
ID="$1"
cd "$(git rev-parse --show-toplevel)"
WS=""; TEST=""; FILE=""
case "$ID" in
  remove-tenant-predicate)
    FILE="packages/core/src/retrieval.ts"; WS="@securerag/core"; TEST="retrieval-hybrid"
    python3 - <<'PY'
p='packages/core/src/retrieval.ts'
s=open(p).read().replace("AND ${grantPredicateSql('d.document_id', 'c.tenant_id')}","AND true")
open(p,'w').write(s)
PY
    ;;
  disable-forced-rls)
    FILE="packages/db/migrations/0003_rls_and_grants.sql"; WS="@securerag/db"; TEST="catalog"
    python3 - <<'PY'
p='packages/db/migrations/0003_rls_and_grants.sql'
s=open(p).read().replace('FORCE ROW LEVEL SECURITY','NO FORCE ROW LEVEL SECURITY')
open(p,'w').write(s)
PY
    ;;
  owner-role-membership)
    FILE="packages/db/migrations/bootstrap/0001_roles_and_extensions.sql"; WS="@securerag/db"; TEST="catalog"
    python3 - <<'PY'
p='packages/db/migrations/bootstrap/0001_roles_and_extensions.sql'
s=open(p).read().replace("GRANT securerag_owner TO securerag_migration;","GRANT securerag_owner TO securerag_migration;\nGRANT securerag_owner TO securerag_api;")
open(p,'w').write(s)
PY
    ;;
  remove-with-check)
    FILE="packages/db/migrations/0003_rls_and_grants.sql"; WS="@securerag/db"; TEST="catalog"
    python3 - <<'PY'
p='packages/db/migrations/0003_rls_and_grants.sql'
s=open(p).read().replace("WITH CHECK (tenant_id = securerag.ctx_tenant_id())","WITH CHECK (true)")
open(p,'w').write(s)
PY
    ;;
  omit-epoch-state-key)
    FILE="packages/security/src/context.ts"; WS="@securerag/security"; TEST="bootstrap"
    python3 - <<'PY'
p='packages/security/src/context.ts'
s=open(p).read().replace("  GUC_AUTH_EPOCH,\n", "")
open(p,'w').write(s)
PY
    ;;
  skip-citation-authz)
    FILE="packages/core/src/documents.ts"; WS="@securerag/core"; TEST="domain"
    python3 - <<'PY'
p='packages/core/src/documents.ts'
s=open(p).read().replace("AND ${grantPredicateSql('d.document_id', 'securerag.ctx_tenant_id()')}","")
open(p,'w').write(s)
PY
    ;;
  stale-version-vector)
    FILE="packages/core/src/ingestion.ts"; WS="@securerag/core"; TEST="ingestion"
    python3 - <<'PY'
p='packages/core/src/ingestion.ts'
s=open(p).read().replace("SET is_current = false, status = 'superseded'","SET is_current = true, status = 'superseded'")
open(p,'w').write(s)
PY
    ;;
  log-raw-pii)
    FILE="packages/core/src/retrieval.ts"; WS="@securerag/core"; TEST="redaction"
    python3 - <<'PY'
p='packages/core/src/retrieval.ts'
s=open(p).read().replace("redactedQuery: questionRedacted,","redactedQuery: params.question,")
open(p,'w').write(s)
PY
    ;;
  generation-without-evidence)
    FILE="packages/core/src/retrieval.ts"; WS="@securerag/core"; TEST="refusal-e2e"
    python3 - <<'PY'
p='packages/core/src/retrieval.ts'
s=open(p).read().replace("if (decideCalibrated(redactedBundle, questionRedacted) === 'INSUFFICIENT_EVIDENCE') {","if (false) {")
open(p,'w').write(s)
PY
    ;;
  *)
    echo "unknown mutant: $ID"; exit 2 ;;
esac
echo "== mutant $ID applied to $FILE; expecting $TEST to FAIL =="
if npm run test --workspace "$WS" -- "$TEST" > /tmp/mutant.log 2>&1; then
  git checkout -- "$FILE"
  echo "FAIL: mutant $ID was NOT caught (tests passed)"
  exit 1
else
  git checkout -- "$FILE"
  echo "OK: mutant $ID was caught"
  exit 0
fi
