#!/usr/bin/env bash
set -u
for id in remove-tenant-predicate disable-forced-rls owner-role-membership remove-with-check omit-epoch-state-key skip-citation-authz stale-version-vector log-raw-pii generation-without-evidence; do
  ops/mutations/run-one.sh "$id" || exit 1
done
echo "ALL MUTANTS CAUGHT"
