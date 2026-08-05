# Audit export (WORM) — format and consumer verification

Slice S8, ADR-0010 ("Tamper evidence: per-tenant hash chain over audit events;
WORM export format documented and testable").

## 1. Retrieving an export

```
GET /audit/export?tenantId=<uuid>
```

- Authenticated with an OIDC session cookie (S1).
- Authorized for **tenant admins** and **active `security_reviewer` members** of
  the requested tenant only (deterministic SQL gate; same rule as quarantine
  review). Members without the role, foreign-tenant principals, and
  nonexistent tenants all get the identical `404 NOT_FOUND` body — no
  enumeration, no gate oracle.
- Every successful export appends an audited `audit:exported` event (chained
  like any other event) inside the same transaction. Denied exports write
  nothing.
- The export contains **only stored audit fields**: the redacted query and
  hashes, ids, scores, decisions, citations, refusal, epoch, request/trace.
  Raw queries, raw PII, tokens, and candidate content never reach
  `audit_events`, so they cannot appear in an export.

## 2. Document shape

```jsonc
{
  "format": "securerag-audit-export/1",
  "tenantId": "…",
  "chainAnchorEventId": "42",            // last chained event (bigint as text)
  "chainAnchorHash": "<64 hex>",         // its event_hash
  "eventCount": 42,
  "generatedAt": "2026-08-05T12:00:00.000Z",
  "exporter": "<principal uuid>",
  "exportSha256": "<64 hex>",            // sha256 of the exact body bytes
  "body": "…"
}
```

`body` is **JSON Lines**, one event per line, **ascending `event_id` order**
(oldest first). Each line is a JSON object with exactly the chained audit
fields plus the event's own hashes:

```jsonc
{
  "eventId": "41", "tenantId": "…", "eventType": "retrieval:allowed",
  "occurredAt": "…", "requestId": "…", "traceId": null,
  "principalId": "…", "membershipId": "…", "authEpoch": "3",
  "redactedQuery": "…", "queryHash": "<hex|null>",
  "filters": null, "candidateIds": […], "scores": […], "selectedIds": […],
  "policyVersions": null, "evidenceDecision": "…", "modelStatus": "…",
  "citations": […], "refusalReason": null, "latencyMs": 42,
  "answerHash": "<hex|null>",
  "prevEventHash": "<hex|null>",          // previous event's event_hash
  "eventHash": "<64 hex|null>"            // null only for legacy pre-chain rows
}
```

Legacy rows written before S8 carry `eventHash: null` and `prevEventHash:
null`; they are exported as-is (backfill never rewrites history).

## 3. Consumer verification procedure

A consumer must run all four steps to trust the document. Steps 2–4 mirror the
database verifier (`verifyAuditChain`) exactly, so the anchor re-verifies
against the live tenant chain when the database is reachable.

1. **Body integrity**: `sha256(bodyBytes) === exportSha256` (byte-exact —
   do not re-serialize; hash the raw body string).
2. **Chain linkage**: parse the body into lines (JSON, in order). For each
   line after the first, `line.prevEventHash` must equal the previous line's
   `eventHash` — OR the break must be covered by a purge tombstone (step 4).
   The first line's `prevEventHash` must be null (or tombstone-covered).
3. **Hash recomputation**: for each line, recompute
   `eventHash = sha256Hex(canonicalChainInput(fields))` where `fields` is the
   line without `eventHash`, and compare to `line.eventHash`. The canonical
   input is the JSON object of the line fields with object keys sorted
   bytewise (UTF-8), bytea as lowercase hex, `occurred_at` as ISO-8601 UTC
   with millisecond precision. Reference implementations: `canonicalChainInput`
   and `computeEventHashHex` in `packages/core/src/audit-chain.ts`. Rows
   following a tombstone-covered purge gap (step 4) are re-seed points: their
   stored hash is carried forward, not recomputed.
4. **Purge-gap tolerance**: a broken link is legitimate only when the export
   contains a chained `audit:purged` line whose
   `filters.eventIdRange = {min, max}` (as decimal-id strings) appears after
   the broken row and covers every id strictly between the two surviving rows
   (or, at chain start, every id below the first survivor). This is exactly
   the S9 retention-purge tombstone contract; anything else is a violation.
5. **Anchor**: the last line's `eventHash` must equal
   `envelope.chainAnchorHash`, and its `eventId` must equal
   `chainAnchorEventId`.

## 4. Failure modes (tamper evidence)

| Event | Detection |
| --- | --- |
| `UPDATE` of any stored field (e.g. `event_type`) | step 3 hash mismatch |
| Delete of a middle event | step 2 prev-link break, no tombstone → violation |
| Reorder / id swap | step 3 mismatch (`event_id` is bound into every hash) |
| Delete of the tail event | chain stays internally valid but the anchor changes; consumers must compare the anchor against a previously retained export |
| Legitimate retention purge (with chained tombstone) | step 4 accepts the gap; the reseeded row is marked |

Runtime roles hold no `UPDATE`/`DELETE` on `audit_events` (insert-only, RLS
`WITH CHECK false`); only the RLS-proven purge path may delete expired rows.
`verifyAuditChain(pool, {tenantId, principalId, requestId})` runs the same
checks against the live database inside a verified security context.
