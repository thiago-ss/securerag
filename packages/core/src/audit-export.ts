import type { Pool } from 'pg';
import { withSecurityContext } from '@securerag/security';
import { appendAudit } from './audit.js';
import {
  CHAIN_SELECT,
  bufferToHex,
  rowToChainRow,
  sha256Hex,
  type ChainFields,
  type ChainRowSql,
} from './audit-chain.js';
import type { SecurityParams } from './types.js';

/**
 * WORM-style audit export (ADR-0010, S8; format documented in
 * docs/ops/audit-export.md). exportAudit produces a deterministic, ordered,
 * self-verifying document:
 *
 *   envelope: { format, tenantId, chainAnchorEventId, chainAnchorHash,
 *               eventCount, generatedAt, exporter, exportSha256, body }
 *   body:     one JSON object per event, oldest first (JSON Lines)
 *   exportSha256: sha256 of the exact body bytes
 *   chainAnchorHash: event_hash of the last chained event
 *
 * A consumer recomputes sha256(body) and re-verifies the hash chain against
 * the anchor (same rules as verifyAuditChain, including tombstone-covered
 * purge gaps). Lines carry ONLY stored audit fields — the redacted query and
 * hashes, ids, scores, decisions, citations, refusal, epoch, request/trace —
 * never raw query text, raw PII, tokens, or candidate content (those never
 * reach audit_events in the first place).
 *
 * Authorization: tenant admins AND active 'security_reviewer' members may
 * export their tenant's audit (deterministic SQL gate). Every successful
 * export appends an audited 'audit:exported' event (with the export body hash)
 * inside the same transaction. Denied and foreign/nonexistent tenants are
 * indistinguishable: member-without-role returns null, non-members raise
 * MembershipError — callers map both to the same 404.
 */

export const AUDIT_EXPORT_FORMAT = 'securerag-audit-export/1' as const;

/** One exported audit event (JSON-Lines line). Never raw query/PII fields. */
export interface AuditExportLine extends ChainFields {
  /** NULL only for legacy pre-chain rows (backfill). */
  eventHash: string | null;
}

export interface AuditExport {
  format: typeof AUDIT_EXPORT_FORMAT;
  tenantId: string;
  chainAnchorEventId: string | null;
  chainAnchorHash: string | null;
  eventCount: number;
  generatedAt: string;
  /** Acting principal (tenant admin / security_reviewer) that requested it. */
  exporter: string;
  /** sha256 of the exact body bytes; the consumer recomputes this. */
  exportSha256: string;
  /** JSON Lines: one event per line, ascending event_id order. */
  body: string;
}

export interface ExportAuditParams extends SecurityParams {
  /** Identity recorded in the envelope as the exporter. */
  exporter: string;
}

export function toExportLine(row: ChainRowSql): AuditExportLine {
  return {
    ...rowToChainRow(row).fields,
    eventHash: bufferToHex(row.event_hash),
  };
}

/** The export line stripped back to ChainFields (for consumer hash recomputation). */
export function exportLineToChainFields(line: AuditExportLine): ChainFields {
  const { eventHash: _eventHash, ...fields } = line;
  return fields;
}

/** Deterministic sha256 over the exact export body bytes (hex). */
export function exportBodySha256(body: string): string {
  return sha256Hex(body);
}

export function auditExportBody(lines: AuditExportLine[]): string {
  return lines.map((l) => JSON.stringify(l)).join('\n');
}

export async function exportAudit(pool: Pool, params: ExportAuditParams): Promise<AuditExport | null> {
  return withSecurityContext(pool, params, async (client, ctx) => {
    const gate = await client.query<{ allowed: boolean }>(
      `SELECT (
         EXISTS (SELECT 1 FROM securerag.tenant_memberships tm
                  WHERE tm.tenant_id = securerag.ctx_tenant_id()
                    AND tm.principal_id = securerag.ctx_principal_id()
                    AND tm.is_active
                    AND tm.role = 'security_reviewer')
         OR securerag.ctx_principal_is_admin(securerag.ctx_tenant_id())
       ) AS allowed`,
    );
    if (!(gate.rows[0]?.allowed ?? false)) return null;

    const { rows } = await client.query<ChainRowSql>(
      `${CHAIN_SELECT} WHERE tenant_id = securerag.ctx_tenant_id() ORDER BY event_id ASC`,
    );
    const lines = rows.map(toExportLine);
    const body = auditExportBody(lines);
    const exportSha256 = exportBodySha256(body);

    const chained = [...lines].reverse().find((l) => l.eventHash !== null);
    const chainAnchorEventId = chained?.eventId ?? null;
    const chainAnchorHash = chained?.eventHash ?? null;

    // Audited in the same transaction: every successful export is itself an
    // audit event (chained onto the anchor the export just recorded).
    await appendAudit({
      client,
      event: {
        eventType: 'audit:exported',
        requestId: params.requestId,
        principalId: ctx.principalId,
        membershipId: ctx.membershipId,
        authEpoch: ctx.authEpoch,
        filters: {
          eventCount: lines.length,
          exportSha256,
          anchorEventId: chainAnchorEventId ?? null,
        },
      },
    });

    return {
      format: AUDIT_EXPORT_FORMAT,
      tenantId: params.tenantId,
      chainAnchorEventId,
      chainAnchorHash,
      eventCount: lines.length,
      generatedAt: new Date().toISOString(),
      exporter: params.exporter,
      exportSha256,
      body,
    };
  });
}
