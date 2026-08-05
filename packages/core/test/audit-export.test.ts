import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { MembershipError, withSecurityContext } from '@securerag/security';
import { getTestDb, resetData, seedFixtures, type TestDb } from '@securerag/db/src/testkit.js';
import { appendAudit, sha256 } from '../src/audit.js';
import { verifyChainRows, type ChainRow } from '../src/audit-chain.js';
import {
  auditExportBody,
  exportAudit,
  exportBodySha256,
  exportLineToChainFields,
  type AuditExportLine,
} from '../src/audit-export.js';
import type { AuditEvent } from '../src/types.js';

describe('S8 WORM audit export on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: Awaited<ReturnType<typeof seedFixtures>>;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    api = db.apiPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  const req = (): string => randomUUID();

  async function appendEvent(
    overrides: Partial<AuditEvent> = {},
    principalId: string = world.alice.id,
  ): Promise<void> {
    await withSecurityContext(
      api,
      { tenantId: world.tenantA.id, principalId, requestId: req() },
      async (client, ctx) => {
        await appendAudit({
          client,
          event: {
            eventType: 'retrieval:allowed',
            requestId: ctx.requestId,
            principalId: ctx.principalId,
            membershipId: ctx.membershipId,
            authEpoch: ctx.authEpoch,
            ...overrides,
          },
        });
      },
    );
  }

  const exportAs = (principalId: string, tenantId: string = world.tenantA.id) =>
    exportAudit(api, {
      tenantId,
      principalId,
      requestId: req(),
      exporter: principalId,
    });

  /** The documented consumer verification procedure (docs/ops/audit-export.md). */
  function verifyExportDoc(doc: Awaited<ReturnType<typeof exportAs>> & object): void {
    expect(exportBodySha256(doc.body)).toBe(doc.exportSha256);
    const lines = doc.body === '' ? [] : (doc.body.split('\n').map((l) => JSON.parse(l)) as AuditExportLine[]);
    expect(lines).toHaveLength(doc.eventCount);
    const chainRows: ChainRow[] = lines.map((l) => ({
      eventId: l.eventId,
      fields: exportLineToChainFields(l),
      eventHashHex: l.eventHash,
    }));
    const verification = verifyChainRows(chainRows);
    expect(verification.valid).toBe(true);
    expect(verification.anchorHash).toBe(doc.chainAnchorHash);
    expect(verification.anchorEventId).toBe(doc.chainAnchorEventId);
  }

  it('exports a deterministic ordered body; lines carry only redacted/hash fields — never raw query or PII', async () => {
    const rawQuestion = 'What is the secret SSN 123-45-6789 of customer "Jane Roe"?';
    const redacted = '[REDACTED_PII] of customer "[REDACTED_NAME]"?';
    await appendEvent({
      eventType: 'retrieval:allowed',
      redactedQuery: redacted,
      queryHash: sha256(redacted),
      candidateIds: ['11111111-1111-4111-8111-111111111111'],
      scores: [0.91, 0.4],
      selectedIds: ['11111111-1111-4111-8111-111111111111'],
      evidenceDecision: 'sufficient',
      modelStatus: 'answered',
      citations: [{ documentId: 'd1', versionId: 'v1', chunkId: 'c1', span: { start: 0, end: 9 }, excerpt: 'redacted excerpt' }],
      latencyMs: 42,
      answerHash: sha256('answer'),
    });
    await appendEvent({
      eventType: 'retrieval:refused',
      refusalReason: 'INSUFFICIENT_EVIDENCE',
    });

    const doc = await exportAs(world.carol.id);
    expect(doc).not.toBeNull();
    const exportDoc = doc!;
    expect(exportDoc.format).toBe('securerag-audit-export/1');
    expect(exportDoc.tenantId).toBe(world.tenantA.id);
    expect(exportDoc.exporter).toBe(world.carol.id);
    expect(exportDoc.eventCount).toBe(2);

    // Ordered: body lines are ascending event_id; deterministic representation.
    const lines = exportDoc.body.split('\n').map((l) => JSON.parse(l)) as AuditExportLine[];
    expect(lines.map((l) => BigInt(l.eventId))).toEqual(
      [...lines].map((l) => BigInt(l.eventId)).sort((a, b) => (a < b ? -1 : 1)),
    );

    // NEVER raw query text / PII: the raw question (with the SSN) is absent
    // from the whole document; only the redacted query + its hash appear.
    expect(exportDoc.body).not.toContain('123-45-6789');
    expect(exportDoc.body).not.toContain('Jane Roe');
    expect(exportDoc.body).not.toContain(rawQuestion);
    for (const line of lines) {
      expect(line.redactedQuery ?? '').not.toContain('123-45-6789');
      expect(line.redactedQuery ?? '').not.toContain('Jane Roe');
      if (line.eventType === 'retrieval:allowed') {
        expect(line.queryHash).not.toBeNull();
        expect(line.candidateIds).not.toBeNull();
        expect(line.scores).not.toBeNull();
      }
      // The only string content fields are stored audit fields: no raw
      // question/token/secret-shaped keys anywhere in a line.
      const keys = Object.keys(line);
      expect(keys).not.toContain('rawQuery');
      expect(keys).not.toContain('question');
      expect(keys).not.toContain('token');
      expect(keys).not.toContain('secret');
    }

    verifyExportDoc(exportDoc);
  });

  it('every export is itself audited (audit:exported) and chained', async () => {
    await exportAs(world.carol.id);
    const { rows } = await db.superuserPool.query<{ event_id: string; event_hash: Buffer | null; filters: unknown }>(
      `SELECT event_id, event_hash, filters
         FROM securerag.audit_events
        WHERE tenant_id = $1 AND event_type = 'audit:exported'
        ORDER BY event_id DESC
        LIMIT 1`,
      [world.tenantA.id],
    );
    expect(rows.length).toBe(1);
    expect(rows[0]!.event_hash).not.toBeNull();
    expect(rows[0]!.filters).toMatchObject({ eventCount: expect.any(Number) });
  });

  it('a tenant member without admin/security_reviewer role gets null (no export, no audit write)', async () => {
    await exportAs(world.carol.id); // an export happens first so denial is distinguishable by absence of a NEW event
    const { rows: before } = await db.superuserPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM securerag.audit_events WHERE tenant_id = $1`,
      [world.tenantA.id],
    );
    const result = await exportAs(world.alice.id);
    expect(result).toBeNull();
    const { rows: after } = await db.superuserPool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM securerag.audit_events WHERE tenant_id = $1`,
      [world.tenantA.id],
    );
    expect(after[0]!.n).toBe(before[0]!.n);
  });

  it('an active security_reviewer member may export', async () => {
    await db.superuserPool.query(
      `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role)
       VALUES ($1, $2, 'security_reviewer')`,
      [world.tenantA.id, world.dave.id],
    );
    const doc = await exportAs(world.dave.id);
    expect(doc).not.toBeNull();
    expect(doc!.tenantId).toBe(world.tenantA.id);
    verifyExportDoc(doc!);
  });

  it('foreign and nonexistent tenants are indistinguishable (both reject with MembershipError)', async () => {
    const foreign = exportAs(world.alice.id, world.tenantB.id);
    const nonexistent = exportAs(world.alice.id, randomUUID());
    await expect(foreign).rejects.toBeInstanceOf(MembershipError);
    await expect(nonexistent).rejects.toBeInstanceOf(MembershipError);
  });

  it('legacy rows appear in the export with a NULL event_hash (backfill documented)', async () => {
    await db.superuserPool.query(
      `INSERT INTO securerag.audit_events
         (tenant_id, event_type, request_id, auth_epoch)
       VALUES ($1, 'retrieval:allowed', gen_random_uuid(), 1)`,
      [world.tenantA.id],
    );
    await appendEvent({ eventType: 'document:read' });
    const doc = await exportAs(world.carol.id);
    const lines = doc!.body.split('\n').map((l) => JSON.parse(l)) as AuditExportLine[];
    const legacy = lines.find((l) => l.eventHash === null);
    expect(legacy).toBeDefined();
    // The chain restarts after the legacy row (documented); the export still
    // verifies (legacy rows are skipped, exactly like the DB verifier).
    verifyExportDoc(doc!);
  });

  it('body helper reproduces the envelope hash for consumers', async () => {
    const lines: AuditExportLine[] = [
      {
        eventId: '1',
        tenantId: world.tenantA.id,
        eventType: 'retrieval:allowed',
        occurredAt: '2026-08-05T00:00:00.000Z',
        requestId: randomUUID(),
        traceId: null,
        principalId: world.alice.id,
        membershipId: '00000000-0000-4000-8000-000000000010',
        authEpoch: '1',
        redactedQuery: null,
        queryHash: null,
        filters: null,
        candidateIds: null,
        scores: null,
        selectedIds: null,
        policyVersions: null,
        evidenceDecision: null,
        modelStatus: null,
        citations: null,
        refusalReason: null,
        latencyMs: null,
        answerHash: null,
        prevEventHash: null,
        eventHash: 'ff'.repeat(32),
      },
    ];
    const body = auditExportBody(lines);
    expect(exportBodySha256(body)).toBe(exportBodySha256(body.split('\n').join('\n')));
    expect(body).toBe(JSON.stringify(lines[0]));
  });
});
