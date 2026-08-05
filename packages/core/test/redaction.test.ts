/**
 * S4 redaction gate on real PostgreSQL + testkit (ADR-0005):
 *  - the evidence bundle that reaches the model NEVER carries raw PII, even
 *    for pii:read principals (derived data is redacted for everyone);
 *  - the question is redacted before embedding/payload/audit (audit stores
 *    the redacted query and its hash, never raw text);
 *  - human surfaces (resolveCitation excerpts) honor pii:read: redacted for
 *    members, original for pii:read principals.
 */
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { SpyGenerator, type SpyRecord } from '@securerag/providers';
import {
  getTestDb,
  resetData,
  seedChunk,
  seedFixtures,
  seedGrant,
  seedVersion,
  type FixtureWorld,
  type TestDb,
} from '@securerag/db/src/testkit.js';
import {
  DEFAULT_PII_CONFIG,
  listAudit,
  redactBundleChunks,
  redactForSurface,
  redactQuestion,
  resolveCitation,
  runRetrieval,
} from '../src/index.js';

const PII_EMAIL = 'ops.ab12cd34@synthetic.example';
const PII_PHONE = '+1-555-12345678';
const PII_SSN = '700-05-1000';
const PII_CARD = '4111 1111 1111 1111';
const PII_CANARY = 'CANARY-pii-0123456789abcdef0123456789abcdef';

const PII_TEXT =
  `Client contact email: ${PII_EMAIL} phone ${PII_PHONE} SSN ${PII_SSN} card ${PII_CARD} reference ${PII_CANARY}`;
// The topic chunk carries the same class words ('client', 'contact', 'email')
// so a redacted question still retrieves the doc (corpus<->query token
// alignment, r5 §4.3) — and >= 2 chunks satisfy EVIDENCE_MIN_CHUNKS.
const TOPIC_TEXT = `Operational notes reference ${PII_CANARY}-b supplementary for pii-doc client contact follow-up email thread`;

// The same shapes the ST harness scans (and the production detector aligns
// with): raw PII must never survive in model context or audit.
const RAW_PII_RE =
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b|\b4\d{3} \d{4} \d{4} \d{4}\b|\+1-555-\d{8}\b/;

describe('S4: PII redaction pipeline on real runtime roles', () => {
  let db: TestDb;
  let api: Pool;
  let world: FixtureWorld;
  let piiChunk: string;

  beforeEach(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);

    const docs = await db.superuserPool.query<{ document_id: string }>(
      `INSERT INTO securerag.documents (tenant_id, title)
       VALUES ($1, 'PII client doc') RETURNING document_id`,
      [world.tenantA.id],
    );
    const documentId = docs.rows[0]!.document_id;
    const versionId = await seedVersion(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId,
      versionNo: 1,
      sourceObjectKey: 'tenant-a/sha/pii-v1.txt',
      contentHash: Buffer.from([0x51, 0x52]),
      status: 'valid',
      isCurrent: true,
    });
    piiChunk = await seedChunk(db.superuserPool, {
      tenantId: world.tenantA.id,
      versionId,
      chunkNo: 1,
      text: PII_TEXT,
      spanStart: 0,
      spanEnd: PII_TEXT.length,
    });
    await seedChunk(db.superuserPool, {
      tenantId: world.tenantA.id,
      versionId,
      chunkNo: 2,
      text: TOPIC_TEXT,
      spanStart: 0,
      spanEnd: TOPIC_TEXT.length,
    });
    for (const principalId of [world.alice.id, world.carol.id]) {
      await seedGrant(db.superuserPool, {
        tenantId: world.tenantA.id,
        documentId,
        subjectType: 'principal',
        subjectId: principalId,
        capability: 'read',
      });
    }
    api = db.apiPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  const params = (tenantId: string, principalId: string, requestId = randomUUID()) => ({
    tenantId,
    principalId,
    requestId,
  });

  it('member (piiRead=false): model context carries tokens, never raw PII; response citations redacted', async () => {
    const records: SpyRecord[] = [];
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(records) },
      { ...params(world.tenantA.id, world.alice.id), question: 'client contact' },
    );
    expect(outcome.decision).toBe('answered');
    if (outcome.decision !== 'answered') return;

    expect(outcome.citations.map((c) => c.chunkId)).toContain(piiChunk);
    expect(records).toHaveLength(1);
    const payloadText = records[0]!.bundle.map((b) => b.text).join('\n');
    expect(payloadText).not.toMatch(RAW_PII_RE);
    expect(payloadText).not.toContain(PII_EMAIL);
    expect(payloadText).not.toContain(PII_PHONE);
    expect(payloadText).not.toContain(PII_SSN);
    expect(payloadText).not.toContain(PII_CARD);
    expect(payloadText).toContain('[EMAIL]');
    expect(payloadText).toContain('[PHONE]');
    expect(payloadText).toContain('[SSN]');
    expect(payloadText).toContain('[CREDIT_CARD]');

    // citation excerpts in the response are the same redacted derivatives
    for (const citation of outcome.citations) {
      expect(citation.excerpt).not.toMatch(RAW_PII_RE);
    }
    const piiCitation = outcome.citations.find((c) => c.chunkId === piiChunk);
    expect(piiCitation?.excerpt).toContain('[EMAIL]');
    expect(piiCitation?.excerpt).toContain('[SSN]');
    expect(piiCitation?.excerpt).toContain('[CREDIT_CARD]');
  });

  it('admin (piiRead=true): model context is STILL redacted (ADR rule — derived data is redacted for everyone)', async () => {
    const records: SpyRecord[] = [];
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator(records) },
      { ...params(world.tenantA.id, world.carol.id), question: 'client contact' },
    );
    expect(outcome.decision).toBe('answered');
    expect(records).toHaveLength(1);
    const payloadText = records[0]!.bundle.map((b) => b.text).join('\n');
    expect(payloadText).not.toMatch(RAW_PII_RE);
    expect(payloadText).not.toContain(PII_EMAIL);
    expect(payloadText).toContain('[EMAIL]');
    expect(payloadText).toContain('[SSN]');
    expect(payloadText).toContain('[CREDIT_CARD]');
  });

  it('resolveCitation: excerpt redacted for member, original for pii:read admin', async () => {
    const member = await resolveCitation(api, {
      ...params(world.tenantA.id, world.alice.id),
      citationId: piiChunk,
    });
    expect(member).not.toBeNull();
    expect(member?.excerpt).not.toMatch(RAW_PII_RE);
    expect(member?.excerpt).toContain('[EMAIL]');
    expect(member?.excerpt).toContain('[PHONE]');
    expect(member?.excerpt).toContain('[SSN]');
    expect(member?.excerpt).toContain('[CREDIT_CARD]');

    const admin = await resolveCitation(api, {
      ...params(world.tenantA.id, world.carol.id),
      citationId: piiChunk,
    });
    expect(admin).not.toBeNull();
    expect(admin?.excerpt).toBe(PII_TEXT);
  });

  it('audit stores the redacted query and its hash — never the raw question', async () => {
    const requestId = randomUUID();
    const outcome = await runRetrieval(
      { pool: api, providers: new SpyGenerator() },
      {
        ...params(world.tenantA.id, world.alice.id, requestId),
        question: `client contact ${PII_EMAIL}`,
      },
    );
    expect(outcome.decision).toBe('answered');

    const events = await listAudit(api, params(world.tenantA.id, world.alice.id));
    const event = events.find((e) => e.requestId === requestId);
    expect(event).toBeDefined();
    expect(event?.redactedQuery).toBe('client contact [EMAIL]');
    expect(event?.redactedQuery).not.toContain(PII_EMAIL);
    const expectedHash = createHash('sha256').update('client contact [EMAIL]').digest();
    expect(event?.queryHash).toEqual(expectedHash);
  });
});

describe('S4: redaction helpers (pure functions)', () => {
  it('redactQuestion redacts before any payload/audit use', () => {
    expect(redactQuestion(`ping ${PII_EMAIL} again`)).toBe('ping [EMAIL] again');
    expect(redactQuestion(`ssn ${PII_SSN}`)).toBe('ssn [SSN]');
    expect(redactQuestion('plain question')).toBe('plain question');
  });

  it('redactBundleChunks re-redacts chunk text at the retrieval boundary', () => {
    const chunk = {
      chunkId: 'c1',
      chunkNo: 1,
      text: PII_TEXT,
      spanStart: 0,
      spanEnd: PII_TEXT.length,
      versionId: 'v',
      versionNo: 1,
      documentId: 'd',
      title: 't',
      rank: 1,
    };
    const redacted = redactBundleChunks([chunk]);
    expect(redacted[0]!.text).not.toMatch(RAW_PII_RE);
    expect(redacted[0]!.text).toContain('[EMAIL]');
    expect(redacted[0]!.text).toContain('[CREDIT_CARD]');
    // chunk identity/position data is untouched (citations still resolve)
    expect(redacted[0]!.chunkId).toBe('c1');
    expect(redacted[0]!.spanStart).toBe(0);
  });

  it('redactForSurface honors pii:read on human surfaces only', () => {
    const pii = DEFAULT_PII_CONFIG;
    expect(redactForSurface(PII_TEXT, pii, false)).toContain('[EMAIL]');
    expect(redactForSurface(PII_TEXT, pii, false)).not.toContain(PII_EMAIL);
    expect(redactForSurface(PII_TEXT, pii, true)).toBe(PII_TEXT);
  });

  it('disabled config passes everything through untouched', () => {
    const off = { ...DEFAULT_PII_CONFIG, enabled: false };
    expect(redactQuestion(`ping ${PII_EMAIL}`, off)).toBe(`ping ${PII_EMAIL}`);
    expect(redactForSurface(PII_TEXT, off, false)).toBe(PII_TEXT);
  });
});
