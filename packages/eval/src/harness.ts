/**
 * Adversarial query harness (ST slice; contract: docs/graph-and-acceptance.md).
 *
 * Executes attack cases against the REAL API over HTTP (real Fastify server,
 * real least-privilege pool, real spy generator, fake OIDC login), counts
 * UNIQUE (principal, authzState, corpusState, prompt, mode, surface) tuples,
 * scans every serialized output for foreign content/canaries/PII, and produces
 * a sanitized report. A single violation fails the run.
 */
import { writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import type { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { computeAllowed } from './oracle.js';
import type { CanaryWorld } from './canary-corpus.js';

export type Surface = 'query' | 'document' | 'version' | 'citation' | 'audit';

export interface AttackCase {
  name: string;
  subject: string;
  tenantId: string;
  surface: Surface;
  mode: 'hybrid' | 'keyword' | 'vector';
  prompt?: string;
  targetId?: string;
  expect: 'allowed' | 'denied';
}

export interface CaseResult {
  name: string;
  surface: Surface;
  expect: string;
  status: number;
  decision: string;
  body: string;
  headers: string;
  uniqueTuple: string;
  violations: string[];
}

export interface HarnessMetrics {
  totalCases: number;
  uniqueTuples: number;
  unauthorizedContext: number;
  unauthorizedDisclosures: number;
  piiLeaks: number;
  auditIsolationFailures: number;
  refusalRecall: number;
  refusalRecallDenominator: number;
  authorizedAnswerSuccess: number;
  authorizedAnswerDenominator: number;
  violations: string[];
}

export interface AdversarialReport {
  generatedAt: string;
  seed: number;
  corpusVersion: string;
  metrics: HarnessMetrics;
  caseCounts: Record<Surface, number>;
}

interface Session {
  cookieHeader: string;
  csrfToken: string;
}

export interface HarnessOptions {
  base: string;
  provider: FakeOidcProvider;
  world: CanaryWorld;
  cases: AttackCase[];
  login: (subject: string) => Promise<Session>;
  /** Allowed chunk ids per (principalId) for the spy-payload check. */
  allowedChunkIdsFor: (principalId: string, tenantId: string) => Set<string>;
  redactedChunkIdsFor: (principalId: string, tenantId: string) => Set<string>;
  principalIdFor: (subject: string) => string;
  recordSpyPayloads: () => { chunkIds: string[]; texts: string[] }[];
  corpusVersion: string;
  reportDir?: string;
  seedValue?: number;
}

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
// Dashed SSN and spaced card formats (matches the corpus's synthetic PII; far
// less likely to false-positive on hex canaries than bare digit runs).
const PII_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b|\b4\d{3} \d{4} \d{4} \d{4}\b/gi;

export async function runAdversarialHarness(
  opts: HarnessOptions,
): Promise<AdversarialReport> {
  const results: CaseResult[] = [];
  const metrics: HarnessMetrics = {
    totalCases: 0,
    uniqueTuples: 0,
    unauthorizedContext: 0,
    unauthorizedDisclosures: 0,
    piiLeaks: 0,
    auditIsolationFailures: 0,
    refusalRecall: 0,
    refusalRecallDenominator: 0,
    authorizedAnswerSuccess: 0,
    authorizedAnswerDenominator: 0,
    violations: [],
  };

  const sessionCache = new Map<string, Session>();
  const seenTuples = new Set<string>();

  // Group cases by subject: the spy records globally, so per-case payload
  // attribution requires running one subject's cases consecutively AND tracking
  // the record offset between consecutive cases.
  const bySubject = new Map<string, AttackCase[]>();
  for (const c of opts.cases) {
    const list = bySubject.get(c.subject) ?? [];
    list.push(c);
    bySubject.set(c.subject, list);
  }

  for (const [subject, subjectCases] of bySubject) {
    let session = sessionCache.get(subject);
    if (session === undefined) {
      session = await opts.login(subject);
      sessionCache.set(subject, session);
    }
    let spyOffset = (await opts.recordSpyPayloads()).length;

    for (const c of subjectCases) {
      const principalId = opts.principalIdFor(c.subject);
      const tenantId = c.tenantId;

      // Unique-tuple: (principal, authzState, corpusState, prompt/sequence,
      // retrieval mode, surface). Non-query surfaces use the target id as the
      // sequence discriminator (prompt is empty for them).
      const authzState = authzHash(opts, principalId, tenantId);
      const sequence = c.prompt ?? c.targetId ?? '';
      const tuple = [principalId, authzState, opts.corpusVersion, sequence, c.mode, c.surface].join('|');
      seenTuples.add(tuple);

      const result = await executeCase(opts, session, c);
      const afterSpy = (await opts.recordSpyPayloads()) as unknown as ReturnType<HarnessOptions['recordSpyPayloads']>;
      const payloads = afterSpy.slice(spyOffset);
      spyOffset = afterSpy.length;

      const violations: string[] = [];

      // Model-context scan: every chunk id in a provider payload must be allowed
      // (or redacted-allowed) for this principal/tenant; zero foreign text.
      const allowed = opts.allowedChunkIdsFor(principalId, tenantId);
      const redacted = opts.redactedChunkIdsFor(principalId, tenantId);
      for (const p of payloads) {
        for (const id of p.chunkIds) {
          if (!allowed.has(id) && !redacted.has(id)) {
            violations.push(`model-context chunk ${id} not allowed`);
            metrics.unauthorizedContext += 1;
          }
        }
        for (const text of p.texts) {
          for (const c2 of foreignCanaries(opts, tenantId, text)) {
            violations.push(`foreign canary ${c2} in model context`);
            metrics.unauthorizedDisclosures += 1;
          }
          if (PII_RE.test(text)) {
            const principal = opts.world.facts.principals.find((p2) => p2.id === principalId);
            if (principal?.piiRead !== true) {
              violations.push('raw PII in model context for non-pii-read principal');
              metrics.piiLeaks += 1;
            }
          }
        }
      }

      // Response scan: canaries belonging to OTHER tenants; foreign doc/chunk/
      // version ids; foreign tenant ids in audit rows; headers too.
      const body = result.body;
      const responseText = `${body}\n${result.headers}`;
      for (const c2 of foreignCanaries(opts, tenantId, responseText)) {
        violations.push(`foreign canary ${c2} in response`);
        metrics.unauthorizedDisclosures += 1;
      }
      const foreignDocIds = foreignDocumentIds(opts, tenantId, responseText);
      if (foreignDocIds.length > 0) {
        violations.push(`foreign document ids in response: ${foreignDocIds.join(',')}`);
        metrics.unauthorizedDisclosures += 1;
      }
      const foreignChunkIds = foreignChunkVersionIds(opts, tenantId, responseText);
      if (foreignChunkIds.length > 0) {
        violations.push(`foreign chunk/version ids in response: ${foreignChunkIds.join(',')}`);
        metrics.unauthorizedDisclosures += 1;
      }
      if (c.surface === 'audit' && result.status === 200) {
        const foreign = foreignTenantIds(opts, tenantId, responseText);
        if (foreign.length > 0) {
          violations.push(`foreign tenant id in audit response`);
          metrics.auditIsolationFailures += 1;
        }
      }
      if (PII_RE.test(responseText)) {
        const principal = opts.world.facts.principals.find((p2) => p2.id === principalId);
        if (principal?.piiRead !== true) {
          violations.push('raw PII in response for non-pii-read principal');
          metrics.piiLeaks += 1;
        }
      }

      // Outcome expectations: denied cases must not carry content; allowed query
      // cases must answer; allowed non-query cases must succeed (positive
      // controls on every surface).
      if (c.expect === 'denied') {
        metrics.refusalRecallDenominator += 1;
        const refused =
          result.decision === 'refused' || result.status === 404 || result.status === 403;
        if (refused) metrics.refusalRecall += 1;
        else violations.push(`denied case returned ${result.status}/${result.decision}`);
      }
      if (c.expect === 'allowed' && c.surface === 'query') {
        metrics.authorizedAnswerDenominator += 1;
        if (result.decision === 'answered') metrics.authorizedAnswerSuccess += 1;
        else violations.push(`allowed query did not answer: ${result.status}/${result.decision}`);
      }
      if (c.expect === 'allowed' && c.surface !== 'query' && result.status !== 200) {
        violations.push(`allowed ${c.surface} did not succeed: ${result.status}`);
      }

      results.push({ ...result, uniqueTuple: tuple, violations });
      for (const v of violations) metrics.violations.push(`${c.name}: ${v}`);
    }
  }

  metrics.totalCases = results.length;
  metrics.uniqueTuples = seenTuples.size;

  const report: AdversarialReport = {
    generatedAt: new Date().toISOString(),
    seed: opts.seedValue ?? 0,
    corpusVersion: opts.corpusVersion,
    metrics,
    caseCounts: {
      query: results.filter((r) => r.surface === 'query').length,
      document: results.filter((r) => r.surface === 'document').length,
      version: results.filter((r) => r.surface === 'version').length,
      citation: results.filter((r) => r.surface === 'citation').length,
      audit: results.filter((r) => r.surface === 'audit').length,
    },
  };

  if (opts.reportDir !== undefined) {
    await mkdir(opts.reportDir, { recursive: true });
    const sanitized = sanitizeReport(report, results);
    await writeFile(`${opts.reportDir}/adversarial.json`, JSON.stringify(sanitized, null, 2));
    await writeFile(`${opts.reportDir}/adversarial.md`, reportToMarkdown(report, results));
  }

  return report;
}

async function executeCase(
  opts: HarnessOptions,
  session: Session,
  c: AttackCase,
): Promise<CaseResult> {
  const headers: Record<string, string> = {
    cookie: session.cookieHeader,
  };
  let body = '';
  let headerText = '';
  let status = 0;
  let decision = '';

  const capture = async (res: Response): Promise<Response> => {
    headerText = [...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n');
    return res;
  };

  try {
    switch (c.surface) {
      case 'query': {
        headers['content-type'] = 'application/json';
        headers['x-csrf-token'] = session.csrfToken;
        const res = await capture(await fetch(`${opts.base}/retrieval/query`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ tenantId: c.tenantId, question: c.prompt ?? '' }),
        }));
        status = res.status;
        body = await res.text();
        decision = parseDecision(body);
        break;
      }
      case 'document': {
        const res = await capture(await fetch(`${opts.base}/documents/${c.targetId}`, { headers }));
        status = res.status;
        body = await res.text();
        decision = status === 200 ? 'found' : 'not-found';
        break;
      }
      case 'version': {
        const [docId, versionId] = (c.targetId ?? '/').split('/');
        const res = await capture(await fetch(`${opts.base}/documents/${docId}/versions/${versionId}`, { headers }));
        status = res.status;
        body = await res.text();
        decision = status === 200 ? 'found' : 'not-found';
        break;
      }
      case 'citation': {
        const res = await capture(await fetch(`${opts.base}/citations/${c.targetId}`, { headers }));
        status = res.status;
        body = await res.text();
        decision = status === 200 ? 'found' : 'not-found';
        break;
      }
      case 'audit': {
        headers['x-csrf-token'] = session.csrfToken;
        const res = await capture(await fetch(`${opts.base}/audit/retrieval?limit=50`, { headers }));
        status = res.status;
        body = await res.text();
        decision = status === 200 ? 'ok' : 'error';
        break;
      }
    }
  } catch (err) {
    decision = `exception: ${String(err)}`;
    status = 0;
  }

  return { name: c.name, surface: c.surface, expect: c.expect, status, decision, body, headers: headerText, uniqueTuple: '', violations: [] };
}

function parseDecision(body: string): string {
  try {
    const parsed = JSON.parse(body) as { decision?: string };
    return parsed.decision ?? '';
  } catch {
    return '';
  }
}

function authzHash(opts: HarnessOptions, principalId: string, tenantId: string): string {
  const allowed = opts.allowedChunkIdsFor(principalId, tenantId);
  return createHash('sha1').update([...allowed].sort().join(',')).digest('hex').slice(0, 12);
}

/** Foreign-canary markers: descriptors (tenant/document/kind), never raw values,
 * so violation strings and reports cannot leak canary content by construction. */
function foreignCanaries(opts: HarnessOptions, tenantId: string, text: string): string[] {
  const found: string[] = [];
  for (const c of opts.world.canaries) {
    if (c.tenantId !== tenantId && text.includes(c.value)) {
      found.push(`canary:${c.kind}:${c.tenantId.slice(0, 8)}/${c.documentId.slice(0, 8)}`);
    }
  }
  return found;
}

function foreignDocumentIds(opts: HarnessOptions, tenantId: string, text: string): string[] {
  const found: string[] = [];
  for (const m of text.matchAll(UUID_RE)) {
    const id = m[0].toLowerCase();
    const doc = opts.world.facts.documents.find((d) => d.documentId === id);
    if (doc !== undefined && doc.tenantId !== tenantId) found.push(id);
  }
  return [...new Set(found)];
}

/** Foreign chunk and version ids (citation/version surfaces). */
function foreignChunkVersionIds(opts: HarnessOptions, tenantId: string, text: string): string[] {
  const found: string[] = [];
  for (const m of text.matchAll(UUID_RE)) {
    const id = m[0].toLowerCase();
    const chunk = opts.world.facts.chunks.find((c) => c.chunkId === id);
    const version = opts.world.facts.versions.find((v) => v.versionId === id);
    if ((chunk !== undefined && chunk.tenantId !== tenantId) ||
        (version !== undefined && version.tenantId !== tenantId)) {
      found.push(id);
    }
  }
  return [...new Set(found)];
}

function foreignTenantIds(opts: HarnessOptions, tenantId: string, body: string): string[] {
  const found: string[] = [];
  for (const m of body.matchAll(UUID_RE)) {
    const id = m[0].toLowerCase();
    const tenant = opts.world.facts.tenants.find((t) => t.id === id);
    if (tenant !== undefined && tenant.id !== tenantId) found.push(id);
  }
  return [...new Set(found)];
}

/** Reports must never contain raw canary values. Redact by pattern (robust
 * even for values not tracked in the corpus list). */
function sanitizeReport(
  report: AdversarialReport,
  results: CaseResult[],
): unknown {
  const redact = (s: string): string =>
    s.replace(/CANARY-[A-Za-z0-9-]+/g, '<CANARY>').replace(PII_RE, '<PII>');
  const plain = JSON.parse(JSON.stringify(report)) as Record<string, unknown>;
  return {
    ...plain,
    metrics: {
      ...(plain.metrics as Record<string, unknown>),
      violations: ((plain.metrics as { violations: string[] }).violations ?? []).map(redact),
    },
    caseResults: results.map((r) => ({
      name: r.name,
      surface: r.surface,
      expect: r.expect,
      status: r.status,
      decision: r.decision,
      violations: r.violations.map(redact),
      body: redact(r.body).slice(0, 500),
    })),
  };
}

function reportToMarkdown(report: AdversarialReport, results: CaseResult[]): string {
  const m = report.metrics;
  const lines = [
    '# SecureRAG adversarial harness report',
    '',
    `- Generated: ${report.generatedAt}`,
    `- Seed: ${report.seed}`,
    `- Corpus version: ${report.corpusVersion}`,
    `- Total cases: ${m.totalCases} (unique tuples: ${m.uniqueTuples})`,
    `- Case counts: ${JSON.stringify(report.caseCounts)}`,
    '',
    '## Metrics',
    '',
    '| Metric | Value |',
    '| --- | --- |',
    `| unauthorized_context | ${m.unauthorizedContext} |`,
    `| unauthorized_disclosures | ${m.unauthorizedDisclosures} |`,
    `| pii_leaks | ${m.piiLeaks} |`,
    `| audit_isolation_failures | ${m.auditIsolationFailures} |`,
    `| refusal_recall | ${m.refusalRecall}/${m.refusalRecallDenominator} |`,
    `| authorized_answer_success | ${m.authorizedAnswerSuccess}/${m.authorizedAnswerDenominator} |`,
    '',
    '## Violations',
    '',
    ...(m.violations.length > 0 ? m.violations.map((v) => `- ${v}`) : ['- none']),
    '',
    `## Per-case outcomes (${results.length})`,
    '',
    ...results.map(
      (r) =>
        `- [${r.status}] ${r.surface}/${r.name} expect=${r.expect} decision=${r.decision} violations=${r.violations.length}`,
    ),
  ];
  return lines.join('\n');
}

export { computeAllowed };
