/**
 * Adversarial query harness (ST + G4; contract: docs/graph-and-acceptance.md).
 *
 * Executes attack cases against the REAL API over HTTP (real Fastify server,
 * real least-privilege pool, real spy generator, fake OIDC login), counts
 * UNIQUE (principal, authzState, corpusState, prompt, mode, surface) tuples,
 * scans every serialized output for foreign content/canaries/PII, and produces
 * a sanitized report. A single violation fails the run.
 *
 * G4 extensions: per-case attack `category` (the 9 contract categories),
 * session-kind variants (expired/revoked/forged/none/no-csrf/wrong-csrf),
 * and the full route surface (source, grant, group, membership, quarantine,
 * retention, export, job, logout, upload, health/error shapes).
 */
import { writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import type { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { computeAllowed } from './oracle.js';
import type { CanaryWorld } from './canary-corpus.js';

/** The 9 contract categories (docs/graph-and-acceptance.md §1,200-query gate). */
export type Category =
  | 'cross-tenant-idor'
  | 'acl'
  | 'lifecycle'
  | 'session-pool'
  | 'injection'
  | 'citations-source-export'
  | 'browser-errors'
  | 'pii'
  | 'evidence';

export type Surface =
  | 'query'
  | 'document'
  | 'documents'
  | 'versions'
  | 'version'
  | 'citation'
  | 'source'
  | 'grant'
  | 'group'
  | 'membership'
  | 'quarantine'
  | 'retention'
  | 'export'
  | 'job'
  | 'logout'
  | 'upload'
  | 'audit'
  | 'health'
  | 'error';

/** Per-case session variant. 'cached' reuses the subject's harness session. */
export type SessionKind =
  | 'cached'
  | 'fresh'
  | 'none'
  | 'forged'
  | 'expired'
  | 'revoked'
  | 'no-csrf'
  | 'wrong-csrf';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface AttackCase {
  name: string;
  subject: string;
  tenantId: string;
  surface: Surface;
  category: Category;
  mode: 'hybrid' | 'keyword' | 'vector';
  prompt?: string;
  /** Path id(s); composite targets use `${docId}/${versionId}`. */
  targetId?: string;
  /** Secondary path id (group member routes use targetId2 for the group). */
  targetId2?: string;
  /** Route variant for surfaces with multiple path shapes (group members). */
  subroute?: string;
  method?: HttpMethod;
  /** JSON body for state-changing cases; upload uses { filename, content }. */
  payload?: unknown;
  /** Query-string params (tenantId, filters, ...). */
  queryParams?: Record<string, string>;
  /** Extra headers (e.g. a wrong content-type). */
  headers?: Record<string, string>;
  /** Session variant; default 'cached'. */
  session?: SessionKind;
  /** Extra unique-tuple discriminator (filters/variants on one route+method). */
  discriminator?: string;
  expect: 'allowed' | 'denied';
}

export interface CaseResult {
  name: string;
  surface: Surface;
  category: Category;
  expect: string;
  status: number;
  decision: string;
  code: string;
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
  categoryCounts: Record<Category, number>;
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
  /** Session cookie name (the test's oidc config); used to craft forged/expired cookies. */
  cookieName?: string;
  /** Cookie header for a genuinely EXPIRED session of the subject (inserted with
   * a past expiry; get_session must reject it exactly like a revoked/forged token). */
  expiredCookieFor?: (subject: string) => Promise<string>;
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
// less likely to false-positive on hex canaries than bare digit runs). The
// production detector (packages/providers/src/pii.ts) aligns byte-identically
// with this scan, so redacted payloads can never trip it.
export const PII_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\+1-555-\d{8}|\b\d{3}-\d{2}-\d{4}\b|\b4\d{3} \d{4} \d{4} \d{4}\b/gi;

const STATE_CHANGING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function defaultMethodFor(surface: Surface): HttpMethod {
  switch (surface) {
    case 'query':
    case 'logout':
    case 'upload':
      return 'POST';
    default:
      return 'GET';
  }
}

export async function runAdversarialHarness(
  opts: HarnessOptions,
): Promise<AdversarialReport> {
  const cookieName = opts.cookieName ?? 'securerag_session';
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
  // the record offset between consecutive cases. Subject insertion order is
  // the array order (Map semantics), so the generators interleave tenants to
  // exercise shared-pool alternation between adjacent subjects.
  const bySubject = new Map<string, AttackCase[]>();
  for (const c of opts.cases) {
    const list = bySubject.get(c.subject) ?? [];
    list.push(c);
    bySubject.set(c.subject, list);
  }

  for (const subjectCases of bySubject.values()) {
    let spyOffset = (await opts.recordSpyPayloads()).length;

    for (const c of subjectCases) {
      const principalId = opts.principalIdFor(c.subject);
      const tenantId = c.tenantId;
      const sessionKind = c.session ?? 'cached';

      // Unique-tuple: (principal, authzState, corpusState, prompt/sequence,
      // retrieval mode, surface). The sequence discriminates every distinct
      // HTTP interaction: prompt (queries), method|surface|target, the
      // tenant claim, the session kind, the route/query params, and a digest
      // of the JSON payload (payload/param variants on one route+method).
      const authzState = authzHash(opts, principalId, tenantId);
      const payloadDigest =
        c.payload === undefined
          ? ''
          : createHash('sha1').update(JSON.stringify(c.payload)).digest('hex').slice(0, 8);
      const paramsDigest =
        c.queryParams === undefined
          ? ''
          : createHash('sha1').update(JSON.stringify(c.queryParams)).digest('hex').slice(0, 8);
      const sequence = [
        c.prompt ?? '',
        c.method ?? defaultMethodFor(c.surface),
        c.surface,
        c.targetId ?? '',
        tenantId,
        sessionKind,
        c.discriminator ?? '',
        paramsDigest,
        payloadDigest,
      ].filter((s) => s.length > 0).join('|');
      const tuple = [principalId, authzState, opts.corpusVersion, sequence, c.mode, c.surface].join('|');
      if (seenTuples.has(tuple)) {
        metrics.violations.push(`${c.name}: DUPLICATE TUPLE ${tuple.slice(0, 140)}`);
      }
      seenTuples.add(tuple);

      const { session, kind } = await resolveSession(opts, sessionCache, c, sessionKind, cookieName);
      const result = await executeCase(opts, session, kind, c);
      // A logout/revoked-session/fresh-session case invalidates the shared
      // cached session: the next cached case must log in again (a stale
      // session would make every following case fail for the wrong reason).
      if (kind !== 'cached' || c.surface === 'logout') {
        sessionCache.delete(c.subject);
      }
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
          // ADR-0005: model context NEVER carries raw PII, even for pii:read
          // principals (pii:read only widens human surfaces).
          if (PII_RE.test(text)) {
            violations.push('raw PII in model context');
            metrics.piiLeaks += 1;
          }
        }
      }

      // Response scan: canaries belonging to OTHER tenants; foreign doc/chunk/
      // version/job ids; foreign tenant ids in audit rows; headers too.
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
      const foreignJobIds2 = foreignJobIds(opts, tenantId, responseText);
      if (foreignJobIds2.length > 0) {
        violations.push(`foreign job ids in response: ${foreignJobIds2.join(',')}`);
        metrics.unauthorizedDisclosures += 1;
      }
      if ((c.surface === 'audit' || c.surface === 'export') && result.status === 200) {
        const foreign = foreignTenantIds(opts, tenantId, responseText);
        if (foreign.length > 0) {
          violations.push(`foreign tenant id in audit response`);
          metrics.auditIsolationFailures += 1;
        }
      }
      // ADR-0005: raw PII in a response is a leak for ANY principal; pii:read
      // applies to human surfaces through redaction, never raw emission.
      if (PII_RE.test(responseText)) {
        violations.push('raw PII in response');
        metrics.piiLeaks += 1;
      }

      // Outcome expectations: denied cases must not carry content (any typed
      // 4xx refusal counts; a refused decision with a stable code counts);
      // allowed query cases must answer; allowed non-query cases must succeed
      // (positive controls on every surface).
      if (c.expect === 'denied') {
        metrics.refusalRecallDenominator += 1;
        const refused =
          result.decision === 'refused' || (result.status >= 400 && result.status < 500);
        if (refused) metrics.refusalRecall += 1;
        else violations.push(`denied case returned ${result.status}/${result.decision}`);
      }
      if (c.expect === 'allowed' && c.surface === 'query') {
        metrics.authorizedAnswerDenominator += 1;
        if (result.decision === 'answered') metrics.authorizedAnswerSuccess += 1;
        else violations.push(`allowed query did not answer: ${result.status}/${result.decision}`);
      }
      if (c.expect === 'allowed' && c.surface !== 'query' && !(result.status >= 200 && result.status < 400)) {
        violations.push(`allowed ${c.surface} did not succeed: ${result.status} ${result.body.slice(0, 120)}`);
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
    caseCounts: surfaceCounts(results),
    categoryCounts: categoryCounts(results),
  };

  if (opts.reportDir !== undefined) {
    await mkdir(opts.reportDir, { recursive: true });
    const sanitized = sanitizeReport(report, results);
    await writeFile(`${opts.reportDir}/adversarial.json`, JSON.stringify(sanitized, null, 2));
    await writeFile(`${opts.reportDir}/adversarial.md`, reportToMarkdown(report, results));
  }

  return report;
}

function surfaceCounts(results: CaseResult[]): Record<Surface, number> {
  const counts = {} as Record<Surface, number>;
  for (const r of results) counts[r.surface] = (counts[r.surface] ?? 0) + 1;
  return counts;
}

function categoryCounts(results: CaseResult[]): Record<Category, number> {
  const counts = {} as Record<Category, number>;
  for (const r of results) counts[r.category] = (counts[r.category] ?? 0) + 1;
  return counts;
}

/** Resolve the per-case session + kind. 'cached' sessions are shared per
 * subject; every other kind is built fresh and never cached. */
async function resolveSession(
  opts: HarnessOptions,
  sessionCache: Map<string, Session>,
  c: AttackCase,
  kind: SessionKind,
  cookieName: string,
): Promise<{ session: Session | null; kind: SessionKind }> {
  switch (kind) {
    case 'none':
      return { session: null, kind };
    case 'forged': {
      // Opaque 43-char base64url token that was never issued (default deny).
      const token = 'A'.repeat(43);
      return {
        session: { cookieHeader: `${cookieName}=${token}`, csrfToken: 'a'.repeat(64) },
        kind,
      };
    }
    case 'expired': {
      if (opts.expiredCookieFor === undefined) {
        throw new Error('expiredCookieFor is required for session=expired cases');
      }
      return { session: { cookieHeader: await opts.expiredCookieFor(c.subject), csrfToken: '' }, kind };
    }
    case 'revoked': {
      // Fresh login, then logout (revokes server-side), then REUSE the revoked
      // cookie: the follow-up request must be rejected exactly like forged/expired.
      const fresh = await opts.login(c.subject);
      await fetch(`${opts.base}/auth/logout`, {
        method: 'POST',
        headers: {
          cookie: fresh.cookieHeader,
          'content-type': 'application/json',
          'x-csrf-token': fresh.csrfToken,
        },
      });
      return { session: fresh, kind };
    }
    case 'fresh':
      return { session: await opts.login(c.subject), kind };
    case 'cached':
    default: {
      let session = sessionCache.get(c.subject);
      if (session === undefined) {
        session = await opts.login(c.subject);
        sessionCache.set(c.subject, session);
      }
      return { session, kind };
    }
  }
}

function buildUrl(opts: HarnessOptions, c: AttackCase): string {
  const base = opts.base;
  const qs = new URLSearchParams(c.queryParams ?? {}).toString();
  const suffix = qs.length > 0 ? `?${qs}` : '';
  switch (c.surface) {
    case 'query':
      return `${base}/retrieval/query`;
    case 'document':
      return `${base}/documents/${c.targetId ?? ''}`;
    case 'documents':
      return `${base}/documents${suffix}`;
    case 'versions':
      return `${base}/documents/${c.targetId ?? ''}/versions`;
    case 'version':
    case 'source': {
      const [docId, versionId] = (c.targetId ?? '/').split('/');
      const tail = c.surface === 'source' ? '/source' : '';
      return `${base}/documents/${docId ?? ''}/versions/${versionId ?? ''}${tail}`;
    }
    case 'citation':
      return `${base}/citations/${c.targetId ?? ''}`;
    case 'grant':
      return `${base}/documents/${c.targetId ?? ''}/grants`;
    case 'group': {
      if (c.subroute === 'members') {
        return `${base}/groups/${c.targetId ?? ''}/members${suffix}`;
      }
      return `${base}/groups${suffix}`;
    }
    case 'membership':
      return `${base}/memberships${suffix}`;
    case 'quarantine': {
      const method = c.method ?? 'GET';
      if (method !== 'GET') {
        return `${base}/quarantine/${c.targetId ?? ''}/review`;
      }
      return `${base}/quarantine${suffix}`;
    }
    case 'retention':
      return `${base}/retention-policy${suffix}`;
    case 'export':
      return `${base}/audit/export${suffix}`;
    case 'job':
      return `${base}/jobs/${c.targetId ?? ''}`;
    case 'logout':
      return `${base}/auth/logout`;
    case 'upload':
      return `${base}/documents/${c.targetId ?? ''}/versions/upload`;
    case 'audit':
      return `${base}/audit/retrieval${suffix}`;
    case 'health':
      return `${base}/${c.targetId ?? 'healthz'}`;
    case 'error':
      return `${base}${c.targetId ?? ''}${suffix}`;
  }
}

async function executeCase(
  opts: HarnessOptions,
  session: Session | null,
  kind: SessionKind,
  c: AttackCase,
): Promise<CaseResult> {
  const method = c.method ?? defaultMethodFor(c.surface);
  const headers: Record<string, string> = { ...(c.headers ?? {}) };
  if (session !== null) headers['cookie'] = session.cookieHeader;

  const isStateChanging = STATE_CHANGING_METHODS.has(method);
  if (isStateChanging) {
    if (kind === 'no-csrf') {
      // Valid session but the browser-like state-changing request omits the
      // CSRF header -> the session hook MUST reject with 403 before the route.
    } else if (kind === 'wrong-csrf') {
      headers['x-csrf-token'] = '0'.repeat(64);
    } else if (session !== null) {
      headers['x-csrf-token'] = session.csrfToken;
    }
  }

  let body = '';
  let headerText = '';
  let status = 0;
  let code = '';

  const capture = async (res: Response): Promise<Response> => {
    headerText = [...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n');
    return res;
  };

  try {
    const url = buildUrl(opts, c);
    let init: RequestInit = { method, headers };
    if (c.surface === 'upload') {
      const p = (c.payload ?? {}) as { filename?: string; content?: string };
      const fd = new FormData();
      if (p.filename !== undefined || p.content !== undefined) {
        fd.append('file', new Blob([p.content ?? 'placeholder upload bytes'], { type: 'text/plain' }), p.filename ?? 'document.txt');
      }
      init = { method, headers, body: fd };
    } else if (method !== 'GET' && method !== 'DELETE' || (method === 'DELETE' && c.payload !== undefined)) {
      // Query cases default the body from the case's tenantId+prompt; explicit
      // payloads (malformed-input probes) override.
      const payload =
        c.surface === 'query' && c.payload === undefined
          ? { tenantId: c.tenantId, question: c.prompt ?? '' }
          : c.payload;
      // A case-supplied content-type (e.g. a wrong content-type probe) wins.
      if (headers['content-type'] === undefined) headers['content-type'] = 'application/json';
      init = { method, headers, body: JSON.stringify(payload ?? {}) };
    }

    const res = await capture(await fetch(url, init));
    status = res.status;
    body = await res.text();
    const outcome = parseOutcome(body);
    code = outcome.code;
    const decision =
      c.surface === 'query' ? outcome.decision : status >= 200 && status < 400 ? 'ok' : 'error';
    return { name: c.name, surface: c.surface, category: c.category, expect: c.expect, status, decision, code, body, headers: headerText, uniqueTuple: '', violations: [] };
  } catch (err) {
    return { name: c.name, surface: c.surface, category: c.category, expect: c.expect, status, decision: `exception: ${String(err)}`, code, body, headers: headerText, uniqueTuple: '', violations: [] };
  }
}

function parseOutcome(body: string): { decision: string; code: string } {
  try {
    const parsed = JSON.parse(body) as { decision?: string; code?: string };
    return { decision: parsed.decision ?? '', code: parsed.code ?? '' };
  } catch {
    return { decision: '', code: '' };
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

/** Foreign job ids (job/upload surfaces: opaque statuses, own tenant only). */
function foreignJobIds(opts: HarnessOptions, tenantId: string, text: string): string[] {
  const found: string[] = [];
  for (const m of text.matchAll(UUID_RE)) {
    const id = m[0].toLowerCase();
    const job = opts.world.facts.jobs.find((j) => j.jobId === id);
    if (job !== undefined && job.tenantId !== tenantId) found.push(id);
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
      category: r.category,
      expect: r.expect,
      status: r.status,
      decision: r.decision,
      code: r.code,
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
    `- Category counts: ${JSON.stringify(report.categoryCounts)}`,
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
        `- [${r.status}] ${r.category}/${r.surface}/${r.name} expect=${r.expect} decision=${r.decision} code=${r.code} violations=${r.violations.length}`,
    ),
  ];
  return lines.join('\n');
}

export { computeAllowed };
