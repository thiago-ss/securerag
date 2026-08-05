import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator } from '@securerag/providers';
import {
  DETERMINISTIC_EMBEDDING,
  InMemorySourceObjectStore,
} from '@securerag/core';
import {
  DETERMINISTIC_MALWARE_SCANNER,
  HEURISTIC_INJECTION_DETECTOR,
  STANDARD_EXTRACTION,
} from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { getTestDb, resetData, seedFixtures, seedGrant, type TestDb } from '@securerag/db/src/testkit.js';
import { buildApp } from '../src/app.js';
import { loginViaOidc } from '../src/testkit.js';
import { runWorkerOnce, type WorkerDeps } from '@securerag/worker/src/index.js';

/**
 * S2 API e2e: multipart upload -> job -> worker pipeline -> authorized
 * source stream. RLS is never mocked; the stream route re-checks the grant
 * per request and foreign/nonexistent versions share the 404 body.
 */
describe('S2 ingestion over HTTP (upload, jobs, authorized source stream)', () => {
  let db: TestDb;
  let world: Awaited<ReturnType<typeof seedFixtures>>;
  let provider: FakeOidcProvider;
  let app: FastifyInstance;
  let base: string;
  let store: InMemorySourceObjectStore;

  const workerDeps = (): WorkerDeps => ({
    workerPool: db.workerPool,
    purgePool: db.purgePool,
    store,
    extractor: STANDARD_EXTRACTION,
    scanner: DETERMINISTIC_MALWARE_SCANNER,
    detector: HEURISTIC_INJECTION_DETECTOR,
    embedding: DETERMINISTIC_EMBEDDING,
  });

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await seedFixtures(db.superuserPool);
    // Alice manages docA (the upload route is manage-gated, ADR-0007);
    // manage implies read for the source stream (grant predicate, grants.ts).
    await seedGrant(db.superuserPool, {
      tenantId: world.tenantA.id,
      documentId: world.docA.id,
      subjectType: 'principal',
      subjectId: world.alice.id,
      capability: 'manage',
    });
    store = new InMemorySourceObjectStore();
    provider = new FakeOidcProvider({ issuer: 'test-issuer', clientId: 'securerag-api' });
    await provider.start();
    app = await buildApp({
      pool: db.apiPool,
      providers: new SpyGenerator(),
      store,
      oidc: {
        issuer: 'test-issuer',
        clientId: 'securerag-api',
        redirectUri: 'http://securerag.test/auth/callback',
        postLogoutRedirectUri: 'http://securerag.test/',
        discoveryUrl: provider.discoveryUrl,
        sessionCookieName: 'securerag_session',
        sessionCookieSecure: false,
        sessionTtlSeconds: 3600,
        postLoginRedirectPath: '/',
      },
    });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await app.close();
    await provider.stop();
    await db.stop();
  });

  async function uploadAs(
    session: { cookieHeader: string; csrfToken: string },
    bytes: Buffer,
    filename: string,
    contentType: string,
    documentId: string,
  ) {
    const boundary = `----securerag${randomUUID().replace(/-/g, '')}`;
    const body = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\ncontent-disposition: form-data; name="file"; filename="${filename}"\r\n` +
          `content-type: ${contentType}\r\n\r\n`,
        'utf8',
      ),
      bytes,
      Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8'),
    ]);
    return fetch(`${base}/documents/${documentId}/versions/upload`, {
      method: 'POST',
      headers: {
        cookie: session.cookieHeader,
        'x-csrf-token': session.csrfToken,
        'content-type': `multipart/form-data; boundary=${boundary}`,
      },
      body,
    });
  }

  it('upload -> job -> worker pipeline -> source stream 200 byte-identical to the upload', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const bytes = Buffer.from(
      'SecureRAG ingestion API round trip.\nContact bob@example.com for follow-up.',
      'utf8',
    );

    const upload = await uploadAs(
      alice,
      bytes,
      'roundtrip.txt',
      'text/plain',
      world.docA.id,
    );
    expect(upload.status).toBe(201);
    const staged = (await upload.json()) as { jobId: string; versionId: string };
    expect(staged.versionId).toBeTruthy();

    // Status endpoint: opaque job metadata, own tenant only.
    const status = await fetch(`${base}/jobs/${staged.jobId}`, {
      headers: { cookie: alice.cookieHeader },
    });
    expect(status.status).toBe(200);
    const job = (await status.json()) as { status: string; jobType: string };
    expect(job.jobType).toBe('ingest');
    expect(['pending', 'running', 'succeeded']).toContain(job.status);

    // Run the worker inline (same store the API wrote to) to complete the
    // pipeline, exactly like the daemon would.
    const result = await runWorkerOnce(workerDeps(), { limit: 10 });
    expect(result.failed).toBe(0);

    const done = (await (await fetch(`${base}/jobs/${staged.jobId}`, {
      headers: { cookie: alice.cookieHeader },
    })).json()) as { status: string };
    expect(done.status).toBe('succeeded');

    // Authorized source stream: byte-identical to the uploaded bytes.
    const stream = await fetch(
      `${base}/documents/${world.docA.id}/versions/${staged.versionId}/source`,
      { headers: { cookie: alice.cookieHeader } },
    );
    expect(stream.status).toBe(200);
    const streamed = Buffer.from(await stream.arrayBuffer());
    expect(streamed.equals(bytes)).toBe(true);
    expect(stream.headers.get('content-type')).toBe('application/octet-stream');

    // The pipeline redacted the PII before chunking: chunks hold the token.
    const { rows } = await db.superuserPool.query<{ text_redacted: string }>(
      `SELECT text_redacted FROM securerag.chunks WHERE version_id = $1`,
      [staged.versionId],
    );
    expect(rows.some((r) => r.text_redacted.includes('[EMAIL]'))).toBe(true);
    expect(rows.some((r) => r.text_redacted.includes('bob@example.com'))).toBe(false);
  });

  it('a second upload of the same content is deduplicated to the same job (idempotent)', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const bytes = Buffer.from('duplicate content bytes', 'utf8');
    const first = await uploadAs(alice, bytes, 'dup.txt', 'text/plain', world.docA.id);
    const second = await uploadAs(alice, bytes, 'dup.txt', 'text/plain', world.docA.id);
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    const a = (await first.json()) as { jobId: string; versionId: string };
    const b = (await second.json()) as { jobId: string; versionId: string };
    expect(b.jobId).toBe(a.jobId);
    expect(b.versionId).toBe(a.versionId);
  });

  it('source stream: foreign tenant document, foreign version, and nonexistent all 404 identically', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    // Foreign document (tenant B's doc) with alice's session.
    const foreignDoc = await fetch(
      `${base}/documents/${world.docB.id}/versions/${world.docB.versionId}/source`,
      { headers: { cookie: alice.cookieHeader } },
    );
    // Random (nonexistent) document + version.
    const random = await fetch(
      `${base}/documents/${randomUUID()}/versions/${randomUUID()}/source`,
      { headers: { cookie: alice.cookieHeader } },
    );
    // Random version of a REAL document alice has no grant on (docB).
    const foreignVersion = await fetch(
      `${base}/documents/${world.docB.id}/versions/${randomUUID()}/source`,
      { headers: { cookie: alice.cookieHeader } },
    );
    expect(foreignDoc.status).toBe(404);
    expect(random.status).toBe(404);
    expect(foreignVersion.status).toBe(404);
    const foreignText = await foreignDoc.text();
    const randomText = await random.text();
    const foreignVersionText = await foreignVersion.text();
    expect(foreignText).toBe(randomText);
    expect(foreignVersionText).toBe(randomText);
  });

  it('an upload by a non-manager (member without manage grant) 404s indistinguishably', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    // docB belongs to tenant B; alice is a member of tenant A only. The
    // across-tenants probe never passes the manage gate.
    const upload = await uploadAs(alice, Buffer.from('x'), 'x.txt', 'text/plain', world.docB.id);
    expect(upload.status).toBe(404);
  });

  it('CSRF is enforced on multipart uploads (state-changing)', async () => {
    const alice = await loginViaOidc(base, provider, 'alice-sub');
    const boundary = `----securerag${randomUUID().replace(/-/g, '')}`;
    const body = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\ncontent-disposition: form-data; name="file"; filename="n.txt"\r\n` +
          `content-type: text/plain\r\n\r\n`,
        'utf8',
      ),
      Buffer.from('no csrf'),
      Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8'),
    ]);
    const response = await fetch(`${base}/documents/${world.docA.id}/versions/upload`, {
      method: 'POST',
      headers: {
        cookie: alice.cookieHeader,
        'content-type': `multipart/form-data; boundary=${boundary}`,
      },
      body,
    });
    expect(response.status).toBe(403);
  });
});
