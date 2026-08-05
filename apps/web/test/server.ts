/**
 * Playwright webServer: boots the REAL API (Testcontainers PostgreSQL +
 * FakeOidcProvider + Fastify) and the vite dev server with a /api proxy, so
 * browser tests exercise real behavior (OIDC redirect, session cookie, CSRF,
 * RLS) end-to-end. Control endpoints drive the deterministic fake identity
 * provider. The API's security posture is unchanged: least-privilege pool,
 * T3 corpus (default-deny grants, a quarantined version), zero mocks.
 */
import type { AddressInfo } from 'node:net';
import { createServer as createViteServer, type ViteDevServer } from 'vite';
import react from '@vitejs/plugin-react';
import type { FastifyInstance } from 'fastify';
import { SpyGenerator } from '@securerag/providers';
import { FakeOidcProvider } from '@securerag/security/src/testkit.js';
import { InMemorySourceObjectStore } from '@securerag/core';
import { getTestDb, resetData, type TestDb } from '@securerag/db/src/testkit.js';
import { buildT3Corpus, type T3Corpus } from '@securerag/eval/src/fixtures.js';
import { buildApp, type OidcApiConfig } from '@securerag/api/src/app.js';

const PORT = Number(process.env['WEB_TEST_PORT'] ?? 5173);
const HOST = '127.0.0.1';
const SUBJECTS: Record<string, string> = {
  alice: 'alice-sub',
  carol: 'carol-sub',
};

const db: TestDb = await getTestDb();
await resetData(db.superuserPool);
const corpus: T3Corpus = await buildT3Corpus(db.superuserPool);

const provider = new FakeOidcProvider({ issuer: 'test-issuer', clientId: 'securerag-api' });
await provider.start();

const oidc: OidcApiConfig = {
  issuer: 'test-issuer',
  clientId: 'securerag-api',
  // Must match the origin the browser actually uses (Playwright baseURL);
  // localhost vs 127.0.0.1 are different cookie origins.
  redirectUri: `http://${HOST}:${PORT}/api/auth/callback`,
  postLogoutRedirectUri: `http://${HOST}:${PORT}/`,
  discoveryUrl: provider.discoveryUrl,
  sessionCookieName: 'securerag_session',
  sessionCookieSecure: false,
  sessionTtlSeconds: 3600,
};

const app: FastifyInstance = await buildApp({
  pool: db.apiPool,
  providers: new SpyGenerator(),
  store: new InMemorySourceObjectStore(),
  oidc,
});
await app.listen({ port: 0, host: HOST });
const apiBase = `http://${HOST}:${(app.server.address() as AddressInfo).port}`;

/** Control middleware: subject selection + world ids for assertions. */
function controlPlugin(): { name: string; configureServer(server: ViteDevServer): void } {
  return {
    name: 'securerag-test-control',
    configureServer(server) {
      server.middlewares.use('/__control', (req, res) => {
        const url = new URL(req.url ?? '/', `http://${HOST}:${PORT}`);
        res.setHeader('content-type', 'application/json');
        if (url.pathname === '/ready') {
          res.end(JSON.stringify({ ok: true }));
          return;
        }
        if (url.pathname === '/world') {
          res.end(
            JSON.stringify({
              tenantA: corpus.world.tenantA.id,
              tenantB: corpus.world.tenantB.id,
              docA: corpus.world.docA.id,
              docA2: corpus.world.docA2.id,
              alice: corpus.world.alice.id,
              bob: corpus.world.bob.id,
              carol: corpus.world.carol.id,
              quarantinedVersion: corpus.world.quarantinedVersion.id,
            }),
          );
          return;
        }
        if (req.method === 'POST' && url.pathname === '/subject') {
          let body = '';
          req.on('data', (chunk: Buffer) => {
            body += chunk.toString();
          });
          req.on('end', () => {
            const parsed = JSON.parse(body === '' ? '{}' : body) as { subject?: string };
            if (parsed.subject === undefined || SUBJECTS[parsed.subject] === undefined) {
              res.statusCode = 400;
              res.end(JSON.stringify({ error: 'unknown subject; use alice|carol' }));
              return;
            }
            provider.defaultSubject = SUBJECTS[parsed.subject] ?? 'alice-sub';
            res.end(JSON.stringify({ ok: true, subject: provider.defaultSubject }));
          });
          return;
        }
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'not_found' }));
      });
    },
  };
}

const vite: ViteDevServer = await createViteServer({
  configFile: false,
  root: new URL('..', import.meta.url).pathname,
  plugins: [react(), controlPlugin()],
  server: {
    host: HOST,
    port: PORT,
    strictPort: true,
    proxy: {
      '/api': {
        target: apiBase,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  logLevel: 'error',
});
await vite.listen();

const address = vite.httpServer?.address();
const boundPort = typeof address === 'object' && address !== null ? address.port : PORT;
console.log(`securerag web test server ready on http://${HOST}:${boundPort} (api ${apiBase})`);
