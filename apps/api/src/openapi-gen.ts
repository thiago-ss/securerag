import { writeFile } from 'node:fs/promises';
import pg from 'pg';
import YAML from 'yaml';
import { InMemorySourceObjectStore } from '@securerag/core';
import { SpyGenerator } from '@securerag/providers';
import { buildApp } from './app.js';

/**
 * Regenerates the committed OpenAPI document at apps/api/openapi.yaml from the
 * live route registrations (npm run openapi:gen --workspace @securerag/api).
 *
 * The pool here is never connected and the OIDC issuer is a placeholder: it
 * exists only so buildApp can register routes; no request ever reaches the
 * provider or the database during generation (OIDC discovery is lazy).
 */
const { Pool } = pg;
const pool = new Pool({
  host: 'localhost',
  database: 'securerag',
  user: 'securerag_api',
  password: 'unused-for-openapi-generation',
});

try {
  const app = await buildApp({
    pool,
    providers: new SpyGenerator(),
    store: new InMemorySourceObjectStore(),
    oidc: {
      issuer: 'https://id.example.invalid',
      clientId: 'securerag-api',
      redirectUri: 'https://securerag.example.invalid/auth/callback',
      sessionCookieName: '__Host-securerag_session',
      sessionCookieSecure: true,
    },
  });
  await app.ready();
  const document = app.swagger();
  const yaml = YAML.stringify(document);
  const target = new URL('../openapi.yaml', import.meta.url);
  await writeFile(target, yaml);
  const paths = Object.keys(document.paths ?? {}).length;
  console.log(`openapi.yaml written (${yaml.length} bytes, ${paths} path(s))`);
  await app.close();
} finally {
  await pool.end();
}
