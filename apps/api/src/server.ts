import { createRuntimePool, sessionCookieName } from '@securerag/security';
import { InMemorySourceObjectStore, S3SourceObjectStore } from '@securerag/core';
import { SpyGenerator } from '@securerag/providers';
import { buildApp } from './app.js';
import { envSchema } from './schemas.js';

/**
 * API entrypoint (S1/S2). Reads the runtime environment via the zod env schema,
 * builds the least-privilege securerag_api pool, wires the real OIDC provider
 * configuration (issuer = trust anchor), and starts the Fastify server.
 * Graceful shutdown: SIGTERM/SIGINT close the server first, then the pool.
 *
 * S1 provider: the deterministic SpyGenerator is the ONLY generator in this
 * node; real adapters land behind the same AnswerGenerator seam later.
 * S2 store: SOURCE_STORE selects the object adapter ('memory' for CI/demo,
 * 's3' for S3/MinIO with SSE-S3 behind the S3_* env config).
 */
const env = envSchema.parse(process.env);

const pool = createRuntimePool('securerag_api', {
  host: env.PGHOST,
  port: env.PGPORT,
  database: env.PGDATABASE,
  password: env.PGPASSWORD,
  max: 10,
});

const store = env.SOURCE_STORE === 's3'
  ? new S3SourceObjectStore({
      bucket: env.S3_BUCKET,
      ...(env.S3_ENDPOINT !== undefined ? { endpoint: env.S3_ENDPOINT } : {}),
      region: env.S3_REGION,
      forcePathStyle: env.S3_FORCE_PATH_STYLE,
      ...(env.S3_ACCESS_KEY_ID !== undefined && env.S3_SECRET_ACCESS_KEY !== undefined
        ? { accessKeyId: env.S3_ACCESS_KEY_ID, secretAccessKey: env.S3_SECRET_ACCESS_KEY }
        : {}),
    })
  : new InMemorySourceObjectStore();

const sessionCookieSecure = env.SESSION_COOKIE_SECURE;
const app = await buildApp({
  pool,
  providers: new SpyGenerator(),
  store,
  oidc: {
    issuer: env.OIDC_ISSUER,
    clientId: env.OIDC_CLIENT_ID,
    redirectUri: env.OIDC_REDIRECT_URI,
    ...(env.OIDC_POST_LOGOUT_REDIRECT_URI !== undefined
      ? { postLogoutRedirectUri: env.OIDC_POST_LOGOUT_REDIRECT_URI }
      : {}),
    ...(env.OIDC_DISCOVERY_URL !== undefined ? { discoveryUrl: env.OIDC_DISCOVERY_URL } : {}),
    sessionCookieName: sessionCookieName(sessionCookieSecure),
    sessionCookieSecure,
    sessionTtlSeconds: env.SESSION_TTL_SECONDS,
    postLoginRedirectPath: '/',
    postLogoutRedirectPath: '/',
  },
});

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`securerag-api graceful shutdown (${signal})`);
  try {
    await app.close();
  } finally {
    await pool.end();
    process.exit(0);
  }
}
process.on('SIGTERM', () => {
  void shutdown('SIGTERM');
});
process.on('SIGINT', () => {
  void shutdown('SIGINT');
});

try {
  await app.listen({ port: env.PORT, host: env.HOST });
  console.log(`securerag-api listening on http://${env.HOST}:${env.PORT}`);
} catch (err) {
  console.error('securerag-api failed to start', err);
  await pool.end();
  process.exit(1);
}
