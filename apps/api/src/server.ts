import { createRuntimePool } from '@securerag/security';
import { SpyGenerator } from '@securerag/providers';
import { buildApp } from './app.js';
import { envSchema } from './schemas.js';

/**
 * API entrypoint (T3 contract §API, apps/api deliverable). Reads the runtime
 * environment via the zod env schema, builds the least-privilege
 * securerag_api pool, and starts the Fastify server. Graceful shutdown:
 * SIGTERM/SIGINT close the server first, then the pool.
 *
 * T3 provider: the deterministic SpyGenerator is the ONLY generator in this
 * node (contract: "model spy is the only generator"); real adapters land
 * behind the same AnswerGenerator seam later.
 */
const env = envSchema.parse(process.env);

const pool = createRuntimePool('securerag_api', {
  host: env.PGHOST,
  port: env.PGPORT,
  database: env.PGDATABASE,
  password: env.PGPASSWORD,
  max: 10,
});

const app = await buildApp({ pool, providers: new SpyGenerator() });

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
