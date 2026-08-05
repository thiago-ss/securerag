import { readFile } from 'node:fs/promises';
import { GenericContainer, Wait } from 'testcontainers';
import pg from 'pg';
import { applyMigrations } from '../src/migrate.js';

const { Pool } = pg;

export const PGVECTOR_IMAGE = 'pgvector/pgvector:0.8.6-pg18';

/** The ready log line can race the first real connection; retry until the server answers. */
async function waitForReady(pool: pg.Pool): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const client = await pool.connect();
      await client.query('SELECT 1');
      client.release();
      return;
    } catch (err) {
      lastError = err;
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw new Error(`postgres never became ready: ${String(lastError)}`);
}

export interface TestDb {
  superuserPool: pg.Pool;
  migrationPool: pg.Pool;
  apiPool: pg.Pool;
  workerPool: pg.Pool;
  host: string;
  port: number;
  stop: () => Promise<void>;
}

export const TEST_PASSWORDS = {
  securerag_migration: 'migration-test-password',
  securerag_api: 'api-test-password',
  securerag_worker: 'worker-test-password',
  securerag_audit_retention: 'audit-retention-test-password',
  securerag_purge: 'purge-test-password',
} as const;

let cached: TestDb | null = null;

/** Shared PostgreSQL 18 + pgvector container for the whole test process. */
export async function getTestDb(): Promise<TestDb> {
  if (cached) return cached;

  const container = await new GenericContainer(PGVECTOR_IMAGE)
    .withEnvironment({
      POSTGRES_DB: 'securerag',
      POSTGRES_USER: 'postgres',
      POSTGRES_PASSWORD: 'superuser-test-password',
    })
    .withExposedPorts(5432)
    .withWaitStrategy(
      Wait.forLogMessage(/database system is ready to accept connections/),
    )
    .start();

  const port = container.getMappedPort(5432);
  const host = container.getHost();

  const superuserPool = new Pool({
    host,
    port,
    database: 'securerag',
    user: 'postgres',
    password: 'superuser-test-password',
    max: 3,
  });

  await waitForReady(superuserPool);

  // Bootstrap: run the roles+extensions bootstrap migration as the container
  // superuser, assign generated passwords to the runtime roles (never stored in
  // the repo). Schema migrations (0002+) run as the ephemeral migration role.
  const bootstrapSql = await readFile(
    new URL('../migrations/bootstrap/0001_roles_and_extensions.sql', import.meta.url),
    'utf8',
  );
  await superuserPool.query(bootstrapSql);
  for (const [role, password] of Object.entries(TEST_PASSWORDS)) {
    await superuserPool.query(
      `ALTER ROLE ${role} LOGIN PASSWORD '${password.replace(/'/g, "''")}'`,
    );
  }

  const migrationPool = new Pool({
    host,
    port,
    database: 'securerag',
    user: 'securerag_migration',
    password: TEST_PASSWORDS['securerag_migration'],
    max: 3,
  });
  await applyMigrations(migrationPool);

  const makePool = (role: 'securerag_api' | 'securerag_worker'): pg.Pool =>
    new Pool({
      host,
      port,
      database: 'securerag',
      user: role,
      password: TEST_PASSWORDS[role],
      max: 3,
    });

  cached = {
    superuserPool,
    migrationPool,
    apiPool: makePool('securerag_api'),
    workerPool: makePool('securerag_worker'),
    host,
    port,
    stop: async () => {
      await superuserPool.end();
      await migrationPool.end();
      await cached?.apiPool.end();
      await cached?.workerPool.end();
      await container.stop();
      cached = null;
    },
  };
  return cached;
}
