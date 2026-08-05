import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Pool, PoolClient, PoolConfig } from 'pg';
import { fileURLToPath } from 'node:url';

export interface MigrationRow {
  filename: string;
  checksum: string;
  applied_at: Date;
}

const MIGRATIONS_DIR = fileURLToPath(
  new URL('../migrations', import.meta.url),
);

const LOCK_KEY = 0x5ec2_2ea9;

/**
 * Applies pending SQL migrations in lexical order inside one transaction each,
 * protected by an advisory lock. Idempotent: already-applied files are skipped,
 * and any drift between the stored and current file checksum raises.
 *
 * Bootstrap files (role creation, extensions) live in `migrations/bootstrap/` and
 * run once as the superuser bootstrap role, never through this runner.
 */
export async function applyMigrations(
  pool: Pool,
  options: { dir?: string } = {},
): Promise<MigrationRow[]> {
  const dir = options.dir ?? MIGRATIONS_DIR;
  await ensureMigrationTable(pool);

  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_KEY]);
    const files = (await readdir(dir))
      .filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f))
      .sort();

    const rows = await asOwner(client, async () =>
      client.query<MigrationRow>(
        'SELECT filename, checksum, applied_at FROM securerag.migrations ORDER BY filename',
      ),
    );
    const applied = new Map(rows.rows.map((r) => [r.filename, r.checksum]));

    const stored = new Set(applied.keys());
    const onDisk = new Set(files);
    for (const filename of stored) {
      if (!onDisk.has(filename)) {
        throw new Error(
          `migration drift: ${filename} was applied but no longer exists in ${dir}`,
        );
      }
    }

    for (const file of files) {
      const content = await readFile(path.join(dir, file), 'utf8');
      const checksum = createHash('sha256').update(content).digest('hex');
      const previous = applied.get(file);
      if (previous !== undefined) {
        if (previous !== checksum) {
          throw new Error(
            `migration drift detected for ${file}: stored checksum ${previous} != current ${checksum}`,
          );
        }
        continue;
      }
      await client.query('BEGIN');
      try {
        await client.query(content);
        await asOwner(client, () =>
          client.query(
            `INSERT INTO securerag.migrations (filename, checksum) VALUES ($1, $2)`,
            [file, checksum],
          ),
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      }
    }
    const final = await asOwner(client, async () =>
      client.query<MigrationRow>(
        'SELECT filename, checksum, applied_at FROM securerag.migrations ORDER BY filename',
      ),
    );
    return final.rows;
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    client.release();
  }
}

async function ensureMigrationTable(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('SET ROLE securerag_owner');
    await client.query(
      `CREATE SCHEMA IF NOT EXISTS securerag AUTHORIZATION securerag_owner`,
    );
    await client.query(
      `CREATE TABLE IF NOT EXISTS securerag.migrations (
         filename   text PRIMARY KEY,
         checksum   text NOT NULL,
         applied_at timestamptz NOT NULL DEFAULT now()
       )`,
    );
    await client.query('RESET ROLE');
  } finally {
    client.release();
  }
}

async function asOwner<T>(client: PoolClient, fn: () => Promise<T>): Promise<T> {
  await client.query('SET ROLE securerag_owner');
  try {
    return await fn();
  } finally {
    await client.query('RESET ROLE');
  }
}

/** Connection settings for the configured runtime roles (passwords from env/secrets). */
export function runtimePool(
  role: 'securerag_api' | 'securerag_worker',
  config: PoolConfig,
): PoolConfig {
  return { ...config, user: role, application_name: `securerag-${role}` };
}

export { MIGRATIONS_DIR };
