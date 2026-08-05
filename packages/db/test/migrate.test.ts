import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getTestDb, type TestDb } from './helpers.js';
import { applyMigrations } from '../src/migrate.js';
import type { Pool } from 'pg';

describe('migration runner', () => {
  let db: TestDb;
  let pool: Pool;

  beforeAll(async () => {
    db = await getTestDb();
    pool = db.migrationPool;
  });

  afterAll(async () => {
    await db.stop();
  });

  it('applies all migrations idempotently with recorded checksums', async () => {
    const first = await applyMigrations(pool);
    expect(first.map((r) => r.filename)).toEqual([
      '0002_schema.sql',
      '0003_rls_and_grants.sql',
    ]);
    const second = await applyMigrations(pool);
    expect(second.map((r) => r.filename)).toEqual(first.map((r) => r.filename));
    for (const row of second) {
      expect(row.checksum).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('detects drift between stored and current migration checksums', async () => {
    const { rows: before } = await pool.query<{ filename: string; checksum: string }>(
      'SELECT filename, checksum FROM securerag.migrations',
    );
    const original = new Map(before.map((r) => [r.filename, r.checksum] as const));
    await pool.query(
      `UPDATE securerag.migrations SET checksum = repeat('0', 64) WHERE filename = '0002_schema.sql'`,
    );
    await expect(applyMigrations(pool)).rejects.toThrow(/drift/);
    for (const [filename, checksum] of original) {
      await pool.query(`UPDATE securerag.migrations SET checksum = $1 WHERE filename = $2`, [
        checksum,
        filename,
      ]);
    }
    await expect(applyMigrations(pool)).resolves.toHaveLength(original.size);
  });
});
