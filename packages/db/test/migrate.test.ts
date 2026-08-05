import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, writeFile, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { getTestDb, type TestDb } from './helpers.js';
import { applyMigrations, MIGRATIONS_DIR } from '../src/migrate.js';
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
      '0004_hybrid_retrieval.sql',
      '0005_oidc_sessions.sql',
      '0006_security_invariants.sql',
      '0007_pii.sql',
      '0008_injection.sql',
      '0009_retention.sql',
      '0010_history_manage_scope.sql',
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

  it('rejects when an applied migration disappears from disk', async () => {
    await pool.query(
      `INSERT INTO securerag.migrations (filename, checksum)
       VALUES ('0999_ghost_migration.sql', repeat('a', 64))`,
    );
    await expect(applyMigrations(pool)).rejects.toThrow(/no longer exists/);
    await db.superuserPool.query(`DELETE FROM securerag.migrations WHERE filename = '0999_ghost_migration.sql'`);
  });

  it('is failure-atomic: a failing migration records nothing and leaves prior state intact', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'securerag-migrate-'));
    try {
      await cp(MIGRATIONS_DIR, dir, { recursive: true });
      const failing = `SELECT 1;\nINSERT INTO securerag.tenants (tenant_id, name) VALUES ('not-a-uuid', 'x');\n`;
      await writeFile(path.join(dir, '0004_failing_test.sql'), failing);
      await expect(applyMigrations(pool, { dir })).rejects.toThrow(/uuid/);
      const { rows } = await pool.query<{ filename: string }>(
        'SELECT filename FROM securerag.migrations ORDER BY filename',
      );
      expect(rows.map((r) => r.filename)).toEqual([
        '0002_schema.sql',
        '0003_rls_and_grants.sql',
        '0004_hybrid_retrieval.sql',
        '0005_oidc_sessions.sql',
        '0006_security_invariants.sql',
        '0007_pii.sql',
        '0008_injection.sql',
        '0009_retention.sql',
      '0010_history_manage_scope.sql',
      ]);
      const { rows: tenants } = await db.superuserPool.query<{ tenant_id: string }>(
        'SELECT tenant_id FROM securerag.tenants',
      );
      expect(tenants).toHaveLength(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
