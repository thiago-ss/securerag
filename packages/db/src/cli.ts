import { applyMigrations } from './migrate.js';
import pg from 'pg';

const { Pool } = pg;

async function main(): Promise<void> {
  const command = process.argv[2] ?? 'up';
  const pool = new Pool({
    host: process.env['PGHOST'] ?? 'localhost',
    port: Number(process.env['PGPORT'] ?? 5432),
    database: process.env['PGDATABASE'] ?? 'securerag',
    user: process.env['PGUSER'] ?? 'securerag_migration',
    password: process.env['PGPASSWORD'],
    max: 2,
  });
  try {
    if (command === 'up') {
      const applied = await applyMigrations(pool);
      for (const row of applied) {
        console.log(`${row.filename} ${row.checksum.slice(0, 12)} ${row.applied_at.toISOString()}`);
      }
      console.log(`${applied.length} migration(s) applied/verified`);
    } else if (command === 'status') {
      const { rows } = await pool.query(
        'SELECT filename, checksum, applied_at FROM securerag.migrations ORDER BY filename',
      );
      for (const row of rows) {
        console.log(`${row.filename} ${row.checksum.slice(0, 12)} ${row.applied_at.toISOString()}`);
      }
    } else {
      throw new Error(`unknown command: ${command} (expected up|status)`);
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
