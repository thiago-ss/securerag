import { readFile } from 'node:fs/promises';
import { GenericContainer, Wait } from 'testcontainers';
import pg from 'pg';
import { applyMigrations } from './migrate.js';

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

export interface FixtureWorld {
  tenantA: { id: string };
  tenantB: { id: string };
  alice: { id: string };
  bob: { id: string };
  carol: { id: string };
  dave: { id: string };
  docA: { id: string; versionId: string };
  docB: { id: string; versionId: string };
}

/**
 * Trusted fixture creation (superuser: fixtures are part of the corpus, RLS applies
 * to the roles under test, never to fixture setup). Returns stable ids.
 */
export async function seedFixtures(pool: pg.Pool): Promise<FixtureWorld> {
  const tenants = await pool.query<{ tenant_id: string }>(
    `INSERT INTO securerag.tenants (tenant_id, name) VALUES
       (gen_random_uuid(), 'Tenant Alpha'),
       (gen_random_uuid(), 'Tenant Beta')
     RETURNING tenant_id`,
  );
  const [tenantA, tenantB] = tenants.rows;
  if (!tenantA || !tenantB) throw new Error('fixture tenant insert failed');

  const principals = await pool.query<{ principal_id: string }>(
    `INSERT INTO securerag.principals (principal_id, provider, external_subject, display_name) VALUES
       (gen_random_uuid(), 'test-issuer', 'alice-sub', 'Alice'),
       (gen_random_uuid(), 'test-issuer', 'bob-sub', 'Bob'),
       (gen_random_uuid(), 'test-issuer', 'carol-sub', 'Carol'),
       (gen_random_uuid(), 'test-issuer', 'dave-sub', 'Dave')
     RETURNING principal_id`,
  );
  const [alice, bob, carol, dave] = principals.rows;
  if (!alice || !bob || !carol || !dave) throw new Error('fixture principal insert failed');

  await pool.query(
    `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role) VALUES
       ($1, $2, 'member'),
       ($3, $4, 'member'),
       ($1, $5, 'admin')`,
    [tenantA.tenant_id, alice.principal_id, tenantB.tenant_id, bob.principal_id, carol.principal_id],
  );
  await pool.query(
    `INSERT INTO securerag.tenant_admins (tenant_id, principal_id) VALUES ($1, $2)`,
    [tenantA.tenant_id, carol.principal_id],
  );

  const docs = await pool.query<{ document_id: string }>(
    `INSERT INTO securerag.documents (tenant_id, title) VALUES
       ($1, 'Alpha private doc'),
       ($2, 'Beta private doc')
     RETURNING document_id`,
    [tenantA.tenant_id, tenantB.tenant_id],
  );
  const [docA, docB] = docs.rows;
  if (!docA || !docB) throw new Error('fixture document insert failed');

  const versions = await pool.query<{ version_id: string }>(
    `INSERT INTO securerag.document_versions
       (tenant_id, document_id, version_no, source_object_key, content_hash, status, is_current)
     VALUES
       ($1, $2, 1, 'tenant-a/sha/alpha-v1.txt', decode('aabb', 'hex'), 'valid', true),
       ($3, $4, 1, 'tenant-b/sha/beta-v1.txt', decode('ccdd', 'hex'), 'valid', true)
     RETURNING version_id`,
    [tenantA.tenant_id, docA.document_id, tenantB.tenant_id, docB.document_id],
  );
  const [versionA, versionB] = versions.rows;
  if (!versionA || !versionB) throw new Error('fixture version insert failed');

  await pool.query(
    `INSERT INTO securerag.chunks
       (tenant_id, version_id, chunk_no, text_redacted, span_start, span_end, content_hash)
     VALUES
       ($1, $2, 1, 'Alpha secret formula one', 0, 21, decode('1122', 'hex')),
       ($1, $2, 2, 'Alpha secret formula two', 22, 44, decode('3344', 'hex')),
       ($3, $4, 1, 'Beta secret formula one', 0, 21, decode('5566', 'hex'))`,
    [tenantA.tenant_id, versionA.version_id, tenantB.tenant_id, versionB.version_id],
  );

  return {
    tenantA: { id: tenantA.tenant_id },
    tenantB: { id: tenantB.tenant_id },
    alice: { id: alice.principal_id },
    bob: { id: bob.principal_id },
    carol: { id: carol.principal_id },
    dave: { id: dave.principal_id },
    docA: { id: docA.document_id, versionId: versionA.version_id },
    docB: { id: docB.document_id, versionId: versionB.version_id },
  };
}

// ---------- T3 seeding helpers (groups, grants, versions, chunks) ----------
// Trusted fixture creation like seedFixtures: RLS applies to the roles under
// test, never to fixture setup. Used by packages/eval corpus builder so the
// DB world and the oracle facts derive from the same inserts.

export interface SeedVersionParams {
  tenantId: string;
  documentId: string;
  versionNo: number;
  sourceObjectKey: string;
  contentHash: Buffer;
  status: string;
  isCurrent: boolean;
}

export interface SeedGrantParams {
  tenantId: string;
  documentId: string;
  subjectType: 'principal' | 'group' | 'tenant_role';
  subjectId: string;
  capability: 'read' | 'write' | 'manage';
}

export interface SeedChunkParams {
  tenantId: string;
  versionId: string;
  chunkNo: number;
  text: string;
  spanStart: number;
  spanEnd: number;
}

export async function seedGroup(
  pool: pg.Pool,
  tenantId: string,
  name: string,
): Promise<string> {
  const { rows } = await pool.query<{ group_id: string }>(
    `INSERT INTO securerag.groups (tenant_id, name) VALUES ($1, $2) RETURNING group_id`,
    [tenantId, name],
  );
  const groupId = rows[0]?.group_id;
  if (!groupId) throw new Error('fixture group insert failed');
  return groupId;
}

export async function seedGroupMembership(
  pool: pg.Pool,
  tenantId: string,
  groupId: string,
  principalId: string,
): Promise<void> {
  await pool.query(
    `INSERT INTO securerag.group_memberships (tenant_id, group_id, principal_id)
     VALUES ($1, $2, $3)`,
    [tenantId, groupId, principalId],
  );
}

export async function seedGrant(
  pool: pg.Pool,
  params: SeedGrantParams,
): Promise<string> {
  const { rows } = await pool.query<{ grant_id: string }>(
    `INSERT INTO securerag.document_grants
       (tenant_id, document_id, subject_type, subject_id, capability)
     VALUES ($1, $2, $3, $4, $5) RETURNING grant_id`,
    [
      params.tenantId,
      params.documentId,
      params.subjectType,
      params.subjectId,
      params.capability,
    ],
  );
  const grantId = rows[0]?.grant_id;
  if (!grantId) throw new Error('fixture grant insert failed');
  return grantId;
}

/** Revocation is row deletion (document_grants has no status column). */
export async function revokeGrant(
  pool: pg.Pool,
  tenantId: string,
  grantId: string,
): Promise<void> {
  await pool.query(
    `DELETE FROM securerag.document_grants WHERE tenant_id = $1 AND grant_id = $2`,
    [tenantId, grantId],
  );
}

export async function seedVersion(
  pool: pg.Pool,
  params: SeedVersionParams,
): Promise<string> {
  const { rows } = await pool.query<{ version_id: string }>(
    `INSERT INTO securerag.document_versions
       (tenant_id, document_id, version_no, source_object_key, content_hash, status, is_current)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING version_id`,
    [
      params.tenantId,
      params.documentId,
      params.versionNo,
      params.sourceObjectKey,
      params.contentHash,
      params.status,
      params.isCurrent,
    ],
  );
  const versionId = rows[0]?.version_id;
  if (!versionId) throw new Error('fixture version insert failed');
  return versionId;
}

export async function seedChunk(
  pool: pg.Pool,
  params: SeedChunkParams,
): Promise<string> {
  const { rows } = await pool.query<{ chunk_id: string }>(
    `INSERT INTO securerag.chunks
       (tenant_id, version_id, chunk_no, text_redacted, span_start, span_end, content_hash)
     VALUES ($1, $2, $3, $4, $5, $6, decode('aabb', 'hex')) RETURNING chunk_id`,
    [
      params.tenantId,
      params.versionId,
      params.chunkNo,
      params.text,
      params.spanStart,
      params.spanEnd,
    ],
  );
  const chunkId = rows[0]?.chunk_id;
  if (!chunkId) throw new Error('fixture chunk insert failed');
  return chunkId;
}

/** Wipe tenant-owned data between tests (superuser path; RLS never applies to fixtures). */
export async function resetData(pool: pg.Pool): Promise<void> {
  await pool.query(
    `TRUNCATE
       securerag.audit_events,
       securerag.chunks,
       securerag.document_grants,
       securerag.document_versions,
       securerag.documents,
       securerag.group_memberships,
       securerag.groups,
       securerag.tenant_admins,
       securerag.tenant_memberships,
       securerag.jobs,
       securerag.retention_policies,
       securerag.sessions,
       securerag.principals,
       securerag.tenants
     RESTART IDENTITY CASCADE`,
  );
  await pool.query('UPDATE securerag.authorization_epoch SET epoch = 0');
}

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
