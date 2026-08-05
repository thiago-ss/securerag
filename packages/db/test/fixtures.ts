import type { Pool } from 'pg';

export interface FixtureWorld {
  tenantA: { id: string };
  tenantB: { id: string };
  alice: { id: string };
  bob: { id: string };
  carol: { id: string };
  docA: { id: string; versionId: string };
  docB: { id: string; versionId: string };
}

/**
 * Trusted fixture creation (superuser: fixtures are part of the corpus, RLS applies
 * to the roles under test, never to fixture setup). Returns stable ids.
 */
export async function seedFixtures(pool: Pool): Promise<FixtureWorld> {
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
       (gen_random_uuid(), 'test-issuer', 'carol-sub', 'Carol')
     RETURNING principal_id`,
  );
  const [alice, bob, carol] = principals.rows;
  if (!alice || !bob || !carol) throw new Error('fixture principal insert failed');

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
    docA: { id: docA.document_id, versionId: versionA.version_id },
    docB: { id: docB.document_id, versionId: versionB.version_id },
  };
}

/** Wipe tenant-owned data between tests (superuser path; RLS never applies to fixtures). */
export async function resetData(pool: Pool): Promise<void> {
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
