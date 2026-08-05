import type pg from 'pg';
import {
  seedFixtures,
  seedGrant,
  seedGroup,
  seedGroupMembership,
  seedVersion,
  seedChunk,
  revokeGrant,
  type FixtureWorld,
} from '@securerag/db/src/testkit.js';
import type { OracleFacts } from './oracle.js';

/**
 * T3 corpus builder (contract §G2 gate tests item 8). One builder produces
 * BOTH the DB-seeded world (via testkit seed + the T3 grant/group/version
 * seeding helpers) AND the oracle facts for the same data; the facts are
 * materialized by reading the seeded DB state back (plus the intentionally
 * revoked grant), so the two cannot drift.
 *
 * Corpus (≥2 tenants; grants via principal/group/tenant_role; a revoked
 * grant; a superseded version; a quarantined version):
 *  - tenant A: alice (member), carol (admin), dave (no membership)
 *    - docA  v1 valid+current  chunks 'Alpha secret formula one/two'
 *            v2 SUPERSEDED     chunk  'Alpha secret formula superseded'
 *            v3 QUARANTINED    chunk  'Alpha secret formula quarantined'
 *            grants: principal alice; principal carol -> REVOKED at seed time
 *    - docA2 v1 valid+current  chunk  'Alpha widget spec secret formula'
 *            grant: tenant_role 'member' (alice; carol's role is admin -> no)
 *  - tenant B: bob (member)
 *    - docB  v1 valid+current  chunk  'Beta secret formula one'
 *            grant: group 'Beta Group' {bob}
 *    - docB2 v1 valid+current  chunk  'Beta ops secret formula review'
 *            grant: principal bob
 *
 * Questions the tests use:
 *  - 'secret formula' matches every seeded chunk text; after version/RLS
 *    filtering it yields exactly the oracle-allowed chunks (alice: 3, bob: 3)
 *    for the bidirectional production ⊆ oracle ∧ oracle ⊆ production check.
 *  - 'widget' matches ONLY the docA2 chunk -> below EVIDENCE_MIN_CHUNKS -> a
 *    genuine below-threshold refusal with authorized evidence present.
 */

export interface T3ChunkIds {
  alphaOne: string;
  alphaTwo: string;
  alphaWidget: string;
  betaOne: string;
  betaTwo: string;
  superseded: string;
  quarantined: string;
}

export interface T3World extends FixtureWorld {
  groupA: { id: string };
  groupB: { id: string };
  docA2: { id: string; versionId: string };
  docB2: { id: string; versionId: string };
  supersededVersion: { id: string };
  quarantinedVersion: { id: string };
  aliceDocAGrant: string;
  bobDocB2Grant: string;
  chunks: T3ChunkIds;
}

export interface T3Corpus {
  world: T3World;
  facts: OracleFacts;
}

export async function buildT3Corpus(pool: pg.Pool): Promise<T3Corpus> {
  const world = await seedFixtures(pool);

  const groupA = await seedGroup(pool, world.tenantA.id, 'Alpha Group');
  await seedGroupMembership(pool, world.tenantA.id, groupA, world.alice.id);
  const groupB = await seedGroup(pool, world.tenantB.id, 'Beta Group');
  await seedGroupMembership(pool, world.tenantB.id, groupB, world.bob.id);

  const aliceDocAGrant = await seedGrant(pool, {
    tenantId: world.tenantA.id,
    documentId: world.docA.id,
    subjectType: 'principal',
    subjectId: world.alice.id,
    capability: 'read',
  });
  const revokedGrant = await seedGrant(pool, {
    tenantId: world.tenantA.id,
    documentId: world.docA.id,
    subjectType: 'principal',
    subjectId: world.carol.id,
    capability: 'read',
  });
  await revokeGrant(pool, world.tenantA.id, revokedGrant);

  const docA2 = await seedDocument(pool, world.tenantA.id, 'Alpha widget doc');
  const docB2 = await seedDocument(pool, world.tenantB.id, 'Beta ops doc');

  await seedGrant(pool, {
    tenantId: world.tenantA.id,
    documentId: docA2,
    subjectType: 'tenant_role',
    subjectId: 'member',
    capability: 'read',
  });
  await seedGrant(pool, {
    tenantId: world.tenantB.id,
    documentId: world.docB.id,
    subjectType: 'group',
    subjectId: groupB,
    capability: 'read',
  });
  const bobDocB2Grant = await seedGrant(pool, {
    tenantId: world.tenantB.id,
    documentId: docB2,
    subjectType: 'principal',
    subjectId: world.bob.id,
    capability: 'read',
  });

  const supersededVersion = await seedVersion(pool, {
    tenantId: world.tenantA.id,
    documentId: world.docA.id,
    versionNo: 2,
    sourceObjectKey: 'tenant-a/sha/alpha-v2.txt',
    contentHash: Buffer.from([0x10, 0x11]),
    status: 'superseded',
    isCurrent: false,
  });
  const quarantinedVersion = await seedVersion(pool, {
    tenantId: world.tenantA.id,
    documentId: world.docA.id,
    versionNo: 3,
    sourceObjectKey: 'tenant-a/sha/alpha-v3.txt',
    contentHash: Buffer.from([0x20, 0x21]),
    status: 'quarantined',
    isCurrent: false,
  });

  const docA2Version = await seedVersion(pool, {
    tenantId: world.tenantA.id,
    documentId: docA2,
    versionNo: 1,
    sourceObjectKey: 'tenant-a/sha/widget-v1.txt',
    contentHash: Buffer.from([0x30, 0x31]),
    status: 'valid',
    isCurrent: true,
  });
  const docB2Version = await seedVersion(pool, {
    tenantId: world.tenantB.id,
    documentId: docB2,
    versionNo: 1,
    sourceObjectKey: 'tenant-b/sha/ops-v1.txt',
    contentHash: Buffer.from([0x40, 0x41]),
    status: 'valid',
    isCurrent: true,
  });

  // seedFixtures already created docA v1 chunks 'Alpha secret formula one/two';
  // reuse their ids instead of duplicating chunks.
  const docAChunks = await pool.query<{ chunk_id: string; text_redacted: string }>(
    `SELECT chunk_id, text_redacted
       FROM securerag.chunks
      WHERE tenant_id = $1 AND version_id = $2`,
    [world.tenantA.id, world.docA.versionId],
  );
  const docAChunkIdByText = new Map(docAChunks.rows.map((r) => [r.text_redacted, r.chunk_id]));

  const chunks: T3ChunkIds = {
    alphaOne: expectChunkId(docAChunkIdByText, 'Alpha secret formula one'),
    alphaTwo: expectChunkId(docAChunkIdByText, 'Alpha secret formula two'),
    alphaWidget: await seedChunk(pool, {
      tenantId: world.tenantA.id,
      versionId: docA2Version,
      chunkNo: 1,
      text: 'Alpha widget spec secret formula',
      spanStart: 0,
      spanEnd: 33,
    }),
    betaOne: await seedChunk(pool, {
      tenantId: world.tenantB.id,
      versionId: world.docB.versionId,
      chunkNo: 2,
      text: 'Beta secret formula one',
      spanStart: 0,
      spanEnd: 23,
    }),
    betaTwo: await seedChunk(pool, {
      tenantId: world.tenantB.id,
      versionId: docB2Version,
      chunkNo: 1,
      text: 'Beta ops secret formula review',
      spanStart: 0,
      spanEnd: 31,
    }),
    superseded: await seedChunk(pool, {
      tenantId: world.tenantA.id,
      versionId: supersededVersion,
      chunkNo: 1,
      text: 'Alpha secret formula superseded',
      spanStart: 0,
      spanEnd: 31,
    }),
    quarantined: await seedChunk(pool, {
      tenantId: world.tenantA.id,
      versionId: quarantinedVersion,
      chunkNo: 1,
      text: 'Alpha secret formula quarantined',
      spanStart: 0,
      spanEnd: 32,
    }),
  };

  const facts = await materializeFacts(pool, {
    revokedGrantTenantId: world.tenantA.id,
    revokedGrantDocumentId: world.docA.id,
    revokedGrantSubjectId: world.carol.id,
  });

  return {
    world: {
      ...world,
      groupA: { id: groupA },
      groupB: { id: groupB },
      docA2: { id: docA2, versionId: docA2Version },
      docB2: { id: docB2, versionId: docB2Version },
      supersededVersion: { id: supersededVersion },
      quarantinedVersion: { id: quarantinedVersion },
      aliceDocAGrant,
      bobDocB2Grant,
      chunks,
    },
    facts,
  };
}

async function seedDocument(pool: pg.Pool, tenantId: string, title: string): Promise<string> {
  const { rows } = await pool.query<{ document_id: string }>(
    `INSERT INTO securerag.documents (tenant_id, title) VALUES ($1, $2) RETURNING document_id`,
    [tenantId, title],
  );
  const documentId = rows[0]?.document_id;
  if (!documentId) throw new Error('t3 fixture document insert failed');
  return documentId;
}

function expectChunkId(byText: Map<string, string>, text: string): string {
  const chunkId = byText.get(text);
  if (!chunkId) throw new Error(`t3 fixture chunk not found for text: ${text}`);
  return chunkId;
}

interface RevokedGrantFact {
  revokedGrantTenantId: string;
  revokedGrantDocumentId: string;
  revokedGrantSubjectId: string;
}

/**
 * Materialize oracle facts by reading the seeded world back (drift-free by
 * construction), then re-inject the seed-time revoked grant so the oracle
 * knows it existed and was revoked (the row itself is deleted).
 */
async function materializeFacts(
  pool: pg.Pool,
  revoked: RevokedGrantFact,
): Promise<OracleFacts> {
  const [tenants, principals, memberships, groups, groupMemberships, documents, versions, chunks, grants] =
    await Promise.all([
      pool.query(`SELECT tenant_id AS id FROM securerag.tenants ORDER BY tenant_id`),
      pool.query(`SELECT principal_id AS id FROM securerag.principals ORDER BY principal_id`),
      pool.query(
        `SELECT tenant_id, principal_id, role, is_active FROM securerag.tenant_memberships ORDER BY tenant_id`,
      ),
      pool.query(`SELECT tenant_id, group_id FROM securerag.groups ORDER BY tenant_id, group_id`),
      pool.query(
        `SELECT tenant_id, group_id, principal_id FROM securerag.group_memberships ORDER BY tenant_id`,
      ),
      pool.query(
        `SELECT tenant_id, document_id, title, status FROM securerag.documents ORDER BY tenant_id`,
      ),
      pool.query(
        `SELECT tenant_id, document_id, version_id, version_no, status, is_current
           FROM securerag.document_versions ORDER BY tenant_id`,
      ),
      pool.query(
        `SELECT tenant_id, version_id, chunk_id, chunk_no, text_redacted
           FROM securerag.chunks ORDER BY tenant_id`,
      ),
      pool.query(
        `SELECT tenant_id, document_id, subject_type, subject_id, capability
           FROM securerag.document_grants ORDER BY tenant_id`,
      ),
    ]);

  return {
    tenants: tenants.rows.map((r: { id: string }) => ({ id: r.id })),
    principals: principals.rows.map((r: { id: string }) => ({ id: r.id })),
    memberships: memberships.rows.map(
      (r: { tenant_id: string; principal_id: string; role: string; is_active: boolean }) => ({
        tenantId: r.tenant_id,
        principalId: r.principal_id,
        role: r.role,
        isActive: r.is_active,
      }),
    ),
    groups: groups.rows.map((r: { tenant_id: string; group_id: string }) => ({
      tenantId: r.tenant_id,
      groupId: r.group_id,
    })),
    groupMemberships: groupMemberships.rows.map(
      (r: { tenant_id: string; group_id: string; principal_id: string }) => ({
        tenantId: r.tenant_id,
        groupId: r.group_id,
        principalId: r.principal_id,
      }),
    ),
    documents: documents.rows.map(
      (r: { tenant_id: string; document_id: string; title: string; status: string }) => ({
        tenantId: r.tenant_id,
        documentId: r.document_id,
        title: r.title,
        status: r.status,
      }),
    ),
    versions: versions.rows.map(
      (r: {
        tenant_id: string;
        document_id: string;
        version_id: string;
        version_no: number;
        status: string;
        is_current: boolean;
      }) => ({
        tenantId: r.tenant_id,
        documentId: r.document_id,
        versionId: r.version_id,
        versionNo: r.version_no,
        status: r.status,
        isCurrent: r.is_current,
      }),
    ),
    chunks: chunks.rows.map(
      (r: {
        tenant_id: string;
        version_id: string;
        chunk_id: string;
        chunk_no: number;
        text_redacted: string;
      }) => ({
        tenantId: r.tenant_id,
        versionId: r.version_id,
        chunkId: r.chunk_id,
        chunkNo: r.chunk_no,
        text: r.text_redacted,
      }),
    ),
    grants: [
      ...grants.rows.map(
        (r: {
          tenant_id: string;
          document_id: string;
          subject_type: string;
          subject_id: string;
          capability: string;
        }) => ({
          tenantId: r.tenant_id,
          documentId: r.document_id,
          subjectType: r.subject_type as OracleFacts['grants'][number]['subjectType'],
          subjectId: r.subject_id,
          capability: r.capability,
          revoked: false,
        }),
      ),
      {
        tenantId: revoked.revokedGrantTenantId,
        documentId: revoked.revokedGrantDocumentId,
        subjectType: 'principal' as const,
        subjectId: revoked.revokedGrantSubjectId,
        capability: 'read',
        revoked: true,
      },
    ],
  };
}
