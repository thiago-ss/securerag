/**
 * SecureRAG demo seed (S10, ADR-0011). Creates TWO synthetic tenants with
 * synthetic documents (no real data, no canaries) plus memberships and
 * grants for the Keycloak demo users, so the one-command demo has content
 * to browse, search, and manage immediately.
 *
 * Connects as the DEMO database superuser (like the testkit fixture
 * seeding: RLS applies to the runtime roles, never to corpus setup).
 *
 *   docker compose -f ops/compose.yml up --build -d   # first
 *   npm run demo:seed                                  # then this
 *
 * Environment (defaults match ops/.env.example):
 *   PGHOST=localhost PGPORT=55432 PGDATABASE=securerag PGUSER=postgres
 *   PGPASSWORD=... OIDC_ISSUER=http://localhost:8180/realms/securerag-demo
 *
 * Principals link to the Keycloak realm users through the PINNED user ids
 * in ops/keycloak-realm.json (provider = OIDC_ISSUER, external_subject =
 * the realm user id) — Keycloak preserves user ids on realm import, so a
 * login as alice/carol resolves to exactly these rows. Idempotent: re-run
 * at any time (ON CONFLICT DO NOTHING, fixed ids).
 */
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import { DETERMINISTIC_EMBEDDING, toVectorLiteral } from '@securerag/core';

const { Pool } = pg;

const env = {
  PGHOST: process.env['PGHOST'] ?? 'localhost',
  PGPORT: Number(process.env['PGPORT'] ?? 55432),
  PGDATABASE: process.env['PGDATABASE'] ?? 'securerag',
  PGUSER: process.env['PGUSER'] ?? 'postgres',
  PGPASSWORD: process.env['PGPASSWORD'] ?? '',
  OIDC_ISSUER: process.env['OIDC_ISSUER'] ?? 'http://localhost:8180/realms/securerag-demo',
};

// Pinned Keycloak realm user ids (ops/keycloak-realm.json).
const ALICE_SUB = '00000000-0000-4000-8000-000000000001';
const CAROL_SUB = '00000000-0000-4000-8000-000000000002';

// Fixed demo ids (idempotent seeding).
const TENANT_ACME = '11111111-1111-4111-8111-111111111111';
const TENANT_GLOBEX = '22222222-2222-4222-8222-222222222222';
const DOC_SALES = '11111111-1111-4111-8111-111111111101';
const DOC_SECURITY = '11111111-1111-4111-8111-111111111102';
const DOC_ROADMAP = '22222222-2222-4222-8222-222222222201';

interface DemoDoc {
  tenantId: string;
  documentId: string;
  title: string;
  content: string;
}

const DOCS: DemoDoc[] = [
  {
    tenantId: TENANT_ACME,
    documentId: DOC_SALES,
    title: 'Acme sales playbook',
    content: [
      'The Acme launch window opens in Q3 with a phased rollout across three regions.',
      'Enterprise deals above 250 seats require executive approval before the quote is sent.',
      'The partner channel receives a 15 percent margin on first-year bookings.',
    ].join('\n'),
  },
  {
    tenantId: TENANT_ACME,
    documentId: DOC_SECURITY,
    title: 'Acme security policy',
    content: [
      'Access reviews run quarterly and every privileged role is reviewed by a second approver.',
      'Secrets are stored in the central vault and rotated every ninety days without exception.',
      'Incident response declares a severity level within one hour of confirmed impact.',
    ].join('\n'),
  },
  {
    tenantId: TENANT_GLOBEX,
    documentId: DOC_ROADMAP,
    title: 'Globex product roadmap',
    content: [
      'The Globex platform ships an offline-first mobile client in the next release.',
      'A unified billing engine consolidates invoicing across all product lines.',
      'The roadmap prioritizes auditability features for regulated customers.',
    ].join('\n'),
  },
];

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

async function main(): Promise<void> {
  const pool = new Pool({
    host: env.PGHOST,
    port: env.PGPORT,
    database: env.PGDATABASE,
    user: env.PGUSER,
    password: env.PGPASSWORD,
    max: 3,
  });

  try {
    await pool.query(`INSERT INTO securerag.tenants (tenant_id, name) VALUES
      ($1, 'Acme Corp'), ($2, 'Globex Inc') ON CONFLICT (tenant_id) DO NOTHING`,
      [TENANT_ACME, TENANT_GLOBEX]);

    const principals = await pool.query(
      `INSERT INTO securerag.principals
         (principal_id, provider, external_subject, display_name, pii_read)
       VALUES
         (gen_random_uuid(), $1, $2, 'Alice', false),
         (gen_random_uuid(), $1, $3, 'Carol', false)
       ON CONFLICT (provider, external_subject) DO NOTHING`,
      [env.OIDC_ISSUER, ALICE_SUB, CAROL_SUB],
    );

    const alice = await pool.query<{ principal_id: string }>(
      `SELECT principal_id FROM securerag.principals WHERE provider = $1 AND external_subject = $2`,
      [env.OIDC_ISSUER, ALICE_SUB],
    );
    const carol = await pool.query<{ principal_id: string }>(
      `SELECT principal_id FROM securerag.principals WHERE provider = $1 AND external_subject = $2`,
      [env.OIDC_ISSUER, CAROL_SUB],
    );
    const aliceId = alice.rows[0]?.principal_id;
    const carolId = carol.rows[0]?.principal_id;
    if (aliceId === undefined || carolId === undefined) {
      throw new Error('demo principals did not resolve');
    }

    await pool.query(
      `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role) VALUES
         ($1, $2, 'member'),
         ($1, $3, 'admin'),
         ($4, $3, 'member')
       ON CONFLICT DO NOTHING`,
      [TENANT_ACME, aliceId, carolId, TENANT_GLOBEX],
    );
    await pool.query(
      `INSERT INTO securerag.tenant_admins (tenant_id, principal_id) VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [TENANT_ACME, carolId],
    );
    await pool.query(
      `INSERT INTO securerag.retention_policies
         (tenant_id, source_days, derived_days, audit_days, grace_days, legal_hold)
       VALUES
         ($1, 3650, 365, 3650, 30, false),
         ($2, 3650, 365, 3650, 30, false)
       ON CONFLICT (tenant_id) DO NOTHING`,
      [TENANT_ACME, TENANT_GLOBEX],
    );

    let chunks = 0;
    for (const doc of DOCS) {
      await pool.query(
        `INSERT INTO securerag.documents (tenant_id, document_id, title) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [doc.tenantId, doc.documentId, doc.title],
      );
      const versionId = randomUUID();
      const hash = sha256Hex(doc.content);
      const version = await pool.query(
        `INSERT INTO securerag.document_versions
           (tenant_id, document_id, version_id, version_no, source_object_key, content_hash, status, is_current)
         VALUES ($1, $2, $3, 1, $4, decode($5, 'hex'), 'valid', true)
         ON CONFLICT (tenant_id, document_id, version_no) DO NOTHING
         RETURNING version_id`,
        [doc.tenantId, doc.documentId, versionId, `demo/${doc.documentId}/${hash}.txt`, hash],
      );
      const seededVersion = version.rows[0]?.version_id;
      if (seededVersion === undefined) {
        // version already seeded for this document: skip chunk re-seeding
        continue;
      }

      const lines = doc.content.split('\n').filter((line) => line.length > 0);
      const vectors = await DETERMINISTIC_EMBEDDING.embed(lines);
      let span = 0;
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i]!;
        const chunkId = randomUUID();
        const vector = vectors[i];
        if (vector === undefined) throw new Error('embedding failed');
        await pool.query(
          `INSERT INTO securerag.chunks
             (tenant_id, chunk_id, version_id, chunk_no, text_redacted, span_start, span_end, content_hash, embedding)
           VALUES ($1, $2, $3, $4, $5, $6, $7, decode($8, 'hex'), $9::vector)
           ON CONFLICT DO NOTHING`,
          [
            doc.tenantId,
            chunkId,
            seededVersion,
            i + 1,
            line,
            span,
            span + line.length,
            sha256Hex(line),
            toVectorLiteral(vector),
          ],
        );
        span += line.length + 1;
        chunks += 1;
      }

      // Grants: every member may read; the demo owner manages (upload path).
      await pool.query(
        `INSERT INTO securerag.document_grants
           (tenant_id, document_id, subject_type, subject_id, capability)
         VALUES
           ($1, $2, 'tenant_role', 'member', 'read'),
           ($1, $2, 'principal', $3, 'manage')
         ON CONFLICT DO NOTHING`,
        [doc.tenantId, doc.documentId, doc.tenantId === TENANT_ACME ? aliceId : carolId],
      );
    }

    const { rows } = await pool.query<{ tenants: string; principals: string; chunks: string }>(
      `SELECT
         (SELECT count(*) FROM securerag.tenants)::text AS tenants,
         (SELECT count(*) FROM securerag.principals)::text AS principals,
         (SELECT count(*) FROM securerag.chunks)::text AS chunks`,
    );
    const summary = rows[0];
    console.log(
      `demo seed complete: tenants=${summary?.tenants} principals=${summary?.principals} chunks=${summary?.chunks} ` +
        `(this run added ${chunks} chunk(s)) — principals inserted=${principals.rowCount}`,
    );
    console.log('sign in at http://localhost:8080 as alice (alice-demo-password) or carol (carol-demo-password)');
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error('demo seed failed:', err);
  process.exitCode = 1;
});
