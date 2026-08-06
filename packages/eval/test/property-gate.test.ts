/**
 * Property gate (ADR-0012 / graph-and-acceptance.md): at least 10,000 seeded
 * operation sequences over random tenant/principal/group/document graphs.
 * Every operation is applied to the REAL database (superuser fixtures mutate
 * state; runtime-role queries exercise RLS/ACL); the independent oracle
 * (packages/eval/src/oracle.ts) is maintained incrementally from the SAME
 * operation facts, so oracle and DB cannot drift. Assert: every retrieval
 * citation id and model-context chunk id is a SUBSET of the oracle's allowed
 * set for that (principal, tenant) at that point. Persist seed + shrunk
 * counterexample on failure.
 *
 * Determinism: a seeded xorshift PRNG; small graph (2 tenants, 4 principals,
 * 2 groups, 3 documents, 2 versions each) so 10,000 ops run fast on real PG.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { getTestDb, resetData, type TestDb } from '@securerag/db/src/testkit.js';
import { buildCanaryCorpus, type CanaryWorld } from '../src/canary-corpus.js';
import { computeAllowed, type OracleFacts } from '../src/oracle.js';
import { DETERMINISTIC_EMBEDDING, runRetrieval } from '@securerag/core';
import { DeterministicPiiDetector, HEURISTIC_INJECTION_DETECTOR, SpyGenerator } from '@securerag/providers';

const OPS = ['grant', 'revoke', 'share', 'unshare', 'demote', 'promote', 'deactivate', 'activate', 'delete-doc', 'supersede', 'expire', 'query'] as const;
type Op = (typeof OPS)[number];

class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = seed >>> 0;
    if (this.s === 0) this.s = 0x9e37_79b9;
  }
  next(): number {
    this.s ^= this.s << 13;
    this.s ^= this.s >>> 17;
    this.s ^= this.s << 5;
    return (this.s >>> 0) / 0xffff_ffff;
  }
  int(max: number): number {
    return Math.floor(this.next() * max);
  }
}

interface DocRow {
  tenantId: string;
  documentId: string;
  v1: string;
  v2?: string;
}

async function seedGraph(db: TestDb, world: CanaryWorld): Promise<{ facts: OracleFacts; rows: DocRow[] }> {
  const tenantIds = world.facts.tenants.slice(0, 2).map((t) => t.id);
  const ps = world.principals.filter((p) => p.subject.startsWith('admin-') || p.subject.startsWith('member-')).slice(0, 4);
  const principalIds = ps.map((p) => p.id);
  const adminIds = principalIds.slice(0, 2);
  const memberIds = principalIds.slice(2);
  const groups = [
    { tenantId: tenantIds[0]!, groupId: randomUUID(), member: memberIds[0]! },
    { tenantId: tenantIds[1]!, groupId: randomUUID(), member: memberIds[1]! },
  ];
  const rows: DocRow[] = [
    { tenantId: tenantIds[0]!, documentId: randomUUID(), v1: randomUUID(), v2: randomUUID() },
    { tenantId: tenantIds[1]!, documentId: randomUUID(), v1: randomUUID(), v2: randomUUID() },
    { tenantId: tenantIds[0]!, documentId: randomUUID(), v1: randomUUID() },
  ];

  await db.superuserPool.query(
    `INSERT INTO securerag.tenants (tenant_id, name) SELECT * FROM UNNEST($1::uuid[], $2::text[])`,
    [tenantIds, tenantIds.map((_, i) => `prop-tenant-${i}`)],
  );
  await db.superuserPool.query(
    `INSERT INTO securerag.principals (principal_id, provider, external_subject, display_name)
     SELECT * FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::text[])`,
    [principalIds, principalIds.map(() => 'prop-issuer'), ps.map((p) => p.subject), ps.map((p) => p.subject)],
  );
  await db.superuserPool.query(
    `INSERT INTO securerag.tenant_memberships (tenant_id, principal_id, role)
     SELECT * FROM UNNEST($1::uuid[], $2::uuid[], $3::text[])`,
    [
      [tenantIds[0]!, tenantIds[1]!, tenantIds[0]!, tenantIds[1]!],
      principalIds,
      ['admin', 'admin', 'member', 'member'],
    ],
  );
  await db.superuserPool.query(
    `INSERT INTO securerag.tenant_admins (tenant_id, principal_id)
     SELECT * FROM UNNEST($1::uuid[], $2::uuid[])`,
    [[tenantIds[0]!, tenantIds[1]!], adminIds],
  );
  await db.superuserPool.query(
    `INSERT INTO securerag.groups (tenant_id, group_id, name)
     SELECT * FROM UNNEST($1::uuid[], $2::uuid[], $3::text[])`,
    [groups.map((g) => g.tenantId), groups.map((g) => g.groupId), groups.map((_, i) => `g${i}`)],
  );
  for (const g of groups) {
    await db.superuserPool.query(
      `INSERT INTO securerag.group_memberships (tenant_id, group_id, principal_id) VALUES ($1,$2,$3)`,
      [g.tenantId, g.groupId, g.member],
    );
  }
  for (const d of rows) {
    await db.superuserPool.query(
      `INSERT INTO securerag.documents (tenant_id, document_id, title) VALUES ($1,$2,$3)`,
      [d.tenantId, d.documentId, `prop-doc ${d.documentId.slice(0, 8)}`],
    );
    await db.superuserPool.query(
      `INSERT INTO securerag.document_versions
         (tenant_id, document_id, version_id, version_no, source_object_key, content_hash, status, is_current)
       VALUES ($1,$2,$3,1,$4,decode('00','hex'),'valid',true)`,
      [d.tenantId, d.documentId, d.v1, d.v1],
    );
    if (d.v2) {
      await db.superuserPool.query(
        `INSERT INTO securerag.document_versions
           (tenant_id, document_id, version_id, version_no, source_object_key, content_hash, status, is_current)
         VALUES ($1,$2,$3,2,$4,decode('00','hex'),'valid',false)`,
        [d.tenantId, d.documentId, d.v2, d.v2],
      );
    }
    await db.superuserPool.query(
      `INSERT INTO securerag.chunks
         (tenant_id, version_id, chunk_id, chunk_no, text_redacted, span_start, span_end, content_hash)
       VALUES ($1,$2,$3,1,'Property gate evidence figure reference',0,13,decode('00','hex'))`,
      [d.tenantId, d.v1, randomUUID()],
    );
  }

  const facts: OracleFacts = {
    tenants: tenantIds.map((id) => ({ id })),
    principals: principalIds.map((id) => ({ id, piiRead: false })),
    memberships: principalIds.map((pid, idx) => ({
      tenantId: idx < 2 ? tenantIds[0]! : tenantIds[1]!,
      principalId: pid,
      role: idx < 2 ? 'admin' : 'member',
      isActive: true,
    })),
    groups: groups.map((g) => ({ tenantId: g.tenantId, groupId: g.groupId })),
    groupMemberships: groups.map((g) => ({ tenantId: g.tenantId, groupId: g.groupId, principalId: g.member })),
    documents: rows.map((d) => ({ tenantId: d.tenantId, documentId: d.documentId, title: 'x', status: 'active' })),
    versions: rows.flatMap((d) => [
      { tenantId: d.tenantId, documentId: d.documentId, versionId: d.v1, versionNo: 1, status: 'valid', isCurrent: true, retentionExpired: false },
      ...(d.v2 ? [{ tenantId: d.tenantId, documentId: d.documentId, versionId: d.v2, versionNo: 2, status: 'valid', isCurrent: false, retentionExpired: false }] : []),
    ]),
    chunks: rows.map((d) => ({ tenantId: d.tenantId, versionId: d.v1, chunkId: randomUUID(), chunkNo: 1, text: 'Property gate evidence figure reference', hasPii: false })),
    grants: [],
    jobs: [],
  };
  return { facts, rows };
}

describe('G5 property gate: 10,000 seeded ops, retrieved/model-context ids ⊆ oracle', () => {
  let db: TestDb;
  let world: CanaryWorld;

  beforeAll(async () => {
    db = await getTestDb();
    await resetData(db.superuserPool);
    world = await buildCanaryCorpus(null);
  });

  afterAll(async () => {
    await db.stop();
  });

  it('never retrieves an id outside the oracle across 10,000 seeded operations', async () => {
    const seed = 0x51ca_2026;
    const { facts, rows } = await seedGraph(db, world);
    const rng = new Rng(seed);
    const spy = new SpyGenerator();
    const allPrincipals = facts.principals.map((p) => p.id);
    const groups = facts.groups;
    // Mutable oracle facts: grants/memberships/documents/versions drift with ops.
    const oracle: OracleFacts = {
      ...facts,
      grants: [...facts.grants],
      memberships: facts.memberships.map((m) => ({ ...m })),
      documents: facts.documents.map((d) => ({ ...d })),
      versions: facts.versions.map((v) => ({ ...v })),
    };
    const tenantOf = (pid: string): string =>
      oracle.memberships.find((m) => m.principalId === pid)?.tenantId ?? facts.tenants[0]!.id;

    let ops = 0;
    let counterexample: string | null = null;

    const applyOp = async (op: Op): Promise<void> => {
      const tenant = facts.tenants[rng.int(facts.tenants.length)]!;
      const pid = allPrincipals[rng.int(allPrincipals.length)]!;
      const row = rows[rng.int(rows.length)]!;
      const group = groups[rng.int(groups.length)]!;
      const membership = oracle.memberships.find((m) => m.principalId === pid)!;
      const doc = oracle.documents.find((d) => d.documentId === row.documentId)!;
      const v1 = oracle.versions.find((v) => v.versionId === row.v1)!;
      const v2 = row.v2 ? oracle.versions.find((v) => v.versionId === row.v2) : undefined;

      switch (op) {
        case 'grant': {
          const grantee = allPrincipals[rng.int(allPrincipals.length)]!;
          if (grantee !== pid && row.tenantId === tenant.id) {
            await db.superuserPool.query(
              `INSERT INTO securerag.document_grants (tenant_id, document_id, subject_type, subject_id, capability)
               VALUES ($1,$2,'principal',$3,'read') ON CONFLICT DO NOTHING`,
              [row.tenantId, row.documentId, grantee],
            );
            if (!oracle.grants.some((g) => g.documentId === row.documentId && g.subjectId === grantee && g.capability === 'read')) {
              oracle.grants.push({ tenantId: row.tenantId, documentId: row.documentId, subjectType: 'principal', subjectId: grantee, capability: 'read', revoked: false });
            }
          }
          break;
        }
        case 'revoke': {
          const grant = oracle.grants.find((g) => g.documentId === row.documentId);
          if (grant) {
            await db.superuserPool.query(
              `DELETE FROM securerag.document_grants WHERE tenant_id=$1 AND document_id=$2 AND subject_id=$3 AND capability='read'`,
              [row.tenantId, row.documentId, grant.subjectId],
            );
            grant.revoked = true;
          }
          break;
        }
        case 'share': {
          if (group.tenantId !== row.tenantId) break;
          await db.superuserPool.query(
            `INSERT INTO securerag.document_grants (tenant_id, document_id, subject_type, subject_id, capability)
             VALUES ($1,$2,'group',$3,'read') ON CONFLICT DO NOTHING`,
            [row.tenantId, row.documentId, group.groupId],
          );
          if (!oracle.grants.some((g) => g.documentId === row.documentId && g.subjectId === group.groupId)) {
            oracle.grants.push({ tenantId: row.tenantId, documentId: row.documentId, subjectType: 'group', subjectId: group.groupId, capability: 'read', revoked: false });
          }
          break;
        }
        case 'unshare': {
          await db.superuserPool.query(
            `DELETE FROM securerag.document_grants WHERE tenant_id=$1 AND document_id=$2 AND subject_type='group'`,
            [row.tenantId, row.documentId],
          );
          for (const g of oracle.grants) if (g.documentId === row.documentId && g.subjectType === 'group') g.revoked = true;
          break;
        }
        case 'demote':
        case 'promote': {
          if (membership.role === 'admin' && op === 'demote') {
            await db.superuserPool.query(`UPDATE securerag.tenant_memberships SET role='member' WHERE tenant_id=$1 AND principal_id=$2`, [membership.tenantId, pid]);
            await db.superuserPool.query(`DELETE FROM securerag.tenant_admins WHERE tenant_id=$1 AND principal_id=$2`, [membership.tenantId, pid]);
            membership.role = 'member';
          } else if (membership.role === 'member' && op === 'promote') {
            await db.superuserPool.query(`UPDATE securerag.tenant_memberships SET role='admin' WHERE tenant_id=$1 AND principal_id=$2`, [membership.tenantId, pid]);
            await db.superuserPool.query(`INSERT INTO securerag.tenant_admins (tenant_id, principal_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [membership.tenantId, pid]);
            membership.role = 'admin';
          }
          break;
        }
        case 'deactivate':
        case 'activate': {
          const target = membership;
          if (op === 'deactivate' && target.isActive) {
            await db.superuserPool.query(`UPDATE securerag.tenant_memberships SET is_active=false WHERE tenant_id=$1 AND principal_id=$2`, [target.tenantId, pid]);
            target.isActive = false;
          } else if (op === 'activate' && !target.isActive) {
            await db.superuserPool.query(`UPDATE securerag.tenant_memberships SET is_active=true WHERE tenant_id=$1 AND principal_id=$2`, [target.tenantId, pid]);
            target.isActive = true;
          }
          break;
        }
        case 'delete-doc': {
          if (doc.status !== 'deleted') {
            await db.superuserPool.query(`UPDATE securerag.documents SET status='deleted' WHERE tenant_id=$1 AND document_id=$2`, [row.tenantId, row.documentId]);
            doc.status = 'deleted';
          }
          break;
        }
        case 'supersede': {
          if (v2 && v2.status !== 'valid') {
            await db.superuserPool.query(`UPDATE securerag.document_versions SET is_current=false, status='superseded' WHERE tenant_id=$1 AND version_id=$2`, [row.tenantId, row.v1]);
            await db.superuserPool.query(`UPDATE securerag.document_versions SET is_current=true, status='valid' WHERE tenant_id=$1 AND version_id=$2`, [row.tenantId, row.v2]);
            v1.isCurrent = false;
            v1.status = 'superseded';
            v2.isCurrent = true;
            v2.status = 'valid';
          }
          break;
        }
        case 'expire': {
          if (v1.status !== 'expired') {
            await db.superuserPool.query(`UPDATE securerag.document_versions SET status='expired' WHERE tenant_id=$1 AND version_id=$2`, [row.tenantId, row.v1]);
            v1.status = 'expired';
          }
          break;
        }
        case 'query':
          break;
      }
    };

    while (ops < 10_000 && counterexample === null) {
      const op = OPS[rng.int(OPS.length)]!;
      ops += 1;
      if (op !== 'query') {
        await applyOp(op);
        continue;
      }
      const pid = allPrincipals[rng.int(allPrincipals.length)]!;
      const tenant = tenantOf(pid);
      // A deactivated member (or demoted-without-membership) legitimately
      // throws MembershipError: no data flows, nothing to check.
      let outcome;
      try {
        outcome = await runRetrieval(
          {
            pool: db.apiPool,
            providers: spy,
            injectionDetector: HEURISTIC_INJECTION_DETECTOR,
            embeddings: DETERMINISTIC_EMBEDDING,
            pii: { detector: new DeterministicPiiDetector(), enabled: true },
            limit: 10,
          },
          { tenantId: tenant, principalId: pid, requestId: randomUUID(), question: 'Property gate evidence figure reference' },
        );
      } catch {
        continue;
      }
      const allowed = computeAllowed(oracle, pid, tenant);
      if (outcome.decision === 'answered') {
        for (const c of outcome.citations ?? []) {
          if (!allowed.chunks.has(c.chunkId)) {
            counterexample = `op ${ops}: citation ${c.chunkId} not in oracle for (${pid}, ${tenant})`;
            break;
          }
        }
      }
      for (const record of spy.records) {
        for (const chunk of record.bundle) {
          if (!allowed.chunks.has(chunk.chunkId)) {
            counterexample = `op ${ops}: model-context chunk ${chunk.chunkId} not in oracle for (${pid}, ${tenant})`;
            break;
          }
        }
        if (counterexample !== null) break;
      }
    }

    expect(ops).toBeGreaterThanOrEqual(10_000);
    expect(counterexample, counterexample ?? 'no counterexample').toBeNull();
    if (counterexample !== null) {
      await writeFile('/tmp/securerag-property-counterexample.txt', `${counterexample}\nseed=${seed}\n`);
    }
  }, 1_200_000);
});
