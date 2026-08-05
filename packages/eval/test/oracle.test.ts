import { describe, expect, it } from 'vitest';
import { computeAllowed, type OracleFacts } from '../src/oracle.js';

const T = '11111111-1111-4111-8111-111111111111';
const A = '22222222-2222-4222-8222-222222222222';
const M = '33333333-3333-4333-8333-333333333333';
const DOC_ACTIVE = '44444444-4444-4444-8444-444444444444';
const DOC_DELETED = '55555555-5555-4555-8555-555555555555';
const V_ACTIVE = '66666666-6666-4666-8666-666666666666';
const V_DELETED = '77777777-7777-4777-8777-777777777777';
const V_EXPIRED = '88888888-8888-4888-8888-888888888888';
const C1 = '99999999-9999-4999-8999-999999999999';
const C2 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const C3 = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

const base: OracleFacts = {
  tenants: [{ id: T }],
  principals: [{ id: A, piiRead: true }, { id: M, piiRead: false }],
  memberships: [
    { tenantId: T, principalId: A, role: 'admin', isActive: true },
    { tenantId: T, principalId: M, role: 'member', isActive: true },
  ],
  groups: [],
  groupMemberships: [],
  documents: [
    { tenantId: T, documentId: DOC_ACTIVE, title: 'active', status: 'active' },
    { tenantId: T, documentId: DOC_DELETED, title: 'deleted', status: 'deleted' },
  ],
  versions: [
    { tenantId: T, documentId: DOC_ACTIVE, versionId: V_ACTIVE, versionNo: 1, status: 'valid', isCurrent: true, retentionExpired: false },
    { tenantId: T, documentId: DOC_DELETED, versionId: V_DELETED, versionNo: 1, status: 'valid', isCurrent: true, retentionExpired: false },
    { tenantId: T, documentId: DOC_ACTIVE, versionId: V_EXPIRED, versionNo: 2, status: 'valid', isCurrent: false, retentionExpired: true },
  ],
  chunks: [
    { tenantId: T, versionId: V_ACTIVE, chunkId: C1, chunkNo: 1, text: 'c1', hasPii: false },
    { tenantId: T, versionId: V_DELETED, chunkId: C2, chunkNo: 1, text: 'c2', hasPii: false },
    { tenantId: T, versionId: V_EXPIRED, chunkId: C3, chunkNo: 1, text: 'c3', hasPii: true },
  ],
  grants: [
    { tenantId: T, documentId: DOC_ACTIVE, subjectType: 'principal', subjectId: A, capability: 'read', revoked: false },
    { tenantId: T, documentId: DOC_DELETED, subjectType: 'principal', subjectId: A, capability: 'read', revoked: false },
  ],
};

describe('oracle semantics (ST extensions)', () => {
  it('excludes soft-deleted documents from documents, versions, AND chunks', () => {
    const allowed = computeAllowed(base, A, T);
    expect(allowed.documents).toEqual(new Set([DOC_ACTIVE]));
    expect(allowed.documents.has(DOC_DELETED)).toBe(false);
    expect(allowed.versions.has(V_DELETED)).toBe(false);
    expect(allowed.chunks.has(C2)).toBe(false);
  });

  it('excludes retention-expired versions (and their chunks) even when current', () => {
    const allowed = computeAllowed(base, A, T);
    expect(allowed.versions.has(V_EXPIRED)).toBe(false);
    expect(allowed.chunks.has(C3)).toBe(false);
  });

  it('marks PII chunks as redacted for principals without pii:read, and unredacted for those with it', () => {
    const withPii = computeAllowed(base, A, T);
    expect(withPii.redactedChunks.has(C3)).toBe(false);
    const withoutPii = computeAllowed(base, M, T);
    expect(withoutPii.redactedChunks.has(C3)).toBe(false); // M has no grant on the doc at all
    // Give M a grant and verify redaction marking.
    const grantsM: OracleFacts = {
      ...base,
      grants: [{ tenantId: T, documentId: DOC_ACTIVE, subjectType: 'principal', subjectId: M, capability: 'read', revoked: false }],
      chunks: [{ tenantId: T, versionId: V_ACTIVE, chunkId: C3, chunkNo: 1, text: 'c3', hasPii: true }],
      versions: [{ tenantId: T, documentId: DOC_ACTIVE, versionId: V_ACTIVE, versionNo: 1, status: 'valid', isCurrent: true, retentionExpired: false }],
    };
    const mAllowed = computeAllowed(grantsM, M, T);
    expect(mAllowed.chunks.has(C3)).toBe(true);
    expect(mAllowed.redactedChunks.has(C3)).toBe(true);
    expect(computeAllowed(grantsM, A, T).redactedChunks.has(C3)).toBe(false);
  });

  it('default-denies principals with no active membership', () => {
    const allowed = computeAllowed(base, '00000000-0000-4000-8000-000000000000', T);
    expect(allowed.documents.size).toBe(0);
    expect(allowed.versions.size).toBe(0);
    expect(allowed.chunks.size).toBe(0);
    expect(allowed.redactedChunks.size).toBe(0);
  });
});
