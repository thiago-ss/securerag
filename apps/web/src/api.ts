import { env } from './env';
import type {
  AuditRecord,
  DocumentInfo,
  DocumentListItem,
  GrantEntry,
  GroupRecord,
  JobStatus,
  Me,
  MembershipRecord,
  Problem,
  QuarantineRecord,
  RetentionPolicy,
  RetrievalOutcome,
  VersionMetadata,
} from './types';

/**
 * Typed same-origin API client. Session auth flows through the HttpOnly
 * session cookie; state-changing requests carry the CSRF token from /auth/me.
 * Error handling: problem+json bodies surface as typed ApiError; 401s bubble
 * so the app shell can drop to the login page.
 */
export class ApiError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export const API_BASE = env.VITE_API_BASE.replace(/\/$/, '');

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !(init.body instanceof FormData)) {
    headers.set('content-type', 'application/json');
  }
  const method = (init.method ?? 'GET').toUpperCase();
  if (method !== 'GET' && csrfToken !== null) {
    headers.set('x-csrf-token', csrfToken);
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers, credentials: 'same-origin' });
  if (!res.ok) {
    let problem: Problem = { code: 'UNKNOWN', message: 'Request failed' };
    try {
      problem = (await res.json()) as Problem;
    } catch {
      // non-JSON error body: keep the default problem
    }
    throw new ApiError(problem.code, res.status, problem.message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const qs = search.toString();
  return qs === '' ? '' : `?${qs}`;
}

export const api = {
  me: (): Promise<Me> => request<Me>('/auth/me'),

  login: (): void => {
    window.location.assign(`${API_BASE}/auth/login`);
  },

  logout: async (): Promise<void> => {
    await request<{ ok: true }>('/auth/logout', { method: 'POST' });
    window.location.assign('/');
  },

  // ---- documents ----
  listDocuments: (tenantId: string): Promise<{ documents: DocumentListItem[] }> =>
    request(`/documents${query({ tenantId })}`),
  createDocument: (tenantId: string, title: string): Promise<{ document: DocumentInfo }> =>
    request('/documents', { method: 'POST', body: JSON.stringify({ tenantId, title }) }),
  getDocument: (documentId: string): Promise<DocumentInfo> =>
    request(`/documents/${documentId}`),
  listVersions: (documentId: string): Promise<{ versions: VersionMetadata[] }> =>
    request(`/documents/${documentId}/versions`),
  uploadVersion: (documentId: string, file: File): Promise<JobStatus> => {
    const form = new FormData();
    form.append('file', file);
    return request(`/documents/${documentId}/versions/upload`, { method: 'POST', body: form });
  },
  sourceUrl: (documentId: string, versionId: string): string =>
    `${API_BASE}/documents/${documentId}/versions/${versionId}/source`,

  // ---- grants ----
  listGrants: (documentId: string): Promise<{ grants: GrantEntry[] }> =>
    request(`/documents/${documentId}/grants`),
  addGrant: (
    documentId: string,
    body: { subjectType: GrantEntry['subjectType']; subjectId: string; capability: GrantEntry['capability'] },
  ): Promise<{ grant: GrantEntry }> =>
    request(`/documents/${documentId}/grants`, { method: 'POST', body: JSON.stringify(body) }),
  removeGrant: (documentId: string, grantId: string): Promise<{ ok: true }> =>
    request(`/documents/${documentId}/grants`, { method: 'DELETE', body: JSON.stringify({ grantId }) }),

  // ---- retrieval ----
  queryRetrieval: (tenantId: string, question: string): Promise<RetrievalOutcome> =>
    request('/retrieval/query', { method: 'POST', body: JSON.stringify({ tenantId, question }) }),

  // ---- quarantine ----
  listQuarantine: (tenantId: string): Promise<{ versions: QuarantineRecord[] }> =>
    request(`/quarantine${query({ tenantId })}`),
  reviewQuarantine: (
    versionId: string,
    body: { tenantId: string; decision: 'release' | 'keep'; reviewerCtx?: string },
  ): Promise<{ ok: true }> =>
    request(`/quarantine/${versionId}/review`, { method: 'POST', body: JSON.stringify(body) }),

  // ---- audit ----
  listAudit: (limit: number): Promise<{ events: AuditRecord[] }> =>
    request(`/audit/retrieval${query({ limit })}`),

  // ---- retention ----
  getRetentionPolicy: (tenantId: string): Promise<RetentionPolicy> =>
    request(`/retention-policy${query({ tenantId })}`),
  putRetentionPolicy: (
    body: Partial<Pick<RetentionPolicy, 'sourceDays' | 'derivedDays' | 'auditDays' | 'graceDays' | 'legalHold'>> & { tenantId: string },
  ): Promise<RetentionPolicy> =>
    request('/retention-policy', { method: 'PUT', body: JSON.stringify(body) }),

  // ---- memberships ----
  listMemberships: (tenantId: string): Promise<{ members: MembershipRecord[] }> =>
    request(`/memberships${query({ tenantId })}`),
  addMembership: (
    body: { tenantId: string; principalId: string; role: string },
  ): Promise<{ membership: MembershipRecord }> =>
    request('/memberships', { method: 'POST', body: JSON.stringify(body) }),
  patchMembership: (
    body: { tenantId: string; principalId: string; role?: string; isActive?: boolean },
  ): Promise<{ ok: true }> =>
    request('/memberships', { method: 'PATCH', body: JSON.stringify(body) }),
  removeMembership: (tenantId: string, principalId: string): Promise<{ ok: true }> =>
    request(`/memberships${query({ tenantId, principalId })}`, { method: 'DELETE' }),

  // ---- groups ----
  listGroups: (tenantId: string): Promise<{ groups: GroupRecord[] }> =>
    request(`/groups${query({ tenantId })}`),
  createGroup: (tenantId: string, name: string): Promise<{ group: GroupRecord }> =>
    request('/groups', { method: 'POST', body: JSON.stringify({ tenantId, name }) }),
  deleteGroup: (tenantId: string, groupId: string): Promise<{ ok: true }> =>
    request(`/groups${query({ tenantId, groupId })}`, { method: 'DELETE' }),
  addGroupMember: (groupId: string, body: { tenantId: string; principalId: string }): Promise<{ ok: true }> =>
    request(`/groups/${groupId}/members`, { method: 'POST', body: JSON.stringify(body) }),
  removeGroupMember: (groupId: string, tenantId: string, principalId: string): Promise<{ ok: true }> =>
    request(`/groups/${groupId}/members${query({ tenantId, principalId })}`, { method: 'DELETE' }),
};
