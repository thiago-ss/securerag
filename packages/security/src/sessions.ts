import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';
import { withIdentityContext } from './bootstrap.js';

/**
 * Server-side session service (ADR-0004). The session cookie carries an opaque
 * 256-bit bearer token; the database stores ONLY sha256(token) in
 * sessions.token_hash (migration 0005), so a database leak never yields live
 * credentials. Session rows are created through RLS as the principal
 * (principal_scope), lookups run through the SECURITY DEFINER get_session
 * which enforces expiry + revocation INSIDE SQL (ADR-0014) — foreign,
 * expired, and revoked tokens all yield null and the API rejects them
 * byte-identically (default deny).
 */

export interface SessionRow {
  sessionId: string;
  principalId: string;
  csrfToken: Buffer;
  expiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
}

interface SessionRowDb {
  session_id: string;
  principal_id: string;
  csrf_token: Buffer;
  expires_at: Date;
  revoked_at: Date | null;
  created_at: Date;
}

function toSessionRow(row: SessionRowDb): SessionRow {
  return {
    sessionId: row.session_id,
    principalId: row.principal_id,
    csrfToken: row.csrf_token,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  };
}

/** 256-bit opaque session token, base64url (43 chars). */
export function newSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

/** sha256 of the raw token — the ONLY thing the database ever stores. */
export function hashSessionToken(token: string): Buffer {
  return createHash('sha256').update(token).digest();
}

export interface CreateSessionParams {
  principalId: string;
  /** Session lifetime in seconds (default 8h). */
  ttlSeconds?: number;
  /** Injectable RNG for deterministic tests. */
  randomBytes?: (size: number) => Buffer;
}

/**
 * Insert a new session row for the principal through RLS (principal_scope
 * WITH CHECK requires principal_id == ctx principal, so the insert is bound
 * to the principal context established by withIdentityContext). Returns the
 * opaque token (cookie value) and the created row.
 */
export async function createSession(
  pool: Pool,
  params: CreateSessionParams,
): Promise<{ token: string; session: SessionRow }> {
  const token = newSessionToken();
  const csrfToken = (params.randomBytes ?? randomBytes)(32);
  const ttlSeconds = params.ttlSeconds ?? 8 * 3600;
  const result = await withIdentityContext(pool, params.principalId, async (client) => {
    const { rows } = await client.query<SessionRowDb>(
      `INSERT INTO securerag.sessions
         (principal_id, csrf_token, token_hash, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(secs => $4))
       RETURNING session_id, principal_id, csrf_token, expires_at, revoked_at, created_at`,
      [params.principalId, csrfToken, hashSessionToken(token), ttlSeconds],
    );
    const row = rows[0];
    if (row === undefined) throw new Error('session insert returned no row');
    return toSessionRow(row);
  });
  return { token, session: result.result };
}

/** Valid session for the token, or null for foreign/expired/revoked alike. */
export async function getSession(pool: Pool, token: string): Promise<SessionRow | null> {
  const { rows } = await pool.query<SessionRowDb>(
    `SELECT session_id, principal_id, csrf_token, expires_at, revoked_at, created_at
       FROM securerag.get_session($1)`,
    [hashSessionToken(token)],
  );
  const row = rows[0];
  return row === undefined ? null : toSessionRow(row);
}

/** Logout: revoke the session server-side. Returns false for unknown tokens. */
export async function revokeSession(pool: Pool, token: string): Promise<boolean> {
  const { rows } = await pool.query<{ revoke_session: boolean }>(
    `SELECT revoke_session FROM securerag.revoke_session($1)`,
    [hashSessionToken(token)],
  );
  return rows[0]?.revoke_session === true;
}

/** Timing-safe CSRF comparison of the session's csrf_token against the
 * X-CSRF-Token header (hex). Wrong length or malformed hex never matches. */
export function csrfMatches(expected: Buffer, provided: string | undefined): boolean {
  if (provided === undefined || provided.length === 0) return false;
  if (!/^[0-9a-fA-F]*$/.test(provided)) return false;
  const providedBytes = Buffer.from(provided, 'hex');
  if (providedBytes.length !== expected.length) return false;
  return timingSafeEqual(expected, providedBytes);
}

export const SESSION_COOKIE_HOST_PREFIX = '__Host-';
export const SESSION_COOKIE_PLAIN_NAME = 'securerag_session';

/** Production cookie name honors the __Host- prefix; plain over non-TLS (tests). */
export function sessionCookieName(secure: boolean): string {
  return secure ? `${SESSION_COOKIE_HOST_PREFIX}${SESSION_COOKIE_PLAIN_NAME}` : SESSION_COOKIE_PLAIN_NAME;
}

/**
 * Prefix rules (draft-ietf-httpbis-rfc6265bis §4.1.3.2): a __Host- cookie is
 * only accepted by user agents when set with Secure, Path=/ and no Domain —
 * so a __Host- name REQUIRES secure transport. Also rejects names that could
 * inject attributes.
 */
export function validateSessionCookieConfig(name: string, secure: boolean): void {
  if (name.startsWith(SESSION_COOKIE_HOST_PREFIX) && !secure) {
    throw new Error('__Host- session cookie requires Secure (cookies over plain HTTP cannot use the prefix)');
  }
  if (/[=\s;,]/.test(name)) {
    throw new Error(`invalid session cookie name: ${JSON.stringify(name)}`);
  }
}

export interface SessionCookieOptions {
  name: string;
  value: string;
  secure: boolean;
  /** Seconds; omitted for session-cookie semantics. */
  maxAgeSeconds?: number;
  /** Absolute expiry (e.g. epoch for deletion). */
  expires?: Date;
  path?: string;
}

/** HttpOnly + Secure + SameSite=Lax + Path=/ (ADR-0004; SameSite=Lax keeps the
 * OIDC redirect callback working, research r2 §Session cookie security notes). */
export function buildSessionCookie(options: SessionCookieOptions): string {
  validateSessionCookieConfig(options.name, options.secure);
  const parts = [
    `${options.name}=${options.value}`,
    'HttpOnly',
    'SameSite=Lax',
    `Path=${options.path ?? '/'}`,
  ];
  if (options.secure) parts.push('Secure');
  if (options.expires !== undefined) parts.push(`Expires=${options.expires.toUTCString()}`);
  if (options.maxAgeSeconds !== undefined) parts.push(`Max-Age=${Math.floor(options.maxAgeSeconds)}`);
  return parts.join('; ');
}

/** Cookie-clearing value for logout (Expires in the past + Max-Age=0). */
export function expireSessionCookie(name: string, secure: boolean): string {
  return buildSessionCookie({ name, value: '', secure, expires: new Date(0), maxAgeSeconds: 0 });
}

/** Extract the cookie value for `name` from a Cookie header (null when absent). */
export function parseCookieHeader(header: string | string[] | undefined, name: string): string | null {
  const value = Array.isArray(header) ? header.join('; ') : header;
  if (value === undefined || value.length === 0) return null;
  for (const part of value.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    if (part.slice(0, eq).trim() === name) {
      const cookieValue = part.slice(eq + 1).trim();
      return cookieValue.length > 0 ? cookieValue : null;
    }
  }
  return null;
}
