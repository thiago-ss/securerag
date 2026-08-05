import { createHash, randomBytes } from 'node:crypto';
import { decodeJwt, findJwk, jwkToKeyObject, verifyJwsSignature, base64urlEncode, type DecodedJwt, type Jwk } from './jwt.js';

/**
 * OIDC provider client (ADR-0004): discovery (RFC 8414), authorization URL
 * builder (Authorization Code + PKCE S256 + state + nonce, RFC 7636), token
 * exchange, JWKS fetch with TTL cache + re-fetch on unknown kid (OIDC Core
 * §10.1.1), and id_token validation implementing the FULL 12-item checklist
 * from research r2. No real Keycloak anywhere in CI — tests use the in-process
 * fake provider (src/testkit.ts).
 *
 * Trust anchor: the configured `issuer`. Discovery metadata is accepted only
 * if its `issuer` field matches EXACTLY; jwks_uri is anchored via discovery
 * (never hard-coded). All endpoints are fetched over whatever httpFetch
 * provides (production TLS is the deployment envelope's concern; the
 * signature verification never relies on the TLS exemption, research r2
 * §id_token checklist item 5).
 */

export interface OidcClientConfig {
  /** Exact issuer identifier (trust anchor); MUST match the discovery `issuer`. */
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri?: string;
  /** Defaults to `${issuer}/.well-known/openid-configuration`. */
  discoveryUrl?: string;
  /** Clock skew allowance for exp/iat, seconds (default 120). */
  clockSkewSeconds?: number;
  /** Reject tokens whose iat is older than this, seconds (default 300). */
  maxIatSkewSeconds?: number;
  /** When set, auth_time must be present and no older than this, seconds. */
  maxAgeSeconds?: number;
  /** When set, the acr claim must be one of these values. */
  acrValues?: string[];
  /** JWKS cache TTL, ms (default 300_000; OIDC Core §10.1.1 rotation overlap). */
  jwksCacheTtlMs?: number;
  /** Injectable HTTP client; defaults to global fetch. */
  httpFetch?: typeof fetch;
  /** Injectable clock, epoch ms; defaults to Date.now. */
  now?: () => number;
}

export interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  code_challenge_methods_supported?: string[];
}

export interface PendingLogin {
  state: string;
  nonce: string;
  codeVerifier: string;
  codeChallenge: string;
  redirectUri: string;
  /** Epoch ms after which the flow is invalid. */
  expiresAt: number;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  azp?: string;
  exp: number;
  iat: number;
  nonce?: string;
  auth_time?: number;
  acr?: string;
  at_hash?: string;
  c_hash?: string;
  [claim: string]: unknown;
}

export interface ExchangeResult {
  idToken: string;
  accessToken: string;
  claims: IdTokenClaims;
  expiresIn?: number;
}

/** Discovery / token-endpoint failures (provider unreachable or misconfigured). */
export class OidcProviderError extends Error {
  readonly code = 'OIDC_PROVIDER_ERROR';

  constructor() {
    super('OIDC provider error');
    this.name = 'OidcProviderError';
  }
}

/** Static message for ALL id_token validation failures (no reason oracle). */
export class InvalidIdTokenError extends Error {
  readonly code = 'INVALID_ID_TOKEN';

  constructor() {
    super('Invalid id_token');
    this.name = 'InvalidIdTokenError';
  }
}

const DEFAULT_CLOCK_SKEW_SECONDS = 120;
const DEFAULT_MAX_IAT_SKEW_SECONDS = 300;
const DEFAULT_JWKS_CACHE_TTL_MS = 300_000;

function nowSeconds(now: () => number): number {
  return Math.floor(now() / 1000);
}

/**
 * Pure id_token validation — the FULL 12-item checklist (research r2):
 *  1. nested/encrypted JWT rejected (never negotiated → any enc/zip rejects);
 *  2. iss exact match; 3. aud contains client_id and no extra audiences;
 *  4. azp == client_id when present; 5. signature via JWKS (no TLS exemption);
 *  6. alg allowlist RS256/ES256 (none/HS* rejected); 7. exp (skewed);
 *  8. iat (skewed, max age); 9. nonce presence + equality (replay is bound by
 *     the one-time login flow consumption in the caller); 10. auth_time vs
 *     max_age; 11. acr when requested; 12. at_hash/c_hash (at_hash validated
 *     against the access token when present; a c_hash in the code flow is an
 *     unexpected artifact and rejects).
 * Throws InvalidIdTokenError on ANY failure — the message is static.
 */
export function validateIdToken(
  token: string,
  params: {
    issuer: string;
    clientId: string;
    expectedNonce: string;
    jwks: readonly Jwk[];
    accessToken?: string;
    clockSkewSeconds?: number;
    maxIatSkewSeconds?: number;
    maxAgeSeconds?: number;
    acrValues?: string[];
    now?: () => number;
  },
): IdTokenClaims {
  const now = params.now ?? Date.now;
  const skew = params.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const maxIatSkew = params.maxIatSkewSeconds ?? DEFAULT_MAX_IAT_SKEW_SECONDS;

  let decoded: DecodedJwt;
  try {
    decoded = decodeJwt(token);
  } catch {
    throw new InvalidIdTokenError();
  }

  // 1. nested/encrypted JWT: encryption was never negotiated, so any
  //    encryption artifact (or a non-JWT typ) rejects.
  const { header, payload } = decoded;
  if (header.enc !== undefined || header.zip !== undefined) throw new InvalidIdTokenError();
  if (header.typ !== undefined && header.typ !== 'JWT') throw new InvalidIdTokenError();

  // 6. alg allowlist BEFORE any key/signature work.
  const alg = header.alg;
  if (alg !== 'RS256' && alg !== 'ES256') throw new InvalidIdTokenError();

  // 5. signature via JWKS (kid lookup with kty/alg/use consistency). Every
  //    key-selection failure (unknown kid, malformed JWK, unsupported key
  //    shape) surfaces as the same InvalidIdTokenError — never a distinguishable
  //    error that could enumerate keys.
  try {
    const key = findJwk(params.jwks, header.kid, alg);
    if (!verifyJwsSignature(alg, decoded.data, decoded.signature, jwkToKeyObject(key))) {
      throw new InvalidIdTokenError();
    }
  } catch (err) {
    if (err instanceof InvalidIdTokenError) throw err;
    throw new InvalidIdTokenError();
  }

  const claims = payload as IdTokenClaims;

  // 2. iss exact match.
  if (claims.iss !== params.issuer) throw new InvalidIdTokenError();

  // 3. aud contains client_id; extra audiences reject (nothing else is trusted).
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audiences.length === 0 || !audiences.includes(params.clientId)) {
    throw new InvalidIdTokenError();
  }
  if (audiences.some((a) => a !== params.clientId)) throw new InvalidIdTokenError();

  // 4. azp == client_id when present.
  if (claims.azp !== undefined && claims.azp !== params.clientId) throw new InvalidIdTokenError();

  // sub is required by OIDC Core §2 and anchors the principal.
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) throw new InvalidIdTokenError();

  // 7. exp (with small clock skew).
  if (typeof claims.exp !== 'number' || nowSeconds(now) - skew > claims.exp) {
    throw new InvalidIdTokenError();
  }

  // 8. iat: not in the future beyond skew, and not too old.
  if (typeof claims.iat !== 'number') throw new InvalidIdTokenError();
  if (claims.iat > nowSeconds(now) + skew) throw new InvalidIdTokenError();
  if (nowSeconds(now) - claims.iat > maxIatSkew) throw new InvalidIdTokenError();

  // 9. nonce: MUST be present and equal (the one-time login flow bounds replay).
  if (claims.nonce !== params.expectedNonce) throw new InvalidIdTokenError();

  // 10. auth_time / max_age.
  if (params.maxAgeSeconds !== undefined) {
    const authTime = claims.auth_time;
    if (typeof authTime !== 'number') throw new InvalidIdTokenError();
    if (nowSeconds(now) - authTime > params.maxAgeSeconds) throw new InvalidIdTokenError();
  }

  // 11. acr when requested.
  if (params.acrValues !== undefined && params.acrValues.length > 0) {
    if (typeof claims.acr !== 'string' || !params.acrValues.includes(claims.acr)) {
      throw new InvalidIdTokenError();
    }
  }

  // 12. at_hash / c_hash: at_hash is validated whenever present (we always
  //     have the access token in the code flow); c_hash is a hybrid-flow
  //     artifact and rejects in the code flow.
  if (claims.c_hash !== undefined) throw new InvalidIdTokenError();
  if (claims.at_hash !== undefined) {
    const accessToken = params.accessToken;
    if (accessToken === undefined) throw new InvalidIdTokenError();
    const expected = base64urlEncode(
      createHash('sha256').update(accessToken).digest().subarray(0, 16),
    );
    if (claims.at_hash !== expected) throw new InvalidIdTokenError();
  }

  return claims;
}

export interface IdTokenValidationContext {
  jwks: readonly Jwk[];
  expectedNonce: string;
  accessToken?: string;
}

/** In-memory one-time login flow store (state/nonce/codeVerifier binding). */
export class InMemoryLoginStore {
  private readonly entries = new Map<string, PendingLogin>();

  add(flow: PendingLogin): void {
    this.entries.set(flow.state, flow);
  }

  /** One-time consumption: the entry is deleted before expiry is checked, so a
   * replayed state never observes a second entry (RFC 9700 §4.2.4). */
  consume(state: string): PendingLogin | null {
    const flow = this.entries.get(state);
    if (flow === undefined) return null;
    this.entries.delete(state);
    if (Date.now() > flow.expiresAt) return null;
    return flow;
  }
}

export class OidcClient {
  private discoveryPromise: Promise<OidcMetadata> | null = null;
  private jwksCache: { keys: Jwk[]; fetchedAt: number } | null = null;

  constructor(readonly config: OidcClientConfig) {}

  private fetchImpl(): typeof fetch {
    return this.config.httpFetch ?? fetch;
  }

  private now(): number {
    return (this.config.now ?? Date.now)();
  }

  /** Discovery with TTL-less memoization (metadata is immutable per issuer). */
  async discover(): Promise<OidcMetadata> {
    this.discoveryPromise ??= this.discoverOnce();
    return this.discoveryPromise;
  }

  private async discoverOnce(): Promise<OidcMetadata> {
    const discoveryUrl = this.config.discoveryUrl ?? `${this.config.issuer}/.well-known/openid-configuration`;
    let response: Response;
    try {
      response = await this.fetchImpl()(discoveryUrl);
    } catch {
      throw new OidcProviderError();
    }
    if (!response.ok) throw new OidcProviderError();
    let metadata: unknown;
    try {
      metadata = await response.json();
    } catch {
      throw new OidcProviderError();
    }
    const doc = metadata as Partial<OidcMetadata>;
    if (typeof doc.issuer !== 'string' || doc.issuer !== this.config.issuer) {
      throw new OidcProviderError();
    }
    if (
      typeof doc.authorization_endpoint !== 'string' ||
      typeof doc.token_endpoint !== 'string' ||
      typeof doc.jwks_uri !== 'string'
    ) {
      throw new OidcProviderError();
    }
    if (
      doc.code_challenge_methods_supported !== undefined &&
      !doc.code_challenge_methods_supported.includes('S256')
    ) {
      throw new OidcProviderError();
    }
    return {
      issuer: doc.issuer,
      authorization_endpoint: doc.authorization_endpoint,
      token_endpoint: doc.token_endpoint,
      jwks_uri: doc.jwks_uri,
      ...(doc.end_session_endpoint !== undefined ? { end_session_endpoint: doc.end_session_endpoint } : {}),
      ...(doc.code_challenge_methods_supported !== undefined
        ? { code_challenge_methods_supported: doc.code_challenge_methods_supported }
        : {}),
    };
  }

  async getJwks(): Promise<Jwk[]> {
    const cached = this.jwksCache;
    const ttl = this.config.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS;
    if (cached !== null && this.now() - cached.fetchedAt < ttl) return cached.keys;
    const keys = await this.fetchJwks();
    this.jwksCache = { keys, fetchedAt: this.now() };
    return keys;
  }

  private async fetchJwks(): Promise<Jwk[]> {
    const metadata = await this.discover();
    let response: Response;
    try {
      response = await this.fetchImpl()(metadata.jwks_uri);
    } catch {
      throw new OidcProviderError();
    }
    if (!response.ok) throw new OidcProviderError();
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new OidcProviderError();
    }
    const keys = (body as { keys?: unknown }).keys;
    if (!Array.isArray(keys)) throw new OidcProviderError();
    return keys as Jwk[];
  }

  /** A 256-bit state, a 256-bit nonce, and a 256-bit PKCE code_verifier. */
  createLoginFlow(now = Date.now()): PendingLogin {
    const state = base64urlEncode(randomBytes(32));
    const nonce = base64urlEncode(randomBytes(32));
    const codeVerifier = base64urlEncode(randomBytes(32));
    return {
      state,
      nonce,
      codeVerifier,
      codeChallenge: base64urlEncode(createHash('sha256').update(codeVerifier).digest()),
      redirectUri: this.config.redirectUri,
      expiresAt: now + 10 * 60_000,
    };
  }

  async buildAuthorizationUrl(flow: PendingLogin): Promise<string> {
    const metadata = await this.discover();
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: flow.redirectUri,
      scope: 'openid profile',
      state: flow.state,
      nonce: flow.nonce,
      code_challenge: flow.codeChallenge,
      code_challenge_method: 'S256',
    });
    if (this.config.maxAgeSeconds !== undefined) {
      params.set('max_age', String(this.config.maxAgeSeconds));
    }
    if (this.config.acrValues !== undefined && this.config.acrValues.length > 0) {
      params.set('acr_values', this.config.acrValues.join(' '));
    }
    return `${metadata.authorization_endpoint}?${params.toString()}`;
  }

  /**
   * Exchange the authorization code (RFC 7636) and validate the returned
   * id_token. The one-time login flow is consumed by the caller BEFORE this
   * call; the nonce equality plus the consumed flow make replay impossible.
   */
  async exchangeCode(flow: PendingLogin, code: string): Promise<ExchangeResult> {
    const metadata = await this.discover();
    let response: Response;
    try {
      response = await this.fetchImpl()(metadata.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: flow.redirectUri,
          client_id: this.config.clientId,
          code_verifier: flow.codeVerifier,
        }),
      });
    } catch {
      throw new OidcProviderError();
    }
    if (!response.ok) throw new OidcProviderError();
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new OidcProviderError();
    }
    const token = body as { id_token?: unknown; access_token?: unknown; expires_in?: unknown };
    // Without a validatable id_token there is NO authentication (research r2).
    if (typeof token.id_token !== 'string') throw new OidcProviderError();
    const accessToken = typeof token.access_token === 'string' ? token.access_token : '';
    const claims = await this.validateTokenWithJwksRetry(token.id_token, flow.nonce, accessToken);
    return {
      idToken: token.id_token,
      accessToken,
      claims,
      ...(typeof token.expires_in === 'number' ? { expiresIn: token.expires_in } : {}),
    };
  }

  private validationParams(
    nonce: string,
    accessToken: string | undefined,
  ): Omit<Parameters<typeof validateIdToken>[1], 'jwks'> {
    const cfg = this.config;
    return {
      issuer: cfg.issuer,
      clientId: cfg.clientId,
      expectedNonce: nonce,
      ...(accessToken !== undefined ? { accessToken } : {}),
      ...(cfg.clockSkewSeconds !== undefined ? { clockSkewSeconds: cfg.clockSkewSeconds } : {}),
      ...(cfg.maxIatSkewSeconds !== undefined ? { maxIatSkewSeconds: cfg.maxIatSkewSeconds } : {}),
      ...(cfg.maxAgeSeconds !== undefined ? { maxAgeSeconds: cfg.maxAgeSeconds } : {}),
      ...(cfg.acrValues !== undefined ? { acrValues: cfg.acrValues } : {}),
      ...(cfg.now !== undefined ? { now: cfg.now } : {}),
    };
  }

  /**
   * Validate with JWKS rotation support (OIDC Core §10.1.1): an id_token
   * carrying an unknown kid re-fetches the JWKS ONCE (the cached set is
   * expired) and retries; a second failure rejects. Every failure surfaces as
   * InvalidIdTokenError.
   */
  private async validateTokenWithJwksRetry(
    token: string,
    nonce: string,
    accessToken?: string,
  ): Promise<IdTokenClaims> {
    const base = this.validationParams(nonce, accessToken);
    const attempt = async (): Promise<IdTokenClaims> => validateIdToken(token, {
      ...base,
      jwks: await this.getJwks(),
    });
    try {
      return await attempt();
    } catch (err) {
      if (!(err instanceof InvalidIdTokenError)) throw err;
      if (this.usesUnknownKid(token)) {
        this.jwksCache = null; // force a fresh fetch
        return attempt();
      }
      throw err;
    }
  }

  private usesUnknownKid(token: string): boolean {
    const cached = this.jwksCache;
    if (cached === null) return false;
    let kid: string | undefined;
    try {
      kid = decodeJwt(token).header.kid;
    } catch {
      return false;
    }
    if (kid === undefined) return false;
    return !cached.keys.some((k) => k.kid === kid);
  }

  /** Validate a raw id_token against the discovered JWKS (test seam). */
  async validateToken(token: string, nonce: string, accessToken?: string): Promise<IdTokenClaims> {
    return this.validateTokenWithJwksRetry(token, nonce, accessToken);
  }

  /** RP-initiated logout URL (OIDC RP-Initiated Logout 1.0); null when the
   * provider exposes no end_session_endpoint. id_token_hint is optional. */
  async endSessionUrl(idTokenHint?: string): Promise<string | null> {
    const metadata = await this.discover();
    const endpoint = metadata.end_session_endpoint;
    if (endpoint === undefined) return null;
    const params = new URLSearchParams();
    if (idTokenHint !== undefined) params.set('id_token_hint', idTokenHint);
    if (this.config.postLogoutRedirectUri !== undefined) {
      params.set('post_logout_redirect_uri', this.config.postLogoutRedirectUri);
    }
    const query = params.toString();
    return query.length > 0 ? `${endpoint}?${query}` : endpoint;
  }
}
