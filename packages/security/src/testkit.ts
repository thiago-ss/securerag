import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { base64urlEncode, type Jwk, type JwkSet } from './jwt.js';

/**
 * In-process, deterministic OIDC provider for CI (research r2 §Keycloak demo
 * notes: Keycloak is demo-only, never in CI). Serves discovery, authorization
 * (PKCE S256), token exchange, JWKS, and RP-initiated logout, and issues
 * properly signed id_tokens carrying all 12 checklist claims. Negative
 * variants are produced by mutation hooks / signature overrides / raw token
 * overrides — every one of them MUST be rejected by the client with the same
 * outcome (no validation oracle).
 *
 * The provider NEVER talks to the API: /authorize redirects the user agent
 * (here: the test's fetch client) back to the configured redirect_uri, which
 * the test then follows.
 */

export type FakeSigningAlg = 'RS256' | 'ES256' | 'HS256' | 'none';

export interface FakeTokenContext {
  nonce: string;
  subject: string;
  codeVerifier: string;
  accessToken: string;
}

export type IdTokenMutation = (
  claims: Record<string, unknown>,
  ctx: FakeTokenContext,
) => Record<string, unknown>;

export interface FakeOidcProviderOptions {
  /** Exact issuer value the provider asserts in metadata and tokens (default 'test-issuer'). */
  issuer?: string;
  clientId?: string;
  /** Default subject for /authorize (tests set this to the desired principal). */
  defaultSubject?: string;
  /** Default acr claim (default 'urn:securerag:acr:1'). */
  defaultAcr?: string;
  /** Token lifetime seconds (default 300). */
  tokenLifetimeSeconds?: number;
}

interface PendingCode {
  codeChallenge: string;
  nonce: string;
  subject: string;
  redirectUri: string;
  clientId: string;
  issuedAt: number;
}

export class FakeOidcProvider {
  readonly issuer: string;
  readonly clientId: string;
  defaultSubject: string;
  defaultAcr: string;
  /** Access token issued at /token (controls at_hash determinism). */
  accessToken = 'securerag-fake-access-token';

  private readonly rsaPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  private readonly ecPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  private readonly rsaJwk: Jwk;
  private readonly ecJwk: Jwk;
  private readonly rsaPublicPem = this.rsaPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  private readonly tokenLifetimeSeconds: number;

  private server: Server | null = null;
  private baseUrlValue = '';
  private readonly codes = new Map<string, PendingCode>();
  private mutation: IdTokenMutation | null = null;
  private signing: { alg: FakeSigningAlg; kid: string | undefined } = {
    alg: 'RS256',
    kid: 'fake-rsa-1',
  };
  private tokenOverride: string | null = null;
  private lastIssuedIdToken: string | null = null;

  lastAuthorizeParams: URLSearchParams | null = null;
  lastTokenRequest: URLSearchParams | null = null;

  constructor(options: FakeOidcProviderOptions = {}) {
    this.issuer = options.issuer ?? 'test-issuer';
    this.clientId = options.clientId ?? 'securerag-api';
    this.defaultSubject = options.defaultSubject ?? 'alice-sub';
    this.defaultAcr = options.defaultAcr ?? 'urn:securerag:acr:1';
    this.tokenLifetimeSeconds = options.tokenLifetimeSeconds ?? 300;
    this.rsaJwk = {
      kty: 'RSA',
      kid: 'fake-rsa-1',
      use: 'sig',
      alg: 'RS256',
      ...(this.rsaPair.publicKey.export({ format: 'jwk' }) as { n: string; e: string }),
    };
    this.ecJwk = {
      kty: 'EC',
      kid: 'fake-ec-1',
      use: 'sig',
      alg: 'ES256',
      ...(this.ecPair.publicKey.export({ format: 'jwk' }) as { crv: string; x: string; y: string }),
    };
  }

  get baseUrl(): string {
    if (this.baseUrlValue === '') throw new Error('FakeOidcProvider not started');
    return this.baseUrlValue;
  }

  get discoveryUrl(): string {
    return `${this.baseUrl}/.well-known/openid-configuration`;
  }

  get jwks(): JwkSet {
    return { keys: [this.rsaJwk, this.ecJwk] };
  }

  /** The raw id_token from the last token exchange (for tamper tests). */
  get lastIdToken(): string | null {
    return this.lastIssuedIdToken;
  }

  /** Replace id_token claims before signing (negative variants). */
  setIdTokenMutation(mutation: IdTokenMutation | null): void {
    this.mutation = mutation;
  }

  /** Choose the signing algorithm and kid for issued tokens. */
  setSigning(alg: FakeSigningAlg, kid?: string): void {
    this.signing = { alg, kid };
  }

  /** Serve an arbitrary raw token verbatim at /token (tampered/garbage variants). */
  setTokenOverride(token: string | null): void {
    this.tokenOverride = token;
  }

  /** Sign an arbitrary payload with the provider's keys (unit-test seam).
   * `kid: null` suppresses the kid entirely (missing-kid negative variant). */
  signToken(
    payload: Record<string, unknown>,
    opts: { alg?: FakeSigningAlg; kid?: string | null; header?: Record<string, unknown> } = {},
  ): string {
    const alg = opts.alg ?? this.signing.alg;
    const kid =
      opts.kid === null
        ? undefined
        : opts.kid ?? (alg === 'ES256' ? 'fake-ec-1' : alg === 'RS256' ? 'fake-rsa-1' : undefined);
    const header = { alg, typ: 'JWT', ...(kid !== undefined ? { kid } : {}), ...opts.header };
    return this.signRaw(header, payload, alg);
  }

  private signRaw(header: Record<string, unknown>, payload: Record<string, unknown>, alg: FakeSigningAlg): string {
    const head = base64urlEncode(Buffer.from(JSON.stringify(header), 'utf8'));
    const body = base64urlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
    const data = `${head}.${body}`;
    let signature = '';
    if (alg === 'RS256') {
      signature = base64urlEncode(sign('sha256', Buffer.from(data, 'utf8'), this.rsaPair.privateKey));
    } else if (alg === 'ES256') {
      signature = base64urlEncode(
        sign('sha256', Buffer.from(data, 'utf8'), { key: this.ecPair.privateKey, dsaEncoding: 'ieee-p1363' }),
      );
    } else if (alg === 'HS256') {
      // Alg-confusion forgery: HMAC with the RSA PUBLIC key (the classic HS* attack).
      signature = base64urlEncode(createHmac('sha256', this.rsaPublicPem).update(data).digest());
    }
    return `${data}.${signature}`;
  }

  private buildClaims(nonce: string, subject: string, accessToken: string): Record<string, unknown> {
    const now = Math.floor(Date.now() / 1000);
    return {
      iss: this.issuer,
      sub: subject,
      aud: this.clientId,
      azp: this.clientId,
      iat: now,
      exp: now + this.tokenLifetimeSeconds,
      nonce,
      auth_time: now - 60,
      acr: this.defaultAcr,
      jti: base64urlEncode(randomBytes(16)),
      sid: base64urlEncode(randomBytes(16)),
      at_hash: base64urlEncode(createHash('sha256').update(accessToken).digest().subarray(0, 16)),
    };
  }

  private json(reply: import('node:http').ServerResponse, status: number, body: unknown): void {
    reply.writeHead(status, { 'content-type': 'application/json' });
    reply.end(JSON.stringify(body));
  }

  async start(): Promise<void> {
    if (this.server !== null) return;
    this.server = createServer((request, reply) => {
      void this.handle(request, reply);
    });
    await new Promise<void>((resolve) => {
      this.server!.listen(0, '127.0.0.1', () => resolve());
    });
    const address = this.server.address() as AddressInfo;
    this.baseUrlValue = `http://127.0.0.1:${address.port}`;
  }

  async stop(): Promise<void> {
    if (this.server === null) return;
    const server = this.server;
    this.server = null;
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err === undefined ? resolve() : reject(err)));
    });
  }

  private async handle(request: import('node:http').IncomingMessage, reply: import('node:http').ServerResponse): Promise<void> {
    const url = new URL(request.url ?? '/', this.baseUrlValue || 'http://127.0.0.1');
    try {
      if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
        this.json(reply, 200, {
          issuer: this.issuer,
          authorization_endpoint: `${this.baseUrl}/authorize`,
          token_endpoint: `${this.baseUrl}/token`,
          jwks_uri: `${this.baseUrl}/jwks`,
          end_session_endpoint: `${this.baseUrl}/end_session`,
          response_types_supported: ['code'],
          code_challenge_methods_supported: ['S256'],
          id_token_signing_alg_values_supported: ['RS256', 'ES256'],
        });
        return;
      }
      if (request.method === 'GET' && url.pathname === '/jwks') {
        this.json(reply, 200, this.jwks);
        return;
      }
      if (request.method === 'GET' && url.pathname === '/authorize') {
        this.handleAuthorize(url.searchParams, reply);
        return;
      }
      if (request.method === 'POST' && url.pathname === '/token') {
        await this.handleToken(request, reply);
        return;
      }
      if (request.method === 'GET' && url.pathname === '/end_session') {
        const target = url.searchParams.get('post_logout_redirect_uri');
        if (target === null) {
          reply.writeHead(200, { 'content-type': 'text/plain' });
          reply.end('logged out');
          return;
        }
        reply.writeHead(302, { location: target });
        reply.end();
        return;
      }
      this.json(reply, 404, { error: 'not_found' });
    } catch {
      this.json(reply, 500, { error: 'internal_error' });
    }
  }

  private handleAuthorize(params: URLSearchParams, reply: import('node:http').ServerResponse): void {
    this.lastAuthorizeParams = new URLSearchParams(params);
    const fail = (): void => {
      reply.writeHead(400, { 'content-type': 'application/json' });
      reply.end(JSON.stringify({ error: 'invalid_request' }));
    };
    if (
      params.get('response_type') !== 'code' ||
      params.get('client_id') !== this.clientId ||
      params.get('code_challenge_method') !== 'S256' ||
      params.get('state') === null ||
      params.get('nonce') === null ||
      params.get('code_challenge') === null
    ) {
      fail();
      return;
    }
    const redirectUri = params.get('redirect_uri');
    if (redirectUri === null) {
      fail();
      return;
    }
    const code = base64urlEncode(randomBytes(32));
    this.codes.set(code, {
      codeChallenge: params.get('code_challenge') as string,
      nonce: params.get('nonce') as string,
      subject: this.defaultSubject,
      redirectUri,
      clientId: this.clientId,
      issuedAt: Date.now(),
    });
    const callback = new URL(redirectUri);
    callback.searchParams.set('code', code);
    callback.searchParams.set('state', params.get('state') as string);
    callback.searchParams.set('iss', this.issuer);
    reply.writeHead(302, { location: callback.toString() });
    reply.end();
  }

  private async handleToken(request: import('node:http').IncomingMessage, reply: import('node:http').ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
    this.lastTokenRequest = new URLSearchParams(body);
    const fail = (): void => this.json(reply, 400, { error: 'invalid_grant' });

    if (body.get('grant_type') !== 'authorization_code') {
      fail();
      return;
    }
    const rawCode = body.get('code');
    if (rawCode === null) {
      fail();
      return;
    }
    const code: string = rawCode;
    const pending = this.codes.get(code);
    if (pending === undefined) {
      fail();
      return;
    }
    this.codes.delete(code); // one-time use
    if (Date.now() - pending.issuedAt > 10 * 60_000) {
      fail();
      return;
    }
    if (body.get('client_id') !== this.clientId || body.get('redirect_uri') !== pending.redirectUri) {
      fail();
      return;
    }
    // PKCE S256 check (RFC 7636 §4.6); mismatch and missing verifier both fail.
    const verifier = body.get('code_verifier');
    if (verifier === null || base64urlEncode(createHash('sha256').update(verifier).digest()) !== pending.codeChallenge) {
      fail();
      return;
    }

    if (this.tokenOverride !== null) {
      const override = this.tokenOverride;
      this.lastIssuedIdToken = override;
      this.json(reply, 200, {
        id_token: override,
        access_token: this.accessToken,
        token_type: 'Bearer',
        expires_in: this.tokenLifetimeSeconds,
      });
      return;
    }

    const claims = this.buildClaims(pending.nonce, pending.subject, this.accessToken);
    const finalClaims = this.mutation !== null ? this.mutation(claims, {
      nonce: pending.nonce,
      subject: pending.subject,
      codeVerifier: verifier,
      accessToken: this.accessToken,
    }) : claims;
    const idToken = this.signToken(finalClaims, {
      alg: this.signing.alg,
      ...(this.signing.kid !== undefined ? { kid: this.signing.kid } : {}),
    });
    this.lastIssuedIdToken = idToken;
    this.json(reply, 200, {
      id_token: idToken,
      access_token: this.accessToken,
      token_type: 'Bearer',
      expires_in: this.tokenLifetimeSeconds,
    });
  }
}
