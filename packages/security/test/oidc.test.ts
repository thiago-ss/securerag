import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import {
  InMemoryLoginStore,
  InvalidIdTokenError,
  OidcClient,
  OidcProviderError,
  validateIdToken,
  base64urlEncode,
  type IdTokenClaims,
} from '../src/index.js';
import { FakeOidcProvider } from '../src/testkit.js';

const ISSUER = 'test-issuer';
const CLIENT_ID = 'securerag-api';

/** Minimal valid claims; every checklist test starts here and mutates one axis. */
function baseClaims(nonce: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  const accessToken = 'securerag-fake-access-token';
  return {
    iss: ISSUER,
    sub: 'alice-sub',
    aud: CLIENT_ID,
    azp: CLIENT_ID,
    exp: now + 300,
    iat: now,
    nonce,
    auth_time: now - 60,
    acr: 'urn:securerag:acr:1',
    at_hash: base64urlEncode(createHash('sha256').update(accessToken).digest().subarray(0, 16)),
    ...overrides,
  };
}

describe('jwt primitives: strict decoding and signature verification', () => {
  let provider: FakeOidcProvider;
  const nonce = 'nonce-1';

  beforeAll(async () => {
    provider = new FakeOidcProvider();
    await provider.start();
  });

  afterAll(async () => {
    await provider.stop();
  });

  function validate(token: string, expectedNonce = nonce): IdTokenClaims {
    return validateIdToken(token, {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      expectedNonce,
      jwks: provider.jwks.keys,
      accessToken: 'securerag-fake-access-token',
    });
  }

  it('accepts a properly signed RS256 token', () => {
    const token = provider.signToken(baseClaims(nonce));
    const claims = validate(token);
    expect(claims.sub).toBe('alice-sub');
  });

  it('accepts a properly signed ES256 token (allowlist includes both)', () => {
    const token = provider.signToken(baseClaims(nonce), { alg: 'ES256' });
    expect(validate(token).iss).toBe(ISSUER);
  });

  it('rejects alg none (empty signature)', () => {
    const token = provider.signToken(baseClaims(nonce), { alg: 'none' });
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('rejects alg HS256 (alg-confusion forgery signed with the RSA public key)', () => {
    const token = provider.signToken(baseClaims(nonce), { alg: 'HS256' });
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('rejects a tampered signature', () => {
    const token = provider.signToken(baseClaims(nonce));
    const [h, p] = token.split('.');
    const tampered = `${h}.${p}.${p}`;
    expect(() => validate(tampered)).toThrow(InvalidIdTokenError);
  });

  it('rejects an unknown kid even after a fresh JWKS has the real keys', () => {
    const token = provider.signToken(baseClaims(nonce), { kid: 'unknown-kid' });
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('rejects a missing kid (never guesses keys)', () => {
    const token = provider.signToken(baseClaims(nonce), { kid: null });
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('rejects malformed tokens: not a JWT, wrong segment count, non-JSON payload', () => {
    expect(() => validate('not-a-jwt')).toThrow(InvalidIdTokenError);
    expect(() => validate(`${randomBytes(16).toString('base64url')}.x.y`)).toThrow(InvalidIdTokenError);
    const token = provider.signToken(baseClaims(nonce));
    const [h, p] = token.split('.');
    expect(() => validate(`${h}.${p}.${p}.${p}`)).toThrow(InvalidIdTokenError);
  });
});

describe('id_token validation — the 12-item checklist (negative variants)', () => {
  let provider: FakeOidcProvider;

  beforeAll(async () => {
    provider = new FakeOidcProvider();
    await provider.start();
  });

  afterAll(async () => {
    await provider.stop();
  });

  function validate(
    token: string,
    opts: {
      expectedNonce?: string;
      /** null omits the access token entirely (at_hash-present token then rejects). */
      accessToken?: string | null;
      maxAgeSeconds?: number;
      acrValues?: string[];
      issuer?: string;
    } = {},
  ): IdTokenClaims {
    const params: Parameters<typeof validateIdToken>[1] = {
      issuer: opts.issuer ?? ISSUER,
      clientId: CLIENT_ID,
      expectedNonce: opts.expectedNonce ?? 'nonce-1',
      jwks: provider.jwks.keys,
    };
    if (opts.accessToken !== null) {
      params.accessToken = opts.accessToken ?? 'securerag-fake-access-token';
    }
    if (opts.maxAgeSeconds !== undefined) params.maxAgeSeconds = opts.maxAgeSeconds;
    if (opts.acrValues !== undefined) params.acrValues = opts.acrValues;
    return validateIdToken(token, params);
  }

  const now = (): number => Math.floor(Date.now() / 1000);

  it('1. rejects an encrypted (nested) JWT — encryption was never negotiated', () => {
    const token = provider.signToken(baseClaims('nonce-1'), {
      header: { enc: 'A128CBC-HS256' },
    });
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('1b. rejects a non-JWT typ', () => {
    const token = provider.signToken(baseClaims('nonce-1'), { header: { typ: 'at+jwt' } });
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('2. rejects a wrong iss (exact string match)', () => {
    const token = provider.signToken(baseClaims('nonce-1', { iss: 'https://evil.example' }));
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('3. rejects aud without client_id, extra audiences, and non-array junk', () => {
    const wrongAud = provider.signToken(baseClaims('nonce-1', { aud: 'another-client' }));
    expect(() => validate(wrongAud)).toThrow(InvalidIdTokenError);
    const extraAud = provider.signToken(baseClaims('nonce-1', { aud: [CLIENT_ID, 'another'] }));
    expect(() => validate(extraAud)).toThrow(InvalidIdTokenError);
    const noAud = provider.signToken(baseClaims('nonce-1', { aud: undefined }));
    expect(() => validate(noAud)).toThrow(InvalidIdTokenError);
  });

  it('4. rejects a mismatched azp; accepts azp == client_id', () => {
    const wrongAzp = provider.signToken(baseClaims('nonce-1', { azp: 'evil-client' }));
    expect(() => validate(wrongAzp)).toThrow(InvalidIdTokenError);
    const goodAzp = provider.signToken(baseClaims('nonce-1'));
    expect(validate(goodAzp).azp).toBe(CLIENT_ID);
  });

  it('5. rejects a token signed with a different key (kid points elsewhere)', () => {
    const other = new FakeOidcProvider();
    const token = other.signToken(baseClaims('nonce-1'));
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('6. rejects alg none/HS256/unknown even when claims are perfect', () => {
    for (const alg of ['none', 'HS256', 'ES384', 'RS512'] as const) {
      const token = provider.signToken(baseClaims('nonce-1'), { alg: alg as never });
      expect(() => validate(token), `alg ${alg} must reject`).toThrow(InvalidIdTokenError);
    }
  });

  it('7. rejects an expired token (exp in the past, beyond skew)', () => {
    const token = provider.signToken(baseClaims('nonce-1', { exp: now() - 3600 }));
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('8. rejects iat in the future beyond skew and iat too old', () => {
    const future = provider.signToken(baseClaims('nonce-1', { iat: now() + 3600 }));
    expect(() => validate(future)).toThrow(InvalidIdTokenError);
    const ancient = provider.signToken(baseClaims('nonce-1', { iat: now() - 10_000_000 }));
    expect(() => validate(ancient)).toThrow(InvalidIdTokenError);
  });

  it('9. rejects a missing nonce and a mismatched (replayed) nonce', () => {
    const missing = provider.signToken(baseClaims('nonce-1', { nonce: undefined }));
    expect(() => validate(missing)).toThrow(InvalidIdTokenError);
    const replayed = provider.signToken(baseClaims('nonce-1', { nonce: 'stale-nonce' }));
    expect(() => validate(replayed)).toThrow(InvalidIdTokenError);
    expect(() => validate(replayed, { expectedNonce: 'other' })).toThrow(InvalidIdTokenError);
  });

  it('10. rejects stale or missing auth_time when max_age is configured; accepts fresh', () => {
    const stale = provider.signToken(baseClaims('nonce-1', { auth_time: now() - 10 * 3600 }));
    expect(() => validate(stale, { maxAgeSeconds: 600 })).toThrow(InvalidIdTokenError);
    const missing = provider.signToken(baseClaims('nonce-1', { auth_time: undefined }));
    expect(() => validate(missing, { maxAgeSeconds: 600 })).toThrow(InvalidIdTokenError);
    const fresh = provider.signToken(baseClaims('nonce-1'));
    expect(validate(fresh, { maxAgeSeconds: 600 }).sub).toBe('alice-sub');
  });

  it('11. rejects a wrong acr when acr_values are requested; accepts a matching one', () => {
    const wrong = provider.signToken(baseClaims('nonce-1', { acr: 'urn:other' }));
    expect(() => validate(wrong, { acrValues: ['urn:securerag:acr:1'] })).toThrow(InvalidIdTokenError);
    const good = provider.signToken(baseClaims('nonce-1'));
    expect(validate(good, { acrValues: ['urn:securerag:acr:1'] }).acr).toBe('urn:securerag:acr:1');
  });

  it('12. rejects a wrong at_hash; rejects at_hash without an access token; accepts no at_hash', () => {
    const wrong = provider.signToken(baseClaims('nonce-1', { at_hash: 'AAAAAA' }));
    expect(() => validate(wrong)).toThrow(InvalidIdTokenError);
    const noAccess = provider.signToken(baseClaims('nonce-1'));
    expect(() => validate(noAccess, { accessToken: null })).toThrow(InvalidIdTokenError);
    const absent = provider.signToken(baseClaims('nonce-1', { at_hash: undefined }));
    expect(validate(absent).sub).toBe('alice-sub');
  });

  it('12b. rejects a c_hash in the code flow (hybrid-only artifact)', () => {
    const token = provider.signToken(baseClaims('nonce-1', { c_hash: 'AAAAAA' }));
    expect(() => validate(token)).toThrow(InvalidIdTokenError);
  });

  it('rejects a missing or empty sub', () => {
    const missing = provider.signToken(baseClaims('nonce-1', { sub: undefined }));
    expect(() => validate(missing)).toThrow(InvalidIdTokenError);
    const empty = provider.signToken(baseClaims('nonce-1', { sub: '' }));
    expect(() => validate(empty)).toThrow(InvalidIdTokenError);
  });

  it('rejects a token whose signature was made with an unrelated key and a mismatched jwks set', () => {
    const token = provider.signToken(baseClaims('nonce-1'));
    expect(() =>
      validateIdToken(token, {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        expectedNonce: 'nonce-1',
        jwks: [],
      }),
    ).toThrow(InvalidIdTokenError);
  });
});

describe('OidcClient over HTTP with the fake provider (discovery, PKCE, JWKS cache)', () => {
  let provider: FakeOidcProvider;
  let client: OidcClient;

  beforeAll(async () => {
    provider = new FakeOidcProvider();
    await provider.start();
    client = new OidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: 'http://securerag.test/auth/callback',
      postLogoutRedirectUri: 'http://securerag.test/',
      discoveryUrl: provider.discoveryUrl,
    });
  });

  afterAll(async () => {
    await provider.stop();
  });

  it('discovers metadata from the provider and anchors issuer + S256 support', async () => {
    const metadata = await client.discover();
    expect(metadata.issuer).toBe(ISSUER);
    expect(metadata.token_endpoint).toBe(`${provider.baseUrl}/token`);
    expect(metadata.code_challenge_methods_supported).toContain('S256');
  });

  it('rejects a discovery document whose issuer differs from the configured issuer', async () => {
    const rogue = new FakeOidcProvider({ issuer: 'https://evil.example' });
    await rogue.start();
    try {
      const bad = new OidcClient({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: 'http://securerag.test/auth/callback',
        discoveryUrl: rogue.discoveryUrl,
      });
      await expect(bad.discover()).rejects.toBeInstanceOf(OidcProviderError);
    } finally {
      await rogue.stop();
    }
  });

  it('builds an authorization URL with code + PKCE S256 + state + nonce', async () => {
    const flow = client.createLoginFlow();
    const url = new URL(await client.buildAuthorizationUrl(flow));
    expect(url.pathname).toBe('/authorize');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('redirect_uri')).toBe('http://securerag.test/auth/callback');
    expect(url.searchParams.get('scope')).toContain('openid');
    expect(url.searchParams.get('state')).toBe(flow.state);
    expect(url.searchParams.get('nonce')).toBe(flow.nonce);
    expect(url.searchParams.get('code_challenge')).toBe(flow.codeChallenge);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('exchanges a code end-to-end and validates the signed id_token (incl. at_hash)', async () => {
    const flow = client.createLoginFlow();
    const url = new URL(await client.buildAuthorizationUrl(flow));
    const authorize = await fetch(url, { redirect: 'manual' });
    expect(authorize.status).toBe(302);
    const callback = new URL(authorize.headers.get('location') as string);
    expect(callback.searchParams.get('iss')).toBe(ISSUER);
    expect(callback.searchParams.get('state')).toBe(flow.state);

    const exchanged = await client.exchangeCode(flow, callback.searchParams.get('code') as string);
    expect(exchanged.claims.iss).toBe(ISSUER);
    expect(exchanged.claims.sub).toBe('alice-sub');
    expect(exchanged.claims.nonce).toBe(flow.nonce);
    expect(exchanged.accessToken).toBe('securerag-fake-access-token');
  });

  it('a second exchange with the same code fails (one-time authorization codes)', async () => {
    const flow = client.createLoginFlow();
    const url = new URL(await client.buildAuthorizationUrl(flow));
    const authorize = await fetch(url, { redirect: 'manual' });
    const code = new URL(authorize.headers.get('location') as string).searchParams.get('code') as string;
    await expect(client.exchangeCode(flow, code)).resolves.toBeTruthy();
    await expect(client.exchangeCode(flow, code)).rejects.toBeInstanceOf(OidcProviderError);
  });

  it('rejects a token exchange carrying the wrong code_verifier (PKCE enforcement)', async () => {
    const flow = client.createLoginFlow();
    const url = new URL(await client.buildAuthorizationUrl(flow));
    const authorize = await fetch(url, { redirect: 'manual' });
    const code = new URL(authorize.headers.get('location') as string).searchParams.get('code') as string;
    const wrongVerifier = {
      ...flow,
      codeVerifier: base64urlEncode(randomBytes(32)),
    };
    await expect(client.exchangeCode(wrongVerifier, code)).rejects.toBeInstanceOf(OidcProviderError);
  });

  it('caches the JWKS (single fetch for many validations) and re-fetches once on an unknown kid', async () => {
    let jwksFetches = 0;
    const counting = new OidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: 'http://securerag.test/auth/callback',
      discoveryUrl: provider.discoveryUrl,
      httpFetch: async (input, init) => {
        const response = await fetch(input, init);
        if (String(input).endsWith('/jwks')) jwksFetches += 1;
        return response;
      },
    });
    const nonce = 'cache-nonce';
    const good = provider.signToken(baseClaims(nonce, { nonce }));
    await counting.validateToken(good, nonce, 'securerag-fake-access-token');
    await counting.validateToken(good, nonce, 'securerag-fake-access-token');
    await counting.validateToken(good, nonce, 'securerag-fake-access-token');
    expect(jwksFetches).toBe(1);

    const unknown = provider.signToken(baseClaims(nonce, { nonce }), { kid: 'rotated-key' });
    await expect(counting.validateToken(unknown, nonce)).rejects.toBeInstanceOf(InvalidIdTokenError);
    expect(jwksFetches).toBe(2);
  });

  it('exposes the RP-initiated logout URL with post_logout_redirect_uri', async () => {
    const url = await client.endSessionUrl();
    expect(url).toContain('/end_session');
    expect(new URL(url as string).searchParams.get('post_logout_redirect_uri')).toBe('http://securerag.test/');
  });

  it('login flow store: one-time consumption and expiry', () => {
    const store = new InMemoryLoginStore();
    const flow = client.createLoginFlow();
    store.add(flow);
    expect(store.consume(flow.state)?.state).toBe(flow.state);
    expect(store.consume(flow.state)).toBeNull();
    expect(store.consume('never-issued')).toBeNull();

    const expiredStore = new InMemoryLoginStore();
    const stale = client.createLoginFlow(Date.now() - 600_001);
    expiredStore.add(stale);
    expect(expiredStore.consume(stale.state)).toBeNull();
  });
});
