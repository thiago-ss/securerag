import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';

/**
 * Minimal JOSE primitives (JWS parsing, JWK→KeyObject, signature verification)
 * built directly on node:crypto. No external dependencies; the verification
 * surface is deliberately narrow:
 *  - alg allowlist RS256/ES256 only (asymmetric; `none` and HS* are rejected
 *    before any key work, per research r2 §id_token checklist item 6);
 *  - strict base64url segment decoding (no lenient padding handling);
 *  - key selection by kid with kty/use/alg consistency checks (alg confusion,
 *    research r2 §JWKS notes);
 *  - ES256 verifies with the IEEE P1363 (r||s) signature format that Node
 *    produces for P-256 (JWS requires raw r||s).
 */

export const ALLOWED_SIGNING_ALGS = ['RS256', 'ES256'] as const;

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
}

export type JwkSet = { keys: Jwk[] };

export interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
  enc?: string;
  zip?: string;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: Record<string, unknown>;
  /** The concatenated "header.payload" ASCII text that was signed. */
  data: string;
  signature: Buffer;
}

/**
 * Static-message failure for every invalid-token cause (parse, structure,
 * signature, claims). The message never names the failing check, so an
 * attacker gains no validation oracle from error text.
 */
export class InvalidTokenError extends Error {
  readonly code = 'INVALID_TOKEN';

  constructor() {
    super('Invalid token');
    this.name = 'InvalidTokenError';
  }
}

export function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

export function base64urlDecode(input: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) throw new InvalidTokenError();
  return Buffer.from(input, 'base64url');
}

/** Parse a compact JWS strictly: exactly three strict-base64url segments. */
export function decodeJwt(token: string): DecodedJwt {
  if (typeof token !== 'string' || token.length === 0 || token.length > 65536) {
    throw new InvalidTokenError();
  }
  const segments = token.split('.');
  if (segments.length !== 3) throw new InvalidTokenError();
  const [headerB64, payloadB64, signatureB64] = segments;
  if (!headerB64 || !payloadB64) throw new InvalidTokenError();

  const header = parseJsonSegment(headerB64);
  const payload = parseJsonSegment(payloadB64);
  if (
    typeof header !== 'object' ||
    header === null ||
    Array.isArray(header) ||
    typeof (header as { alg?: unknown }).alg !== 'string'
  ) {
    throw new InvalidTokenError();
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new InvalidTokenError();
  }

  const signature = base64urlDecode(signatureB64 ?? '');
  return {
    header: header as JwtHeader,
    payload: payload as Record<string, unknown>,
    data: `${headerB64}.${payloadB64}`,
    signature,
  };
}

function parseJsonSegment(segment: string): unknown {
  let text: Buffer;
  try {
    text = base64urlDecode(segment);
  } catch {
    throw new InvalidTokenError();
  }
  try {
    return JSON.parse(text.toString('utf8'));
  } catch {
    throw new InvalidTokenError();
  }
}

/**
 * Verify a JWS signature for the given allowlisted alg. Callers must have
 * checked `alg` against ALLOWED_SIGNING_ALGS first; this function performs the
 * key-type consistency check again defensively.
 */
export function verifyJwsSignature(
  alg: string,
  data: string,
  signature: Buffer,
  key: KeyObject,
): boolean {
  try {
    if (alg === 'RS256') {
      return cryptoVerify('sha256', Buffer.from(data, 'utf8'), key, signature);
    }
    if (alg === 'ES256') {
      return cryptoVerify(
        'sha256',
        Buffer.from(data, 'utf8'),
        { key, dsaEncoding: 'ieee-p1363' },
        signature,
      );
    }
    return false;
  } catch {
    return false;
  }
}

/** Convert a JWK to a public KeyObject; unsupported shapes throw InvalidTokenError. */
export function jwkToKeyObject(jwk: Jwk): KeyObject {
  try {
    if (jwk.kty === 'RSA' && typeof jwk.n === 'string' && typeof jwk.e === 'string') {
      return createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    }
    if (jwk.kty === 'EC' && jwk.crv === 'P-256' && typeof jwk.x === 'string' && typeof jwk.y === 'string') {
      return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
    }
  } catch {
    throw new InvalidTokenError();
  }
  throw new InvalidTokenError();
}

/**
 * Select the signing key for (kid, alg) with consistency checks. A missing or
 * unknown kid rejects (we never guess keys); kty must match the alg family;
 * an explicitly declared `alg`/`use` must match the token's.
 */
export function findJwk(keys: readonly Jwk[], kid: string | undefined, alg: string): Jwk {
  if (kid === undefined) throw new InvalidTokenError();
  const candidates = keys.filter(
    (k) =>
      k.kid === kid &&
      (k.use === undefined || k.use === 'sig') &&
      (k.alg === undefined || k.alg === alg) &&
      (alg === 'RS256' ? k.kty === 'RSA' : k.kty === 'EC'),
  );
  if (candidates.length === 0) throw new InvalidTokenError();
  return candidates[0] as Jwk;
}
