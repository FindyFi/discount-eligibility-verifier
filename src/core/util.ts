import { createHash } from 'node:crypto';

export type Json = Record<string, unknown>;
export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

export function b64urlDecode(s: string): Buffer {
  // Lenient: tolerate padding, whitespace and standard base64 alphabet.
  const clean = s.replace(/\s+/g, '').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  return Buffer.from(clean, 'base64url');
}

export function b64urlJson<T = Json>(s: string): T {
  return JSON.parse(b64urlDecode(s).toString('utf8')) as T;
}

const HASH_ALGS: Record<string, string> = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' };

export function hashB64url(alg: string, input: string): string {
  const nodeAlg = HASH_ALGS[alg.toLowerCase()];
  if (!nodeAlg) throw new Error(`Unsupported hash algorithm ${alg}`);
  return createHash(nodeAlg).update(input, 'ascii').digest('base64url');
}

export function isObject(v: unknown): v is Json {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function isHttpsUrl(s: unknown): s is string {
  if (typeof s !== 'string') return false;
  try {
    return new URL(s).protocol === 'https:';
  } catch {
    return false;
  }
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Decode the protected header and payload of a compact JWS without verifying it. */
export function decodeJwtUnverified(jwt: string): { header: Json; payload: Json } {
  const parts = jwt.trim().split('.');
  if (parts.length !== 3) throw new Error('Not a compact JWS (expected three dot-separated parts)');
  return { header: b64urlJson(parts[0]!), payload: b64urlJson(parts[1]!) };
}

/** GET with timeout and a single retry on network errors or 5xx responses. */
export async function fetchText(
  fetcher: Fetcher,
  url: string,
  opts: { accept?: string; timeoutMs?: number } = {},
): Promise<{ status: number; body: string; contentType: string }> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetcher(url, {
        headers: opts.accept ? { accept: opts.accept } : {},
        signal: AbortSignal.timeout(opts.timeoutMs ?? 8000),
        redirect: 'follow',
      });
      const body = await res.text();
      if (res.status >= 500 && attempt === 0) {
        lastErr = new Error(`HTTP ${res.status}`);
        continue;
      }
      return { status: res.status, body, contentType: res.headers.get('content-type') ?? '' };
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`GET ${url} failed: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);
}

/** An error caused by infrastructure (network, unavailable endpoints) rather than an invalid credential. */
export class TransientError extends Error {
  override name = 'TransientError';
}

/**
 * Verifies a compact JWS against a JWK Set. Keys are matched by `kid`; if no key carries the
 * header's kid, keys without a kid are tried (registrations often omit it). Encryption keys and
 * keys for other algorithms are skipped. The cryptographic check is never relaxed.
 */
export async function verifyWithJwks(
  jws: string,
  jwks: { keys?: unknown[] },
  algorithms: string[],
): Promise<{ payload: Uint8Array; protectedHeader: Record<string, unknown>; key: Record<string, unknown> }> {
  const { compactVerify, decodeProtectedHeader, importJWK } = await import('jose');
  const header = decodeProtectedHeader(jws);
  const alg = header.alg;
  if (!alg || !algorithms.includes(alg)) throw new Error(`Algorithm "${String(alg)}" is not allowed`);
  const keys = (Array.isArray(jwks?.keys) ? jwks.keys : []).filter(
    (k): k is Record<string, unknown> => isObject(k) && k.use !== 'enc' && (k.alg === undefined || k.alg === alg),
  );
  const byKid = header.kid !== undefined ? keys.filter((k) => k.kid === header.kid) : keys;
  const candidates = byKid.length ? byKid : keys.filter((k) => k.kid === undefined);
  if (candidates.length === 0) throw new Error(`No key${header.kid ? ` with kid "${header.kid}"` : ''} in the key set`);
  let lastErr: unknown;
  for (const jwk of candidates) {
    try {
      const res = await compactVerify(jws, await importJWK(jwk, alg), { algorithms });
      return { payload: res.payload, protectedHeader: res.protectedHeader as Record<string, unknown>, key: jwk };
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error(`signature verification failed${lastErr instanceof Error ? `: ${lastErr.message}` : ''}`);
}
