/**
 * Test-wallet helper: builds an SD-JWT presentation with selected disclosures and a KB-JWT.
 */
import { SignJWT, type CryptoKey, type JWK, importJWK } from 'jose';
import { createHash } from 'node:crypto';

export interface PresentOptions {
  /** Claim names to disclose (top-level). Others are withheld. */
  disclose: string[];
  holderKey: CryptoKey | JWK;
  nonce: string;
  aud: string;
  iat?: number;
  alg?: string;
}

export async function createPresentation(sdJwt: string, opts: PresentOptions): Promise<string> {
  const parts = sdJwt.trim().split('~').filter((p, i) => i === 0 || p.length > 0);
  const issuerJwt = parts[0]!;
  const sdAlg = (JSON.parse(Buffer.from(issuerJwt.split('.')[1]!, 'base64url').toString()) as { _sd_alg?: string })._sd_alg ?? 'sha-256';
  const selected = parts.slice(1).filter((d) => {
    const arr = JSON.parse(Buffer.from(d, 'base64url').toString()) as unknown[];
    return arr.length === 3 && opts.disclose.includes(arr[1] as string);
  });
  const presented = [issuerJwt, ...selected].join('~') + '~';
  const sdHash = createHash(sdAlg.replace('-', '')).update(presented, 'ascii').digest('base64url');
  const alg = opts.alg ?? 'ES256';
  const key = 'kty' in opts.holderKey ? await importJWK(opts.holderKey, alg) : opts.holderKey;
  const kb = await new SignJWT({ nonce: opts.nonce, aud: opts.aud, iat: opts.iat ?? Math.floor(Date.now() / 1000), sd_hash: sdHash })
    .setProtectedHeader({ alg, typ: 'kb+jwt' })
    .sign(key);
  return presented + kb;
}
