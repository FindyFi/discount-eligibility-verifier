/**
 * Key Binding JWT verification: proves the presenter controls the key in the credential's `cnf`
 * and that the presentation was made for this verifier (aud) and this request (nonce).
 */
import { compactVerify, importJWK, type JWK } from 'jose';
import { hashB64url, isObject, nowSeconds, type Json } from './util.js';

export interface KeyBindingExpectations {
  nonce: string;
  /** Accepted audience values, e.g. ["redirect_uri:https://verifier/response"] or ["origin:https://verifier"]. */
  audience: string[];
  maxAgeSeconds?: number;
  clockSkewSeconds?: number;
  allowedAlgs: string[];
}

export async function verifyKeyBinding(
  kbJwt: string,
  cnf: unknown,
  presentedSdJwt: string,
  sdAlg: string,
  exp: KeyBindingExpectations,
): Promise<void> {
  if (!isObject(cnf) || !isObject(cnf.jwk)) throw new Error('Credential has no cnf.jwk holder key');
  const header = JSON.parse(Buffer.from(kbJwt.split('.')[0]!, 'base64url').toString('utf8')) as Json;
  if (header.typ !== 'kb+jwt') throw new Error(`KB-JWT typ is "${String(header.typ)}", expected "kb+jwt"`);
  if (typeof header.alg !== 'string' || !exp.allowedAlgs.includes(header.alg)) throw new Error(`KB-JWT alg "${String(header.alg)}" is not allowed`);

  let payload: Json;
  try {
    const key = await importJWK(cnf.jwk as JWK, header.alg);
    const res = await compactVerify(kbJwt, key, { algorithms: exp.allowedAlgs });
    payload = JSON.parse(new TextDecoder().decode(res.payload)) as Json;
  } catch (e) {
    throw new Error(`KB-JWT signature does not verify with the holder key: ${(e as Error).message}`);
  }

  if (payload.nonce !== exp.nonce) throw new Error('KB-JWT nonce does not match the request');
  if (typeof payload.aud !== 'string' || !exp.audience.includes(payload.aud)) {
    throw new Error(`KB-JWT audience "${String(payload.aud)}" does not match this verifier`);
  }
  const skew = exp.clockSkewSeconds ?? 60;
  const now = nowSeconds();
  if (typeof payload.iat !== 'number') throw new Error('KB-JWT has no iat');
  if (payload.iat - skew > now) throw new Error('KB-JWT is issued in the future');
  if (now - payload.iat > (exp.maxAgeSeconds ?? 300) + skew) throw new Error('KB-JWT is too old');
  if (payload.sd_hash !== hashB64url(sdAlg, presentedSdJwt)) throw new Error('KB-JWT sd_hash does not match the presented SD-JWT');
}
