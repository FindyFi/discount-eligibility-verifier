/** Minimal SD-JWT VC issuer for tests. */
import { SignJWT, type CryptoKey, type JWK } from 'jose';
import { createHash, randomBytes } from 'node:crypto';

export interface IssueOptions {
  key: CryptoKey;
  kid: string;
  /** Claims always visible in the payload. */
  claims: Record<string, unknown>;
  /** Top-level claims issued as selectively disclosable. */
  sdClaims?: Record<string, unknown>;
  holderJwk?: JWK;
  typ?: string;
  /** Extra digests to add to _sd (decoys or digests of disclosures that are not included). */
  extraDigests?: string[];
}

export function makeDisclosure(name: string, value: unknown): { encoded: string; digest: string } {
  const encoded = Buffer.from(JSON.stringify([randomBytes(16).toString('base64url'), name, value])).toString('base64url');
  return { encoded, digest: createHash('sha256').update(encoded).digest('base64url') };
}

export async function issueSdJwt(opts: IssueOptions): Promise<string> {
  const disclosures = Object.entries(opts.sdClaims ?? {}).map(([k, v]) => makeDisclosure(k, v));
  const payload: Record<string, unknown> = {
    ...opts.claims,
    _sd_alg: 'sha-256',
    _sd: [...disclosures.map((d) => d.digest), ...(opts.extraDigests ?? [])].sort(),
    ...(opts.holderJwk ? { cnf: { jwk: opts.holderJwk } } : {}),
  };
  const jwt = await new SignJWT(payload).setProtectedHeader({ alg: 'ES256', kid: opts.kid, typ: opts.typ ?? 'dc+sd-jwt' }).sign(opts.key);
  return [jwt, ...disclosures.map((d) => d.encoded)].join('~') + '~';
}
