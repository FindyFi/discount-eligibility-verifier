import { describe, expect, it } from 'vitest';
import { parseSdJwt, reconstructClaims } from '../src/core/sdjwt.js';
import { issueSdJwt, makeDisclosure } from './helpers/issuer.js';
import { newKey } from './helpers/federation.js';

const k = await newKey('issuer');
const base = await issueSdJwt({ key: k.privateKey, kid: 'issuer', claims: { iss: 'https://i.example', vct: 'urn:t' }, sdClaims: { a: 1, b: 'two' } });

describe('parseSdJwt', () => {
  it('parses an issued SD-JWT with disclosures', () => {
    const p = parseSdJwt(base);
    expect(p.disclosures.map((d) => d.name).sort()).toEqual(['a', 'b']);
    expect(p.kbJwt).toBeUndefined();
    expect(p.presentedSdJwt).toBe(base);
  });

  it('tolerates whitespace, line breaks, quotes and a missing trailing tilde', () => {
    const messy = `  "${base.slice(0, 40)}\n${base.slice(40, -1)}"  `;
    const p = parseSdJwt(messy);
    expect(p.disclosures).toHaveLength(2);
    expect(p.presentedSdJwt).toBe(base);
  });

  it('separates a trailing KB-JWT', () => {
    const p = parseSdJwt(base + 'eyJhbGciOiJFUzI1NiJ9.eyJ4IjoxfQ.c2ln');
    expect(p.kbJwt).toBe('eyJhbGciOiJFUzI1NiJ9.eyJ4IjoxfQ.c2ln');
    expect(p.presentedSdJwt).toBe(base);
  });

  it('rejects garbage', () => {
    expect(() => parseSdJwt('hello')).toThrow(/compact JWS/);
    expect(() => parseSdJwt(base.split('~')[0] + '~bm90IGpzb24~')).toThrow(/Disclosure/);
  });
});

describe('reconstructClaims', () => {
  it('reveals only presented disclosures', () => {
    const [jwt, d1] = base.split('~');
    const { claims } = reconstructClaims(parseSdJwt(`${jwt}~${d1}~`));
    expect(Object.keys(claims).filter((c) => c === 'a' || c === 'b')).toHaveLength(1);
    expect(claims._sd).toBeUndefined();
    expect(claims._sd_alg).toBeUndefined();
  });

  it('rejects a disclosure that the credential does not reference', () => {
    const forged = makeDisclosure('a', 999).encoded;
    const [jwt] = base.split('~');
    expect(() => reconstructClaims(parseSdJwt(`${jwt}~${forged}~`))).toThrow(/does not reference/);
  });

  it('rejects duplicate disclosures', () => {
    const [jwt, d1] = base.split('~');
    expect(() => reconstructClaims(parseSdJwt(`${jwt}~${d1}~${d1}~`))).toThrow(/Duplicate/);
  });

  it('rejects a disclosure that overwrites a plain claim', async () => {
    const d = makeDisclosure('vct', 'urn:evil');
    const sd = await issueSdJwt({ key: k.privateKey, kid: 'issuer', claims: { vct: 'urn:t' }, extraDigests: [d.digest] });
    expect(() => reconstructClaims(parseSdJwt(sd + d.encoded + '~'))).toThrow(/collides/);
  });

  it('handles array element disclosures', async () => {
    const el = Buffer.from(JSON.stringify(['salt', 'x'])).toString('base64url');
    const { createHash } = await import('node:crypto');
    const digest = createHash('sha256').update(el).digest('base64url');
    const sd = await issueSdJwt({ key: k.privateKey, kid: 'issuer', claims: { list: [{ '...': digest }, 'y', { '...': 'undisclosed' }] } });
    const { claims } = reconstructClaims(parseSdJwt(sd + el + '~'));
    expect(claims.list).toEqual(['x', 'y']);
  });
});
