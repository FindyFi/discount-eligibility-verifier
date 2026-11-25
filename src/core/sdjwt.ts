/**
 * SD-JWT parsing and disclosure processing (RFC 9901 / draft-ietf-oauth-selective-disclosure-jwt).
 * Signature and key binding checks live elsewhere; this module only handles structure.
 */
import { b64urlDecode, b64urlJson, hashB64url, isObject, type Json } from './util.js';

export interface Disclosure {
  encoded: string;
  digest: string;
  salt: string;
  /** Claim name for object properties; undefined for array elements. */
  name?: string;
  value: unknown;
}

export interface ParsedSdJwt {
  issuerJwt: string;
  header: Json;
  payload: Json;
  disclosures: Disclosure[];
  kbJwt?: string;
  /** The `<issuer-jwt>~<d1>~...~<dn>~` string that the KB-JWT's sd_hash covers. */
  presentedSdJwt: string;
}

export class SdJwtFormatError extends Error {
  override name = 'SdJwtFormatError';
}

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

export function parseSdJwt(input: string): ParsedSdJwt {
  // Lenient on transport artefacts: surrounding whitespace, embedded line breaks, quotes.
  const compact = input.trim().replace(/^"|"$/g, '').replace(/\s+/g, '');
  const parts = compact.split('~');
  const issuerJwt = parts[0] ?? '';
  if (!JWT_RE.test(issuerJwt)) throw new SdJwtFormatError('Issuer-signed JWT is not a compact JWS');

  let rest = parts.slice(1);
  let kbJwt: string | undefined;
  const last = rest[rest.length - 1];
  if (last && JWT_RE.test(last)) {
    kbJwt = last;
    rest = rest.slice(0, -1);
  }
  // Empty segments: the canonical trailing "~" and accidental doubled separators.
  const encodedDisclosures = rest.filter((d) => d.length > 0);

  let header: Json;
  let payload: Json;
  try {
    [header, payload] = issuerJwt.split('.').slice(0, 2).map((p) => b64urlJson(p)) as [Json, Json];
  } catch {
    throw new SdJwtFormatError('Issuer-signed JWT header or payload is not valid base64url JSON');
  }
  if (!isObject(payload)) throw new SdJwtFormatError('Issuer-signed JWT payload is not a JSON object');

  const sdAlg = typeof payload._sd_alg === 'string' ? payload._sd_alg : 'sha-256';
  const disclosures = encodedDisclosures.map((encoded) => decodeDisclosure(encoded, sdAlg));

  const presentedSdJwt = [issuerJwt, ...encodedDisclosures].join('~') + '~';
  return { issuerJwt, header, payload, disclosures, kbJwt, presentedSdJwt };
}

function decodeDisclosure(encoded: string, sdAlg: string): Disclosure {
  let arr: unknown;
  try {
    arr = JSON.parse(b64urlDecode(encoded).toString('utf8'));
  } catch {
    throw new SdJwtFormatError('Disclosure is not valid base64url JSON');
  }
  if (!Array.isArray(arr) || (arr.length !== 2 && arr.length !== 3) || typeof arr[0] !== 'string') {
    throw new SdJwtFormatError('Disclosure must be a JSON array of 2 or 3 elements starting with a salt string');
  }
  let digest: string;
  try {
    digest = hashB64url(sdAlg, encoded);
  } catch (e) {
    throw new SdJwtFormatError((e as Error).message);
  }
  if (arr.length === 3) {
    if (typeof arr[1] !== 'string') throw new SdJwtFormatError('Disclosure claim name must be a string');
    return { encoded, digest, salt: arr[0], name: arr[1], value: arr[2] };
  }
  return { encoded, digest, salt: arr[0], value: arr[1] };
}

/**
 * Rebuilds the processed claim set from the payload and the presented disclosures.
 * Enforces the security-relevant rules strictly: every disclosure must be referenced exactly once,
 * digests must be unique, and disclosures must not overwrite plain claims or use reserved names.
 */
export function reconstructClaims(parsed: ParsedSdJwt): { claims: Json; disclosedPaths: string[][] } {
  const byDigest = new Map<string, Disclosure>();
  for (const d of parsed.disclosures) {
    if (byDigest.has(d.digest)) throw new SdJwtFormatError('Duplicate disclosure');
    byDigest.set(d.digest, d);
  }
  const seenDigests = new Set<string>();
  const used = new Set<string>();
  const disclosedPaths: string[][] = [];

  const claimDigest = (digest: unknown): Disclosure | undefined => {
    if (typeof digest !== 'string') throw new SdJwtFormatError('Digest values must be strings');
    if (seenDigests.has(digest)) throw new SdJwtFormatError('Digest appears more than once in the SD-JWT');
    seenDigests.add(digest);
    const d = byDigest.get(digest);
    if (d) used.add(digest);
    return d;
  };

  const walk = (node: unknown, path: string[]): unknown => {
    if (Array.isArray(node)) {
      const out: unknown[] = [];
      node.forEach((el) => {
        if (isObject(el) && Object.keys(el).length === 1 && '...' in el) {
          const d = claimDigest(el['...']);
          if (!d) return; // undisclosed array element: drop
          if (d.name !== undefined) throw new SdJwtFormatError('Array element disclosure must have 2 elements');
          const elPath = [...path, String(out.length)];
          disclosedPaths.push(elPath);
          out.push(walk(d.value, elPath));
        } else {
          out.push(walk(el, [...path, String(out.length)]));
        }
      });
      return out;
    }
    if (!isObject(node)) return node;

    const out: Json = {};
    for (const [k, v] of Object.entries(node)) {
      if (k === '_sd' || k === '_sd_alg') continue;
      out[k] = walk(v, [...path, k]);
    }
    const sd = node._sd;
    if (sd !== undefined) {
      if (!Array.isArray(sd)) throw new SdJwtFormatError('_sd must be an array');
      for (const digest of sd) {
        const d = claimDigest(digest);
        if (!d) continue; // decoy or undisclosed
        if (d.name === undefined) throw new SdJwtFormatError('Object property disclosure must have 3 elements');
        if (d.name === '_sd' || d.name === '...') throw new SdJwtFormatError(`Disclosure uses reserved claim name ${d.name}`);
        if (d.name in out) throw new SdJwtFormatError(`Disclosure for "${d.name}" collides with an existing claim`);
        disclosedPaths.push([...path, d.name]);
        out[d.name] = walk(d.value, [...path, d.name]);
      }
    }
    return out;
  };

  const claims = walk(parsed.payload, []) as Json;
  if (used.size !== byDigest.size) throw new SdJwtFormatError('Presentation contains a disclosure that the credential does not reference');
  return { claims, disclosedPaths };
}
