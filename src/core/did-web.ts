/**
 * did:web resolution, for issuers the operator has chosen to trust directly (without OpenID Federation).
 * https://w3c-ccg.github.io/did-method-web/
 */
import type { JSONWebKeySet } from 'jose';
import { fetchText, isObject, type Fetcher, type Json } from './util.js';

/** Maps did:web:host[:path…] to the URL of its DID document. Throws on anything that is not a well-formed did:web. */
export function didWebUrl(did: string): string {
  const m = /^did:web:([^#?\s]+)$/.exec(did);
  if (!m) throw new Error(`${JSON.stringify(did)} is not a did:web identifier`);
  const [host, ...path] = m[1]!.split(':').map((s) => decodeURIComponent(s));
  if (!host || path.some((s) => !s || /[/?#]/.test(s))) throw new Error(`${did} has an invalid method-specific identifier`);
  const url = new URL(`https://${host}`);
  if (url.pathname !== '/' || url.search || url.hash || url.username) throw new Error(`${did} has an invalid host`);
  return path.length ? `${url.origin}/${path.map(encodeURIComponent).join('/')}/did.json` : `${url.origin}/.well-known/did.json`;
}

export class DidResolutionError extends Error {
  constructor(
    message: string,
    /** Network or server trouble: retrying may help. */
    readonly transient = false,
  ) {
    super(message);
  }
}

export async function resolveDidWeb(did: string, fetcher: Fetcher): Promise<Json> {
  let url: string;
  try {
    url = didWebUrl(did);
  } catch (e) {
    throw new DidResolutionError((e as Error).message);
  }
  let res;
  try {
    res = await fetchText(fetcher, url, { accept: 'application/did+json, application/json' });
  } catch (e) {
    throw new DidResolutionError((e as Error).message, true);
  }
  if (res.status >= 500) throw new DidResolutionError(`GET ${url} returned HTTP ${res.status}`, true);
  if (res.status !== 200) throw new DidResolutionError(`GET ${url} returned HTTP ${res.status}`);
  let doc: unknown;
  try {
    doc = JSON.parse(res.body);
  } catch {
    throw new DidResolutionError(`${url} is not JSON`);
  }
  if (!isObject(doc) || doc.id !== did) throw new DidResolutionError(`DID document at ${url} does not have id ${did}`);
  return doc;
}

/**
 * Public signing keys of a DID document. Only keys listed under assertionMethod count when that property exists.
 * Each key is listed under its full DID URL and under its fragment, since SD-JWT VC `kid` headers use either.
 */
export function didDocumentKeys(doc: Json): JSONWebKeySet {
  const did = String(doc.id);
  const methods = (Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []).filter(isObject);
  const absolute = (id: string) => (id.startsWith('#') ? did + id : id);
  const allowed = Array.isArray(doc.assertionMethod)
    ? new Set(doc.assertionMethod.map((m) => (typeof m === 'string' ? absolute(m) : isObject(m) ? absolute(String(m.id)) : '')))
    : undefined;
  const keys: Record<string, unknown>[] = [];
  for (const vm of methods) {
    if (typeof vm.id !== 'string' || !isObject(vm.publicKeyJwk)) continue;
    const id = absolute(vm.id);
    if (allowed && !allowed.has(id)) continue;
    const { d: _d, ...jwk } = vm.publicKeyJwk;
    const fragment = id.includes('#') ? id.slice(id.indexOf('#') + 1) : undefined;
    for (const kid of [id, ...(fragment ? [`#${fragment}`, fragment] : [])]) keys.push({ ...jwk, kid });
  }
  return { keys: keys as JSONWebKeySet['keys'] };
}
