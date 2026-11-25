/**
 * Finds the keys an issuer uses to sign credentials, anchored in its federation trust chain.
 */
import type { JSONWebKeySet } from 'jose';
import type { TrustChainResult } from './federation.js';
import { fetchText, isHttpsUrl, isObject, type Fetcher, type Json } from './util.js';

/** Entity types whose metadata may carry credential signing keys. */
const ISSUER_METADATA_TYPES = ['openid_credential_issuer', 'jwt_vc_issuer', 'vc_issuer'];

export interface IssuerKeyOptions {
  fetch?: Fetcher;
  /**
   * Also accept keys from `/.well-known/jwt-vc-issuer` of the (federation-trusted) issuer URL.
   * Weaker than keys inside the signed federation metadata: it relies on TLS alone.
   */
  allowJwtVcIssuerMetadata?: boolean;
}

export interface IssuerKeys {
  jwks: JSONWebKeySet;
  source: string;
}

export async function resolveIssuerKeys(chain: Extract<TrustChainResult, { ok: true }>, opts: IssuerKeyOptions = {}): Promise<IssuerKeys[]> {
  const fetcher = opts.fetch ?? ((u, i) => fetch(u, i));
  const found: IssuerKeys[] = [];

  for (const type of ISSUER_METADATA_TYPES) {
    const md = chain.metadata[type];
    if (!isObject(md)) continue;
    if (isJwks(md.jwks)) found.push({ jwks: md.jwks, source: `federation metadata ${type}.jwks` });
    if (isHttpsUrl(md.jwks_uri)) {
      const jwks = await getJwks(fetcher, md.jwks_uri).catch(() => undefined);
      if (jwks) found.push({ jwks, source: `federation metadata ${type}.jwks_uri` });
    }
  }

  if (opts.allowJwtVcIssuerMetadata) {
    const u = new URL(chain.entityId);
    const url = `${u.origin}/.well-known/jwt-vc-issuer${u.pathname.replace(/\/$/, '')}`;
    const res = await fetchText(fetcher, url, { accept: 'application/json' }).catch(() => undefined);
    if (res?.status === 200) {
      try {
        const md = JSON.parse(res.body) as Json;
        if (md.issuer === chain.entityId) {
          if (isJwks(md.jwks)) found.push({ jwks: md.jwks, source: 'jwt-vc-issuer metadata' });
          else if (isHttpsUrl(md.jwks_uri)) {
            const jwks = await getJwks(fetcher, md.jwks_uri).catch(() => undefined);
            if (jwks) found.push({ jwks, source: 'jwt-vc-issuer metadata jwks_uri' });
          }
        }
      } catch {
        /* ignore malformed optional metadata */
      }
    }
  }
  return found;
}

function isJwks(v: unknown): v is JSONWebKeySet {
  return isObject(v) && Array.isArray(v.keys);
}

async function getJwks(fetcher: Fetcher, url: string): Promise<JSONWebKeySet | undefined> {
  const res = await fetchText(fetcher, url, { accept: 'application/json, application/jwk-set+json' });
  if (res.status !== 200) return undefined;
  const parsed = JSON.parse(res.body) as unknown;
  return isJwks(parsed) ? parsed : undefined;
}
