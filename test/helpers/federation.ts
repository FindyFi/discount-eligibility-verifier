/** In-memory OpenID Federation for tests: entities, subordinate statements and a fetch() over them. */
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import type { Fetcher } from '../../src/core/util.js';

export interface TestEntity {
  id: string;
  key: CryptoKey;
  jwk: JWK;
  authorityHints: string[];
  metadata: Record<string, Record<string, unknown>>;
  /** Overrides for the entity configuration payload (e.g. to omit fields or alter iss). */
  ecOverrides?: Record<string, unknown>;
}

export interface SubordinateOptions {
  metadata?: Record<string, Record<string, unknown>>;
  metadata_policy?: Record<string, Record<string, Record<string, unknown>>>;
  /** Keys the superior vouches for; defaults to the subordinate's real key. */
  jwks?: { keys: JWK[] };
  exp?: number;
  /** Extra claims, e.g. to reproduce non-conforming registries. */
  extra?: Record<string, unknown>;
}

export async function newKey(kid: string) {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'ES256', use: 'sig' };
  return { privateKey, publicKey, jwk };
}

export class TestFederation {
  readonly entities = new Map<string, TestEntity>();
  /** key: `${superior}|${sub}` */
  readonly subordinates = new Map<string, SubordinateOptions>();
  /** Extra static routes (e.g. jwt-vc-issuer metadata). */
  readonly routes = new Map<string, { status: number; body: string; contentType?: string }>();
  /** Every URL fetched, for assertions. */
  readonly requests: string[] = [];
  offline = false;

  async addEntity(id: string, opts: { authorityHints?: string[]; metadata?: TestEntity['metadata']; ecOverrides?: Record<string, unknown> } = {}): Promise<TestEntity> {
    const k = await newKey(`${new URL(id).hostname}-fed`);
    const isSuperior = (opts.authorityHints ?? []).length === 0 || opts.metadata?.federation_entity !== undefined;
    const metadata: TestEntity['metadata'] = { ...(opts.metadata ?? {}) };
    if (isSuperior) {
      metadata.federation_entity = { federation_fetch_endpoint: `${id}/fetch`, ...(metadata.federation_entity ?? {}) };
    }
    const e: TestEntity = { id, key: k.privateKey, jwk: k.jwk, authorityHints: opts.authorityHints ?? [], metadata, ecOverrides: opts.ecOverrides };
    this.entities.set(id, e);
    return e;
  }

  addSubordinate(superior: string, sub: string, opts: SubordinateOptions = {}) {
    this.subordinates.set(`${superior}|${sub}`, opts);
  }

  readonly fetch: Fetcher = async (url) => {
    this.requests.push(url);
    if (this.offline) throw new TypeError('fetch failed');
    const route = this.routes.get(url);
    if (route) return new Response(route.body, { status: route.status, headers: { 'content-type': route.contentType ?? 'application/json' } });

    const u = new URL(url);
    if (u.pathname.endsWith('/.well-known/openid-federation')) {
      const id = url.replace(/\/\.well-known\/openid-federation$/, '');
      const e = this.entities.get(id);
      if (!e) return new Response('not found', { status: 404 });
      const now = Math.floor(Date.now() / 1000);
      const payload: Record<string, unknown> = {
        iss: id,
        sub: id,
        iat: now,
        exp: now + 3600,
        jwks: { keys: [e.jwk] },
        metadata: e.metadata,
        ...(e.authorityHints.length ? { authority_hints: e.authorityHints } : {}),
        ...e.ecOverrides,
      };
      return jwtResponse(await sign(payload, e));
    }
    if (u.pathname.endsWith('/fetch')) {
      const superiorId = `${u.origin}${u.pathname.replace(/\/fetch$/, '')}`;
      const superior = this.entities.get(superiorId);
      const sub = u.searchParams.get('sub') ?? '';
      const opts = this.subordinates.get(`${superiorId}|${sub}`);
      const subEntity = this.entities.get(sub);
      if (!superior || !opts) return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
      const now = Math.floor(Date.now() / 1000);
      const payload: Record<string, unknown> = {
        iss: superiorId,
        sub,
        iat: now,
        exp: opts.exp ?? now + 3600,
        jwks: opts.jwks ?? { keys: subEntity ? [subEntity.jwk] : [] },
        ...(opts.metadata ? { metadata: opts.metadata } : {}),
        ...(opts.metadata_policy ? { metadata_policy: opts.metadata_policy } : {}),
        ...opts.extra,
      };
      return jwtResponse(await sign(payload, superior));
    }
    return new Response('not found', { status: 404 });
  };
}

async function sign(payload: Record<string, unknown>, e: TestEntity): Promise<string> {
  return new SignJWT(payload).setProtectedHeader({ alg: 'ES256', kid: e.jwk.kid!, typ: 'entity-statement+jwt' }).sign(e.key);
}

function jwtResponse(jwt: string): Response {
  return new Response(jwt, { status: 200, headers: { 'content-type': 'application/entity-statement+jwt' } });
}
