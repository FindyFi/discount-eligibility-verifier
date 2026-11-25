/**
 * OpenID Federation 1.0 trust chain resolution (bottom-up, following authority_hints).
 *
 * Strict on everything that carries trust: entity identifiers are compared exactly,
 * every statement signature is verified, expiry is enforced, and there are no fallbacks
 * that bypass a missing link. Lenient on transport details (content types, whitespace).
 */
import type { JSONWebKeySet } from 'jose';
import { fetchText, isHttpsUrl, isObject, nowSeconds, TransientError, verifyWithJwks, type Fetcher, type Json } from './util.js';

export interface TrustAnchorConfig {
  entityId: string;
  /** Pinned federation keys of the trust anchor. If omitted, the anchor's self-signed entity configuration is trusted on first fetch (TLS-authenticated). */
  jwks?: JSONWebKeySet;
}

export interface FederationOptions {
  trustAnchors: TrustAnchorConfig[];
  fetch?: Fetcher;
  /** Maximum number of intermediates between leaf and trust anchor. */
  maxPathLength?: number;
  clockSkewSeconds?: number;
  /** Upper bound for caching a resolved chain, in seconds. */
  cacheTtlSeconds?: number;
  allowedAlgs?: string[];
}

export interface EntityStatement extends Json {
  /** The statement as fetched (compact JWS), e.g. for passing on as a trust_chain. */
  jwt?: string;
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  jwks?: JSONWebKeySet;
  authority_hints?: string[];
  metadata?: Record<string, Json>;
  metadata_policy?: Record<string, Record<string, Json>>;
  metadata_policy_crit?: string[];
}

export type TrustChainResult =
  | {
      ok: true;
      entityId: string;
      trustAnchor: string;
      /** [leaf entity configuration, subordinate statements..., trust anchor entity configuration] */
      chain: EntityStatement[];
      /** Leaf metadata after applying superior metadata and metadata policies. */
      metadata: Record<string, Json>;
      expiresAt: number;
    }
  | { ok: false; entityId: string; errors: string[]; transient: boolean };

const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';
const DEFAULT_ALGS = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA', 'RS256'];
const KNOWN_POLICY_OPERATORS = new Set(['value', 'add', 'default', 'one_of', 'subset_of', 'superset_of', 'essential']);

class ChainError extends Error {}

export class FederationResolver {
  private readonly fetcher: Fetcher;
  private readonly anchors: Map<string, TrustAnchorConfig>;
  private readonly cache = new Map<string, { result: TrustChainResult; until: number }>();
  private readonly skew: number;

  constructor(private readonly opts: FederationOptions) {
    this.fetcher = opts.fetch ?? ((url, init) => fetch(url, init));
    this.anchors = new Map(opts.trustAnchors.map((a) => [a.entityId, a]));
    this.skew = opts.clockSkewSeconds ?? 60;
  }

  isTrustAnchor(entityId: string): boolean {
    return this.anchors.has(entityId);
  }

  async resolve(entityId: string): Promise<TrustChainResult> {
    const cached = this.cache.get(entityId);
    if (cached && cached.until > nowSeconds()) return cached.result;

    const result = await this.resolveUncached(entityId);
    const ttl = this.opts.cacheTtlSeconds ?? 3600;
    // Successful chains are cached until the earliest statement expiry; failures briefly, so fixes in the registry show up quickly.
    const until = result.ok ? Math.min(result.expiresAt, nowSeconds() + ttl) : nowSeconds() + (result.transient ? 10 : 60);
    this.cache.set(entityId, { result, until });
    return result;
  }

  clearCache(): void {
    this.cache.clear();
  }

  private async resolveUncached(entityId: string): Promise<TrustChainResult> {
    const errors: string[] = [];
    let transient = false;
    if (!isHttpsUrl(entityId)) {
      return { ok: false, entityId, errors: [`Entity identifier must be an https URL, got "${entityId}"`], transient: false };
    }
    try {
      const leaf = await this.fetchEntityConfiguration(entityId);
      const paths = await this.climb(leaf, 0, new Set([entityId]), errors);
      if (paths) {
        const chain = [leaf, ...paths];
        const metadata = resolveMetadata(chain);
        const expiresAt = Math.min(...chain.map((s) => s.exp));
        return { ok: true, entityId, trustAnchor: chain[chain.length - 1]!.iss, chain, metadata, expiresAt };
      }
    } catch (e) {
      if (e instanceof TransientError) transient = true;
      errors.push((e as Error).message);
    }
    if (errors.length === 0) errors.push(`No trust chain from ${entityId} to a configured trust anchor`);
    return { ok: false, entityId, errors, transient };
  }

  /** Returns [subordinate statement, ..., trust anchor configuration] or undefined when no hint leads to an anchor. */
  private async climb(subject: EntityStatement, depth: number, visited: Set<string>, errors: string[]): Promise<EntityStatement[] | undefined> {
    const hints = Array.isArray(subject.authority_hints) ? subject.authority_hints.filter((h) => typeof h === 'string') : [];
    if (hints.length === 0) {
      errors.push(`${subject.sub}: entity configuration has no authority_hints`);
      return undefined;
    }
    // Prefer hints that are configured trust anchors.
    hints.sort((a, b) => Number(this.anchors.has(b)) - Number(this.anchors.has(a)));

    for (const hint of hints) {
      if (visited.has(hint)) continue;
      const isAnchor = this.anchors.has(hint);
      if (!isAnchor && depth >= (this.opts.maxPathLength ?? 3)) {
        errors.push(`${subject.sub}: path length limit reached at ${hint}`);
        continue;
      }
      try {
        const superior = await this.fetchEntityConfiguration(hint, this.anchors.get(hint)?.jwks);
        const statement = await this.fetchSubordinateStatement(superior, subject.sub);
        // The subject's self-signed configuration must verify with the keys its superior vouches for.
        if (!statement.jwks) throw new ChainError(`Subordinate statement from ${hint} about ${subject.sub} has no jwks`);
        await this.verifyStatement(subject.jwt!, statement.jwks, `entity configuration of ${subject.sub} against keys in ${hint}'s subordinate statement`);

        if (isAnchor) return [statement, superior];
        const rest = await this.climb(superior, depth + 1, new Set([...visited, hint]), errors);
        if (rest) return [statement, ...rest];
      } catch (e) {
        if (e instanceof TransientError) throw e;
        errors.push((e as Error).message);
      }
    }
    return undefined;
  }

  private async fetchEntityConfiguration(entityId: string, pinnedJwks?: JSONWebKeySet): Promise<EntityStatement> {
    const url = entityId.replace(/\/$/, '') + '/.well-known/openid-federation';
    const jwt = await this.fetchJwt(url, `entity configuration of ${entityId}`);
    const unverified = decodeStatement(jwt, `entity configuration of ${entityId}`);
    if (unverified.iss !== entityId || unverified.sub !== entityId) {
      throw new ChainError(`Entity configuration at ${url} has iss "${unverified.iss}" / sub "${unverified.sub}", expected exactly "${entityId}"`);
    }
    const keys = pinnedJwks ?? unverified.jwks;
    if (!keys) throw new ChainError(`Entity configuration of ${entityId} has no jwks`);
    const verified = await this.verifyStatement(jwt, keys, `entity configuration of ${entityId}`);
    return Object.assign(verified, { jwt });
  }

  private async fetchSubordinateStatement(superior: EntityStatement, sub: string): Promise<EntityStatement> {
    const fe = superior.metadata?.federation_entity;
    const endpoint = isObject(fe) ? fe.federation_fetch_endpoint : undefined;
    if (!isHttpsUrl(endpoint)) throw new ChainError(`${superior.sub} does not publish a federation_fetch_endpoint`);
    const url = new URL(endpoint);
    url.searchParams.set('sub', sub);
    const jwt = await this.fetchJwt(url.toString(), `subordinate statement from ${superior.sub} about ${sub}`);
    if (!superior.jwks) throw new ChainError(`${superior.sub} has no federation keys`);
    const st = await this.verifyStatement(jwt, superior.jwks, `subordinate statement from ${superior.sub} about ${sub}`);
    if (st.iss !== superior.sub || st.sub !== sub) {
      throw new ChainError(`Subordinate statement from ${superior.sub} has iss "${st.iss}" / sub "${st.sub}", expected "${superior.sub}" / "${sub}"`);
    }
    return Object.assign(st, { jwt });
  }

  private async fetchJwt(url: string, what: string): Promise<string> {
    const res = await fetchText(this.fetcher, url, { accept: 'application/entity-statement+jwt, application/jwt;q=0.9, */*;q=0.1' }).catch((e: Error) => {
      throw new TransientError(`Could not fetch ${what}: ${e.message}`);
    });
    if (res.status === 404) throw new ChainError(`${what} not found (HTTP 404 at ${url})`);
    if (res.status >= 500) throw new TransientError(`${what}: HTTP ${res.status} at ${url}`);
    if (res.status !== 200) throw new ChainError(`${what}: HTTP ${res.status} at ${url}`);
    const body = res.body.trim().replace(/^"|"$/g, '');
    if (body.split('.').length !== 3) throw new ChainError(`${what} at ${url} is not a JWT`);
    return body;
  }

  private async verifyStatement(jwt: string, jwks: JSONWebKeySet, what: string): Promise<EntityStatement> {
    let payload: Uint8Array;
    let header: { typ?: string; alg?: string };
    try {
      const res = await verifyWithJwks(jwt, jwks, this.opts.allowedAlgs ?? DEFAULT_ALGS);
      payload = res.payload;
      header = res.protectedHeader;
    } catch (e) {
      throw new ChainError(`Signature of ${what} does not verify: ${(e as Error).message}`);
    }
    if (header.typ !== undefined && header.typ.toLowerCase() !== ENTITY_STATEMENT_TYP) {
      throw new ChainError(`${what} has typ "${header.typ}", expected "${ENTITY_STATEMENT_TYP}"`);
    }
    const st = JSON.parse(new TextDecoder().decode(payload)) as EntityStatement;
    const now = nowSeconds();
    if (typeof st.exp !== 'number' || st.exp + this.skew < now) throw new ChainError(`${what} has expired`);
    if (typeof st.iat === 'number' && st.iat - this.skew > now) throw new ChainError(`${what} is issued in the future`);
    return st;
  }
}

function decodeStatement(jwt: string, what: string): EntityStatement {
  try {
    return JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8')) as EntityStatement;
  } catch {
    throw new ChainError(`${what} payload is not valid JSON`);
  }
}

/**
 * Leaf metadata, overridden by the immediate superior's `metadata`, then with each superior's
 * metadata_policy applied from the trust anchor downwards.
 *
 * Simplification: policies are applied level by level instead of first being merged into one
 * policy. The outcome is the same for non-conflicting policies; conflicts surface as errors
 * on application instead of at merge time.
 */
export function resolveMetadata(chain: EntityStatement[]): Record<string, Json> {
  const leaf = chain[0]!;
  const metadata: Record<string, Json> = structuredClone(leaf.metadata ?? {});
  const immediate = chain[1];
  if (immediate?.metadata) {
    for (const [type, params] of Object.entries(immediate.metadata)) {
      metadata[type] = { ...(metadata[type] ?? {}), ...params };
    }
  }
  const subordinates = chain.slice(1, -1).reverse(); // from the trust anchor's statement down
  for (const st of subordinates) {
    // Robustness: some registries publish metadata_policy_crit as {} instead of an array.
    const crit = new Set(Array.isArray(st.metadata_policy_crit) ? st.metadata_policy_crit.filter((x) => typeof x === 'string') : []);
    const policies = isObject(st.metadata_policy) ? st.metadata_policy : {};
    for (const [type, policy] of Object.entries(policies)) {
      if (!isObject(policy)) continue;
      if (!metadata[type]) continue;
      metadata[type] = applyPolicy(metadata[type]!, policy, crit, st.iss);
    }
  }
  return metadata;
}

function applyPolicy(md: Json, policy: Record<string, Json>, crit: Set<string>, from: string): Json {
  const out = { ...md };
  for (const [param, ops] of Object.entries(policy)) {
    if (!isObject(ops)) continue;
    for (const op of Object.keys(ops)) {
      if (!KNOWN_POLICY_OPERATORS.has(op) && crit.has(op)) throw new Error(`${from}: unsupported critical metadata policy operator "${op}"`);
    }
    let v = out[param];
    const asArray = (x: unknown) => (Array.isArray(x) ? x : x === undefined ? [] : [x]);
    if ('value' in ops) v = ops.value === null ? undefined : ops.value;
    if ('add' in ops && v !== undefined) v = [...new Set([...asArray(v), ...asArray(ops.add)])];
    else if ('add' in ops) v = asArray(ops.add);
    if ('default' in ops && v === undefined) v = ops.default;
    if ('one_of' in ops && v !== undefined && !asArray(ops.one_of).includes(v)) {
      throw new Error(`${from}: metadata parameter ${param} value is not one of the allowed values`);
    }
    if ('subset_of' in ops && v !== undefined) {
      const allowed = asArray(ops.subset_of);
      v = asArray(v).filter((x) => allowed.includes(x));
    }
    if ('superset_of' in ops && v !== undefined) {
      const have = asArray(v);
      if (!asArray(ops.superset_of).every((x) => have.includes(x))) throw new Error(`${from}: metadata parameter ${param} is missing required values`);
    }
    if (ops.essential === true && v === undefined) throw new Error(`${from}: essential metadata parameter ${param} is missing`);
    if (v === undefined) delete out[param];
    else out[param] = v;
  }
  return out;
}
