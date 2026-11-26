/**
 * The verifier as an OpenID Federation leaf entity: publishes its entity configuration and signs
 * OpenID4VP request objects for the `openid_federation` client identifier prefix.
 *
 * Specification gaps and the choices made here:
 * - OpenID4VP 1.0 does not name the entity type for verifier metadata. The same metadata is published
 *   under each type in `metadataEntityTypes` (default: openid_credential_verifier and openid_relying_party).
 * - Request objects are always signed, with a key published in that metadata's `jwks`. The federation
 *   entity key only signs the entity configuration, as OpenID Federation recommends.
 * - The verifier's trust chain is sent in the `trust_chain` JWS header so wallets need not resolve it.
 */
import { SignJWT, calculateJwkThumbprint, importJWK, type CryptoKey, type JWK } from 'jose';
import type { FederationResolver, TrustChainResult } from '../core/index.js';
import type { FederationConfig, ServiceConfig } from './config.js';
import { clientMetadata, responseUri, SIGNING_ALGS } from './oid4vp.js';

export const SELF_ISSUED_AUDIENCE = 'https://self-issued.me/v2';

export interface LoadedKey {
  key: CryptoKey;
  publicJwk: JWK;
  alg: string;
}

export async function loadKey(privateJwk: JWK): Promise<LoadedKey> {
  const alg = privateJwk.alg ?? (privateJwk.kty === 'OKP' ? 'EdDSA' : 'ES256');
  const key = (await importJWK(privateJwk, alg)) as CryptoKey;
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = privateJwk;
  const publicJwk: JWK = { ...pub, alg, use: 'sig' };
  publicJwk.kid ??= await calculateJwkThumbprint(publicJwk);
  return { key, publicJwk, alg };
}

export class VerifierEntity {
  private cachedConfiguration?: { jwt: string; refreshAfter: number };
  private constructor(
    private readonly config: ServiceConfig,
    private readonly fed: FederationConfig,
    private readonly federationKey: LoadedKey,
    private readonly requestKey: LoadedKey,
    private readonly resolver: FederationResolver,
    private readonly log: (msg: string) => void,
  ) {}

  static async create(config: ServiceConfig, resolver: FederationResolver, log: (msg: string) => void = () => {}): Promise<VerifierEntity> {
    const fed = config.federation;
    if (!fed) throw new Error('federation is not configured');
    return new VerifierEntity(config, fed, await loadKey(fed.federationKey), await loadKey(fed.requestSigningKey), resolver, log);
  }

  get entityId(): string {
    return this.fed.entityId;
  }

  get clientId(): string {
    return `openid_federation:${this.fed.entityId}`;
  }

  get federationPublicJwk(): JWK {
    return this.federationKey.publicJwk;
  }

  /** Verifier metadata, published under each configured entity type. */
  verifierMetadata(): Record<string, unknown> {
    const name = this.config.oid4vp.verifierName ?? this.fed.organizationName;
    return {
      ...clientMetadata(this.config),
      ...(name ? { client_name: name } : {}),
      ...(this.fed.logoUri ? { logo_uri: this.fed.logoUri } : {}),
      ...(this.fed.policyUri ? { policy_uri: this.fed.policyUri } : {}),
      jwks: { keys: [this.requestKey.publicJwk] },
      response_uris: [responseUri(this.config)],
      redirect_uris: [responseUri(this.config)],
      response_types: ['vp_token'],
      request_object_signing_alg: this.requestKey.alg,
      authorization_signed_response_alg_values_supported: SIGNING_ALGS,
    };
  }

  /** The signed entity configuration served at /.well-known/openid-federation. */
  async entityConfiguration(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (this.cachedConfiguration && this.cachedConfiguration.refreshAfter > now) return this.cachedConfiguration.jwt;
    const ttl = this.fed.entityConfigurationTtlSeconds;
    const verifierMd = this.verifierMetadata();
    const metadata: Record<string, unknown> = {
      federation_entity: compact({
        organization_name: this.fed.organizationName,
        display_name: this.config.oid4vp.verifierName,
        logo_uri: this.fed.logoUri,
        homepage_uri: this.fed.homepageUri,
        policy_uri: this.fed.policyUri,
        contacts: this.fed.contacts,
      }),
    };
    for (const type of this.fed.metadataEntityTypes) metadata[type] = verifierMd;
    const jwt = await new SignJWT({
      iss: this.fed.entityId,
      sub: this.fed.entityId,
      iat: now,
      exp: now + ttl,
      jwks: { keys: [this.federationKey.publicJwk] },
      authority_hints: this.fed.authorityHints,
      metadata,
    })
      .setProtectedHeader({ alg: this.federationKey.alg, kid: this.federationKey.publicJwk.kid!, typ: 'entity-statement+jwt' })
      .sign(this.federationKey.key);
    // Re-sign well before expiry so cached copies never go stale.
    this.cachedConfiguration = { jwt, refreshAfter: now + Math.floor(ttl / 2) };
    return jwt;
  }

  /** Resolves this verifier's own trust chain (also validates the registration at the trust anchor). */
  selfCheck(): Promise<TrustChainResult> {
    return this.resolver.resolve(this.fed.entityId);
  }

  async trustChain(): Promise<string[] | undefined> {
    if (!this.fed.includeTrustChain) return undefined;
    const chain = await this.selfCheck();
    if (!chain.ok) {
      this.log(`own trust chain unavailable, sending request without trust_chain: ${chain.errors.join('; ')}`);
      return undefined;
    }
    return chain.chain.map((s) => s.jwt!).filter(Boolean);
  }

  /** Signs an OpenID4VP request object. */
  async signRequestObject(params: Record<string, unknown>, lifetimeSeconds = 300): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const trustChain = await this.trustChain();
    return new SignJWT({ ...params, client_id: this.clientId, iss: this.clientId, aud: SELF_ISSUED_AUDIENCE, iat: now, exp: now + lifetimeSeconds })
      .setProtectedHeader({
        alg: this.requestKey.alg,
        kid: this.requestKey.publicJwk.kid!,
        typ: 'oauth-authz-req+jwt',
        ...(trustChain ? { trust_chain: trustChain } : {}),
      })
      .sign(this.requestKey.key);
  }
}

function compact(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== ''));
}
