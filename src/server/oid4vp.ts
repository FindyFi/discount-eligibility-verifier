/**
 * OpenID for Verifiable Presentations 1.0: request construction and response parsing.
 */
import { claimsOfInterest, type CredentialTypePolicy } from '../core/index.js';
import type { ClientIdPrefix, ServiceConfig } from './config.js';
import type { Session } from './sessions.js';

export const SIGNING_ALGS = ['ES256', 'ES384', 'ES512', 'EdDSA'];

export function responseUri(config: ServiceConfig): string {
  return `${config.publicUrl}/oid4vp/response`;
}

export function clientId(config: ServiceConfig, prefix: ClientIdPrefix = config.oid4vp.clientIdPrefix): string {
  if (prefix === 'openid_federation') {
    if (!config.federation) throw new Error('openid_federation requires federation configuration');
    return `openid_federation:${config.federation.entityId}`;
  }
  return `redirect_uri:${responseUri(config)}`;
}

/**
 * Audiences a wallet may put in the KB-JWT for the wallet-link flows. OpenID4VP 1.0 requires the full
 * client_id including its prefix; the unprefixed form is accepted from pre-1.0 wallets.
 */
export function presentationAudiences(config: ServiceConfig, prefix: ClientIdPrefix = config.oid4vp.clientIdPrefix): string[] {
  const unprefixed = prefix === 'openid_federation' ? config.federation!.entityId : responseUri(config);
  return [clientId(config, prefix), unprefixed];
}

/** Audiences for the Digital Credentials API, where the browser vouches for the origin. */
export function originAudiences(origin: string): string[] {
  return [`origin:${origin}`, `web-origin:${origin}`, origin];
}

export function buildDcqlQuery(policies: CredentialTypePolicy[]) {
  const credentials = policies.map((p) => ({
    id: p.id,
    format: 'dc+sd-jwt',
    meta: { vct_values: p.vct },
    claims: claimsOfInterest(p).map((path) => ({ path: path.split('.') })),
  }));
  return credentials.length > 1
    ? { credentials, credential_sets: [{ options: credentials.map((c) => [c.id]), required: true }] }
    : { credentials };
}

export function clientMetadata(config: ServiceConfig) {
  return {
    vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': SIGNING_ALGS, 'kb-jwt_alg_values': SIGNING_ALGS } },
    ...(config.oid4vp.verifierName ? { client_name: config.oid4vp.verifierName } : {}),
  };
}

export function authorizationRequestParams(config: ServiceConfig, session: Session, policies: CredentialTypePolicy[]): Record<string, string> {
  return {
    client_id: clientId(config, session.clientIdPrefix),
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: responseUri(config),
    nonce: session.nonce,
    state: session.state,
    dcql_query: JSON.stringify(buildDcqlQuery(policies)),
    client_metadata: JSON.stringify(clientMetadata(config)),
  };
}

/** The link a wallet opens (shown as a QR code or tapped on the same device). */
export function walletUrl(config: ServiceConfig, session: Session, policies: CredentialTypePolicy[]): string {
  const base = config.oid4vp.walletUrlScheme.replace(/\?$/, '');
  const sep = base.includes('?') ? '&' : '?';
  // Signed requests (openid_federation) are always passed by reference to keep the link short.
  const byReference = (session.requestMode ?? config.oid4vp.requestMode) === 'reference' || session.clientIdPrefix === 'openid_federation';
  const params = byReference
    ? { client_id: clientId(config, session.clientIdPrefix), request_uri: `${config.publicUrl}/oid4vp/request/${session.state}` }
    : authorizationRequestParams(config, session, policies);
  return base + sep + new URLSearchParams(params).toString();
}

/** Request parameters with the JSON-valued ones as objects, as they appear inside a request object. */
export function requestObjectClaims(params: Record<string, string>): Record<string, unknown> {
  return { ...params, dcql_query: JSON.parse(params.dcql_query!), client_metadata: JSON.parse(params.client_metadata!) };
}

/** Request object for request_uri. Unsigned, as the redirect_uri prefix gives the wallet no key to check a signature with. */
export function unsignedRequestObject(params: Record<string, string>): string {
  const payload = requestObjectClaims(params);
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'none', typ: 'oauth-authz-req+jwt' })}.${enc(payload)}.`;
}

/** Request for navigator.credentials.get({ digital: { requests: [...] } }). */
export function dcApiRequest(config: ServiceConfig, session: Session, policies: CredentialTypePolicy[]) {
  return {
    protocol: 'openid4vp-v1-unsigned',
    data: {
      response_type: 'vp_token',
      response_mode: 'dc_api',
      nonce: session.nonce,
      dcql_query: buildDcqlQuery(policies),
      client_metadata: clientMetadata(config),
    },
  };
}

/**
 * Extracts presentations from a vp_token. Lenient about the shapes wallets send:
 * 1.0 `{ "<query id>": ["<sd-jwt>"] }`, pre-1.0 `{ "<query id>": "<sd-jwt>" }`, a bare string, an array,
 * or any of these JSON-encoded as a string.
 */
export function extractPresentations(vpToken: unknown): { queryId?: string; presentation: string }[] {
  if (typeof vpToken === 'string') {
    const t = vpToken.trim();
    if (t.startsWith('{') || t.startsWith('[')) {
      try {
        return extractPresentations(JSON.parse(t));
      } catch {
        /* not JSON after all */
      }
    }
    return t ? [{ presentation: t }] : [];
  }
  if (Array.isArray(vpToken)) return vpToken.flatMap((v) => extractPresentations(v));
  if (vpToken && typeof vpToken === 'object') {
    return Object.entries(vpToken).flatMap(([queryId, v]) =>
      (Array.isArray(v) ? v : [v]).filter((p): p is string => typeof p === 'string').map((presentation) => ({ queryId, presentation })),
    );
  }
  return [];
}
