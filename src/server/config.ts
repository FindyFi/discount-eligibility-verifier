/**
 * Service configuration: a YAML (or JSON) file with ${ENV_VAR} interpolation, plus a few env overrides.
 */
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { JWK } from 'jose';
import type { CredentialTypePolicy, TrustAnchorConfig } from '../core/index.js';

export type ClientIdPrefix = 'redirect_uri' | 'openid_federation';

export interface ApiClient {
  id: string;
  apiKey: string;
  /** Receives the signed result (application/jwt) when a session completes. */
  webhookUrl?: string;
  /** URL prefixes the client may use as same-device return URLs. */
  allowedReturnUrls?: string[];
  /** Web origins where the client embeds the verifier (for the Digital Credentials API). */
  allowedOrigins?: string[];
}

export interface FederationConfig {
  /** The verifier's Entity Identifier (default: publicUrl). Its entity configuration is served at <entityId>/.well-known/openid-federation. */
  entityId: string;
  /** Superiors that publish a subordinate statement about this verifier (normally the trust anchor). */
  authorityHints: string[];
  /** Private JWK of the federation entity key (signs the entity configuration). Register its public part at the trust anchor. */
  federationKey: JWK;
  /** Private JWK for signing OpenID4VP request objects; published in the verifier metadata. */
  requestSigningKey: JWK;
  /** Entity types under which the verifier metadata is published. */
  metadataEntityTypes: string[];
  organizationName?: string;
  logoUri?: string;
  homepageUri?: string;
  policyUri?: string;
  contacts?: string[];
  entityConfigurationTtlSeconds: number;
  /** Send the verifier's trust chain in the request object's JWS header. */
  includeTrustChain: boolean;
}

export interface ServiceConfig {
  publicUrl: string;
  port: number;
  trustAnchors: TrustAnchorConfig[];
  credentialTypes: CredentialTypePolicy[];
  timeZone: string;
  allowJwtVcIssuerMetadata: boolean;
  oid4vp: {
    clientIdPrefix: ClientIdPrefix;
    /** "value": all parameters in the QR/link; "reference": a short link with request_uri. */
    requestMode: 'value' | 'reference';
    walletUrlScheme: string;
    sessionTtlSeconds: number;
    verifierName?: string;
  };
  /** Present when the verifier is an OpenID Federation entity (needed for the openid_federation client ID prefix). */
  federation?: FederationConfig;
  dcApi: { enabled: boolean; allowedOrigins: string[] };
  kiosk: { enabled: boolean; acceptedTypes?: string[]; resetAfterSeconds: number };
  apiClients: ApiClient[];
  /** Private JWK (JSON string or object) used to sign results. Generated per process if absent. */
  resultSigningKey?: JWK;
  /** Allow cross-origin browser calls to the public endpoints from these origins. */
  corsOrigins: string[];
  /** Wallet compatibility tester (compat.html). */
  compat: { enabled: boolean; token?: string; resultsFile: string; wallets: string[] };
}

export async function loadConfig(path = process.env.CONFIG_FILE ?? 'config/verifier.yaml'): Promise<ServiceConfig> {
  const text = interpolateEnv(await readFile(path, 'utf8'), path);
  const raw = (parseYaml(text) ?? {}) as Record<string, any>;
  return normalizeConfig(raw, dirname(resolve(path)));
}

/** Replaces ${VAR} and ${VAR:-default}; YAML comments (whole-line or after whitespace) are left alone. */
export function interpolateEnv(text: string, path: string, env: NodeJS.ProcessEnv = process.env): string {
  return text
    .split('\n')
    .map((line) => {
      const comment = /(^|\s)#/.exec(line);
      const code = comment ? line.slice(0, comment.index) : line;
      const rest = comment ? line.slice(comment.index) : '';
      return (
        code.replace(/\$\{([A-Z0-9_]+)(?::-([^}]*))?\}/g, (_, name: string, fallback?: string) => {
          const v = env[name] ?? fallback;
          if (v === undefined) throw new Error(`${path}: environment variable ${name} is not set`);
          return v;
        }) + rest
      );
    })
    .join('\n');
}

export async function normalizeConfig(raw: Record<string, any>, baseDir = process.cwd()): Promise<ServiceConfig> {
  const errors: string[] = [];
  const publicUrl = String(process.env.PUBLIC_URL ?? raw.publicUrl ?? '').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(publicUrl)) errors.push('publicUrl must be an absolute http(s) URL (or set PUBLIC_URL)');

  let credentialTypes = raw.credentialTypes;
  if (typeof credentialTypes === 'string') {
    credentialTypes = JSON.parse(await readFile(resolve(baseDir, credentialTypes), 'utf8'));
  }
  if (!Array.isArray(credentialTypes) || credentialTypes.length === 0) errors.push('credentialTypes must be a non-empty list or a path to a JSON file');
  else {
    for (const p of credentialTypes) {
      if (!p?.id || !Array.isArray(p.vct) || p.vct.length === 0) errors.push(`credential type ${JSON.stringify(p?.id)} needs an id and a vct list`);
    }
  }

  const trustAnchors = Array.isArray(raw.trustAnchors) ? raw.trustAnchors : [];
  if (trustAnchors.length === 0) errors.push('trustAnchors must list at least one trust anchor');

  const prefix = raw.oid4vp?.clientIdPrefix ?? 'redirect_uri';
  if (!['redirect_uri', 'openid_federation'].includes(prefix)) errors.push(`oid4vp.clientIdPrefix "${prefix}" is not supported`);

  let federation: FederationConfig | undefined;
  if (raw.federation) {
    const f = raw.federation;
    const entityId = String(f.entityId ?? publicUrl).replace(/\/+$/, '');
    if (!/^https:\/\/[^?#]+$/.test(entityId)) errors.push('federation.entityId (default publicUrl) must be an https URL without query or fragment');
    const federationKey = parseJwk(f.federationKey ?? process.env.FEDERATION_KEY, 'federation.federationKey (or FEDERATION_KEY)', errors);
    const requestSigningKey = parseJwk(f.requestSigningKey ?? process.env.REQUEST_SIGNING_KEY, 'federation.requestSigningKey (or REQUEST_SIGNING_KEY)', errors);
    const authorityHints = Array.isArray(f.authorityHints) && f.authorityHints.length ? f.authorityHints.map(String) : trustAnchors.map((t: { entityId: string }) => t.entityId);
    if (federationKey && requestSigningKey && federationKey.x === requestSigningKey.x && federationKey.n === requestSigningKey.n) {
      errors.push('federation.requestSigningKey must differ from federation.federationKey');
    }
    federation = {
      entityId,
      authorityHints,
      federationKey: federationKey!,
      requestSigningKey: requestSigningKey!,
      metadataEntityTypes: Array.isArray(f.metadataEntityTypes) && f.metadataEntityTypes.length ? f.metadataEntityTypes : ['openid_credential_verifier', 'openid_relying_party'],
      organizationName: f.organizationName,
      logoUri: f.logoUri,
      homepageUri: f.homepageUri,
      policyUri: f.policyUri,
      contacts: f.contacts,
      entityConfigurationTtlSeconds: Number(f.entityConfigurationTtlSeconds ?? 86400),
      includeTrustChain: f.includeTrustChain ?? true,
    };
  }
  if (raw.compat?.enabled && String(raw.compat?.token ?? '').length < 16) errors.push('compat.token must be at least 16 characters when compat.enabled is set');
  if (prefix === 'openid_federation' && !federation) errors.push('oid4vp.clientIdPrefix "openid_federation" requires a federation section');

  const apiClients: ApiClient[] = Array.isArray(raw.apiClients) ? raw.apiClients : [];
  for (const c of apiClients) {
    if (!c.id || !c.apiKey || String(c.apiKey).length < 16) errors.push(`apiClient ${JSON.stringify(c.id)} needs an id and an apiKey of at least 16 characters`);
  }

  let resultSigningKey = raw.resultSigningKey ?? process.env.RESULT_SIGNING_KEY;
  if (typeof resultSigningKey === 'string' && resultSigningKey.trim()) {
    try {
      resultSigningKey = JSON.parse(resultSigningKey);
    } catch {
      errors.push('resultSigningKey must be a private JWK in JSON');
    }
  } else if (!resultSigningKey) resultSigningKey = undefined;

  if (errors.length) throw new Error(`Invalid configuration:\n  - ${errors.join('\n  - ')}`);

  return {
    publicUrl,
    port: Number(process.env.PORT ?? raw.port ?? 8374),
    trustAnchors,
    credentialTypes,
    timeZone: raw.timeZone ?? 'Europe/Helsinki',
    allowJwtVcIssuerMetadata: raw.allowJwtVcIssuerMetadata ?? true,
    oid4vp: {
      clientIdPrefix: prefix,
      // By reference by default: short QR codes, and Heidi rejects requests passed in the QR code.
      requestMode: raw.oid4vp?.requestMode === 'value' ? 'value' : 'reference',
      walletUrlScheme: raw.oid4vp?.walletUrlScheme ?? 'openid4vp://',
      sessionTtlSeconds: Number(raw.oid4vp?.sessionTtlSeconds ?? 300),
      verifierName: raw.oid4vp?.verifierName,
    },
    dcApi: { enabled: raw.dcApi?.enabled ?? true, allowedOrigins: raw.dcApi?.allowedOrigins ?? [] },
    kiosk: { enabled: raw.kiosk?.enabled ?? false, acceptedTypes: raw.kiosk?.acceptedTypes, resetAfterSeconds: Number(raw.kiosk?.resetAfterSeconds ?? 8) },
    federation,
    apiClients,
    resultSigningKey,
    corsOrigins: raw.corsOrigins ?? [],
    compat: {
      enabled: raw.compat?.enabled ?? false,
      token: raw.compat?.token || undefined,
      resultsFile: raw.compat?.resultsFile ?? 'data/compat-results.json',
      wallets: raw.compat?.wallets ?? ['Heidi', 'Hovi Wallet', 'Paradym', 'Talao', 'Toppan Wallet', 'UniMe'],
    },
  };
}

function parseJwk(value: unknown, what: string, errors: string[]): JWK | undefined {
  let jwk = value;
  if (typeof jwk === 'string') {
    if (!jwk.trim()) jwk = undefined;
    else
      try {
        jwk = JSON.parse(jwk);
      } catch {
        errors.push(`${what} must be a private JWK in JSON`);
        return undefined;
      }
  }
  if (!jwk || typeof jwk !== 'object' || !('d' in jwk)) {
    errors.push(`${what} is required: a private JWK (generate one with npm run keygen)`);
    return undefined;
  }
  return jwk as JWK;
}
