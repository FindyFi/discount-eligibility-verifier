/**
 * Verifies an SD-JWT VC presentation end to end and evaluates discount eligibility.
 */
import { FederationResolver, type TrustAnchorConfig } from './federation.js';
import { resolveIssuerKeys } from './issuer-keys.js';
import { verifyKeyBinding } from './keybinding.js';
import { claimsOfInterest, evaluatePolicy, findPolicy, getClaim, type CredentialTypePolicy } from './policy.js';
import { parseSdJwt, reconstructClaims, type ParsedSdJwt } from './sdjwt.js';
import { isHttpsUrl, isObject, TransientError, verifyWithJwks, type Fetcher, type Json } from './util.js';

export interface VerifierConfig {
  trustAnchors: TrustAnchorConfig[];
  credentialTypes: CredentialTypePolicy[];
  /** Time zone for date-only claims such as "2026-12-31". Default Europe/Helsinki. */
  timeZone?: string;
  clockSkewSeconds?: number;
  /** Signature algorithms accepted for credentials and key binding. */
  allowedAlgs?: string[];
  /** Accept signing keys from /.well-known/jwt-vc-issuer of a federation-trusted issuer. Default true. */
  allowJwtVcIssuerMetadata?: boolean;
  /** What to do with credentials carrying a `status` claim until status lists are supported. Default "reject". */
  unsupportedStatus?: 'reject' | 'accept';
  keyBindingMaxAgeSeconds?: number;
  fetch?: Fetcher;
}

export interface VerificationExpectations {
  /** Nonce from the presentation request. */
  nonce?: string;
  /** Accepted KB-JWT audiences, e.g. the request's client_id. */
  audience?: string[];
  /** Restrict to these policy ids (e.g. only "student"). Defaults to all configured types. */
  acceptedTypes?: string[];
  /** Set false only for debugging pasted credentials; production verification always requires key binding. */
  requireKeyBinding?: boolean;
  now?: Date;
}

export type CheckId = 'format' | 'credential_type' | 'validity_period' | 'key_binding' | 'issuer_trust' | 'signature' | 'disclosures' | 'status' | 'eligibility';

export interface Check {
  id: CheckId;
  /** true = passed, false = failed, null = not run */
  ok: boolean | null;
  message: string;
}

export interface VerificationResult {
  /** accepted: eligible; rejected: invalid or ineligible; error: could not complete (e.g. network) — retrying may help. */
  outcome: 'accepted' | 'rejected' | 'error';
  credentialType?: string;
  label?: Record<string, string>;
  issuer?: { entityId: string; name?: string; organizationName?: string; logoUri?: string; trustAnchor?: string };
  /** Only the claims the policy is interested in; never the full disclosed set. */
  claims: Json;
  validUntil?: string;
  checks: Check[];
  reasons: string[];
}

const ORDER: CheckId[] = ['format', 'credential_type', 'validity_period', 'key_binding', 'issuer_trust', 'signature', 'disclosures', 'status', 'eligibility'];
const DEFAULT_ALGS = ['ES256', 'ES384', 'ES512', 'EdDSA', 'PS256'];
const SD_JWT_TYPS = ['dc+sd-jwt', 'vc+sd-jwt'];

class CheckFailed extends Error {
  constructor(
    readonly id: CheckId,
    message: string,
    readonly transient = false,
  ) {
    super(message);
  }
}

export class Verifier {
  readonly federation: FederationResolver;
  private readonly algs: string[];

  constructor(readonly config: VerifierConfig) {
    this.algs = config.allowedAlgs ?? DEFAULT_ALGS;
    this.federation = new FederationResolver({
      trustAnchors: config.trustAnchors,
      fetch: config.fetch,
      clockSkewSeconds: config.clockSkewSeconds,
    });
  }

  async verify(presentation: string, exp: VerificationExpectations = {}): Promise<VerificationResult> {
    const checks = new Map<CheckId, Check>();
    const pass = (id: CheckId, message: string) => checks.set(id, { id, ok: true, message });
    const result: VerificationResult = { outcome: 'rejected', claims: {}, checks: [], reasons: [] };
    const now = exp.now ?? new Date();
    const nowS = Math.floor(now.getTime() / 1000);
    const skew = this.config.clockSkewSeconds ?? 60;
    const tz = this.config.timeZone ?? 'Europe/Helsinki';

    try {
      // 1. Structure
      let parsed: ParsedSdJwt;
      try {
        parsed = parseSdJwt(presentation);
      } catch (e) {
        throw new CheckFailed('format', (e as Error).message);
      }
      const typ = typeof parsed.header.typ === 'string' ? parsed.header.typ.toLowerCase() : undefined;
      if (typ && !SD_JWT_TYPS.includes(typ)) throw new CheckFailed('format', `Unexpected typ "${parsed.header.typ}"`);
      if (typeof parsed.header.alg !== 'string' || !this.algs.includes(parsed.header.alg)) {
        throw new CheckFailed('format', `Signature algorithm "${String(parsed.header.alg)}" is not allowed`);
      }
      pass('format', `SD-JWT VC with ${parsed.disclosures.length} disclosure(s)${parsed.kbJwt ? ' and key binding' : ''}`);
      const payload = parsed.payload;

      // 2. Credential type
      const candidates = exp.acceptedTypes ? this.config.credentialTypes.filter((p) => exp.acceptedTypes!.includes(p.id)) : this.config.credentialTypes;
      const policy = findPolicy(candidates, payload.vct);
      if (!policy) throw new CheckFailed('credential_type', `Credential type ${JSON.stringify(payload.vct)} is not accepted here`);
      result.credentialType = policy.id;
      result.label = policy.label;
      pass('credential_type', `${policy.id} (${String(payload.vct)})`);

      // 3. Validity period
      if (payload.exp !== undefined) {
        if (typeof payload.exp !== 'number') throw new CheckFailed('validity_period', 'exp is not a number');
        if (payload.exp + skew < nowS) throw new CheckFailed('validity_period', `Credential expired at ${new Date(payload.exp * 1000).toISOString()}`);
      }
      if (typeof payload.nbf === 'number' && payload.nbf - skew > nowS) throw new CheckFailed('validity_period', 'Credential is not yet valid');
      if (typeof payload.iat === 'number' && payload.iat - skew > nowS) throw new CheckFailed('validity_period', 'Credential is issued in the future');
      pass('validity_period', payload.exp !== undefined ? `Valid until ${new Date((payload.exp as number) * 1000).toISOString()}` : 'No expiry set');

      // 4. Key binding
      const sdAlg = typeof payload._sd_alg === 'string' ? payload._sd_alg : 'sha-256';
      if (parsed.kbJwt) {
        if (!exp.nonce || !exp.audience?.length) throw new CheckFailed('key_binding', 'Verifier did not supply nonce and audience to check key binding against');
        try {
          await verifyKeyBinding(parsed.kbJwt, payload.cnf, parsed.presentedSdJwt, sdAlg, {
            nonce: exp.nonce,
            audience: exp.audience,
            allowedAlgs: this.algs,
            clockSkewSeconds: skew,
            maxAgeSeconds: this.config.keyBindingMaxAgeSeconds,
          });
        } catch (e) {
          throw new CheckFailed('key_binding', (e as Error).message);
        }
        pass('key_binding', 'Presented by the credential holder for this request');
      } else if (exp.requireKeyBinding === false) {
        checks.set('key_binding', { id: 'key_binding', ok: null, message: 'Not required (debug mode)' });
      } else {
        throw new CheckFailed('key_binding', 'Presentation has no key binding JWT');
      }

      // 5. Issuer trust
      const iss = payload.iss;
      if (!isHttpsUrl(iss)) throw new CheckFailed('issuer_trust', `Issuer ${JSON.stringify(iss)} is not an https entity identifier, so it cannot be checked against the federation`);
      const chain = await this.federation.resolve(iss);
      if (!chain.ok) throw new CheckFailed('issuer_trust', `Issuer is not trusted: ${chain.errors.join('; ')}`, chain.transient);
      const fe = isObject(chain.metadata.federation_entity) ? chain.metadata.federation_entity : {};
      result.issuer = {
        entityId: iss,
        name: str(fe.display_name),
        organizationName: str(fe.organization_name),
        logoUri: str(fe.logo_uri),
        trustAnchor: chain.trustAnchor,
      };
      pass('issuer_trust', `Trust chain of ${chain.chain.length} statements to ${chain.trustAnchor}`);

      // 6. Signature with federation-anchored keys
      const keySets = await resolveIssuerKeys(chain, { fetch: this.config.fetch, allowJwtVcIssuerMetadata: this.config.allowJwtVcIssuerMetadata ?? true });
      if (keySets.length === 0) throw new CheckFailed('signature', 'Issuer publishes no credential signing keys in its federation metadata');
      const errors: string[] = [];
      let verifiedWith: string | undefined;
      for (const ks of keySets) {
        try {
          await verifyWithJwks(parsed.issuerJwt, ks.jwks, this.algs);
          verifiedWith = ks.source;
          break;
        } catch (e) {
          errors.push(`${ks.source}: ${(e as Error).message}`);
        }
      }
      if (!verifiedWith) throw new CheckFailed('signature', `Signature does not verify with the issuer's keys (${errors.join('; ')})`);
      pass('signature', `Verified with key from ${verifiedWith}`);

      // 7. Disclosures
      let claims: Json;
      try {
        claims = reconstructClaims(parsed).claims;
      } catch (e) {
        throw new CheckFailed('disclosures', (e as Error).message);
      }
      pass('disclosures', `${parsed.disclosures.length} disclosure(s) match the signed digests`);

      // 8. Status
      if (payload.status !== undefined) {
        if ((this.config.unsupportedStatus ?? 'reject') === 'reject') throw new CheckFailed('status', 'Credential has a status reference, but status list checking is not supported yet');
        checks.set('status', { id: 'status', ok: null, message: 'Status reference present but not checked (configured to accept)' });
      } else {
        pass('status', 'Credential is not revocable');
      }

      // 9. Eligibility
      const outcome = evaluatePolicy(policy, claims, now.getTime(), tz);
      for (const path of claimsOfInterest(policy)) {
        const v = getClaim(claims, path);
        if (v !== undefined) result.claims[path] = v;
      }
      const validUntilMs = Math.min(outcome.validUntil ?? Infinity, typeof payload.exp === 'number' ? payload.exp * 1000 : Infinity);
      if (Number.isFinite(validUntilMs)) result.validUntil = new Date(validUntilMs).toISOString();
      if (!outcome.ok) throw new CheckFailed('eligibility', outcome.failures.join('; '));
      pass('eligibility', `Meets the ${policy.id} policy`);

      result.outcome = 'accepted';
    } catch (e) {
      if (e instanceof CheckFailed) {
        checks.set(e.id, { id: e.id, ok: false, message: e.message });
        result.reasons.push(e.message);
        result.outcome = e.transient ? 'error' : 'rejected';
      } else {
        // Unexpected failures (network errors outside the federation resolver, bugs) never yield "accepted".
        result.reasons.push(`${e instanceof TransientError ? 'Temporary failure' : 'Internal error'}: ${(e as Error).message}`);
        result.outcome = 'error';
      }
    }

    result.checks = ORDER.map((id) => checks.get(id) ?? { id, ok: null, message: 'Not run' });
    return result;
  }
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}
