/**
 * The verifier's did:web identity, for the `decentralized_identifier` client identifier prefix:
 * publishes the DID document and signs OpenID4VP request objects with its key.
 */
import { SignJWT } from 'jose';
import type { ServiceConfig } from './config.js';
import { loadKey, SELF_ISSUED_AUDIENCE, type LoadedKey } from './federation-entity.js';

const KEY_FRAGMENT = 'key-1';

export class VerifierDid {
  private constructor(
    readonly did: string,
    private readonly key: LoadedKey,
  ) {}

  static async create(config: ServiceConfig): Promise<VerifierDid> {
    if (!config.didWeb) throw new Error('didWeb is not configured');
    return new VerifierDid(config.didWeb.did, await loadKey(config.didWeb.requestSigningKey));
  }

  get clientId(): string {
    return `decentralized_identifier:${this.did}`;
  }

  get keyId(): string {
    return `${this.did}#${KEY_FRAGMENT}`;
  }

  didDocument() {
    return {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: this.did,
      verificationMethod: [{ id: this.keyId, type: 'JsonWebKey2020', controller: this.did, publicKeyJwk: this.key.publicJwk }],
      authentication: [this.keyId],
      assertionMethod: [this.keyId],
    };
  }

  /** Signs an OpenID4VP request object; `kid` is the DID URL of the verification method, as the specification requires. */
  async signRequestObject(params: Record<string, unknown>, lifetimeSeconds = 300): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ ...params, client_id: this.clientId, iss: this.did, aud: SELF_ISSUED_AUDIENCE, iat: now, exp: now + lifetimeSeconds })
      .setProtectedHeader({ alg: this.key.alg, kid: this.keyId, typ: 'oauth-authz-req+jwt' })
      .sign(this.key.key);
  }
}
