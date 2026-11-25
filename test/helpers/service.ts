/** A complete verifier service over an in-memory federation, for component and flow tests. */
import { createApp } from '../../src/server/app.js';
import { normalizeConfig } from '../../src/server/config.js';
import { createResultSigner } from '../../src/server/results.js';
import { MemorySessionStore } from '../../src/server/sessions.js';
import { createPresentation } from '../../tools/wallet/present.js';
import { newKey, TestFederation } from './federation.js';
import { issueSdJwt } from './issuer.js';

export const PUBLIC_URL = 'https://verifier.example';
export const API_KEY = 'shop-secret-key-0123456789';
const TA = 'https://ta.example';
const ISSUER = 'https://pension.example';
const PENSION_VCT = 'https://alennusperuste.todiste.fi/credentials/v3/PensionCredential';

export async function createTestService(overrides: Record<string, unknown> = {}) {
  const fed = new TestFederation();
  const holder = await newKey('holder');
  const issuerKey = await newKey('pension-signing');
  await fed.addEntity(TA);
  await fed.addEntity(ISSUER, { authorityHints: [TA], metadata: { federation_entity: { organization_name: 'Kela' }, openid_credential_issuer: { jwks: { keys: [issuerKey.jwk] } } } });
  fed.addSubordinate(TA, ISSUER);
  const config = await normalizeConfig({
    publicUrl: PUBLIC_URL,
    trustAnchors: [{ entityId: TA }],
    credentialTypes: [{ id: 'pension', label: { fi: 'Eläkeläinen', en: 'Pensioner' }, vct: [PENSION_VCT], require: { Voimassa: true } }],
    kiosk: { enabled: true, resetAfterSeconds: 8 },
    apiClients: [{ id: 'shop', apiKey: API_KEY, allowedReturnUrls: [`${PUBLIC_URL}/`] }],
    ...overrides,
  });
  const app = createApp({ config, store: new MemorySessionStore(), signer: await createResultSigner(PUBLIC_URL), fetch: fed.fetch, log: () => {} });

  const issue = (voimassa: unknown = true, iss = ISSUER) =>
    issueSdJwt({ key: issuerKey.privateKey, kid: 'pension-signing', claims: { iss, vct: PENSION_VCT }, sdClaims: { Voimassa: voimassa, Hetu: '010101-123N' }, holderJwk: holder.jwk });

  /**
   * Answers an openid4vp:// link the way a wallet would, fetching the request object when passed by reference.
   * Options let tests misbehave like real wallets (wrong audience, untrusted issuer, error responses).
   */
  async function wallet(link: string, voimassa: unknown = true, opts: { aud?: string; iss?: string; userAgent?: string; error?: string } = {}) {
    let params = new URL(link.replace('openid4vp://', 'https://wallet.invalid/')).searchParams;
    const headers: Record<string, string> = opts.userAgent ? { 'user-agent': opts.userAgent } : {};
    if (params.get('request_uri')) {
      const jwt = await (await app.request(new URL(params.get('request_uri')!).pathname, { headers })).text();
      const claims = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;
      params = new URLSearchParams(Object.fromEntries(Object.entries(claims).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)])));
    }
    const form: Record<string, string> = { state: params.get('state')! };
    if (opts.error) form.error = opts.error;
    else {
      const vp = await createPresentation(await issue(voimassa, opts.iss), { disclose: ['Voimassa'], holderKey: holder.privateKey, nonce: params.get('nonce')!, aud: opts.aud ?? params.get('client_id')! });
      form.vp_token = JSON.stringify({ pension: [vp] });
    }
    const res = await app.request(new URL(params.get('response_uri')!).pathname, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString(),
    });
    return (await res.json()) as Record<string, string>;
  }

  /** A DC API presentation for a request obtained by the component. */
  async function dcPresentation(request: { data: { nonce: string } }, origin = PUBLIC_URL) {
    const vp = await createPresentation(await issue(), { disclose: ['Voimassa'], holderKey: holder.privateKey, nonce: request.data.nonce, aud: `origin:${origin}` });
    return { vp_token: { pension: [vp] } };
  }

  return { app, config, wallet, dcPresentation };
}
