import { beforeEach, describe, expect, it } from 'vitest';
import { compactVerify, createLocalJWKSet, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { FederationResolver } from '../src/core/index.js';
import { createApp } from '../src/server/app.js';
import { normalizeConfig } from '../src/server/config.js';
import { createResultSigner } from '../src/server/results.js';
import { MemorySessionStore } from '../src/server/sessions.js';
import { createPresentation } from '../tools/wallet/present.js';
import { newKey, TestFederation } from './helpers/federation.js';
import { issueSdJwt } from './helpers/issuer.js';

const VERIFIER = 'https://verifier.example';
const TA = 'https://ta.example';
const ISSUER = 'https://pension.example';
const PENSION_VCT = 'https://alennusperuste.todiste.fi/credentials/v3/PensionCredential';
const API_KEY = 'shop-secret-key-0123456789';
const CLIENT_ID = `openid_federation:${VERIFIER}`;

const privateJwk = async (): Promise<JWK> => ({ ...(await exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey)), alg: 'ES256' });
const federationKey = await privateJwk();
const requestSigningKey = await privateJwk();
const holder = await newKey('holder');
const issuerKey = await newKey('pension-signing');
const { d: _d, ...federationPublicKey } = federationKey;

let fed: TestFederation;
let app: ReturnType<typeof createApp>;

const baseConfig = (overrides: Record<string, unknown> = {}) => ({
  publicUrl: VERIFIER,
  trustAnchors: [{ entityId: TA }],
  credentialTypes: [{ id: 'pension', vct: [PENSION_VCT], require: { Voimassa: true } }],
  oid4vp: { verifierName: 'Alennusten tarkistus' },
  federation: { federationKey, requestSigningKey, organizationName: 'Findynet', contacts: ['info@example.org'] },
  apiClients: [{ id: 'shop', apiKey: API_KEY }],
  kiosk: { enabled: true },
  ...overrides,
});

async function setup(opts: { registered?: boolean; config?: Record<string, unknown> } = {}) {
  fed = new TestFederation();
  await fed.addEntity(TA);
  await fed.addEntity(ISSUER, { authorityHints: [TA], metadata: { openid_credential_issuer: { jwks: { keys: [issuerKey.jwk] } } } });
  fed.addSubordinate(TA, ISSUER);
  if (opts.registered !== false) fed.addSubordinate(TA, VERIFIER, { jwks: { keys: [federationPublicKey] } });
  // The verifier's own entity configuration is served by the app itself.
  const fetcher = (url: string, init?: RequestInit) => (url.startsWith(VERIFIER) ? Promise.resolve(app.request(url, init)) : fed.fetch(url, init));
  const config = await normalizeConfig(baseConfig(opts.config));
  app = createApp({ config, store: new MemorySessionStore(), signer: await createResultSigner(VERIFIER), fetch: fetcher, log: () => {} });
  return fetcher;
}

beforeEach(async () => {
  await setup(); // not returned: vitest would call a returned function as a teardown hook
});

async function createSession(body: object = { client_id_prefix: 'openid_federation' }) {
  const res = await app.request('/api/sessions', { method: 'POST', headers: { authorization: `Bearer ${API_KEY}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: res.status, body: (await res.json()) as Record<string, string> };
}

/** What a federation-aware wallet does: resolve the verifier, then check the request signature with its metadata keys. */
async function fetchAndVerifyRequest(walletUrl: string, fetcher: (u: string, i?: RequestInit) => Promise<Response>) {
  const link = new URL(walletUrl.replace('openid4vp://', 'https://wallet.invalid/'));
  const clientId = link.searchParams.get('client_id')!;
  expect(clientId).toBe(CLIENT_ID);
  const requestJwt = await (await app.request(new URL(link.searchParams.get('request_uri')!).pathname)).text();
  const chain = await new FederationResolver({ trustAnchors: [{ entityId: TA }], fetch: fetcher }).resolve(clientId.slice('openid_federation:'.length));
  expect(chain.ok).toBe(true);
  if (!chain.ok) throw new Error('unreachable');
  const jwks = chain.metadata.openid_credential_verifier!.jwks as { keys: JWK[] };
  const { payload, protectedHeader } = await compactVerify(requestJwt, createLocalJWKSet(jwks));
  return { header: protectedHeader as Record<string, any>, claims: JSON.parse(new TextDecoder().decode(payload)) as Record<string, any>, requestJwt };
}

describe('verifier entity configuration', () => {
  it('is a valid, self-signed leaf entity configuration with verifier metadata', async () => {
    const res = await app.request('/.well-known/openid-federation');
    expect(res.headers.get('content-type')).toBe('application/entity-statement+jwt');
    const jwt = await res.text();
    expect(decodeProtectedHeader(jwt)).toMatchObject({ typ: 'entity-statement+jwt', alg: 'ES256' });
    const { payload } = await compactVerify(jwt, await importJWK(federationPublicKey, 'ES256'));
    const ec = JSON.parse(new TextDecoder().decode(payload));
    expect(ec).toMatchObject({ iss: VERIFIER, sub: VERIFIER, authority_hints: [TA] });
    expect(ec.exp - ec.iat).toBe(86400);
    expect(ec.metadata.federation_entity).toMatchObject({ organization_name: 'Findynet', display_name: 'Alennusten tarkistus' });
    for (const type of ['openid_credential_verifier', 'openid_relying_party']) {
      expect(ec.metadata[type]).toMatchObject({ client_name: 'Alennusten tarkistus', response_uris: [`${VERIFIER}/oid4vp/response`], vp_formats_supported: { 'dc+sd-jwt': {} } });
    }
    // The request signing key is published in metadata and differs from the federation key.
    const requestKeys = ec.metadata.openid_credential_verifier.jwks.keys;
    expect(requestKeys).toHaveLength(1);
    expect(requestKeys[0].x).toBe(requestSigningKey.x);
    expect(requestKeys[0].d).toBeUndefined();
    expect(ec.jwks.keys[0].x).toBe(federationKey.x);
    expect(ec.jwks.keys[0].d).toBeUndefined();
  });

  it('is not served when federation is not configured', async () => {
    await setup({ config: { federation: undefined } });
    expect((await app.request('/.well-known/openid-federation')).status).toBe(404);
  });
});

describe('openid_federation requests', () => {
  it('signs the request object and includes the trust chain', async () => {
    const fetcher = await setup();
    const { status, body } = await createSession();
    expect(status).toBe(201);
    expect(body.client_id_prefix).toBe('openid_federation');
    expect(body.wallet_url!.length).toBeLessThan(250);

    const { header, claims } = await fetchAndVerifyRequest(body.wallet_url!, fetcher);
    expect(header.typ).toBe('oauth-authz-req+jwt');
    expect(header.trust_chain).toHaveLength(3);
    expect(decodeProtectedHeader(header.trust_chain[0]).typ).toBe('entity-statement+jwt');
    expect(claims).toMatchObject({
      client_id: CLIENT_ID,
      aud: 'https://self-issued.me/v2',
      response_type: 'vp_token',
      response_mode: 'direct_post',
      response_uri: `${VERIFIER}/oid4vp/response`,
      dcql_query: { credentials: [{ id: 'pension', format: 'dc+sd-jwt' }] },
    });
    expect(claims.nonce).toBeTruthy();
    expect(claims.state).toBeTruthy();
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(300);
  });

  it('cannot be verified with the federation key (keys are separated)', async () => {
    const { body } = await createSession();
    const link = new URL(body.wallet_url!.replace('openid4vp://', 'https://wallet.invalid/'));
    const requestJwt = await (await app.request(new URL(link.searchParams.get('request_uri')!).pathname)).text();
    await expect(compactVerify(requestJwt, await importJWK(federationPublicKey, 'ES256'))).rejects.toThrow();
  });

  it('accepts presentations bound to the federation client_id, and the unprefixed entity id', async () => {
    const fetcher = await setup();
    for (const aud of [CLIENT_ID, VERIFIER]) {
      const { body } = await createSession();
      const { claims } = await fetchAndVerifyRequest(body.wallet_url!, fetcher);
      const credential = await issueSdJwt({ key: issuerKey.privateKey, kid: 'pension-signing', claims: { iss: ISSUER, vct: PENSION_VCT }, sdClaims: { Voimassa: true }, holderJwk: holder.jwk });
      const vp = await createPresentation(credential, { disclose: ['Voimassa'], holderKey: holder.privateKey, nonce: claims.nonce, aud });
      await app.request('/oid4vp/response', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ vp_token: JSON.stringify({ pension: [vp] }), state: claims.state }).toString(),
      });
      const status = (await (await app.request(`/api/sessions/${body.session_id}`, { headers: { authorization: `Bearer ${API_KEY}` } })).json()) as Record<string, any>;
      expect([aud, status.outcome]).toEqual([aud, 'accepted']);
    }
  });

  it('rejects a presentation bound to the redirect_uri client_id in a federation session', async () => {
    const fetcher = await setup();
    const { body } = await createSession();
    const { claims } = await fetchAndVerifyRequest(body.wallet_url!, fetcher);
    const credential = await issueSdJwt({ key: issuerKey.privateKey, kid: 'pension-signing', claims: { iss: ISSUER, vct: PENSION_VCT }, sdClaims: { Voimassa: true }, holderJwk: holder.jwk });
    const vp = await createPresentation(credential, { disclose: ['Voimassa'], holderKey: holder.privateKey, nonce: claims.nonce, aud: `redirect_uri:${VERIFIER}/oid4vp/response` });
    await app.request('/oid4vp/response', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ vp_token: JSON.stringify({ pension: [vp] }), state: claims.state }).toString(),
    });
    const status = (await (await app.request(`/api/sessions/${body.session_id}`, { headers: { authorization: `Bearer ${API_KEY}` } })).json()) as Record<string, any>;
    expect(status.outcome).toBe('rejected');
  });

  it('still signs requests, without trust_chain, when the verifier is not registered yet', async () => {
    await setup({ registered: false });
    const { body } = await createSession();
    const link = new URL(body.wallet_url!.replace('openid4vp://', 'https://wallet.invalid/'));
    const requestJwt = await (await app.request(new URL(link.searchParams.get('request_uri')!).pathname)).text();
    const header = decodeProtectedHeader(requestJwt) as Record<string, unknown>;
    expect(header.typ).toBe('oauth-authz-req+jwt');
    expect(header.trust_chain).toBeUndefined();
    const { d: _rd, ...requestPublicKey } = requestSigningKey;
    await compactVerify(requestJwt, await importJWK(requestPublicKey, 'ES256'));
  });

  it('keeps redirect_uri sessions unsigned when both prefixes are available', async () => {
    const { body } = await createSession({ client_id_prefix: 'redirect_uri' });
    expect(body.client_id_prefix).toBe('redirect_uri');
    expect(body.wallet_url).toContain('client_id=redirect_uri%3A');
  });

  it('uses openid_federation for kiosk sessions when it is the default prefix', async () => {
    await setup({ config: { oid4vp: { clientIdPrefix: 'openid_federation' } } });
    const res = await app.request('/public/kiosk/sessions', { method: 'POST' });
    const s = (await res.json()) as Record<string, string>;
    expect(s.client_id_prefix).toBe('openid_federation');
    expect(s.wallet_url).toContain(encodeURIComponent(CLIENT_ID));
  });
});

describe('configuration', () => {
  it('rejects openid_federation without a federation section, or with an unknown prefix', async () => {
    await expect(normalizeConfig(baseConfig({ federation: undefined, oid4vp: { clientIdPrefix: 'openid_federation' } }))).rejects.toThrow(/requires a federation section/);
    await setup({ config: { federation: undefined } });
    expect((await createSession({ client_id_prefix: 'openid_federation' })).status).toBe(400);
    expect((await createSession({ client_id_prefix: 'x509_san_dns' })).status).toBe(400);
  });

  it('requires both keys, different from each other, and an https entity identifier', async () => {
    await expect(normalizeConfig(baseConfig({ federation: { requestSigningKey } }))).rejects.toThrow(/federationKey/);
    await expect(normalizeConfig(baseConfig({ federation: { federationKey, requestSigningKey: federationKey } }))).rejects.toThrow(/must differ/);
    const { d: _x, ...publicOnly } = requestSigningKey;
    await expect(normalizeConfig(baseConfig({ federation: { federationKey, requestSigningKey: publicOnly } }))).rejects.toThrow(/private JWK/);
    await expect(normalizeConfig(baseConfig({ publicUrl: 'http://localhost:8080' }))).rejects.toThrow(/https URL/);
  });
});
