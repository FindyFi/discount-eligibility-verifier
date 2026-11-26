import { beforeEach, describe, expect, it } from 'vitest';
import { compactVerify, createLocalJWKSet, decodeProtectedHeader, exportJWK, generateKeyPair } from 'jose';
import { normalizeConfig } from '../src/server/config.js';
import { Verifier } from '../src/core/verifier.js';
import { didDocumentKeys, didWebUrl } from '../src/core/did-web.js';
import { createPresentation } from '../tools/wallet/present.js';
import { newKey } from './helpers/federation.js';
import { issueSdJwt } from './helpers/issuer.js';
import { createTestService, PUBLIC_URL } from './helpers/service.js';

const TOKEN = 'compat-tester-token-0123456789';
const PENSION_VCT = 'https://alennusperuste.todiste.fi/credentials/v3/PensionCredential';

async function didWebKey() {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  return { ...(await exportJWK(privateKey)), alg: 'ES256' };
}

describe('decentralized_identifier client ID prefix', () => {
  let svc: Awaited<ReturnType<typeof createTestService>>;
  beforeEach(async () => {
    svc = await createTestService({ compat: { enabled: true, token: TOKEN, resultsFile: '/dev/null' }, didWeb: { requestSigningKey: await didWebKey() } });
  });
  const compat = (path: string, init: RequestInit = {}) =>
    svc.app.request(`/api/compat${path}`, { ...init, headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' } });
  const start = async (variant: object) => (await (await compat('/sessions', { method: 'POST', body: JSON.stringify({ variant, credential_type: 'pension' }) })).json()) as Record<string, string>;

  it('serves a DID document and signs request objects with its key', async () => {
    const doc = await (await svc.app.request('/.well-known/did.json')).json();
    expect(doc.id).toBe('did:web:verifier.example');
    expect(doc.assertionMethod).toEqual(['did:web:verifier.example#key-1']);

    const s = await start({ clientIdPrefix: 'decentralized_identifier', requestMode: 'reference' });
    const url = new URL(s.wallet_url!.replace('openid4vp://', 'https://wallet.invalid/'));
    expect(url.searchParams.get('client_id')).toBe('decentralized_identifier:did:web:verifier.example');
    expect(url.searchParams.get('request_uri')).toBeTruthy();
    expect(url.searchParams.get('dcql_query')).toBeNull();

    const jwt = await (await svc.app.request(new URL(url.searchParams.get('request_uri')!).pathname)).text();
    expect(decodeProtectedHeader(jwt)).toMatchObject({ alg: 'ES256', kid: 'did:web:verifier.example#key-1', typ: 'oauth-authz-req+jwt' });
    const { payload } = await compactVerify(jwt, createLocalJWKSet(didDocumentKeys(doc)));
    const claims = JSON.parse(new TextDecoder().decode(payload));
    expect(claims).toMatchObject({ client_id: 'decentralized_identifier:did:web:verifier.example', response_uri: `${PUBLIC_URL}/oid4vp/response`, aud: 'https://self-issued.me/v2' });
    expect(claims.dcql_query.credentials[0].id).toBe('pension');
  });

  it('accepts a presentation whose key binding names the full client ID', async () => {
    const s = await start({ clientIdPrefix: 'decentralized_identifier', requestMode: 'reference' });
    expect(await svc.wallet(s.wallet_url!)).toEqual({});
  });

  it('is only offered, and only allowed in the API, when configured', async () => {
    const plain = await createTestService({ compat: { enabled: true, token: TOKEN, resultsFile: '/dev/null' } });
    const info = (await (await plain.app.request('/api/compat/info', { headers: { authorization: `Bearer ${TOKEN}` } })).json()) as { variants: { clientIdPrefix: string }[] };
    expect(info.variants.map((v) => v.clientIdPrefix)).not.toContain('decentralized_identifier');
    expect((await plain.app.request('/.well-known/did.json')).status).toBe(404);
  });

  it('needs an https publicUrl without a path', async () => {
    const key = await didWebKey();
    const base = { trustAnchors: [{ entityId: 'https://ta.example' }], credentialTypes: [{ id: 'p', vct: ['x'] }], didWeb: { requestSigningKey: key } };
    await expect(normalizeConfig({ ...base, publicUrl: 'http://localhost:8374' })).rejects.toThrow(/didWeb needs publicUrl/);
    await expect(normalizeConfig({ ...base, publicUrl: 'https://verifier.example/app' })).rejects.toThrow(/didWeb needs publicUrl/);
    expect((await normalizeConfig({ ...base, publicUrl: 'https://verifier.example:8443' })).didWeb?.did).toBe('did:web:verifier.example%3A8443');
  });
});

describe('legacy_redirect_uri variant', () => {
  it('sends client_id_scheme with a bare client_id, by value and by reference', async () => {
    const svc = await createTestService({ compat: { enabled: true, token: TOKEN, resultsFile: '/dev/null' } });
    for (const requestMode of ['value', 'reference']) {
      const res = await svc.app.request('/api/compat/sessions', {
        method: 'POST',
        headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ variant: { clientIdPrefix: 'legacy_redirect_uri', requestMode }, credential_type: 'pension' }),
      });
      expect(res.status).toBe(201);
      const s = (await res.json()) as Record<string, string>;
      const params = new URL(s.wallet_url!.replace('openid4vp://', 'https://wallet.invalid/')).searchParams;
      expect(params.get('client_id')).toBe(`${PUBLIC_URL}/oid4vp/response`);
      expect(params.get('client_id_scheme')).toBe('redirect_uri');
      expect(params.get('request_uri') !== null).toBe(requestMode === 'reference');
      if (requestMode === 'value') expect(JSON.parse(params.get('client_metadata')!).vp_formats['vc+sd-jwt']).toBeTruthy();
      // The wallet echoes the bare client_id as the key binding audience.
      expect(await svc.wallet(s.wallet_url!)).toEqual({});
    }
  });

  it('is not available through the integration API', async () => {
    const svc = await createTestService();
    const res = await svc.app.request('/api/sessions', {
      method: 'POST',
      headers: { authorization: 'Bearer shop-secret-key-0123456789', 'content-type': 'application/json' },
      body: JSON.stringify({ client_id_prefix: 'legacy_redirect_uri' }),
    });
    expect(res.status).toBe(400);
  });
});

describe('trusted did:web issuers', () => {
  const DID = 'did:web:issuer.example';
  const NONCE = 'n-0S6_WzA2Mj';
  const AUD = 'redirect_uri:https://verifier.example/response';
  const TA = 'https://ta.example';
  let key: Awaited<ReturnType<typeof newKey>>;
  let holder: Awaited<ReturnType<typeof newKey>>;
  let docs: Map<string, { status: number; body: string }>;
  const fetcher = async (url: string) => {
    const r = docs.get(url);
    if (!r) throw new TypeError('fetch failed');
    return new Response(r.body, { status: r.status });
  };

  beforeEach(async () => {
    key = await newKey('key-1');
    holder = await newKey('holder');
    docs = new Map([
      [
        'https://issuer.example/.well-known/did.json',
        {
          status: 200,
          body: JSON.stringify({
            id: DID,
            verificationMethod: [{ id: `${DID}#key-1`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: key.jwk }],
            assertionMethod: [`${DID}#key-1`],
          }),
        },
      ],
    ]);
  });

  const verifier = (trusted = [{ did: DID, name: 'Procivis demo', organizationName: 'Kela' }]) =>
    new Verifier({ trustAnchors: [{ entityId: TA }], credentialTypes: [{ id: 'pension', vct: [PENSION_VCT], require: { Voimassa: true } }], trustedDidIssuers: trusted, fetch: fetcher });
  const credential = (kid = `${DID}#key-1`, iss = DID, signer = key) =>
    issueSdJwt({ key: signer.privateKey, kid, claims: { iss, vct: PENSION_VCT }, sdClaims: { Voimassa: true }, holderJwk: holder.jwk });
  const present = async (cred: string) => createPresentation(cred, { disclose: ['Voimassa'], holderKey: holder.privateKey, nonce: NONCE, aud: AUD });
  const verify = async (cred: string, v = verifier()) => v.verify(await present(cred), { nonce: NONCE, audience: [AUD] });

  it('accepts a credential from a configured did:web issuer without any federation', async () => {
    const r = await verify(await credential());
    expect(r.reasons).toEqual([]);
    expect(r.outcome).toBe('accepted');
    expect(r.issuer).toMatchObject({ entityId: DID, name: 'Procivis demo', organizationName: 'Kela', trustAnchor: 'configured trusted issuer' });
  });

  it('accepts a kid that is only the fragment', async () => {
    expect((await verify(await credential('key-1'))).outcome).toBe('accepted');
    expect((await verify(await credential('#key-1'))).outcome).toBe('accepted');
  });

  it('rejects a did:web issuer that is not configured, saying why', async () => {
    const r = await verify(await credential(), verifier([]));
    expect(r.outcome).toBe('rejected');
    expect(r.reasons[0]).toMatch(/not a configured trusted did:web issuer/);
  });

  it('rejects a signature from a key the DID document does not list', async () => {
    const r = await verify(await credential(`${DID}#key-1`, DID, await newKey('key-1')));
    expect(r.outcome).toBe('rejected');
    expect(r.checks.find((c) => c.id === 'signature')?.ok).toBe(false);
  });

  it('ignores keys outside assertionMethod', async () => {
    const other = await newKey('key-2');
    docs.set('https://issuer.example/.well-known/did.json', {
      status: 200,
      body: JSON.stringify({ id: DID, verificationMethod: [{ id: `${DID}#key-2`, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: other.jwk }], assertionMethod: [] }),
    });
    expect((await verify(await credential(`${DID}#key-2`, DID, other))).outcome).toBe('rejected');
  });

  it('rejects a DID document whose id differs', async () => {
    docs.set('https://issuer.example/.well-known/did.json', { status: 200, body: JSON.stringify({ id: 'did:web:evil.example', verificationMethod: [] }) });
    const r = await verify(await credential());
    expect(r.outcome).toBe('rejected');
    expect(r.reasons[0]).toMatch(/does not have id/);
  });

  it('reports an unreachable DID document as a temporary error', async () => {
    docs.clear();
    expect((await verify(await credential())).outcome).toBe('error');
  });
});

describe('did:web helpers', () => {
  it('maps DIDs to document URLs', () => {
    expect(didWebUrl('did:web:example.com')).toBe('https://example.com/.well-known/did.json');
    expect(didWebUrl('did:web:example.com%3A8443:ssi:did-web:v1:abc')).toBe('https://example.com:8443/ssi/did-web/v1/abc/did.json');
    expect(() => didWebUrl('did:key:z6Mk')).toThrow();
    expect(() => didWebUrl('did:web:exa mple.com')).toThrow();
    expect(() => didWebUrl('did:web:example.com%2Fevil')).toThrow();
  });

  it('configures trusted issuers and rejects malformed entries', async () => {
    const base = { publicUrl: 'https://v.example', trustAnchors: [{ entityId: 'https://ta.example' }], credentialTypes: [{ id: 'p', vct: ['x'] }] };
    const cfg = await normalizeConfig({ ...base, trustedDidIssuers: ['did:web:a.example', { did: 'did:web:b.example', name: 'B' }] });
    expect(cfg.trustedDidIssuers).toEqual([{ did: 'did:web:a.example' }, { did: 'did:web:b.example', name: 'B', organizationName: undefined }].map((t) => expect.objectContaining(t)));
    await expect(normalizeConfig({ ...base, trustedDidIssuers: ['did:key:z6Mk'] })).rejects.toThrow(/did:web/);
  });
});
