import { beforeEach, describe, expect, it } from 'vitest';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { createApp } from '../src/server/app.js';
import { normalizeConfig, type ServiceConfig } from '../src/server/config.js';
import { extractPresentations } from '../src/server/oid4vp.js';
import { createResultSigner } from '../src/server/results.js';
import { MemorySessionStore } from '../src/server/sessions.js';
import type { CredentialTypePolicy } from '../src/core/index.js';
import { createPresentation } from '../tools/wallet/present.js';
import { newKey, TestFederation } from './helpers/federation.js';
import { issueSdJwt } from './helpers/issuer.js';

const PUBLIC_URL = 'https://verifier.example';
const TA = 'https://ta.example';
const ISSUER = 'https://pension.example';
const PENSION_VCT = 'https://alennusperuste.todiste.fi/credentials/v3/PensionCredential';
const STUDENT_VCT = 'https://openbadge.digicredential.eu/credentials/student-status/v1/StudentStatusVCT';
const SHOP_ORIGIN = 'https://shop.example';
const WEBHOOK = 'https://shop.example/hooks/eligibility';
const API_KEY = 'shop-secret-key-0123456789';

const policies: CredentialTypePolicy[] = [
  { id: 'pension', label: { en: 'Pensioner' }, vct: [PENSION_VCT], require: { Voimassa: true } },
  { id: 'student', vct: [STUDENT_VCT], require: { enrolment_status: 'enrolled' }, validUntilClaim: 'expiry_date' },
];

const holder = await newKey('holder');
const issuerKey = await newKey('pension-signing');

let fed: TestFederation;
let webhooks: string[];
let app: ReturnType<typeof createApp>;
let config: ServiceConfig;
let credential: string;

async function setup(overrides: Record<string, any> = {}) {
  fed = new TestFederation();
  webhooks = [];
  await fed.addEntity(TA);
  await fed.addEntity(ISSUER, { authorityHints: [TA], metadata: { federation_entity: { organization_name: 'Kela' }, openid_credential_issuer: { jwks: { keys: [issuerKey.jwk] } } } });
  fed.addSubordinate(TA, ISSUER);
  const fetcher = async (url: string, init?: RequestInit) => {
    if (url === WEBHOOK) {
      webhooks.push(String(init?.body));
      return new Response(null, { status: 204 });
    }
    return fed.fetch(url, init);
  };
  config = await normalizeConfig({
    publicUrl: PUBLIC_URL,
    trustAnchors: [{ entityId: TA }],
    credentialTypes: policies,
    apiClients: [{ id: 'shop', apiKey: API_KEY, webhookUrl: WEBHOOK, allowedReturnUrls: [`${SHOP_ORIGIN}/checkout`], allowedOrigins: [SHOP_ORIGIN] }],
    ...overrides,
  });
  const signer = await createResultSigner(PUBLIC_URL);
  app = createApp({ config, store: new MemorySessionStore(), signer, fetch: fetcher, log: () => {} });
  credential = await issueSdJwt({
    key: issuerKey.privateKey,
    kid: 'pension-signing',
    claims: { iss: ISSUER, vct: PENSION_VCT },
    sdClaims: { Hetu: '010101-123N', Voimassa: true, Muodostettu: '25.11.2026' },
    holderJwk: holder.jwk,
  });
}

beforeEach(() => setup());

const api = (path: string, init: RequestInit = {}) =>
  app.request(path, { ...init, headers: { authorization: `Bearer ${API_KEY}`, 'content-type': 'application/json', ...(init.headers ?? {}) } });

async function createSession(body: object = {}) {
  const res = await api('/api/sessions', { method: 'POST', body: JSON.stringify(body) });
  expect(res.status).toBe(201);
  return (await res.json()) as Record<string, string>;
}

/** Simulated wallet: reads the request (by value or reference), presents, and posts the response. */
async function wallet(walletUrl: string, opts: { cred?: string; disclose?: string[]; aud?: string; nonce?: string; form?: Record<string, string> } = {}) {
  let params = new URL(walletUrl.replace('openid4vp://', 'https://wallet/')).searchParams;
  if (params.get('request_uri')) {
    const res = await app.request(new URL(params.get('request_uri')!).pathname);
    expect(res.headers.get('content-type')).toContain('oauth-authz-req+jwt');
    const [header, payload] = (await res.text()).split('.').map((p) => (p ? JSON.parse(Buffer.from(p, 'base64url').toString()) : undefined));
    expect(header.alg).toBe('none');
    params = new URLSearchParams({ ...payload, dcql_query: JSON.stringify(payload.dcql_query) });
  }
  const dcql = JSON.parse(params.get('dcql_query')!);
  const query = dcql.credentials[0];
  const disclose = opts.disclose ?? query.claims.map((c: { path: string[] }) => c.path[0]);
  const vp = await createPresentation(opts.cred ?? credential, { disclose, holderKey: holder.privateKey, nonce: opts.nonce ?? params.get('nonce')!, aud: opts.aud ?? params.get('client_id')! });
  const form = opts.form ?? { vp_token: JSON.stringify({ [query.id]: [vp] }), state: params.get('state')! };
  const res = await app.request(new URL(params.get('response_uri')!).pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
  });
  return { res, params, body: (await res.json()) as Record<string, string> };
}

async function verifyResultJwt(jwt: string) {
  const jwks = await (await app.request('/.well-known/jwks.json')).json();
  return (await jwtVerify(jwt, createLocalJWKSet(jwks), { issuer: PUBLIC_URL, audience: 'shop', typ: 'eligibility-result+jwt' })).payload;
}

describe('integration API', () => {
  it('requires an API key', async () => {
    expect((await app.request('/api/sessions', { method: 'POST' })).status).toBe(401);
    expect((await app.request('/api/sessions', { method: 'POST', headers: { authorization: 'Bearer wrong-key-wrong-key-xx' } })).status).toBe(401);
  });

  it('rejects unknown credential types and disallowed return URLs', async () => {
    expect((await api('/api/sessions', { method: 'POST', body: JSON.stringify({ accepted_types: ['nope'] }) })).status).toBe(400);
    expect((await api('/api/sessions', { method: 'POST', body: JSON.stringify({ return_url: 'https://evil.example/checkout' }) })).status).toBe(400);
  });

  it('runs a cross-device flow end to end, with a signed result and webhook', async () => {
    const s = await createSession({ reference: 'order-42' });
    expect(s.wallet_url).toMatch(/^openid4vp:\/\/\?client_id=redirect_uri%3A/);
    expect(s.same_device_wallet_url).toBeUndefined();

    const { res, params, body } = await wallet(s.wallet_url!);
    expect(res.status).toBe(200);
    expect(body).toEqual({});
    expect(JSON.parse(params.get('dcql_query')!).credential_sets[0].options).toEqual([['pension'], ['student']]);

    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status).toMatchObject({ status: 'completed', outcome: 'accepted', credential_type: 'pension', reference: 'order-42', flow: 'cross_device', claims: { Voimassa: true } });
    expect(JSON.stringify(status)).not.toContain('010101-123N');

    const payload = await verifyResultJwt(status.result_jwt);
    expect(payload).toMatchObject({ session_id: s.session_id, outcome: 'accepted', credential_type: 'pension' });

    await new Promise((r) => setTimeout(r, 10));
    expect(webhooks).toHaveLength(1);
    expect((await verifyResultJwt(webhooks[0]!)).session_id).toBe(s.session_id);
  });

  it('does not let another client read the session', async () => {
    await setup({ apiClients: [{ id: 'shop', apiKey: API_KEY }, { id: 'other', apiKey: 'other-secret-key-0123456789' }] });
    const s = await createSession();
    const res = await app.request(`/api/sessions/${s.session_id}`, { headers: { authorization: 'Bearer other-secret-key-0123456789' } });
    expect(res.status).toBe(404);
  });

  it('supports request by reference', async () => {
    await setup({ oid4vp: { requestMode: 'reference' } });
    const s = await createSession();
    expect(s.wallet_url).toContain('request_uri=');
    expect(s.wallet_url!.length).toBeLessThan(250);
    await wallet(s.wallet_url!);
    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status.outcome).toBe('accepted');
  });

  it('enforces the accepted types of the session', async () => {
    const s = await createSession({ accepted_types: ['student'] });
    await wallet(s.wallet_url!, { disclose: ['Voimassa'] });
    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status.outcome).toBe('rejected');
  });

  it('rejects a presentation made for another verifier (audience)', async () => {
    const s = await createSession();
    await wallet(s.wallet_url!, { aud: 'redirect_uri:https://other-verifier.example/response' });
    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status.outcome).toBe('rejected');
    expect(status.reasons.join()).toMatch(/audience/);
  });

  it('refuses a second response for the same session', async () => {
    await setup({ oid4vp: { requestMode: 'value' } }); // reads state from the QR link
    const s = await createSession();
    const first = await wallet(s.wallet_url!);
    const again = await wallet(s.wallet_url!, { form: { vp_token: 'x', state: first.params.get('state')! } });
    expect(again.res.status).toBe(400);
  });

  it('records wallet errors', async () => {
    await setup({ oid4vp: { requestMode: 'value' } }); // reads state from the QR link
    const s = await createSession();
    const state = new URL(s.wallet_url!.replace('openid4vp://', 'https://w/')).searchParams.get('state')!;
    await wallet(s.wallet_url!, { form: { error: 'access_denied', error_description: 'User declined', state } });
    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status).toMatchObject({ status: 'failed', outcome: 'wallet_error', wallet_error: { error: 'access_denied' } });
  });

  it('long-polls until the session changes', async () => {
    const s = await createSession();
    const poll = api(`/api/sessions/${s.session_id}?wait=5`);
    await new Promise((r) => setTimeout(r, 20));
    await wallet(s.wallet_url!);
    const status = (await (await poll).json()) as Record<string, any>;
    expect(status.status).toBe('completed');
  });

  it('expires sessions', async () => {
    await setup({ oid4vp: { sessionTtlSeconds: -1, requestMode: 'value' } }); // by reference, the expired request cannot even be fetched
    const s = await createSession();
    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status).toMatchObject({ status: 'expired', outcome: 'expired' });
    const { res } = await wallet(s.wallet_url!);
    expect(res.status).toBe(400);
  });
});

describe('same-device flow', () => {
  it('redirects back with a response code and shows the result only to that browser', async () => {
    const s = await createSession({ return_url: `${SHOP_ORIGIN}/checkout?step=2` });
    expect(s.same_device_wallet_url).toBeDefined();
    const { body } = await wallet(s.same_device_wallet_url!);
    const ret = new URL(body.redirect_uri!);
    expect(ret.origin + ret.pathname).toBe(`${SHOP_ORIGIN}/checkout`);
    const frag = new URLSearchParams(ret.hash.slice(1));
    expect(frag.get('verifier_session')).toBe(s.session_id);

    const pub = (q = '') => Promise.resolve(app.request(`/public/sessions/${s.session_id}${q}`, { headers: { 'x-session-token': s.browser_token! } })).then((r: Response) => r.json() as Promise<Record<string, any>>);
    expect((await pub()).status).toBe('awaiting_return');
    expect((await pub(`?response_code=${frag.get('response_code')}`)).outcome).toBe('accepted');

    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status).toMatchObject({ flow: 'same_device', same_device_confirmed: true });
    expect((await verifyResultJwt(status.result_jwt)).same_device_confirmed).toBe(true);
  });
});

describe('browser endpoints', () => {
  it('requires the session token', async () => {
    const s = await createSession();
    expect((await app.request(`/public/sessions/${s.session_id}`)).status).toBe(404);
    expect((await app.request(`/public/sessions/${s.session_id}?token=nope`)).status).toBe(404);
    const ok = await app.request(`/public/sessions/${s.session_id}?token=${s.browser_token}`);
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as Record<string, any>).status).toBe('pending');
  });

  it('kiosk sessions are disabled by default and never offer a same-device link', async () => {
    expect((await app.request('/public/kiosk/sessions', { method: 'POST' })).status).toBe(404);
    await setup({ kiosk: { enabled: true, acceptedTypes: ['pension'] } });
    const res = await app.request('/public/kiosk/sessions', { method: 'POST' });
    expect(res.status).toBe(201);
    const s = (await res.json()) as Record<string, any>;
    expect(s.accepted_types).toEqual(['pension']);
    expect(s.same_device_wallet_url).toBeUndefined();
    await wallet(s.wallet_url);
    const view = (await (await app.request(`/public/sessions/${s.session_id}?token=${s.browser_token}`)).json()) as Record<string, any>;
    expect(view).toMatchObject({ status: 'completed', outcome: 'accepted', label: { en: 'Pensioner' }, issuer: { name: 'Kela' } });
  });

  it('allows CORS only from configured origins', async () => {
    const s = await createSession();
    const ok = await app.request(`/public/sessions/${s.session_id}?token=${s.browser_token}`, { headers: { origin: SHOP_ORIGIN } });
    expect(ok.headers.get('access-control-allow-origin')).toBe(SHOP_ORIGIN);
    const bad = await app.request(`/public/sessions/${s.session_id}?token=${s.browser_token}`, { headers: { origin: 'https://evil.example' } });
    expect(bad.headers.get('access-control-allow-origin')).toBeNull();
  });
});

describe('Digital Credentials API', () => {
  const dc = async (s: Record<string, string>, origin: string, path: 'request' | 'response', body?: object) =>
    app.request(`/public/sessions/${s.session_id}/dc-api/${path}`, {
      method: 'POST',
      headers: { 'x-session-token': s.browser_token!, origin, 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });

  it('verifies a response bound to the embedding origin', async () => {
    const s = await createSession();
    const reqRes = await dc(s, SHOP_ORIGIN, 'request');
    expect(reqRes.status).toBe(200);
    const req = (await reqRes.json()) as Record<string, any>;
    expect(req).toMatchObject({ protocol: 'openid4vp-v1-unsigned', data: { response_mode: 'dc_api' } });
    expect(req.data.client_id).toBeUndefined();

    const vp = await createPresentation(credential, { disclose: ['Voimassa'], holderKey: holder.privateKey, nonce: req.data.nonce, aud: `origin:${SHOP_ORIGIN}` });
    const out = (await (await dc(s, SHOP_ORIGIN, 'response', { data: { vp_token: { pension: [vp] } } })).json()) as Record<string, any>;
    expect(out.outcome).toBe('accepted');
    const status = (await (await api(`/api/sessions/${s.session_id}`)).json()) as Record<string, any>;
    expect(status.flow).toBe('dc_api');
  });

  it('refuses requests from origins that are not allowed', async () => {
    const s = await createSession();
    expect((await dc(s, 'https://evil.example', 'request')).status).toBe(403);
  });

  it('rejects a DC API response whose key binding names another origin', async () => {
    const s = await createSession();
    const req = (await (await dc(s, SHOP_ORIGIN, 'request')).json()) as Record<string, any>;
    const vp = await createPresentation(credential, { disclose: ['Voimassa'], holderKey: holder.privateKey, nonce: req.data.nonce, aud: 'origin:https://evil.example' });
    const out = (await (await dc(s, SHOP_ORIGIN, 'response', { data: { vp_token: { pension: [vp] } } })).json()) as Record<string, any>;
    expect(out.outcome).toBe('rejected');
  });
});

describe('vp_token parsing', () => {
  it('accepts the response shapes wallets send', () => {
    expect(extractPresentations({ q: ['a', 'b'] })).toEqual([{ queryId: 'q', presentation: 'a' }, { queryId: 'q', presentation: 'b' }]);
    expect(extractPresentations({ q: 'a' })).toEqual([{ queryId: 'q', presentation: 'a' }]);
    expect(extractPresentations('{"q":["a"]}')).toEqual([{ queryId: 'q', presentation: 'a' }]);
    expect(extractPresentations(' a~b~ ')).toEqual([{ presentation: 'a~b~' }]);
    expect(extractPresentations(['a'])).toEqual([{ presentation: 'a' }]);
    expect(extractPresentations(undefined)).toEqual([]);
  });
});

describe('configuration', () => {
  it('validates and fills defaults', async () => {
    await expect(normalizeConfig({ publicUrl: 'nope', trustAnchors: [], credentialTypes: [] })).rejects.toThrow(/publicUrl[\s\S]*credentialTypes[\s\S]*trustAnchors/);
    await expect(normalizeConfig({ publicUrl: PUBLIC_URL, trustAnchors: [{ entityId: TA }], credentialTypes: policies, apiClients: [{ id: 'x', apiKey: 'short' }] })).rejects.toThrow(/apiKey/);
    const c = await normalizeConfig({ publicUrl: PUBLIC_URL + '/', trustAnchors: [{ entityId: TA }], credentialTypes: policies });
    expect(c).toMatchObject({ publicUrl: PUBLIC_URL, oid4vp: { clientIdPrefix: 'redirect_uri', requestMode: 'reference' }, kiosk: { enabled: false } });
  });
});

describe('environment interpolation', async () => {
  const { interpolateEnv } = await import('../src/server/config.js');
  it('substitutes variables and defaults but not inside comments', () => {
    const env = { A: 'x' };
    expect(interpolateEnv('a: ${A}\nb: ${B:-def} # uses ${NOPE}\n# ${ALSO_NOPE}', 'f', env)).toBe('a: x\nb: def # uses ${NOPE}\n# ${ALSO_NOPE}');
    expect(() => interpolateEnv('c: ${MISSING}', 'f', env)).toThrow(/MISSING/);
  });
});
