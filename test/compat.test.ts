import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { CompatStore, describeVpToken } from '../src/server/compat.js';
import { normalizeConfig } from '../src/server/config.js';
import { API_KEY, createTestService, PUBLIC_URL } from './helpers/service.js';

const TOKEN = 'compat-tester-token-0123456789';
let svc: Awaited<ReturnType<typeof createTestService>>;
let resultsFile: string;

beforeEach(async () => {
  resultsFile = join(await mkdtemp(join(tmpdir(), 'compat-')), 'results.json');
  svc = await createTestService({ compat: { enabled: true, token: TOKEN, resultsFile } });
});

const compat = (path: string, init: RequestInit = {}, token = TOKEN) =>
  svc.app.request(`/api/compat${path}`, { ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(init.headers ?? {}) } });

async function runVariant(requestMode: 'value' | 'reference') {
  const res = await compat('/sessions', { method: 'POST', body: JSON.stringify({ variant: { clientIdPrefix: 'redirect_uri', requestMode }, credential_type: 'pension' }) });
  expect(res.status).toBe(201);
  return (await res.json()) as Record<string, string>;
}

async function save(sessionId: string, extra: object = {}) {
  const res = await compat('/results', { method: 'POST', body: JSON.stringify({ session_id: sessionId, wallet: 'Paradym', platform: 'iOS', ...extra }) });
  expect(res.status).toBe(201);
  return (await res.json()) as Record<string, any>;
}

describe('access', () => {
  it('is disabled by default and needs the tester token', async () => {
    const plain = await createTestService();
    expect((await plain.app.request('/api/compat/info', { headers: { authorization: `Bearer ${TOKEN}` } })).status).toBe(404);
    expect((await compat('/info', {}, 'wrong-token-wrong-token-xx')).status).toBe(401);
    expect((await compat('/info', {}, API_KEY)).status).toBe(401);
    const info = (await (await compat('/info')).json()) as Record<string, any>;
    expect(info.wallets).toContain('Paradym');
    expect(info.variants).toEqual([
      { clientIdPrefix: 'redirect_uri', requestMode: 'value' },
      { clientIdPrefix: 'redirect_uri', requestMode: 'reference' },
      { clientIdPrefix: 'legacy_redirect_uri', requestMode: 'value' },
      { clientIdPrefix: 'legacy_redirect_uri', requestMode: 'reference' },
    ]);
  });

  it('requires a long token when enabled', async () => {
    await expect(normalizeConfig({ publicUrl: PUBLIC_URL, trustAnchors: [{ entityId: 'https://ta.example' }], credentialTypes: svc.config.credentialTypes, compat: { enabled: true } })).rejects.toThrow(/compat.token/);
  });
});

describe('recording', () => {
  it('records a working wallet with protocol diagnostics and no claim values', async () => {
    const s = await runVariant('reference');
    expect(s.wallet_url).toContain('request_uri=');
    await svc.wallet(s.wallet_url!, true, { userAgent: 'ParadymWallet/1.2 (iOS)' });
    const rec = await save(s.session_id!, { wallet_version: '1.2', notes: 'showed verifier URL' });
    expect(rec).toMatchObject({
      wallet: 'Paradym',
      walletVersion: '1.2',
      credentialType: 'pension',
      variant: { clientIdPrefix: 'redirect_uri', requestMode: 'reference' },
      verdict: 'works',
      outcome: 'accepted',
      credentialAccepted: true,
      notes: 'showed verifier URL',
      diagnostics: {
        requestUserAgent: 'ParadymWallet/1.2 (iOS)',
        vpTokenShape: 'json-string(object{pension:array[1]})',
        presentationCount: 1,
        hasKeyBinding: true,
        kbJwtTyp: 'kb+jwt',
        kbJwtAud: `redirect_uri:${PUBLIC_URL}/oid4vp/response`,
      },
    });
    expect(rec.diagnostics.requestFetchedAt).toBeDefined();
    expect(JSON.stringify(rec)).not.toContain('010101-123N');
    expect(await readFile(resultsFile, 'utf8')).not.toContain('010101-123N');
  });

  it('counts the protocol as working when only the credential is rejected (e.g. untrusted issuer)', async () => {
    const s = await runVariant('value');
    await svc.wallet(s.wallet_url!, true, { iss: 'https://untrusted.example' });
    const rec = await save(s.session_id!);
    expect(rec).toMatchObject({ verdict: 'works', credentialAccepted: false, failedCheck: 'issuer_trust', outcome: 'rejected' });
  });

  it('marks protocol errors as failed and keeps the audience the wallet used', async () => {
    const s = await runVariant('value');
    await svc.wallet(s.wallet_url!, true, { aud: `${PUBLIC_URL}/oid4vp/response-typo` });
    const rec = await save(s.session_id!);
    expect(rec).toMatchObject({ verdict: 'failed', failedCheck: 'key_binding', diagnostics: { kbJwtAud: `${PUBLIC_URL}/oid4vp/response-typo` } });
  });

  it('marks wallet error responses as failed', async () => {
    const s = await runVariant('value');
    await svc.wallet(s.wallet_url!, true, { error: 'invalid_request' });
    expect(await save(s.session_id!)).toMatchObject({ verdict: 'failed', walletError: { error: 'invalid_request' }, diagnostics: { vpTokenShape: 'error' } });
  });

  it('accepts a manual verdict for wallets that never respond', async () => {
    const s = await runVariant('reference');
    const rec = await save(s.session_id!, { verdict: 'wallet_refused', notes: 'Unsupported QR code' });
    expect(rec).toMatchObject({ verdict: 'wallet_refused', status: 'pending', notes: 'Unsupported QR code' });
    expect(rec.diagnostics).toBeUndefined();
  });

  it('only records compatibility sessions, and needs a wallet name', async () => {
    const apiSession = (await (
      await svc.app.request('/api/sessions', { method: 'POST', headers: { authorization: `Bearer ${API_KEY}`, 'content-type': 'application/json' }, body: JSON.stringify({ reference: 'compat' }) })
    ).json()) as Record<string, string>;
    expect((await compat('/results', { method: 'POST', body: JSON.stringify({ session_id: apiSession.session_id, wallet: 'X' }) })).status).toBe(400);
    const s = await runVariant('value');
    expect((await compat('/results', { method: 'POST', body: JSON.stringify({ session_id: s.session_id }) })).status).toBe(400);
  });

  it('persists results to the file, lists and deletes them', async () => {
    const s = await runVariant('value');
    await svc.wallet(s.wallet_url!);
    const rec = await save(s.session_id!);
    expect(await new CompatStore(resultsFile).all()).toHaveLength(1);
    const listed = (await (await compat('/results')).json()) as unknown[];
    expect(listed).toHaveLength(1);
    expect((await compat(`/results/${rec.id}`, { method: 'DELETE' })).status).toBe(204);
    expect(await new CompatStore(resultsFile).all()).toHaveLength(0);
  });
});

describe('describeVpToken', () => {
  it('describes structure without content', () => {
    expect(describeVpToken({ pension: ['eyJ...~'] })).toBe('object{pension:array[1]}');
    expect(describeVpToken({ pension: 'eyJ...~' })).toBe('object{pension:string}');
    expect(describeVpToken('eyJ...~')).toBe('string');
    expect(describeVpToken('["a"]')).toBe('json-string(array[1])');
  });
});
