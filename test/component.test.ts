// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { API_KEY, createTestService, PUBLIC_URL } from './helpers/service.js';
import '../src/web/verifier-element.js';

type Service = Awaited<ReturnType<typeof createTestService>>;
let svc: Service;

beforeEach(async () => {
  svc = await createTestService();
  (window as any).happyDOM?.setURL(`${PUBLIC_URL}/kiosk.html`);
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => svc.app.request(String(input), init));
  document.body.innerHTML = '';
  document.body.style.backgroundColor = '';
  sessionStorage.clear();
});

afterEach(() => {
  document.body.innerHTML = '';
  vi.unstubAllGlobals();
  delete (window as any).DigitalCredential;
});

function mount(attrs: Record<string, string>) {
  const el = document.createElement('credential-verifier');
  for (const [k, v] of Object.entries({ server: PUBLIC_URL, lang: 'en', ...attrs })) el.setAttribute(k, v);
  const events: { type: string; detail: any }[] = [];
  for (const type of ['verification-status', 'verification-result']) el.addEventListener(type, (e) => events.push({ type, detail: (e as CustomEvent).detail }));
  document.body.append(el);
  return { el, events, shadow: el.shadowRoot! };
}

async function until<T>(fn: () => T | undefined | null | false, timeoutMs = 3000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for condition');
    await new Promise((r) => setTimeout(r, 10));
  }
}

const qrLink = (shadow: ShadowRoot) => shadow.querySelector<HTMLAnchorElement>('a.qr')?.getAttribute('href');

async function createApiSession(body: object) {
  const res = await svc.app.request('/api/sessions', { method: 'POST', headers: { authorization: `Bearer ${API_KEY}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return (await res.json()) as Record<string, string>;
}

describe('kiosk mode', () => {
  it('asks for a tap first when sound is on, to unlock audio', async () => {
    const { shadow } = mount({ mode: 'kiosk' });
    const start = await until(() => shadow.querySelector<HTMLButtonElement>('[data-action="start"]'));
    expect(start.textContent).toBe('Tap to start');
    start.click();
    expect(await until(() => qrLink(shadow))).toMatch(/^openid4vp:\/\//);
  });

  it('shows a QR code, turns the page green on success, then starts over', async () => {
    const { el, shadow, events } = mount({ mode: 'kiosk', sound: 'off', 'reset-after': '0.2' });
    const link = await until(() => qrLink(shadow));
    expect(shadow.querySelector('svg path')).not.toBeNull();
    expect(shadow.textContent).toContain('Accepted credentials: Pensioner');
    // Kiosk never offers same-device options
    expect(shadow.querySelector('[data-action="same-device"], [data-action="dc-api"]')).toBeNull();

    await svc.wallet(link!);
    await until(() => el.getAttribute('data-state') === 'accepted');
    expect(shadow.querySelector('.result-title')?.textContent).toBe('Accepted');
    expect(shadow.querySelector('.result-type')?.textContent).toBe('Pensioner');
    expect(shadow.querySelector('.issuer')?.textContent).toBe('Issued by Kela');
    expect(document.body.style.backgroundColor).not.toBe('');
    expect(events.find((e) => e.type === 'verification-result')?.detail).toMatchObject({ outcome: 'accepted', credentialType: 'pension' });
    expect(JSON.stringify(events)).not.toContain('010101-123N');

    const next = await until(() => (qrLink(shadow) !== link ? qrLink(shadow) : undefined));
    expect(next).toMatch(/^openid4vp:\/\//);
    expect(el.getAttribute('data-state')).toBe('neutral');
    expect(document.body.style.backgroundColor).toBe('');
  });

  it('shows a red result with details when the credential is not accepted', async () => {
    const { el, shadow } = mount({ mode: 'kiosk', sound: 'off', 'reset-after': '0' });
    await svc.wallet((await until(() => qrLink(shadow)))!, false);
    await until(() => el.getAttribute('data-state') === 'rejected');
    expect(shadow.querySelector('.result-title')?.textContent).toBe('Not accepted');
    expect(shadow.querySelector('.reason')?.textContent).toMatch(/Voimassa/);
  });

  it('never shows the DC API button, even when the browser supports it', async () => {
    (window as any).DigitalCredential = { userAgentAllowsProtocol: () => true };
    vi.stubGlobal('navigator', { ...navigator, credentials: { get: async () => null } });
    // Sanity check: the same browser setup does show the button in embedded mode.
    const s = await createApiSession({});
    const embedded = mount({ 'session-id': s.session_id!, 'session-token': s.browser_token! });
    await until(() => embedded.shadow.querySelector('[data-action="dc-api"]'));
    embedded.el.remove();

    const { shadow } = mount({ mode: 'kiosk', sound: 'off' });
    await until(() => qrLink(shadow));
    expect(shadow.querySelector('[data-action="dc-api"]')).toBeNull();
  });

  it('hides the same-device link even if handed a session that has one', async () => {
    const s = await createApiSession({ return_url: `${PUBLIC_URL}/checkout` });
    const { shadow } = mount({ mode: 'kiosk', sound: 'off', 'session-id': s.session_id!, 'session-token': s.browser_token! });
    await until(() => qrLink(shadow));
    expect(shadow.querySelector('[data-action="same-device"]')).toBeNull();
  });

  it('localises the texts', async () => {
    const { shadow } = mount({ mode: 'kiosk', sound: 'off', lang: 'fi' });
    await until(() => qrLink(shadow));
    expect(shadow.textContent).toContain('Skannaa lompakkosovelluksella');
    expect(shadow.textContent).toContain('Hyväksytyt todisteet: Eläkeläinen');
  });
});

describe('embedded mode', () => {
  it('uses a session from the backend and offers the same-device link', async () => {
    const s = await createApiSession({ return_url: `${PUBLIC_URL}/checkout` });
    const { el, shadow } = mount({ 'session-id': s.session_id!, 'session-token': s.browser_token! });
    const link = await until(() => shadow.querySelector<HTMLAnchorElement>('[data-action="same-device"]'));
    expect(link.getAttribute('href')).toBe(s.same_device_wallet_url);
    expect(el.getAttribute('data-state')).toBe('neutral');
    // Embedded mode does not colour the page unless asked to
    await svc.wallet(qrLink(shadow)!);
    await until(() => el.getAttribute('data-state') === 'accepted');
    expect(document.body.style.backgroundColor).toBe('');
  });

  it('completes the same-device flow after the wallet returns to the page', async () => {
    const s = await createApiSession({ return_url: `${PUBLIC_URL}/checkout` });
    const first = mount({ 'session-id': s.session_id!, 'session-token': s.browser_token! });
    (await until(() => first.shadow.querySelector<HTMLAnchorElement>('[data-action="same-device"]'))).dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true }));
    first.el.remove();

    const { redirect_uri } = await svc.wallet(s.same_device_wallet_url!);
    // The browser comes back to the return URL with the response code in the fragment.
    (window as any).happyDOM.setURL(redirect_uri);
    const { el, shadow } = mount({});
    await until(() => el.getAttribute('data-state') === 'accepted');
    expect(shadow.querySelector('.result-title')?.textContent).toBe('Accepted');
    expect(location.hash).toBe('');
  });

  it('uses the Digital Credentials API when the browser supports it', async () => {
    const s = await createApiSession({});
    let request: any;
    (window as any).DigitalCredential = { userAgentAllowsProtocol: (p: string) => p === 'openid4vp-v1-unsigned' };
    vi.stubGlobal('navigator', {
      ...navigator,
      language: 'en',
      credentials: {
        get: async (opts: any) => {
          request = opts.digital.requests[0];
          return { data: await svc.dcPresentation(request) };
        },
      },
    });
    const { el, shadow } = mount({ 'session-id': s.session_id!, 'session-token': s.browser_token! });
    (await until(() => shadow.querySelector<HTMLButtonElement>('[data-action="dc-api"]'))).click();
    await until(() => el.getAttribute('data-state') === 'accepted');
    expect(request.protocol).toBe('openid4vp-v1-unsigned');
  });

  it('stays usable when the user cancels the wallet dialog', async () => {
    const s = await createApiSession({});
    (window as any).DigitalCredential = {};
    vi.stubGlobal('navigator', { ...navigator, credentials: { get: async () => Promise.reject(Object.assign(new Error('cancelled'), { name: 'NotAllowedError' })) } });
    const { shadow } = mount({ 'session-id': s.session_id!, 'session-token': s.browser_token! });
    (await until(() => shadow.querySelector<HTMLButtonElement>('[data-action="dc-api"]'))).click();
    await new Promise((r) => setTimeout(r, 50));
    expect(qrLink(shadow)).toMatch(/^openid4vp/);
    expect(shadow.querySelector('.notice')).toBeNull();
  });

  it('shows a connection error and recovers', async () => {
    let fail = true;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => (fail ? Promise.reject(new TypeError('offline')) : svc.app.request(String(input), init)));
    const { el, shadow } = mount({ mode: 'kiosk', sound: 'off' });
    await until(() => el.getAttribute('data-state') === 'error');
    expect(shadow.textContent).toContain('Cannot reach the verification service.');
    fail = false;
    expect(await until(() => qrLink(shadow), 5000)).toMatch(/^openid4vp/);
  });
});
