/**
 * <credential-verifier> web component.
 *
 * Attributes
 *   server         Base URL of the verifier service (default: where this script was loaded from)
 *   mode           "embedded" (default) or "kiosk" (full screen, loops, never offers same-device options)
 *   session-id, session-token   A session created by your backend via POST /api/sessions
 *   start-url      Alternatively, a URL the component POSTs to for { session_id, browser_token }
 *                  (your backend, or the service's kiosk endpoint; kiosk mode uses that by default)
 *   lang           fi | sv | en (default: page language)
 *   sound          on | off (default: on in kiosk mode)
 *   page-feedback  on | off: colour the whole page by the result (default: on in kiosk mode)
 *   reset-after    Seconds before starting over after a result (kiosk default from server config)
 *
 * Events (bubbling, composed)
 *   verification-status  detail: PublicSession (every status change)
 *   verification-result  detail: PublicSession (final state; check the signed result on your backend)
 */
import { dcApiSupported, HttpError, VerifierApi, type PublicConfig, type PublicSession, type SessionRef } from './api.js';
import { formatDate, label, pickLang, t, type Lang, type MessageKey } from './i18n.js';
import { qrSvg } from './qr.js';
import { Sound } from './sound.js';
import { STYLES } from './styles.js';

const SCRIPT_ORIGIN = (() => {
  try {
    return new URL(import.meta.url).origin;
  } catch {
    return location.origin;
  }
})();

type View =
  | { kind: 'start' }
  | { kind: 'loading' }
  | { kind: 'session'; session: PublicSession }
  | { kind: 'connection_error' };

const TERMINAL = new Set(['completed', 'failed', 'expired', 'awaiting_return']);
const STORAGE_PREFIX = 'credential-verifier:';

export class CredentialVerifierElement extends HTMLElement {
  static observedAttributes = ['session-id', 'session-token', 'lang'];

  private readonly root: ShadowRoot;
  private api!: VerifierApi;
  private config?: PublicConfig;
  private ref?: SessionRef;
  private responseCode?: string;
  private view: View = { kind: 'loading' };
  private abort?: AbortController;
  private resetTimer?: ReturnType<typeof setTimeout>;
  private readonly sound = new Sound();
  private savedPageBackground?: string;
  private dcApiBusy = false;
  private notice?: string;
  private connected = false;

  constructor() {
    super();
    this.root = this.attachShadow({ mode: 'open' });
    this.root.addEventListener('click', (e) => this.onClick(e));
  }

  get kiosk(): boolean {
    return this.getAttribute('mode') === 'kiosk';
  }

  private get lang_(): Lang {
    return pickLang(this.getAttribute('lang'), document.documentElement.lang, navigator.language);
  }

  private flag(name: string, kioskDefault: boolean): boolean {
    const v = this.getAttribute(name);
    return v === null ? this.kiosk && kioskDefault : v !== 'off' && v !== 'false';
  }

  private get startUrl(): string | undefined {
    const attr = this.getAttribute('start-url');
    if (attr) return new URL(attr, location.href).toString();
    return this.kiosk ? `${this.api.server}/public/kiosk/sessions` : undefined;
  }

  connectedCallback(): void {
    this.connected = true;
    this.api = new VerifierApi((this.getAttribute('server') ?? SCRIPT_ORIGIN).replace(/\/+$/, ''));
    this.setAttribute('data-mode', this.kiosk ? 'kiosk' : 'embedded');
    void this.boot();
  }

  disconnectedCallback(): void {
    this.connected = false;
    this.abort?.abort();
    clearTimeout(this.resetTimer);
    this.restorePage();
  }

  attributeChangedCallback(name: string, oldValue: string | null, newValue: string | null): void {
    if (!this.connected || oldValue === newValue) return;
    if (name === 'lang') this.render();
    else if (this.getAttribute('session-id') && this.getAttribute('session-token')) void this.run();
  }

  /** Starts over with a fresh session (kiosk reset, "try again"). */
  restart(): void {
    clearTimeout(this.resetTimer);
    this.restorePage();
    this.ref = undefined;
    this.responseCode = undefined;
    void this.run();
  }

  private async boot(): Promise<void> {
    this.render();
    try {
      this.config = await this.api.config();
    } catch {
      /* the component still works without labels and kiosk defaults */
    }
    this.consumeReturnFragment();
    if (this.kiosk && this.flag('sound', true) && !this.sound.ready) {
      this.view = { kind: 'start' };
      this.render();
      return;
    }
    void this.run();
  }

  /** After a same-device flow the wallet returns here with #verifier_session=…&response_code=… */
  private consumeReturnFragment(): void {
    const frag = new URLSearchParams(location.hash.slice(1));
    const id = frag.get('verifier_session');
    const code = frag.get('response_code');
    if (!id || !code) return;
    let token: string | null = null;
    try {
      token = sessionStorage.getItem(STORAGE_PREFIX + id);
    } catch {
      /* storage blocked */
    }
    if (!token) return;
    this.ref = { id, token };
    this.responseCode = code;
    frag.delete('verifier_session');
    frag.delete('response_code');
    const rest = frag.toString();
    history.replaceState(history.state, '', location.pathname + location.search + (rest ? `#${rest}` : ''));
  }

  private async run(): Promise<void> {
    this.abort?.abort();
    const abort = (this.abort = new AbortController());
    this.notice = undefined;
    this.view = { kind: 'loading' };
    this.render();

    let failures = 0;
    while (!abort.signal.aborted) {
      try {
        if (!this.ref) this.ref = await this.obtainSession(abort.signal);
        if (!this.ref) return; // nothing to show yet: waiting for attributes
        const prev = this.view.kind === 'session' ? this.view.session.status : undefined;
        const session = await this.api.status(this.ref, { wait: prev ? 25 : 0, since: prev, responseCode: this.responseCode, signal: abort.signal });
        this.responseCode = undefined;
        failures = 0;
        if (abort.signal.aborted) return;
        if (session.status !== prev || this.view.kind !== 'session') {
          this.view = { kind: 'session', session };
          this.render();
          this.emit('verification-status', session);
        }
        if (TERMINAL.has(session.status)) {
          this.finish(session);
          return;
        }
      } catch (e) {
        if (abort.signal.aborted) return;
        if (e instanceof HttpError && e.status === 404 && this.ref) {
          // Session unknown (expired and swept): start over where possible.
          this.ref = undefined;
          if (!this.startUrl) {
            this.view = { kind: 'session', session: { id: '', status: 'expired', expiresAt: new Date().toISOString() } };
            this.render();
            return;
          }
          continue;
        }
        failures++;
        this.view = { kind: 'connection_error' };
        this.render();
        await sleep(Math.min(30000, 1000 * 2 ** Math.min(failures, 5)), abort.signal);
      }
    }
  }

  private async obtainSession(signal: AbortSignal): Promise<SessionRef | undefined> {
    const id = this.getAttribute('session-id');
    const token = this.getAttribute('session-token');
    if (id && token) return { id, token };
    const startUrl = this.startUrl;
    return startUrl ? this.api.start(startUrl, signal) : undefined;
  }

  private finish(session: PublicSession): void {
    const outcome = resultKind(session);
    if (outcome === 'expired' && this.kiosk) {
      this.restart(); // silently show a fresh code
      return;
    }
    if (this.flag('sound', true)) {
      if (outcome === 'accepted') this.sound.success();
      else if (outcome === 'rejected') this.sound.failure();
      else this.sound.notice();
    }
    if (this.flag('page-feedback', true)) this.colourPage(outcome);
    this.emit('verification-result', session);

    const resetAfter = Number(this.getAttribute('reset-after') ?? (this.kiosk ? this.config?.kiosk.resetAfterSeconds ?? 8 : 0));
    if (resetAfter > 0 && this.startUrl) this.resetTimer = setTimeout(() => this.restart(), resetAfter * 1000);
  }

  private async useDcApi(): Promise<void> {
    if (!this.ref || this.dcApiBusy) return;
    this.dcApiBusy = true;
    this.notice = undefined;
    this.render();
    try {
      const request = await this.api.dcApiRequest(this.ref);
      const credential = (await navigator.credentials.get({ digital: { requests: [request] }, mediation: 'required' } as CredentialRequestOptions)) as
        | (Credential & { data?: unknown })
        | null;
      if (credential?.data !== undefined) await this.api.dcApiResponse(this.ref, credential.data);
    } catch (e) {
      const name = (e as Error).name;
      if (name !== 'AbortError' && name !== 'NotAllowedError') this.notice = (e as Error).message;
    } finally {
      this.dcApiBusy = false;
      this.render();
    }
  }

  private onClick(e: Event): void {
    const target = (e.target as Element).closest('[data-action]');
    this.sound.unlock(); // any interaction may enable audio
    if (!target) return;
    const action = target.getAttribute('data-action');
    if (action === 'start') void this.run();
    else if (action === 'retry') this.restart();
    else if (action === 'dc-api') void this.useDcApi();
    else if (action === 'same-device' && this.ref) {
      try {
        sessionStorage.setItem(STORAGE_PREFIX + this.ref.id, this.ref.token);
      } catch {
        /* storage blocked: the result will still reach the backend */
      }
    }
  }

  private emit(type: string, detail: PublicSession): void {
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
  }

  private colourPage(outcome: string): void {
    const colour = getComputedStyle(this).getPropertyValue(`--cv-${outcome}`).trim() || { accepted: '#1a7f37', rejected: '#c62828' }[outcome] || '#b45309';
    this.savedPageBackground ??= document.body.style.backgroundColor;
    document.body.style.transition = 'background-color 200ms ease-out';
    document.body.style.backgroundColor = colour;
  }

  private restorePage(): void {
    if (this.savedPageBackground === undefined) return;
    document.body.style.backgroundColor = this.savedPageBackground;
    this.savedPageBackground = undefined;
  }

  // ---------- rendering ----------

  private render(): void {
    const L = this.lang_;
    const tr = (k: MessageKey, v?: Record<string, string>) => t(L, k, v);
    let state = 'neutral';
    let body: string;

    switch (this.view.kind) {
      case 'start':
        body = `<button class="primary big" data-action="start" part="button">${esc(tr('start'))}</button>`;
        break;
      case 'loading':
        body = `<div class="spinner" aria-hidden="true"></div><p class="status">${esc(tr('loading'))}</p>`;
        break;
      case 'connection_error':
        state = 'error';
        body = `<div class="icon" aria-hidden="true">!</div><h2>${esc(tr('connection_error'))}</h2>`;
        break;
      case 'session': {
        const s = this.view.session;
        if (!TERMINAL.has(s.status)) {
          body = s.status === 'processing' ? this.renderVerifying(L) : this.renderWaiting(s, L);
        } else {
          state = resultKind(s);
          body = this.renderResult(s, L);
        }
        break;
      }
    }

    this.setAttribute('data-state', state);
    this.root.innerHTML = `<style>${STYLES}</style><div class="card" part="card" data-state="${state}"><div class="live" role="status" aria-live="polite">${body}</div></div>`;
  }

  private renderWaiting(s: PublicSession, L: Lang): string {
    const types = (s.acceptedTypes ?? []).map((id) => label(this.config?.credentialTypes.find((c) => c.id === id)?.label, L, id)).join(', ');
    const qr = s.walletUrl ? `<a class="qr" part="qr" href="${escAttr(s.walletUrl)}" aria-label="${escAttr(t(L, 'scan'))}">${qrSvg(s.walletUrl)}</a>` : '';
    const sameDevice = !this.kiosk && s.sameDeviceWalletUrl;
    const dcApi = !this.kiosk && this.config?.dcApi.enabled !== false && dcApiSupported();
    const buttons = [
      dcApi ? `<button class="primary" data-action="dc-api" part="button" ${this.dcApiBusy ? 'disabled' : ''}>${esc(t(L, 'dc_api'))}</button>` : '',
      sameDevice ? `<a class="button${dcApi ? '' : ' primary'}" data-action="same-device" part="button" href="${escAttr(s.sameDeviceWalletUrl!)}">${esc(t(L, 'open_wallet'))}</a>` : '',
    ].join('');
    return `
      <h2>${esc(t(L, 'scan'))}</h2>
      ${qr}
      ${types ? `<p class="hint">${esc(t(L, 'accepted_types', { types }))}</p>` : ''}
      ${buttons ? `<div class="buttons">${buttons}</div>` : ''}
      ${s.status === 'request_retrieved' ? `<p class="status">${esc(t(L, 'waiting'))}</p>` : ''}
      ${this.notice ? `<p class="notice">${esc(this.notice)}</p>` : ''}`;
  }

  private renderVerifying(L: Lang): string {
    return `<div class="spinner" aria-hidden="true"></div><p class="status big-text">${esc(t(L, 'verifying'))}</p>`;
  }

  private renderResult(s: PublicSession, L: Lang): string {
    const kind = resultKind(s);
    const retry = !this.kiosk && (this.startUrl || kind === 'expired') ? `<button class="button" data-action="retry" part="button">${esc(t(L, 'try_again'))}</button>` : '';
    if (s.status === 'awaiting_return') return `<p class="status">${esc(t(L, 'awaiting_return'))}</p>`;
    if (kind === 'accepted') {
      const typeLabel = label(s.label, L, s.credentialType ?? '');
      const until = s.validUntil ? t(L, 'valid_until', { date: formatDate(s.validUntil, L) }) : '';
      return `
        <div class="icon" aria-hidden="true">✓</div>
        <h2 class="result-title">${esc(t(L, 'accepted'))}</h2>
        <p class="result-type">${esc(typeLabel)}</p>
        ${until ? `<p class="valid-until">${esc(until)}</p>` : ''}
        ${s.issuer?.name ? `<p class="issuer">${esc(t(L, 'issued_by', { issuer: s.issuer.name }))}</p>` : ''}`;
    }
    const [titleKey, hintKey]: [MessageKey, MessageKey | undefined] =
      kind === 'rejected' ? ['rejected', 'rejected_hint'] : kind === 'expired' ? ['expired', undefined] : kind === 'wallet_error' ? ['wallet_error', undefined] : ['error', 'error_hint'];
    return `
      <div class="icon" aria-hidden="true">${kind === 'rejected' ? '✗' : '!'}</div>
      <h2 class="result-title">${esc(t(L, titleKey))}</h2>
      ${hintKey ? `<p>${esc(t(L, hintKey))}</p>` : ''}
      ${s.reason ? `<details><summary>${esc(t(L, 'details'))}</summary><p class="reason">${esc(s.reason)}</p></details>` : ''}
      ${retry}`;
  }
}

/** accepted | rejected | error | wallet_error | expired */
function resultKind(s: PublicSession): string {
  if (s.status === 'expired') return 'expired';
  if (s.status === 'failed') return 'wallet_error';
  if (s.status === 'awaiting_return') return 'neutral';
  return s.outcome ?? 'error';
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
}
const escAttr = esc;

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => (clearTimeout(timer), resolve()), { once: true });
  });
}

if (!customElements.get('credential-verifier')) customElements.define('credential-verifier', CredentialVerifierElement);
