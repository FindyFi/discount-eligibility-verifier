/** Client for the verifier service's browser endpoints. */

export interface SessionRef {
  id: string;
  token: string;
}

export interface PublicSession {
  id: string;
  status: 'pending' | 'request_retrieved' | 'processing' | 'completed' | 'failed' | 'expired' | 'awaiting_return';
  outcome?: 'accepted' | 'rejected' | 'error';
  credentialType?: string;
  label?: Record<string, string>;
  issuer?: { name?: string; logoUri?: string };
  claims?: Record<string, unknown>;
  validUntil?: string;
  reason?: string;
  expiresAt: string;
  acceptedTypes?: string[];
  walletUrl?: string;
  sameDeviceWalletUrl?: string;
}

export interface PublicConfig {
  kiosk: { enabled: boolean; acceptedTypes?: string[]; resetAfterSeconds: number };
  dcApi: { enabled: boolean };
  credentialTypes: { id: string; label?: Record<string, string> }[];
}

export class VerifierApi {
  constructor(readonly server: string) {}

  async config(signal?: AbortSignal): Promise<PublicConfig> {
    return this.json(`${this.server}/public/config`, { signal });
  }

  /** POSTs to a session starter (the kiosk endpoint or a service provider's own backend). */
  async start(startUrl: string, signal?: AbortSignal): Promise<SessionRef> {
    const sameOrigin = new URL(startUrl, location.href).origin === location.origin;
    const body = await this.json<Record<string, string>>(startUrl, { method: 'POST', signal, credentials: sameOrigin ? 'include' : 'omit' });
    const id = body.session_id ?? body.sessionId ?? body.id;
    const token = body.browser_token ?? body.browserToken ?? body.token;
    if (!id || !token) throw new Error('start-url did not return session_id and browser_token');
    return { id, token };
  }

  async status(s: SessionRef, opts: { wait?: number; since?: string; responseCode?: string; signal?: AbortSignal } = {}): Promise<PublicSession> {
    const q = new URLSearchParams();
    if (opts.wait) q.set('wait', String(opts.wait));
    if (opts.since) q.set('since', opts.since);
    if (opts.responseCode) q.set('response_code', opts.responseCode);
    return this.json(`${this.server}/public/sessions/${encodeURIComponent(s.id)}?${q}`, { headers: { 'x-session-token': s.token }, signal: opts.signal });
  }

  async dcApiRequest(s: SessionRef): Promise<{ protocol: string; data: unknown }> {
    return this.json(`${this.server}/public/sessions/${encodeURIComponent(s.id)}/dc-api/request`, { method: 'POST', headers: { 'x-session-token': s.token } });
  }

  async dcApiResponse(s: SessionRef, data: unknown): Promise<PublicSession> {
    return this.json(`${this.server}/public/sessions/${encodeURIComponent(s.id)}/dc-api/response`, {
      method: 'POST',
      headers: { 'x-session-token': s.token, 'content-type': 'application/json' },
      body: JSON.stringify({ data }),
    });
  }

  private async json<T>(url: string, init: RequestInit): Promise<T> {
    const res = await fetch(url, init);
    if (!res.ok) throw new HttpError(res.status, await res.text().catch(() => ''));
    return res.json() as Promise<T>;
  }
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    body: string,
  ) {
    super(`HTTP ${status}${body ? `: ${body.slice(0, 200)}` : ''}`);
  }
}

/** Whether this browser can ask a wallet through the Digital Credentials API with unsigned OpenID4VP. */
export function dcApiSupported(): boolean {
  const DC = (globalThis as { DigitalCredential?: { userAgentAllowsProtocol?: (p: string) => boolean } }).DigitalCredential;
  if (!DC || !navigator.credentials) return false;
  try {
    return typeof DC.userAgentAllowsProtocol === 'function' ? DC.userAgentAllowsProtocol('openid4vp-v1-unsigned') : true;
  } catch {
    return false;
  }
}
