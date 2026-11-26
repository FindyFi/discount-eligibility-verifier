/**
 * HTTP API of the verifier service.
 *
 *   Integration API (service provider backends, Bearer API key)
 *     POST /api/sessions                      create a verification session
 *     GET  /api/sessions/:id                  status and signed result
 *   Browser endpoints (web component / kiosk page, session token)
 *     POST /public/kiosk/sessions             create a session from the kiosk page (if enabled)
 *     GET  /public/sessions/:id               status for display (long-poll with ?wait=<s>)
 *     POST /public/sessions/:id/dc-api/request   Digital Credentials API request
 *     POST /public/sessions/:id/dc-api/response  Digital Credentials API response
 *     GET  /public/config                     UI settings
 *   Wallet endpoints (OpenID4VP)
 *     GET  /oid4vp/request/:state             request object (request_uri)
 *     POST /oid4vp/response                   direct_post response
 *   Other
 *     GET  /.well-known/openid-federation     the verifier's entity configuration (if federation is configured)
 *     GET  /.well-known/jwks.json             keys for verifying result JWTs
 *     GET  /healthz
 */
import { timingSafeEqual } from 'node:crypto';
import { Hono, type Context } from 'hono';
import { cors } from 'hono/cors';
import { Verifier, type CredentialTypePolicy, type Fetcher, type VerificationResult } from '../core/index.js';
import { CLIENT_ID_PREFIXES, type ApiClient, type ClientIdPrefix, type ServiceConfig } from './config.js';
import { VerifierDid } from './did-entity.js';
import { CompatStore, deriveVerdict, describeVpToken, keyBindingDiagnostics, type Variant } from './compat.js';
import { VerifierEntity } from './federation-entity.js';
import {
  authorizationRequestParams,
  dcApiRequest,
  extractPresentations,
  isSignedPrefix,
  originAudiences,
  presentationAudiences,
  requestObjectClaims,
  unsignedRequestObject,
  walletUrl,
} from './oid4vp.js';
import { deliverWebhook, publicView, resultPayload, type ResultSigner } from './results.js';
import { isTerminal, randomToken, type Flow, type Session, type SessionStore } from './sessions.js';

export interface AppDeps {
  config: ServiceConfig;
  store: SessionStore;
  signer: ResultSigner;
  verifier?: Verifier;
  /** The verifier's federation entity; created from config.federation when omitted. */
  entity?: Promise<VerifierEntity>;
  /** The verifier's did:web identity; created from config.didWeb when omitted. */
  did?: Promise<VerifierDid>;
  fetch?: Fetcher;
  log?: (msg: string) => void;
}

export function createApp(deps: AppDeps) {
  const { config, store, signer } = deps;
  const log = deps.log ?? ((m: string) => console.log(`[verifier] ${m}`));
  const fetcher: Fetcher = deps.fetch ?? ((u, i) => fetch(u, i));
  const verifier =
    deps.verifier ??
    new Verifier({
      trustAnchors: config.trustAnchors,
      credentialTypes: config.credentialTypes,
      timeZone: config.timeZone,
      allowJwtVcIssuerMetadata: config.allowJwtVcIssuerMetadata,
      trustedDidIssuers: config.trustedDidIssuers,
      fetch: deps.fetch,
    });
  const entity = deps.entity ?? (config.federation ? VerifierEntity.create(config, verifier.federation, log) : undefined);
  const did = deps.did ?? (config.didWeb ? VerifierDid.create(config) : undefined);
  const policiesFor = (s: Session): CredentialTypePolicy[] => config.credentialTypes.filter((p) => s.acceptedTypes.includes(p.id));
  const selfOrigin = new URL(config.publicUrl).origin;
  const browserOrigins = new Set([
    selfOrigin,
    ...config.corsOrigins,
    ...config.dcApi.allowedOrigins,
    ...config.apiClients.flatMap((c) => c.allowedOrigins ?? []),
  ]);

  const app = new Hono();

  app.use('/public/*', cors({ origin: (o) => (browserOrigins.has(o) ? o : null), allowMethods: ['GET', 'POST'], allowHeaders: ['content-type', 'x-session-token'] }));
  app.use('/oid4vp/*', cors({ origin: '*' }));

  app.onError((err, c) => {
    log(`unhandled error on ${c.req.method} ${c.req.path}: ${err.message}`);
    return c.json({ error: 'server_error' }, 500);
  });

  app.get('/healthz', (c) => c.json({ ok: true }));
  app.get('/.well-known/jwks.json', (c) => c.json(signer.publicJwks));
  app.get('/.well-known/openid-federation', async (c) => {
    if (!entity) return c.json({ error: 'not_found' }, 404);
    return c.body(await (await entity).entityConfiguration(), 200, { 'content-type': 'application/entity-statement+jwt' });
  });

  app.get('/.well-known/did.json', async (c) => {
    if (!did) return c.json({ error: 'not_found' }, 404);
    return c.body(JSON.stringify((await did).didDocument()), 200, { 'content-type': 'application/did+json' });
  });

  // ---------- Integration API ----------

  const authenticate = (c: Context): ApiClient | undefined => {
    const m = /^Bearer\s+(.+)$/i.exec(c.req.header('authorization') ?? '');
    if (!m) return undefined;
    const presented = Buffer.from(m[1]!.trim());
    return config.apiClients.find((cl) => {
      const expected = Buffer.from(cl.apiKey);
      return expected.length === presented.length && timingSafeEqual(expected, presented);
    });
  };

  app.post('/api/sessions', async (c) => {
    const client = authenticate(c);
    if (!client) return c.json({ error: 'unauthorized' }, 401);
    const body = await readJson(c);
    const accepted = resolveAcceptedTypes(body.accepted_types ?? body.acceptedTypes);
    if (!accepted.ok) return c.json({ error: 'invalid_request', error_description: accepted.error }, 400);
    const prefix = resolvePrefix(body.client_id_prefix ?? body.clientIdPrefix);
    if (!prefix.ok) return c.json({ error: 'invalid_request', error_description: prefix.error }, 400);
    const returnUrl = body.return_url ?? body.returnUrl;
    if (returnUrl !== undefined && !isAllowedReturnUrl(returnUrl, client)) {
      return c.json({ error: 'invalid_request', error_description: 'return_url is not allowed for this client' }, 400);
    }
    const session = await newSession({ apiClientId: client.id, reference: optionalString(body.reference), acceptedTypes: accepted.types, returnUrl, clientIdPrefix: prefix.prefix });
    log(`session ${session.id} created by ${client.id} for ${accepted.types.join('|')}`);
    return c.json(sessionCreatedResponse(session), 201);
  });

  app.get('/api/sessions/:id', async (c) => {
    const client = authenticate(c);
    if (!client) return c.json({ error: 'unauthorized' }, 401);
    const s = await store.get(c.req.param('id'));
    if (!s || s.apiClientId !== client.id) return c.json({ error: 'not_found' }, 404);
    await waitIfAsked(c, s, true);
    const fresh = (await store.get(s.id))!;
    return c.json({ ...resultPayload(fresh), ...(fresh.resultJwt ? { result_jwt: fresh.resultJwt } : {}) });
  });

  // ---------- Browser endpoints ----------

  app.get('/public/config', (c) =>
    c.json({
      kiosk: config.kiosk,
      dcApi: { enabled: config.dcApi.enabled },
      credentialTypes: config.credentialTypes.map((p) => ({ id: p.id, label: p.label })),
    }),
  );

  app.post('/public/kiosk/sessions', async (c) => {
    if (!config.kiosk.enabled) return c.json({ error: 'not_found' }, 404);
    const accepted = resolveAcceptedTypes(config.kiosk.acceptedTypes);
    if (!accepted.ok) return c.json({ error: 'server_error', error_description: accepted.error }, 500);
    const session = await newSession({ acceptedTypes: accepted.types });
    return c.json(sessionCreatedResponse(session), 201);
  });

  const browserSession = async (c: Context): Promise<Session | undefined> => {
    const s = await store.get(c.req.param('id') ?? '');
    const token = c.req.header('x-session-token') ?? c.req.query('token') ?? '';
    if (!s || !safeEqual(token, s.browserToken)) return undefined;
    return s;
  };

  app.get('/public/sessions/:id', async (c) => {
    let s = await browserSession(c);
    if (!s) return c.json({ error: 'not_found' }, 404);
    const code = c.req.query('response_code');
    if (code && s.responseCode && safeEqual(code, s.responseCode) && !s.responseCodeConfirmed) {
      s = (await store.update(s.id, { responseCodeConfirmed: true }))!;
      await refreshResultJwt(s);
    }
    await waitIfAsked(c, s);
    s = (await store.get(s.id))!;
    // Same-device: the result is shown only in the browser that received the response code.
    const hideResult = s.flow === 'same_device' && !s.responseCodeConfirmed && s.status === 'completed';
    const view = { ...publicView(s), acceptedTypes: s.acceptedTypes, ...(isTerminal(s.status) ? {} : walletLinks(s)) };
    return c.json(hideResult ? { ...view, status: 'awaiting_return', outcome: undefined, claims: undefined, issuer: undefined } : view);
  });

  app.post('/public/sessions/:id/dc-api/request', async (c) => {
    if (!config.dcApi.enabled) return c.json({ error: 'not_found' }, 404);
    const s = await browserSession(c);
    if (!s) return c.json({ error: 'not_found' }, 404);
    if (isTerminal(s.status)) return c.json({ error: 'invalid_request', error_description: `session is ${s.status}` }, 409);
    const origin = c.req.header('origin') ?? selfOrigin;
    if (!allowedDcOrigin(origin, s)) return c.json({ error: 'invalid_request', error_description: `origin ${origin} is not allowed` }, 403);
    await store.update(s.id, { dcApiOrigin: origin });
    return c.json(dcApiRequest(config, s, policiesFor(s)));
  });

  app.post('/public/sessions/:id/dc-api/response', async (c) => {
    const s = await browserSession(c);
    if (!s) return c.json({ error: 'not_found' }, 404);
    if (!s.dcApiOrigin) return c.json({ error: 'invalid_request', error_description: 'no DC API request was issued for this session' }, 409);
    if (isTerminal(s.status) || s.status === 'processing') return c.json({ error: 'invalid_request', error_description: `session is ${s.status}` }, 409);
    const body = await readJson(c);
    // Accept the DigitalCredential.data object, or { data }, or { vp_token }.
    const data = body.data ?? body;
    const vpToken = typeof data === 'string' ? safeJson(data)?.vp_token ?? data : data.vp_token;
    if (data.error) {
      await failWithWalletError(s, String(data.error), optionalString(data.error_description));
      return c.json(publicView((await store.get(s.id))!));
    }
    await processPresentation(s, vpToken, originAudiences(s.dcApiOrigin), 'dc_api');
    return c.json(publicView((await store.get(s.id))!));
  });

  // ---------- Wallet endpoints (OpenID4VP) ----------

  app.get('/oid4vp/request/:state', async (c) => {
    const s = await sessionForState(c.req.param('state'));
    if (!s || isTerminal(s.status)) return c.json({ error: 'invalid_request', error_description: 'unknown or finished request' }, 404);
    await store.update(s.id, {
      ...(s.status === 'pending' ? { status: 'request_retrieved' as const } : {}),
      diagnostics: { ...s.diagnostics, requestFetchedAt: new Date().toISOString(), requestUserAgent: optionalString(c.req.header('user-agent')) },
    });
    const params = authorizationRequestParams(config, s, policiesFor(s));
    params.state = c.req.param('state');
    const claims = requestObjectClaims(params);
    const requestObject =
      s.clientIdPrefix === 'openid_federation'
        ? await (await entity!).signRequestObject(claims)
        : s.clientIdPrefix === 'decentralized_identifier'
          ? await (await did!).signRequestObject(claims)
          : unsignedRequestObject(params);
    return c.body(requestObject, 200, { 'content-type': 'application/oauth-authz-req+jwt' });
  });

  app.post('/oid4vp/response', async (c) => {
    const body = await readFormOrJson(c);
    const state = optionalString(body.state);
    const s = state ? await sessionForState(state) : undefined;
    if (!s) return c.json({ error: 'invalid_request', error_description: 'unknown state' }, 400);
    if (isTerminal(s.status) || s.status === 'processing') return c.json({ error: 'invalid_request', error_description: `session is ${s.status}` }, 400);
    const sameDevice = state === sameDeviceState(s);
    const presentations = extractPresentations(body.vp_token);
    await store.update(s.id, {
      diagnostics: {
        ...s.diagnostics,
        responseAt: new Date().toISOString(),
        responseUserAgent: optionalString(c.req.header('user-agent')),
        responseContentType: optionalString(c.req.header('content-type')),
        vpTokenShape: body.vp_token !== undefined ? describeVpToken(body.vp_token) : body.response ? 'encrypted response' : body.error ? 'error' : 'missing',
        presentationCount: presentations.length,
        ...keyBindingDiagnostics(presentations[0]?.presentation),
      },
    });

    if (body.error) {
      await failWithWalletError(s, String(body.error), optionalString(body.error_description));
      return c.json({});
    }
    if (body.response) {
      // direct_post.jwt (encrypted responses) is not requested by this verifier.
      await failWithWalletError(s, 'unsupported_response', 'Encrypted responses are not supported');
      return c.json({ error: 'invalid_request', error_description: 'encrypted responses are not supported' }, 400);
    }

    const done = await processPresentation(s, body.vp_token, presentationAudiences(config, s.clientIdPrefix), sameDevice ? 'same_device' : 'cross_device');
    if (sameDevice && s.returnUrl) {
      const responseCode = randomToken();
      await store.update(done.id, { responseCode });
      const ret = new URL(s.returnUrl);
      ret.hash = new URLSearchParams({ verifier_session: s.id, response_code: responseCode }).toString();
      return c.json({ redirect_uri: ret.toString() });
    }
    return c.json({});
  });

  // ---------- Wallet compatibility tester ----------

  const compat = config.compat.enabled ? new CompatStore(config.compat.resultsFile) : undefined;
  const compatAuthorized = (c: Context) => {
    const m = /^Bearer\s+(.+)$/i.exec(c.req.header('authorization') ?? '');
    return !!(compat && config.compat.token && m && safeEqual(m[1]!.trim(), config.compat.token));
  };

  app.use('/api/compat/*', async (c, next) => {
    if (!compat) return c.json({ error: 'not_found' }, 404);
    if (!compatAuthorized(c)) return c.json({ error: 'unauthorized' }, 401);
    await next();
  });

  app.get('/api/compat/info', (c) =>
    c.json({
      wallets: config.compat.wallets,
      credentialTypes: config.credentialTypes.map((p) => ({ id: p.id, label: p.label })),
      variants: compatVariants(),
    }),
  );

  app.post('/api/compat/sessions', async (c) => {
    const body = await readJson(c);
    const variant = compatVariants().find((v) => v.clientIdPrefix === body.variant?.clientIdPrefix && v.requestMode === body.variant?.requestMode);
    if (!variant) return c.json({ error: 'invalid_request', error_description: 'unknown variant' }, 400);
    const accepted = resolveAcceptedTypes(body.credential_type ? [body.credential_type] : undefined);
    if (!accepted.ok) return c.json({ error: 'invalid_request', error_description: accepted.error }, 400);
    const session = await newSession({ acceptedTypes: accepted.types, clientIdPrefix: variant.clientIdPrefix, requestMode: variant.requestMode, reference: 'compat' });
    return c.json(sessionCreatedResponse(session), 201);
  });

  app.get('/api/compat/results', async (c) => c.json(await compat!.all()));

  app.post('/api/compat/results', async (c) => {
    const body = await readJson(c);
    const s = await store.get(String(body.session_id ?? ''));
    if (!s || s.reference !== 'compat' || s.apiClientId) return c.json({ error: 'invalid_request', error_description: 'unknown compatibility session' }, 400);
    const wallet = optionalString(body.wallet);
    if (!wallet) return c.json({ error: 'invalid_request', error_description: 'wallet is required' }, 400);
    const derived = deriveVerdict(s);
    const manual = ['no_response', 'wallet_refused', 'other', 'failed', 'works'].includes(body.verdict) ? (body.verdict as typeof derived.verdict) : undefined;
    const rec = await compat!.add({
      wallet,
      walletVersion: optionalString(body.wallet_version),
      platform: optionalString(body.platform),
      credentialType: s.acceptedTypes.join('|'),
      variant: { clientIdPrefix: s.clientIdPrefix, requestMode: isSignedPrefix(s.clientIdPrefix) ? 'reference' : s.requestMode ?? config.oid4vp.requestMode },
      sessionId: s.id,
      status: s.status,
      outcome: s.result?.outcome,
      verdict: manual ?? derived.verdict,
      credentialAccepted: s.result ? s.result.outcome === 'accepted' : undefined,
      failedCheck: derived.failedCheck,
      reasons: s.result?.reasons.slice(0, 3),
      walletError: s.walletError,
      diagnostics: s.diagnostics,
      notes: optionalString(body.notes),
    });
    return c.json(rec, 201);
  });

  app.delete('/api/compat/results/:id', async (c) => ((await compat!.remove(c.req.param('id'))) ? c.body(null, 204) : c.json({ error: 'not_found' }, 404)));

  function compatVariants(): Variant[] {
    const variants: Variant[] = [
      { clientIdPrefix: 'redirect_uri', requestMode: 'value' },
      { clientIdPrefix: 'redirect_uri', requestMode: 'reference' },
    ];
    variants.push({ clientIdPrefix: 'legacy_redirect_uri', requestMode: 'value' }, { clientIdPrefix: 'legacy_redirect_uri', requestMode: 'reference' });
    if (config.federation) variants.push({ clientIdPrefix: 'openid_federation', requestMode: 'reference' });
    if (config.didWeb) variants.push({ clientIdPrefix: 'decentralized_identifier', requestMode: 'reference' });
    return variants;
  }

  // ---------- helpers ----------

  async function newSession(init: {
    apiClientId?: string;
    reference?: string;
    acceptedTypes: string[];
    returnUrl?: string;
    clientIdPrefix?: ClientIdPrefix;
    requestMode?: 'value' | 'reference';
  }): Promise<Session> {
    return store.create({ ...init, clientIdPrefix: init.clientIdPrefix ?? config.oid4vp.clientIdPrefix, expiresAt: Date.now() + config.oid4vp.sessionTtlSeconds * 1000 });
  }

  function resolvePrefix(input: unknown): { ok: true; prefix: ClientIdPrefix } | { ok: false; error: string } {
    if (input === undefined || input === null || input === '') return { ok: true, prefix: config.oid4vp.clientIdPrefix };
    if (input === 'redirect_uri') return { ok: true, prefix: input };
    if (input === 'openid_federation') {
      return config.federation ? { ok: true, prefix: input } : { ok: false, error: 'openid_federation is not configured on this verifier' };
    }
    if (input === 'decentralized_identifier') {
      return config.didWeb ? { ok: true, prefix: input } : { ok: false, error: 'decentralized_identifier is not configured on this verifier' };
    }
    return { ok: false, error: `unsupported client_id_prefix ${JSON.stringify(input)}; use ${CLIENT_ID_PREFIXES.filter((p) => p !== 'legacy_redirect_uri').join(', ')}` };
  }

  /** Each session has a cross-device state and a same-device variant ("<state>.sd"). */
  function sessionForState(state: string) {
    return store.getByState(state.endsWith('.sd') ? state.slice(0, -3) : state);
  }

  function sameDeviceState(s: Session) {
    return `${s.state}.sd`;
  }

  function walletLinks(s: Session) {
    const policies = policiesFor(s);
    return {
      walletUrl: walletUrl(config, s, policies),
      ...(s.returnUrl ? { sameDeviceWalletUrl: walletUrl(config, { ...s, state: sameDeviceState(s) }, policies) } : {}),
    };
  }

  function sessionCreatedResponse(s: Session) {
    const links = walletLinks(s);
    return {
      session_id: s.id,
      browser_token: s.browserToken,
      wallet_url: links.walletUrl,
      ...(links.sameDeviceWalletUrl ? { same_device_wallet_url: links.sameDeviceWalletUrl } : {}),
      accepted_types: s.acceptedTypes,
      client_id_prefix: s.clientIdPrefix,
      expires_at: new Date(s.expiresAt).toISOString(),
    };
  }

  function resolveAcceptedTypes(input: unknown): { ok: true; types: string[] } | { ok: false; error: string } {
    const all = config.credentialTypes.map((p) => p.id);
    if (input === undefined || input === null) return { ok: true, types: all };
    const list = Array.isArray(input) ? input : String(input).split(',');
    const types = [...new Set(list.map((t) => String(t).trim()).filter(Boolean))];
    const unknown = types.filter((t) => !all.includes(t));
    if (types.length === 0 || unknown.length) return { ok: false, error: `unknown credential types: ${unknown.join(', ') || '(none given)'}; available: ${all.join(', ')}` };
    return { ok: true, types };
  }

  function isAllowedReturnUrl(url: unknown, client: ApiClient): url is string {
    if (typeof url !== 'string') return false;
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:' && u.hostname !== 'localhost') return false;
    } catch {
      return false;
    }
    return (client.allowedReturnUrls ?? []).some((prefix) => url.startsWith(prefix));
  }

  function allowedDcOrigin(origin: string, s: Session): boolean {
    if (origin === selfOrigin || config.dcApi.allowedOrigins.includes(origin)) return true;
    const client = config.apiClients.find((c) => c.id === s.apiClientId);
    return (client?.allowedOrigins ?? []).includes(origin);
  }

  /** Verifies every presentation in the vp_token; the first accepted one wins. */
  async function processPresentation(s: Session, vpToken: unknown, audience: string[], flow: Flow): Promise<Session> {
    await store.update(s.id, { status: 'processing', flow });
    const presentations = extractPresentations(vpToken);
    let result: VerificationResult | undefined;
    if (presentations.length === 0) {
      result = { outcome: 'rejected', claims: {}, checks: [], reasons: ['The wallet response contained no presentation'] };
    }
    for (const p of presentations) {
      const r = await verifier.verify(p.presentation, { nonce: s.nonce, audience, acceptedTypes: s.acceptedTypes });
      if (!result || r.outcome === 'accepted' || (result.outcome === 'rejected' && r.outcome === 'error')) result = r;
      if (r.outcome === 'accepted') break;
    }
    const updated = (await store.update(s.id, { status: 'completed', result }))!;
    log(`session ${s.id} ${result!.outcome}${result!.credentialType ? ` (${result!.credentialType})` : ''} via ${flow}${result!.outcome === 'accepted' ? '' : `: ${result!.reasons[0] ?? ''}`}`);
    await refreshResultJwt(updated);
    return updated;
  }

  async function failWithWalletError(s: Session, error: string, description?: string) {
    const updated = (await store.update(s.id, { status: 'failed', walletError: { error, ...(description ? { error_description: description } : {}) } }))!;
    log(`session ${s.id} failed: wallet error ${error}`);
    await refreshResultJwt(updated);
  }

  /** Signs the current result and notifies the client's webhook (once per signed state). */
  async function refreshResultJwt(s: Session) {
    if (!isTerminal(s.status)) return;
    const jwt = await signer.sign({ ...resultPayload(s), jti: randomToken(12) }, s.apiClientId);
    await store.update(s.id, { resultJwt: jwt });
    const client = config.apiClients.find((c) => c.id === s.apiClientId);
    if (client?.webhookUrl) void deliverWebhook(fetcher, client, s, jwt, log);
  }

  /**
   * Long-polling with ?wait=<seconds> (max 30). Browsers wake on any status change (to show "verifying…");
   * backends (untilTerminal) wake only when the session has finished.
   */
  async function waitIfAsked(c: Context, s: Session, untilTerminal = false) {
    const wait = Math.min(Number(c.req.query('wait') ?? 0) || 0, 30);
    if (wait <= 0) return;
    const since = c.req.query('since') ?? s.status;
    const deadline = Date.now() + wait * 1000;
    let current: Session | undefined = s;
    while (current && !isTerminal(current.status) && (untilTerminal || current.status === since) && Date.now() < deadline) {
      await store.waitForChange(s.id, deadline - Date.now());
      current = await store.get(s.id);
    }
  }

  return app;
}

async function readJson(c: Context): Promise<Record<string, any>> {
  try {
    const v = await c.req.json();
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

/** Wallets post application/x-www-form-urlencoded per spec; some send JSON. Accept both. */
async function readFormOrJson(c: Context): Promise<Record<string, any>> {
  const ct = c.req.header('content-type') ?? '';
  if (ct.includes('json')) return readJson(c);
  const text = await c.req.text();
  if (text.trim().startsWith('{')) return safeJson(text) ?? {};
  return Object.fromEntries(new URLSearchParams(text));
}

function safeJson(s: string): Record<string, any> | undefined {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

function optionalString(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v.slice(0, 500) : undefined;
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
