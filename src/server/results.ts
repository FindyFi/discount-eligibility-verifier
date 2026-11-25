/**
 * Signed verification results: what service providers receive by webhook or API.
 * The result JWT lets a backend trust a result even if it was relayed through a browser.
 */
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from 'jose';
import type { Fetcher } from '../core/index.js';
import type { ApiClient } from './config.js';
import type { Session } from './sessions.js';

export const RESULT_JWT_TYP = 'eligibility-result+jwt';

export interface ResultSigner {
  publicJwks: { keys: JWK[] };
  sign(payload: Record<string, unknown>, audience?: string): Promise<string>;
}

export async function createResultSigner(issuer: string, privateJwk?: JWK): Promise<ResultSigner & { ephemeral: boolean }> {
  let key: CryptoKey;
  let publicJwk: JWK;
  const ephemeral = !privateJwk;
  if (privateJwk) {
    const alg = privateJwk.alg ?? 'ES256';
    key = (await importJWK(privateJwk, alg)) as CryptoKey;
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = privateJwk;
    publicJwk = { ...pub, alg };
  } else {
    const kp = await generateKeyPair('ES256', { extractable: true });
    key = kp.privateKey;
    publicJwk = { ...(await exportJWK(kp.publicKey)), alg: 'ES256' };
  }
  publicJwk.kid ??= await calculateJwkThumbprint(publicJwk);
  publicJwk.use = 'sig';
  const alg = publicJwk.alg!;

  return {
    ephemeral,
    publicJwks: { keys: [publicJwk] },
    sign: (payload, audience) => {
      const jwt = new SignJWT(payload).setProtectedHeader({ alg, kid: publicJwk.kid!, typ: RESULT_JWT_TYP }).setIssuer(issuer).setIssuedAt();
      if (audience) jwt.setAudience(audience);
      return jwt.sign(key);
    },
  };
}

/** Full result for the service provider's backend. */
export function resultPayload(s: Session) {
  const r = s.result;
  return {
    session_id: s.id,
    ...(s.reference ? { reference: s.reference } : {}),
    status: s.status,
    outcome: r?.outcome ?? (s.status === 'expired' ? 'expired' : s.walletError ? 'wallet_error' : 'pending'),
    ...(r?.credentialType ? { credential_type: r.credentialType } : {}),
    ...(r?.issuer ? { credential_issuer: r.issuer } : {}),
    ...(r && Object.keys(r.claims).length ? { claims: r.claims } : {}),
    ...(r?.validUntil ? { valid_until: r.validUntil } : {}),
    ...(s.flow ? { flow: s.flow } : {}),
    ...(s.flow === 'same_device' ? { same_device_confirmed: s.responseCodeConfirmed === true } : {}),
    ...(r && r.reasons.length ? { reasons: r.reasons } : {}),
    ...(r ? { checks: r.checks } : {}),
    ...(s.walletError ? { wallet_error: s.walletError } : {}),
  };
}

/** Display-oriented view for the browser that shows the session (no check details). */
export function publicView(s: Session) {
  const r = s.result;
  return {
    id: s.id,
    status: s.status,
    outcome: r?.outcome,
    credentialType: r?.credentialType,
    label: r?.label,
    issuer: r?.issuer ? { name: r.issuer.name ?? r.issuer.organizationName, logoUri: r.issuer.logoUri } : undefined,
    claims: r?.claims,
    validUntil: r?.validUntil,
    reason: r && r.outcome !== 'accepted' ? r.reasons[0] : s.walletError ? s.walletError.error_description ?? s.walletError.error : undefined,
    expiresAt: new Date(s.expiresAt).toISOString(),
  };
}

/** Delivers the signed result with retries; never throws. */
export async function deliverWebhook(fetcher: Fetcher, client: ApiClient, s: Session, jwt: string, log: (msg: string) => void, delaysMs = [0, 2000, 10000, 30000]) {
  if (!client.webhookUrl) return;
  for (const [attempt, delay] of delaysMs.entries()) {
    if (delay) await new Promise((r) => setTimeout(r, delay));
    try {
      const res = await fetcher(client.webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/jwt', 'x-verifier-session': s.id },
        body: jwt,
        signal: AbortSignal.timeout(10000),
      });
      if (res.ok) return;
      log(`webhook ${client.id} attempt ${attempt + 1}: HTTP ${res.status}`);
      if (res.status >= 400 && res.status < 500 && res.status !== 429) return;
    } catch (e) {
      log(`webhook ${client.id} attempt ${attempt + 1}: ${(e as Error).message}`);
    }
  }
}
