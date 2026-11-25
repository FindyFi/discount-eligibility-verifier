/**
 * Minimal OpenID4VCI test wallet: redeems a pre-authorized-code credential offer
 * and stores the issued credential as a test fixture.
 *
 * Usage:
 *   npm run redeem-offer -- '<openid-credential-offer://... | https://offer-uri | JSON>' <name> [tx_code]
 *
 * Output (git-ignored, contains a private key and live credentials):
 *   test/fixtures/live/holder-key.json   holder key pair (reused across runs)
 *   test/fixtures/live/<name>.sd-jwt     the credential as issued
 *   test/fixtures/live/<name>.json       issuer/metadata context for the fixture
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { SignJWT, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';

const OUT_DIR = join(import.meta.dirname, '../../test/fixtures/live');
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

type Json = Record<string, any>;

async function main() {
  const [offerArg, name, txCode] = process.argv.slice(2);
  if (!offerArg || !name) {
    console.error('Usage: redeem-offer <offer> <name> [tx_code]');
    process.exit(2);
  }

  const offer = await resolveOffer(offerArg);
  log('offer', offer);

  const grant = offer.grants?.[PRE_AUTH_GRANT];
  if (!grant) throw new Error(`Offer has no pre-authorized_code grant (grants: ${Object.keys(offer.grants ?? {})})`);
  if (grant.tx_code && !txCode) throw new Error(`Offer requires a tx_code: ${JSON.stringify(grant.tx_code)}`);

  const issuer: string = offer.credential_issuer;
  const issuerMeta = await fetchWellKnown(issuer, 'openid-credential-issuer');
  const asIssuer: string = grant.authorization_server ?? issuerMeta.authorization_servers?.[0] ?? issuer;
  const asMeta =
    (await fetchWellKnown(asIssuer, 'oauth-authorization-server').catch(() => null)) ??
    (await fetchWellKnown(asIssuer, 'openid-configuration'));

  // Token request
  const tokenBody = new URLSearchParams({ grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': grant['pre-authorized_code'] });
  if (txCode) tokenBody.set('tx_code', txCode);
  const token = await postJson(asMeta.token_endpoint, tokenBody);
  log('token response', { ...token, access_token: '<redacted>' });

  // Nonce (OpenID4VCI 1.0 nonce endpoint; fall back to c_nonce from token response)
  let cNonce: string | undefined = token.c_nonce;
  if (issuerMeta.nonce_endpoint) cNonce = (await postJson(issuerMeta.nonce_endpoint, undefined)).c_nonce ?? cNonce;

  const holder = await loadOrCreateHolderKey();
  const configId: string = offer.credential_configuration_ids[0];
  const config = issuerMeta.credential_configurations_supported?.[configId];
  if (!config) throw new Error(`Issuer metadata has no configuration ${configId}`);

  const proof = await new SignJWT({ aud: issuer, iat: Math.floor(Date.now() / 1000), ...(cNonce ? { nonce: cNonce } : {}) })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holder.publicJwk })
    .sign(holder.privateKey);

  const credResponse = await postJson(
    issuerMeta.credential_endpoint,
    { credential_configuration_id: configId, proofs: { jwt: [proof] } },
    token.access_token,
  );

  const credential: string | undefined = credResponse.credentials?.[0]?.credential ?? credResponse.credential;
  if (typeof credential !== 'string') throw new Error(`No credential in response: ${JSON.stringify(credResponse)}`);

  await mkdir(OUT_DIR, { recursive: true });
  await writeFile(join(OUT_DIR, `${name}.sd-jwt`), credential + '\n');
  await writeFile(
    join(OUT_DIR, `${name}.json`),
    JSON.stringify({ redeemedAt: new Date().toISOString(), credentialIssuer: issuer, configurationId: configId, format: config.format, vct: config.vct }, null, 2) + '\n',
  );
  console.log(`\nSaved ${join(OUT_DIR, `${name}.sd-jwt`)}`);

  // Best-effort acceptance notification so the issuer does not leave the offer pending
  if (issuerMeta.notification_endpoint && credResponse.notification_id) {
    await postJson(issuerMeta.notification_endpoint, { notification_id: credResponse.notification_id, event: 'credential_accepted' }, token.access_token)
      .catch((e) => console.warn('notification failed (ignored):', e.message));
  }
}

async function resolveOffer(arg: string): Promise<Json> {
  const s = arg.trim();
  if (s.startsWith('{')) return JSON.parse(s);
  if (/^https?:\/\//.test(s) && !s.includes('credential_offer')) return getJson(s);
  const params = new URL(s.replace(/^[a-z0-9+.-]+:\/\/\??/i, 'https://x/?')).searchParams;
  const byValue = params.get('credential_offer');
  if (byValue) return JSON.parse(byValue);
  const uri = params.get('credential_offer_uri');
  if (uri) return getJson(uri);
  throw new Error('Could not parse credential offer');
}

/** RFC 8414 style: /.well-known/<suffix> inserted between host and path, with appended-path fallback. */
async function fetchWellKnown(identifier: string, suffix: string): Promise<Json> {
  const u = new URL(identifier);
  const path = u.pathname.replace(/\/$/, '');
  const candidates = [`${u.origin}/.well-known/${suffix}${path}`, `${u.origin}${path}/.well-known/${suffix}`];
  let lastErr: unknown;
  for (const c of candidates) {
    try {
      return await getJson(c);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

async function getJson(url: string): Promise<Json> {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status} ${await res.text()}`);
  return res.json() as Promise<Json>;
}

async function postJson(url: string, body: URLSearchParams | Json | undefined, accessToken?: string): Promise<Json> {
  const headers: Record<string, string> = { accept: 'application/json' };
  let payload: string | undefined;
  if (body instanceof URLSearchParams) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    payload = body.toString();
  } else if (body) {
    headers['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;
  const res = await fetch(url, { method: 'POST', headers, body: payload });
  const text = await res.text();
  if (!res.ok) throw new Error(`POST ${url} -> ${res.status} ${text}`);
  return text ? (JSON.parse(text) as Json) : {};
}

async function loadOrCreateHolderKey() {
  const file = join(OUT_DIR, 'holder-key.json');
  try {
    const jwk = JSON.parse(await readFile(file, 'utf8')) as JWK;
    const { d: _d, ...publicJwk } = jwk;
    return { privateKey: await importJWK(jwk, 'ES256'), publicJwk };
  } catch {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk = { ...(await exportJWK(privateKey)), alg: 'ES256' };
    await mkdir(OUT_DIR, { recursive: true });
    await writeFile(file, JSON.stringify(jwk, null, 2) + '\n', { mode: 0o600 });
    return { privateKey, publicJwk: { ...(await exportJWK(publicKey)), alg: 'ES256' } };
  }
}

function log(label: string, value: unknown) {
  console.log(`--- ${label}\n${JSON.stringify(value, null, 2)}`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
