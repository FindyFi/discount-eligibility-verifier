/**
 * Test wallet over HTTP: answers an OpenID4VP request (openid4vp:// link) with a stored test credential.
 *
 *   npm run wallet -- '<openid4vp://...>' <fixture-name> [claim,claim]
 *
 * Discloses the claims the DCQL query asks for unless a list is given.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createPresentation } from './present.js';

const [link, name, discloseArg] = process.argv.slice(2);
if (!link || !name) {
  console.error("Usage: wallet '<openid4vp://...>' <fixture-name> [claim,claim]");
  process.exit(2);
}
const FIXTURES = join(import.meta.dirname, '../../test/fixtures/live');
const credential = (await readFile(join(FIXTURES, `${name}.sd-jwt`), 'utf8')).trim();
const holderKey = JSON.parse(await readFile(join(FIXTURES, 'holder-key.json'), 'utf8'));
const vct = JSON.parse(Buffer.from(credential.split('.')[1]!, 'base64url').toString()).vct as string;

let params = new URL(link.replace(/^[a-z0-9+.-]+:\/\/\/?\??/i, 'https://wallet.invalid/?')).searchParams;
if (params.get('request_uri')) {
  const jwt = await (await fetch(params.get('request_uri')!)).text();
  const payload = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString());
  params = new URLSearchParams(Object.fromEntries(Object.entries(payload).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)])));
}
const dcql = JSON.parse(params.get('dcql_query') ?? '{"credentials":[]}');
const query = dcql.credentials.find((q: any) => q.meta?.vct_values?.includes(vct));
if (!query) console.warn(`warning: no DCQL query matches vct ${vct}; presenting anyway`);
const disclose = discloseArg ? discloseArg.split(',') : (query?.claims ?? []).map((c: any) => c.path[0]);

const vp = await createPresentation(credential, { disclose, holderKey, nonce: params.get('nonce')!, aud: params.get('client_id')! });
const res = await fetch(params.get('response_uri')!, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ vp_token: JSON.stringify({ [query?.id ?? 'credential']: [vp] }), state: params.get('state')! }),
});
console.log(`POST ${params.get('response_uri')} -> ${res.status} ${await res.text()}`);
console.log(`disclosed: ${disclose.join(', ') || 'nothing'}`);
