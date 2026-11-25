/**
 * Verifies a live test credential against the real trust anchor, presenting it with the test wallet key.
 *
 *   npm run verify-live -- <name> [claim,claim,...] [--max-age=<claim>:<ISO duration>]
 *
 * <name> refers to test/fixtures/live/<name>.sd-jwt created by `npm run redeem-offer`.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Verifier, type CredentialTypePolicy } from '../src/core/index.js';
import { claimsOfInterest } from '../src/core/policy.js';
import { createPresentation } from './wallet/present.js';

const ROOT = join(import.meta.dirname, '..');
const TRUST_ANCHOR = process.env.TRUST_ANCHOR ?? 'https://findy.trustregistry.eu';

const args = process.argv.slice(2);
const name = args.find((a) => !a.startsWith('--'));
if (!name) {
  console.error('Usage: verify-live <name> [claim,claim] [--max-age=Claim:P3M]');
  process.exit(2);
}
const discloseArg = args.filter((a) => !a.startsWith('--'))[1];
const maxAgeArg = args.find((a) => a.startsWith('--max-age='))?.slice('--max-age='.length);

const policies = JSON.parse(await readFile(join(ROOT, 'config/credential-types.json'), 'utf8')) as CredentialTypePolicy[];
if (maxAgeArg) {
  const [claim, duration] = maxAgeArg.split(':');
  for (const p of policies) if (p.id === 'pension') p.maxAge = { claim: claim!, duration: duration! };
}

const sdJwt = (await readFile(join(ROOT, `test/fixtures/live/${name}.sd-jwt`), 'utf8')).trim();
const holderKey = JSON.parse(await readFile(join(ROOT, 'test/fixtures/live/holder-key.json'), 'utf8'));
const vct = JSON.parse(Buffer.from(sdJwt.split('.')[1]!, 'base64url').toString()).vct;
const policy = policies.find((p) => p.vct.includes(vct));
const disclose = discloseArg ? discloseArg.split(',') : policy ? claimsOfInterest(policy) : [];

const nonce = crypto.randomUUID();
const aud = 'redirect_uri:https://verifier.localhost/response';
const vp = await createPresentation(sdJwt, { disclose, holderKey, nonce, aud });

const verifier = new Verifier({ trustAnchors: [{ entityId: TRUST_ANCHOR }], credentialTypes: policies });
const result = await verifier.verify(vp, { nonce, audience: [aud] });

const icon = { accepted: '✅', rejected: '❌', error: '⚠️' }[result.outcome];
console.log(`${icon} ${result.outcome.toUpperCase()}  (${name}, disclosed: ${disclose.join(', ') || 'nothing'})`);
for (const c of result.checks) console.log(`  ${c.ok === true ? '✓' : c.ok === false ? '✗' : '·'} ${c.id.padEnd(16)} ${c.message}`);
console.log('result:', JSON.stringify({ credentialType: result.credentialType, issuer: result.issuer, claims: result.claims, validUntil: result.validUntil }, null, 2));
process.exit(result.outcome === 'accepted' ? 0 : 1);
