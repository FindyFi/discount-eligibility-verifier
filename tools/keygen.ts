/** Prints a new ES256 private JWK for RESULT_SIGNING_KEY. */
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
const { privateKey } = await generateKeyPair('ES256', { extractable: true });
const jwk = { ...(await exportJWK(privateKey)), alg: 'ES256' };
const { d: _d, ...pub } = jwk;
console.log(JSON.stringify({ ...jwk, kid: await calculateJwkThumbprint(pub) }));
