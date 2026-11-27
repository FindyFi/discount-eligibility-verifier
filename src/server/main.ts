/**
 * Entry point: `node dist/server/main.js` (or `npm start`). Configuration via CONFIG_FILE (default config/verifier.yaml).
 */
import { existsSync } from 'node:fs';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import { Verifier } from '../core/index.js';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { VerifierDid } from './did-entity.js';
import { VerifierEntity } from './federation-entity.js';
import { fillPublicUrl } from './pages.js';
import { createResultSigner } from './results.js';
import { MemorySessionStore } from './sessions.js';

const config = await loadConfig();
const signer = await createResultSigner(config.publicUrl, config.resultSigningKey);
if (signer.ephemeral) {
  console.warn('[verifier] No resultSigningKey configured: using a per-process key. Result JWTs will not verify after a restart or across instances.');
}
const store = new MemorySessionStore();

const root = new Hono();
const log = (m: string) => console.log(`[verifier] ${m}`);
const verifier = new Verifier({
  trustAnchors: config.trustAnchors,
  credentialTypes: config.credentialTypes,
  timeZone: config.timeZone,
  allowJwtVcIssuerMetadata: config.allowJwtVcIssuerMetadata,
  trustedDidIssuers: config.trustedDidIssuers,
});
const entity = config.federation ? VerifierEntity.create(config, verifier.federation, log) : undefined;
const did = config.didWeb ? VerifierDid.create(config) : undefined;
root.route('/', createApp({ config, store, signer, verifier, entity, did, log }));
const staticDir = process.env.STATIC_DIR ?? 'public';
if (existsSync(staticDir)) root.use('/*', fillPublicUrl(config.publicUrl), serveStatic({ root: staticDir }));

const server = serve({ fetch: root.fetch, port: config.port }, (info) => {
  console.log(`[verifier] listening on :${info.port}, public URL ${config.publicUrl}`);
  console.log(`[verifier] trust anchors: ${config.trustAnchors.map((t) => t.entityId).join(', ')}; credential types: ${config.credentialTypes.map((t) => t.id).join(', ')}`);
  console.log(`[verifier] default client_id prefix: ${config.oid4vp.clientIdPrefix}`);
  if (entity) void reportFederationStatus(entity);
  if (config.didWeb) console.log(`[verifier] did:web identity ${config.didWeb.did}, document at ${config.publicUrl}/.well-known/did.json`);
  if (config.trustedDidIssuers.length) console.log(`[verifier] trusted did:web issuers: ${config.trustedDidIssuers.map((t) => t.did).join(', ')}`);
});

/** Tells the operator whether the verifier is registered in the federation, and what to register. */
async function reportFederationStatus(entityPromise: Promise<VerifierEntity>) {
  const e = await entityPromise;
  log(`federation entity ${e.entityId}, configuration at ${e.entityId}/.well-known/openid-federation`);
  const chain = await e.selfCheck();
  if (chain.ok) {
    log(`federation: registered, trust chain to ${chain.trustAnchor}`);
  } else {
    log(`federation: NOT resolvable yet (${chain.errors.join('; ')})`);
    log(`federation: register entity ${e.entityId} at ${config.federation!.authorityHints.join(', ')} with federation key ${JSON.stringify(e.federationPublicJwk)}`);
  }
}

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    store.close();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
