import { beforeEach, describe, expect, it } from 'vitest';
import { FederationResolver } from '../src/core/federation.js';
import { newKey, TestFederation } from './helpers/federation.js';

const TA = 'https://ta.example';
const LEAF = 'https://issuer.example';

let fed: TestFederation;
beforeEach(async () => {
  fed = new TestFederation();
  await fed.addEntity(TA);
  await fed.addEntity(LEAF, { authorityHints: [TA], metadata: { openid_credential_issuer: { credential_issuer: LEAF } } });
  fed.addSubordinate(TA, LEAF);
});

const resolver = (pinned = false) =>
  new FederationResolver({ trustAnchors: [{ entityId: TA, ...(pinned ? { jwks: { keys: [fed.entities.get(TA)!.jwk] } } : {}) }], fetch: fed.fetch });

describe('FederationResolver', () => {
  it('resolves a leaf directly under the trust anchor', async () => {
    const r = await resolver(true).resolve(LEAF);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.trustAnchor).toBe(TA);
    expect(r.chain).toHaveLength(3);
    expect(r.metadata.openid_credential_issuer?.credential_issuer).toBe(LEAF);
  });

  it('resolves through an intermediate', async () => {
    const MID = 'https://mid.example';
    const LEAF2 = 'https://deep.example';
    await fed.addEntity(MID, { authorityHints: [TA], metadata: { federation_entity: {} } });
    await fed.addEntity(LEAF2, { authorityHints: [MID] });
    fed.addSubordinate(TA, MID);
    fed.addSubordinate(MID, LEAF2);
    const r = await resolver().resolve(LEAF2);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.chain.map((s) => `${s.iss}>${s.sub}`)).toEqual([`${LEAF2}>${LEAF2}`, `${MID}>${LEAF2}`, `${TA}>${MID}`, `${TA}>${TA}`]);
  });

  it('fails when the leaf has no authority_hints (no workaround via the anchor)', async () => {
    await fed.addEntity(LEAF, { metadata: { openid_credential_issuer: {} } });
    fed.addSubordinate(TA, LEAF);
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join()).toMatch(/no authority_hints/);
  });

  it('compares entity identifiers exactly (trailing slash mismatch fails)', async () => {
    fed.subordinates.clear();
    fed.addSubordinate(TA, LEAF + '/');
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join()).toMatch(/not found/);
  });

  it('fails when the anchor vouches for different keys than the leaf uses', async () => {
    const other = await newKey('other');
    fed.addSubordinate(TA, LEAF, { jwks: { keys: [other.jwk] } });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join()).toMatch(/does not verify/);
  });

  it('fails when the trust anchor does not match pinned keys', async () => {
    const other = await newKey('pinned');
    const r = await new FederationResolver({ trustAnchors: [{ entityId: TA, jwks: { keys: [other.jwk] } }], fetch: fed.fetch }).resolve(LEAF);
    expect(r.ok).toBe(false);
  });

  it('fails on an expired subordinate statement', async () => {
    fed.addSubordinate(TA, LEAF, { exp: Math.floor(Date.now() / 1000) - 3600 });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join()).toMatch(/expired/);
  });

  it('fails when the leaf configuration claims a different identifier', async () => {
    await fed.addEntity(LEAF, { authorityHints: [TA], ecOverrides: { iss: 'https://evil.example', sub: 'https://evil.example' } });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join()).toMatch(/expected exactly/);
  });

  it('rejects non-https entity identifiers such as DIDs', async () => {
    const r = await resolver().resolve('did:web:issuer.example');
    expect(r.ok).toBe(false);
  });

  it('applies superior metadata and metadata policy', async () => {
    fed.addSubordinate(TA, LEAF, {
      metadata: { openid_credential_issuer: { display_hint: 'from-anchor' } },
      metadata_policy: { openid_credential_issuer: { required_flag: { default: true }, credential_issuer: { one_of: [LEAF] } } },
    });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.metadata.openid_credential_issuer).toMatchObject({ display_hint: 'from-anchor', required_flag: true });
  });

  it('reports network failures as transient', async () => {
    fed.offline = true;
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.transient).toBe(true);
  });

  it('caches successful resolutions', async () => {
    const res = resolver();
    await res.resolve(LEAF);
    const n = fed.requests.length;
    await res.resolve(LEAF);
    expect(fed.requests.length).toBe(n);
  });
});

describe('key matching', () => {
  it('accepts a superior that registered the subordinate key without a kid', async () => {
    const { kid: _kid, ...withoutKid } = fed.entities.get(LEAF)!.jwk;
    fed.addSubordinate(TA, LEAF, { jwks: { keys: [withoutKid] } });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(true);
  });

  it('still rejects a kid-less registered key that does not match the signature', async () => {
    const other = await newKey('x');
    const { kid: _kid, ...withoutKid } = other.jwk;
    fed.addSubordinate(TA, LEAF, { jwks: { keys: [withoutKid] } });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(false);
  });
});

describe('non-conforming registry output', () => {
  it('tolerates metadata_policy_crit and metadata_policy published as empty objects (seen at findy.trustregistry.eu)', async () => {
    fed.addSubordinate(TA, LEAF, { extra: { metadata_policy: {}, metadata_policy_crit: {} } });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(true);
  });

  it('ignores malformed policy entries instead of crashing', async () => {
    fed.addSubordinate(TA, LEAF, { extra: { metadata_policy: { openid_credential_issuer: { credential_issuer: 'not-an-object' } } } });
    const r = await resolver().resolve(LEAF);
    expect(r.ok).toBe(true);
  });
});
