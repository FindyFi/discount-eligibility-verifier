import { beforeEach, describe, expect, it } from 'vitest';
import { Verifier, type VerifierConfig } from '../src/core/verifier.js';
import type { CredentialTypePolicy } from '../src/core/policy.js';
import { createPresentation } from '../tools/wallet/present.js';
import { newKey, TestFederation } from './helpers/federation.js';
import { issueSdJwt } from './helpers/issuer.js';

const TA = 'https://ta.example';
const PENSION_ISSUER = 'https://pension.example/issuer';
const STUDENT_ISSUER = 'https://student.example';
const PENSION_VCT = 'https://alennusperuste.todiste.fi/credentials/v3/PensionCredential';
const STUDENT_VCT = 'https://openbadge.digicredential.eu/credentials/student-status/v1/StudentStatusVCT';
const AUD = 'redirect_uri:https://verifier.example/response';
const NONCE = 'n-0S6_WzA2Mj';

const policies: CredentialTypePolicy[] = [
  { id: 'pension', vct: [PENSION_VCT], require: { Voimassa: true } },
  { id: 'student', vct: [STUDENT_VCT], require: { enrolment_status: 'enrolled' }, validUntilClaim: 'expiry_date', disclose: ['institution_name'] },
];

const holder = await newKey('holder');
const pensionKey = await newKey('pension-signing');
const studentKey = await newKey('student-signing');
const now = Math.floor(Date.now() / 1000);

let fed: TestFederation;
let config: VerifierConfig;

beforeEach(async () => {
  fed = new TestFederation();
  await fed.addEntity(TA);
  // Pension issuer publishes its signing key inside federation metadata.
  await fed.addEntity(PENSION_ISSUER, {
    authorityHints: [TA],
    metadata: { federation_entity: { organization_name: 'Kela' }, openid_credential_issuer: { credential_issuer: PENSION_ISSUER, jwks: { keys: [pensionKey.jwk] } } },
  });
  // Student issuer publishes its signing key via /.well-known/jwt-vc-issuer only.
  await fed.addEntity(STUDENT_ISSUER, { authorityHints: [TA], metadata: { openid_credential_issuer: { credential_issuer: STUDENT_ISSUER } } });
  fed.routes.set(`${STUDENT_ISSUER}/.well-known/jwt-vc-issuer`, { status: 200, body: JSON.stringify({ issuer: STUDENT_ISSUER, jwks: { keys: [studentKey.jwk] } }) });
  fed.addSubordinate(TA, PENSION_ISSUER);
  fed.addSubordinate(TA, STUDENT_ISSUER);
  config = { trustAnchors: [{ entityId: TA }], credentialTypes: policies, fetch: fed.fetch };
});

const pension = (claims: Record<string, unknown> = {}, sd: Record<string, unknown> = {}) =>
  issueSdJwt({
    key: pensionKey.privateKey,
    kid: 'pension-signing',
    claims: { iss: PENSION_ISSUER, vct: PENSION_VCT, iat: now, ...claims },
    sdClaims: { Hetu: '010101-123N', Voimassa: true, Muodostettu: '25.11.2026', ...sd },
    holderJwk: holder.jwk,
  });

const student = (claims: Record<string, unknown> = {}) =>
  issueSdJwt({
    key: studentKey.privateKey,
    kid: 'student-signing',
    claims: { iss: STUDENT_ISSUER, vct: STUDENT_VCT, iat: now, exp: now + 86400 * 30, enrolment_status: 'enrolled', expiry_date: '2099-12-31', ...claims },
    sdClaims: { given_name: 'Maija', family_name: 'Meikäläinen', institution_name: 'Esimerkkiyliopisto' },
    holderJwk: holder.jwk,
  });

const present = (sdJwt: string, disclose: string[], o: { nonce?: string; aud?: string; iat?: number } = {}) =>
  createPresentation(sdJwt, { disclose, holderKey: holder.privateKey, nonce: o.nonce ?? NONCE, aud: o.aud ?? AUD, iat: o.iat });

const verify = (vp: string, cfg: Partial<VerifierConfig> = {}, extra: object = {}) =>
  new Verifier({ ...config, ...cfg }).verify(vp, { nonce: NONCE, audience: [AUD], ...extra });

describe('Verifier: accepted', () => {
  it('accepts a pension credential without exp, disclosing only Voimassa', async () => {
    const r = await verify(await present(await pension(), ['Voimassa']));
    expect(r.reasons).toEqual([]);
    expect(r.outcome).toBe('accepted');
    expect(r.credentialType).toBe('pension');
    expect(r.issuer).toMatchObject({ entityId: PENSION_ISSUER, organizationName: 'Kela', trustAnchor: TA });
    expect(r.claims).toEqual({ Voimassa: true });
    expect(r.validUntil).toBeUndefined();
    expect(r.checks.every((c) => c.ok === true)).toBe(true);
  });

  it('never returns claims outside the policy, even if the wallet over-discloses', async () => {
    const r = await verify(await present(await pension(), ['Voimassa', 'Hetu', 'Muodostettu']));
    expect(r.outcome).toBe('accepted');
    expect(r.claims).toEqual({ Voimassa: true });
    expect(JSON.stringify(r)).not.toContain('010101-123N');
  });

  it('accepts a student credential with keys from jwt-vc-issuer metadata', async () => {
    const r = await verify(await present(await student(), ['institution_name']));
    expect(r.reasons).toEqual([]);
    expect(r.outcome).toBe('accepted');
    expect(r.claims).toEqual({ enrolment_status: 'enrolled', expiry_date: '2099-12-31', institution_name: 'Esimerkkiyliopisto' });
    expect(r.checks.find((c) => c.id === 'signature')?.message).toMatch(/jwt-vc-issuer/);
    expect(r.validUntil).toBeDefined();
  });

  it('accepts the legacy vc+sd-jwt typ and string-encoded booleans', async () => {
    const sd = await issueSdJwt({
      key: pensionKey.privateKey, kid: 'pension-signing', typ: 'vc+sd-jwt',
      claims: { iss: PENSION_ISSUER, vct: PENSION_VCT }, sdClaims: { Voimassa: 'true' }, holderJwk: holder.jwk,
    });
    expect((await verify(await present(sd, ['Voimassa']))).outcome).toBe('accepted');
  });
});

describe('Verifier: optional max age', () => {
  const withMaxAge = (duration: string) => ({ credentialTypes: [{ ...policies[0]!, maxAge: { claim: 'Muodostettu', duration } }] });
  const fmt = (d: Date) => `${d.getDate()}.${d.getMonth() + 1}.${d.getFullYear()}`;

  it('accepts a recent credential', async () => {
    const vp = await present(await pension({}, { Muodostettu: fmt(new Date()) }), ['Voimassa', 'Muodostettu']);
    expect((await verify(vp, withMaxAge('P3M'))).outcome).toBe('accepted');
  });

  it('rejects a credential older than allowed', async () => {
    const vp = await present(await pension({}, { Muodostettu: '1.1.2020' }), ['Voimassa', 'Muodostettu']);
    const r = await verify(vp, withMaxAge('P3Y'));
    expect(r.outcome).toBe('rejected');
    expect(r.reasons.join()).toMatch(/older than allowed/);
  });

  it('rejects when the date claim is withheld', async () => {
    const r = await verify(await present(await pension(), ['Voimassa']), withMaxAge('P3M'));
    expect(r.outcome).toBe('rejected');
    expect(r.reasons.join()).toMatch(/Muodostettu.*not disclosed/);
  });
});

describe('Verifier: rejected', () => {
  const failed = (r: { checks: { id: string; ok: boolean | null }[] }) => r.checks.find((c) => c.ok === false)?.id;

  it('rejects expired credentials when exp is set', async () => {
    const r = await verify(await present(await student({ exp: now - 3600 }), []));
    expect([r.outcome, failed(r)]).toEqual(['rejected', 'validity_period']);
  });

  it('rejects a student whose expiry_date has passed', async () => {
    const r = await verify(await present(await student({ expiry_date: '2020-06-30' }), []));
    expect([r.outcome, failed(r)]).toEqual(['rejected', 'eligibility']);
  });

  it('rejects an ineligible claim value', async () => {
    const r = await verify(await present(await pension({}, { Voimassa: false }), ['Voimassa']));
    expect([r.outcome, failed(r)]).toEqual(['rejected', 'eligibility']);
  });

  it('rejects when a required claim is withheld', async () => {
    const r = await verify(await present(await pension(), []));
    expect([r.outcome, failed(r)]).toEqual(['rejected', 'eligibility']);
  });

  it('rejects credential types that are not accepted', async () => {
    const r = await verify(await present(await pension({ vct: 'https://other.example/vct' }), ['Voimassa']));
    expect(failed(r)).toBe('credential_type');
    const r2 = await verify(await present(await pension(), ['Voimassa']), {}, { acceptedTypes: ['student'] });
    expect(failed(r2)).toBe('credential_type');
  });

  it('rejects missing key binding, wrong nonce, wrong audience and stale proofs', async () => {
    const sd = await pension();
    expect(failed(await verify(sd))).toBe('key_binding');
    expect(failed(await verify(await present(sd, ['Voimassa'], { nonce: 'other' })))).toBe('key_binding');
    expect(failed(await verify(await present(sd, ['Voimassa'], { aud: 'redirect_uri:https://evil.example' })))).toBe('key_binding');
    expect(failed(await verify(await present(sd, ['Voimassa'], { iat: now - 3600 })))).toBe('key_binding');
  });

  it('rejects a KB-JWT signed by someone other than the holder', async () => {
    const thief = await newKey('thief');
    const vp = await createPresentation(await pension(), { disclose: ['Voimassa'], holderKey: thief.privateKey, nonce: NONCE, aud: AUD });
    expect(failed(await verify(vp))).toBe('key_binding');
  });

  it('rejects a presentation whose disclosures were altered after key binding', async () => {
    const sd = await pension();
    const vp = await present(sd, ['Voimassa', 'Muodostettu']);
    const [jwt, d1, , kb] = vp.split('~');
    // Disclosure removed by an intermediary
    expect(failed(await verify(`${jwt}~${d1}~${kb}`))).toBe('key_binding');
    // Extra disclosure (the Hetu) smuggled in after the holder signed
    const hetu = sd.split('~').slice(1).find((d) => d && Buffer.from(d, 'base64url').toString().includes('Hetu'))!;
    const [, ...rest] = vp.split('~');
    expect(failed(await verify([jwt, hetu, ...rest].join('~')))).toBe('key_binding');
  });

  it('rejects issuers identified by a DID', async () => {
    const r = await verify(await present(await pension({ iss: 'did:web:pension.example' }), ['Voimassa']));
    expect(failed(r)).toBe('issuer_trust');
    expect(r.reasons.join()).toMatch(/not an https entity identifier/);
  });

  it('rejects issuers outside the federation', async () => {
    fed.subordinates.delete(`${TA}|${PENSION_ISSUER}`);
    const r = await verify(await present(await pension(), ['Voimassa']));
    expect([r.outcome, failed(r)]).toEqual(['rejected', 'issuer_trust']);
  });

  it('rejects credentials signed with a key the federation does not vouch for', async () => {
    const rogue = await newKey('pension-signing');
    const sd = await issueSdJwt({ key: rogue.privateKey, kid: 'pension-signing', claims: { iss: PENSION_ISSUER, vct: PENSION_VCT }, sdClaims: { Voimassa: true }, holderJwk: holder.jwk });
    expect(failed(await verify(await present(sd, ['Voimassa'])))).toBe('signature');
  });

  it('does not use jwt-vc-issuer keys when disabled', async () => {
    const r = await verify(await present(await student(), []), { allowJwtVcIssuerMetadata: false });
    expect(failed(r)).toBe('signature');
  });

  it('rejects credentials with a status reference until status lists are supported', async () => {
    const r = await verify(await present(await pension({ status: { status_list: { idx: 1, uri: 'https://x' } } }), ['Voimassa']));
    expect(failed(r)).toBe('status');
  });

  it('rejects disallowed signature algorithms', async () => {
    const r = await verify(await present(await pension(), ['Voimassa']), { allowedAlgs: ['EdDSA'] });
    expect(failed(r)).toBe('format');
  });
});

describe('Verifier: errors', () => {
  it('reports an unreachable federation as a retryable error, not a rejection', async () => {
    const vp = await present(await pension(), ['Voimassa']);
    fed.offline = true;
    const r = await verify(vp);
    expect(r.outcome).toBe('error');
  });

  it('reports malformed input as rejected', async () => {
    const r = await verify('not a credential');
    expect(r.outcome).toBe('rejected');
    expect(r.checks[0]).toMatchObject({ id: 'format', ok: false });
  });
});
