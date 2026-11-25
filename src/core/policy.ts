/** Configurable, per-credential-type eligibility rules. */
import { parseClaimDate, subtractDuration } from './dates.js';
import type { Json } from './util.js';

export interface CredentialTypePolicy {
  /** Stable identifier used in results and APIs, e.g. "pension". */
  id: string;
  /** Human-readable labels per locale, e.g. { fi: "Eläkeläinen", en: "Pensioner" }. */
  label?: Record<string, string>;
  /** Accepted `vct` values. */
  vct: string[];
  /** Claims that must be disclosed and equal one of the given values. Keys are dot-separated claim paths. */
  require?: Record<string, unknown>;
  /** A date claim after which the credential no longer qualifies (date-only values are inclusive). */
  validUntilClaim?: string;
  /** Optional maximum age based on a date claim, e.g. { claim: "Muodostettu", duration: "P3M" }. */
  maxAge?: { claim: string; duration: string };
  /** Claims to request from the wallet and return in results (beyond those in `require`). */
  disclose?: string[];
}

export interface PolicyOutcome {
  ok: boolean;
  failures: string[];
  /** Latest instant (epoch ms) at which the credential still satisfies the policy, if bounded. */
  validUntil?: number;
}

export function findPolicy(policies: CredentialTypePolicy[], vct: unknown): CredentialTypePolicy | undefined {
  return typeof vct === 'string' ? policies.find((p) => p.vct.includes(vct)) : undefined;
}

export function getClaim(claims: Json, path: string): unknown {
  let node: unknown = claims;
  for (const seg of path.split('.')) {
    if (node === null || typeof node !== 'object') return undefined;
    node = (node as Record<string, unknown>)[seg];
  }
  return node;
}

export function evaluatePolicy(policy: CredentialTypePolicy, claims: Json, nowMs: number, timeZone: string): PolicyOutcome {
  const failures: string[] = [];
  let validUntil: number | undefined;

  for (const [path, expected] of Object.entries(policy.require ?? {})) {
    const actual = getClaim(claims, path);
    if (actual === undefined) {
      failures.push(`Required claim "${path}" was not disclosed`);
      continue;
    }
    const accepted = Array.isArray(expected) ? expected : [expected];
    if (!accepted.some((e) => looselyEqual(actual, e))) failures.push(`Claim "${path}" has value ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
  }

  if (policy.validUntilClaim) {
    const raw = getClaim(claims, policy.validUntilClaim);
    const d = parseClaimDate(raw, timeZone);
    if (raw === undefined) failures.push(`Claim "${policy.validUntilClaim}" was not disclosed`);
    else if (!d) failures.push(`Claim "${policy.validUntilClaim}" is not a recognisable date: ${JSON.stringify(raw)}`);
    else if (d.end < nowMs) failures.push(`Validity ended (${policy.validUntilClaim} = ${String(raw)})`);
    else validUntil = d.end;
  }

  if (policy.maxAge) {
    const raw = getClaim(claims, policy.maxAge.claim);
    const d = parseClaimDate(raw, timeZone);
    if (raw === undefined) failures.push(`Claim "${policy.maxAge.claim}" was not disclosed`);
    else if (!d) failures.push(`Claim "${policy.maxAge.claim}" is not a recognisable date: ${JSON.stringify(raw)}`);
    else {
      const oldestAccepted = subtractDuration(nowMs, policy.maxAge.duration);
      if (d.start < oldestAccepted) failures.push(`Credential is older than allowed (${policy.maxAge.claim} = ${String(raw)}, max age ${policy.maxAge.duration})`);
      else {
        // Inverse of subtractDuration is not exact for months; good enough as an informational bound.
        const ageLimit = d.start + (nowMs - oldestAccepted);
        validUntil = validUntil === undefined ? ageLimit : Math.min(validUntil, ageLimit);
      }
    }
  }

  return { ok: failures.length === 0, failures, validUntil };
}

/** Robust comparison: issuers may encode booleans and numbers as strings ("true", "1"). */
function looselyEqual(actual: unknown, expected: unknown): boolean {
  if (actual === expected) return true;
  if (typeof expected === 'boolean' && typeof actual === 'string') return actual.trim().toLowerCase() === String(expected);
  if (typeof expected === 'number' && typeof actual === 'string') return actual.trim() !== '' && Number(actual) === expected;
  if (typeof expected === 'string' && typeof actual === 'string') return actual.trim().toLowerCase() === expected.trim().toLowerCase();
  return false;
}

/** All claim paths a policy needs disclosed (used to build DCQL queries and filter results). */
export function claimsOfInterest(policy: CredentialTypePolicy): string[] {
  return [
    ...new Set([
      ...Object.keys(policy.require ?? {}),
      ...(policy.validUntilClaim ? [policy.validUntilClaim] : []),
      ...(policy.maxAge ? [policy.maxAge.claim] : []),
      ...(policy.disclose ?? []),
    ]),
  ];
}
