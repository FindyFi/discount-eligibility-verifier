export { Verifier, type VerifierConfig, type VerificationExpectations, type VerificationResult, type Check, type CheckId } from './verifier.js';
export { FederationResolver, resolveMetadata, type TrustAnchorConfig, type TrustChainResult, type EntityStatement } from './federation.js';
export { parseSdJwt, reconstructClaims, SdJwtFormatError, type ParsedSdJwt, type Disclosure } from './sdjwt.js';
export { evaluatePolicy, claimsOfInterest, type CredentialTypePolicy } from './policy.js';
export { parseClaimDate } from './dates.js';
export type { Fetcher } from './util.js';
