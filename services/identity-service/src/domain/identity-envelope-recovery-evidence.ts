import { createHash } from 'node:crypto';
import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import type { IdentityEnvelopeRecoveryEnrollment } from '../contracts/identity-envelope-recovery.js';
import type { IdentityRuntimeEvidenceSigner } from './identity-kernel.js';
import { identityActorKeyDigest } from './identity-runtime-authorization.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

/** Purpose338 authenticates recovery evidence. It never signs a purpose371
 * envelope or grants ordinary administrator/runtime authority. */
export function identityEnvelopeRecoveryEvidencePayload(input: {
  enrollment: IdentityEnvelopeRecoveryEnrollment;
  operationId: string;
  actorPrincipalId: string;
  purpose: 'activation' | 'closure' | 'rotation-creation' | 'rotation-phase';
  value: unknown;
  authenticationDigest: string;
  issuedAt: string;
  expiresAt: string;
}) {
  const commit = (purpose: string, value: unknown) =>
    canonicalAuthorizationDigestBytes({
      domain: `pc.identity.envelope-recovery.${purpose}.v1`,
      value,
    });
  const e = input.enrollment;
  return encodeIdentityAuthContextAssertionPayload({
    assertionId: input.operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(e.participantId, input.actorPrincipalId),
    participantContextDigest: commit('context', [
      e.participantId,
      e.privacyDomainId,
      e.platformContextId,
      e.rootEpoch,
      e.rootRevision,
      e.rootDigest,
      e.installationDigest,
    ]),
    audienceDigest: commit(input.purpose, input.value),
    senderBindingKind: 1,
    senderCredentialBindingDigest: commit('executor', e.recoveryPrincipal),
    assuranceProfileDigest: commit('assurance', [
      e.assurance,
      'independent-two-custodian-webauthn-uv',
      'exact-371-rotation-only',
      'no-runtime-capability',
    ]),
    authorityVectorDigest: commit('custody', e),
    authenticationEvidenceDigest: Buffer.from(input.authenticationDigest.slice(7), 'hex'),
    issuedAtNs: BigInt(Date.parse(input.issuedAt)) * 1000000n,
    expiresAtNs: BigInt(Date.parse(input.expiresAt)) * 1000000n,
  });
}

export async function signIdentityEnvelopeRecoveryEvidence(
  payload: Buffer,
  signer: IdentityRuntimeEvidenceSigner,
) {
  const signed = await signer.signCanonicalAssertion(payload);
  if (
    !signed.evidenceCbor.equals(payload) ||
    !signed.evidenceDigest.equals(createHash('sha256').update(payload).digest()) ||
    !(await signer.verifyCanonicalAssertion(payload, signed.coseSign1))
  )
    throw new PlatformRecoveryError();
  return signed;
}
