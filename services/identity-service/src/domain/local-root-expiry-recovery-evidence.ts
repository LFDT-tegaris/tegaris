import { encodeIdentityAuthContextAssertionPayload } from '../../../../packages/security-kernel/src/index.js';
import type {
  LocalRootExpiryRecoveryEnrollment,
  LocalRootExpiryRecoveryIntent,
} from '../contracts/local-root-expiry-recovery.js';
import type { PlatformRecoveryProof } from './platform-recovery-ceremony.js';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import { identityActorKeyDigest } from './identity-runtime-authorization.js';
/** Complete signed effect binding, reconstructed for durable readback. */
export function localRootExpiryRecoveryEvidencePayload(
  enrollment: LocalRootExpiryRecoveryEnrollment,
  intent: LocalRootExpiryRecoveryIntent,
  operationId: string,
  result: unknown,
  proofs: readonly PlatformRecoveryProof[],
  issuedAtNs: bigint,
) {
  const e = enrollment,
    commit = (domain: string, value: unknown) =>
      canonicalAuthorizationDigestBytes({
        domain: `pc.identity.local-root-expiry-recovery.${domain}.v${e.schemaVersion}`,
        value,
      });
  return encodeIdentityAuthContextAssertionPayload({
    assertionId: operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(e.participantId, e.recoveryPrincipal.principalId),
    participantContextDigest: commit('context', [
      e.participantId,
      e.privacyDomainId,
      e.platformContextId,
      e.rootEpoch,
      e.rootDigest,
    ]),
    audienceDigest: commit('result', result),
    senderBindingKind: 1,
    senderCredentialBindingDigest: commit('executor', e.recoveryPrincipal),
    assuranceProfileDigest: commit('assurance', [
      e.assurance,
      'independent-two-custodian-webauthn-uv',
      'local-root-expiry-only',
      'unchanged-permissions',
    ]),
    authorityVectorDigest: commit('custody', e),
    authenticationEvidenceDigest: commit(
      'proofs',
      proofs.map(({ verifiedProofMaxAgeMs: _age, ...proof }) => ({
        ...proof,
        verifiedAt: proof.verifiedAt.toISOString(),
      })),
    ),
    issuedAtNs,
    expiresAtNs: BigInt(Date.parse(intent.validUntil)) * 1000000n,
  });
}
