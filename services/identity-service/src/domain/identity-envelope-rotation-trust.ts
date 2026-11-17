import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import {
  assertIdentityEnvelopeRotationIssuerUnchanged,
  type IdentityEnvelopeRotationIssuer,
} from '../db/identity-envelope-rotation-issuer.js';
import {
  identityEnvelopeRotationDescriptorSchema,
  type IdentityEnvelopeRotationDescriptor,
} from './identity-envelope-rotation-provider.js';

const uuid = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const ordinaryAdmissionSchema = z.strictObject({
  rotationId: uuid,
  // Original governed creation operation; never a per-transition retry identity.
  operationId: uuid,
  candidateDigest: digest,
  approvalRequestId: uuid,
  approvalDecisionDigest: digest,
  makerPrincipalId: uuid,
  checkerPrincipalId: uuid,
  oldTrustDigest: digest,
});
const recoveryAdmissionSchema = z.strictObject({
  kind: z.literal('IDENTITY_ENVELOPE_SIGNER_RECOVERY'),
  enrollment: identityEnvelopeRecoveryEnrollment,
  lease: identityEnvelopeRecoveryLease,
});
export const identityEnvelopeRotationAdmissionSchema = z.union([
  ordinaryAdmissionSchema,
  recoveryAdmissionSchema,
]);
const admissionSchema = identityEnvelopeRotationAdmissionSchema;
export type IdentityEnvelopeRotationAdmission = z.infer<typeof admissionSchema>;

/** Construct immutable public metadata only. This never admits a key or grants
 * signing authority. The durable rotation owner must authenticate the original
 * candidate/independent decision, obtain the descriptor from its stored PREPARE
 * observation, re-fence actual actors/issuer and verify possession before INSERT.
 * Historical trust may have older issuer epochs; it is provenance, not new-use
 * authority. Its signed bytes and digest are never changed. */
export function buildIdentityEnvelopeRotationTrust(input: {
  oldTrust: IdentityEnvelopeSigningTrust;
  oldLifecycleState: 'ACTIVE' | 'REVOKED' | 'RETIRED';
  descriptor: IdentityEnvelopeRotationDescriptor;
  preparedIssuer: IdentityEnvelopeRotationIssuer;
  currentIssuer: IdentityEnvelopeRotationIssuer;
  admission: IdentityEnvelopeRotationAdmission;
  observedAtNs: bigint;
}): IdentityEnvelopeSigningTrust {
  const admission = admissionSchema.parse(input.admission);
  const descriptor = identityEnvelopeRotationDescriptorSchema.parse(input.descriptor);
  const old = input.oldTrust;
  // Canonicalization validates the exact 371 profile and rejects mixed receipt grants.
  identityEnvelopeSigningTrustPreimage(old);
  assertIdentityEnvelopeRotationIssuerUnchanged(input.preparedIssuer, input.currentIssuer);
  const issuer = input.currentIssuer;
  const recovery = 'kind' in admission ? admission : undefined;
  if (recovery !== undefined) {
    const { enrollment: e, lease } = recovery;
    // The caller must authenticate the signed enrollment/lease and stored
    // consumed proofs. This builder cannot infer custody from ordinary grants
    // or turn a lease into an approval request. Its digest retains exact
    // custody provenance independently of the ordinary approval branch.
    assertIdentityEnvelopeRotationIssuerUnchanged(lease.issuer, issuer);
    if (
      canonicalAuthorizationDigest(e) !== lease.enrollmentDigest ||
      e.enrollmentId !== lease.enrollmentId ||
      e.recoveryPrincipal.principalId !== lease.executorPrincipalId ||
      e.issuerPrincipalId !== issuer.workloadPrincipalId ||
      e.issuerParticipantEpoch !== issuer.workloadParticipantEpoch ||
      (BigInt(e.issuerPrincipalEpoch) + 1n).toString() !== issuer.workloadPrincipalEpoch ||
      e.issuerCredentialEpoch !== issuer.workloadCredentialEpoch ||
      e.issuerCredentialPublicKeyDigest !== issuer.workloadPublicKeyDigest ||
      e.oldTrustDigest !== lease.oldTrustDigest ||
      e.selectionAdmissionVersion !== lease.selectionAdmissionVersion ||
      e.participantId !== old.participantId ||
      e.privacyDomainId !== old.privacyDomainId ||
      e.request.environmentId !== old.environmentId ||
      e.request.workloadCredentialId !== issuer.workloadCredentialId ||
      e.request.oldFingerprint !== old.signerId ||
      e.request.oldReference !== old.secretReference ||
      e.request.newReference !== descriptor.reference ||
      (e.request.newFingerprint !== undefined &&
        e.request.newFingerprint !== descriptor.fingerprint) ||
      Date.parse(lease.validFrom) < Date.parse(e.validFrom) ||
      Date.parse(lease.validUntil) > Date.parse(e.validUntil) ||
      input.observedAtNs < BigInt(Date.parse(lease.validFrom)) * 1000000n ||
      input.observedAtNs >= BigInt(Date.parse(lease.validUntil)) * 1000000n
    )
      throw new Error('Identity envelope recovery admission unavailable');
  }
  const oldTrustDigest =
    'kind' in admission ? admission.lease.oldTrustDigest : admission.oldTrustDigest;
  const rotationId = 'kind' in admission ? admission.lease.rotationId : admission.rotationId;
  if (
    input.oldLifecycleState !== 'ACTIVE' ||
    oldTrustDigest !== identityEnvelopeSigningTrustDigest(old) ||
    (!('kind' in admission) && admission.makerPrincipalId === admission.checkerPrincipalId) ||
    descriptor.state !== 'ACTIVE' ||
    descriptor.fingerprint === old.signerId ||
    descriptor.reference === old.secretReference ||
    descriptor.participantId !== old.participantId ||
    descriptor.privacyDomainId !== old.privacyDomainId ||
    descriptor.environmentId !== old.environmentId ||
    (recovery === undefined &&
      (descriptor.workloadCredentialId !== old.workloadCredentialId ||
        BigInt(descriptor.workloadCredentialEpoch) !== old.workloadCredentialEpoch)) ||
    issuer.participantId !== descriptor.participantId ||
    issuer.privacyDomainId !== descriptor.privacyDomainId ||
    issuer.workloadCredentialId !== descriptor.workloadCredentialId ||
    issuer.workloadCredentialEpoch !== descriptor.workloadCredentialEpoch ||
    issuer.workloadPublicKeyDigest === descriptor.fingerprint ||
    input.observedAtNs < BigInt(descriptor.validFromNs) ||
    input.observedAtNs >= BigInt(descriptor.validUntilNs) ||
    input.observedAtNs < BigInt(issuer.credentialValidFromNs) ||
    (issuer.credentialValidUntilNs !== null &&
      BigInt(descriptor.validUntilNs) > BigInt(issuer.credentialValidUntilNs))
  )
    throw new Error('Identity envelope rotation trust unavailable');
  const admissionDigest = createHash('sha256')
    .update(
      recovery === undefined
        ? 'pc.identity.envelope-key-rotation-admission.v1\0'
        : 'pc.identity.envelope-key-recovery-admission.v1\0',
    )
    .update(
      canonicalDefinitionJson({
        ...admission,
        issuer,
        newFingerprint: descriptor.fingerprint,
        newReference: descriptor.reference,
        newVersion: descriptor.version,
      }),
    )
    .digest();
  const trust: IdentityEnvelopeSigningTrust = {
    participantId: old.participantId,
    privacyDomainId: old.privacyDomainId,
    environmentId: old.environmentId,
    signerId: descriptor.fingerprint,
    publicKeySpkiDer: Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
    workloadCredentialId: issuer.workloadCredentialId,
    workloadCredentialEpoch: BigInt(issuer.workloadCredentialEpoch),
    workloadParticipantEpoch: BigInt(issuer.workloadParticipantEpoch),
    workloadPrincipalEpoch: BigInt(issuer.workloadPrincipalEpoch),
    keyEpoch: old.keyEpoch + 1n,
    validFromNs: BigInt(descriptor.validFromNs),
    validUntilNs: BigInt(descriptor.validUntilNs),
    admissionKind: 'GOVERNED',
    admissionReference: `urn:openpc:resource:${rotationId}`,
    admissionDigest,
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: descriptor.reference,
    secretVersion: descriptor.version,
    purpose: old.purpose,
    profileId: old.profileId,
    profileVersion: old.profileVersion,
    profileDigest: old.profileDigest,
  };
  identityEnvelopeSigningTrustPreimage(trust);
  return trust;
}
