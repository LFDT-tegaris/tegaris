import { generateKeyPairSync, sign } from 'node:crypto';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../../identity-service/src/contracts/authorization.js';
import {
  identityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryLease,
} from '../../identity-service/src/contracts/identity-envelope-recovery.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../../identity-service/src/domain/identity-envelope-recovery.test-fixture.js';
import {
  planIdentityEnvelopeRotationAttempts,
  type IdentityEnvelopeRotationPlanInput,
} from '../../identity-service/src/domain/identity-envelope-rotation-plan.js';
import {
  identityEnvelopeRotationDescriptorSchema,
  identityEnvelopeRotationPossessionPreimage,
  identityEnvelopeRotationRequestDigest,
} from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';
import { authenticateIdentityEnvelopeRotationDualProof } from './identity-envelope-rotation-proof.js';

export function identityEnvelopeDualProofFixture(
  options: { expiredPredecessor?: boolean; continuedCredential?: boolean } = {},
) {
  const f = identityEnvelopeRecoveryFixture();
  const at = BigInt(f.now.getTime()) * 1000000n;
  const oldKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const newKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const oldSpki = Buffer.from(oldKey.publicKey.export({ type: 'spki', format: 'der' }));
  const newSpki = Buffer.from(newKey.publicKey.export({ type: 'spki', format: 'der' }));
  const oldTrust: IdentityEnvelopeSigningTrust = {
    participantId: f.enrollment.participantId,
    privacyDomainId: f.enrollment.privacyDomainId,
    environmentId: 'local',
    signerId: evidenceKeyId(oldSpki),
    publicKeySpkiDer: oldSpki,
    workloadCredentialId: f.enrollment.request.workloadCredentialId,
    workloadCredentialEpoch: 1n,
    workloadParticipantEpoch: 1n,
    workloadPrincipalEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: at - 1000000n,
    validUntilNs: options.expiredPredecessor === true ? at - 1000n : at + 7200000000000n,
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'unit-original-trust',
    admissionDigest: Buffer.alloc(32, 1),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: f.enrollment.request.oldReference,
    secretVersion: '1',
    purpose: identityEnvelopeContext.purpose,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  const enrollment = identityEnvelopeRecoveryEnrollment.parse({
    ...f.enrollment,
    oldTrustDigest: identityEnvelopeSigningTrustDigest(oldTrust),
    issuerCredentialEpoch: options.continuedCredential ? '2' : f.enrollment.issuerCredentialEpoch,
    request: {
      ...f.enrollment.request,
      oldFingerprint: oldTrust.signerId,
      workloadCredentialId: options.continuedCredential
        ? id(991)
        : f.enrollment.request.workloadCredentialId,
    },
  });
  const issuer = {
    participantId: enrollment.participantId,
    privacyDomainId: enrollment.privacyDomainId,
    workloadCredentialId: enrollment.request.workloadCredentialId,
    workloadPrincipalId: enrollment.issuerPrincipalId,
    workloadParticipantEpoch: '7',
    workloadPrincipalEpoch: '2',
    workloadCredentialEpoch: enrollment.issuerCredentialEpoch,
    workloadPublicKeyDigest: enrollment.issuerCredentialPublicKeyDigest,
    credentialValidFromNs: (at - 1000000n).toString(),
    credentialValidUntilNs: (at + 7200000000000n).toString(),
  };
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: enrollment.enrollmentId,
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    intentDigest: 'sha256:' + '71'.repeat(32),
    rotationId: id(401),
    creationOperationId: id(402),
    activationOperationId: id(403),
    executorPrincipalId: enrollment.recoveryPrincipal.principalId,
    issuer,
    oldTrustDigest: enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    proofIds: [id(600), id(601), id(602), id(603)],
    proofEvidenceDigest: 'sha256:' + '72'.repeat(32),
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  const descriptor = identityEnvelopeRotationDescriptorSchema.parse({
    participantId: issuer.participantId,
    privacyDomainId: issuer.privacyDomainId,
    environmentId: 'local',
    workloadCredentialId: issuer.workloadCredentialId,
    workloadCredentialEpoch: issuer.workloadCredentialEpoch,
    secretClass: 'SECRET-SIGNING-KEY',
    reference: enrollment.request.newReference,
    version: '2',
    purpose: identityEnvelopeContext.purpose,
    purposeCode: 371,
    schemaId: 24034,
    schemaVersion: 1,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
    algorithm: 'ES256',
    fingerprint: evidenceKeyId(newSpki),
    publicKeySpkiHex: newSpki.toString('hex'),
    validFromNs: at.toString(),
    validUntilNs: (at + 3600000000000n).toString(),
    state: 'ACTIVE',
    revokedAtNs: null,
    retiredAtNs: null,
  });
  const input: {
    -readonly [K in keyof IdentityEnvelopeRotationPlanInput]: IdentityEnvelopeRotationPlanInput[K];
  } = {
    request: enrollment.request,
    rotationId: lease.rotationId,
    operationId: id(700),
    state: 'DISTRIBUTED',
    toState: 'VERIFIED',
    oldTrust,
    preparedIssuer: issuer,
    currentIssuer: { ...issuer },
    admission: { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment, lease },
    descriptor,
    callerWorkloadCredentialId: issuer.workloadCredentialId,
    nowNs: at + 10000000n,
    authorityValidUntilNs: at + 900000000000n,
  };
  let attempt = 710;
  const plan = planIdentityEnvelopeRotationAttempts(input, () => id(attempt++));
  const records = plan.attempts.map(({ slot, request }) => {
    if (request.method !== 'PROVE') throw Error('invalid dual proof fixture');
    const old = slot === 'old';
    const observedDescriptor = old
      ? {
          ...descriptor,
          workloadCredentialId: oldTrust.workloadCredentialId,
          workloadCredentialEpoch: oldTrust.workloadCredentialEpoch.toString(),
          reference: oldTrust.secretReference,
          version: oldTrust.secretVersion,
          fingerprint: oldTrust.signerId,
          publicKeySpkiHex: oldSpki.toString('hex'),
          validFromNs: oldTrust.validFromNs.toString(),
          validUntilNs: oldTrust.validUntilNs.toString(),
        }
      : descriptor;
    const observation = {
      schemaVersion: 1,
      providerId: 'unit-provider',
      method: 'PROVE',
      operationId: request.operationId,
      attemptId: request.attemptId,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
      recordedAtNs: (input.nowNs + 500000n).toString(),
      outcome: 'SUCCEEDED',
      reason: null,
      descriptor: observedDescriptor,
      resultHex: sign('sha256', identityEnvelopeRotationPossessionPreimage(request), {
        key: old ? oldKey.privateKey : newKey.privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('hex'),
    };
    return { slot, request, firstObservation: { ...observation }, observation };
  });
  input.nowNs += 1000000n;
  return {
    input,
    records,
    trust: plan.successor!,
    newKey,
    oldKey,
    authenticate: () => authenticateIdentityEnvelopeRotationDualProof(input, records),
  };
}

export function identityEnvelopeEffectiveProofFixture() {
  const f = identityEnvelopeDualProofFixture();
  const input = {
    ...f.input,
    selectedTrust: f.trust,
    state: 'CUTOVER_FENCED' as const,
    toState: 'OBSERVING' as const,
    nowNs: f.input.nowNs + 1000000n,
  };
  const plan = planIdentityEnvelopeRotationAttempts(input, () => id(720));
  const attempt = plan.attempts[0]!;
  if (attempt.request.method !== 'PROVE') throw Error('invalid effective proof fixture');
  const observation = {
    schemaVersion: 1,
    providerId: 'unit-provider',
    method: 'PROVE',
    operationId: attempt.request.operationId,
    attemptId: attempt.request.attemptId,
    requestDigest: identityEnvelopeRotationRequestDigest(attempt.request),
    recordedAtNs: (input.nowNs + 500000n).toString(),
    outcome: 'SUCCEEDED',
    reason: null,
    descriptor: input.descriptor!,
    resultHex: sign('sha256', identityEnvelopeRotationPossessionPreimage(attempt.request), {
      key: f.newKey.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex'),
  };
  const record = {
    slot: attempt.slot,
    request: attempt.request,
    firstObservation: { ...observation },
    observation,
  };
  input.nowNs += 1000000n;
  return { ...f, input, record };
}
