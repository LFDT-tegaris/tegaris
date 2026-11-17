import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  signingRotationActions,
  type EnvelopeSigningRotationRequest,
  type SigningRotationState,
  SigningRotationError,
  envelopeSigningRotationRequestSchema,
} from './signing-rotation.js';
import { signingTransitionEffects } from '../../../../packages/security-kernel/src/signing-transitions.js';
import {
  buildIdentityEnvelopeRotationTrust,
  identityEnvelopeRotationAdmissionSchema,
  type IdentityEnvelopeRotationAdmission,
} from './identity-envelope-rotation-trust.js';
import {
  identityEnvelopeRotationRequestSchema,
  type IdentityEnvelopeRotationDescriptor,
  type IdentityEnvelopeRotationRequest,
} from './identity-envelope-rotation-provider.js';
import {
  assertIdentityEnvelopeRotationIssuerUnchanged,
  type IdentityEnvelopeRotationIssuer,
} from '../db/identity-envelope-rotation-issuer.js';

export interface IdentityEnvelopeRotationPlanInput {
  readonly request: EnvelopeSigningRotationRequest;
  readonly rotationId: string;
  readonly operationId: string;
  readonly state: SigningRotationState;
  readonly toState: SigningRotationState;
  readonly oldTrust: IdentityEnvelopeSigningTrust;
  readonly preparedIssuer: IdentityEnvelopeRotationIssuer;
  readonly currentIssuer: IdentityEnvelopeRotationIssuer;
  readonly admission: IdentityEnvelopeRotationAdmission;
  readonly descriptor?: IdentityEnvelopeRotationDescriptor;
  readonly callerWorkloadCredentialId: string;
  readonly nowNs: bigint;
  readonly authorityValidUntilNs: bigint;
}

/** Immutable planning only. The current custody/ordinary owner must fence
 * actual authority and commit these exact attempts before Participant I/O. */
export function planIdentityEnvelopeRotationAttempts(
  input: IdentityEnvelopeRotationPlanInput,
  attemptId: () => string,
) {
  const request = envelopeSigningRotationRequestSchema.parse(input.request);
  const admission = identityEnvelopeRotationAdmissionSchema.parse(input.admission);
  const effects = signingTransitionEffects(
    signingRotationActions.advance,
    input.state,
    input.toState,
  );
  assertIdentityEnvelopeRotationIssuerUnchanged(input.preparedIssuer, input.currentIssuer);
  const issuer = input.currentIssuer;
  const recovery = 'kind' in admission ? admission : undefined;
  const rotationId = 'kind' in admission ? admission.lease.rotationId : admission.rotationId;
  const oldDigest = 'kind' in admission ? admission.lease.oldTrustDigest : admission.oldTrustDigest;
  const leaseUntil =
    recovery === undefined
      ? input.authorityValidUntilNs
      : BigInt(Date.parse(recovery.lease.validUntil)) * 1000000n;
  if (
    !effects ||
    effects.kind !== 'ADVANCE' ||
    effects.resumeFrom !== null ||
    rotationId !== input.rotationId ||
    oldDigest !== identityEnvelopeSigningTrustDigest(input.oldTrust) ||
    issuer.participantId !== input.oldTrust.participantId ||
    issuer.privacyDomainId !== input.oldTrust.privacyDomainId ||
    request.environmentId !== input.oldTrust.environmentId ||
    request.workloadCredentialId !== issuer.workloadCredentialId ||
    (recovery === undefined &&
      (request.workloadCredentialId !== input.oldTrust.workloadCredentialId ||
        issuer.workloadCredentialEpoch !== input.oldTrust.workloadCredentialEpoch.toString())) ||
    request.oldReference !== input.oldTrust.secretReference ||
    request.oldFingerprint !== input.oldTrust.signerId ||
    input.callerWorkloadCredentialId !== issuer.workloadCredentialId ||
    input.authorityValidUntilNs > leaseUntil ||
    input.nowNs >= input.authorityValidUntilNs ||
    (issuer.credentialValidUntilNs !== null &&
      input.authorityValidUntilNs > BigInt(issuer.credentialValidUntilNs))
  )
    throw new SigningRotationError('DENIED');
  if (
    recovery !== undefined &&
    (canonicalAuthorizationDigest(request) !==
      canonicalAuthorizationDigest(recovery.enrollment.request) ||
      canonicalAuthorizationDigest(recovery.enrollment) !== recovery.lease.enrollmentDigest ||
      canonicalAuthorizationDigest(recovery.lease.issuer) !==
        canonicalAuthorizationDigest(issuer) ||
      recovery.enrollment.enrollmentId !== recovery.lease.enrollmentId ||
      recovery.enrollment.recoveryPrincipal.principalId !== recovery.lease.executorPrincipalId ||
      recovery.enrollment.issuerPrincipalId !== issuer.workloadPrincipalId ||
      recovery.enrollment.issuerParticipantEpoch !== issuer.workloadParticipantEpoch ||
      (BigInt(recovery.enrollment.issuerPrincipalEpoch) + 1n).toString() !==
        issuer.workloadPrincipalEpoch ||
      recovery.enrollment.issuerCredentialEpoch !== issuer.workloadCredentialEpoch ||
      recovery.enrollment.issuerCredentialPublicKeyDigest !== issuer.workloadPublicKeyDigest ||
      recovery.enrollment.oldTrustDigest !== recovery.lease.oldTrustDigest ||
      recovery.enrollment.selectionAdmissionVersion !== recovery.lease.selectionAdmissionVersion ||
      recovery.enrollment.participantId !== issuer.participantId ||
      recovery.enrollment.privacyDomainId !== issuer.privacyDomainId ||
      Date.parse(recovery.lease.validFrom) < Date.parse(recovery.enrollment.validFrom) ||
      Date.parse(recovery.lease.validUntil) > Date.parse(recovery.enrollment.validUntil) ||
      input.nowNs < BigInt(Date.parse(recovery.lease.validFrom)) * 1000000n)
  )
    throw new SigningRotationError('DENIED');
  const governanceDigest = canonicalAuthorizationDigest({
    domain: 'pc.identity.envelope-rotation-governance.v1',
    admission,
  });
  let successor: IdentityEnvelopeSigningTrust | undefined;
  if (input.descriptor !== undefined)
    successor = buildIdentityEnvelopeRotationTrust({
      oldTrust: input.oldTrust,
      oldLifecycleState: 'ACTIVE',
      descriptor: input.descriptor,
      preparedIssuer: input.preparedIssuer,
      currentIssuer: issuer,
      admission,
      observedAtNs: input.nowNs,
    });
  if (effects.providerSteps.some(([, method]) => method !== 'PREPARE') && !successor)
    throw new SigningRotationError('CONFLICT');
  const attempts = effects.providerSteps.map(([slot, method]) => {
    const old = slot === 'old';
    const reference = old ? request.oldReference : request.newReference;
    const common = {
      participantId: issuer.participantId,
      privacyDomainId: issuer.privacyDomainId,
      environmentId: request.environmentId,
      workloadCredentialId: issuer.workloadCredentialId,
      workloadCredentialEpoch: issuer.workloadCredentialEpoch,
      secretClass: 'SECRET-SIGNING-KEY' as const,
      reference,
      version: reference.slice(reference.lastIndexOf('#') + 1),
      purpose: identityEnvelopeContext.purpose,
      purposeCode: 371 as const,
      schemaId: 24034 as const,
      schemaVersion: 1 as const,
      schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
      profileId: identityEnvelopeSigningProfile.profileId,
      profileVersion: 1 as const,
      profileDigest: identityEnvelopeSigningProfileDigest,
      callerWorkloadCredentialId: input.callerWorkloadCredentialId,
      rotationId: input.rotationId,
      operationId: input.operationId,
      attemptId: attemptId(),
      issuerParticipantEpoch: issuer.workloadParticipantEpoch,
      issuerPrincipalEpoch: issuer.workloadPrincipalEpoch,
      governanceDigest,
    };
    let value: IdentityEnvelopeRotationRequest;
    if (method === 'PREPARE')
      value = identityEnvelopeRotationRequestSchema.parse({
        ...common,
        method,
        ...(request.newFingerprint === undefined
          ? {}
          : { expectedFingerprint: request.newFingerprint }),
      });
    else {
      if (!successor || !input.descriptor) throw new SigningRotationError('CONFLICT');
      const expectedFingerprint = old ? request.oldFingerprint : input.descriptor.fingerprint;
      if (method === 'DISTRIBUTE')
        value = identityEnvelopeRotationRequestSchema.parse({
          ...common,
          method,
          expectedFingerprint,
          trustContextDigest: identityEnvelopeSigningTrustDigest(successor),
        });
      else if (method === 'PROVE') {
        const recoveryPredecessor =
          old && recovery !== undefined
            ? {
                purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' as const,
                enrollmentId: recovery.lease.enrollmentId,
                enrollmentDigest: recovery.lease.enrollmentDigest,
                recoveryId: recovery.lease.recoveryId,
                activationOperationId: recovery.lease.activationOperationId,
                leaseDigest: canonicalAuthorizationDigest(recovery.lease),
                oldTrustDigest: recovery.lease.oldTrustDigest,
              }
            : undefined;
        const end = [
          input.nowNs + 300000000000n,
          input.authorityValidUntilNs,
          ...(recoveryPredecessor !== undefined
            ? []
            : [BigInt(old ? input.oldTrust.validUntilNs : input.descriptor.validUntilNs)]),
        ].reduce((a, b) => (a < b ? a : b));
        value = identityEnvelopeRotationRequestSchema.parse({
          ...common,
          method,
          expectedFingerprint,
          challengeHex: identityEnvelopeSigningTrustDigest(successor).slice(7),
          challengeIssuedAtNs: input.nowNs.toString(),
          challengeExpiresAtNs: end.toString(),
          ...(recoveryPredecessor === undefined ? {} : { recoveryPredecessor }),
        });
      } else
        value = identityEnvelopeRotationRequestSchema.parse({
          ...common,
          method,
          expectedFingerprint,
        });
    }
    return { slot, request: value };
  });
  if (new Set(attempts.map((a) => a.request.attemptId)).size !== attempts.length)
    throw new SigningRotationError('CONFLICT');
  return { attempts, successor, governanceDigest };
}
