import { createHash } from 'node:crypto';
import {
  assertIdentityEnvelopeSigningTrust,
  authorityEnvelopeDigest,
  decodeEnvelopeProposal,
  encodeIdentityAuthorityEnvelope,
  identityEnvelopeContext,
  identityEnvelopeSigningTrustDigest,
  type EnvelopeActorEvidence,
  type IdentityAuthorityEnvelope,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeProviderRequestDigest,
  identityEnvelopeProviderRequestSchema,
} from '../domain/identity-envelope-signing-provider.js';
import { AuthorityFenceError } from './authority-fence.js';
import type { StoredEnvelopeProposal } from './identity-envelope-proposal.js';

/** Materialization inputs selected by the scoped activation transaction, never
 * an HTTP body or evidence of current authority. SQL reservation must bind all
 * these identities to their durable owners before any provider invocation. */
export interface EnvelopeActivationSources {
  proposal: StoredEnvelopeProposal;
  submission: {
    operationId: string;
    approvalRequestId: string;
    approvalDigest: string;
  };
  activation: {
    operationId: string;
    candidateId: string;
    candidateDigest: string;
    approvalRequestId: string;
    approvalDigest: string;
    expectedApprovedVersion: string;
    maker: EnvelopeActorEvidence;
    checker: EnvelopeActorEvidence;
  };
  idempotency: {
    recordId: string;
    key: string;
    principalId: string;
    assertionBindingDigest: string;
  };
  attemptId: string;
  callerWorkloadCredentialId: string;
  trust: IdentityEnvelopeSigningTrust;
  recordedAtNs: bigint;
}

/** Pure exact-byte construction only. It neither grants permission nor signs,
 * dispatches, consumes an approval, or changes the envelope's public state. */
export function materializeInitialEnvelopeActivation(input: EnvelopeActivationSources) {
  const { proposal: stored, activation, submission, trust, idempotency, recordedAtNs } = input;
  const proposal = decodeEnvelopeProposal(stored.bytes);
  const candidateDigest = canonicalAuthorizationDigest({ envelopeId: stored.envelopeId });
  if (
    stored.state !== 'APPROVED' ||
    stored.version !== '3' ||
    activation.expectedApprovedVersion !== stored.version ||
    stored.envelopeId !== proposal.envelopeId ||
    stored.targetParticipantId !== proposal.participantId ||
    stored.makerPrincipalId !== proposal.issuer.authority.principalId ||
    authorityEnvelopeDigest(stored.bytes) !== `sha256:${stored.digest.toString('hex')}` ||
    proposal.issuance !== 'PLATFORM_ROOT' ||
    // Cross-Participant signer installation/current-lineage qualification is a
    // separate owner. Never borrow the issuer's key for a target Participant.
    proposal.participantId !== proposal.issuer.authority.participantId ||
    trust.participantId !== proposal.participantId ||
    trust.privacyDomainId !== stored.issuerAuthority.durable.grant.privacyDomainId ||
    stored.submissionApprovalId !== submission.approvalRequestId ||
    stored.submissionMaker === null ||
    stored.submissionChecker === null ||
    activation.candidateDigest !== candidateDigest ||
    idempotency.principalId !== activation.maker.authority.principalId ||
    !idempotency.key ||
    !/^sha256:[0-9a-f]{64}$/u.test(idempotency.assertionBindingDigest) ||
    recordedAtNs % 1000n !== 0n ||
    [proposal.usable, proposal.grantable].some(
      (scope) =>
        recordedAtNs < BigInt(scope.validFromNs) || recordedAtNs >= BigInt(scope.validUntilNs),
    )
  )
    throw new AuthorityFenceError();
  const artifact: IdentityAuthorityEnvelope = {
    proposalBytes: Buffer.from(stored.bytes),
    proposalDigest: authorityEnvelopeDigest(stored.bytes),
    submission: {
      operationId: submission.operationId,
      // The existing SUBMIT owner resolves AUTHORITY_ENVELOPE directly. Its
      // subject is the immutable proposal, not the consumed CREATE candidate.
      candidateId: stored.envelopeId,
      candidateDigest: authorityEnvelopeDigest(stored.bytes),
      approvalRequestId: submission.approvalRequestId,
      approvalDigest: submission.approvalDigest,
      submittedVersion: '2',
      approvedVersion: stored.version,
      maker: stored.submissionMaker,
      checker: stored.submissionChecker,
    },
    activation: {
      ...activation,
      activeVersion: '4',
      actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE',
      idempotencyBindingDigest: canonicalAuthorizationDigest({
        domain: 'pc.identity.authority-envelope-activation-idempotency.v1',
        participantId: trust.participantId,
        privacyDomainId: trust.privacyDomainId,
        envelopeId: stored.envelopeId,
        operationId: activation.operationId,
        actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE',
        candidateDigest,
        expectedApprovedVersion: stored.version,
        ...idempotency,
      }),
    },
    signer: {
      environmentId: trust.environmentId,
      participantId: trust.participantId,
      privacyDomainId: trust.privacyDomainId,
      profileId: trust.profileId,
      profileVersion: String(trust.profileVersion),
      profileDigest: trust.profileDigest,
      keyId: trust.signerId,
      keyVersion: trust.secretVersion,
      workloadCredentialId: trust.workloadCredentialId,
      workloadCredentialEpoch: String(trust.workloadCredentialEpoch),
      trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
    },
    issuedAtNs: String(recordedAtNs),
  };
  const payload = encodeIdentityAuthorityEnvelope(artifact);
  assertIdentityEnvelopeSigningTrust(payload, trust, recordedAtNs);
  const request = identityEnvelopeProviderRequestSchema.parse({
    participantId: trust.participantId,
    privacyDomainId: trust.privacyDomainId,
    environmentId: trust.environmentId,
    workloadCredentialId: trust.workloadCredentialId,
    workloadCredentialEpoch: String(trust.workloadCredentialEpoch),
    profileId: trust.profileId,
    profileVersion: 1,
    profileDigest: trust.profileDigest,
    trustContextDigest: artifact.signer.trustContextDigest,
    secretClass: trust.secretClass,
    reference: trust.secretReference,
    version: trust.secretVersion,
    purpose: identityEnvelopeContext.purpose,
    purposeCode: identityEnvelopeContext.purposeCode,
    schemaId: identityEnvelopeContext.schemaId,
    schemaVersion: identityEnvelopeContext.schemaVersion,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    method: 'SIGN_AUTHORITY_ENVELOPE',
    callerWorkloadCredentialId: input.callerWorkloadCredentialId,
    attemptId: input.attemptId,
    operationId: activation.operationId,
    expectedFingerprint: trust.signerId,
    payloadHex: payload.toString('hex'),
  });
  return {
    payload,
    payloadDigest: createHash('sha256').update(payload).digest(),
    request,
    requestDigest: Buffer.from(identityEnvelopeProviderRequestDigest(request).slice(7), 'hex'),
  };
}
