import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  authorityEnvelopeDigest,
  decodeEnvelopeProposal,
  decodeIdentityAuthorityEnvelope,
  encodeEnvelopeProposal,
  evidenceKeyId,
  identityEnvelopeSigningProfileDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import {
  envelopeFixtureId as id,
  identityEnvelopeFixture,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  materializeInitialEnvelopeActivation,
  type EnvelopeActivationSources,
} from './identity-envelope-activation-payload.js';

function sources(): EnvelopeActivationSources {
  const publicKeySpkiDer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export(
    {
      type: 'spki',
      format: 'der',
    },
  );
  const artifact = identityEnvelopeFixture(evidenceKeyId(publicKeySpkiDer));
  const proposal = decodeEnvelopeProposal(artifact.proposalBytes);
  const trust: IdentityEnvelopeSigningTrust = {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'test',
    signerId: evidenceKeyId(publicKeySpkiDer),
    publicKeySpkiDer,
    workloadCredentialId: id(221),
    workloadCredentialEpoch: 11n,
    workloadParticipantEpoch: 2n,
    workloadPrincipalEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: 1800000000000000000n,
    validUntilNs: 1800003600000000000n,
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'independent-initial-trust',
    admissionDigest: Buffer.alloc(32, 1),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/envelope#version-1',
    secretVersion: 'version-1',
    purpose: 'pc.cose.identity-authority-envelope.v1',
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  const captured = (evidence: typeof artifact.submission.maker) => ({
    binding: evidence.authority,
    durable: {
      grant: {
        ...evidence.authority,
        assignmentRowVersion: evidence.authority.assignmentVersion,
        privacyDomainId: trust.privacyDomainId,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceId: proposal.envelopeId,
      },
      dependencies: {},
    },
  });
  return {
    proposal: {
      envelopeId: proposal.envelopeId,
      targetParticipantId: proposal.participantId,
      makerPrincipalId: proposal.issuer.authority.principalId,
      bytes: artifact.proposalBytes,
      digest: Buffer.from(artifact.proposalDigest.slice(7), 'hex'),
      issuerAuthority: captured(artifact.submission.maker),
      state: 'APPROVED',
      version: '3',
      submissionApprovalId: artifact.submission.approvalRequestId,
      submissionMaker: artifact.submission.maker,
      submissionChecker: artifact.submission.checker,
      submissionCheckerAuthority: captured(artifact.submission.checker),
    },
    submission: artifact.submission,
    activation: {
      ...artifact.activation,
      candidateDigest: canonicalAuthorizationDigest({ envelopeId: proposal.envelopeId }),
    },
    idempotency: {
      recordId: id(300),
      key: 'independent-envelope-activation-1',
      principalId: artifact.activation.maker.authority.principalId,
      assertionBindingDigest: `sha256:${'01'.repeat(32)}`,
    },
    attemptId: id(301),
    callerWorkloadCredentialId: id(302),
    trust,
    recordedAtNs: 1800000001000000000n,
  };
}

describe('typed activation materialization before durable reservation', () => {
  it('uses exact submitted bytes, the actual submission subject and separate ACTIVATE identity', () => {
    const input = sources();
    const result = materializeInitialEnvelopeActivation(input);
    const artifact = decodeIdentityAuthorityEnvelope(result.payload);
    expect(artifact.proposalBytes).toEqual(input.proposal.bytes);
    expect(artifact.submission).toMatchObject({
      candidateId: input.proposal.envelopeId,
      candidateDigest: authorityEnvelopeDigest(input.proposal.bytes),
      approvalRequestId: input.proposal.submissionApprovalId,
      submittedVersion: '2',
      approvedVersion: '3',
    });
    expect(artifact.activation).toMatchObject({
      operationId: input.activation.operationId,
      candidateId: input.activation.candidateId,
      expectedApprovedVersion: '3',
      activeVersion: '4',
    });
    expect(result.request.payloadHex).toBe(result.payload.toString('hex'));
    expect(result.request.attemptId).toBe(input.attemptId);
    expect(result.payloadDigest).toEqual(createHash('sha256').update(result.payload).digest());
    expect(materializeInitialEnvelopeActivation(input)).toEqual(result);
  });

  it.each([
    ['unsigned draft', (s: EnvelopeActivationSources) => (s.proposal.state = 'DRAFT')],
    [
      'stale version',
      (s: EnvelopeActivationSources) => (s.activation.expectedApprovedVersion = '2'),
    ],
    [
      'other approval',
      (s: EnvelopeActivationSources) => (s.submission.approvalRequestId = id(400)),
    ],
    [
      'other candidate',
      (s: EnvelopeActivationSources) =>
        (s.activation.candidateDigest = `sha256:${'00'.repeat(32)}`),
    ],
    [
      'different principal',
      (s: EnvelopeActivationSources) => (s.idempotency.principalId = id(400)),
    ],
    [
      'reused approval',
      (s: EnvelopeActivationSources) =>
        (s.activation.approvalRequestId = s.submission.approvalRequestId),
    ],
    [
      'reused proof',
      (s: EnvelopeActivationSources) =>
        (s.activation.maker.stepUpChallengeId = s.proposal.submissionMaker!.stepUpChallengeId),
    ],
    [
      'foreign signer privacy',
      (s: EnvelopeActivationSources) => (s.trust = { ...s.trust, privacyDomainId: id(400) }),
    ],
    ['expired scope', (s: EnvelopeActivationSources) => (s.recordedAtNs = 1800003600000000000n)],
    [
      'expired signer',
      (s: EnvelopeActivationSources) => (s.trust = { ...s.trust, validUntilNs: s.recordedAtNs }),
    ],
    ['proposal digest', (s: EnvelopeActivationSources) => (s.proposal.digest = Buffer.alloc(32))],
  ])('rejects %s before producing a provider request', (_name, change) => {
    const input = sources();
    change(input);
    expect(() => materializeInitialEnvelopeActivation(input)).toThrow();
  });

  it('does not reinterpret a cross-Participant root as the issuer signer scope', () => {
    const input = sources();
    const proposal = decodeEnvelopeProposal(input.proposal.bytes);
    proposal.participantId = id(400);
    input.proposal.targetParticipantId = proposal.participantId;
    input.proposal.bytes = encodeEnvelopeProposal(proposal);
    input.proposal.digest = Buffer.from(
      authorityEnvelopeDigest(input.proposal.bytes).slice(7),
      'hex',
    );
    expect(() => materializeInitialEnvelopeActivation(input)).toThrow();
  });

  it('binds the original complete idempotency identity and caller without mutating sources', () => {
    const input = sources();
    const originalBytes = Buffer.from(input.proposal.bytes);
    const first = materializeInitialEnvelopeActivation(input);
    const changed = materializeInitialEnvelopeActivation({
      ...input,
      idempotency: { ...input.idempotency, key: 'independent-envelope-activation-2' },
    });
    expect(changed.payload).not.toEqual(first.payload);
    expect(changed.requestDigest).not.toEqual(first.requestDigest);
    expect(input.proposal.bytes).toEqual(originalBytes);
    expect(decodeIdentityAuthorityEnvelope(first.payload).signer.keyId).toBe(input.trust.signerId);
  });
});
