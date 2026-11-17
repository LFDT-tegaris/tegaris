/** Independent canonical/crypto test input only. Never used to seed business
 * states or to grant the retained runtime-retirement actors any authority. */
import { authorityEnvelopeDigest, encodeEnvelopeProposal } from './codec.js';
import type {
  EnvelopeActorEvidence,
  EnvelopeAuthorityBinding,
  EnvelopeProposal,
  EnvelopeScope,
  IdentityAuthorityEnvelope,
} from './types.js';

export const envelopeFixtureId = (n: number) =>
  `018f0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
export const envelopeFixtureDigest = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
export function envelopeFixtureScope(depth = 2): EnvelopeScope {
  const dimensions = () => ({
    participantIds: [envelopeFixtureId(1)],
    privacyDomainIds: [envelopeFixtureId(2)],
    resourceIds: [envelopeFixtureId(3)],
    dataClasses: ['METADATA'],
    targetProfileIds: ['target-1'],
    riskClasses: ['HIGH'] as ['HIGH'],
  });
  return {
    administration: { ...dimensions(), actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'] },
    runtime: { ...dimensions(), capabilityIds: ['CALL_RESULT_DISCLOSURE'] },
    validFromNs: '1800000000000000000',
    validUntilNs: '1800003600000000000',
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: depth,
  };
}
function authority(principal: number): EnvelopeAuthorityBinding {
  return {
    participantId: envelopeFixtureId(1),
    participantEpoch: '2',
    principalId: envelopeFixtureId(principal),
    principalEpoch: '3',
    sessionId: envelopeFixtureId(principal + 10),
    sessionEpoch: '4',
    assignmentId: envelopeFixtureId(principal + 20),
    assignmentVersion: '5',
    authorityEnvelopeId: envelopeFixtureId(50),
    authorityEpoch: '6',
    delegationEpoch: '7',
    roleId: `urn:openpc:role:${envelopeFixtureId(principal + 30)}`,
    roleVersion: '8',
    roleDigest: envelopeFixtureDigest(principal),
    authorityDigest: envelopeFixtureDigest(principal + 1),
  };
}
function actor(principal: number, challenge: number): EnvelopeActorEvidence {
  return {
    authority: authority(principal),
    stepUpChallengeId: envelopeFixtureId(challenge),
    stepUpEvidenceDigest: envelopeFixtureDigest(challenge),
    signerCredentialId: envelopeFixtureId(principal + 40),
    signerCredentialEpoch: '9',
  };
}
export function identityEnvelopeFixture(keyId: string): IdentityAuthorityEnvelope {
  const proposal: EnvelopeProposal = {
    envelopeId: envelopeFixtureId(60),
    semanticRevision: '1',
    participantId: envelopeFixtureId(1),
    participantEpoch: '2',
    authorityEpoch: '6',
    delegationEpoch: '7',
    issuance: 'PLATFORM_ROOT',
    usable: envelopeFixtureScope(),
    grantable: envelopeFixtureScope(),
    issuer: {
      kind: 'PLATFORM',
      authority: authority(100),
      platformContextId: envelopeFixtureId(4),
      platformAuthorityEpoch: '10',
      platformAuthorityDigest: envelopeFixtureDigest(10),
      parent: null,
    },
  };
  const proposalBytes = encodeEnvelopeProposal(proposal);
  return {
    proposalBytes,
    proposalDigest: authorityEnvelopeDigest(proposalBytes),
    submission: {
      operationId: envelopeFixtureId(201),
      candidateId: envelopeFixtureId(202),
      candidateDigest: envelopeFixtureDigest(202),
      approvalRequestId: envelopeFixtureId(203),
      approvalDigest: envelopeFixtureDigest(203),
      submittedVersion: '2',
      approvedVersion: '3',
      maker: actor(100, 204),
      checker: actor(101, 205),
    },
    activation: {
      operationId: envelopeFixtureId(211),
      candidateId: envelopeFixtureId(212),
      candidateDigest: envelopeFixtureDigest(212),
      approvalRequestId: envelopeFixtureId(213),
      approvalDigest: envelopeFixtureDigest(213),
      expectedApprovedVersion: '3',
      activeVersion: '4',
      idempotencyBindingDigest: envelopeFixtureDigest(214),
      actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE',
      maker: actor(100, 214),
      checker: actor(101, 215),
    },
    signer: {
      environmentId: 'test',
      participantId: envelopeFixtureId(1),
      privacyDomainId: envelopeFixtureId(2),
      profileId: 'identity-authority-envelope-v1',
      profileVersion: '1',
      profileDigest: envelopeFixtureDigest(220),
      keyId,
      keyVersion: 'version-1',
      workloadCredentialId: envelopeFixtureId(221),
      workloadCredentialEpoch: '11',
      trustContextDigest: envelopeFixtureDigest(222),
    },
    issuedAtNs: '1800000001000000000',
  };
}
