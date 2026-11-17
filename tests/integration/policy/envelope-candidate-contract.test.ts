import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { decodeEnvelopeProposal } from '../../../packages/security-kernel/src/index.js';
import { identityEnvelopeFixture } from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { projectApprovalCandidate } from '../../../services/module-registry/src/approval-candidate-contract.js';
import { projectEnvelopeApprovalCandidate } from '../../../services/module-registry/src/envelope-candidate-contract.js';
import { canonicalJson } from '../../../services/module-registry/src/domain/digest.js';

const fixture = identityEnvelopeFixture('test-review-key');
const proposal = decodeEnvelopeProposal(fixture.proposalBytes);
const hash = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;

it('projects only the versioned finite review fields from the exact canonical proposal', () => {
  const view = projectEnvelopeApprovalCandidate(fixture.proposalBytes, fixture.proposalDigest);
  expect(view).toEqual({
    schema: 'pc.identity.authority-envelope-review',
    schemaVersion: 1,
    envelopeId: proposal.envelopeId,
    participantId: proposal.participantId,
    semanticRevision: proposal.semanticRevision,
    participantEpoch: proposal.participantEpoch,
    authorityEpoch: proposal.authorityEpoch,
    delegationEpoch: proposal.delegationEpoch,
    issuance: proposal.issuance,
    usable: proposal.usable,
    grantable: proposal.grantable,
  });
  expect(JSON.stringify(view)).not.toContain(proposal.issuer.authority.sessionId);
  expect(JSON.stringify(view)).not.toContain(proposal.issuer.authority.assignmentId);
  expect(hash(view)).not.toBe(fixture.proposalDigest);
  expect(() => projectEnvelopeApprovalCandidate(fixture.proposalBytes, hash('wrong'))).toThrow(
    'PC-POLICY-2001',
  );
  const changed = Buffer.from(fixture.proposalBytes);
  changed[0] = 0;
  expect(() => projectEnvelopeApprovalCandidate(changed, hash('wrong'))).toThrow('PC-POLICY-2001');
});

it('reviews only the closed typed CREATE document under its actual catalogue action and class', () => {
  const document = {
    schema: 'pc.identity.authority-envelope-proposal',
    schemaVersion: 1,
    envelopeId: proposal.envelopeId,
    id: proposal.envelopeId,
    participantId: proposal.participantId,
    state: 'DRAFT',
    issuance: proposal.issuance,
    usable: proposal.usable,
    grantable: proposal.grantable,
  };
  const input = {
    document,
    candidateDigest: hash(document),
    catalogOperationId: 'ID-OP-ENVELOPE-CREATE',
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceType: 'participant',
    operationClass: 'UPDATE',
  };
  expect(projectApprovalCandidate(input)).toEqual({ candidate: document, redactedFields: [] });
  for (const change of [
    { operationClass: 'CREATE' },
    { catalogOperationId: 'ID-OP-ASSIGNMENT-CREATE' },
    { actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' },
    { candidateDigest: hash('wrong') },
  ])
    expect(() => projectApprovalCandidate({ ...input, ...change })).toThrow('PC-POLICY-2001');
  const injected = { ...document, issuer: proposal.issuer };
  expect(() =>
    projectApprovalCandidate({ ...input, document: injected, candidateDigest: hash(injected) }),
  ).toThrow('PC-POLICY-2001');
});
