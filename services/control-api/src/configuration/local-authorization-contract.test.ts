import { describe, expect, it } from 'vitest';

import {
  decodeLocalMutationAuthorization,
  decodeLocalPolicyAuthorization,
} from './local-authorization-contract.js';

const ids = {
  sessionId: '018f0000-0000-7000-8000-000000000001',
  participantId: '018f0000-0000-7000-8000-000000000002',
  privacyDomainId: '018f0000-0000-7000-8000-000000000003',
  principalId: '018f0000-0000-7000-8000-000000000004',
  checkerPrincipalId: '018f0000-0000-7000-8000-000000000005',
  signerCredentialId: '018f0000-0000-7000-8000-000000000006',
  approvalRequestId: '018f0000-0000-7000-8000-000000000007',
  mfaChallengeId: '018f0000-0000-7000-8000-000000000008',
  authorityEnvelopeId: '018f0000-0000-7000-8000-000000000009',
  assignmentId: '018f0000-0000-7000-8000-000000000010',
} as const;

const policyProof = {
  sessionId: ids.sessionId,
  sessionEpoch: '6',
  participantId: ids.participantId,
  principalId: ids.principalId,
  participantEpoch: '1',
  principalEpoch: '2',
  assignmentId: ids.assignmentId,
  assignmentRowVersion: '3',
  authorityEnvelopeId: ids.authorityEnvelopeId,
  authorityEpoch: '4',
  delegationEpoch: '5',
};

const mutationProof = {
  evidenceKind: 'USER_WEBAUTHN',
  sessionId: ids.sessionId,
  sessionEpoch: '6',
  participantId: ids.participantId,
  privacyDomainId: ids.privacyDomainId,
  principalId: ids.principalId,
  principalEpoch: '2',
  checkerPrincipalId: ids.checkerPrincipalId,
  signerCredentialId: ids.signerCredentialId,
  approvalRequestId: ids.approvalRequestId,
  mfaChallengeId: ids.mfaChallengeId,
  webauthnSessionId: ids.sessionId,
  participantEpoch: '1',
  authorityEnvelopeId: ids.authorityEnvelopeId,
  authorityEpoch: '4',
  delegationEpoch: '5',
  assignmentId: ids.assignmentId,
  assignmentEpoch: '3',
  webauthnAssertionBindingDigest: Buffer.alloc(32, 1).toString('base64'),
  webauthnEvidenceCbor: Buffer.from('webauthn-evidence').toString('base64'),
  webauthnEvidenceDigest: Buffer.alloc(32, 3).toString('base64'),
  webauthnCoseSign1: Buffer.from('webauthn-cose-sign1').toString('base64'),
  evidenceCbor: Buffer.from('local-evidence').toString('base64'),
  evidenceDigest: Buffer.alloc(32, 2).toString('base64'),
  coseSign1: Buffer.from('local-cose-sign1').toString('base64'),
};

describe('local authorization serialized contracts', () => {
  it('keeps step-up-only proofs distinct and requires every independent verification field', () => {
    const proof = {
      ...mutationProof,
      evidenceKind: 'IDENTITY_RUNTIME_STEP_UP',
      signerKeyDigest: Buffer.alloc(32, 4).toString('base64'),
      webauthnSignerCredentialId: ids.signerCredentialId,
    };
    const value = Object.fromEntries(
      Object.entries(proof).filter(
        ([key]) => !['signerCredentialId', 'checkerPrincipalId', 'approvalRequestId'].includes(key),
      ),
    );
    const decoded = decodeLocalMutationAuthorization(value);
    expect(decoded.evidenceKind).toBe('IDENTITY_RUNTIME_STEP_UP');
    expect(decoded.webauthnEvidenceCbor).toEqual(Buffer.from('webauthn-evidence'));
    expect(decoded.evidenceCbor).toEqual(Buffer.from('local-evidence'));
    for (const field of [
      'mfaChallengeId',
      'webauthnSessionId',
      'webauthnSignerCredentialId',
      'webauthnAssertionBindingDigest',
      'webauthnEvidenceCbor',
      'webauthnEvidenceDigest',
      'webauthnCoseSign1',
      'signerKeyDigest',
    ]) {
      expect(() =>
        decodeLocalMutationAuthorization(
          Object.fromEntries(Object.entries(value).filter(([key]) => key !== field)),
        ),
      ).toThrow();
    }
    for (const extra of [
      { approvalRequestId: ids.approvalRequestId },
      { checkerPrincipalId: ids.checkerPrincipalId },
      { signerCredentialId: ids.signerCredentialId },
      { evidenceKind: 'IDENTITY_RUNTIME' },
    ])
      expect(() => decodeLocalMutationAuthorization({ ...value, ...extra })).toThrow();
  });
  it('accepts runtime assertions without user credentials and rejects mixed proof kinds', () => {
    const proof = {
      ...policyProof,
      privacyDomainId: ids.privacyDomainId,
      assignmentEpoch: '3',
      evidenceKind: 'IDENTITY_RUNTIME',
      signerKeyDigest: Buffer.alloc(32, 4).toString('base64'),
      evidenceCbor: mutationProof.evidenceCbor,
      evidenceDigest: mutationProof.evidenceDigest,
      coseSign1: mutationProof.coseSign1,
    };
    const runtimeProof = Object.fromEntries(
      Object.entries(proof).filter(([key]) => key !== 'assignmentRowVersion'),
    );
    const decoded = decodeLocalMutationAuthorization(runtimeProof);
    expect(decoded.evidenceKind).toBe('IDENTITY_RUNTIME');
    expect(decoded.signerCredentialId).toBeUndefined();
    for (const extra of [
      { signerCredentialId: ids.signerCredentialId },
      { approvalRequestId: ids.approvalRequestId },
      { checkerPrincipalId: ids.checkerPrincipalId },
      { mfaChallengeId: ids.mfaChallengeId },
      { evidenceKind: 'READ_CONTEXT' },
      { evidenceKind: 'USER_WEBAUTHN' },
    ])
      expect(() => decodeLocalMutationAuthorization({ ...runtimeProof, ...extra })).toThrow();
  });
  it('maps the mutation-specific assignment epoch and binary proof fields', () => {
    const authorization = decodeLocalMutationAuthorization(mutationProof);
    expect(authorization.assignmentEpoch).toBe('3');
    expect(authorization.checkerPrincipalId).toBe(ids.checkerPrincipalId);
    expect(authorization.webauthnAssertionBindingDigest).toEqual(Buffer.alloc(32, 1));
    expect(authorization.webauthnEvidenceCbor).toEqual(Buffer.from('webauthn-evidence'));
    expect(authorization.evidenceCbor).toEqual(Buffer.from('local-evidence'));
  });

  it('rejects the policy-only row-version alias at the mutation boundary', () => {
    const withoutMutationEpoch = Object.fromEntries(
      Object.entries(mutationProof).filter(([key]) => key !== 'assignmentEpoch'),
    );
    expect(() =>
      decodeLocalMutationAuthorization({
        ...withoutMutationEpoch,
        assignmentRowVersion: '3',
      }),
    ).toThrow();
  });

  it('rejects a mutation proof with a non-SHA-256 evidence digest', () => {
    expect(() =>
      decodeLocalMutationAuthorization({
        ...mutationProof,
        evidenceDigest: Buffer.alloc(31).toString('base64'),
      }),
    ).toThrow();
  });

  it('maps the policy row version into the internal assignment epoch', () => {
    const authorization = decodeLocalPolicyAuthorization(policyProof, ids.privacyDomainId);
    expect(authorization.privacyDomainId).toBe(ids.privacyDomainId);
    expect(authorization.assignmentEpoch).toBe('3');
  });
});
