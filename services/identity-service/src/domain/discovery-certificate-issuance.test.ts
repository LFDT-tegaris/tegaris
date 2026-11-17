import type { PoolClient } from 'pg';
import {
  trustFixture as discoveryTrustFixture,
  id as discoveryId,
} from './discovery-certificate-recovery.test-fixture.js';
import { discoveryCertificateRotationCandidate } from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import { workloadCertificateRequestDigest } from './workload-credential-issuer.js';
import {
  prepareDiscoveryCertificateIssuance,
  finishDiscoveryCertificateIssuerAttempt,
  readDiscoveryCertificateObservation,
} from '../db/discovery-certificate-issuance-store.js';
import { expect, it, vi } from 'vitest';
import {
  nextDiscoveryCertificateIssuance,
  type DiscoveryCertificateIssuanceState,
} from './discovery-certificate-issuance.js';
import type { WorkloadIssuerRecovery } from './workload-credential-issuer.js';
const now = new Date('2026-10-02T08:00:00Z'),
  expires = new Date(now.getTime() + 60000);
const issuer: WorkloadIssuerRecovery = {
  profileDigest: Buffer.alloc(32, 1),
  replayProfile: 'READBACK_REQUIRED',
  verifyObservation: () => undefined,
};
const original: DiscoveryCertificateIssuanceState = {
  state: 'PREPARED',
  issuerProfileDigest: Buffer.alloc(32, 1),
  replayProfile: 'READBACK_REQUIRED',
  attemptCount: 0,
  latestAttemptDeadline: null,
};
const policy = { attemptMs: 120000, maximumAttempts: 3 };
it('bounds a first claim by actual authority expiry and keeps observation/readback free of new issuer I/O', () => {
  expect(nextDiscoveryCertificateIssuance(original, issuer, policy, now, expires)).toEqual({
    kind: 'CLAIM',
    deadline: expires,
  });
  expect(
    nextDiscoveryCertificateIssuance(
      { ...original, state: 'OBSERVED', attemptCount: 1, latestAttemptDeadline: expires },
      issuer,
      policy,
      now,
      now,
    ),
  ).toEqual({ kind: 'COMMIT_OBSERVATION' });
  expect(
    nextDiscoveryCertificateIssuance(
      { ...original, state: 'COMMITTED', attemptCount: 1, latestAttemptDeadline: expires },
      issuer,
      policy,
      now,
      now,
    ),
  ).toEqual({ kind: 'READ_COMMITTED' });
  expect(() => nextDiscoveryCertificateIssuance(original, issuer, policy, now, now)).toThrow();
});
it('does not turn a competing in-flight call into a resend or retry production uncertainty', () => {
  const active = {
    ...original,
    state: 'ISSUING' as const,
    attemptCount: 1,
    latestAttemptDeadline: expires,
  };
  expect(nextDiscoveryCertificateIssuance(active, issuer, policy, now, expires)).toEqual({
    kind: 'IN_PROGRESS',
  });
  expect(nextDiscoveryCertificateIssuance(active, issuer, policy, expires, expires)).toEqual({
    kind: 'MARK_AMBIGUOUS',
  });
  expect(
    nextDiscoveryCertificateIssuance(
      { ...active, state: 'AMBIGUOUS' },
      issuer,
      policy,
      now,
      expires,
    ),
  ).toEqual({ kind: 'RECONCILE_REQUIRED' });
});
it('permits only a bounded separately recorded replay of the same qualified immutable profile', () => {
  const qualified = { ...issuer, replayProfile: 'IMMUTABLE_REQUEST_RESPONSE' as const };
  const unknown = {
    ...original,
    state: 'AMBIGUOUS' as const,
    replayProfile: qualified.replayProfile,
    attemptCount: 1,
    latestAttemptDeadline: now,
  };
  expect(nextDiscoveryCertificateIssuance(unknown, qualified, policy, now, expires)).toEqual({
    kind: 'CLAIM',
    deadline: expires,
  });
  expect(
    nextDiscoveryCertificateIssuance(
      { ...unknown, attemptCount: 3 },
      qualified,
      policy,
      now,
      expires,
    ),
  ).toEqual({ kind: 'ATTEMPT_LIMIT' });
  expect(() => nextDiscoveryCertificateIssuance(unknown, issuer, policy, now, expires)).toThrow();
  expect(() =>
    nextDiscoveryCertificateIssuance(
      unknown,
      { ...qualified, profileDigest: Buffer.alloc(32, 9) },
      policy,
      now,
      expires,
    ),
  ).toThrow();
  expect(() =>
    nextDiscoveryCertificateIssuance(
      { ...unknown, attemptCount: 0 },
      qualified,
      policy,
      now,
      expires,
    ),
  ).toThrow();
});

it('rejects malformed state or a certificate observation with no retained issuer attempt', () => {
  expect(() =>
    nextDiscoveryCertificateIssuance(
      { ...original, state: 'INVALID' } as never,
      issuer,
      policy,
      now,
      expires,
    ),
  ).toThrow();
  expect(() =>
    nextDiscoveryCertificateIssuance(
      { ...original, state: 'OBSERVED' },
      issuer,
      policy,
      now,
      expires,
    ),
  ).toThrow();
});

/** Database and authority facts are mocked here. These assertions cover owner
 * composition only; real role/crypto/HTTP/native qualification is separate. */
function storeFixture(state: DiscoveryCertificateIssuanceState['state'] = 'PREPARED') {
  const d = discoveryTrustFixture(),
    binding = d.intent.certificateRecovery;
  const candidate = discoveryCertificateRotationCandidate(binding);
  const request = {
    credentialId: binding.successorCredentialId,
    participantId: d.source.enrollment.participantId,
    principalId: binding.workloadPrincipalId,
    workloadId: `urn:openpc:workload:${binding.targetId}`,
    publicKeySpkiDer: Buffer.from(binding.successorPublicKeySpkiDer, 'base64'),
  };
  const row = {
    ...original,
    state,
    issuanceId: discoveryId(600),
    recoveryId: d.intent.recoveryId,
    approvalRequestId: discoveryId(601),
    certificateDer: null,
    request: { ...request, publicKeySpkiDer: request.publicKeySpkiDer.toString('base64') },
    requestDigest: workloadCertificateRequestDigest(request),
    candidateDigest: canonicalAuthorizationDigestBytes(candidate),
    attemptCount: state === 'PREPARED' ? 0 : 1,
    latestAttemptDeadline: state === 'PREPARED' ? null : expires,
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [] });
  query
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [{ intent: d.intent, candidateId: discoveryId(602), authorityExpiresAt: expires }],
    })
    .mockResolvedValueOnce({ rowCount: 1, rows: [] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [row] });
  const client = { query } as unknown as PoolClient;
  const input: Parameters<typeof prepareDiscoveryCertificateIssuance>[1] = {
    participantId: request.participantId,
    operationId: discoveryId(603),
    rotation: {
      ...request,
      replacedCredentialId: binding.predecessorCredentialId,
      predecessorEpoch: binding.predecessorEpoch,
    },
    candidate,
    proof: {
      authorized: true,
      idempotencyKey: 'original-rotation-intent',
      candidateDigest: `sha256:${row.candidateDigest.toString('hex')}`,
      privacyDomainId: d.source.enrollment.privacyDomainId,
      approvalRequestId: row.approvalRequestId,
      checkerPrincipalId: d.intent.administrators[1].principalId,
      aggregateVersion: binding.predecessorRevision,
      evidenceCbor: Buffer.from('checker-decision'),
      evidenceDigest: Buffer.alloc(32, 1),
      coseSign1: Buffer.from('checker-cose'),
      webauthnAssertionBindingDigest: Buffer.alloc(32, 2),
      evidenceKind: 'USER_WEBAUTHN',
      signerCredentialId: discoveryId(604),
    },
    authority: {
      makerAuthority: {
        principalId: d.intent.administrators[0].principalId,
        sessionId: discoveryId(605),
        sessionEpoch: '1',
        participantEpoch: '1',
        principalEpoch: '1',
        assignmentId: discoveryId(606),
        assignmentRowVersion: '1',
        authorityEnvelopeId: discoveryId(607),
        authorityEpoch: '1',
        delegationEpoch: '1',
        privacyDomainId: d.source.enrollment.privacyDomainId,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceId: binding.predecessorCredentialId,
        catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
      },
      approvalAuthorities: [],
      makerSignerCredentialId: discoveryId(604),
      checkerSignerCredentialId: discoveryId(608),
    },
    issuer,
    policy,
    now,
    newId: () => discoveryId(609),
  };
  return { d, row, request, query, client, input };
}
it('returns a claim only after the exact issuance and independent attempt writes have completed', async () => {
  const f = storeFixture();
  const result = await prepareDiscoveryCertificateIssuance(f.client, f.input);
  expect(result).toMatchObject({
    kind: 'CLAIM',
    issuanceId: f.row.issuanceId,
    deadline: expires,
    request: f.request,
  });
  expect(f.query).toHaveBeenCalledTimes(5);
  expect(f.query.mock.calls[3]![0]).toContain(
    'insert into control.discovery_certificate_issuer_attempt',
  );
  expect(f.query.mock.calls[3]![1]).toContain(f.input.operationId);
  expect(f.query.mock.calls[3]![1]).toContain(f.input.proof.webauthnAssertionBindingDigest);
  expect(f.query.mock.calls[4]![0]).toContain("state='ISSUING'");
});
it.each(['ISSUING', 'AMBIGUOUS', 'OBSERVED', 'COMMITTED', 'REJECTED'] as const)(
  'keeps %s readback free of another attempt',
  async (state) => {
    const f = storeFixture(state);
    const result = await prepareDiscoveryCertificateIssuance(f.client, f.input);
    expect(result.kind).toBe(state === 'OBSERVED' ? 'OBSERVED' : 'UNAVAILABLE');
    expect(f.query).toHaveBeenCalledTimes(3);
  },
);
it('retains an expired in-flight attempt as ambiguous and requires a later independently admitted reconciliation', async () => {
  const f = storeFixture('ISSUING');
  f.input = { ...f.input, now: expires };
  await expect(prepareDiscoveryCertificateIssuance(f.client, f.input)).resolves.toEqual({
    kind: 'UNAVAILABLE',
  });
  expect(f.query).toHaveBeenCalledTimes(5);
  expect(f.query.mock.calls[3]![0]).toContain("failure_code='CLAIM_EXPIRED'");
  expect(f.query.mock.calls[4]![0]).toContain("state='AMBIGUOUS'");
});
it.each(['maker', 'checker', 'revision', 'approval', 'request', 'candidate', 'profile', 'binding'])(
  'rejects a changed %s at the durable claim owner',
  async (failure) => {
    const f = storeFixture();
    if (failure === 'maker')
      f.input = {
        ...f.input,
        authority: {
          ...f.input.authority,
          makerAuthority: { ...f.input.authority.makerAuthority, principalId: discoveryId(999) },
        },
      };
    if (failure === 'checker')
      f.input = { ...f.input, proof: { ...f.input.proof, checkerPrincipalId: discoveryId(999) } };
    if (failure === 'revision')
      f.input = { ...f.input, proof: { ...f.input.proof, aggregateVersion: '2' } };
    if (failure === 'approval') f.row.approvalRequestId = discoveryId(999);
    if (failure === 'request') f.row.requestDigest = Buffer.alloc(32, 9);
    if (failure === 'candidate') f.row.candidateDigest = Buffer.alloc(32, 9);
    if (failure === 'profile') f.row.issuerProfileDigest = Buffer.alloc(32, 9);
    if (failure === 'binding') {
      const { webauthnAssertionBindingDigest, ...proof } = f.input.proof;
      expect(webauthnAssertionBindingDigest).toHaveLength(32);
      f.input = { ...f.input, proof };
    }
    await expect(prepareDiscoveryCertificateIssuance(f.client, f.input)).rejects.toThrow();
    expect(
      f.query.mock.calls.some((call) =>
        String(call[0]).includes('insert into control.discovery_certificate_issuer_attempt'),
      ),
    ).toBe(false);
  },
);
it('persists failed external I/O as ambiguous without certificate or business writes', async () => {
  const f = storeFixture();
  f.query.mockReset().mockResolvedValue({ rowCount: 1, rows: [] });
  await finishDiscoveryCertificateIssuerAttempt(f.client, {
    participantId: f.input.participantId,
    privacyDomainId: f.input.proof.privacyDomainId,
    issuanceId: f.row.issuanceId,
    attemptId: discoveryId(610),
  });
  expect(f.query).toHaveBeenCalledTimes(2);
  for (const call of f.query.mock.calls) {
    expect(call[0]).not.toContain('control.credential');
    expect(call[1]).toContain('AMBIGUOUS');
    expect(call[1]).toContain('HTTP_IO_AMBIGUOUS');
  }
});
it('refuses to rewrite an already terminal original attempt or mark its issuance observed', async () => {
  const f = storeFixture();
  f.query.mockReset().mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(
    finishDiscoveryCertificateIssuerAttempt(f.client, {
      participantId: f.input.participantId,
      privacyDomainId: f.input.proof.privacyDomainId,
      issuanceId: f.row.issuanceId,
      attemptId: discoveryId(610),
    }),
  ).rejects.toThrow();
  expect(f.query).toHaveBeenCalledOnce();
});
it('locks and independently verifies an observation under the same issuer profile without dispatch', async () => {
  const f = storeFixture(),
    certificateDer = Buffer.from('retained-certificate'),
    verifyObservation = vi.fn().mockReturnValue({ certificateDer });
  f.query.mockReset().mockResolvedValue({
    rowCount: 1,
    rows: [
      {
        certificateDer,
        profileDigest: issuer.profileDigest,
        replayProfile: issuer.replayProfile,
        requestDigest: f.row.requestDigest,
      },
    ],
  });
  await expect(
    readDiscoveryCertificateObservation(
      f.client,
      {
        participantId: f.input.participantId,
        privacyDomainId: f.input.proof.privacyDomainId,
        issuanceId: f.row.issuanceId,
        request: f.request,
      },
      { ...issuer, verifyObservation },
      now,
    ),
  ).resolves.toMatchObject({ certificateDer });
  expect(verifyObservation).toHaveBeenCalledWith(f.request, certificateDer, now);
  expect(f.query.mock.calls[0]![0]).toContain('for update');
});
it('denies an absent or cryptographically rejected observation before effect admission', async () => {
  const f = storeFixture();
  f.query.mockReset().mockResolvedValue({ rowCount: 0, rows: [] });
  const input = {
    participantId: f.input.participantId,
    privacyDomainId: f.input.proof.privacyDomainId,
    issuanceId: f.row.issuanceId,
    request: f.request,
  };
  await expect(readDiscoveryCertificateObservation(f.client, input, issuer, now)).rejects.toThrow();
  f.query.mockResolvedValue({
    rowCount: 1,
    rows: [
      {
        certificateDer: Buffer.from('bad'),
        profileDigest: issuer.profileDigest,
        replayProfile: issuer.replayProfile,
        requestDigest: f.row.requestDigest,
      },
    ],
  });
  await expect(readDiscoveryCertificateObservation(f.client, input, issuer, now)).rejects.toThrow();
});
