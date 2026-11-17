import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  encodeIdentityCredentialPayload,
  signIdentityCredentialCoseSign1Es256,
} from '@openpc/security-kernel';
import { createLocalIdentityRuntimeCryptoAdapter } from '../domain/identity-runtime-crypto.js';
import { createIdentityRuntimeAuthorizationAssertion } from '../domain/identity-runtime-authorization.js';
import { verifyStoredStepUpEvidence } from './verified-step-up-evidence.js';
import {
  selectCommittedIdentityStepUp,
  type CommittedIdentityStepUpInput,
} from './identity-step-up-signer.js';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';

function committedRequestFixture() {
  // SQL composition only: the returned assurance/evidence rows do not prove
  // installed roles, causal provenance, uniqueness joins, or passage of time.
  const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const assertion = Buffer.alloc(32, 7);
  const inputDigest = Buffer.alloc(32, 8);
  const input: CommittedIdentityStepUpInput = {
    participantId: id(101),
    privacyDomainId: id(201),
    principalId: id(111),
    sessionId: id(117),
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    candidateDigest: inputDigest,
    assertionBindingDigest: assertion,
    idempotencyKey: 'exact-committed-business-key',
    catalogOperationId: 'ID-OP-WORKLOAD-ISSUE',
    resourceId: id(701),
    aggregateType: 'workload-credential',
    expectedRevision: '0',
    approvalRequestId: id(601),
    checkerPrincipalId: id(112),
    checkerCredentialId: id(501),
    evidenceCbor: Buffer.from('original-checker-cbor'),
    evidenceDigest: Buffer.alloc(32, 9),
    coseSign1: Buffer.from('original-checker-cose'),
    operationId: id(801),
  };
  const record = {
    operation_id: id(801),
    input_digest: inputDigest,
    expected_revision: '0',
    assertion_digest: assertion,
    result_digest: canonicalAuthorizationDigestBytes({ credentialId: id(701) }),
    result_payload: { credentialId: id(701) },
    result_revision: '1',
    terminal_state: 'COMMITTED',
    unexpired: true,
  };
  const evidence = {
    mfaChallengeId: id(901),
    assertionBindingDigest: assertion,
    credentialId: id(502),
    credentialPublicKey: Buffer.from('key'),
    credentialPublicKeyDigest: Buffer.alloc(32, 1),
    verificationEvidenceCbor: Buffer.from('original-verify-cbor'),
    verificationEvidenceDigest: Buffer.alloc(32, 2),
    verificationCoseSign1: Buffer.from('original-verify-cose'),
    verificationCandidateDigest: Buffer.alloc(32, 3),
    verificationOccurredAt: new Date('2026-10-06T09:50:01Z'),
    verificationSessionId: id(117),
    boundParticipantEpoch: '1',
    boundPrincipalEpoch: '1',
    boundAuthorityEnvelopeId: id(401),
    boundEnvelopeEpoch: '1',
    boundAssignmentId: id(301),
  };
  const assurance = {
    fresh: true,
    source_id: id(902),
    verified_at: new Date('2026-10-06T10:00:00Z'),
    credential_id: id(503),
    credential_epoch: '2',
  };
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [record] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [assurance] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [evidence] });
  return { input, record, evidence, assurance, query, client: { query } as unknown as PoolClient };
}

it('reads the exact committed request and original verification without starting a mutation', async () => {
  const f = committedRequestFixture();
  const result = await selectCommittedIdentityStepUp(f.client, f.input, true);
  expect(result?.operationId).toBe(f.record.operation_id);
  expect(result?.mfaChallengeId).toBe(f.evidence.mfaChallengeId);
  expect(result?.assertionBindingDigest).toBe(f.record.assertion_digest);
  expect(result?.verificationEvidenceCbor).toBe(f.evidence.verificationEvidenceCbor);
  expect(result?.result).toBe(f.record.result_payload);
  expect(result?.currentAssurance).toEqual({
    sourceId: f.assurance.source_id,
    verifiedAt: f.assurance.verified_at,
    credentialId: f.assurance.credential_id,
    credentialEpoch: f.assurance.credential_epoch,
  });
  expect(result?.currentAssurance.credentialId).not.toBe(result?.credentialId);
  expect(f.query.mock.calls[0]?.[1]).toEqual([
    f.input.participantId,
    f.input.privacyDomainId,
    f.input.principalId,
    f.input.actionIntentId,
    f.input.catalogOperationId,
    f.input.idempotencyKey,
    f.input.resourceId,
    f.input.candidateDigest,
    f.input.expectedRevision,
    f.input.approvalRequestId,
  ]);
  expect(f.query.mock.calls[0]?.[0]).toContain('for update');
  expect(
    f.query.mock.calls.every((call) => !/^\s*(?:insert|update|delete)\b/iu.test(call[0])),
  ).toBe(true);
});

it.each([
  'expired',
  'changed input',
  'changed revision',
  'changed assertion',
  'changed operation',
  'missing result digest',
  'missing result revision',
  'ambiguous record',
])('rejects %s before historical evidence selection', async (kind) => {
  const f = committedRequestFixture();
  const bad = { ...f.record };
  let count = 1;
  if (kind === 'expired') bad.unexpired = false;
  if (kind === 'changed input') bad.input_digest = Buffer.alloc(32, 6);
  if (kind === 'changed revision') bad.expected_revision = '1';
  if (kind === 'changed assertion') bad.assertion_digest = Buffer.alloc(32, 6);
  if (kind === 'changed operation') bad.operation_id = f.input.resourceId;
  const row: Record<string, unknown> = { ...bad };
  if (kind === 'missing result digest') row.result_digest = null;
  if (kind === 'missing result revision') row.result_revision = null;
  if (kind === 'ambiguous record') count = 2;
  f.query
    .mockReset()
    .mockResolvedValue({ rowCount: count, rows: Array.from({ length: count }, () => row) });
  await expect(selectCommittedIdentityStepUp(f.client, f.input)).rejects.toThrow(
    'PC-IDENTITY-1009',
  );
  expect(f.query).toHaveBeenCalledOnce();
});

it.each([false, null, 'missing', 'ambiguous'])(
  'rejects %s current assurance without a historical fallback',
  async (state) => {
    const f = committedRequestFixture();
    const rows =
      state === 'missing'
        ? []
        : state === 'ambiguous'
          ? [f.assurance, f.assurance]
          : [{ ...f.assurance, fresh: state }];
    f.query
      .mockReset()
      .mockResolvedValueOnce({ rowCount: 1, rows: [f.record] })
      .mockResolvedValueOnce({ rowCount: rows.length, rows });
    await expect(selectCommittedIdentityStepUp(f.client, f.input)).rejects.toThrow('PC-AUTH-0005');
    expect(f.query).toHaveBeenCalledTimes(2);
  },
);

it.each([0, 2])(
  'rejects %s original evidence matches without choosing another challenge',
  async (count) => {
    const f = committedRequestFixture();
    f.query
      .mockReset()
      .mockResolvedValueOnce({ rowCount: 1, rows: [f.record] })
      .mockResolvedValueOnce({ rowCount: 1, rows: [f.assurance] })
      .mockResolvedValueOnce({
        rowCount: count,
        rows: Array.from({ length: count }, () => f.evidence),
      });
    await expect(selectCommittedIdentityStepUp(f.client, f.input)).rejects.toThrow(
      'PC-IDENTITY-1005',
    );
  },
);

it.each(['credential', 'epoch', 'timestamp'])(
  'rejects missing current pinned %s even when the assurance result says fresh',
  async (kind) => {
    const f = committedRequestFixture();
    const row: Record<string, unknown> = { ...f.assurance };
    if (kind === 'credential') row.credential_id = null;
    if (kind === 'epoch') row.credential_epoch = null;
    if (kind === 'timestamp') row.verified_at = null;
    f.query
      .mockReset()
      .mockResolvedValueOnce({ rowCount: 1, rows: [f.record] })
      .mockResolvedValueOnce({ rowCount: 1, rows: [row] });
    await expect(selectCommittedIdentityStepUp(f.client, f.input)).rejects.toThrow('PC-AUTH-0005');
    expect(f.query).toHaveBeenCalledTimes(2);
  },
);

it('preserves a genuinely NULL legacy source without inventing a pinned credential', async () => {
  const f = committedRequestFixture();
  f.query
    .mockReset()
    .mockResolvedValueOnce({ rowCount: 1, rows: [f.record] })
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [{ ...f.assurance, source_id: null, credential_id: null, credential_epoch: null }],
    })
    .mockResolvedValueOnce({ rowCount: 1, rows: [f.evidence] });
  const result = await selectCommittedIdentityStepUp(f.client, f.input);
  expect(result?.currentAssurance).toEqual({
    sourceId: null,
    verifiedAt: f.assurance.verified_at,
    credentialId: null,
    credentialEpoch: null,
  });
});

it.each(['APPROVED', 'PENDING'])(
  'does not select historical admission when a %s candidate has no consumed join',
  async () => {
    // The database owns this zero-row join decision, including exclusion of an
    // expired prior record. Actual APPROVED/expired SQL qualification stays open.
    const f = committedRequestFixture();
    f.query.mockReset().mockResolvedValue({ rowCount: 0, rows: [] });
    await expect(selectCommittedIdentityStepUp(f.client, f.input)).resolves.toBeUndefined();
    expect(f.query).toHaveBeenCalledOnce();
    expect(f.query.mock.calls[0]?.[1]).toEqual([
      f.input.participantId,
      f.input.privacyDomainId,
      f.input.principalId,
      f.input.actionIntentId,
      f.input.catalogOperationId,
      f.input.idempotencyKey,
      f.input.resourceId,
      f.input.candidateDigest,
      f.input.expectedRevision,
      f.input.approvalRequestId,
    ]);
  },
);

it('does not treat a matching consumed candidate with a noncommitted record as committed readback', async () => {
  const f = committedRequestFixture();
  f.query
    .mockReset()
    .mockResolvedValue({ rowCount: 1, rows: [{ ...f.record, terminal_state: null }] });
  await expect(selectCommittedIdentityStepUp(f.client, f.input)).resolves.toBeUndefined();
  expect(f.query).toHaveBeenCalledOnce();
});

it('requires the exact stored resource and credential epoch even for a valid historical ES256 signature', async () => {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' });
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const principalId = '018f0000-0000-7000-8000-000000000111';
  const evidenceCbor = encodeIdentityCredentialPayload({
    participantId: `urn:openpc:participant:${participantId}`,
    principalId: `urn:openpc:principal:${principalId}`,
    authorityEpoch: '1',
    issuedAt: '2026-09-15T00:00:00.000000Z',
    expiresAt: '2026-09-15T00:05:00.000000Z',
  });
  const coseSign1 = signIdentityCredentialCoseSign1Es256(
    keys.privateKey.export({ type: 'pkcs8', format: 'der' }),
    publicKey,
    evidenceCbor,
  );
  const input = {
    participantId,
    principalId,
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    credentialId: '018f0000-0000-7000-8000-000000000501',
    credentialEpoch: '3',
    mfaChallengeId: '018f0000-0000-7000-8000-000000000601',
    resourceId: '018f0000-0000-7000-8000-000000000701',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    candidateDigest: Buffer.alloc(32, 1),
    credentialPublicKey: publicKey,
    evidenceCbor,
    coseSign1,
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [{}] });
  const client = { query } as unknown as PoolClient;
  expect(await verifyStoredStepUpEvidence(client, input, undefined)).toBe(true);
  expect(query.mock.calls[0]![1]).toEqual([
    participantId,
    principalId,
    input.mfaChallengeId,
    input.actionIntentId,
    input.candidateDigest,
    input.resourceId,
    input.privacyDomainId,
    input.credentialId,
    evidenceCbor,
    coseSign1,
    '3',
  ]);
  // The SQL owner supplies the binding decision; a signature cannot override it.
  query.mockResolvedValueOnce({ rowCount: 0, rows: [] });
  expect(await verifyStoredStepUpEvidence(client, input, undefined)).toBe(false);
  query.mockResolvedValueOnce({ rowCount: 2, rows: [{}, {}] });
  expect(await verifyStoredStepUpEvidence(client, input, undefined)).toBe(false);
  expect(
    await verifyStoredStepUpEvidence(client, { ...input, credentialEpoch: undefined }, undefined),
  ).toBe(false);
  const altered = Buffer.from(coseSign1);
  altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
  expect(
    await verifyStoredStepUpEvidence(client, { ...input, coseSign1: altered }, undefined),
  ).toBe(false);
});

it('requires a trusted signature, committed verification, exact actor/audience and valid issuance time', async () => {
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' });
  const runtime = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: keys.privateKey.export({ type: 'pkcs8', format: 'der' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const at = new Date('2026-09-15T00:00:00Z');
  const context = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    principalId: '018f0000-0000-7000-8000-000000000111',
    sessionId: '018f0000-0000-7000-8000-000000000117',
    sessionEpoch: '1',
    sessionIssuedAt: new Date(at.getTime() - 60000),
    sessionIdleExpiresAt: new Date(at.getTime() + 600000),
    sessionAbsoluteExpiresAt: new Date(at.getTime() + 3600000),
    participantEpoch: '1',
    principalEpoch: '1',
    assignmentId: '018f0000-0000-7000-8000-000000000301',
    assignmentRowVersion: '1',
    authorityEnvelopeId: '018f0000-0000-7000-8000-000000000401',
    authorityEpoch: '1',
    delegationEpoch: '1',
    actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
    resourceId: '018f0000-0000-7000-8000-000000000117',
    candidateDigest: `sha256:${'a'.repeat(64)}`,
    sessionToken: 'test-session',
  };
  const evidenceCbor = createIdentityRuntimeAuthorizationAssertion('stored-step-up', context, at);
  const { coseSign1 } = await runtime.signCanonicalAssertion(evidenceCbor);
  const input = {
    participantId: context.participantId,
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    principalId: context.principalId,
    credentialId: '018f0000-0000-7000-8000-000000000501',
    evidenceCbor,
    coseSign1,
    credentialPublicKey: publicKey,
    approvalRequestId: '018f0000-0000-7000-8000-000000000601',
  };
  const row = {
    candidate_digest: Buffer.from('a'.repeat(64), 'hex'),
    session_id: context.sessionId,
    occurred_at: new Date(at.getTime() + 500),
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [row] });
  const client = { query } as unknown as PoolClient;
  expect(await verifyStoredStepUpEvidence(client, input, runtime)).toBe(true);
  expect(query.mock.calls[0]![0]).not.toContain(
    "challenge.consumed_at>clock_timestamp()-interval '5 minutes'",
  );
  const { approvalRequestId, ...liveEvidence } = input;
  expect(query.mock.calls[0]![1]).toContain(approvalRequestId);
  expect(
    await verifyStoredStepUpEvidence(
      client,
      {
        ...liveEvidence,
        mfaChallengeId: '018f0000-0000-7000-8000-000000000602',
        actionIntentId: context.actionIntentId,
        candidateDigest: Buffer.from('a'.repeat(64), 'hex'),
      },
      runtime,
    ),
  ).toBe(true);
  expect(query.mock.calls[1]![0]).toContain(
    "challenge.consumed_at>clock_timestamp()-interval '5 minutes'",
  );
  expect(await verifyStoredStepUpEvidence(client, input, undefined)).toBe(false);
  expect(
    await verifyStoredStepUpEvidence(
      client,
      { ...input, principalId: context.participantId },
      runtime,
    ),
  ).toBe(false);
  const altered = Buffer.from(coseSign1);
  altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
  expect(await verifyStoredStepUpEvidence(client, { ...input, coseSign1: altered }, runtime)).toBe(
    false,
  );
  for (const changed of [
    { ...row, candidate_digest: Buffer.alloc(32, 1) },
    { ...row, session_id: context.participantId },
    { ...row, occurred_at: new Date(at.getTime() - 6000) },
    { ...row, occurred_at: new Date(at.getTime() + 60001) },
  ]) {
    query.mockResolvedValueOnce({ rowCount: 1, rows: [changed] });
    expect(await verifyStoredStepUpEvidence(client, input, runtime)).toBe(false);
  }
  for (const rows of [[], [row, row]]) {
    query.mockResolvedValueOnce({ rowCount: rows.length, rows });
    expect(await verifyStoredStepUpEvidence(client, input, runtime)).toBe(false);
  }
});
