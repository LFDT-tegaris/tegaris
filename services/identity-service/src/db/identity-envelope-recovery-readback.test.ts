import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { createHash } from 'node:crypto';
import { identityEnvelopeRecoveryEvidencePayload } from '../domain/identity-envelope-recovery-evidence.js';
import {
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryLease,
  identityEnvelopeRecoveryReceiptView,
} from '../contracts/identity-envelope-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { readIdentityEnvelopeRecoveryReceipt } from './identity-envelope-recovery-readback.js';
const session = vi.hoisted(() => vi.fn());
vi.mock('./platform-recovery-proof.js', () => ({ readPlatformRecoverySession: session }));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const intent = identityEnvelopeRecoveryIntent.parse({
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(f.enrollment),
    rotationId: id(401),
    creationOperationId: id(402),
    sourceParticipantEpoch: '7',
    sourceIssuerPrincipalEpoch: '1',
    sourceIssuerCredentialEpoch: '1',
    oldTrustDigest: f.enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  const row = {
    document: f.enrollment,
    documentDigest: Buffer.from(canonicalAuthorizationDigest(f.enrollment).slice(7), 'hex'),
    signature: Buffer.from(f.signed.signature, 'base64url'),
    pin: f.trust,
    intent,
    intentDigest: Buffer.from(canonicalAuthorizationDigest(intent).slice(7), 'hex'),
    state: 'EXPIRED',
    revision: '2',
    enrollmentRevision: '1',
    enrollmentState: 'REVOKED',
    pinState: 'REVOKED',
    now: new Date('2026-10-03T09:00:00.000Z'),
    bindings: null as unknown,
    activatedAt: null as Date | null,
    operationId: null as string | null,
    evidenceCbor: null as Buffer | null,
    evidenceDigest: null as Buffer | null,
    cose: null as Buffer | null,
    current: false,
    reviewedAt: null as Date | null,
  };
  const proofs: {
    principalId: string;
    phase: string;
    proofId: string;
    verifiedAt: Date;
    intentDigest: Buffer;
  }[] = [];
  const query = vi.fn(async (sql: string) =>
    sql.includes('from control.platform_recovery_proof')
      ? { rowCount: proofs.length, rows: proofs }
      : { rowCount: 1, rows: [row] },
  );
  const client = { query } as never;
  const actor = {
    participantId: f.enrollment.participantId,
    principalId: f.enrollment.custodians[0].principalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  session.mockResolvedValue({ sessionId: id(410), sessionEpoch: '1' });
  return { ...f, intent, row, proofs, query, client, actor };
}
it('reads unchanged original evidence after expiry/revocation with no lease or mutation', async () => {
  const f = fixture();
  const result = await readIdentityEnvelopeRecoveryReceipt(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    f.intent.recoveryId,
    true,
  );
  expect(result.receipt).toMatchObject({
    state: 'EXPIRED',
    authority: 'NONE',
    expired: true,
    enrollmentState: 'REVOKED',
    receivingTrustState: 'REVOKED',
  });
  expect(result.intent).toEqual(f.intent);
  expect(identityEnvelopeRecoveryReceiptView.parse(result.receipt)).toMatchObject({
    actors: {
      executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: f.enrollment.custodians.map((custodian) => custodian.principalId),
    },
    assurance: f.enrollment.assurance,
    proofs: [],
  });
  expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(sql))).toBe(false);
});
it('reads immutable proof identity/time after its session expires without treating it as fresh authority', async () => {
  const f = fixture();
  f.proofs.push({
    principalId: f.enrollment.custodians[0].principalId,
    phase: 'APPROVE',
    proofId: id(600),
    verifiedAt: f.now,
    intentDigest: f.row.intentDigest,
  });
  const result = await readIdentityEnvelopeRecoveryReceipt(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    f.intent.recoveryId,
    true,
  );
  expect(result.receipt.proofs).toEqual([
    {
      principalId: f.proofs[0]!.principalId,
      phase: 'APPROVE',
      proofId: id(600),
      verifiedAt: f.now.toISOString(),
    },
  ]);
  expect(result.receipt.authority).toBe('NONE');
});
it.each(['foreign-intent', 'future-time', 'foreign-actor', 'duplicate-proof'] as const)(
  'denies %s stored proof metadata',
  async (failure) => {
    const f = fixture();
    const proof = {
      principalId: f.enrollment.custodians[0].principalId,
      phase: 'APPROVE',
      proofId: id(600),
      verifiedAt: f.now,
      intentDigest: f.row.intentDigest,
    };
    if (failure === 'foreign-intent') proof.intentDigest = Buffer.alloc(32, 99);
    if (failure === 'future-time') proof.verifiedAt = new Date(f.row.now.getTime() + 1);
    if (failure === 'foreign-actor') proof.principalId = id(999);
    f.proofs.push(proof);
    if (failure === 'duplicate-proof') f.proofs.push({ ...proof, proofId: id(601) });
    await expect(
      readIdentityEnvelopeRecoveryReceipt(
        f.client,
        f.actor,
        f.enrollment.enrollmentId,
        f.intent.recoveryId,
        true,
      ),
    ).rejects.toThrow();
  },
);

function activatedFixture() {
  const f = fixture();
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: f.intent.recoveryId,
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentDigest: f.intent.enrollmentDigest,
    intentDigest: canonicalAuthorizationDigest(f.intent),
    rotationId: f.intent.rotationId,
    creationOperationId: f.intent.creationOperationId,
    activationOperationId: id(500),
    executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
    oldTrustDigest: f.enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    issuer: {
      participantId: f.enrollment.participantId,
      privacyDomainId: f.enrollment.privacyDomainId,
      workloadCredentialId: f.enrollment.request.workloadCredentialId,
      workloadPrincipalId: f.enrollment.issuerPrincipalId,
      workloadParticipantEpoch: '7',
      workloadPrincipalEpoch: '2',
      workloadCredentialEpoch: '1',
      workloadPublicKeyDigest: f.enrollment.issuerCredentialPublicKeyDigest,
      credentialValidFromNs: '0',
      credentialValidUntilNs: null,
    },
    proofIds: [id(510), id(511), id(512), id(513)],
    proofEvidenceDigest: 'sha256:' + 'aa'.repeat(32),
    validFrom: f.intent.validFrom,
    validUntil: f.intent.validUntil,
    postReviewRequired: true,
  });
  const payload = identityEnvelopeRecoveryEvidencePayload({
    enrollment: f.enrollment,
    operationId: lease.activationOperationId,
    actorPrincipalId: lease.executorPrincipalId,
    purpose: 'activation',
    value: lease,
    authenticationDigest: lease.proofEvidenceDigest,
    issuedAt: lease.validFrom,
    expiresAt: lease.validUntil,
  });
  Object.assign(f.row, {
    state: 'ACTIVE',
    now: f.now,
    bindings: lease,
    activatedAt: f.now,
    operationId: lease.activationOperationId,
    evidenceCbor: payload,
    evidenceDigest: createHash('sha256').update(payload).digest(),
    cose: Buffer.from('unit-only'),
    current: true,
    enrollmentState: 'ACTIVE',
    pinState: 'ACTIVE',
  });
  const verify = vi.fn(async () => ({ signerKeyDigest: Buffer.alloc(32, 1) }));
  const read = (authorityEvaluation: 'CURRENT' | 'CUSTODY_ONLY' = 'CURRENT') =>
    readIdentityEnvelopeRecoveryReceipt(
      f.client,
      f.actor,
      f.enrollment.enrollmentId,
      f.intent.recoveryId,
      true,
      { verifyCanonicalAssertion: verify } as never,
      authorityEvaluation,
    );
  return { ...f, lease, verify, read };
}
it('readback grants only the exact recorded live lease after signed-byte and current-owner verification', async () => {
  const f = activatedFixture();
  await expect(f.read()).resolves.toMatchObject({
    receipt: {
      authority: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
      lease: { rotationId: f.intent.rotationId, creationOperationId: f.intent.creationOperationId },
      postReviewStatus: 'REQUIRED',
    },
  });
  expect(f.verify).toHaveBeenCalledOnce();
  f.row.current = false;
  await expect(f.read()).resolves.toMatchObject({ receipt: { authority: 'NONE' } });
  expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(sql))).toBe(false);
});
it.each([
  'changed-binding',
  'changed-signed-bytes',
  'changed-digest',
  'changed-operation',
  'invalid-signature',
])('rejects %s without recovering or refreshing authority', async (failure) => {
  const f = activatedFixture();
  if (failure === 'changed-binding') f.lease.rotationId = id(999);
  if (failure === 'changed-signed-bytes') f.row.evidenceCbor = Buffer.from('changed');
  if (failure === 'changed-digest') f.row.evidenceDigest = Buffer.alloc(32, 0);
  if (failure === 'changed-operation') f.row.operationId = id(999);
  if (failure === 'invalid-signature') f.verify.mockResolvedValue(undefined as never);
  await expect(f.read()).rejects.toThrow();
  expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(sql))).toBe(false);
});
it('expired signed evidence stays readable with no authority or changed lease lifetime', async () => {
  const f = activatedFixture();
  f.row.now = new Date(Date.parse(f.intent.validUntil));
  await expect(f.read()).resolves.toMatchObject({
    receipt: { authority: 'NONE', lease: { validUntil: f.intent.validUntil } },
  });
});
it.each(['forged-signature', 'changed-intent', 'foreign-actor', 'lost-session', 'qa-disabled'])(
  'denies %s on historical readback',
  async (failure) => {
    const f = fixture();
    if (failure === 'forged-signature') f.row.signature = Buffer.alloc(64, 1);
    if (failure === 'changed-intent') f.row.intent.rotationId = id(499);
    if (failure === 'foreign-actor')
      f.actor.principalId = f.enrollment.administratorPrincipalIds[0];
    if (failure === 'lost-session') session.mockRejectedValue(Error('lost session'));
    await expect(
      readIdentityEnvelopeRecoveryReceipt(
        f.client,
        f.actor,
        f.enrollment.enrollmentId,
        f.intent.recoveryId,
        failure !== 'qa-disabled',
      ),
    ).rejects.toThrow();
    expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(sql))).toBe(false);
  },
);

it('custody-only readback authenticates original evidence and current session without evaluating or granting current authority', async () => {
  const f = activatedFixture();
  const result = await f.read('CUSTODY_ONLY');
  expect(result.receipt).toMatchObject({ authority: 'NONE', lease: f.lease });
  expect(f.verify).toHaveBeenCalledOnce();
  expect(session).toHaveBeenCalledOnce();
  const sql = f.query.mock.calls[0]![0];
  expect(sql).toContain('false as current');
  expect(sql).not.toContain('identity_envelope_recovery_lease_current');
  expect(f.query.mock.calls.some(([query]) => /^(insert|update|delete)/iu.test(query))).toBe(false);
});
it.each(['signature', 'binding', 'foreign-actor', 'lost-session'] as const)(
  'custody-only readback denies %s without granting or refreshing authority',
  async (failure) => {
    const f = activatedFixture();
    if (failure === 'signature') f.verify.mockResolvedValue(undefined as never);
    if (failure === 'binding') f.row.operationId = id(999);
    if (failure === 'foreign-actor') f.actor.principalId = id(999);
    if (failure === 'lost-session') session.mockRejectedValue(Error('lost session'));
    await expect(f.read('CUSTODY_ONLY')).rejects.toThrow();
    expect(f.query.mock.calls.some(([query]) => /^(insert|update|delete)/iu.test(query))).toBe(
      false,
    );
  },
);
it('rejects an unknown authority-evaluation mode before reading', async () => {
  const f = activatedFixture();
  await expect(f.read('UNKNOWN' as never)).rejects.toThrow();
  expect(f.query).not.toHaveBeenCalled();
});
