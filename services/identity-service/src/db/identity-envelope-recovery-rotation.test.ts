import { createHash } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { identityEnvelopeRecoveryLease } from '../contracts/identity-envelope-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import { identityEnvelopeRecoveryEvidencePayload } from '../domain/identity-envelope-recovery-evidence.js';
import {
  createIdentityEnvelopeRecoveryRotation,
  authenticateIdentityEnvelopeRecoveryRotationCreation,
  resolveIdentityEnvelopeRecoveryRotationOperation,
} from './identity-envelope-recovery-rotation.js';
const owner = vi.hoisted(() => ({ read: vi.fn(), purpose: vi.fn() }));
vi.mock('./identity-envelope-recovery-readback.js', () => ({
  readIdentityEnvelopeRecoveryReceipt: owner.read,
}));
vi.mock('./recovery-enrollment-purpose.js', () => ({
  readRecoveryEnrollmentPurpose: owner.purpose,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentDigest: canonicalAuthorizationDigest(f.enrollment),
    intentDigest: 'sha256:' + '11'.repeat(32),
    rotationId: id(401),
    creationOperationId: id(402),
    activationOperationId: id(403),
    executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
    issuer: {
      participantId: f.enrollment.participantId,
      privacyDomainId: f.enrollment.privacyDomainId,
      workloadCredentialId: f.enrollment.request.workloadCredentialId,
      workloadPrincipalId: f.enrollment.issuerPrincipalId,
      workloadParticipantEpoch: '7',
      workloadPrincipalEpoch: '2',
      workloadCredentialEpoch: '1',
      workloadPublicKeyDigest: f.enrollment.issuerCredentialPublicKeyDigest,
      credentialValidFromNs: (BigInt(f.now.getTime()) * 1000000n).toString(),
      credentialValidUntilNs: null,
    },
    oldTrustDigest: f.enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    proofIds: [id(600), id(601), id(602), id(603)],
    proofEvidenceDigest: 'sha256:' + '77'.repeat(32),
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  const actor = {
    participantId: f.enrollment.participantId,
    principalId: lease.executorPrincipalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  const receipt = { lease, authority: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' };
  owner.read.mockResolvedValue({ enrollment: f.enrollment, receipt });
  owner.purpose.mockResolvedValue('pc.identity.identity-envelope-recovery-enrollment');
  const saved = {
    request: f.enrollment.request,
    recoveryId: lease.recoveryId,
    candidateDigest: canonicalAuthorizationDigestBytes({ request: f.enrollment.request, lease }),
    maker: actor.principalId,
    approvalId: null,
    approvedOperationId: lease.activationOperationId,
    createdAt: f.now,
    state: 'PREPARED',
    revision: '3',
  };
  let prior = false;
  let current = true;
  let now = f.now;
  let eventDigest: Buffer | undefined;
  const result = {
    schema: 'pc.identity.identity-envelope-recovery-rotation-creation',
    schemaVersion: 1,
    operationId: lease.creationOperationId,
    recoveryId: lease.recoveryId,
    enrollmentId: f.enrollment.enrollmentId,
    rotationId: lease.rotationId,
    candidateDigest: canonicalAuthorizationDigest({ request: f.enrollment.request, lease }),
    revision: '2',
    state: 'APPROVED',
    createdAt: f.now.toISOString(),
  };
  const payload = identityEnvelopeRecoveryEvidencePayload({
    enrollment: f.enrollment,
    operationId: lease.creationOperationId,
    actorPrincipalId: actor.principalId,
    purpose: 'rotation-creation',
    value: result,
    authenticationDigest: lease.proofEvidenceDigest,
    issuedAt: result.createdAt,
    expiresAt: lease.validUntil,
  });
  const query = vi.fn(async (sql: string, parameters?: unknown[]) => {
    void parameters;
    if (sql.includes('join control.platform_recovery_case c'))
      return { rowCount: prior ? 1 : 0, rows: prior ? [saved] : [] };
    if (sql.includes('for update')) return { rowCount: prior ? 1 : 0, rows: prior ? [saved] : [] };
    if (sql.includes('clock_timestamp() as now')) return { rowCount: 1, rows: [{ now, current }] };
    if (sql.includes('from control.action_intent'))
      return {
        rowCount: 1,
        rows: [{ digest: Buffer.from(f.enrollment.request.actionIntentDigest.slice(7), 'hex') }],
      };
    if (sql.includes('select payload_cbor'))
      return {
        rowCount: 1,
        rows: [
          {
            cbor: payload,
            digest: eventDigest ?? createHash('sha256').update(payload).digest(),
            cose: Buffer.from('unit-only'),
          },
        ],
      };
    if (sql.startsWith('select * from openpc.lock')) return { rowCount: 1, rows: [] };
    if (/^(insert|update)/u.test(sql)) return { rowCount: 1, rows: [] };
    throw new Error('unexpected SQL');
  });
  const signer = {
    signCanonicalAssertion: vi.fn(async (cbor: Buffer) => ({
      evidenceCbor: cbor,
      evidenceDigest: createHash('sha256').update(cbor).digest(),
      coseSign1: Buffer.from('unit-only'),
      signerKeyDigest: Buffer.alloc(32, 1),
    })),
    verifyCanonicalAssertion: vi.fn(async () => ({ signerKeyDigest: Buffer.alloc(32, 1) })),
  };
  const client = { query } as never;
  const create = (op = lease.creationOperationId) =>
    createIdentityEnvelopeRecoveryRotation(
      client,
      actor,
      f.enrollment.enrollmentId,
      lease.recoveryId,
      op,
      true,
      signer,
    );
  const resolve = () =>
    resolveIdentityEnvelopeRecoveryRotationOperation(
      client,
      actor,
      f.enrollment.enrollmentId,
      lease.recoveryId,
      true,
      signer,
    );
  return {
    ...f,
    lease,
    actor,
    receipt,
    saved,
    query,
    client,
    signer,
    create,
    resolve,
    prior: () => {
      prior = true;
    },
    expired: () => {
      now = new Date(f.now.getTime() + 900000);
      receipt.authority = 'NONE';
      current = false;
    },
    corruptEvent: () => {
      eventDigest = Buffer.alloc(32, 9);
    },
    stale: () => {
      current = false;
    },
  };
}
const mutations = (f: ReturnType<typeof fixture>) =>
  f.query.mock.calls.filter(([sql]) => /^(insert|update|delete)/u.test(sql));
it('resolves only the authenticated executor reservation, with no mutation', async () => {
  const f = fixture();
  expect(await f.resolve()).toBe(f.lease.creationOperationId);
  expect(owner.read).toHaveBeenCalledWith(
    expect.anything(),
    f.actor,
    f.enrollment.enrollmentId,
    f.lease.recoveryId,
    true,
    f.signer,
    'CUSTODY_ONLY',
  );
  expect(mutations(f)).toEqual([]);
  owner.purpose.mockResolvedValue('pc.identity.platform-recovery-enrollment');
  await expect(f.resolve()).rejects.toThrow();
});
it('creates exactly one custody-bound shared rotation and original signed outbox, without provider or ordinary approval effects', async () => {
  const f = fixture();
  expect(await f.create()).toMatchObject({
    rotationId: f.lease.rotationId,
    operationId: f.lease.creationOperationId,
    state: 'APPROVED',
    revision: '2',
    replay: false,
  });
  expect(owner.read.mock.calls[0]).toHaveLength(6);
  const writes = mutations(f);
  expect(writes).toHaveLength(4);
  expect(writes[0]![0]).toContain('recovery_case_id');
  expect(writes[1]![1]).toContain(f.lease.activationOperationId);
  expect(writes[3]![1]).toContain(f.lease.creationOperationId);
  expect(
    writes.every(
      ([sql]) =>
        !/(approval_request|authority_envelope|signing_provider_attempt|business_signing_key)/u.test(
          sql,
        ),
    ),
  ).toBe(true);
  expect(f.signer.signCanonicalAssertion).toHaveBeenCalledOnce();
});
it('replays authenticated historical creation after expiry with no new signing or mutation', async () => {
  const f = fixture();
  f.prior();
  f.expired();
  expect(await f.create()).toMatchObject({
    replay: true,
    state: 'APPROVED',
    currentState: 'PREPARED',
    currentRevision: '3',
    authority: 'NONE',
  });
  expect(mutations(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  expect(f.signer.verifyCanonicalAssertion).toHaveBeenCalledOnce();
});
it.each(['expired', 'stale', 'foreign-executor', 'wrong-operation', 'missing-lease'] as const)(
  'denies new creation for %s before signing or mutation',
  async (kind) => {
    const f = fixture();
    if (kind === 'expired') f.expired();
    if (kind === 'stale') f.stale();
    if (kind === 'foreign-executor') f.actor.principalId = id(104);
    if (kind === 'missing-lease')
      owner.read.mockResolvedValue({ enrollment: f.enrollment, receipt: { authority: 'NONE' } });
    await expect(f.create(kind === 'wrong-operation' ? id(800) : undefined)).rejects.toThrow();
    expect(mutations(f)).toEqual([]);
    expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  },
);
it.each([
  'request',
  'candidate',
  'case',
  'ordinary-approval',
  'activation',
  'event-digest',
  'signature',
] as const)('denies tampered historical %s without new effects', async (kind) => {
  const f = fixture();
  f.prior();
  if (kind === 'request') f.saved.request = { ...f.saved.request, reason: 'changed original' };
  if (kind === 'candidate') f.saved.candidateDigest = Buffer.alloc(32, 9);
  if (kind === 'case') f.saved.recoveryId = id(800);
  if (kind === 'ordinary-approval') Object.assign(f.saved, { approvalId: id(800) });
  if (kind === 'activation') f.saved.approvedOperationId = id(800);
  if (kind === 'event-digest') f.corruptEvent();
  if (kind === 'signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false as never);
  await expect(f.create()).rejects.toThrow();
  expect(mutations(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it('signer failure cannot begin durable rotation writes', async () => {
  const f = fixture();
  f.signer.signCanonicalAssertion.mockRejectedValue(new Error('signer unavailable'));
  await expect(f.create()).rejects.toThrow();
  expect(mutations(f)).toEqual([]);
});
it('failed rotation CAS propagates so the caller transaction rolls back', async () => {
  const f = fixture();
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation(async (sql: string) =>
    sql.startsWith('update control.signing_key_rotation')
      ? { rowCount: 0, rows: [] }
      : original(sql),
  );
  await expect(f.create()).rejects.toThrow();
  expect(mutations(f)).toHaveLength(2);
});

it('resolves the original reservation without current lease authority or new signing', async () => {
  const f = fixture();
  f.expired();
  expect(await f.resolve()).toBe(f.lease.creationOperationId);
  expect(mutations(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['foreign-executor', 'missing-lease', 'invalid-custody-or-session'] as const)(
  'immutable reservation resolution denies %s',
  async (failure) => {
    const f = fixture();
    if (failure === 'foreign-executor') f.actor.principalId = id(999);
    if (failure === 'missing-lease')
      owner.read.mockResolvedValue({ receipt: { authority: 'NONE' } });
    if (failure === 'invalid-custody-or-session')
      owner.read.mockRejectedValue(Error('invalid custody or session'));
    await expect(f.resolve()).rejects.toThrow();
    expect(mutations(f)).toEqual([]);
    expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  },
);

function readOriginal(f: ReturnType<typeof fixture>, operationId = f.lease.creationOperationId) {
  return authenticateIdentityEnvelopeRecoveryRotationCreation(
    f.client,
    {
      kind: 'HISTORICAL',
      subject: {
        participantId: f.actor.participantId,
        principalId: f.actor.principalId,
      },
    },
    f.enrollment,
    f.lease,
    operationId,
    f.signer,
  );
}
it('verifies existing original creation after expiry without current eligibility, signing, mutation or authority', async () => {
  const f = fixture();
  f.prior();
  f.expired();
  const result = await readOriginal(f);
  expect(result).toMatchObject({
    state: 'APPROVED',
    revision: '2',
    operationId: f.lease.creationOperationId,
  });
  expect(result).not.toHaveProperty('authority');
  expect(owner.read).not.toHaveBeenCalled();
  expect(f.query.mock.calls.every(([sql]) => !sql.includes('lease_current'))).toBe(true);
  expect(f.query.mock.calls[0]![0]).toContain('c.lease_bindings=$7::jsonb');
  expect(mutations(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  expect(f.signer.verifyCanonicalAssertion).toHaveBeenCalledOnce();
});
it('never creates or signs when immutable creation is absent', async () => {
  const f = fixture();
  await expect(readOriginal(f)).rejects.toThrow();
  expect(mutations(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each([
  'wrong-actor',
  'wrong-operation',
  'enrollment-digest',
  'old-trust',
  'executor',
  'request',
  'case',
  'candidate',
  'ordinary-approval',
  'activation',
  'early-time',
  'expired-time',
  'event-digest',
  'event-bytes',
  'signature',
  'missing-event',
] as const)('immutable creation denies %s without fallback or new effects', async (failure) => {
  const f = fixture();
  f.prior();
  if (failure === 'wrong-actor') f.actor.principalId = id(999);
  if (failure === 'enrollment-digest') f.lease.enrollmentDigest = 'sha256:' + 'ff'.repeat(32);
  if (failure === 'old-trust') f.lease.oldTrustDigest = 'sha256:' + 'ff'.repeat(32);
  if (failure === 'executor') f.lease.executorPrincipalId = id(999);
  if (failure === 'request') f.saved.request = { ...f.saved.request, reason: 'changed' };
  if (failure === 'case') f.saved.recoveryId = id(999);
  if (failure === 'candidate') f.saved.candidateDigest = Buffer.alloc(32, 9);
  if (failure === 'ordinary-approval') Object.assign(f.saved, { approvalId: id(999) });
  if (failure === 'activation') f.saved.approvedOperationId = id(999);
  if (failure === 'early-time') f.saved.createdAt = new Date(Date.parse(f.lease.validFrom) - 1);
  if (failure === 'expired-time') f.saved.createdAt = new Date(f.lease.validUntil);
  if (failure === 'event-digest') f.corruptEvent();
  if (failure === 'signature')
    f.signer.verifyCanonicalAssertion.mockResolvedValue(undefined as never);
  if (failure === 'missing-event' || failure === 'event-bytes') {
    const query = f.query.getMockImplementation()!;
    f.query.mockImplementation(async (sql, values) =>
      sql.includes('select payload_cbor')
        ? failure === 'missing-event'
          ? { rowCount: 0, rows: [] }
          : {
              rowCount: 1,
              rows: [
                {
                  cbor: Buffer.from('changed'),
                  digest: Buffer.alloc(32),
                  cose: Buffer.from('changed'),
                },
              ],
            }
        : query(sql, values),
    );
  }
  await expect(
    readOriginal(f, failure === 'wrong-operation' ? id(999) : undefined),
  ).rejects.toThrow();
  expect(mutations(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
