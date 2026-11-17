import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import { identityEnvelopeRecoveryLease } from '../contracts/identity-envelope-recovery.js';
import { identityEnvelopeRotationRequestDigest } from '../domain/identity-envelope-rotation-provider.js';
import {
  queueIdentityEnvelopeRecoveryRotation,
  resolveIdentityEnvelopeRecoveryRotationStep,
} from './identity-envelope-recovery-rotation-queue.js';
const owner = vi.hoisted(() => ({
  read: vi.fn(),
  resolve: vi.fn(),
  creation: vi.fn(),
  source: vi.fn(),
  plan: vi.fn(),
  publish: vi.fn(),
  prepared: vi.fn(),
  distributed: vi.fn(),
  successor: vi.fn(),
  consumer: vi.fn(),
}));
vi.mock('./identity-envelope-recovery-rotation-prepare.js', () => ({
  publishIdentityEnvelopeRecoveryRotationPhase: owner.publish,
  readIdentityEnvelopeRecoveryPreparedDescriptor: owner.prepared,
  readIdentityEnvelopeRecoveryDistributedDescriptor: owner.distributed,
}));
vi.mock('./identity-envelope-recovery-readback.js', () => ({
  readIdentityEnvelopeRecoveryReceipt: owner.read,
}));
vi.mock('./identity-envelope-recovery-rotation.js', () => ({
  resolveIdentityEnvelopeRecoveryRotationOperation: owner.resolve,
  authenticateIdentityEnvelopeRecoveryRotationCreation: owner.creation,
}));
vi.mock('./identity-envelope-rotation-successor-source.js', () => ({
  captureIdentityEnvelopeRotationSuccessorSource: owner.successor,
}));
vi.mock('../../../participant-service/src/identity-envelope-rotation-consumer.js', () => ({
  readIdentityEnvelopeRotationConsumer: owner.consumer,
}));
vi.mock('./identity-envelope-rotation-candidate.js', () => ({
  captureIdentityEnvelopeRotationSource: owner.source,
}));
vi.mock('../domain/identity-envelope-rotation-plan.js', () => ({
  planIdentityEnvelopeRotationAttempts: owner.plan,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const issuer = {
    participantId: f.enrollment.participantId,
    privacyDomainId: f.enrollment.privacyDomainId,
    workloadCredentialId: f.enrollment.request.workloadCredentialId,
    workloadPrincipalId: f.enrollment.issuerPrincipalId,
    workloadParticipantEpoch: '7',
    workloadPrincipalEpoch: '2',
    workloadCredentialEpoch: '1',
    workloadPublicKeyDigest: f.enrollment.issuerCredentialPublicKeyDigest,
    credentialValidFromNs: '1791007200000000000',
    credentialValidUntilNs: null,
  };
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
    issuer,
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
  const binding = { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment: f.enrollment, lease };
  const command = {
    kind: 'ROTATION_ADVANCE' as const,
    recoveryId: lease.recoveryId,
    expectedRevision: '2',
    idempotencyKey: 'original-custody-phase-0001',
  };
  const step = {
    operationId: id(700),
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    principalId: actor.principalId,
    fromRevision: '2',
    fromState: 'APPROVED',
    toState: 'PREPARED',
    state: 'STARTED',
    authorityBinding: binding,
    authorityDigest: canonicalAuthorizationDigestBytes(binding),
  };
  const request = {
    participantId: f.enrollment.participantId,
    privacyDomainId: f.enrollment.privacyDomainId,
    environmentId: f.enrollment.request.environmentId,
    workloadCredentialId: issuer.workloadCredentialId,
    workloadCredentialEpoch: '1',
    secretClass: 'SECRET-SIGNING-KEY' as const,
    reference: f.enrollment.request.newReference,
    version: '2',
    purpose: identityEnvelopeContext.purpose,
    purposeCode: 371 as const,
    schemaId: 24034 as const,
    schemaVersion: 1 as const,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: 'pc.identity.authority-envelope.v1' as const,
    profileVersion: 1 as const,
    profileDigest: identityEnvelopeSigningProfileDigest,
    callerWorkloadCredentialId: issuer.workloadCredentialId,
    rotationId: lease.rotationId,
    operationId: step.operationId,
    attemptId: id(701),
    issuerParticipantEpoch: '7',
    issuerPrincipalEpoch: '2',
    governanceDigest: canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-rotation-governance.v1',
      admission: binding,
    }),
    method: 'PREPARE' as const,
  } as const;
  const attempt = {
    slot: 'new',
    request,
    digest: Buffer.from(identityEnvelopeRotationRequestDigest(request).slice(7), 'hex'),
    state: 'STARTED',
    first: null,
    observation: null,
    ambiguityKind: null as string | null,
  };
  let previous = false;
  const rotation = { state: 'APPROVED', revision: '2', recoveryId: lease.recoveryId };
  const query = vi.fn(
    async (sql: string, params?: unknown[]): Promise<{ rowCount: number; rows: unknown[] }> => {
      void params;
      if (sql.startsWith('update control.identity_envelope_rotation_step')) {
        step.state = 'STARTED';
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes('from control.identity_envelope_rotation_step'))
        return { rowCount: previous ? 1 : 0, rows: previous ? [step] : [] };
      if (sql.includes('from control.identity_envelope_rotation_attempt'))
        return { rowCount: 1, rows: [attempt] };
      if (sql.includes('from control.signing_key_rotation'))
        return { rowCount: 1, rows: [rotation] };
      if (sql.startsWith('select * from openpc.lock')) return { rowCount: 1, rows: [] };
      if (sql.startsWith('insert')) return { rowCount: 1, rows: [] };
      throw new Error('unexpected SQL');
    },
  );
  owner.read.mockResolvedValue({ enrollment: f.enrollment, receipt });
  owner.resolve.mockResolvedValue(lease.creationOperationId);
  owner.source.mockResolvedValue({
    trust: { unit: 'old' },
    issuer,
    recordedAtNs: BigInt(f.now.getTime()) * 1000000n,
  });
  owner.plan.mockReturnValue({ attempts: [{ slot: 'new', request }] });
  const client = { query } as never;
  const queue = (op = step.operationId) =>
    queueIdentityEnvelopeRecoveryRotation(
      client,
      actor,
      f.enrollment.enrollmentId,
      command,
      op,
      true,
      {} as never,
    );
  const resolve = () =>
    resolveIdentityEnvelopeRecoveryRotationStep(
      client,
      actor,
      f.enrollment.enrollmentId,
      command,
      true,
      {} as never,
    );
  return {
    ...f,
    lease,
    actor,
    receipt,
    binding,
    command,
    step,
    request,
    attempt,
    rotation,
    query,
    queue,
    resolve,
    previous: () => {
      previous = true;
    },
  };
}
const writes = (f: ReturnType<typeof fixture>) =>
  f.query.mock.calls.filter(([sql]) => /^(insert|update|delete)/u.test(sql));

it('queues DISTRIBUTE only from authenticated prepared metadata under the original live lease', async () => {
  const f = fixture();
  f.rotation.state = 'PREPARED';
  f.rotation.revision = '3';
  f.command.expectedRevision = '3';
  const prepared = {
    descriptor: { fingerprint: 'sha256:' + '81'.repeat(32) },
    result: { trustDigest: 'sha256:' + '82'.repeat(32) },
  };
  owner.prepared.mockResolvedValue(prepared);
  const request = {
    ...f.request,
    method: 'DISTRIBUTE',
    expectedFingerprint: prepared.descriptor.fingerprint,
    trustContextDigest: prepared.result.trustDigest,
  };
  owner.plan.mockReturnValue({ attempts: [{ slot: 'new', request }] });
  expect(await f.queue()).toMatchObject({
    fromRevision: '3',
    fromState: 'PREPARED',
    toState: 'DISTRIBUTED',
    state: 'READY',
    permissionEffect: 'NONE',
    attempts: [{ method: 'DISTRIBUTE' }],
  });
  expect(owner.prepared).toHaveBeenCalledTimes(1);
  expect(owner.plan.mock.calls[0]?.[0]).toMatchObject({
    state: 'PREPARED',
    toState: 'DISTRIBUTED',
    descriptor: prepared.descriptor,
    currentIssuer: f.lease.issuer,
  });
  expect(writes(f)).toHaveLength(2);
  expect(writes(f)[0]?.[1]?.slice(10, 12)).toEqual(['PREPARED', 'DISTRIBUTED']);
});

it('denies distribution when the original signed preparation cannot authenticate', async () => {
  const f = fixture();
  f.rotation.state = 'PREPARED';
  f.rotation.revision = '3';
  f.command.expectedRevision = '3';
  owner.prepared.mockRejectedValue(new Error('original PREPARE unavailable'));
  await expect(f.queue()).rejects.toThrow('original PREPARE unavailable');
  expect(writes(f)).toHaveLength(0);
  expect(owner.plan).not.toHaveBeenCalled();
});

it.each(['trust-context', 'fingerprint', 'method'])(
  'denies changed DISTRIBUTE %s on original replay',
  async (kind) => {
    const f = fixture();
    f.previous();
    f.step.fromRevision = '3';
    f.step.fromState = 'PREPARED';
    f.step.toState = 'DISTRIBUTED';
    f.command.expectedRevision = '3';
    const prepared = {
      descriptor: { fingerprint: 'sha256:' + '81'.repeat(32) },
      result: { trustDigest: 'sha256:' + '82'.repeat(32) },
    };
    owner.prepared.mockResolvedValue(prepared);
    const request = {
      ...f.request,
      method: kind === 'method' ? 'PREPARE' : 'DISTRIBUTE',
      expectedFingerprint:
        kind === 'fingerprint' ? 'sha256:' + '83'.repeat(32) : prepared.descriptor.fingerprint,
      trustContextDigest:
        kind === 'trust-context' ? 'sha256:' + '84'.repeat(32) : prepared.result.trustDigest,
    };
    f.attempt.request = request as never;
    // Real parser also rejects the extra DISTRIBUTE field on a PREPARE request.
    if (kind !== 'method')
      f.attempt.digest = Buffer.from(
        identityEnvelopeRotationRequestDigest(request as never).slice(7),
        'hex',
      );
    await expect(f.queue()).rejects.toThrow();
    expect(writes(f)).toHaveLength(0);
  },
);

it.each(['IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY', 'NONE'])(
  'reopens only exact original lookup under %s readback authority',
  async (authority) => {
    const f = fixture();
    f.previous();
    f.step.state = 'WRITE_AMBIGUITY';
    f.attempt.state = 'WRITE_AMBIGUITY';
    f.attempt.ambiguityKind = 'NOT_FOUND';
    f.receipt.authority = authority;
    expect(await f.resolve()).toBe(f.step.operationId);
    const result = await f.queue();
    expect(result).toMatchObject({
      state: 'STARTED',
      replay: true,
      authority,
      permissionEffect: 'NONE',
      attempts: [
        { attemptId: f.request.attemptId, state: 'WRITE_AMBIGUITY', ambiguityKind: 'NOT_FOUND' },
      ],
    });
    expect(writes(f)).toHaveLength(1);
    expect(writes(f)[0]?.[0]).toContain("set state='STARTED'");
    expect(writes(f)[0]?.[1]).toEqual([
      f.step.operationId,
      f.actor.participantId,
      f.enrollment.privacyDomainId,
      f.lease.rotationId,
      f.lease.recoveryId,
      f.actor.principalId,
    ]);
    expect(owner.source).not.toHaveBeenCalled();
    expect(owner.plan).not.toHaveBeenCalled();
    expect(owner.creation).not.toHaveBeenCalled();
    expect(f.attempt.state).toBe('WRITE_AMBIGUITY');
    expect(f.attempt.ambiguityKind).toBe('NOT_FOUND');
  },
);

it.each(['READY', 'STARTED', 'OBSERVED', 'missing-failure'])(
  'does not reopen a %s attempt as historical reconciliation',
  async (kind) => {
    const f = fixture();
    f.previous();
    f.step.state = 'WRITE_AMBIGUITY';
    f.attempt.state = kind === 'missing-failure' ? 'WRITE_AMBIGUITY' : kind;
    f.attempt.ambiguityKind = kind === 'missing-failure' ? null : 'UNKNOWN';
    await expect(f.queue()).rejects.toThrow();
    expect(writes(f)).toHaveLength(0);
  },
);

it('propagates failed exact lookup reactivation instead of claiming it is queued', async () => {
  const f = fixture();
  f.previous();
  f.step.state = 'WRITE_AMBIGUITY';
  f.attempt.state = 'WRITE_AMBIGUITY';
  f.attempt.ambiguityKind = 'UNKNOWN';
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation(async (sql, params) =>
    sql.startsWith('update') ? { rowCount: 0, rows: [] } : original(sql, params),
  );
  await expect(f.queue()).rejects.toThrow();
  expect(owner.source).not.toHaveBeenCalled();
});
it('commits only one exact READY step and attempt; the queue response claims no permission or provider effect', async () => {
  const f = fixture();
  expect(await f.queue()).toMatchObject({
    operationId: f.step.operationId,
    state: 'READY',
    permissionEffect: 'NONE',
    replay: false,
  });
  const changed = writes(f);
  expect(changed).toHaveLength(2);
  expect(changed[0]![0]).toContain('identity_envelope_rotation_step');
  expect(changed[1]![1]).toContainEqual(f.request);
  expect(changed[1]![1]).toContainEqual(f.attempt.digest);
  expect(owner.creation).toHaveBeenCalledWith(
    expect.anything(),
    { kind: 'CURRENT', actor: f.actor },
    f.enrollment,
    f.lease,
    f.lease.creationOperationId,
    expect.anything(),
  );
  expect(owner.plan.mock.calls[0]![0]).toMatchObject({
    preparedIssuer: f.lease.issuer,
    admission: f.binding,
    callerWorkloadCredentialId: f.lease.issuer.workloadCredentialId,
  });
});
it('selects the original operation for exact replay, without creating new authority or attempts', async () => {
  const f = fixture();
  f.previous();
  expect(await f.resolve()).toBe(f.step.operationId);
  f.receipt.authority = 'NONE';
  expect(await f.queue()).toMatchObject({
    operationId: f.step.operationId,
    state: 'STARTED',
    replay: true,
    authority: 'NONE',
    permissionEffect: 'NONE',
  });
  expect(writes(f)).toEqual([]);
  expect(owner.source).not.toHaveBeenCalled();
  expect(owner.plan).not.toHaveBeenCalled();
  expect(owner.creation).not.toHaveBeenCalled();
});
it.each([
  'executor',
  'expired',
  'revision',
  'terminal',
  'foreign-case',
  'creation-proof',
  'issuer',
] as const)('denies new phase for %s before queue writes', async (kind) => {
  const f = fixture();
  if (kind === 'executor') f.actor.principalId = id(104);
  if (kind === 'expired') f.receipt.authority = 'NONE';
  if (kind === 'revision') f.command.expectedRevision = '3';
  if (kind === 'terminal') f.rotation.state = 'COMPLETE';
  if (kind === 'foreign-case') f.rotation.recoveryId = id(800);
  if (kind === 'creation-proof')
    owner.creation.mockRejectedValue(new Error('bad creation evidence'));
  if (kind === 'issuer')
    owner.plan.mockImplementation(() => {
      throw new Error('issuer drift');
    });
  await expect(f.queue()).rejects.toThrow();
  expect(writes(f)).toEqual([]);
});
it.each([
  'operation',
  'revision',
  'case',
  'binding',
  'binding-digest',
  'attempt-digest',
  'attempt-scope',
] as const)('denies changed original %s on replay without allocating or writing', async (kind) => {
  const f = fixture();
  f.previous();
  if (kind === 'revision') f.command.expectedRevision = '3';
  if (kind === 'case') f.step.recoveryId = id(800);
  if (kind === 'binding') f.step.authorityBinding = { ...f.binding, kind: 'changed' };
  if (kind === 'binding-digest') f.step.authorityDigest = Buffer.alloc(32, 9);
  if (kind === 'attempt-digest') f.attempt.digest = Buffer.alloc(32, 9);
  if (kind === 'attempt-scope') {
    f.attempt.request = { ...f.attempt.request, participantId: id(800) };
    f.attempt.digest = Buffer.from(
      identityEnvelopeRotationRequestDigest(f.attempt.request).slice(7),
      'hex',
    );
  }
  await expect(f.queue(kind === 'operation' ? id(800) : undefined)).rejects.toThrow();
  expect(writes(f)).toEqual([]);
  expect(owner.plan).not.toHaveBeenCalled();
});
it('failed attempt persistence propagates instead of exposing a READY success', async () => {
  const f = fixture();
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation(async (sql, params) =>
    sql.startsWith('insert into control.identity_envelope_rotation_attempt')
      ? { rowCount: 0, rows: [] }
      : original(sql, params),
  );
  await expect(f.queue()).rejects.toThrow();
  expect(writes(f)).toHaveLength(2);
});

it('queues two original possession attempts from authenticated distribution without admitting or selecting trust', async () => {
  const f = fixture();
  f.rotation.state = 'DISTRIBUTED';
  f.rotation.revision = '4';
  f.command.expectedRevision = '4';
  const distributed = {
    descriptor: { fingerprint: 'sha256:' + '81'.repeat(32) },
    result: { trustDigest: 'sha256:' + '82'.repeat(32) },
  };
  owner.distributed.mockResolvedValue(distributed);
  owner.plan.mockReturnValue({
    attempts: [
      {
        slot: 'old',
        request: {
          ...f.request,
          attemptId: id(710),
          reference: f.enrollment.request.oldReference,
          version: '1',
          method: 'PROVE',
          expectedFingerprint: f.enrollment.request.oldFingerprint,
          challengeHex: distributed.result.trustDigest.slice(7),
          challengeIssuedAtNs: '1791007200000000000',
          challengeExpiresAtNs: '1791007500000000000',
        },
      },
      {
        slot: 'new',
        request: {
          ...f.request,
          attemptId: id(711),
          method: 'PROVE',
          expectedFingerprint: distributed.descriptor.fingerprint,
          challengeHex: distributed.result.trustDigest.slice(7),
          challengeIssuedAtNs: '1791007200000000000',
          challengeExpiresAtNs: '1791007500000000000',
        },
      },
    ],
  });
  expect(await f.queue()).toMatchObject({
    fromState: 'DISTRIBUTED',
    toState: 'VERIFIED',
    fromRevision: '4',
    state: 'READY',
    permissionEffect: 'NONE',
    attempts: [
      { attemptId: id(710), method: 'PROVE' },
      { attemptId: id(711), method: 'PROVE' },
    ],
  });
  expect(owner.distributed).toHaveBeenCalledTimes(1);
  expect(writes(f)).toHaveLength(3);
  expect(owner.plan.mock.calls[0]?.[0]).toMatchObject({
    state: 'DISTRIBUTED',
    toState: 'VERIFIED',
    descriptor: distributed.descriptor,
  });
});
it('does not queue possession without the original authenticated distribution', async () => {
  const f = fixture();
  f.rotation.state = 'DISTRIBUTED';
  f.rotation.revision = '4';
  f.command.expectedRevision = '4';
  owner.distributed.mockRejectedValue(Error('distribution unavailable'));
  await expect(f.queue()).rejects.toThrow('distribution unavailable');
  expect(writes(f)).toHaveLength(0);
  expect(owner.plan).not.toHaveBeenCalled();
});

it.each([
  'valid',
  'duplicate-slot',
  'missing-slot',
  'wrong-challenge',
  'missing-first-failure',
] as const)('reconciles only original dual attempt identities for %s replay', async (kind) => {
  const f = fixture();
  f.previous();
  f.step.fromRevision = '4';
  f.step.fromState = 'DISTRIBUTED';
  f.step.toState = 'VERIFIED';
  f.step.state = 'WRITE_AMBIGUITY';
  f.command.expectedRevision = '4';
  f.receipt.authority = 'NONE';
  const distributed = {
    descriptor: { fingerprint: 'sha256:' + '81'.repeat(32) },
    result: { trustDigest: 'sha256:' + '82'.repeat(32) },
  };
  owner.distributed.mockResolvedValue(distributed);
  const common = {
    ...f.request,
    method: 'PROVE' as const,
    challengeHex: distributed.result.trustDigest.slice(7),
    challengeIssuedAtNs: '1791007200000000000',
    challengeExpiresAtNs: '1791007500000000000',
  };
  const requests = [
    {
      ...common,
      reference: f.enrollment.request.oldReference,
      version: '1',
      attemptId: id(710),
      expectedFingerprint: f.enrollment.request.oldFingerprint,
    },
    { ...common, attemptId: id(711), expectedFingerprint: distributed.descriptor.fingerprint },
  ];
  if (kind === 'wrong-challenge') requests[1]!.challengeHex = '11'.repeat(32);
  const rows = requests.map((request, i) => ({
    slot: i === 0 ? 'old' : 'new',
    request,
    digest: Buffer.from(identityEnvelopeRotationRequestDigest(request).slice(7), 'hex'),
    state: i === 0 ? 'WRITE_AMBIGUITY' : 'READY',
    first: null,
    observation: null,
    ambiguityKind: i === 0 ? 'NOT_FOUND' : null,
  }));
  if (kind === 'duplicate-slot') rows[1]!.slot = 'old';
  if (kind === 'missing-slot') rows.pop();
  if (kind === 'missing-first-failure') rows[0]!.ambiguityKind = null;
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation((sql, params) =>
    sql.includes('from control.identity_envelope_rotation_attempt')
      ? Promise.resolve({ rowCount: rows.length, rows: rows as never })
      : original(sql, params),
  );
  if (kind === 'valid') {
    expect(await f.queue()).toMatchObject({
      state: 'STARTED',
      authority: 'NONE',
      attempts: [
        { attemptId: id(710), state: 'WRITE_AMBIGUITY' },
        { attemptId: id(711), state: 'READY' },
      ],
    });
    expect(writes(f)).toHaveLength(1);
    expect(rows[1]!.state).toBe('READY');
  } else {
    await expect(f.queue()).rejects.toThrow();
    expect(writes(f)).toHaveLength(0);
  }
  expect(owner.plan).not.toHaveBeenCalled();
  expect(owner.source).not.toHaveBeenCalled();
});

it.each(['success', 'unpublished', 'provider-attempt'] as const)(
  'publishes zero-provider cutover only through its atomic owner for %s',
  async (kind) => {
    const f = fixture();
    f.rotation.state = 'VERIFIED';
    f.rotation.revision = '5';
    f.command.expectedRevision = '5';
    owner.plan.mockReturnValue({
      attempts: kind === 'provider-attempt' ? [{ slot: 'new', request: f.request }] : [],
    });
    owner.publish.mockResolvedValue(
      kind === 'unpublished'
        ? undefined
        : {
            operationId: f.step.operationId,
            state: 'CUTOVER_FENCED',
            fromRevision: '5',
            revision: '6',
            selectionAdmissionVersion: '2',
            permissionEffect: 'NONE',
          },
    );
    if (kind === 'success') {
      expect(await f.queue()).toMatchObject({
        state: 'COMMITTED',
        fromState: 'VERIFIED',
        toState: 'CUTOVER_FENCED',
        attempts: [],
        result: { selectionAdmissionVersion: '2', permissionEffect: 'NONE' },
      });
      expect(writes(f)).toHaveLength(2);
      expect(writes(f)[1]?.[0]).toContain("set state='STARTED'");
    } else await expect(f.queue()).rejects.toThrow();
    expect(owner.plan.mock.calls[0]?.[0]).toMatchObject({
      state: 'VERIFIED',
      toState: 'CUTOVER_FENCED',
    });
  },
);
it('replays original cutover history without allocating another operation, recapturing issuer or selecting again', async () => {
  const f = fixture();
  f.previous();
  f.step.fromRevision = '5';
  f.step.fromState = 'VERIFIED';
  f.step.toState = 'CUTOVER_FENCED';
  f.step.state = 'COMMITTED';
  f.command.expectedRevision = '5';
  f.receipt.authority = 'NONE';
  owner.publish.mockResolvedValue({
    operationId: f.step.operationId,
    state: 'CUTOVER_FENCED',
    selectionAdmissionVersion: '2',
  });
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation((sql, params) =>
    sql.includes('from control.identity_envelope_rotation_attempt')
      ? Promise.resolve({ rowCount: 0, rows: [] })
      : original(sql, params),
  );
  expect(await f.queue()).toMatchObject({
    state: 'COMMITTED',
    replay: true,
    authority: 'NONE',
    attempts: [],
    result: { selectionAdmissionVersion: '2' },
  });
  expect(writes(f)).toEqual([]);
  expect(owner.plan).not.toHaveBeenCalled();
  expect(owner.source).not.toHaveBeenCalled();
});

function consumerFixture() {
  const f = fixture();
  f.rotation.state = 'CUTOVER_FENCED';
  f.rotation.revision = '6';
  f.command.expectedRevision = '6';
  const distributed = {
    descriptor: { fingerprint: 'sha256:' + '81'.repeat(32) },
    result: { trustDigest: 'sha256:' + '82'.repeat(32) },
  };
  const source = {
    trust: { unit: 'old' },
    selectedTrust: { signerId: distributed.descriptor.fingerprint },
    issuer: f.lease.issuer,
    recordedAtNs: BigInt(f.now.getTime()) * 1000000n,
    cutoverAtNs: BigInt(f.now.getTime()) * 1000000n - 1000000n,
  };
  const consumer = {
    operationId: id(780),
    envelopeId: id(781),
    payloadDigest: 'sha256:' + '83'.repeat(32),
    receiptDigest: 'sha256:' + '84'.repeat(32),
  };
  const request = {
    ...f.request,
    method: 'PROVE' as const,
    expectedFingerprint: distributed.descriptor.fingerprint,
    challengeHex: distributed.result.trustDigest.slice(7),
    challengeIssuedAtNs: source.recordedAtNs.toString(),
    challengeExpiresAtNs: (source.recordedAtNs + 300000000000n).toString(),
  };
  owner.successor.mockResolvedValue(source);
  owner.consumer.mockResolvedValue(consumer);
  owner.distributed.mockResolvedValue(distributed);
  owner.publish.mockResolvedValue({
    state: 'CUTOVER_FENCED',
    signerId: source.selectedTrust.signerId,
  });
  owner.plan.mockReturnValue({ attempts: [{ slot: 'effective', request }] });
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation(async (sql, params) =>
    sql.startsWith('select operation_id::text as "operationId" from')
      ? { rowCount: 1, rows: [{ operationId: id(770) }] }
      : original(sql, params),
  );
  return { ...f, source, consumer, distributed, effectiveRequest: request };
}
it('pins the original actual consumer before the sole effective provider request without revoking old keys', async () => {
  const f = consumerFixture();
  expect(await f.queue()).toMatchObject({
    fromState: 'CUTOVER_FENCED',
    toState: 'OBSERVING',
    fromRevision: '6',
    state: 'READY',
    attempts: [{ method: 'PROVE', state: 'READY' }],
  });
  expect(owner.source).not.toHaveBeenCalled();
  expect(owner.consumer).toHaveBeenCalledWith(
    expect.anything(),
    {
      trust: f.source.selectedTrust,
      cutoverAtNs: f.source.cutoverAtNs,
      observedAtNs: f.source.recordedAtNs,
    },
    {},
  );
  const changed = writes(f);
  expect(changed).toHaveLength(2);
  expect(changed[0]![0]).toContain('consumer_activation_operation_id');
  expect(changed[0]![1]?.[12]).toBe(f.consumer.operationId);
  expect(owner.plan).toHaveBeenCalledWith(
    expect.objectContaining({
      state: 'CUTOVER_FENCED',
      toState: 'OBSERVING',
      oldTrust: f.source.trust,
      descriptor: f.distributed.descriptor,
    }),
    expect.any(Function),
  );
  expect(owner.consumer.mock.invocationCallOrder[0]).toBeLessThan(
    owner.plan.mock.invocationCallOrder[0]!,
  );
});
it.each([
  'missing-consumer',
  'consumer-evidence',
  'current-selection',
  'cutover-evidence',
] as const)('never queues effective I/O with %s', async (kind) => {
  const f = consumerFixture();
  if (kind === 'missing-consumer') owner.consumer.mockResolvedValue(undefined);
  if (kind === 'consumer-evidence')
    owner.consumer.mockRejectedValue(Error('invalid actual activation'));
  if (kind === 'current-selection') owner.successor.mockRejectedValue(Error('selection drift'));
  if (kind === 'cutover-evidence') owner.publish.mockResolvedValue({ state: 'VERIFIED' });
  await expect(f.queue()).rejects.toThrow();
  expect(writes(f)).toHaveLength(0);
  expect(owner.plan).not.toHaveBeenCalled();
});
it('historical ambiguity replay uses only the pinned original effective attempt and never discovers a new consumer', async () => {
  const f = consumerFixture();
  f.previous();
  f.receipt.authority = 'NONE';
  Object.assign(f.step, {
    fromRevision: '6',
    fromState: 'CUTOVER_FENCED',
    toState: 'OBSERVING',
    state: 'WRITE_AMBIGUITY',
    consumerActivationOperationId: f.consumer.operationId,
  });
  Object.assign(f.attempt, {
    slot: 'effective',
    request: f.effectiveRequest,
    state: 'WRITE_AMBIGUITY',
    ambiguityKind: 'NOT_FOUND',
    digest: Buffer.from(identityEnvelopeRotationRequestDigest(f.effectiveRequest).slice(7), 'hex'),
  });
  owner.publish.mockResolvedValue(undefined);
  expect(await f.queue()).toMatchObject({ state: 'STARTED', replay: true, fromRevision: '6' });
  expect(owner.consumer).not.toHaveBeenCalled();
  expect(owner.successor).not.toHaveBeenCalled();
  expect(owner.plan).not.toHaveBeenCalled();
  expect(writes(f)).toHaveLength(1);
});

function retirementQueueFixture(kind: 'revoke' | 'retire' | 'complete') {
  const f = consumerFixture();
  f.rotation.state =
    kind === 'revoke' ? 'OBSERVING' : kind === 'retire' ? 'OLD_REVOKED' : 'OLD_RETIRED';
  f.rotation.revision = kind === 'revoke' ? '7' : kind === 'retire' ? '8' : '9';
  f.command.expectedRevision = f.rotation.revision;
  const observed = {
    operationId: id(770),
    state: 'OBSERVING',
    signerId: f.source.selectedTrust.signerId,
  };
  const request = {
    ...f.request,
    method: kind === 'revoke' ? ('REVOKE' as const) : ('RETIRE' as const),
    reference: f.enrollment.request.oldReference,
    version: '1',
    expectedFingerprint: f.enrollment.request.oldFingerprint,
  };
  owner.publish.mockResolvedValue(observed);
  owner.plan.mockReturnValue({ attempts: kind === 'complete' ? [] : [{ slot: 'old', request }] });
  if (kind === 'complete')
    owner.publish.mockResolvedValueOnce(observed).mockResolvedValueOnce({
      operationId: f.step.operationId,
      state: 'COMPLETE',
      postReviewRequired: true,
    });
  return { ...f, observed, oldRequest: request };
}
it.each(['revoke', 'retire', 'complete'] as const)(
  'queues %s only after authenticating the original accepted consumer observation',
  async (kind) => {
    const f = retirementQueueFixture(kind);
    const view = await f.queue();
    expect(view).toMatchObject({
      fromRevision: f.command.expectedRevision,
      toState: kind === 'revoke' ? 'OLD_REVOKED' : kind === 'retire' ? 'OLD_RETIRED' : 'COMPLETE',
      state: kind === 'complete' ? 'COMMITTED' : 'READY',
      permissionEffect: 'NONE',
    });
    expect(writes(f)[0]![1]?.[13]).toBe(f.observed.operationId);
    expect(owner.consumer).not.toHaveBeenCalled();
    expect(owner.source).not.toHaveBeenCalled();
    expect(view.attempts).toHaveLength(kind === 'complete' ? 0 : 1);
    if (kind !== 'complete') expect(writes(f)[1]![1]?.[6]).toEqual(f.oldRequest);
  },
);
it.each(['missing', 'wrong-phase', 'foreign-issuer', 'substituted-operation'] as const)(
  'denies %s consumer prerequisite before destructive attempt allocation',
  async (kind) => {
    const f = retirementQueueFixture('revoke');
    if (kind === 'missing') owner.publish.mockResolvedValue(undefined);
    if (kind === 'wrong-phase') f.observed.state = 'VERIFIED';
    if (kind === 'foreign-issuer') f.observed.signerId = 'sha256:' + 'ff'.repeat(32);
    if (kind === 'substituted-operation') f.observed.operationId = id(799);
    await expect(f.queue()).rejects.toThrow();
    expect(writes(f)).toHaveLength(0);
    expect(owner.plan).not.toHaveBeenCalled();
  },
);
it('replays the exact ambiguous old-key attempt and original consumer observation without planning new private I/O', async () => {
  const f = retirementQueueFixture('revoke');
  f.previous();
  f.receipt.authority = 'NONE';
  Object.assign(f.step, {
    fromRevision: '7',
    fromState: 'OBSERVING',
    toState: 'OLD_REVOKED',
    state: 'WRITE_AMBIGUITY',
    consumerObservationOperationId: f.observed.operationId,
  });
  Object.assign(f.attempt, {
    slot: 'old',
    request: f.oldRequest,
    state: 'WRITE_AMBIGUITY',
    ambiguityKind: 'NOT_FOUND',
    digest: Buffer.from(identityEnvelopeRotationRequestDigest(f.oldRequest).slice(7), 'hex'),
  });
  owner.publish.mockResolvedValue(undefined);
  expect(await f.queue()).toMatchObject({
    replay: true,
    state: 'STARTED',
    toState: 'OLD_REVOKED',
    attempts: [{ method: 'REVOKE', state: 'WRITE_AMBIGUITY', ambiguityKind: 'NOT_FOUND' }],
  });
  expect(owner.plan).not.toHaveBeenCalled();
  expect(owner.successor).not.toHaveBeenCalled();
  expect(writes(f)).toHaveLength(1);
});
