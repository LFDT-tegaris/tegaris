import { createHash } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { planIdentityEnvelopeRotationAttempts } from '../domain/identity-envelope-rotation-plan.js';
import { identityEnvelopeRotationRequestDigest } from '../domain/identity-envelope-rotation-provider.js';
import { identityEnvelopeEffectiveProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { recoveryFixtureId as id } from '../domain/identity-envelope-recovery.test-fixture.js';
import { publishIdentityEnvelopeRecoveryRetirement } from './identity-envelope-recovery-rotation-retirement.js';
const owner = vi.hoisted(() => ({ source: vi.fn(), publish: vi.fn(), distributed: vi.fn() }));
vi.mock('./identity-envelope-rotation-successor-source.js', () => ({
  captureIdentityEnvelopeRotationSuccessorSource: owner.source,
}));
vi.mock('./identity-envelope-recovery-rotation-prepare.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./identity-envelope-recovery-rotation-prepare.js')>()),
  resolveIdentityEnvelopeRecoveryRotationPhase: owner.publish,
  resolveIdentityEnvelopeRecoveryDistributedDescriptor: owner.distributed,
}));
beforeEach(() => vi.resetAllMocks());
function immutableRow(t: ReturnType<typeof identityEnvelopeEffectiveProofFixture>['trust']) {
  return {
    participant_id: t.participantId,
    privacy_domain_id: t.privacyDomainId,
    signer_id: t.signerId,
    environment_id: t.environmentId,
    public_key_spki_der: t.publicKeySpkiDer,
    workload_credential_id: t.workloadCredentialId,
    workload_credential_epoch: t.workloadCredentialEpoch.toString(),
    key_epoch: t.keyEpoch.toString(),
    envelope_workload_participant_epoch: t.workloadParticipantEpoch.toString(),
    envelope_workload_principal_epoch: t.workloadPrincipalEpoch.toString(),
    valid_from_ns: t.validFromNs.toString(),
    valid_until_ns: t.validUntilNs.toString(),
    admission_kind: t.admissionKind,
    admission_reference: t.admissionReference,
    admission_digest: t.admissionDigest,
    secret_class: t.secretClass,
    secret_reference: t.secretReference,
    secret_version: t.secretVersion,
    trust_preimage: identityEnvelopeSigningTrustPreimage(t),
    trust_digest: Buffer.from(identityEnvelopeSigningTrustDigest(t).slice(7), 'hex'),
  };
}
function fixture() {
  const f = identityEnvelopeEffectiveProofFixture();
  if (!('kind' in f.input.admission)) throw Error();
  const { enrollment, lease } = f.input.admission;
  const actor = {
    participantId: enrollment.participantId,
    principalId: lease.executorPrincipalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  const observed = {
    operationId: id(740),
    state: 'OBSERVING',
    signerId: f.trust.signerId,
    trustDigest: identityEnvelopeSigningTrustDigest(f.trust),
    selectionAdmissionVersion: '2',
    consumerActivationOperationId: id(780),
    consumerEnvelopeId: id(781),
    consumerPayloadDigest: 'sha256:' + '11'.repeat(32),
    consumerReceiptDigest: 'sha256:' + '12'.repeat(32),
  };
  const at = f.input.nowNs + 10000000n;
  const steps = ['7', '8', '9'].map((fromRevision, i) => ({
    operationId: id(750 + i),
    state: 'STARTED',
    fromRevision,
    fromState: ['OBSERVING', 'OLD_REVOKED', 'OLD_RETIRED'][i]!,
    toState: ['OLD_REVOKED', 'OLD_RETIRED', 'COMPLETE'][i]!,
    consumerObservationId: observed.operationId,
    bound: true,
    current: true,
    result: null as unknown,
    cbor: null as Buffer | null,
    digest: null as Buffer | null,
    cose: null as Buffer | null,
  }));
  const attempts = steps.map((step, i) => {
    const plan = planIdentityEnvelopeRotationAttempts(
      {
        ...f.input,
        operationId: step.operationId,
        state: step.fromState as 'OBSERVING' | 'OLD_REVOKED' | 'OLD_RETIRED',
        toState: step.toState as 'OLD_REVOKED' | 'OLD_RETIRED' | 'COMPLETE',
        nowNs: at,
      },
      () => id(760 + i),
    );
    if (!plan.attempts[0]) return [];
    const request = plan.attempts[0].request,
      t = f.input.oldTrust;
    const descriptor = {
      ...f.input.descriptor!,
      fingerprint: t.signerId,
      publicKeySpkiHex: t.publicKeySpkiDer.toString('hex'),
      reference: t.secretReference,
      version: t.secretVersion,
      validFromNs: t.validFromNs.toString(),
      validUntilNs: t.validUntilNs.toString(),
      state: i === 0 ? 'REVOKED' : 'RETIRED',
      revokedAtNs: at.toString(),
      retiredAtNs: i === 0 ? null : (at + 1000000n).toString(),
    };
    const observation = {
      schemaVersion: 1,
      providerId: 'unit-provider',
      method: request.method,
      operationId: step.operationId,
      attemptId: request.attemptId,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
      recordedAtNs: (at + 2000000n).toString(),
      outcome: 'SUCCEEDED',
      reason: null,
      descriptor,
      resultHex: null,
    };
    return [
      {
        slot: 'old',
        request,
        requestDigest: Buffer.from(identityEnvelopeRotationRequestDigest(request).slice(7), 'hex'),
        state: 'OBSERVED',
        first: structuredClone(observation),
        observation,
        firstDigest: Buffer.from(canonicalAuthorizationDigest(observation).slice(7), 'hex'),
        digest: Buffer.from(canonicalAuthorizationDigest(observation).slice(7), 'hex'),
        startedAtNs: at.toString(),
      },
    ];
  });
  const source = {
    trust: f.input.oldTrust,
    selectedTrust: f.trust,
    issuer: f.input.currentIssuer,
    recordedAtNs: at + 3000000n,
    cutoverAtNs: f.input.nowNs,
  };
  const flags = { retained: true, revocation: true };
  const signer = {
    signCanonicalAssertion: vi.fn(async (payload: Buffer) => ({
      evidenceCbor: payload,
      evidenceDigest: createHash('sha256').update(payload).digest(),
      coseSign1: Buffer.from('unit-cose'),
    })),
    verifyCanonicalAssertion: vi.fn(async () => true),
  };
  const query = vi.fn(
    async (sql: string, params?: unknown[]): Promise<{ rowCount: number; rows: unknown[] }> => {
      if (sql.startsWith('select s.state'))
        return { rowCount: 1, rows: steps.filter((s) => s.operationId === params![0]) };
      if (sql.startsWith('select operation_id')) {
        const prior = steps.find((s) => s.fromRevision === params![5] && s.state === 'COMMITTED');
        return { rowCount: prior ? 1 : 0, rows: prior ? [{ operationId: prior.operationId }] : [] };
      }
      if (sql.startsWith('select slot')) {
        const i = steps.findIndex((s) => s.operationId === params![0]);
        return { rowCount: attempts[i]!.length, rows: attempts[i]! };
      }
      if (sql.startsWith('select key.*'))
        return { rowCount: 2, rows: [immutableRow(f.input.oldTrust), immutableRow(f.trust)] };
      if (sql.startsWith('select exists'))
        return { rowCount: 1, rows: [{ matches: flags.retained }] };
      if (sql.startsWith('select openpc.revoke_'))
        return {
          rowCount: 1,
          rows: [
            {
              revocation: {
                signerId: flags.revocation ? f.input.oldTrust.signerId : 'wrong',
                operationId: steps[0]!.operationId,
                state: 'REVOKED',
              },
            },
          ],
        };
      if (sql.startsWith('update control.identity_envelope_rotation_step')) {
        const s = steps.find((s) => s.operationId === params![0])!;
        s.state = 'COMMITTED';
        s.result = params![1];
        s.cbor = params![2] as Buffer;
        s.digest = params![3] as Buffer;
        s.cose = params![4] as Buffer;
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith('update') || sql.startsWith('insert')) return { rowCount: 1, rows: [] };
      throw Error('unexpected query');
    },
  );
  owner.publish.mockResolvedValue(observed);
  owner.source.mockResolvedValue(source);
  owner.distributed.mockResolvedValue({
    descriptor: f.input.descriptor,
    result: { trustDigest: observed.trustDigest },
  });
  const publish = (i = 0) =>
    publishIdentityEnvelopeRecoveryRetirement(
      { query } as never,
      actor,
      enrollment,
      lease,
      steps[i]!.operationId,
      true,
      signer as never,
    );
  const resync = (i = 0) => {
    const a = attempts[i]![0]!;
    a.first = structuredClone(a.observation);
    a.firstDigest = Buffer.from(canonicalAuthorizationDigest(a.first).slice(7), 'hex');
    a.digest = Buffer.from(canonicalAuthorizationDigest(a.observation).slice(7), 'hex');
  };
  return {
    ...f,
    enrollment,
    lease,
    actor,
    observed,
    steps,
    attempts,
    source,
    flags,
    query,
    signer,
    publish,
    resync,
  };
}
const writes = (f: ReturnType<typeof fixture>) =>
  f.query.mock.calls.filter(([sql]) => /^(insert|update|select openpc.revoke_)/u.test(sql));
it('commits exact old private revocation, then private retirement while public trust remains revoked, then zero-I/O completion requiring post-review', async () => {
  const f = fixture();
  expect(await f.publish()).toMatchObject({
    state: 'OLD_REVOKED',
    oldPrivateKeyState: 'REVOKED',
    consumerObservationOperationId: f.observed.operationId,
  });
  expect(await f.publish(1)).toMatchObject({ state: 'OLD_RETIRED', oldPrivateKeyState: 'RETIRED' });
  expect(await f.publish(2)).toMatchObject({
    state: 'COMPLETE',
    oldPrivateKeyState: 'RETIRED',
    postReviewRequired: true,
  });
  expect(
    f.query.mock.calls.filter(([sql]) => sql.startsWith('select openpc.revoke_')),
  ).toHaveLength(1);
  expect(
    f.query.mock.calls.some(
      ([sql]) =>
        sql.includes("set state='RETIRED'") ||
        sql.includes('signing_provider') ||
        sql.includes('admit_identity') ||
        sql.includes('select_identity'),
    ),
  ).toBe(false);
});
it.each([
  'missing-consumer',
  'foreign-executor',
  'unbound',
  'wrong-original',
  'request',
  'first',
  'lookup',
  'predates-start',
  'future-effect',
  'old-spki',
  'old-reference',
  'old-validity',
  'revocation-before-start',
  'expired',
  'consumer-trust',
] as const)('blocks %s before destructive publication', async (kind) => {
  const f = fixture(),
    s = f.steps[0]!,
    a = f.attempts[0]![0]!;
  if (kind === 'missing-consumer') s.consumerObservationId = '';
  if (kind === 'foreign-executor') f.actor.principalId = id(799);
  if (kind === 'unbound') s.bound = false;
  if (kind === 'wrong-original') f.observed.operationId = id(799);
  if (kind === 'request') a.requestDigest = Buffer.alloc(32, 9);
  if (kind === 'first') a.firstDigest = Buffer.alloc(32, 9);
  if (kind === 'lookup') a.digest = Buffer.alloc(32, 9);
  if (kind === 'predates-start')
    a.startedAtNs = (BigInt(a.observation.recordedAtNs) + 1000n).toString();
  if (kind === 'future-effect') f.source.recordedAtNs = BigInt(a.observation.recordedAtNs) - 1000n;
  if (kind === 'old-spki') {
    a.observation.descriptor = {
      ...a.observation.descriptor,
      publicKeySpkiHex: f.trust.publicKeySpkiDer.toString('hex'),
      fingerprint: f.trust.signerId,
    };
    f.resync();
  }
  if (kind === 'old-reference') {
    a.observation.descriptor.reference = f.enrollment.request.newReference;
    f.resync();
  }
  if (kind === 'old-validity') {
    a.observation.descriptor.validUntilNs = (
      BigInt(a.observation.descriptor.validUntilNs) - 1000n
    ).toString();
    f.resync();
  }
  if (kind === 'revocation-before-start') {
    a.observation.descriptor.revokedAtNs = (BigInt(a.startedAtNs) - 1000n).toString();
    f.resync();
  }
  if (kind === 'expired') f.source.recordedAtNs = BigInt(Date.parse(f.lease.validUntil)) * 1000000n;
  if (kind === 'consumer-trust') f.observed.trustDigest = 'sha256:' + '99'.repeat(32);
  await expect(f.publish()).rejects.toThrow();
  expect(writes(f)).toHaveLength(0);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it('private retirement cannot omit original confirmed public/private revocation', async () => {
  const f = fixture();
  await expect(f.publish(1)).rejects.toThrow();
  expect(writes(f)).toHaveLength(0);
});
it('private retirement must preserve the exact original revocation timestamp', async () => {
  const f = fixture();
  await f.publish();
  const count = writes(f).length;
  f.attempts[1]![0]!.observation.descriptor.revokedAtNs = (
    BigInt(f.attempts[1]![0]!.observation.descriptor.revokedAtNs) - 1000n
  ).toString();
  f.resync(1);
  await expect(f.publish(1)).rejects.toThrow();
  expect(writes(f)).toHaveLength(count);
});
it.each(['pending', 'ambiguous', 'not-current'] as const)(
  'retains %s suffix without a fresh destructive action',
  async (kind) => {
    const f = fixture();
    if (kind === 'pending') f.attempts[0]![0]!.state = 'STARTED';
    if (kind === 'ambiguous') f.attempts[0]![0]!.state = 'WRITE_AMBIGUITY';
    if (kind === 'not-current') f.steps[0]!.current = false;
    expect(await f.publish()).toBeUndefined();
    expect(writes(f)).toHaveLength(0);
  },
);
it('historical completed chain verifies original results and never recaptures, resigns, revokes or retires again', async () => {
  const f = fixture();
  await f.publish();
  await f.publish(1);
  const original = await f.publish(2);
  const count = writes(f).length;
  owner.source.mockClear();
  f.signer.signCanonicalAssertion.mockClear();
  f.steps.forEach((s) => (s.current = false));
  expect(await f.publish(2)).toEqual(original);
  expect(writes(f)).toHaveLength(count);
  expect(owner.source).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['receipt', 'signature', 'result', 'consumer-pin'] as const)(
  'rejects altered original %s after effects without a replay',
  async (kind) => {
    const f = fixture();
    await f.publish();
    const count = writes(f).length;
    if (kind === 'receipt') f.flags.retained = false;
    if (kind === 'signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false);
    if (kind === 'result') f.steps[0]!.digest = Buffer.alloc(32, 9);
    if (kind === 'consumer-pin') f.steps[0]!.consumerObservationId = id(799);
    await expect(f.publish()).rejects.toThrow();
    expect(writes(f)).toHaveLength(count);
  },
);
it('propagates mismatched public revocation confirmation before claiming an outbox success', async () => {
  const f = fixture();
  f.flags.revocation = false;
  await expect(f.publish()).rejects.toThrow();
  expect(writes(f).some(([sql]) => sql.startsWith('insert'))).toBe(false);
});
