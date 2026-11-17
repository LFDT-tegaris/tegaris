import { createHash } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { identityEnvelopeRotationRequestDigest } from '../domain/identity-envelope-rotation-provider.js';
import { identityEnvelopeEffectiveProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { recoveryFixtureId as id } from '../domain/identity-envelope-recovery.test-fixture.js';
import { publishIdentityEnvelopeRecoveryObservation } from './identity-envelope-recovery-rotation-observation.js';
const owner = vi.hoisted(() => ({
  source: vi.fn(),
  consumer: vi.fn(),
  publish: vi.fn(),
  distributed: vi.fn(),
}));
vi.mock('./identity-envelope-rotation-successor-source.js', () => ({
  captureIdentityEnvelopeRotationSuccessorSource: owner.source,
}));
vi.mock('../../../participant-service/src/identity-envelope-rotation-consumer.js', () => ({
  readIdentityEnvelopeRotationConsumer: owner.consumer,
}));
vi.mock('./identity-envelope-recovery-rotation-prepare.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./identity-envelope-recovery-rotation-prepare.js')>()),
  resolveIdentityEnvelopeRecoveryRotationPhase: owner.publish,
  resolveIdentityEnvelopeRecoveryDistributedDescriptor: owner.distributed,
}));
beforeEach(() => vi.resetAllMocks());
function row(trust: ReturnType<typeof identityEnvelopeEffectiveProofFixture>['trust']) {
  return {
    participant_id: trust.participantId,
    privacy_domain_id: trust.privacyDomainId,
    signer_id: trust.signerId,
    environment_id: trust.environmentId,
    public_key_spki_der: trust.publicKeySpkiDer,
    workload_credential_id: trust.workloadCredentialId,
    workload_credential_epoch: trust.workloadCredentialEpoch.toString(),
    key_epoch: trust.keyEpoch.toString(),
    envelope_workload_participant_epoch: trust.workloadParticipantEpoch.toString(),
    envelope_workload_principal_epoch: trust.workloadPrincipalEpoch.toString(),
    valid_from_ns: trust.validFromNs.toString(),
    valid_until_ns: trust.validUntilNs.toString(),
    admission_kind: trust.admissionKind,
    admission_reference: trust.admissionReference,
    admission_digest: trust.admissionDigest,
    secret_class: trust.secretClass,
    secret_reference: trust.secretReference,
    secret_version: trust.secretVersion,
    trust_preimage: identityEnvelopeSigningTrustPreimage(trust),
    trust_digest: Buffer.from(identityEnvelopeSigningTrustDigest(trust).slice(7), 'hex'),
  };
}
function fixture() {
  const f = identityEnvelopeEffectiveProofFixture();
  if (!('kind' in f.input.admission)) throw Error();
  const { enrollment, lease } = f.input.admission;
  const operationId = f.input.operationId;
  const actor = {
    participantId: enrollment.participantId,
    principalId: lease.executorPrincipalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  const step = {
    state: 'STARTED',
    bound: true,
    current: true,
    consumerId: id(780),
    result: null as unknown,
    cbor: null as Buffer | null,
    digest: null as Buffer | null,
    cose: null as Buffer | null,
  };
  const attempt = {
    ...f.record,
    state: 'OBSERVED',
    requestDigest: Buffer.from(
      identityEnvelopeRotationRequestDigest(f.record.request).slice(7),
      'hex',
    ),
    firstDigest: Buffer.from(
      canonicalAuthorizationDigest(f.record.firstObservation).slice(7),
      'hex',
    ),
    digest: Buffer.from(canonicalAuthorizationDigest(f.record.observation).slice(7), 'hex'),
    startedAtNs: (f.input.nowNs - 1000000n).toString(),
  };
  const consumer = {
    operationId: step.consumerId,
    envelopeId: id(781),
    payloadDigest: 'sha256:' + '11'.repeat(32),
    receiptDigest: 'sha256:' + '12'.repeat(32),
  };
  const cutover = {
    state: 'CUTOVER_FENCED',
    signerId: f.trust.signerId,
    trustDigest: identityEnvelopeSigningTrustDigest(f.trust),
    selectionAdmissionVersion: '2',
  };
  const prepared = { descriptor: f.input.descriptor, result: { trustDigest: cutover.trustDigest } };
  const source = {
    trust: f.input.oldTrust,
    selectedTrust: f.trust,
    issuer: f.input.currentIssuer,
    recordedAtNs: f.input.nowNs,
    cutoverAtNs: f.input.nowNs - 10000000n,
  };
  const retained = [row(f.input.oldTrust), row(f.trust)];
  const flags = { retained: true };
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
      if (sql.startsWith('select s.state')) return { rowCount: 1, rows: [step] };
      if (sql.startsWith('select slot')) return { rowCount: 1, rows: [attempt] };
      if (sql.startsWith('select operation_id'))
        return { rowCount: 1, rows: [{ operationId: id(770) }] };
      if (sql.startsWith('select key.*')) return { rowCount: retained.length, rows: retained };
      if (sql.startsWith('select exists'))
        return { rowCount: 1, rows: [{ matches: flags.retained }] };
      if (sql.startsWith('update control.identity_envelope_rotation_step')) {
        step.state = 'COMMITTED';
        step.result = params![1];
        step.cbor = params![2] as Buffer;
        step.digest = params![3] as Buffer;
        step.cose = params![4] as Buffer;
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith('update') || sql.startsWith('insert')) return { rowCount: 1, rows: [] };
      throw Error('unexpected query');
    },
  );
  owner.source.mockResolvedValue(source);
  owner.consumer.mockResolvedValue(consumer);
  owner.publish.mockResolvedValue(cutover);
  owner.distributed.mockResolvedValue(prepared);
  const publish = () =>
    publishIdentityEnvelopeRecoveryObservation(
      { query } as never,
      actor,
      enrollment,
      lease,
      operationId,
      true,
      signer as never,
    );
  return {
    ...f,
    enrollment,
    lease,
    actor,
    step,
    attempt,
    consumer,
    cutover,
    prepared,
    source,
    flags,
    signer,
    query,
    publish,
  };
}
const writes = (f: ReturnType<typeof fixture>) =>
  f.query.mock.calls.filter(([sql]) => /^(insert|update)/u.test(sql));
it('publishes only the pinned actual consumer plus real effective proof and same atomic result/state/outbox', async () => {
  const f = fixture();
  expect(await f.publish()).toMatchObject({
    state: 'OBSERVING',
    revision: '7',
    permissionEffect: 'NONE',
    consumerActivationOperationId: f.step.consumerId,
    consumerEnvelopeId: f.consumer.envelopeId,
  });
  expect(owner.consumer).toHaveBeenCalledWith(
    expect.anything(),
    expect.objectContaining({ operationId: f.step.consumerId, trust: f.trust }),
    f.signer,
  );
  expect(writes(f)).toHaveLength(4);
  expect(
    f.query.mock.calls.some(([sql]) => /REVOKE|RETIRE|admit_identity|select_identity/u.test(sql)),
  ).toBe(false);
});
it.each([
  'missing-pin',
  'foreign-executor',
  'unbound',
  'request-digest',
  'first-digest',
  'lookup-digest',
  'no-start',
  'predates-start',
  'changed-first',
  'expired-proof',
  'missing-consumer',
  'substituted-consumer',
  'trust',
  'bad-cutover',
] as const)('denies %s before signed or durable publication', async (kind) => {
  const f = fixture();
  if (kind === 'missing-pin') f.step.consumerId = '';
  if (kind === 'foreign-executor') f.actor.principalId = id(799);
  if (kind === 'unbound') f.step.bound = false;
  if (kind === 'request-digest') f.attempt.requestDigest = Buffer.alloc(32, 9);
  if (kind === 'first-digest') f.attempt.firstDigest = Buffer.alloc(32, 9);
  if (kind === 'lookup-digest') f.attempt.digest = Buffer.alloc(32, 9);
  if (kind === 'no-start') f.attempt.startedAtNs = '';
  if (kind === 'predates-start')
    f.attempt.startedAtNs = (BigInt(f.attempt.observation.recordedAtNs) + 1000n).toString();
  if (kind === 'changed-first') {
    f.attempt.firstObservation.providerId = 'other';
    f.attempt.firstDigest = Buffer.from(
      canonicalAuthorizationDigest(f.attempt.firstObservation).slice(7),
      'hex',
    );
  }
  if (kind === 'expired-proof') {
    if (f.attempt.request.method !== 'PROVE') throw Error();
    f.source.recordedAtNs = BigInt(f.attempt.request.challengeExpiresAtNs);
  }
  if (kind === 'missing-consumer') owner.consumer.mockResolvedValue(undefined);
  if (kind === 'substituted-consumer') f.consumer.operationId = id(799);
  if (kind === 'trust') f.cutover.trustDigest = 'sha256:' + '99'.repeat(32);
  if (kind === 'bad-cutover') f.cutover.state = 'VERIFIED';
  await expect(f.publish()).rejects.toThrow();
  expect(writes(f)).toHaveLength(0);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['pending', 'not-current'] as const)(
  'leaves %s unproved suffix without publication',
  async (kind) => {
    const f = fixture();
    if (kind === 'pending') f.attempt.state = 'STARTED';
    else f.step.current = false;
    expect(await f.publish()).toBeUndefined();
    expect(writes(f)).toHaveLength(0);
  },
);
it('historical replay preserves original timestamp/proof/consumer and never recaptures or signs authority', async () => {
  const f = fixture();
  const original = await f.publish();
  const count = writes(f).length;
  owner.source.mockClear();
  owner.consumer.mockClear();
  f.signer.signCanonicalAssertion.mockClear();
  f.step.current = false;
  expect(await f.publish()).toEqual(original);
  expect(writes(f)).toHaveLength(count);
  expect(owner.source).not.toHaveBeenCalled();
  expect(owner.consumer).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['signed-result', 'receipt', 'signature', 'pin'] as const)(
  'denies altered historical %s without mutation',
  async (kind) => {
    const f = fixture();
    await f.publish();
    const count = writes(f).length;
    if (kind === 'signed-result') f.step.digest = Buffer.alloc(32, 9);
    if (kind === 'receipt') f.flags.retained = false;
    if (kind === 'signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false);
    if (kind === 'pin') f.step.consumerId = id(799);
    await expect(f.publish()).rejects.toThrow();
    expect(writes(f)).toHaveLength(count);
  },
);
it('propagates a durable result failure before shared state/outbox mutation', async () => {
  const f = fixture();
  const original = f.query.getMockImplementation()!;
  f.query.mockImplementation(async (sql, params) =>
    sql.startsWith('update control.identity_envelope_rotation_step')
      ? { rowCount: 0, rows: [] }
      : original(sql, params),
  );
  await expect(f.publish()).rejects.toThrow();
  expect(writes(f)).toHaveLength(1);
});
