import { createHash, generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { beforeEach, expect, it, vi } from 'vitest';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { identityEnvelopeRecoveryRotationCompletionResult } from '../contracts/identity-envelope-recovery.js';
import { identityEnvelopeEffectiveProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { recoveryFixtureId as id } from '../domain/identity-envelope-recovery.test-fixture.js';
import {
  createLocalIdentityRuntimeCryptoAdapter,
  createLocalIdentityRuntimeVerifier,
} from '../domain/identity-runtime-crypto.js';
import { identityEnvelopeRecoveryEvidencePayload } from '../domain/identity-envelope-recovery-evidence.js';
import { readHistoricalIdentityEnvelopeRecoveryRotation } from './identity-envelope-recovery-rotation-history.js';

const owner = vi.hoisted(() => ({ resolve: vi.fn() }));
vi.mock('./identity-envelope-recovery-rotation-prepare.js', () => ({
  resolveIdentityEnvelopeRecoveryRotationPhase: owner.resolve,
}));
beforeEach(() => vi.resetAllMocks());

async function fixture() {
  const f = identityEnvelopeEffectiveProofFixture();
  if (!('kind' in f.input.admission)) throw new Error();
  const { enrollment, lease } = f.input.admission;
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const verifier = createLocalIdentityRuntimeVerifier([publicKey]);
  const at = Date.parse(lease.validFrom) + 1000;
  const candidateDigest = canonicalAuthorizationDigest({ request: enrollment.request, lease });
  const rotation = {
    request: enrollment.request,
    candidateDigest: Buffer.from(candidateDigest.slice(7), 'hex'),
    recoveryId: lease.recoveryId,
    maker: lease.executorPrincipalId,
    approvalId: null as string | null,
    approvedOperationId: lease.activationOperationId,
    environmentId: enrollment.request.environmentId,
    workloadCredentialId: enrollment.request.workloadCredentialId,
    oldSignerId: enrollment.request.oldFingerprint,
    oldTrustDigest: Buffer.from(lease.oldTrustDigest.slice(7), 'hex'),
    newSignerId: f.trust.signerId,
    state: 'COMPLETE',
    revision: '10',
    createdAt: new Date(at),
  };
  const creation = {
    schema: 'pc.identity.identity-envelope-recovery-rotation-creation',
    schemaVersion: 1,
    operationId: lease.creationOperationId,
    recoveryId: lease.recoveryId,
    enrollmentId: enrollment.enrollmentId,
    rotationId: lease.rotationId,
    candidateDigest,
    revision: '2',
    state: 'APPROVED',
    createdAt: new Date(at).toISOString(),
  };
  const payload = identityEnvelopeRecoveryEvidencePayload({
    enrollment,
    operationId: lease.creationOperationId,
    actorPrincipalId: lease.executorPrincipalId,
    purpose: 'rotation-creation',
    value: creation,
    authenticationDigest: lease.proofEvidenceDigest,
    issuedAt: creation.createdAt,
    expiresAt: lease.validUntil,
  });
  const signed = await signer.signCanonicalAssertion(payload);
  const event = {
    cbor: signed.evidenceCbor,
    digest: signed.evidenceDigest,
    cose: signed.coseSign1,
  };
  const authorityBinding = { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment, lease };
  const authorityDigest = Buffer.from(
    canonicalAuthorizationDigest(authorityBinding).slice(7),
    'hex',
  );
  const states = [
    'APPROVED',
    'PREPARED',
    'DISTRIBUTED',
    'VERIFIED',
    'CUTOVER_FENCED',
    'OBSERVING',
    'OLD_REVOKED',
    'OLD_RETIRED',
    'COMPLETE',
  ];
  const steps = Array.from({ length: 8 }, (_, i) => ({
    operationId: id(910 + i),
    fromRevision: String(i + 2),
    fromState: states[i],
    toState: states[i + 1],
    state: 'COMMITTED',
    bound: true,
    authorityBinding,
    authorityDigest,
    result: { completedAt: new Date(at + 1000 * (i + 1)).toISOString() },
    completedAtNs: (BigInt(at + 1000 * (i + 1)) * 1000000n).toString(),
  }));
  const completion = identityEnvelopeRecoveryRotationCompletionResult.parse({
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId: steps[7]!.operationId,
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: '9',
    revision: '10',
    state: 'COMPLETE',
    signerId: rotation.newSignerId,
    trustDigest: identityEnvelopeSigningTrustDigest(f.trust),
    observationsDigest: canonicalAuthorizationDigest([]),
    completedAt: steps[7]!.result.completedAt,
    selectionAdmissionVersion: '2',
    permissionEffect: 'NONE',
    consumerObservationOperationId: id(930),
    consumerActivationOperationId: id(931),
    consumerEnvelopeId: id(932),
    consumerPayloadDigest: 'sha256:' + '11'.repeat(32),
    consumerReceiptDigest: 'sha256:' + '12'.repeat(32),
    predecessorSignerId: rotation.oldSignerId,
    oldPrivateKeyState: 'RETIRED',
    oldPrivateKeyRevokedAtNs: steps[5]!.completedAtNs,
    oldPrivateKeyRetiredAtNs: steps[6]!.completedAtNs,
    postReviewRequired: true,
  });
  const flags = {
    serializable: true,
    visibleParticipant: true,
    rotationVisible: true,
    eventVisible: true,
  };
  const query = vi.fn(async (sql: string) => {
    if (!/^select /u.test(sql)) throw new Error('Historical reader attempted DML');
    if (sql.startsWith('select openpc.assert_request_context'))
      return { rowCount: 1, rows: [{ serializable: flags.serializable }] };
    if (sql.startsWith('select participant_id from control.participant'))
      return { rowCount: flags.visibleParticipant ? 1 : 0, rows: [] };
    if (sql.startsWith('select r.request'))
      return {
        rowCount: flags.rotationVisible ? 1 : 0,
        rows: flags.rotationVisible ? [rotation] : [],
      };
    if (sql.startsWith('select e.payload_cbor'))
      return { rowCount: flags.eventVisible ? 1 : 0, rows: flags.eventVisible ? [event] : [] };
    if (sql.startsWith('select s.operation_id')) return { rowCount: steps.length, rows: steps };
    throw new Error('Unexpected historical query');
  });
  owner.resolve.mockResolvedValue(completion);
  const read = (operationId = completion.operationId) =>
    readHistoricalIdentityEnvelopeRecoveryRotation(
      { query } as unknown as PoolClient,
      enrollment,
      lease,
      operationId,
      verifier,
    );
  return {
    enrollment,
    lease,
    rotation,
    event,
    steps,
    completion,
    flags,
    query,
    read,
    signer,
    verifier,
  };
}

it('authenticates original signed creation and all eight locked steps before verification-only resolution', async () => {
  const f = await fixture();
  expect(await f.read()).toEqual(f.completion);
  expect(f.query.mock.calls.map(([sql]) => sql)).toEqual([
    expect.stringContaining('assert_request_context(true)'),
    expect.stringMatching(/from control.participant[\s\S]*for update/u),
    expect.stringContaining('for update of r'),
    expect.stringContaining('h.last_sequence=9'),
    expect.stringContaining('order by s.from_revision for update of s'),
  ]);
  const [, context, enrollment, lease, operationId, localQaEnabled, verifyOnly] =
    owner.resolve.mock.calls[0]!;
  expect(context).toEqual({
    kind: 'HISTORICAL',
    subject: {
      participantId: f.enrollment.participantId,
      principalId: f.lease.executorPrincipalId,
    },
  });
  expect(enrollment).toBe(f.enrollment);
  expect(lease).toBe(f.lease);
  expect(operationId).toBe(f.completion.operationId);
  expect(localQaEnabled).toBe(false);
  await expect(verifyOnly.signCanonicalAssertion(Buffer.from('unexpected'))).rejects.toThrow();
  expect(await verifyOnly.verifyCanonicalAssertion(f.event.cbor, f.event.cose)).toBeTruthy();
  expect(Object.isFrozen(await f.read())).toBe(true);
  expect(
    f.query.mock.calls.every(
      ([sql]) => !/set_config|set role|insert|update control|delete/u.test(sql),
    ),
  ).toBe(true);
});
it.each([
  'not-serializable',
  'hidden-participant',
  'hidden-rotation',
  'wrong-state',
  'revision',
  'maker',
  'ordinary-approval',
  'activation',
  'environment',
  'credential',
  'old-signer',
  'old-trust',
  'candidate',
  'request',
  'creation-before-lease',
  'creation-expired',
  'missing-creation',
  'creation-payload',
  'creation-digest',
  'creation-signature',
] as const)('rejects %s before historical phase dispatch', async (kind) => {
  const f = await fixture();
  if (kind === 'not-serializable') f.flags.serializable = false;
  if (kind === 'hidden-participant') f.flags.visibleParticipant = false;
  if (kind === 'hidden-rotation') f.flags.rotationVisible = false;
  if (kind === 'wrong-state') f.rotation.state = 'OLD_RETIRED';
  if (kind === 'revision') f.rotation.revision = '11';
  if (kind === 'maker') f.rotation.maker = id(990);
  if (kind === 'ordinary-approval') f.rotation.approvalId = id(990);
  if (kind === 'activation') f.rotation.approvedOperationId = id(990);
  if (kind === 'environment') f.rotation.environmentId = 'foreign';
  if (kind === 'credential') f.rotation.workloadCredentialId = id(990);
  if (kind === 'old-signer') f.rotation.oldSignerId = 'sha256:' + '99'.repeat(32);
  if (kind === 'old-trust') f.rotation.oldTrustDigest = Buffer.alloc(32, 9);
  if (kind === 'candidate') f.rotation.candidateDigest = Buffer.alloc(32, 9);
  if (kind === 'request')
    f.rotation.request = { ...f.enrollment.request, environmentId: 'foreign' };
  if (kind === 'creation-before-lease')
    f.rotation.createdAt = new Date(Date.parse(f.lease.validFrom) - 1);
  if (kind === 'creation-expired') f.rotation.createdAt = new Date(f.lease.validUntil);
  if (kind === 'missing-creation') f.flags.eventVisible = false;
  if (kind === 'creation-payload') {
    f.event.cbor = Buffer.from('changed');
    f.event.digest = createHash('sha256').update(f.event.cbor).digest();
  }
  if (kind === 'creation-digest') f.event.digest = Buffer.alloc(32, 9);
  if (kind === 'creation-signature') f.event.cose = Buffer.from('changed');
  await expect(f.read()).rejects.toThrow();
  expect(owner.resolve).not.toHaveBeenCalled();
});
it.each([
  'missing',
  'extra',
  'duplicate-operation',
  'uncommitted',
  'unbound',
  'authority-binding',
  'authority-digest',
  'revision-gap',
  'wrong-transition',
  'native-time',
  'time-order',
  'lease-expiry',
  'invalid-time',
  'completion-operation',
] as const)('rejects %s in the locked step set before dispatch', async (kind) => {
  const f = await fixture();
  if (kind === 'missing') f.steps.splice(2, 1);
  if (kind === 'extra') f.steps.push({ ...f.steps[0]!, operationId: id(990) });
  if (kind === 'duplicate-operation') f.steps[2]!.operationId = f.steps[0]!.operationId;
  if (kind === 'uncommitted') f.steps[2]!.state = 'STARTED';
  if (kind === 'unbound') f.steps[2]!.bound = false;
  if (kind === 'authority-binding')
    f.steps[2]!.authorityBinding = {
      ...f.steps[2]!.authorityBinding,
      lease: { ...f.lease, executorPrincipalId: id(990) },
    };
  if (kind === 'authority-digest') f.steps[2]!.authorityDigest = Buffer.alloc(32, 9);
  if (kind === 'revision-gap') f.steps[2]!.fromRevision = '5';
  if (kind === 'wrong-transition') f.steps[2]!.toState = 'COMPLETE';
  if (kind === 'native-time')
    f.steps[2]!.completedAtNs = (BigInt(f.steps[2]!.completedAtNs) + 1000n).toString();
  if (kind === 'time-order') {
    f.steps[2]!.result.completedAt = f.steps[0]!.result.completedAt;
    f.steps[2]!.completedAtNs = f.steps[0]!.completedAtNs;
  }
  if (kind === 'lease-expiry') {
    f.steps[7]!.result.completedAt = f.lease.validUntil;
    f.steps[7]!.completedAtNs = (BigInt(Date.parse(f.lease.validUntil)) * 1000000n).toString();
  }
  if (kind === 'invalid-time') f.steps[2]!.result.completedAt = 'not-a-date';
  await expect(f.read(kind === 'completion-operation' ? id(990) : undefined)).rejects.toThrow();
  expect(owner.resolve).not.toHaveBeenCalled();
});
it('preserves original microsecond phase timestamps without truncating them to milliseconds', async () => {
  const f = await fixture();
  const last = f.steps[7]!;
  last.result.completedAt = last.result.completedAt.replace('Z', '123000Z');
  last.completedAtNs = (BigInt(last.completedAtNs) + 123000n).toString();
  f.completion.completedAt = last.result.completedAt;
  expect(await f.read()).toEqual(f.completion);
});
it('propagates failed historical verification without signing or trying a new live phase', async () => {
  const f = await fixture();
  owner.resolve.mockRejectedValue(new Error('Corrupt original history'));
  await expect(f.read()).rejects.toThrow('Corrupt original history');
  expect(owner.resolve).toHaveBeenCalledTimes(1);
});
