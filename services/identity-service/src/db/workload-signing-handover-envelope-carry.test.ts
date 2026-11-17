import { generateKeyPairSync, sign } from 'node:crypto';
import type { PoolClient } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
} from '@openpc/security-kernel';
import { identityEnvelopeDualProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { readHistoricalIdentityEnvelopeRotationConsumer } from '../../../participant-service/src/identity-envelope-rotation-consumer.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { WorkloadSigningHandoverEnvelopeCarry } from '../contracts/workload-signing-handover-v2.js';
import {
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryLease,
  identityEnvelopeRecoveryRotationCompletionResult,
  identityEnvelopeRecoveryRotationCutoverResult,
} from '../contracts/identity-envelope-recovery.js';
import { identityEnvelopeRecoveryCustodyPreimage } from '../domain/identity-envelope-recovery-custody.js';
import { identityEnvelopeRecoveryEvidencePayload } from '../domain/identity-envelope-recovery-evidence.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { buildIdentityEnvelopeRotationTrust } from '../domain/identity-envelope-rotation-trust.js';
import {
  createLocalIdentityRuntimeCryptoAdapter,
  createLocalIdentityRuntimeVerifier,
} from '../domain/identity-runtime-crypto.js';
import { lockAuthorityFence } from './authority-fence.js';
import { readHistoricalIdentityEnvelopeRecoveryRotation } from './identity-envelope-recovery-rotation-history.js';
import { captureIdentityEnvelopeRotationIssuer } from './identity-envelope-rotation-issuer.js';
import { fenceIdentityEnvelopeSigningTrust } from './identity-envelope-signing-store.js';
import { readWorkloadSigningRepairClosure } from './workload-signing-handover-repair-closure.js';
import { readWorkloadSigningRepairProofs } from './workload-signing-handover-repair-proofs.js';
import { readWorkloadSigningRepairReview } from './workload-signing-handover-repair-review.js';
import { captureWorkloadSigningEnvelopeCarry } from './workload-signing-handover-envelope-carry.js';

vi.mock('./authority-fence.js', () => ({ lockAuthorityFence: vi.fn() }));
vi.mock('./identity-envelope-rotation-issuer.js', async (original) => ({
  ...(await original<typeof import('./identity-envelope-rotation-issuer.js')>()),
  captureIdentityEnvelopeRotationIssuer: vi.fn(),
}));
vi.mock('./identity-envelope-signing-store.js', () => ({
  fenceIdentityEnvelopeSigningTrust: vi.fn(),
}));
vi.mock('./identity-envelope-recovery-rotation-history.js', () => ({
  readHistoricalIdentityEnvelopeRecoveryRotation: vi.fn(),
}));
vi.mock('./workload-signing-handover-repair-proofs.js', () => ({
  readWorkloadSigningRepairProofs: vi.fn(),
}));
vi.mock('./workload-signing-handover-repair-review.js', () => ({
  readWorkloadSigningRepairReview: vi.fn(),
}));
vi.mock('./workload-signing-handover-repair-closure.js', () => ({
  readWorkloadSigningRepairClosure: vi.fn(),
}));
vi.mock('../../../participant-service/src/identity-envelope-rotation-consumer.js', () => ({
  readHistoricalIdentityEnvelopeRotationConsumer: vi.fn(),
}));

afterEach(() => vi.resetAllMocks());
const bytes = (value: string) => Buffer.from(value.slice(7), 'hex');
const ns = (value: number) => BigInt(value) * 1000000n;

// Genuine ES256 custody and typed Identity activation signatures; downstream
// reader mocks isolate composition, not native SQL or complete repair acceptance.
async function fixture(maximumCounters = false) {
  const custody = identityEnvelopeRecoveryFixture();
  const original = identityEnvelopeDualProofFixture({ continuedCredential: true });
  if (!('kind' in original.input.admission) || !original.input.descriptor) throw new Error();
  const oldTrust = {
    ...original.input.oldTrust,
    keyEpoch: maximumCounters ? 18446744073709551614n : 1n,
  };
  const selectionVersion = maximumCounters ? '18446744073709551614' : '1';
  const selectedVersion = (BigInt(selectionVersion) + 1n).toString();
  const enrollment = {
    ...original.input.admission.enrollment,
    custodyTrustId: custody.trust.custodyTrustId,
    custodyTrustDigest: canonicalAuthorizationDigest(custody.trust),
    custodyIssuerKeyId: custody.trust.issuerKeyId,
    custodyIssuerEpoch: custody.trust.issuerEpoch,
    selectionAdmissionVersion: selectionVersion,
    oldTrustDigest: identityEnvelopeSigningTrustDigest(oldTrust),
  };
  const at = custody.now.getTime();
  const intent = identityEnvelopeRecoveryIntent.parse({
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(enrollment),
    rotationId: id(401),
    creationOperationId: id(402),
    sourceParticipantEpoch: enrollment.issuerParticipantEpoch,
    sourceIssuerPrincipalEpoch: enrollment.issuerPrincipalEpoch,
    sourceIssuerCredentialEpoch: enrollment.issuerCredentialEpoch,
    oldTrustDigest: enrollment.oldTrustDigest,
    selectionAdmissionVersion: selectionVersion,
    validFrom: custody.now.toISOString(),
    validUntil: new Date(at + 900000).toISOString(),
    postReviewRequired: true,
  });
  const lease = identityEnvelopeRecoveryLease.parse({
    ...original.input.admission.lease,
    enrollmentDigest: intent.enrollmentDigest,
    intentDigest: canonicalAuthorizationDigest(intent),
    oldTrustDigest: enrollment.oldTrustDigest,
    selectionAdmissionVersion: selectionVersion,
  });
  const trust = buildIdentityEnvelopeRotationTrust({
    oldTrust,
    oldLifecycleState: 'ACTIVE',
    descriptor: original.input.descriptor,
    preparedIssuer: lease.issuer,
    currentIssuer: lease.issuer,
    admission: { kind: 'IDENTITY_ENVELOPE_SIGNER_RECOVERY', enrollment, lease },
    observedAtNs: ns(at + 1000),
  });
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const verifier = createLocalIdentityRuntimeVerifier([publicKey]);
  const activation = await signer.signCanonicalAssertion(
    identityEnvelopeRecoveryEvidencePayload({
      enrollment,
      operationId: lease.activationOperationId,
      actorPrincipalId: lease.executorPrincipalId,
      purpose: 'activation',
      value: lease,
      authenticationDigest: lease.proofEvidenceDigest,
      issuedAt: lease.validFrom,
      expiresAt: lease.validUntil,
    }),
  );
  const completion = identityEnvelopeRecoveryRotationCompletionResult.parse({
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId: id(1200),
    rotationId: lease.rotationId,
    recoveryId: lease.recoveryId,
    fromRevision: '9',
    revision: '10',
    state: 'COMPLETE',
    postReviewRequired: true,
    signerId: trust.signerId,
    trustDigest: identityEnvelopeSigningTrustDigest(trust),
    observationsDigest: canonicalAuthorizationDigest([]),
    completedAt: new Date(at + 5000).toISOString(),
    selectionAdmissionVersion: selectedVersion,
    permissionEffect: 'NONE',
    consumerObservationOperationId: id(1210),
    consumerActivationOperationId: id(1211),
    consumerEnvelopeId: id(1212),
    consumerPayloadDigest: 'sha256:' + '11'.repeat(32),
    consumerReceiptDigest: 'sha256:' + '12'.repeat(32),
    predecessorSignerId: oldTrust.signerId,
    oldPrivateKeyState: 'RETIRED',
    oldPrivateKeyRevokedAtNs: ns(at + 3000).toString(),
    oldPrivateKeyRetiredAtNs: ns(at + 4000).toString(),
  });
  const cutover = identityEnvelopeRecoveryRotationCutoverResult.parse({
    schema: completion.schema,
    schemaVersion: 1,
    rotationId: completion.rotationId,
    recoveryId: completion.recoveryId,
    signerId: completion.signerId,
    trustDigest: completion.trustDigest,
    observationsDigest: completion.observationsDigest,
    selectionAdmissionVersion: selectedVersion,
    permissionEffect: 'NONE',
    operationId: id(1220),
    fromRevision: '5',
    revision: '6',
    state: 'CUTOVER_FENCED',
    completedAt: new Date(at + 2000).toISOString(),
  });
  const carry: WorkloadSigningHandoverEnvelopeCarry = {
    disposition: 'CARRY_COMPLETED_371_RECOVERY' as const,
    purpose: trust.purpose,
    profileDigest: identityEnvelopeSigningProfileDigest,
    signerId: trust.signerId,
    trustDigest: completion.trustDigest,
    selectionAdmissionVersion: selectedVersion,
    recoveryId: lease.recoveryId,
    rotationId: lease.rotationId,
    completionOperationId: completion.operationId,
    leaseClosureOperationId: id(1201),
    reviewOperationId: id(1202),
  };
  const scope = {
    participantId: enrollment.participantId,
    privacyDomainId: enrollment.privacyDomainId,
    environmentId: trust.environmentId,
    workloadCredentialId: trust.workloadCredentialId,
    localQaEnabled: true,
  };
  const history = {
    document: enrollment,
    documentDigest: bytes(canonicalAuthorizationDigest(enrollment)),
    signature: sign('sha256', identityEnvelopeRecoveryCustodyPreimage(enrollment), {
      key: custody.key.privateKey,
      dsaEncoding: 'ieee-p1363',
    }),
    pin: custody.trust,
    pinDigest: bytes(canonicalAuthorizationDigest(custody.trust)),
    intent,
    intentDigest: bytes(canonicalAuthorizationDigest(intent)),
    enrollmentRevision: '1',
    bindings: lease,
    activationOperationId: lease.activationOperationId,
    activatedAt: new Date(lease.validFrom),
    evidenceCbor: activation.evidenceCbor,
    evidenceDigest: activation.evidenceDigest,
    cose: activation.coseSign1,
  };
  const selection = {
    signerId: carry.signerId,
    admissionVersion: carry.selectionAdmissionVersion,
    profileDigest: bytes(carry.profileDigest),
    cutover,
    cutoverOperationId: cutover.operationId,
    cutoverEvidenceDigest: Buffer.alloc(32, 9),
    lifecycleState: 'ACTIVE',
    lifecycleRevision: '2',
    lifecycleChangeDigest: Buffer.alloc(32, 9),
    grantCount: 1,
    ordinaryGrantCount: 0,
    renewalGrantCount: 0,
  };
  const review = {
    schema: 'pc.identity.workload-signing-handover.repair-review.v1' as const,
    participantId: enrollment.participantId,
    privacyDomainId: enrollment.privacyDomainId,
    recoveryId: lease.recoveryId,
    reviewOperationId: carry.reviewOperationId,
    enrollmentId: enrollment.enrollmentId,
    enrollmentDigest: intent.enrollmentDigest,
    leaseClosureState: 'REVOKED' as const,
    closedCaseRevision: '6',
    mutationCandidateId: id(1250),
    candidateDigest: 'sha256:' + '20'.repeat(32),
    approvalRequestId: id(1251),
    approvalDecisionId: id(1252),
    approvalDecisionDigest: 'sha256:' + '21'.repeat(32),
    reviewerPrincipalId: id(1253),
    checkerPrincipalId: id(1254),
    noteDigest: 'sha256:' + '22'.repeat(32),
    reviewedAt: new Date(at + 7000).toISOString(),
    evidenceDigest: 'sha256:' + '23'.repeat(32),
    resultDigest: 'sha256:' + '24'.repeat(32),
  };
  const closure = {
    recoveryId: lease.recoveryId,
    enrollmentId: enrollment.enrollmentId,
    operationId: carry.leaseClosureOperationId,
    state: 'REVOKED' as const,
    revision: '6',
    authority: 'NONE' as const,
    actorPrincipalId: enrollment.recoveryPrincipal.principalId,
    closedAt: new Date(at + 6000).toISOString(),
    evidenceDigest: 'sha256:' + '25'.repeat(32),
  };
  const consumer = {
    operationId: completion.consumerActivationOperationId,
    envelopeId: completion.consumerEnvelopeId,
    payloadDigest: completion.consumerPayloadDigest,
    receiptDigest: completion.consumerReceiptDigest,
  };
  const nowNs = ns(at + 1800000);
  const clock = { nowNs: nowNs.toString() };
  const context = { serializable: true };
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('current_setting')) return { rowCount: 1, rows: [context] };
    if (sql.includes('from control.platform_recovery_case'))
      return { rowCount: 1, rows: [history] };
    if (sql.includes('from control.identity_envelope_signing_selection'))
      return { rowCount: 1, rows: [selection] };
    if (sql.includes('clock_timestamp()')) return { rowCount: 1, rows: [clock] };
    throw new Error('Unexpected native query');
  });
  const current = { issuer: { ...lease.issuer }, recordedAtNs: nowNs };
  const key = { trust, recordedAtNs: nowNs };
  vi.mocked(captureIdentityEnvelopeRotationIssuer).mockResolvedValue(current);
  vi.mocked(fenceIdentityEnvelopeSigningTrust).mockResolvedValue(key);
  vi.mocked(readWorkloadSigningRepairProofs).mockResolvedValue({
    proofIds: lease.proofIds,
    proofEvidenceDigest: `sha256:${lease.proofEvidenceDigest.slice(7)}`,
  });
  vi.mocked(readHistoricalIdentityEnvelopeRecoveryRotation).mockResolvedValue(completion);
  vi.mocked(readWorkloadSigningRepairReview).mockResolvedValue(review);
  vi.mocked(readWorkloadSigningRepairClosure).mockResolvedValue(closure);
  vi.mocked(readHistoricalIdentityEnvelopeRotationConsumer).mockResolvedValue(consumer);
  const client = { query } as unknown as PoolClient;
  const run = () => captureWorkloadSigningEnvelopeCarry(client, scope, carry, verifier);
  return {
    scope,
    carry,
    enrollment,
    lease,
    history,
    completion,
    selection,
    current,
    key,
    consumer,
    clock,
    context,
    query,
    client,
    run,
    nowNs,
  };
}

it('connects original signed history to the unchanged current key without renewing historical authority', async () => {
  const f = await fixture();
  const before = identityEnvelopeSigningTrustPreimage(f.key.trust);
  expect(BigInt(Date.parse(f.lease.validUntil)) * 1000000n).toBeLessThan(f.nowNs);
  const result = await f.run();
  expect(result.trust).toBe(f.key.trust);
  expect(result.document.trustPreimageBase64).toBe(before.toString('base64'));
  expect(identityEnvelopeSigningTrustPreimage(f.key.trust)).toEqual(before);
  expect(result.document.selectionAdmissionVersion).toBe('2');
  expect(result.document).not.toHaveProperty('authority');
  expect(result.document).not.toHaveProperty('session');
  expect(Object.isFrozen(result.document)).toBe(true);
  expect(lockAuthorityFence).toHaveBeenCalledWith(f.client, f.scope.participantId, {
    participant: [{ id: f.scope.participantId, write: true }],
  });
  expect(vi.mocked(lockAuthorityFence).mock.invocationCallOrder[0]).toBeLessThan(
    vi.mocked(captureIdentityEnvelopeRotationIssuer).mock.invocationCallOrder[0]!,
  );
  expect(readHistoricalIdentityEnvelopeRotationConsumer).toHaveBeenCalledWith(
    f.client,
    {
      trust: f.key.trust,
      cutoverAtNs: BigInt(Date.parse(f.selection.cutover.completedAt)) * 1000000n,
      observedAtNs: BigInt(Date.parse(f.completion.completedAt)) * 1000000n,
      operationId: f.completion.consumerActivationOperationId,
      envelopeId: f.completion.consumerEnvelopeId,
    },
    expect.anything(),
  );
  expect(
    f.query.mock.calls.every(([sql]) => !/\b(insert|update|delete|set role)\b/iu.test(sql)),
  ).toBe(true);
});

it('preserves maximum carried key and selector counters without incrementing them', async () => {
  const f = await fixture(true);
  const result = await f.run();
  expect(result.trust.keyEpoch).toBe(18446744073709551615n);
  expect(result.document.selectionAdmissionVersion).toBe('18446744073709551615');
});

it('denies a non-serializable transaction before taking fences or reading history', async () => {
  const f = await fixture();
  f.context.serializable = false;
  await expect(f.run()).rejects.toThrow();
  expect(lockAuthorityFence).not.toHaveBeenCalled();
  expect(readWorkloadSigningRepairProofs).not.toHaveBeenCalled();
});

const historyMutations: readonly [string, (f: Awaited<ReturnType<typeof fixture>>) => void][] = [
  [
    'foreign Participant',
    (f) => {
      f.scope.participantId = id(999);
    },
  ],
  [
    'foreign privacy',
    (f) => {
      f.scope.privacyDomainId = id(999);
    },
  ],
  [
    'foreign environment',
    (f) => {
      f.scope.environmentId = 'other';
    },
  ],
  [
    'other credential',
    (f) => {
      f.scope.workloadCredentialId = id(999);
    },
  ],
  [
    'QA history disabled',
    (f) => {
      f.scope.localQaEnabled = false;
    },
  ],
  [
    'corrupted custody signature',
    (f) => {
      f.history.signature[0] = f.history.signature[0]! ^ 1;
    },
  ],
  [
    'wrong stored enrollment digest',
    (f) => {
      f.history.documentDigest = Buffer.alloc(32);
    },
  ],
  [
    'wrong stored pin digest',
    (f) => {
      f.history.pinDigest = Buffer.alloc(32);
    },
  ],
  [
    'wrong stored intent digest',
    (f) => {
      f.history.intentDigest = Buffer.alloc(32);
    },
  ],
  [
    'wrong original enrollment revision',
    (f) => {
      f.history.enrollmentRevision = '2';
    },
  ],
  [
    'wrong recovery',
    (f) => {
      f.carry.recoveryId = id(999);
    },
  ],
  [
    'wrong rotation',
    (f) => {
      f.carry.rotationId = id(999);
    },
  ],
  [
    'corrupted activation signature',
    (f) => {
      f.history.cose[f.history.cose.length - 1] = f.history.cose[f.history.cose.length - 1]! ^ 1;
    },
  ],
  [
    'changed current public key',
    (f) => {
      f.current.issuer.workloadPublicKeyDigest = 'sha256:' + 'aa'.repeat(32);
    },
  ],
  [
    'changed current credential validity',
    (f) => {
      f.current.issuer.credentialValidUntilNs = '18446744073709551000';
    },
  ],
  [
    'changed current principal epoch',
    (f) => {
      f.current.issuer.workloadPrincipalEpoch = '3';
    },
  ],
];
it.each(historyMutations)('denies %s without continuing to rotation history', async (_, mutate) => {
  const f = await fixture();
  mutate(f);
  await expect(f.run()).rejects.toThrow();
  expect(readHistoricalIdentityEnvelopeRecoveryRotation).not.toHaveBeenCalled();
});

const selectorMutations: readonly [string, (f: Awaited<ReturnType<typeof fixture>>) => void][] = [
  [
    'different selected key',
    (f) => {
      f.selection.signerId = 'sha256:' + 'aa'.repeat(32);
    },
  ],
  [
    'advanced selector version',
    (f) => {
      f.selection.admissionVersion = '3';
    },
  ],
  [
    'wrong profile',
    (f) => {
      f.selection.profileDigest = Buffer.alloc(32);
    },
  ],
  [
    'inactive key',
    (f) => {
      f.selection.lifecycleState = 'REVOKED';
    },
  ],
  [
    'changed lifecycle version',
    (f) => {
      f.selection.lifecycleRevision = '3';
    },
  ],
  [
    'changed lifecycle provenance',
    (f) => {
      f.selection.lifecycleChangeDigest = Buffer.alloc(32);
    },
  ],
  [
    'missing grant',
    (f) => {
      f.selection.grantCount = 0;
    },
  ],
  [
    'additional envelope grant',
    (f) => {
      f.selection.grantCount = 2;
    },
  ],
  [
    'ordinary receipt grant',
    (f) => {
      f.selection.ordinaryGrantCount = 1;
    },
  ],
  [
    'workload renewal grant',
    (f) => {
      f.selection.renewalGrantCount = 1;
    },
  ],
  [
    'other cutover operation',
    (f) => {
      f.selection.cutoverOperationId = id(999);
    },
  ],
  [
    'other completion operation',
    (f) => {
      f.carry.completionOperationId = id(999);
    },
  ],
  [
    'other claimed trust',
    (f) => {
      f.carry.trustDigest = 'sha256:' + 'aa'.repeat(32);
    },
  ],
];
it.each(selectorMutations)('denies %s before reading current trust', async (_, mutate) => {
  const f = await fixture();
  mutate(f);
  await expect(f.run()).rejects.toThrow();
  expect(fenceIdentityEnvelopeSigningTrust).not.toHaveBeenCalled();
});

it.each([
  readWorkloadSigningRepairProofs,
  readHistoricalIdentityEnvelopeRecoveryRotation,
  readWorkloadSigningRepairReview,
  readWorkloadSigningRepairClosure,
  fenceIdentityEnvelopeSigningTrust,
  readHistoricalIdentityEnvelopeRotationConsumer,
])('propagates a required owner denial without producing a carry source (%#)', async (owner) => {
  const f = await fixture();
  vi.mocked(owner).mockRejectedValue(new Error('Original owner denied'));
  await expect(f.run()).rejects.toThrow('Original owner denied');
});

it.each(['operationId', 'envelopeId', 'payloadDigest', 'receiptDigest'] as const)(
  'denies a mismatched original consumer %s',
  async (field) => {
    const f = await fixture();
    f.consumer[field] = field.endsWith('Digest') ? 'sha256:' + 'aa'.repeat(32) : id(999);
    await expect(f.run()).rejects.toThrow();
  },
);

it.each(['-1', '1e18', '18446744073709551616', '1700000000000000001', '1'])(
  'rejects malformed, imprecise or regressing native clock %s',
  async (value) => {
    const f = await fixture();
    f.clock.nowNs = value;
    await expect(f.run()).rejects.toThrow();
  },
);

it('rejects original key expiry reached during historical-consumer verification', async () => {
  const f = await fixture();
  f.clock.nowNs = f.key.trust.validUntilNs.toString();
  await expect(f.run()).rejects.toThrow();
  expect(readHistoricalIdentityEnvelopeRotationConsumer).toHaveBeenCalledOnce();
});
