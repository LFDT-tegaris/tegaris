import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
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
import { readWorkloadSigningRepairClosure } from './workload-signing-handover-repair-closure.js';

async function fixture() {
  const original = identityEnvelopeEffectiveProofFixture();
  if (!('kind' in original.input.admission)) throw new Error();
  const { enrollment, lease } = original.input.admission;
  const at = Date.parse(lease.validFrom);
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const trusted = createLocalIdentityRuntimeVerifier([publicKey]);
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
    signerId: original.trust.signerId,
    trustDigest: identityEnvelopeSigningTrustDigest(original.trust),
    observationsDigest: canonicalAuthorizationDigest([]),
    completedAt: new Date(at + 5000).toISOString(),
    selectionAdmissionVersion: '2',
    permissionEffect: 'NONE',
    consumerObservationOperationId: id(1210),
    consumerActivationOperationId: id(1211),
    consumerEnvelopeId: id(1212),
    consumerPayloadDigest: 'sha256:' + '11'.repeat(32),
    consumerReceiptDigest: 'sha256:' + '12'.repeat(32),
    predecessorSignerId: enrollment.request.oldFingerprint,
    oldPrivateKeyState: 'RETIRED',
    oldPrivateKeyRevokedAtNs: (BigInt(at + 3000) * 1000000n).toString(),
    oldPrivateKeyRetiredAtNs: (BigInt(at + 4000) * 1000000n).toString(),
  });
  const input: Parameters<typeof readWorkloadSigningRepairClosure>[1] = {
    enrollment,
    lease,
    completion,
    closureOperationId: id(1201),
    review: {
      participantId: enrollment.participantId,
      privacyDomainId: enrollment.privacyDomainId,
      recoveryId: lease.recoveryId,
      enrollmentId: enrollment.enrollmentId,
      enrollmentDigest: canonicalAuthorizationDigest(enrollment),
      reviewOperationId: id(1202),
      leaseClosureState: 'REVOKED',
      closedCaseRevision: '6',
      reviewedAt: new Date(at + 7000).toISOString(),
    },
  };
  const row = {
    state: 'REVOKED',
    revision: '7',
    enrollmentDigest: Buffer.from(lease.enrollmentDigest.slice(7), 'hex'),
    intentDigest: Buffer.from(lease.intentDigest.slice(7), 'hex'),
    bindings: lease,
    activatedAt: new Date(lease.validFrom),
    activationOperationId: lease.activationOperationId,
    reviewedAt: new Date(input.review.reviewedAt),
    reviewOperationId: input.review.reviewOperationId,
  };
  const event: { cbor: Buffer; digest: Buffer; cose: Buffer; occurredAt: Date } = {
    cbor: Buffer.alloc(0),
    digest: Buffer.alloc(0),
    cose: Buffer.alloc(0),
    occurredAt: new Date(at + 6000),
  };
  const value = {
    recoveryId: lease.recoveryId,
    enrollmentId: enrollment.enrollmentId,
    operationId: input.closureOperationId,
    state: input.review.leaseClosureState,
    revision: '6',
    authority: 'NONE',
    actorPrincipalId: enrollment.recoveryPrincipal.principalId,
    closedAt: event.occurredAt.toISOString(),
  };
  const resign = async (
    overrides: Partial<Parameters<typeof identityEnvelopeRecoveryEvidencePayload>[0]> = {},
  ) => {
    const payload = identityEnvelopeRecoveryEvidencePayload({
      enrollment: input.enrollment,
      operationId: input.closureOperationId,
      actorPrincipalId: value.actorPrincipalId,
      purpose: 'closure',
      value: { ...value },
      authenticationDigest: canonicalAuthorizationDigest([
        value.actorPrincipalId,
        { sessionId: id(1220), sessionEpoch: '4' },
      ]),
      issuedAt: value.closedAt,
      expiresAt: new Date(Date.parse(value.closedAt) + 60000).toISOString(),
      ...overrides,
    });
    const signed = await signer.signCanonicalAssertion(payload);
    event.cbor = signed.evidenceCbor;
    event.digest = signed.evidenceDigest;
    event.cose = signed.coseSign1;
  };
  await resign();
  const flags = { caseCount: 1, eventCount: 1 };
  const query = vi.fn(async (sql: string) => {
    if (sql === 'select openpc.assert_request_context(true)') return { rowCount: 1, rows: [{}] };
    if (sql.startsWith('select c.state'))
      return {
        rowCount: flags.caseCount,
        rows: Array.from({ length: flags.caseCount }, () => row),
      };
    if (sql.startsWith('select payload_cbor'))
      return {
        rowCount: flags.eventCount,
        rows: Array.from({ length: flags.eventCount }, () => event),
      };
    throw new Error('Unexpected closure query or attempted effect');
  });
  const verifier = {
    verifyCanonicalAssertion: vi.fn(trusted.verifyCanonicalAssertion.bind(trusted)),
  };
  const read = () =>
    readWorkloadSigningRepairClosure({ query } as unknown as PoolClient, input, verifier);
  return { input, row, event, value, resign, flags, query, verifier, trusted, read };
}

it('authenticates one original closure event, consumed-review revision and enrolled closer with real338 crypto', async () => {
  const f = await fixture();
  const result = await f.read();
  expect(result).toEqual({
    ...f.value,
    evidenceDigest: 'sha256:' + f.event.digest.toString('hex'),
  });
  expect(Object.isFrozen(result)).toBe(true);
  expect(f.verifier.verifyCanonicalAssertion).toHaveBeenCalledWith(f.event.cbor, f.event.cose);
  expect(f.query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
  const eventQuery = f.query.mock.calls.find(([sql]) => sql.startsWith('select payload_cbor'))![0];
  expect(eventQuery).not.toContain('event_id=');
  expect(eventQuery).toContain('limit 2');
});
it.each(['executor', 'first-custodian', 'second-custodian'] as const)(
  'accepts the original enrolled %s as closer',
  async (kind) => {
    const f = await fixture();
    f.value.actorPrincipalId =
      kind === 'executor'
        ? f.input.enrollment.recoveryPrincipal.principalId
        : f.input.enrollment.custodians[kind === 'first-custodian' ? 0 : 1].principalId;
    await f.resign();
    expect((await f.read()).actorPrincipalId).toBe(f.value.actorPrincipalId);
  },
);
it('authenticates native EXPIRED state without inferring state from rounded event time', async () => {
  const f = await fixture();
  f.row.state = 'EXPIRED';
  f.input.review.leaseClosureState = 'EXPIRED';
  f.value.state = 'EXPIRED';
  f.event.occurredAt = new Date(Date.parse(f.input.lease.validUntil) + 1000);
  f.value.closedAt = f.event.occurredAt.toISOString();
  f.row.reviewedAt = new Date(f.event.occurredAt.getTime() + 1000);
  f.input.review.reviewedAt = f.row.reviewedAt.toISOString();
  // State is an original signed/native fact. It is not re-derived here.
  await f.resign();
  expect((await f.read()).state).toBe('EXPIRED');
});
it('retains an original REVOKED closure after the recorded lease deadline', async () => {
  const f = await fixture();
  f.event.occurredAt = new Date(Date.parse(f.input.lease.validUntil) + 1000);
  f.value.closedAt = f.event.occurredAt.toISOString();
  f.row.reviewedAt = new Date(f.event.occurredAt.getTime() + 1000);
  f.input.review.reviewedAt = f.row.reviewedAt.toISOString();
  await f.resign();
  expect((await f.read()).state).toBe('REVOKED');
});
it('compares completion and closure at the original338 millisecond precision', async () => {
  const f = await fixture();
  f.input.completion.completedAt = f.value.closedAt.replace('Z', '900000Z');
  expect((await f.read()).closedAt).toBe(f.value.closedAt);
});
it.each(['missing-case', 'duplicate-case', 'missing-event', 'duplicate-event'] as const)(
  'rejects %s instead of choosing a convenient history',
  async (kind) => {
    const f = await fixture();
    if (kind === 'missing-case') f.flags.caseCount = 0;
    if (kind === 'duplicate-case') f.flags.caseCount = 2;
    if (kind === 'missing-event') f.flags.eventCount = 0;
    if (kind === 'duplicate-event') f.flags.eventCount = 2;
    await expect(f.read()).rejects.toThrow();
    expect(f.verifier.verifyCanonicalAssertion).not.toHaveBeenCalled();
  },
);
it.each([
  'participant',
  'privacy',
  'recovery',
  'enrollment',
  'enrollment-digest',
  'completion-rotation',
  'same-operation',
  'closed-revision',
  'native-revision',
  'native-state',
  'native-enrollment',
  'native-intent',
  'native-lease',
  'activation',
  'activation-time',
  'review-operation',
  'review-time',
  'completion-after-closure',
  'closure-after-review',
  'event-digest',
  'event-signature',
] as const)('rejects %s mismatch in closure composition', async (kind) => {
  const f = await fixture();
  if (kind === 'participant') f.input.review.participantId = id(1290);
  if (kind === 'privacy') f.input.review.privacyDomainId = id(1290);
  if (kind === 'recovery') f.input.review.recoveryId = id(1290);
  if (kind === 'enrollment') f.input.review.enrollmentId = id(1290);
  if (kind === 'enrollment-digest') f.input.review.enrollmentDigest = 'sha256:' + '99'.repeat(32);
  if (kind === 'completion-rotation') f.input.completion.rotationId = id(1290);
  if (kind === 'same-operation') f.input.closureOperationId = f.input.completion.operationId;
  if (kind === 'closed-revision') f.input.review.closedCaseRevision = '5';
  if (kind === 'native-revision') f.row.revision = '8';
  if (kind === 'native-state') f.row.state = 'EXPIRED';
  if (kind === 'native-enrollment') f.row.enrollmentDigest = Buffer.alloc(32, 9);
  if (kind === 'native-intent') f.row.intentDigest = Buffer.alloc(32, 9);
  if (kind === 'native-lease')
    f.row.bindings = { ...f.input.lease, proofEvidenceDigest: 'sha256:' + '99'.repeat(32) };
  if (kind === 'activation') f.row.activationOperationId = id(1290);
  if (kind === 'activation-time') f.row.activatedAt = new Date(f.row.activatedAt.getTime() + 1);
  if (kind === 'review-operation') f.row.reviewOperationId = id(1290);
  if (kind === 'review-time')
    f.input.review.reviewedAt = new Date(f.row.reviewedAt.getTime() + 1).toISOString();
  if (kind === 'completion-after-closure')
    f.input.completion.completedAt = new Date(f.event.occurredAt.getTime() + 1).toISOString();
  if (kind === 'closure-after-review')
    f.row.reviewedAt = new Date(f.event.occurredAt.getTime() - 1);
  if (kind === 'event-digest') f.event.digest = Buffer.alloc(32, 9);
  if (kind === 'event-signature') {
    f.event.cose = Buffer.from(f.event.cose);
    const index = f.event.cose.length - 1;
    f.event.cose[index] = f.event.cose[index]! ^ 1;
  }
  await expect(f.read()).rejects.toThrow();
  expect(f.query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
});
it.each([
  'operation-locator',
  'value-recovery',
  'value-enrollment',
  'value-revision',
  'value-state',
  'value-authority',
  'value-closer',
  'value-time',
  'foreign-actor',
  'context',
  'purpose',
  'issued-at',
  'expires-at',
] as const)('rejects coherently signed %s substitution', async (kind) => {
  const f = await fixture();
  const change: Parameters<typeof f.resign>[0] = {};
  if (kind === 'operation-locator') change.operationId = id(1290);
  if (kind === 'value-recovery') change.value = { ...f.value, recoveryId: id(1290) };
  if (kind === 'value-enrollment') change.value = { ...f.value, enrollmentId: id(1290) };
  if (kind === 'value-revision') change.value = { ...f.value, revision: '7' };
  if (kind === 'value-state') change.value = { ...f.value, state: 'EXPIRED' };
  if (kind === 'value-authority') change.value = { ...f.value, authority: 'CURRENT' };
  if (kind === 'value-closer') change.value = { ...f.value, actorPrincipalId: id(1290) };
  if (kind === 'value-time')
    change.value = {
      ...f.value,
      closedAt: new Date(f.event.occurredAt.getTime() + 1).toISOString(),
    };
  if (kind === 'foreign-actor') change.actorPrincipalId = id(1290);
  if (kind === 'context')
    change.enrollment = { ...f.input.enrollment, rootDigest: 'sha256:' + '99'.repeat(32) };
  if (kind === 'purpose') change.purpose = 'activation';
  if (kind === 'issued-at')
    change.issuedAt = new Date(f.event.occurredAt.getTime() + 1).toISOString();
  if (kind === 'expires-at')
    change.expiresAt = new Date(f.event.occurredAt.getTime() + 60001).toISOString();
  await f.resign(change);
  expect(await f.trusted.verifyCanonicalAssertion(f.event.cbor, f.event.cose)).toBeTruthy();
  await expect(f.read()).rejects.toThrow();
});
it('rejects ambiguous enrolled actor-key matches even when the event is coherently signed', async () => {
  const f = await fixture();
  f.input.enrollment = {
    ...f.input.enrollment,
    custodians: [f.input.enrollment.recoveryPrincipal, f.input.enrollment.custodians[1]],
  };
  const digest = canonicalAuthorizationDigest(f.input.enrollment);
  f.input.lease = { ...f.input.lease, enrollmentDigest: digest };
  f.input.review.enrollmentDigest = digest;
  f.row.enrollmentDigest = Buffer.from(digest.slice(7), 'hex');
  f.row.bindings = f.input.lease;
  await f.resign();
  expect(await f.trusted.verifyCanonicalAssertion(f.event.cbor, f.event.cose)).toBeTruthy();
  await expect(f.read()).rejects.toThrow();
});
