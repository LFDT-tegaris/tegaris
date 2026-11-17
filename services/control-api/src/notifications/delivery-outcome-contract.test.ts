import { afterEach, expect, it, vi } from 'vitest';
import { notificationOutcomeSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import { notificationSignedOutcomeSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import { signNotificationClaim } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  decodeNotificationOutcomeObservation,
  encodeNotificationOutcomeObservation,
  proposeNotificationDeliveryOutcome,
  validateNotificationOutcomeObservation,
  validateNotificationDeliveryOutcomeTransition,
  decodeNotificationDeliveryOutcomeTransition,
  notificationDeliveryOutcomeClaims,
} from './delivery-outcome-contract.js';

it.each(['DELIVERED', 'RETRYABLE_NO_EFFECT', 'PERMANENT_FAILURE', 'AMBIGUOUS'] as const)(
  'binds canonical Control %s receipt to exact original/native/state bytes',
  (outcome) => {
    const f = notificationSignedOutcomeSample(outcome),
      r = f.value.receipt;
    expect(
      decodeNotificationDeliveryOutcomeTransition(
        f.encoded.transitionBytes,
        f.encoded.transitionDigest,
      ),
    ).toEqual(f.value);
    expect(r.startReceiptDigest).toBe(sha256(Buffer.from(f.f.original.payloadHex, 'hex')));
    expect(r.dispatchClaimDigest).toBe(sha256(f.f.claim));
    expect(r.gatewayReceiptDigest).toBe(
      sha256(Buffer.from(f.value.input.observation.observation.signed.payloadHex, 'hex')),
    );
    expect(r.gatewayCoseDigest).toBe(f.value.input.observation.observation.receiptDigest);
    expect(r.observationDigest).toBe(f.firstRow.observation_digest);
    expect(r.gatewayReceiptDigest).not.toBe(r.gatewayCoseDigest);
    const bytes = f.encoded.coseSign1;
    bytes.fill(0);
    expect(f.encoded.coseSign1.toString('hex')).toBe(f.value.coseHex);
  },
);
it.each([
  'dispatchClaimDigest',
  'startReceiptDigest',
  'sourceReceiptDigest',
  'gatewayReceiptDigest',
  'gatewayCoseDigest',
  'observationDigest',
  'beforeStateDigest',
  'afterStateDigest',
  'authoritySnapshotDigest',
  'payloadDigest',
] as const)('rejects signed but detached %s outcome binding', (field) => {
  const f = notificationSignedOutcomeSample(),
    value = structuredClone(f.value);
  value.receipt[field] = sha256('detached');
  const signed = signNotificationClaim(
    'NotificationDeliveryOutcomeReceiptV1',
    f.f.signerPrivateKey,
    f.f.signerSpki,
    value.receipt,
  );
  value.payloadHex = signed.payload.toString('hex');
  value.coseHex = signed.cose.toString('hex');
  expect(() => validateNotificationDeliveryOutcomeTransition(value)).toThrow();
});
it('does not confuse STARTED/cancellation purpose with the newly committed outcome purpose', () => {
  const f = notificationSignedOutcomeSample();
  expect(() =>
    validateNotificationDeliveryOutcomeTransition({
      ...f.value,
      payloadHex: f.f.original.payloadHex,
      coseHex: f.f.original.coseHex,
    }),
  ).toThrow();
  expect(() =>
    validateNotificationDeliveryOutcomeTransition({ ...f.value, current: true }),
  ).toThrow();
  expect(() =>
    validateNotificationDeliveryOutcomeTransition({
      ...f.value,
      receipt: { ...f.value.receipt, noEffect: true },
    }),
  ).toThrow();
});
it('uses historical recording time while binding fresh result identity separately from the original send', () => {
  const f = notificationSignedOutcomeSample();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(f.value.metadata.recordedAtMs + 86400000);
  expect(validateNotificationDeliveryOutcomeTransition(f.value).receipt).toEqual(f.value.receipt);
  for (const operationId of [
    f.f.original.receipt.operationId,
    f.f.original.sourceOperationId,
    f.f.original.attempt.attemptId,
  ])
    expect(() =>
      notificationDeliveryOutcomeClaims({
        input: f.value.input,
        workerInstallation: f.value.workerInstallation,
        signerInstallation: f.value.signerInstallation,
        metadata: { ...f.value.metadata, operationId },
      }),
    ).toThrow();
  expect(() =>
    notificationDeliveryOutcomeClaims({
      input: f.value.input,
      workerInstallation: f.value.workerInstallation,
      signerInstallation: f.value.signerInstallation,
      metadata: { ...f.value.metadata, recordedAtMs: f.f.original.attempt.startedAtMs - 1 },
    }),
  ).toThrow();
});
it('rejects a recomputed digest on noncanonical signed-transition JSON', () => {
  const f = notificationSignedOutcomeSample(),
    bytes = Buffer.from(` ${f.encoded.transitionBytes.toString()}`);
  expect(() => decodeNotificationDeliveryOutcomeTransition(bytes, sha256(bytes))).toThrow();
});
afterEach(() => vi.useRealTimers());
it.each([
  'pc.cose.notification-delivery-started-receipt.v1',
  'pc.cose.notification-delivery-cancellation-receipt.v1',
])('rejects %s signer installation for outcome history', (purpose) => {
  const f = notificationSignedOutcomeSample();
  expect(() =>
    validateNotificationDeliveryOutcomeTransition({
      ...f.value,
      signerInstallation: { ...f.value.signerInstallation, purpose },
    }),
  ).toThrow();
});
it('binds the outcome-specific installation validity and worker identity at recording', () => {
  const f = notificationSignedOutcomeSample();
  for (const change of [
    { workerInstallationDigest: sha256('other-worker') },
    { workerProfileDigest: sha256('other-profile') },
    { workloadEpoch: '2' },
    { validUntilNs: (BigInt(f.value.metadata.recordedAtMs) * 1000000n).toString() },
  ])
    expect(() =>
      validateNotificationDeliveryOutcomeTransition({
        ...f.value,
        signerInstallation: { ...f.value.signerInstallation, ...change },
      }),
    ).toThrow();
});
it('retains exact authenticated native bytes in the existing observation format', () => {
  const f = notificationOutcomeSample(),
    e = encodeNotificationOutcomeObservation(f.binding);
  expect(
    decodeNotificationOutcomeObservation(
      f.original,
      f.claim,
      e.observationBytes,
      e.observationDigest,
    ),
  ).toEqual(f.binding.observation);
  const bytes = e.observationBytes;
  bytes.fill(0);
  expect(e.observationBytes.toString()).toBe(canonicalJson(f.binding.observation));
  expect(Object.isFrozen(e.observation)).toBe(true);
});
it.each([
  'pending',
  'late-claim',
  'early-claim',
  'pre-claim-receipt',
  'unsigned',
  'signature',
  'extra',
])('rejects %s at the original authenticated boundary', (kind) => {
  const f = notificationOutcomeSample(),
    value = structuredClone(f.binding);
  if (kind === 'pending')
    Object.assign(value.claim, { state: 'PENDING', claimToken: null, claimedAtMs: null });
  if (kind === 'late-claim') value.claim.claimedAtMs = f.original.attempt.deadlineAtMs;
  if (kind === 'early-claim') value.claim.claimedAtMs = f.original.attempt.startedAtMs - 1;
  if (kind === 'pre-claim-receipt')
    value.observation = f.observation('DELIVERED', f.original.attempt.startedAtMs);
  if (kind === 'unsigned') Object.assign(value.observation, { signed: null });
  if (kind === 'signature') value.observation.signed.coseHex = '00';
  if (kind === 'extra') Object.assign(value, { current: true });
  expect(() => validateNotificationOutcomeObservation(value)).toThrow('outcome unavailable');
});
it('requires exact first signature even when a second signature has identical claims', () => {
  const f = notificationOutcomeSample(),
    first = f.binding.observation;
  expect(validateNotificationOutcomeObservation({ ...f.binding, first }).observation).toEqual(
    first,
  );
  const second = f.observation();
  expect(second.claims).toEqual(first.claims);
  expect(second.signed.coseHex).not.toBe(first.signed.coseHex);
  expect(() =>
    validateNotificationOutcomeObservation({ ...f.binding, observation: second, first }),
  ).toThrow();
});
it('does not replace first signed ambiguity with a later contradictory delivery', () => {
  const f = notificationOutcomeSample(),
    first = f.observation('AMBIGUOUS');
  expect(() => validateNotificationOutcomeObservation({ ...f.binding, first })).toThrow();
  const p = proposeNotificationDeliveryOutcome({
    observation: { ...f.binding, observation: first, first },
    current: f.current,
    configuredLimit: 6,
  });
  expect(p.after.snapshot.state).toBe('AMBIGUOUS');
  expect(p.completionData).toBeNull();
  expect(p.failureWorkRequired).toBe(false);
});
it.each(['digest', 'whitespace', 'duplicate', 'utf8', 'oversized'])(
  'rejects non-original %s persisted encoding',
  (kind) => {
    const f = notificationOutcomeSample(),
      e = encodeNotificationOutcomeObservation(f.binding);
    let bytes = e.observationBytes,
      digest = e.observationDigest;
    if (kind === 'digest') digest = sha256('other');
    if (kind === 'whitespace') bytes = Buffer.from(` ${bytes.toString()}`);
    if (kind === 'duplicate') bytes = Buffer.from(bytes.toString().replace('{', '{"claims":{},'));
    if (kind === 'utf8') bytes = Buffer.from([255]);
    if (kind === 'oversized') bytes = Buffer.alloc(262145);
    if (kind !== 'digest') digest = sha256(bytes);
    expect(() =>
      decodeNotificationOutcomeObservation(f.original, f.claim, bytes, digest),
    ).toThrow();
  },
);
it.each([
  [1, 5000],
  [2, 30000],
  [3, 120000],
  [4, 600000],
  [5, 1800000],
  [6, null],
] as const)('uses existing persisted retry policy for attempt %i', (attempt, delay) => {
  const f = notificationOutcomeSample(attempt),
    observation = f.observation('RETRYABLE_NO_EFFECT');
  const p = proposeNotificationDeliveryOutcome({
    observation: { ...f.binding, observation },
    current: f.current,
    configuredLimit: 100,
  });
  expect(p.after.snapshot.attemptCount).toBe(attempt);
  expect(p.after.snapshot.attemptLimit).toBe(6);
  expect(p.after.snapshot.state).toBe(delay === null ? 'FAILED' : 'RETRY_WAIT');
  expect(p.after.snapshot.nextAttemptAtMs).toBe(
    delay === null ? null : observation.claims.observedAtMs + delay,
  );
  expect(p.failureWorkRequired).toBe(delay === null);
});
it('preserves delivered truth after cancellation, reduced cap and original expiry', () => {
  const f = notificationOutcomeSample();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(f.original.attempt.deadlineAtMs + 86400000);
  const p = proposeNotificationDeliveryOutcome({
    observation: f.binding,
    current: {
      snapshot: {
        ...f.current.snapshot,
        state: 'AMBIGUOUS',
        cancelRequested: true,
        attemptLimit: 0,
      },
      revision: '4',
    },
    configuredLimit: 0,
  });
  expect(p.after.snapshot).toMatchObject({
    state: 'DELIVERED',
    attemptCount: 1,
    attemptLimit: 0,
    cancelRequested: true,
  });
  expect(p.after.revision).toBe('5');
  expect(p.completionData).toMatchObject({
    state: 'DELIVERED',
    attemptCount: '1',
    deliveryReceiptDigest: f.binding.observation.receiptDigest,
  });
  expect(p.failureWorkRequired).toBe(false);
});
it('cancellation wins only after definitive no-effect; permanent failure still requires work', () => {
  const f = notificationOutcomeSample(),
    current = { snapshot: { ...f.current.snapshot, cancelRequested: true }, revision: '3' };
  for (const outcome of ['RETRYABLE_NO_EFFECT', 'PERMANENT_FAILURE'] as const) {
    const p = proposeNotificationDeliveryOutcome({
      observation: { ...f.binding, observation: f.observation(outcome) },
      current,
      configuredLimit: 6,
    });
    expect(p.after.snapshot.state).toBe(outcome === 'RETRYABLE_NO_EFFECT' ? 'CANCELLED' : 'FAILED');
    expect(p.failureWorkRequired).toBe(outcome === 'PERMANENT_FAILURE');
  }
});
it.each([
  'old-revision',
  'same-revision-changed-state',
  'overflow',
  'wrong-attempt',
  'wrong-scope',
  'terminal',
  'unknown',
  'cap-increase',
])('rejects %s instead of creating a new intent', (kind) => {
  const f = notificationOutcomeSample();
  const p = {
    observation: structuredClone(f.binding),
    current: structuredClone(f.current),
    configuredLimit: 6,
  };
  if (kind === 'old-revision') p.current.revision = '1';
  if (kind === 'same-revision-changed-state') p.current.snapshot.cancelRequested = true;
  if (kind === 'overflow') p.current.revision = '18446744073709551615';
  if (kind === 'wrong-attempt') {
    p.current.revision = '3';
    p.current.snapshot.attemptCount = 2;
  }
  if (kind === 'wrong-scope') {
    p.current.revision = '3';
    p.current.snapshot.participantId = p.current.snapshot.privacyDomainId;
  }
  if (kind === 'terminal') {
    p.current.revision = '3';
    p.current.snapshot.state = 'DELIVERED';
  }
  if (kind === 'unknown') Object.assign(p.observation, { observation: null });
  if (kind === 'cap-increase') p.current.snapshot.attemptLimit = 7;
  expect(() => proposeNotificationDeliveryOutcome(p)).toThrow();
});
