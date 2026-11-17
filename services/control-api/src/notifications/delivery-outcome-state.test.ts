import { proposeNotificationDeliveryOutcome } from './delivery-outcome-contract.js';
import { expect, it } from 'vitest';
import { notificationOutcomeSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import { decodeNotificationOutcomeRow } from './delivery-outcome-state.js';
import { decodeNotificationSignedOutcomeRow } from './delivery-outcome-state.js';
import { notificationSignedOutcomeSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import { notificationOutcomeSigningSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import {
  validateNotificationOutcomeSigning,
  assertNotificationOutcomeSigningCurrent,
  consumeNotificationOutcomeSigningClaim,
  decodeNotificationOutcomeSigningRow,
  notificationOutcomeSigningObservation,
  notificationOutcomeSigningTransition,
} from './delivery-outcome-state.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  buildAdmittedNotificationOutcomeSigning,
  notificationOutcomeFinalEffects,
} from './delivery-outcome-state.js';
import type { PoolClient } from 'pg';
import type { NotificationWorkerAdmission } from '../../../identity-service/src/domain/notification-worker.js';
import type { NotificationReceiptSignerSelector } from './receipt-signer-installation.js';

it('rejects a forged worker capability before opening canonical result authority or reading inputs', async () => {
  let touched = 0;
  const denied = new Proxy(
    {},
    {
      get() {
        touched++;
        throw new Error('database touched');
      },
    },
  );
  await expect(
    buildAdmittedNotificationOutcomeSigning(
      denied as PoolClient,
      {} as NotificationWorkerAdmission,
      {
        worker: notificationOutcomeSigningSample().selector.worker,
        signerInstallationDigest: sha256('fake'),
      } as NotificationReceiptSignerSelector,
      {},
    ),
  ).rejects.toThrow('outcome unavailable');
  expect(touched).toBe(0);
});
it.each(['PERMANENT_FAILURE', 'RETRYABLE_NO_EFFECT'] as const)(
  'derives authentic failure WorkItem for terminal %s without an unsigned ID or MutationContext',
  (outcome) => {
    const f = notificationSignedOutcomeSample(outcome, outcome === 'RETRYABLE_NO_EFFECT' ? 6 : 1);
    const effects = notificationOutcomeFinalEffects(f.value);
    expect(effects.failureWork).toMatchObject({
      workItemId: f.value.receipt.receiptId,
      outcomeOperationId: f.value.receipt.operationId,
      notificationOccurrenceId: f.value.receipt.notificationOccurrenceId,
      kind: 'DELIVERY_FAILURE',
      state: 'OPEN',
      payloadDigest: sha256(Buffer.from(f.value.payloadHex, 'hex')),
    });
    expect(effects.completionData?.state).toBe('FAILED');
    expect(() => notificationOutcomeFinalEffects({ ...f.value, coseHex: '00' })).toThrow();
  },
);
it.each(['DELIVERED', 'AMBIGUOUS', 'RETRYABLE_NO_EFFECT'] as const)(
  'creates no failure work for %s',
  (outcome) => {
    const f = notificationSignedOutcomeSample(outcome);
    expect(notificationOutcomeFinalEffects(f.value).failureWork).toBeNull();
  },
);

it('uses native outcome request identity/digest and verifies its signed response into the exact transition', () => {
  const f = notificationOutcomeSigningSample();
  expect(f.preparation.request.method).toBe('SIGN_NOTIFICATION_DELIVERY_OUTCOME');
  expect(f.preparation.request.outcomePreparationDigest).toBe(sha256(f.preparation.preparation));
  expect(notificationOutcomeSigningTransition(f.preparation, f.observation)).toEqual(f.f.value);
  const decoded = decodeNotificationOutcomeSigningRow(f.row, f.selector);
  expect(decoded).toMatchObject({ state: 'DISPATCHED', observation: null });
});
it.each(['request', 'digest', 'input', 'metadata', 'extra'])(
  'rejects changed native signing %s',
  (kind) => {
    const f = notificationOutcomeSigningSample(),
      p = structuredClone(f.preparation);
    if (kind === 'request') p.request.payloadHex = f.f.f.original.payloadHex;
    if (kind === 'digest') p.requestDigest = sha256('different');
    if (kind === 'input') p.preparation.input = {};
    if (kind === 'metadata') p.preparation.metadata = {};
    if (kind === 'extra') Object.assign(p, { claimed: true });
    expect(() => validateNotificationOutcomeSigning(p)).toThrow();
  },
);
it('retains first provider signature/rejection and never treats rejection as an outcome transition', () => {
  const f = notificationOutcomeSigningSample();
  expect(
    notificationOutcomeSigningObservation(f.preparation, f.observation, f.observation),
  ).toEqual(f.observation);
  const rejected = {
    ...f.observation,
    outcome: 'REJECTED',
    reason: 'KEY_UNAVAILABLE',
    coseHex: null,
  };
  expect(notificationOutcomeSigningObservation(f.preparation, rejected).outcome).toBe('REJECTED');
  expect(() =>
    notificationOutcomeSigningObservation(f.preparation, rejected, f.observation),
  ).toThrow();
  expect(() => notificationOutcomeSigningTransition(f.preparation, rejected)).toThrow();
});
it.each(['state', 'token', 'clock', 'expired', 'partial', 'digest', 'noncanonical', 'selector'])(
  'rejects inconsistent %s signing journal',
  (kind) => {
    const f = notificationOutcomeSigningSample(),
      row = { ...f.row },
      q = structuredClone(f.selector);
    if (kind === 'state') row.state = 'UNKNOWN';
    if (kind === 'token') row.dispatch_token = null;
    if (kind === 'clock') row.dispatched_at_ms = `0${row.dispatched_at_ms}`;
    if (kind === 'expired')
      row.dispatched_at_ms = String(f.f.value.metadata.recordedAtMs + 86400000);
    if (kind === 'partial') row.observation_digest = sha256('partial');
    if (kind === 'digest') row.preparation_digest = sha256('other');
    if (kind === 'noncanonical') {
      row.preparation_bytes = Buffer.from(` ${row.preparation_bytes.toString()}`);
      row.preparation_digest = sha256(row.preparation_bytes);
    }
    if (kind === 'selector') q.operationId = q.original.operationId;
    expect(() => decodeNotificationOutcomeSigningRow(row, q)).toThrow();
  },
);
it('distinguishes untouched preparation from exact retained native signing observation', () => {
  const f = notificationOutcomeSigningSample();
  expect(
    decodeNotificationOutcomeSigningRow(
      { ...f.row, state: 'PREPARED', dispatch_token: null, dispatched_at_ms: null },
      f.selector,
    ).state,
  ).toBe('PREPARED');
  const bytes = Buffer.from(canonicalJson(f.observation));
  expect(
    decodeNotificationOutcomeSigningRow(
      { ...f.row, state: 'OBSERVED', observation_bytes: bytes, observation_digest: sha256(bytes) },
      f.selector,
    ).observation,
  ).toEqual(f.observation);
  expect(() =>
    decodeNotificationOutcomeSigningRow({ ...f.row, state: 'OBSERVED' }, f.selector),
  ).toThrow();
});
it('joins the signed outcome to the real-original input row identities without claiming atomic publication', () => {
  const f = notificationSignedOutcomeSample();
  expect(
    decodeNotificationSignedOutcomeRow(
      { original: f.f.original, claim: f.f.claim },
      f.firstRow,
      f.row,
    ),
  ).toEqual(f.value);
});
it.each([
  'operation_id',
  'receipt_id',
  'attempt_id',
  'start_operation_id',
  'notification_occurrence_id',
  'worker_installation_digest',
  'signer_installation_digest',
  'delivery_revision',
  'receipt_digest',
  'transition_digest',
] as const)('rejects detached signed-result %s', (field) => {
  const f = notificationSignedOutcomeSample();
  expect(() =>
    decodeNotificationSignedOutcomeRow({ original: f.f.original, claim: f.f.claim }, f.firstRow, {
      ...f.row,
      [field]: 'wrong',
    }),
  ).toThrow();
});
it('rejects a copied claim, another first receipt or replaced signed bytes in result readback', () => {
  const f = notificationSignedOutcomeSample(),
    record = { original: f.f.original, claim: f.f.claim };
  expect(() =>
    decodeNotificationSignedOutcomeRow(
      { ...record, claim: { ...record.claim, claimToken: 'cd'.repeat(32) } },
      f.firstRow,
      f.row,
    ),
  ).toThrow();
  expect(() =>
    decodeNotificationSignedOutcomeRow(
      record,
      { ...f.firstRow, operation_id: f.f.original.receipt.operationId },
      f.row,
    ),
  ).toThrow();
  for (const field of ['receipt_payload', 'cose_sign1'] as const)
    expect(() =>
      decodeNotificationSignedOutcomeRow(record, f.firstRow, {
        ...f.row,
        [field]: Buffer.from('changed'),
      }),
    ).toThrow();
});
it('retains the distinct final operation identity with native first receipt', () => {
  const f = notificationOutcomeSample();
  const result = decodeNotificationOutcomeRow({ original: f.original, claim: f.claim }, f.row);
  expect(result).toEqual({ operationId: f.row.operation_id, observation: f.binding.observation });
  expect(Object.isFrozen(result.observation)).toBe(true);
});
it.each([
  'participant_id',
  'privacy_domain_id',
  'attempt_id',
  'start_operation_id',
  'observation_id',
  'dispatch_claim_token',
  'outcome',
  'observed_at_ms',
  'operation_id',
  'observation_digest',
] as const)('rejects detached %s row metadata', (field) => {
  const f = notificationOutcomeSample(),
    row = { ...f.row, [field]: 'wrong' };
  expect(() => decodeNotificationOutcomeRow({ original: f.original, claim: f.claim }, row)).toThrow(
    'outcome unavailable',
  );
});
it('does not repurpose STARTED/source/attempt as final operation or normalize altered clock text', () => {
  const f = notificationOutcomeSample(),
    record = { original: f.original, claim: f.claim };
  for (const operation_id of [
    f.original.receipt.operationId,
    f.original.sourceOperationId,
    f.original.attempt.attemptId,
  ])
    expect(() => decodeNotificationOutcomeRow(record, { ...f.row, operation_id })).toThrow();
  expect(() =>
    decodeNotificationOutcomeRow(record, { ...f.row, observed_at_ms: `0${f.row.observed_at_ms}` }),
  ).toThrow();
});
it('rejects PENDING or changed claim readback even with a genuine gateway signature', () => {
  const f = notificationOutcomeSample();
  expect(() =>
    decodeNotificationOutcomeRow(
      { original: f.original, claim: { state: 'PENDING', claimToken: null, claimedAtMs: null } },
      f.row,
    ),
  ).toThrow();
  expect(() =>
    decodeNotificationOutcomeRow(
      { original: f.original, claim: { ...f.claim, claimToken: 'cd'.repeat(32) } },
      f.row,
    ),
  ).toThrow();
});

it('accepts only the exact current projection and original claim for a retained signing intent', () => {
  const f = notificationOutcomeSigningSample();
  const record = decodeNotificationOutcomeSigningRow(f.row, f.selector);
  const p = proposeNotificationDeliveryOutcome(record.preparation.preparation.input);
  const actual = {
    record: { original: p.original, claim: p.claim },
    current: p.before,
    first: null,
  };
  expect(() =>
    assertNotificationOutcomeSigningCurrent(record, actual, f.f.value.receipt.recordedAtMs),
  ).not.toThrow();
  for (const cause of [
    'revision',
    'projection',
    'claim',
    'original',
    'first',
    'early',
    'expired',
  ]) {
    const changed = structuredClone(actual);
    let clock = f.f.value.receipt.recordedAtMs;
    if (cause === 'revision')
      changed.current.revision = String(BigInt(changed.current.revision) + 1n);
    if (cause === 'projection')
      changed.current.snapshot.cancelRequested = !changed.current.snapshot.cancelRequested;
    if (cause === 'claim') changed.record.claim.claimToken = 'a'.repeat(64);
    if (cause === 'original') changed.record.original.coseHex = '00';
    if (cause === 'first')
      Object.assign(changed, {
        first: { operationId: f.selector.operationId, observation: p.observation },
      });
    if (cause === 'early') clock--;
    if (cause === 'expired') clock += 86400000;
    expect(() => assertNotificationOutcomeSigningCurrent(record, changed, clock), cause).toThrow();
  }
});
it('never accepts decoded, copied or caller-created records as executable claims', () => {
  const f = notificationOutcomeSigningSample();
  for (const value of [
    {},
    Object.freeze({}),
    f.selector,
    decodeNotificationOutcomeSigningRow(f.row, f.selector),
  ])
    expect(() => consumeNotificationOutcomeSigningClaim(value)).toThrow();
});
