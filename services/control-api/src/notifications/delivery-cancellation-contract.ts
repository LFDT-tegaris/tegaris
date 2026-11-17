import {
  proposeNotificationDeliveryOutcome,
  validateNotificationDeliveryOutcomeTransition,
} from './delivery-outcome-contract.js';
import { z } from 'zod';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  verifyNotificationDeliveryCancellationReceipt,
  type NotificationDeliveryCancellationReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationRevision } from './endpoint-binding.js';
import { notificationDeliverySourceSelector } from './delivery-source.js';
import { notificationDeliveryStateDigest } from './delivery-start-contract.js';
import { notificationDeliveryDispatchClaim } from './delivery-start-atomic.js';
import { validateNotificationDeliveryStartTransition } from './delivery-start-transition.js';
import {
  notificationWorkerInstallation,
  validateNotificationWorkerInstallation,
} from './worker-installation-contract.js';
import { sha256 } from '../configuration/digest.js';
import {
  notificationDeliveryIdentity,
  notificationDeliverySnapshot,
  planNotificationDelivery,
} from './delivery-policy.js';
import {
  notificationDeliveryBudgetRecord,
  type NotificationDeliveryBudgetRecord,
} from './delivery-start-state.js';

const expectation = notificationDeliveryIdentity.extend({
  expectedRevision: notificationRevision,
});
export type NotificationDeliveryCancellationExpectation = z.infer<typeof expectation>;

export class NotificationDeliveryCancellationContractError extends Error {
  constructor() {
    super('Invalid notification delivery cancellation proposal');
  }
}

/** Pure proposal only: neither caller-supplied records nor matching revisions
 * establish cancellation authority, a committed intent, or external no-effect.
 * The future durable owner must authenticate its initiating contract, reread
 * these bindings under the real fences and atomically retain signed evidence.
 * STARTED/AMBIGUOUS preserve the original outstanding attempt even when no
 * gateway claim is visible. Result/retry consequences belong to delivery-policy.
 */
export function proposeNotificationDeliveryCancellation(
  value: unknown,
  expectedValue: unknown,
  nowMs: number,
): Readonly<NotificationDeliveryBudgetRecord> {
  try {
    const before = notificationDeliveryBudgetRecord.parse(immutableJsonCopy(value));
    const expected = expectation.parse(immutableJsonCopy(expectedValue));
    if (
      before.participantId !== expected.participantId ||
      before.privacyDomainId !== expected.privacyDomainId ||
      before.notificationOccurrenceId !== expected.notificationOccurrenceId ||
      before.payloadDigest !== expected.payloadDigest ||
      before.revision !== expected.expectedRevision
    )
      throw new Error();

    // Strip only already-validated budget provenance to use the existing policy
    // projection. The full record above remains strict and is preserved below.
    const original = notificationDeliverySnapshot.strip().parse(before);
    const plan = planNotificationDelivery(
      { ...original, cancelRequested: true },
      before.attemptLimit,
      nowMs,
    );
    if (plan.action !== 'TERMINAL' && plan.action !== 'RECONCILE') throw new Error();
    // Existing terminal outcomes are immutable, including their cancellation
    // bit. An outstanding send records intent only; policy never erases it.
    const next =
      plan.action === 'TERMINAL' && plan.next.state === original.state ? original : plan.next;
    const revision =
      canonicalJson(next) === canonicalJson(original)
        ? before.revision
        : (BigInt(before.revision) + 1n).toString();
    return immutableJsonCopy(
      notificationDeliveryBudgetRecord.parse({ ...before, ...next, revision }),
    );
  } catch {
    throw new NotificationDeliveryCancellationContractError();
  }
}

/** Exact projection consistency, not an admission, receipt or persistence API.
 * Rejects changes to source, payload, attempt ordinal/time, budget/provenance and
 * revision beyond the proposal. It does not inspect or reset any gateway claim.
 */
export function assertNotificationDeliveryCancellationTransition(
  before: unknown,
  after: unknown,
  expected: unknown,
  nowMs: number,
): void {
  try {
    const proposed = proposeNotificationDeliveryCancellation(before, expected, nowMs);
    const actual = notificationDeliveryBudgetRecord.parse(immutableJsonCopy(after));
    if (canonicalJson(actual) !== canonicalJson(proposed)) throw new Error();
  } catch {
    throw new NotificationDeliveryCancellationContractError();
  }
}

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
/** Historical binding obtained from the actual committed endpoint UPDATE owner.
 * Parsing these identifiers does not authenticate a cause. */
export const notificationCancellationCauseBinding = z.strictObject({
  operationId: z.uuidv7(),
  receiptId: z.uuidv7(),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  environmentId: z.string().min(1).max(160),
  endpointId: z.uuidv7(),
  endpointRevision: notificationRevision,
  successorRevision: notificationRevision,
  profileDigest: digest,
  receiptDigest: digest,
  beforeStateDigest: digest,
  afterStateDigest: digest,
  recordedAtMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
});
export type NotificationDeliveryCancellationCause = z.infer<
  typeof notificationCancellationCauseBinding
>;
export const notificationDeliveryCancellationSelector = z.strictObject({
  source: notificationDeliverySourceSelector,
  causeOperationId: z.uuidv7(),
  expectedRevision: notificationRevision,
});
export type NotificationDeliveryCancellationSelector = z.infer<
  typeof notificationDeliveryCancellationSelector
>;
const signedTransition = z.strictObject({
  schema: z.literal('pc.notification.delivery-cancellation-transition.v1'),
  selector: notificationDeliveryCancellationSelector,
  sourceOperationId: z.uuidv7(),
  sourceReceiptDigest: digest,
  sourceClaims: z.unknown(),
  workerInstallation: notificationWorkerInstallation,
  workerAuthorityDigest: digest,
  cause: notificationCancellationCauseBinding,
  before: notificationDeliveryBudgetRecord,
  after: notificationDeliveryBudgetRecord,
  originalStart: z.unknown(),
  originalClaim: notificationDeliveryDispatchClaim.nullable(),
  originalOutcome: z.unknown().optional(),
  receipt: z.unknown(),
  payloadHex: hex.max(131072),
  coseHex: hex.max(262144),
});

/** Canonical wire and historical projection verification only. The live owner
 * must independently reread cause/source/STARTED/claim and distinct signer
 * admission. This never accepts a callback or caller-provided readiness flag.
 * RETRY_WAIT additionally binds the original signed no-effect outcome. Current
 * SQL publication/cause admission remains independently mandatory.
 */
export function validateNotificationDeliveryCancellationInput(value: unknown) {
  try {
    const p = signedTransition.omit({ coseHex: true }).parse(immutableJsonCopy(value));
    const receipt = decodeNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      Buffer.from(p.payloadHex, 'hex'),
    );
    if (canonicalJson(receipt) !== canonicalJson(p.receipt)) throw new Error();
    const source = decodeNotificationClaim(
      'NotificationDeliveryRequestedReceiptV1',
      encodeNotificationClaim(
        'NotificationDeliveryRequestedReceiptV1',
        p.sourceClaims as NotificationDeliveryRequestedReceiptClaims,
      ),
    );
    if (canonicalJson(source) !== canonicalJson(p.sourceClaims)) throw new Error();
    const worker = validateNotificationWorkerInstallation(
      p.workerInstallation,
      receipt.recordedAtMs,
    );
    const s = p.selector.source;
    const before = p.before;
    if (
      before.cancelRequested ||
      !['PENDING', 'RETRY_WAIT', 'STARTED', 'AMBIGUOUS'].includes(before.state) ||
      worker.installationDigest !== s.worker.installationDigest ||
      receipt.authoritySnapshotDigest !== p.workerAuthorityDigest ||
      source.participantId !== s.worker.participantId ||
      source.privacyDomainId !== s.worker.privacyDomainId ||
      source.notificationOccurrenceId !== s.notificationOccurrenceId ||
      source.eventId !== s.eventId ||
      source.operationId !== p.sourceOperationId ||
      p.sourceReceiptDigest !==
        sha256(encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', source)) ||
      before.deliveryRequestEventId !== source.eventId ||
      before.deliveryRequestOperationId !== source.operationId ||
      before.budgetEnvironmentId !== source.environmentId ||
      before.payloadDigest !== source.payloadDigest ||
      p.cause.operationId !== p.selector.causeOperationId ||
      p.cause.participantId !== source.participantId ||
      p.cause.privacyDomainId !== source.privacyDomainId ||
      p.cause.environmentId !== source.environmentId ||
      p.cause.endpointId !== source.endpointId ||
      p.cause.endpointRevision !== source.endpointRevision ||
      receipt.recordedAtMs < Math.max(source.recordedAtMs, p.cause.recordedAtMs) ||
      receipt.operationId === source.operationId ||
      receipt.receiptId === source.receiptId ||
      receipt.receiptId === p.cause.receiptId ||
      receipt.operationId === receipt.receiptId
    )
      throw new Error();
    assertNotificationDeliveryCancellationTransition(
      before,
      p.after,
      {
        participantId: source.participantId,
        privacyDomainId: source.privacyDomainId,
        notificationOccurrenceId: source.notificationOccurrenceId,
        payloadDigest: source.payloadDigest,
        expectedRevision: p.selector.expectedRevision,
      },
      receipt.recordedAtMs,
    );
    if (p.after.revision !== (BigInt(before.revision) + 1n).toString()) throw new Error();
    if (before.state === 'PENDING') {
      if (p.originalStart !== null || p.originalClaim !== null) throw new Error();
    } else {
      const start = validateNotificationDeliveryStartTransition(p.originalStart);
      if (
        p.originalClaim === null ||
        start.receipt.notificationOccurrenceId !== source.notificationOccurrenceId ||
        start.receipt.participantId !== source.participantId ||
        start.receipt.privacyDomainId !== source.privacyDomainId ||
        start.receipt.sourceEventId !== source.eventId ||
        start.receipt.sourceReceiptDigest !== p.sourceReceiptDigest ||
        start.receipt.payloadDigest !== source.payloadDigest ||
        start.attempt.attemptNumber !== before.attemptCount ||
        start.attempt.startedAtMs !== before.lastStartedAtMs ||
        BigInt(start.receipt.deliveryRevision) >= BigInt(before.revision) ||
        receipt.operationId === start.receipt.operationId ||
        receipt.receiptId === start.receipt.receiptId ||
        (p.originalClaim.state === 'CLAIMED' &&
          (p.originalClaim.claimedAtMs < start.attempt.startedAtMs ||
            p.originalClaim.claimedAtMs >= start.attempt.deadlineAtMs))
      )
        throw new Error();
    }
    if (before.state === 'RETRY_WAIT') {
      const outcome = validateNotificationRetryLineage(
        p.originalOutcome,
        before,
        p.originalStart,
        p.originalClaim,
      );
      if (receipt.recordedAtMs < outcome.receipt.recordedAtMs) throw new Error();
    } else if (p.originalOutcome !== undefined) throw new Error();
    const expected: NotificationDeliveryCancellationReceiptClaims = {
      ...receipt,
      environmentId: source.environmentId,
      participantId: source.participantId,
      privacyDomainId: source.privacyDomainId,
      notificationOccurrenceId: source.notificationOccurrenceId,
      payloadDigest: source.payloadDigest,
      sourceEventId: source.eventId,
      sourceReceiptDigest: p.sourceReceiptDigest,
      workerProfileDigest: worker.input.pins.signedProfileDigest,
      routingProfileDigest: source.routingProfileDigest,
      endpointId: source.endpointId,
      endpointRevision: source.endpointRevision,
      causeOperationId: p.cause.operationId,
      causeAction: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
      causeProfileDigest: p.cause.profileDigest,
      causeReceiptDigest: p.cause.receiptDigest,
      causeBeforeStateDigest: p.cause.beforeStateDigest,
      causeAfterStateDigest: p.cause.afterStateDigest,
      causeEndpointRevision: p.cause.successorRevision,
      deliveryRevision: before.revision,
      beforeStateDigest: notificationDeliveryStateDigest(
        notificationDeliverySnapshot.strip().parse(before),
        before.revision,
      ),
      afterStateDigest: notificationDeliveryStateDigest(
        notificationDeliverySnapshot.strip().parse(p.after),
        p.after.revision,
      ),
      beforeDeliveryState:
        before.state as NotificationDeliveryCancellationReceiptClaims['beforeDeliveryState'],
      afterDeliveryState: p.after
        .state as NotificationDeliveryCancellationReceiptClaims['afterDeliveryState'],
      attemptCount: before.attemptCount,
      disposition:
        before.state === 'PENDING'
          ? 'CANCELLED_BEFORE_START'
          : before.state === 'RETRY_WAIT'
            ? 'PREVENT_LATER_ATTEMPTS'
            : 'RECONCILE_ORIGINAL',
    };
    if (
      !encodeNotificationClaim('NotificationDeliveryCancellationReceiptV1', expected).equals(
        Buffer.from(p.payloadHex, 'hex'),
      )
    )
      throw new Error();
    return immutableJsonCopy({ ...p, receipt, sourceClaims: source });
  } catch {
    throw new NotificationDeliveryCancellationContractError();
  }
}
/** A validated input is not signed or admitted. Only this distinct function
 * verifies the original signature, and durable admission remains independent. */
export function validateSignedNotificationDeliveryCancellation(value: unknown) {
  try {
    const parsed = signedTransition.parse(immutableJsonCopy(value));
    const { coseHex, ...input } = parsed;
    const p = validateNotificationDeliveryCancellationInput(input);
    const worker = validateNotificationWorkerInstallation(
      p.workerInstallation,
      p.receipt.recordedAtMs,
    );
    verifyNotificationDeliveryCancellationReceipt(
      worker.profile,
      worker.input.pins.signedProfileDigest,
      p.receipt,
      Buffer.from(p.payloadHex, 'hex'),
      Buffer.from(coseHex, 'hex'),
    );
    return immutableJsonCopy({ ...p, coseHex });
  } catch {
    throw new NotificationDeliveryCancellationContractError();
  }
}
export type NotificationDeliveryCancellationTransition = ReturnType<
  typeof validateSignedNotificationDeliveryCancellation
>;

export function encodeNotificationDeliveryCancellation(value: unknown) {
  const transition = validateSignedNotificationDeliveryCancellation(value);
  const bytes = Buffer.from(canonicalJson(transition));
  if (bytes.length > 1048576) throw new NotificationDeliveryCancellationContractError();
  return {
    transition,
    bytes,
    digest: sha256(bytes),
    receiptPayload: Buffer.from(transition.payloadHex, 'hex'),
    receiptDigest: sha256(Buffer.from(transition.payloadHex, 'hex')),
    coseSign1: Buffer.from(transition.coseHex, 'hex'),
  };
}
export function decodeNotificationDeliveryCancellation(bytes: Buffer, digest: string) {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length > 1048576 || sha256(bytes) !== digest)
      throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const encoded = encodeNotificationDeliveryCancellation(JSON.parse(text));
    if (!encoded.bytes.equals(bytes)) throw new Error();
    return encoded.transition;
  } catch {
    throw new NotificationDeliveryCancellationContractError();
  }
}
/** Historical cryptographic join only. The caller must separately establish
 * original publication and current SQL/source/lease/native authority. A lowered
 * budget may advance revision; it cannot rewrite the original no-effect result. */
export function validateNotificationRetryLineage(
  outcomeValue: unknown,
  before: NotificationDeliveryBudgetRecord,
  originalStart: unknown,
  originalClaim: unknown,
) {
  try {
    const outcome = validateNotificationDeliveryOutcomeTransition(outcomeValue);
    const proposal = proposeNotificationDeliveryOutcome(outcome.input);
    const after = proposal.after;
    if (
      outcome.receipt.outcome !== 'RETRYABLE_NO_EFFECT' ||
      after.snapshot.state !== 'RETRY_WAIT' ||
      before.state !== 'RETRY_WAIT' ||
      before.cancelRequested ||
      canonicalJson(proposal.original) !== canonicalJson(originalStart) ||
      canonicalJson(proposal.claim) !== canonicalJson(originalClaim) ||
      before.attemptLimit > after.snapshot.attemptLimit ||
      BigInt(before.revision) < BigInt(after.revision) ||
      canonicalJson({
        ...notificationDeliverySnapshot.strip().parse(before),
        attemptLimit: after.snapshot.attemptLimit,
      }) !== canonicalJson(after.snapshot) ||
      before.deliveryRequestEventId !== proposal.original.source.eventId ||
      before.deliveryRequestOperationId !== proposal.original.sourceOperationId ||
      before.budgetEnvironmentId !== outcome.receipt.environmentId
    )
      throw new Error();
    return outcome;
  } catch {
    throw new NotificationDeliveryCancellationContractError();
  }
}
