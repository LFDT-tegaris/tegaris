import { z } from 'zod';
import { digestSchema, uuidSchema } from '../configuration/resource-contracts.js';

// Notification gateway retries: one initial send, then the five delays below.
export const notificationRetryDelaysMs = Object.freeze([
  5000, 30000, 120000, 600000, 1800000,
] as const);
const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const limit = z.number().int().min(0).max(100);
const identity = {
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  notificationOccurrenceId: uuidSchema,
  payloadDigest: digestSchema,
};
export const notificationDeliveryIdentity = z.strictObject(identity);
export const notificationDeliveryStateValues = [
  'PENDING',
  'RETRY_WAIT',
  'STARTED',
  'AMBIGUOUS',
  'DELIVERED',
  'FAILED',
  'CANCELLED',
  'QUARANTINED',
] as const;
export const notificationDeliveryState = z.enum(notificationDeliveryStateValues);
export const notificationDeliverySnapshot = z
  .strictObject({
    ...identity,
    state: notificationDeliveryState,
    attemptCount: z.number().int().min(0).max(6),
    attemptLimit: z.number().int().min(0).max(6),
    nextAttemptAtMs: time.nullable(),
    lastStartedAtMs: time.nullable(),
    cancelRequested: z.boolean(),
  })
  .refine((value) => {
    if ((value.attemptCount === 0) !== (value.lastStartedAtMs === null)) return false;
    if (value.state === 'PENDING')
      return value.attemptCount === 0 && value.nextAttemptAtMs !== null;
    if (value.state === 'RETRY_WAIT')
      return (
        value.attemptCount > 0 &&
        value.attemptCount < 6 &&
        value.nextAttemptAtMs !== null &&
        value.nextAttemptAtMs > value.lastStartedAtMs!
      );
    if (value.nextAttemptAtMs !== null) return false;
    return !['STARTED', 'AMBIGUOUS', 'DELIVERED'].includes(value.state) || value.attemptCount > 0;
  });
export type NotificationDeliverySnapshot = z.infer<typeof notificationDeliverySnapshot>;
export type NotificationDeliveryIdentity = z.infer<typeof notificationDeliveryIdentity>;
export class NotificationDeliveryPolicyError extends Error {
  constructor() {
    super('Invalid notification delivery transition');
  }
}
function invalid(): never {
  throw new NotificationDeliveryPolicyError();
}
function snapshot(value: NotificationDeliverySnapshot) {
  const parsed = notificationDeliverySnapshot.safeParse(value);
  if (!parsed.success) invalid();
  return parsed.data;
}
function boundedLimit(previous: number, current: number): number {
  if (!limit.safeParse(current).success) invalid();
  return Math.min(previous, current, 6);
}
function clock(nowMs: number): void {
  if (!time.safeParse(nowMs).success) invalid();
}

export function initialDeliverySnapshot(
  occurrence: NotificationDeliveryIdentity,
  configuredLimit: number,
  dueAtMs: number,
): NotificationDeliverySnapshot {
  const parsed = notificationDeliveryIdentity.safeParse(occurrence);
  if (!parsed.success) invalid();
  clock(dueAtMs);
  return {
    ...parsed.data,
    state: 'PENDING',
    attemptCount: 0,
    attemptLimit: boundedLimit(6, configuredLimit),
    nextAttemptAtMs: dueAtMs,
    lastStartedAtMs: null,
    cancelRequested: false,
  };
}

export interface NotificationDeliveryPlan {
  readonly action: 'START' | 'WAIT' | 'RECONCILE' | 'TERMINAL';
  readonly next: NotificationDeliverySnapshot;
}

/** Pure proposal, never dispatch authority. Persist the reduced limit and STARTED
 * attempt under the occurrence/revision fence before I/O. Do not send from an
 * uncommitted plan; P0 must recheck scope, endpoint verification and current owners. */
export function planNotificationDelivery(
  persisted: NotificationDeliverySnapshot,
  configuredLimit: number,
  nowMs: number,
): NotificationDeliveryPlan {
  const prior = snapshot(persisted);
  clock(nowMs);
  const next = { ...prior, attemptLimit: boundedLimit(prior.attemptLimit, configuredLimit) };
  if (next.lastStartedAtMs !== null && nowMs < next.lastStartedAtMs) invalid();
  // Cancellation, retirement or a lower limit must not erase an unresolved original send.
  if (next.state === 'STARTED' || next.state === 'AMBIGUOUS') return { action: 'RECONCILE', next };
  if (['DELIVERED', 'FAILED', 'CANCELLED', 'QUARANTINED'].includes(next.state))
    return { action: 'TERMINAL', next };
  if (next.cancelRequested)
    return { action: 'TERMINAL', next: { ...next, state: 'CANCELLED', nextAttemptAtMs: null } };
  if (next.attemptCount >= next.attemptLimit)
    return { action: 'TERMINAL', next: { ...next, state: 'FAILED', nextAttemptAtMs: null } };
  if (nowMs < next.nextAttemptAtMs!) return { action: 'WAIT', next };
  return {
    action: 'START',
    next: {
      ...next,
      state: 'STARTED',
      attemptCount: next.attemptCount + 1,
      nextAttemptAtMs: null,
      lastStartedAtMs: nowMs,
    },
  };
}

const observation = z.strictObject({
  ...identity,
  attemptNumber: z.number().int().min(1).max(6),
  startedAtMs: time,
  observedAtMs: time,
  outcome: z.enum(['DELIVERED', 'RETRYABLE_NO_EFFECT', 'PERMANENT_FAILURE', 'AMBIGUOUS']),
});
export type NotificationDeliveryObservation = z.infer<typeof observation>;

/** A proposal from an owner-authenticated observation, not a receipt or proof of
 * delivery. P0 must authenticate and atomically retain the original observation,
 * signed outcome and outbox before committing this state. Unknown/lost ACK is
 * AMBIGUOUS; only a definitive no-effect outcome permits another attempt. */
export function planNotificationObservation(
  persisted: NotificationDeliverySnapshot,
  value: NotificationDeliveryObservation,
  configuredLimit: number,
): NotificationDeliverySnapshot {
  const prior = snapshot(persisted);
  const parsed = observation.safeParse(value);
  if (!parsed.success) invalid();
  const actual = parsed.data;
  if (
    !['STARTED', 'AMBIGUOUS'].includes(prior.state) ||
    actual.participantId !== prior.participantId ||
    actual.privacyDomainId !== prior.privacyDomainId ||
    actual.notificationOccurrenceId !== prior.notificationOccurrenceId ||
    actual.payloadDigest !== prior.payloadDigest ||
    actual.attemptNumber !== prior.attemptCount ||
    actual.startedAtMs !== prior.lastStartedAtMs ||
    actual.observedAtMs < actual.startedAtMs
  )
    invalid();
  const next = { ...prior, attemptLimit: boundedLimit(prior.attemptLimit, configuredLimit) };
  if (actual.outcome === 'AMBIGUOUS') return { ...next, state: 'AMBIGUOUS' };
  if (actual.outcome === 'DELIVERED') return { ...next, state: 'DELIVERED' };
  if (actual.outcome === 'PERMANENT_FAILURE') return { ...next, state: 'FAILED' };
  if (next.cancelRequested) return { ...next, state: 'CANCELLED' };
  if (next.attemptCount >= next.attemptLimit) return { ...next, state: 'FAILED' };
  const delay = notificationRetryDelaysMs[next.attemptCount - 1];
  if (delay === undefined) invalid();
  const due = actual.observedAtMs + delay;
  clock(due);
  return { ...next, state: 'RETRY_WAIT', nextAttemptAtMs: due };
}
