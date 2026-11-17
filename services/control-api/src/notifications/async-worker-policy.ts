import { canonicalJson } from '../configuration/digest.js';
import { notificationRetryDelaysMs } from './delivery-policy.js';
import type { NotificationAsyncInputClaims } from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import { encodeNotificationAsync } from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';

export class NotificationAsyncWorkerPolicyError extends Error {
  constructor() {
    super('Notification async worker policy unavailable');
  }
}

/** No defaults. The accepted notification gateway schedule remains canonical;
 * a signed declaration cannot override the notification gateway schedule. */
export function assertNotificationWorkerSchedule(input: NotificationAsyncInputClaims) {
  encodeNotificationAsync('input', input);
  if (canonicalJson(input.retryDelaysMs) !== canonicalJson(notificationRetryDelaysMs))
    throw new NotificationAsyncWorkerPolicyError();
}

function finite(value: number, positive = false) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < (positive ? 1 : 0))
    throw new NotificationAsyncWorkerPolicyError();
  return BigInt(value);
}
/** Derived once from the original published intent; reclaim/retry never moves it. */
export function notificationWorkDeadline(
  input: NotificationAsyncInputClaims,
  publishedAtMs: number,
) {
  assertNotificationWorkerSchedule(input);
  const origin = finite(publishedAtMs);
  const deadline = [
    origin + finite(input.domainDeadlineMs, true),
    origin + finite(input.maximumQueueAgeMs, true),
    finite(input.validUntilMs, true),
  ].reduce((a, b) => (a < b ? a : b));
  if (deadline <= origin || deadline > BigInt(Number.MAX_SAFE_INTEGER))
    throw new NotificationAsyncWorkerPolicyError();
  return Number(deadline);
}
/** Pure resource calculation, never a lease or an admitted SQL reservation. */
export function notificationQueueAdmission(
  input: NotificationAsyncInputClaims,
  observed: { items: number; bytes: number },
  size: { envelopeBytes: number; payloadBytes: number },
): 'ADMIT' | 'PAYLOAD_LIMIT' | 'QUEUE_FULL' {
  assertNotificationWorkerSchedule(input);
  const payload = finite(size.payloadBytes, true);
  const items = finite(observed.items),
    bytes = finite(observed.bytes);
  if (payload > BigInt(input.maximumPayloadBytes)) return 'PAYLOAD_LIMIT';
  if (
    items >= BigInt(input.queueItems) ||
    bytes + finite(size.envelopeBytes, true) > BigInt(input.queueBytes)
  )
    return 'QUEUE_FULL';
  return 'ADMIT';
}
export function notificationLeaseDeadline(
  input: NotificationAsyncInputClaims,
  originalDeadlineMs: number,
  nowMs: number,
) {
  assertNotificationWorkerSchedule(input);
  const now = finite(nowMs),
    original = finite(originalDeadlineMs);
  const until = [now + BigInt(input.leaseMs), original, BigInt(input.validUntilMs)].reduce(
    (a, b) => (a < b ? a : b),
  );
  if (until <= now) throw new NotificationAsyncWorkerPolicyError();
  return Number(until);
}
