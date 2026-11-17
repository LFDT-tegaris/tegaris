import {
  assertNotificationDeliveryStartOriginal,
  type NotificationDeliveryStartedReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  assertNotificationAttempt,
  type AdapterCallContextV1,
  type InstalledNotificationChannel,
  type NotificationDeliveryAttemptBinding,
} from './gateway-contracts.js';
import {
  notificationDeliverySnapshot,
  planNotificationDelivery,
  type NotificationDeliverySnapshot,
} from './delivery-policy.js';

function revision(value: string): bigint {
  if (
    typeof value !== 'string' ||
    !/^[1-9][0-9]{0,19}$/u.test(value) ||
    BigInt(value) >= 18446744073709551615n
  )
    throw new Error('Invalid notification delivery revision');
  return BigInt(value);
}
export function notificationDeliveryStateDigest(
  value: NotificationDeliverySnapshot,
  version: string,
) {
  const projection = notificationDeliverySnapshot.parse(immutableJsonCopy(value));
  // The terminal successor may use the maximum u64 revision; no further START
  // is possible from it. The preparation boundary separately checks headroom.
  if (
    typeof version !== 'string' ||
    !/^[1-9][0-9]{0,19}$/u.test(version) ||
    BigInt(version) > 18446744073709551615n
  )
    throw new Error('Invalid notification delivery revision');
  return sha256({ schema: 'pc.notification-delivery.state.v1', revision: version, projection });
}

/** Pure joined contract, never SQL, peer, credential, plaintext or send authority.
 * Durable owners supply an authenticated PUBLISHED source, exact installed channel,
 * locked current delivery/revision and verified START receipt. The SQL owner must
 * atomically persist these exact before/after states and original attempt/context
 * bytes with the receipt operation. A later live dispatch admission is mandatory. */
export function assertNotificationDeliveryStartBinding(input: {
  receipt: NotificationDeliveryStartedReceiptClaims;
  source: NotificationDeliveryRequestedReceiptClaims;
  channel: InstalledNotificationChannel;
  attempt: NotificationDeliveryAttemptBinding;
  context: AdapterCallContextV1;
  before: NotificationDeliverySnapshot;
  after: NotificationDeliverySnapshot;
  configuredLimit: number;
}): void {
  const value = immutableJsonCopy(input),
    p = value.receipt;
  assertNotificationDeliveryStartOriginal(p, value.source);
  const checked = assertNotificationAttempt(value.channel, value.attempt, value.context);
  const before = notificationDeliverySnapshot.parse(value.before);
  const after = notificationDeliverySnapshot.parse(value.after);
  const plan = planNotificationDelivery(before, value.configuredLimit, p.startedAtMs);
  const version = revision(p.deliveryRevision);
  if (
    plan.action !== 'START' ||
    canonicalJson(plan.next) !== canonicalJson(after) ||
    before.participantId !== p.participantId ||
    before.privacyDomainId !== p.privacyDomainId ||
    before.notificationOccurrenceId !== p.notificationOccurrenceId ||
    before.payloadDigest !== p.payloadDigest ||
    value.channel.claims.environmentId !== p.environmentId ||
    checked.attempt.notificationOccurrenceId !==
      `urn:openpc:resource:${p.notificationOccurrenceId}` ||
    checked.attempt.endpointId !== `urn:openpc:resource:${p.endpointId}` ||
    checked.attempt.endpointRevision !== p.endpointRevision ||
    checked.attempt.channelProfileDigest !== p.signedChannelProfileDigest ||
    checked.attempt.templateDigest !== p.templateDigest ||
    checked.attempt.payloadDigest !== p.payloadDigest ||
    checked.attempt.attemptId !== p.attemptId ||
    checked.attempt.attemptNumber !== p.attemptNumber ||
    checked.attempt.startedAtMs !== p.startedAtMs ||
    checked.attempt.deadlineAtMs !== p.deadlineAtMs ||
    after.attemptCount !== p.attemptNumber ||
    checked.context.authorizationDigest !== p.authoritySnapshotDigest ||
    checked.context.auditCorrelationId !== p.operationId ||
    sha256(checked.attempt) !== p.attemptDigest ||
    sha256(checked.context) !== p.contextDigest ||
    notificationDeliveryStateDigest(before, p.deliveryRevision) !== p.beforeStateDigest ||
    notificationDeliveryStateDigest(after, (version + 1n).toString()) !== p.afterStateDigest
  )
    throw new Error('Notification STARTED binding rejected');
}
