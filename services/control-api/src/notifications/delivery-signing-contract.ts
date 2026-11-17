import { z } from 'zod';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  type NotificationDeliveryRequestedReceiptClaims,
  type NotificationDeliveryStartedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  createNotificationReceiptRequest,
  validateNotificationReceiptRequest,
  validateNotificationReceiptObservation,
  type NotificationReceiptProviderObservation,
  type NotificationReceiptProviderTrust,
} from '../../../identity-service/src/domain/notification-receipt-provider.js';
import { validateNotificationDeliveryPreparation } from './delivery-start-preparation.js';
import { notificationDeliverySnapshot } from './delivery-policy.js';
import { assertNotificationDeliveryStartBinding } from './delivery-start-contract.js';
import { validateNotificationDeliveryStartTransition } from './delivery-start-transition.js';
import { notificationDeliverySourceSelector } from './delivery-source.js';

const digest = z
  .string()
  .length(71)
  .regex(/^sha256:[0-9a-f]{64}$/u);
export const notificationDeliverySigningSelector = z.strictObject({
  source: notificationDeliverySourceSelector,
  operationId: z.uuidv7(),
  signerInstallationDigest: digest,
});
export type NotificationDeliverySigningSelector = z.infer<
  typeof notificationDeliverySigningSelector
>;
export class NotificationDeliverySigningError extends Error {
  constructor() {
    super('Notification delivery signing unavailable');
  }
}
const record = z.strictObject({
  schema: z.literal('pc.notification.delivery-signing.v1'),
  deliveryPreparation: z.unknown(),
  sourceClaims: z.unknown(),
  trust: z.strictObject({ signer: z.unknown(), worker: z.unknown() }),
  request: z.unknown(),
  requestDigest: digest,
});
export function notificationSigningSnapshot(before: unknown) {
  return notificationDeliverySnapshot.parse(
    immutableJsonCopy(
      Object.fromEntries(
        Object.entries(z.record(z.string(), z.unknown()).parse(immutableJsonCopy(before))).filter(
          ([key]) =>
            [
              'participantId',
              'privacyDomainId',
              'notificationOccurrenceId',
              'payloadDigest',
              'state',
              'attemptCount',
              'attemptLimit',
              'nextAttemptAtMs',
              'lastStartedAtMs',
              'cancelRequested',
            ].includes(key),
        ),
      ),
    ),
  );
}
/** Exact historical construction only; the state owner supplies real retained
 * preparation, authenticated source and current signer before storing any bytes. */
export function buildNotificationDeliverySigning(input: {
  deliveryPreparation: unknown;
  sourceClaims: NotificationDeliveryRequestedReceiptClaims;
  trust: NotificationReceiptProviderTrust;
  receiptId: string;
}) {
  try {
    const p = validateNotificationDeliveryPreparation(input.deliveryPreparation),
      s = input.sourceClaims,
      t = input.trust;
    const receipt: NotificationDeliveryStartedReceiptClaims = {
      environmentId: s.environmentId,
      participantId: s.participantId,
      privacyDomainId: s.privacyDomainId,
      receiptId: z.uuidv7().parse(input.receiptId),
      operationId: p.operationId,
      attemptId: p.attempt.attemptId,
      notificationOccurrenceId: s.notificationOccurrenceId,
      payloadObjectId: s.payloadObjectId,
      keyPreparationId: s.keyPreparationId,
      sourceEventId: s.eventId,
      sourceDataDigest: s.dataDigest,
      sourceReceiptDigest: p.sourceReceiptDigest,
      routingProfileDigest: s.routingProfileDigest,
      workerProfileDigest: t.signer.workerProfileDigest,
      authoritySnapshotDigest: p.authorityDigest,
      endpointId: s.endpointId,
      endpointRevision: s.endpointRevision,
      templateDigest: s.templateDigest,
      payloadDigest: s.payloadDigest,
      encryptedObjectDigest: s.encryptedObjectDigest,
      keyId: s.keyId,
      signedChannelProfileDigest: p.channel.signedProfileDigest,
      attemptDigest: p.attemptDigest,
      contextDigest: p.contextDigest,
      attemptNumber: p.attempt.attemptNumber,
      startedAtMs: p.attempt.startedAtMs,
      deadlineAtMs: p.attempt.deadlineAtMs,
      deliveryRevision: p.before.revision,
      beforeStateDigest: p.beforeStateDigest,
      afterStateDigest: p.plannedAfterStateDigest,
      signerKeyId: sha256(Buffer.from(t.signer.publicKeySpkiHex, 'hex')),
    };
    const request = createNotificationReceiptRequest(t, {
      payloadHex: encodeNotificationClaim('NotificationDeliveryStartedReceiptV1', receipt).toString(
        'hex',
      ),
      deliveryPreparationDigest: sha256(p),
    });
    return validateNotificationDeliverySigning({
      schema: 'pc.notification.delivery-signing.v1',
      deliveryPreparation: p,
      sourceClaims: s,
      trust: t,
      request,
      requestDigest: validateNotificationReceiptRequest(request, t).requestDigest,
    });
  } catch {
    throw new NotificationDeliverySigningError();
  }
}
export function validateNotificationDeliverySigning(value: unknown) {
  try {
    const raw = record.parse(immutableJsonCopy(value)),
      p = validateNotificationDeliveryPreparation(raw.deliveryPreparation);
    const checked = validateNotificationReceiptRequest(
        raw.request,
        raw.trust as NotificationReceiptProviderTrust,
      ),
      r = checked.claims;
    const source = decodeNotificationClaim(
      'NotificationDeliveryRequestedReceiptV1',
      encodeNotificationClaim(
        'NotificationDeliveryRequestedReceiptV1',
        raw.sourceClaims as NotificationDeliveryRequestedReceiptClaims,
      ),
    );
    if (
      canonicalJson(source) !== canonicalJson(raw.sourceClaims) ||
      raw.requestDigest !== checked.requestDigest ||
      checked.request.deliveryPreparationDigest !== sha256(p) ||
      r.receiptId === p.operationId ||
      r.receiptId === p.attempt.attemptId ||
      r.receiptId === source.receiptId ||
      r.receiptId === p.sourceOperationId ||
      r.operationId !== p.operationId ||
      r.attemptId !== p.attempt.attemptId ||
      checked.signer.pins.workerInstallationDigest !== p.source.worker.installationDigest ||
      checked.signer.pins.workloadCredentialId !== p.workerCredentialId ||
      checked.signer.pins.workloadEpoch !== p.workerEpoch ||
      p.sourceOperationId !== source.operationId ||
      p.source.eventId !== source.eventId ||
      p.source.notificationOccurrenceId !== source.notificationOccurrenceId ||
      p.sourceReceiptDigest !==
        sha256(encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', source)) ||
      r.authoritySnapshotDigest !== p.authorityDigest ||
      r.deliveryRevision !== p.before.revision
    )
      throw new Error();
    assertNotificationDeliveryStartBinding({
      receipt: r,
      source,
      channel: p.channel,
      attempt: p.attempt,
      context: p.context,
      before: notificationSigningSnapshot(p.before),
      after: p.plannedAfter,
      configuredLimit: p.configuredLimit,
    });
    const result = immutableJsonCopy({
      schema: raw.schema,
      deliveryPreparation: p,
      sourceClaims: source,
      trust: { signer: checked.signer.pins, worker: checked.worker.input },
      request: checked.request,
      requestDigest: checked.requestDigest,
    });
    if (Buffer.byteLength(canonicalJson(result)) > 524288) throw new Error();
    return result;
  } catch {
    throw new NotificationDeliverySigningError();
  }
}
export type NotificationDeliverySigningPreparation = ReturnType<
  typeof validateNotificationDeliverySigning
>;
export function decodeNotificationDeliverySigning(bytes: Buffer, expectedDigest: string) {
  try {
    if (
      !Buffer.isBuffer(bytes) ||
      !bytes.length ||
      bytes.length > 524288 ||
      sha256(bytes) !== digest.parse(expectedDigest)
    )
      throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes),
      p = validateNotificationDeliverySigning(JSON.parse(text));
    if (canonicalJson(p) !== text) throw new Error();
    return p;
  } catch {
    throw new NotificationDeliverySigningError();
  }
}
export function notificationSigningObservation(
  p: NotificationDeliverySigningPreparation,
  value: unknown,
  first?: NotificationReceiptProviderObservation,
) {
  return validateNotificationReceiptObservation(p.request, value, p.trust, first);
}
export function notificationSigningTransition(
  p: NotificationDeliverySigningPreparation,
  observation: NotificationReceiptProviderObservation,
) {
  const o = notificationSigningObservation(p, observation);
  if (o.outcome !== 'SIGNED') throw new NotificationDeliverySigningError();
  const d = p.deliveryPreparation;
  return validateNotificationDeliveryStartTransition({
    schema: 'pc.notification.delivery-start-transition.v1',
    sourceOperationId: d.sourceOperationId,
    workerInstallation: p.trust.worker,
    workerInstallationDigest: d.source.worker.installationDigest,
    workerAuthorityDigest: d.authorityDigest,
    receipt: decodeNotificationClaim(
      'NotificationDeliveryStartedReceiptV1',
      Buffer.from(p.request.payloadHex, 'hex'),
    ),
    source: p.sourceClaims,
    channel: d.channel,
    attempt: d.attempt,
    context: d.context,
    before: notificationSigningSnapshot(d.before),
    after: d.plannedAfter,
    configuredLimit: d.configuredLimit,
    payloadHex: p.request.payloadHex,
    coseHex: o.coseHex,
  });
}
