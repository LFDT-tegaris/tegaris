import { createHash } from 'node:crypto';
import { evidenceKeyId } from '../business-transition/cose.js';
import {
  encodeNotificationClaim,
  verifyNotificationClaim,
  type NotificationWorkerProfileClaims,
  type NotificationOccurrenceReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
  type NotificationDeliveryStartedReceiptClaims,
  type NotificationDeliveryCancellationReceiptClaims,
  type NotificationDeliveryOutcomeReceiptClaims,
} from './codec.js';

const digest = (value: Buffer) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const reject = (): never => {
  throw new Error('Notification workload contract rejected');
};
export interface InstalledNotificationWorkerProfile {
  readonly issuerSpki: Buffer;
  readonly signedProfileDigest: string;
  readonly environmentId: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly profileId: string;
  readonly revision: string;
  readonly serviceId: NotificationWorkerProfileClaims['serviceId'];
  readonly processRole: NotificationWorkerProfileClaims['processRole'];
  readonly subscriptionId: NotificationWorkerProfileClaims['subscriptionId'];
  readonly principalId: string;
  readonly workloadCredentialId: string;
  readonly workloadEpoch: string;
  readonly workloadId: string;
  readonly workloadKeyDigest: string;
}

/** Cryptographic/profile admission only. Pins must be read independently from
 * privileged immutable installation. The real TLS/Identity peer, current DB
 * state, authority/route/module/key fences and atomic effect remain mandatory.
 * This value is not an authority capability and must never come from HTTP/event
 * claims. Expired profiles may still be decoded for historical evidence only. */
export function verifyInstalledNotificationWorkerProfile(
  pins: InstalledNotificationWorkerProfile,
  payload: Buffer,
  cose: Buffer,
  nowMs: number,
): Readonly<NotificationWorkerProfileClaims> {
  try {
    if (
      !pins ||
      !Number.isSafeInteger(nowMs) ||
      nowMs < 0 ||
      Object.is(nowMs, -0) ||
      digest(cose) !== pins.signedProfileDigest
    )
      return reject();
    const profile = verifyNotificationClaim(
      'NotificationWorkerProfileV1',
      pins.issuerSpki,
      payload,
      cose,
    );
    for (const name of [
      'environmentId',
      'participantId',
      'privacyDomainId',
      'profileId',
      'revision',
      'serviceId',
      'processRole',
      'subscriptionId',
      'principalId',
      'workloadCredentialId',
      'workloadEpoch',
      'workloadId',
    ] as const)
      if (profile[name] !== pins[name]) return reject();
    if (
      profile.validFromMs > nowMs ||
      profile.validUntilMs <= nowMs ||
      !/^sha256:[0-9a-f]{64}$/u.test(pins.workloadKeyDigest) ||
      evidenceKeyId(Buffer.from(profile.receiptSignerSpki, 'hex')) === pins.workloadKeyDigest ||
      profile.issuerKeyId === pins.workloadKeyDigest
    )
      return reject();
    return Object.freeze(profile);
  } catch {
    return reject();
  }
}

export type NotificationWorkerReceiptFamily =
  'NotificationOccurrenceReceiptV1' | 'NotificationDeliveryRequestedReceiptV1';
/** Exact original prepared bytes and the separately admitted worker profile are
 * inputs from durable owners. This is proof verification, not receipt creation,
 * a current workload lease, SQL admission, signing permission or an outbox ACK. */
export function verifyNotificationWorkerReceipt(
  family: NotificationWorkerReceiptFamily,
  profile: Readonly<NotificationWorkerProfileClaims>,
  signedProfileDigest: string,
  expected: NotificationOccurrenceReceiptClaims | NotificationDeliveryRequestedReceiptClaims,
  payload: Buffer,
  cose: Buffer,
) {
  try {
    encodeNotificationClaim('NotificationWorkerProfileV1', profile);
    if (
      family !== 'NotificationOccurrenceReceiptV1' &&
      family !== 'NotificationDeliveryRequestedReceiptV1'
    )
      return reject();
    const occurrence = family === 'NotificationOccurrenceReceiptV1';
    if (
      profile.serviceId !== (occurrence ? 'LS-NOTIFICATION' : 'LS-CONTROL-WORK') ||
      profile.subscriptionId !==
        (occurrence
          ? 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'
          : 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1') ||
      expected.workerProfileDigest !== signedProfileDigest ||
      expected.environmentId !== profile.environmentId ||
      expected.participantId !== profile.participantId ||
      expected.privacyDomainId !== profile.privacyDomainId ||
      expected.routingProfileDigest !== profile.routingProfileDigest ||
      expected.signerKeyId !== evidenceKeyId(Buffer.from(profile.receiptSignerSpki, 'hex')) ||
      expected.recordedAtMs < profile.validFromMs ||
      expected.recordedAtMs >= profile.validUntilMs ||
      (!occurrence &&
        (expected as NotificationDeliveryRequestedReceiptClaims).sourceId !== profile.sourceId) ||
      !encodeNotificationClaim(family, expected).equals(payload)
    )
      return reject();
    return verifyNotificationClaim(
      family,
      Buffer.from(profile.receiptSignerSpki, 'hex'),
      payload,
      cose,
    );
  } catch {
    return reject();
  }
}

export const notificationDeliveryRequestedNamespace = 'NOTIFICATION_DELIVERY_REQUESTED_V1';
/** Original occurrence must already have been authenticated by its own retained
 * receipt and state owner. A correct comparison grants no publication authority. */
export function assertNotificationDeliveryRequestOriginal(
  request: NotificationDeliveryRequestedReceiptClaims,
  occurrence: NotificationOccurrenceReceiptClaims,
) {
  encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', request);
  const payload = encodeNotificationClaim('NotificationOccurrenceReceiptV1', occurrence);
  if (request.occurrenceReceiptDigest !== digest(payload)) return reject();
  for (const key of [
    'environmentId',
    'participantId',
    'privacyDomainId',
    'notificationId',
    'notificationOccurrenceId',
    'payloadObjectId',
    'keyPreparationId',
    'sourceEventId',
    'sourceDataDigest',
    'sourceReceiptDigest',
    'routingProfileDigest',
    'custodyDigest',
    'endpointId',
    'endpointRevision',
    'templateDigest',
    'payloadDigest',
    'encryptedObjectDigest',
    'keyId',
  ] as const)
    if (request[key] !== occurrence[key]) return reject();
  if (
    request.recordedAtMs < occurrence.recordedAtMs ||
    request.operationId === occurrence.operationId ||
    request.receiptId === occurrence.receiptId
  )
    return reject();
}
/** Wire derivation only. The publisher still owns exact original outbox custody. */
export function notificationDeliveryRequestedEnvelope(
  claims: NotificationDeliveryRequestedReceiptClaims,
) {
  encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', claims);
  return {
    specversion: '1.0' as const,
    id: claims.eventId,
    source: `urn:openpc:service:${claims.sourceId}`,
    type: 'io.openpc.notification.delivery.requested.v1',
    subject: `urn:openpc:notification-occurrence:${claims.notificationOccurrenceId}`,
    time: new Date(claims.recordedAtMs).toISOString().replace('Z', '000Z'),
    datacontenttype: 'application/json' as const,
    dataschema:
      'https://schemas.openpc.local/event-payloads.schema.json#/$defs/NotificationDeliveryRequested',
    participantid: `urn:openpc:participant:${claims.participantId}`,
    privacydomainid: `urn:openpc:privacy-domain:${claims.privacyDomainId}`,
    correlationid: claims.operationId,
    causationid: claims.sourceEventId,
    sequence: claims.sequence,
    data: {
      notificationOccurrenceId: `urn:openpc:notification-occurrence:${claims.notificationOccurrenceId}`,
      endpointId: `urn:openpc:resource:${claims.endpointId}`,
      templateDigest: claims.templateDigest,
      payloadDigest: claims.payloadDigest,
    },
  };
}

/** Historical proof only. START uses its own exact delivery subscription; the
 * occurrence/source publishers remain unable to produce delivery admission. */
export function verifyNotificationDeliveryStartedReceipt(
  profile: Readonly<NotificationWorkerProfileClaims>,
  signedProfileDigest: string,
  expected: NotificationDeliveryStartedReceiptClaims,
  payload: Buffer,
  cose: Buffer,
) {
  try {
    encodeNotificationClaim('NotificationWorkerProfileV1', profile);
    if (
      profile.serviceId !== 'LS-NOTIFICATION' ||
      profile.processRole !== 'ROLE-NOTIFICATION-WORKER' ||
      profile.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' ||
      expected.workerProfileDigest !== signedProfileDigest ||
      expected.environmentId !== profile.environmentId ||
      expected.participantId !== profile.participantId ||
      expected.privacyDomainId !== profile.privacyDomainId ||
      expected.routingProfileDigest !== profile.routingProfileDigest ||
      expected.signerKeyId !== evidenceKeyId(Buffer.from(profile.receiptSignerSpki, 'hex')) ||
      expected.startedAtMs < profile.validFromMs ||
      expected.deadlineAtMs > profile.validUntilMs ||
      !encodeNotificationClaim('NotificationDeliveryStartedReceiptV1', expected).equals(payload)
    )
      return reject();
    return verifyNotificationClaim(
      'NotificationDeliveryStartedReceiptV1',
      Buffer.from(profile.receiptSignerSpki, 'hex'),
      payload,
      cose,
    );
  } catch {
    return reject();
  }
}

/** Consistency with the separately authenticated original publication only.
 * Callers must obtain both proofs from their real signed/durable owners. */
export function assertNotificationDeliveryStartOriginal(
  started: NotificationDeliveryStartedReceiptClaims,
  requested: NotificationDeliveryRequestedReceiptClaims,
): void {
  encodeNotificationClaim('NotificationDeliveryStartedReceiptV1', started);
  const source = encodeNotificationClaim('NotificationDeliveryRequestedReceiptV1', requested);
  for (const field of [
    'environmentId',
    'participantId',
    'privacyDomainId',
    'notificationOccurrenceId',
    'payloadObjectId',
    'keyPreparationId',
    'routingProfileDigest',
    'endpointId',
    'endpointRevision',
    'templateDigest',
    'payloadDigest',
    'encryptedObjectDigest',
    'keyId',
  ] as const)
    if (started[field] !== requested[field]) return reject();
  if (
    started.sourceEventId !== requested.eventId ||
    started.sourceDataDigest !== requested.dataDigest ||
    started.sourceReceiptDigest !== digest(source) ||
    started.operationId === requested.operationId ||
    started.receiptId === requested.receiptId ||
    started.startedAtMs < requested.recordedAtMs
  )
    return reject();
}

/** Historical exact-byte verification only. The caller independently verifies
 * committed endpoint cause and delivery preimages; this is never cancel/send
 * admission, a current worker lease or a substitute for the native signer. */
export function verifyNotificationDeliveryCancellationReceipt(
  profile: Readonly<NotificationWorkerProfileClaims>,
  signedProfileDigest: string,
  expected: NotificationDeliveryCancellationReceiptClaims,
  payload: Buffer,
  cose: Buffer,
) {
  try {
    encodeNotificationClaim('NotificationWorkerProfileV1', profile);
    if (
      profile.serviceId !== 'LS-NOTIFICATION' ||
      profile.processRole !== 'ROLE-NOTIFICATION-WORKER' ||
      profile.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' ||
      expected.workerProfileDigest !== signedProfileDigest ||
      expected.environmentId !== profile.environmentId ||
      expected.participantId !== profile.participantId ||
      expected.privacyDomainId !== profile.privacyDomainId ||
      expected.routingProfileDigest !== profile.routingProfileDigest ||
      expected.signerKeyId !== evidenceKeyId(Buffer.from(profile.receiptSignerSpki, 'hex')) ||
      expected.recordedAtMs < profile.validFromMs ||
      expected.recordedAtMs >= profile.validUntilMs ||
      !encodeNotificationClaim('NotificationDeliveryCancellationReceiptV1', expected).equals(
        payload,
      )
    )
      return reject();
    return verifyNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      Buffer.from(profile.receiptSignerSpki, 'hex'),
      payload,
      cose,
    );
  } catch {
    return reject();
  }
}

/** Historical outcome signature only; original gateway/STARTED and atomic state owners remain mandatory. */
export function verifyNotificationDeliveryOutcomeReceipt(
  profile: Readonly<NotificationWorkerProfileClaims>,
  signedProfileDigest: string,
  expected: NotificationDeliveryOutcomeReceiptClaims,
  payload: Buffer,
  cose: Buffer,
) {
  try {
    encodeNotificationClaim('NotificationWorkerProfileV1', profile);
    if (
      profile.serviceId !== 'LS-NOTIFICATION' ||
      profile.processRole !== 'ROLE-NOTIFICATION-WORKER' ||
      profile.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' ||
      expected.workerProfileDigest !== signedProfileDigest ||
      expected.environmentId !== profile.environmentId ||
      expected.participantId !== profile.participantId ||
      expected.privacyDomainId !== profile.privacyDomainId ||
      expected.routingProfileDigest !== profile.routingProfileDigest ||
      expected.signerKeyId !== evidenceKeyId(Buffer.from(profile.receiptSignerSpki, 'hex')) ||
      expected.recordedAtMs < profile.validFromMs ||
      expected.recordedAtMs >= profile.validUntilMs ||
      !encodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', expected).equals(payload)
    )
      return reject();
    return verifyNotificationClaim(
      'NotificationDeliveryOutcomeReceiptV1',
      Buffer.from(profile.receiptSignerSpki, 'hex'),
      payload,
      cose,
    );
  } catch {
    return reject();
  }
}
