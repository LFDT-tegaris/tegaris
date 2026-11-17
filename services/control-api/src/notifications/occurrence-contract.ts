import { z } from 'zod';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  evidenceKeyId,
  verifyNotificationWorkerReceipt,
  assertNotificationDeliveryRequestOriginal,
  notificationDeliveryRequestedEnvelope,
  encodeNotificationDeliveryRequestedData,
  type NotificationWorkerProfileClaims,
  type NotificationOccurrenceReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { evidenceScope, digest } from '../evidence/segment.js';
import { notificationOccurrenceUrn } from '../evidence/notification-key-contracts.js';
import { resourceUrnSchema } from '../configuration/resource-contracts.js';
import { notificationWorkerSelector } from './worker-installation.js';
import { parseNotificationDeliveryRequestedEnvelope } from './event-input.js';

export const notificationOccurrenceFamily = z.enum([
  'NotificationOccurrenceReceiptV1',
  'NotificationDeliveryRequestedReceiptV1',
]);
export type NotificationOccurrenceFamily = z.infer<typeof notificationOccurrenceFamily>;
export const notificationOccurrenceSelector = z.strictObject({
  worker: notificationWorkerSelector,
  preparationId: z.uuidv7(),
});
export const notificationOccurrencePrepareInput = z.strictObject({
  worker: notificationWorkerSelector,
  source: z.strictObject({
    scope: evidenceScope.strict(),
    evidenceExportId: z.uuidv7(),
    eventId: z.uuidv7(),
  }),
  keyPreparationId: z.uuidv7(),
});
export type NotificationOccurrencePrepareInput = z.infer<typeof notificationOccurrencePrepareInput>;
export type NotificationOccurrenceSelector = z.infer<typeof notificationOccurrenceSelector>;
export class NotificationOccurrenceError extends Error {
  constructor(readonly code: 'INVALID' | 'CONFLICT' | 'UNAVAILABLE' | 'INTEGRITY' | 'UNKNOWN') {
    super(`Notification occurrence ${code}`);
  }
}
export function parseNotificationOccurrence<T>(schema: z.ZodType<T>, value: unknown): T {
  try {
    return schema.parse(immutableJsonCopy(value));
  } catch {
    throw new NotificationOccurrenceError('INVALID');
  }
}

/** Wire references are projected only from validated owner UUIDs; resource and
 * occurrence namespaces are never interchangeable aliases. */
export function notificationOccurrenceReferences(value: {
  notificationId: string;
  notificationOccurrenceId: string;
  payloadObjectId: string;
}) {
  const p = z
    .strictObject({
      notificationId: z.uuidv7(),
      notificationOccurrenceId: z.uuidv7(),
      payloadObjectId: z.uuidv7(),
    })
    .parse(value);
  return {
    notificationRef: resourceUrnSchema.parse(`urn:openpc:resource:${p.notificationId}`),
    occurrenceRef: notificationOccurrenceUrn(p.notificationOccurrenceId),
    payloadObjectRef: resourceUrnSchema.parse(`urn:openpc:resource:${p.payloadObjectId}`),
  };
}

const retainedInput = z.strictObject({
  schema: z.literal('pc.notification.occurrence-preparation.v1'),
  preparationId: z.uuidv7(),
  family: notificationOccurrenceFamily,
  input: notificationOccurrencePrepareInput,
  workerProfile: z.unknown(),
  workerProfileDigest: digest,
  workerAuthorityDigest: digest,
  payloadHex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(131072),
});
export interface NotificationOccurrencePreparation {
  readonly schema: 'pc.notification.occurrence-preparation.v1';
  readonly preparationId: string;
  readonly family: NotificationOccurrenceFamily;
  readonly input: NotificationOccurrencePrepareInput;
  readonly workerProfile: Readonly<NotificationWorkerProfileClaims>;
  readonly workerProfileDigest: string;
  readonly workerAuthorityDigest: string;
  readonly payloadHex: string;
}

/** Pure consistency check, never worker admission. The SQL/Identity owner supplies
 * the actual installed profile, reserved identities and verified source/custody. */
export function validateNotificationOccurrencePreparation(
  value: unknown,
): NotificationOccurrencePreparation {
  try {
    const p = retainedInput.parse(immutableJsonCopy(value));
    const profile = decodeNotificationClaim(
      'NotificationWorkerProfileV1',
      encodeNotificationClaim(
        'NotificationWorkerProfileV1',
        p.workerProfile as NotificationWorkerProfileClaims,
      ),
    );
    const claims = decodeNotificationClaim(p.family, Buffer.from(p.payloadHex, 'hex'));
    const occurrence = p.family === 'NotificationOccurrenceReceiptV1';
    const worker = p.input.worker,
      source = p.input.source;
    if (
      worker.participantId !== source.scope.participantId ||
      worker.privacyDomainId !== source.scope.privacyDomainId ||
      profile.participantId !== worker.participantId ||
      profile.privacyDomainId !== worker.privacyDomainId ||
      profile.serviceId !== (occurrence ? 'LS-NOTIFICATION' : 'LS-CONTROL-WORK') ||
      profile.subscriptionId !==
        (occurrence
          ? 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'
          : 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1') ||
      claims.participantId !== worker.participantId ||
      claims.privacyDomainId !== worker.privacyDomainId ||
      claims.environmentId !== profile.environmentId ||
      claims.sourceEventId !== source.eventId ||
      claims.keyPreparationId !== p.input.keyPreparationId ||
      claims.workerProfileDigest !== p.workerProfileDigest ||
      claims.authoritySnapshotDigest !== p.workerAuthorityDigest ||
      claims.routingProfileDigest !== profile.routingProfileDigest ||
      claims.signerKeyId !== evidenceKeyId(Buffer.from(profile.receiptSignerSpki, 'hex')) ||
      claims.recordedAtMs < profile.validFromMs ||
      claims.recordedAtMs >= profile.validUntilMs ||
      (!occurrence &&
        (claims as NotificationDeliveryRequestedReceiptClaims).sourceId !== profile.sourceId)
    )
      throw new Error();
    return immutableJsonCopy({ ...p, workerProfile: profile });
  } catch {
    throw new NotificationOccurrenceError('INTEGRITY');
  }
}
export function decodeNotificationOccurrencePreparation(bytes: Buffer, expectedDigest: string) {
  try {
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length < 1 ||
      bytes.length > 262144 ||
      sha256(bytes) !== expectedDigest
    )
      throw new Error();
    const value = validateNotificationOccurrencePreparation(JSON.parse(bytes.toString('utf8')));
    if (!bytes.equals(Buffer.from(canonicalJson(value)))) throw new Error();
    return value;
  } catch {
    throw new NotificationOccurrenceError('INTEGRITY');
  }
}
/** Exact retained signing result only. Never signs, substitutes a new attempt,
 * accepts a callback status, advances a cursor or grants current publication. */
export function verifyNotificationOccurrenceObservation(
  preparation: NotificationOccurrencePreparation,
  cose: Buffer,
) {
  const p = validateNotificationOccurrencePreparation(preparation);
  try {
    const payload = Buffer.from(p.payloadHex, 'hex');
    if (!Buffer.isBuffer(cose) || cose.length < 65 || cose.length > 131072) throw new Error();
    const claims = decodeNotificationClaim(p.family, payload);
    verifyNotificationWorkerReceipt(
      p.family,
      p.workerProfile,
      p.workerProfileDigest,
      claims,
      payload,
      cose,
    );
    return { claims, payload, cose: Buffer.from(cose), receiptDigest: sha256(payload) };
  } catch {
    throw new NotificationOccurrenceError('INTEGRITY');
  }
}
export function assertNotificationOccurrencePair(
  occurrence: NotificationOccurrencePreparation,
  occurrenceCose: Buffer,
  delivery: NotificationOccurrencePreparation,
  deliveryCose: Buffer,
) {
  if (
    occurrence.family !== 'NotificationOccurrenceReceiptV1' ||
    delivery.family !== 'NotificationDeliveryRequestedReceiptV1'
  )
    throw new NotificationOccurrenceError('INTEGRITY');
  const o = verifyNotificationOccurrenceObservation(occurrence, occurrenceCose);
  const d = verifyNotificationOccurrenceObservation(delivery, deliveryCose);
  try {
    if (
      canonicalJson(occurrence.input.source) !== canonicalJson(delivery.input.source) ||
      occurrence.input.keyPreparationId !== delivery.input.keyPreparationId
    )
      throw new Error();
    assertNotificationDeliveryRequestOriginal(
      d.claims as NotificationDeliveryRequestedReceiptClaims,
      o.claims as NotificationOccurrenceReceiptClaims,
    );
    return { occurrence: o, delivery: d };
  } catch {
    throw new NotificationOccurrenceError('INTEGRITY');
  }
}

/** Pure registered event construction from both ORIGINAL verified receipts.
 * This function grants no current worker, route, key, mutation or delivery right.
 * SQL receives DATA CBOR and its raw H32, while the public envelope retains the
 * exact occurrence and endpoint wire fields from the canonical codec. */
export function constructNotificationDeliveryRequestedEvent(
  occurrence: NotificationOccurrencePreparation,
  occurrenceCose: Buffer,
  delivery: NotificationOccurrencePreparation,
  deliveryCose: Buffer,
) {
  const pair = assertNotificationOccurrencePair(occurrence, occurrenceCose, delivery, deliveryCose);
  const claims = pair.delivery.claims as NotificationDeliveryRequestedReceiptClaims;
  const { notificationOccurrenceId, endpointId, templateDigest, payloadDigest } = claims;
  const data = encodeNotificationDeliveryRequestedData({
    notificationOccurrenceId,
    endpointId,
    templateDigest,
    payloadDigest,
  });
  if (sha256(data) !== claims.dataDigest) throw new NotificationOccurrenceError('INTEGRITY');
  // The shared codec derives the registered wire references; the public event
  // contract additionally requires the exact signed DATA digest extension.
  const envelope = parseNotificationDeliveryRequestedEnvelope({
    ...notificationDeliveryRequestedEnvelope(claims),
    datadigest: claims.dataDigest,
  });
  if (
    envelope.data.notificationOccurrenceId !==
      notificationOccurrenceUrn(claims.notificationOccurrenceId) ||
    envelope.data.endpointId !== resourceUrnSchema.parse(`urn:openpc:resource:${claims.endpointId}`)
  )
    throw new NotificationOccurrenceError('INTEGRITY');
  return {
    claims,
    envelope,
    payloadCbor: Buffer.from(data),
    payloadDigest: Buffer.from(claims.dataDigest.slice(7), 'hex'),
    receiptPayload: Buffer.from(pair.delivery.payload),
    receiptCose: Buffer.from(pair.delivery.cose),
  };
}

/** Exact retained-envelope comparison for publication/readback tests. Even a
 * structurally valid envelope cannot substitute foreign scope, sequence, source,
 * namespace, optional fields or a caller-recomputed digest for the signed pair. */
export function bindNotificationDeliveryRequestedEvent(
  value: unknown,
  occurrence: NotificationOccurrencePreparation,
  occurrenceCose: Buffer,
  delivery: NotificationOccurrencePreparation,
  deliveryCose: Buffer,
) {
  const original = constructNotificationDeliveryRequestedEvent(
    occurrence,
    occurrenceCose,
    delivery,
    deliveryCose,
  );
  try {
    const supplied = parseNotificationDeliveryRequestedEnvelope(immutableJsonCopy(value));
    if (canonicalJson(supplied) !== canonicalJson(original.envelope)) throw new Error();
    return original;
  } catch {
    throw new NotificationOccurrenceError('INTEGRITY');
  }
}
