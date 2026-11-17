import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { evidenceScope, digest } from './segment.js';
import { evidenceKmsInstallationInput, evidenceKmsObjectIntent, kmsUuid } from './kms-contracts.js';
import { inspectNotificationPayload } from './notification-payload-crypto.js';

export class NotificationKeyCustodyError extends Error {
  constructor(readonly code: 'INVALID' | 'CONFLICT' | 'INTEGRITY' | 'UNAVAILABLE' | 'UNKNOWN') {
    super(`Notification key custody ${code}`);
  }
}
export const notificationKeyPurpose = 'NOTIFICATION_PAYLOAD' as const;
export const notificationKeyPrepareInput = z.strictObject({
  scope: evidenceScope,
  evidenceExportId: kmsUuid,
  producerTrustDigest: digest,
  kmsInstallationDigest: digest,
  routing: z.strictObject({
    profileId: kmsUuid,
    revision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
    signedProfileDigest: digest,
  }),
});
export const notificationKeySelector = z.strictObject({
  participantId: kmsUuid,
  privacyDomainId: kmsUuid,
  producerTrustDigest: digest,
  kmsInstallationDigest: digest,
  preparationId: kmsUuid,
});
/** Immutable preparation only. Reserved occurrence identity is not an admitted
 * notification, a delivery grant or an assertion that its consumer has closed. */
export const notificationKeyPreparation = z.strictObject({
  purpose: z.literal(notificationKeyPurpose),
  preparationId: kmsUuid,
  occurrenceId: kmsUuid,
  input: notificationKeyPrepareInput,
  sourceEventId: kmsUuid,
  sourceDataDigest: digest,
  sourceReceiptDigest: digest,
  routingInstallationDigest: digest,
  kms: evidenceKmsInstallationInput,
  objectIntent: evidenceKmsObjectIntent,
});
export type NotificationKeyPrepareInput = z.infer<typeof notificationKeyPrepareInput>;
export type NotificationKeySelector = z.infer<typeof notificationKeySelector>;
export type NotificationKeyPreparation = z.infer<typeof notificationKeyPreparation>;
export function parseNotificationKey<T>(schema: z.ZodType<T>, value: unknown): T {
  try {
    return schema.parse(immutableJsonCopy(value));
  } catch {
    throw new NotificationKeyCustodyError('INVALID');
  }
}
export function notificationOccurrenceUrn(id: string): string {
  return `urn:openpc:notification-occurrence:${kmsUuid.parse(id)}`;
}
export function notificationKeyFile(value: NotificationKeyPreparation): string {
  return `notification-${kmsUuid.parse(value.objectIntent.payloadObjectId)}-1.raw`;
}
export function validateNotificationKeyPreparation(value: unknown): NotificationKeyPreparation {
  const p = parseNotificationKey(notificationKeyPreparation, value),
    i = p.input,
    o = p.objectIntent;
  if (
    o.participantId !== i.scope.participantId ||
    o.privacyDomainId !== i.scope.privacyDomainId ||
    o.notificationOccurrenceRef !== notificationOccurrenceUrn(p.occurrenceId) ||
    o.routingProfileDigest !== i.routing.signedProfileDigest ||
    p.kms.participantId !== i.scope.participantId ||
    p.kms.privacyDomainId !== i.scope.privacyDomainId ||
    p.kms.producerTrustDigest !== i.producerTrustDigest ||
    p.kms.environmentId !== o.environmentId ||
    sha256(p.kms) !== i.kmsInstallationDigest
  )
    throw new NotificationKeyCustodyError('INTEGRITY');
  return p;
}
export function decodeNotificationKeyPreparation(bytes: Buffer, expectedDigest: string) {
  try {
    if (
      !Buffer.isBuffer(bytes) ||
      !bytes.length ||
      bytes.length > 32768 ||
      sha256(bytes) !== expectedDigest
    )
      throw new Error();
    const p = validateNotificationKeyPreparation(JSON.parse(bytes.toString('utf8')));
    if (!bytes.equals(Buffer.from(canonicalJson(p)))) throw new Error();
    return p;
  } catch {
    throw new NotificationKeyCustodyError('INTEGRITY');
  }
}
export function assertNotificationKeySelector(
  p: NotificationKeyPreparation,
  selector: NotificationKeySelector,
) {
  if (
    p.preparationId !== selector.preparationId ||
    p.input.scope.participantId !== selector.participantId ||
    p.input.scope.privacyDomainId !== selector.privacyDomainId ||
    p.input.producerTrustDigest !== selector.producerTrustDigest ||
    p.input.kmsInstallationDigest !== selector.kmsInstallationDigest
  )
    throw new NotificationKeyCustodyError('CONFLICT');
}
/** Structural original-ciphertext check. AEAD opening still needs a real KMS
 * DECRYPT lease; this function grants no material or publication authority. */
export function inspectNotificationKeyCiphertext(
  p: NotificationKeyPreparation,
  keyId: string,
  bytes: Buffer,
) {
  const inspected = inspectNotificationPayload(bytes);
  if (canonicalJson(inspected.header.binding) !== canonicalJson({ ...p.objectIntent, keyId }))
    throw new NotificationKeyCustodyError('INTEGRITY');
  return inspected;
}
