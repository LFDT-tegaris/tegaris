import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  decodeNotificationClaim,
  verifyNotificationDeliveryCancellationReceipt,
} from '@openpc/security-kernel';
import { canonicalJson } from '../../../control-api/src/configuration/digest.js';
import { immutableJsonCopy } from '../../../control-api/src/privacy-explorer/immutable.js';
import {
  bindNotificationReceiptSignerWorker,
  validateNotificationCancellationSignerInstallation,
  notificationCancellationSigningPurpose,
} from '../../../control-api/src/notifications/receipt-signer-installation.js';
import {
  NotificationReceiptProviderUnknown,
  notificationReceiptObservationSchema,
  type NotificationReceiptProviderObservation,
  type NotificationReceiptProviderTrust,
} from './notification-receipt-provider.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z.uuidv7();
const requestSchema = z.strictObject({
  schemaVersion: z.literal(1),
  method: z.literal('SIGN_NOTIFICATION_DELIVERY_CANCELLATION'),
  purpose: z.literal(notificationCancellationSigningPurpose),
  signerInstallationDigest: digest,
  providerId: z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
  secretClass: z.literal('SECRET-SIGNING-KEY'),
  reference: z.string().min(1).max(331),
  version: z.string().min(1).max(96),
  keyEpoch: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  signerKeyId: digest,
  environmentId: z.string().min(1).max(160),
  participantId: uuid,
  privacyDomainId: uuid,
  workloadCredentialId: uuid,
  workloadEpoch: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  workerInstallationDigest: digest,
  workerProfileDigest: digest,
  signingAttemptId: uuid,
  operationId: uuid,
  causeOperationId: uuid,
  cancellationPreparationDigest: digest,
  payloadHex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(131072),
});
export type NotificationCancellationReceiptRequest = z.infer<typeof requestSchema>;

/** Closed historical protocol. The restricting owner must separately prove the
 * genuine committed endpoint cause, original source custody, serialized state
 * and a durable exclusive signing claim before any provider perform call. */
export function validateNotificationCancellationReceiptRequest(
  value: unknown,
  trust: NotificationReceiptProviderTrust,
) {
  try {
    const request = immutableJsonCopy(requestSchema.parse(immutableJsonCopy(value)));
    const signer = validateNotificationCancellationSignerInstallation(trust.signer),
      p = signer.pins;
    const payload = Buffer.from(request.payloadHex, 'hex');
    const claims = decodeNotificationClaim('NotificationDeliveryCancellationReceiptV1', payload);
    const worker = bindNotificationReceiptSignerWorker(signer, trust.worker, claims.recordedAtMs);
    if (
      request.signerInstallationDigest !== signer.digest ||
      request.signerKeyId !== signer.signerKeyId ||
      request.reference !== p.secretReference ||
      request.version !== p.secretVersion ||
      [
        'providerId',
        'purpose',
        'secretClass',
        'keyEpoch',
        'environmentId',
        'participantId',
        'privacyDomainId',
        'workloadCredentialId',
        'workloadEpoch',
        'workerInstallationDigest',
        'workerProfileDigest',
      ].some((k) => request[k as keyof typeof request] !== p[k as keyof typeof p]) ||
      claims.receiptId !== request.signingAttemptId ||
      claims.operationId !== request.operationId ||
      claims.causeOperationId !== request.causeOperationId ||
      claims.environmentId !== p.environmentId ||
      claims.participantId !== p.participantId ||
      claims.privacyDomainId !== p.privacyDomainId ||
      claims.workerProfileDigest !== p.workerProfileDigest ||
      claims.routingProfileDigest !== worker.profile.routingProfileDigest ||
      claims.signerKeyId !== signer.signerKeyId
    )
      throw new Error();
    const requestDigest =
      'sha256:' +
      createHash('sha256')
        .update('pc.notification.cancellation-receipt-provider-request.v1\0')
        .update(canonicalJson(request))
        .digest('hex');
    return {
      request,
      claims,
      signer,
      worker,
      payload,
      requestDigest,
      notBeforeMs: claims.recordedAtMs,
      notAfterMs: Math.min(worker.profile.validUntilMs, Number(BigInt(p.validUntilNs) / 1000000n)),
    };
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}

export function createNotificationCancellationReceiptRequest(
  trust: NotificationReceiptProviderTrust,
  value: { payloadHex: string; cancellationPreparationDigest: string },
) {
  try {
    const signer = validateNotificationCancellationSignerInstallation(trust.signer),
      p = signer.pins;
    const selected = requestSchema
      .pick({ payloadHex: true, cancellationPreparationDigest: true })
      .parse(immutableJsonCopy(value));
    const claims = decodeNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      Buffer.from(selected.payloadHex, 'hex'),
    );
    return validateNotificationCancellationReceiptRequest(
      {
        schemaVersion: 1,
        method: 'SIGN_NOTIFICATION_DELIVERY_CANCELLATION',
        purpose: p.purpose,
        signerInstallationDigest: signer.digest,
        providerId: p.providerId,
        secretClass: p.secretClass,
        reference: p.secretReference,
        version: p.secretVersion,
        keyEpoch: p.keyEpoch,
        signerKeyId: signer.signerKeyId,
        environmentId: p.environmentId,
        participantId: p.participantId,
        privacyDomainId: p.privacyDomainId,
        workloadCredentialId: p.workloadCredentialId,
        workloadEpoch: p.workloadEpoch,
        workerInstallationDigest: p.workerInstallationDigest,
        workerProfileDigest: p.workerProfileDigest,
        signingAttemptId: claims.receiptId,
        operationId: claims.operationId,
        causeOperationId: claims.causeOperationId,
        ...selected,
      },
      trust,
    ).request;
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}

export function validateNotificationCancellationReceiptObservation(
  original: NotificationCancellationReceiptRequest,
  value: unknown,
  trust: NotificationReceiptProviderTrust,
  first?: NotificationReceiptProviderObservation,
): NotificationReceiptProviderObservation {
  try {
    const bound = validateNotificationCancellationReceiptRequest(original, trust);
    const observation = immutableJsonCopy(
      notificationReceiptObservationSchema.parse(immutableJsonCopy(value)),
    );
    if (
      observation.providerId !== bound.request.providerId ||
      observation.signingAttemptId !== bound.request.signingAttemptId ||
      observation.requestDigest !== bound.requestDigest
    )
      throw new Error();
    if (observation.outcome === 'SIGNED') {
      if (
        observation.recordedAtMs < bound.notBeforeMs ||
        observation.recordedAtMs >= bound.notAfterMs
      )
        throw new Error();
      verifyNotificationDeliveryCancellationReceipt(
        bound.worker.profile,
        bound.request.workerProfileDigest,
        bound.claims,
        bound.payload,
        Buffer.from(observation.coseHex!, 'hex'),
      );
    }
    if (
      first !== undefined &&
      canonicalJson(validateNotificationCancellationReceiptObservation(original, first, trust)) !==
        canonicalJson(observation)
    )
      throw new Error();
    return observation;
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}

export function validateNotificationCancellationReceiptLookup(
  original: NotificationCancellationReceiptRequest,
  value: unknown,
  trust: NotificationReceiptProviderTrust,
  first?: NotificationReceiptProviderObservation,
) {
  try {
    const bound = validateNotificationCancellationReceiptRequest(original, trust);
    const result = z
      .discriminatedUnion('state', [
        z.strictObject({
          state: z.literal('ABSENT'),
          signingAttemptId: uuid,
          requestDigest: digest,
        }),
        z.strictObject({
          state: z.literal('OBSERVED'),
          observation: notificationReceiptObservationSchema,
        }),
      ])
      .parse(immutableJsonCopy(value));
    if (result.state === 'ABSENT') {
      if (
        first !== undefined ||
        result.signingAttemptId !== bound.request.signingAttemptId ||
        result.requestDigest !== bound.requestDigest
      )
        throw new Error();
      return undefined;
    }
    return validateNotificationCancellationReceiptObservation(
      original,
      result.observation,
      trust,
      first,
    );
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
