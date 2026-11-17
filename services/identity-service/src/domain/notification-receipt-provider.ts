import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  decodeNotificationClaim,
  verifyNotificationDeliveryStartedReceipt,
} from '@openpc/security-kernel';
import { canonicalJson } from '../../../control-api/src/configuration/digest.js';
import { immutableJsonCopy } from '../../../control-api/src/privacy-explorer/immutable.js';
import {
  bindNotificationReceiptSignerWorker,
  validateNotificationReceiptSignerInstallation,
  notificationReceiptSigningPurpose,
  type NotificationReceiptSignerInstallation,
} from '../../../control-api/src/notifications/receipt-signer-installation.js';
import type { NotificationWorkerInstallation } from '../../../control-api/src/notifications/worker-installation-contract.js';

const uuid = z.uuidv7(),
  digest = z
    .string()
    .length(71)
    .regex(/^sha256:[0-9a-f]{64}$/u);
const hex = z
  .string()
  .regex(/^(?:[0-9a-f]{2})+$/u)
  .refine((v) => v.trim() === v);
const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const requestSchema = z.strictObject({
  schemaVersion: z.literal(1),
  method: z.literal('SIGN_NOTIFICATION_DELIVERY_STARTED'),
  signerInstallationDigest: digest,
  providerId: z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
  purpose: z.literal(notificationReceiptSigningPurpose),
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
  deliveryAttemptId: uuid,
  deliveryPreparationDigest: digest,
  payloadHex: hex.max(131072),
});
export type NotificationReceiptProviderRequest = z.infer<typeof requestSchema>;
export const notificationReceiptObservationSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    providerId: z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
    signingAttemptId: uuid,
    requestDigest: digest,
    recordedAtMs: time,
    outcome: z.enum(['SIGNED', 'REJECTED']),
    reason: z
      .enum([
        'REVOKED',
        'EXPIRED',
        'WRONG_SCOPE',
        'INVALID_REQUEST',
        'ATTEMPT_CONFLICT',
        'KEY_UNAVAILABLE',
      ])
      .nullable(),
    coseHex: hex.max(133120).nullable(),
  })
  .refine((o) =>
    o.outcome === 'SIGNED'
      ? o.reason === null && o.coseHex !== null
      : o.reason !== null && o.coseHex === null,
  );
export type NotificationReceiptProviderObservation = z.infer<
  typeof notificationReceiptObservationSchema
>;
export class NotificationReceiptProviderUnknown extends Error {
  constructor() {
    super('Notification receipt signing outcome requires reconciliation');
  }
}
export interface NotificationReceiptProviderTrust {
  readonly signer: NotificationReceiptSignerInstallation;
  readonly worker: NotificationWorkerInstallation;
}
/** Transport leaf only. Calling perform requires the future durable owner's
 * exclusive committed DISPATCHED claim. This interface supplies no such claim;
 * it is deliberately not wired to any production route/worker here. No automatic
 * retry follows timeout, ABSENT, UNKNOWN, restart or an expired historical result. */
export interface NotificationReceiptProvider {
  perform(
    request: NotificationReceiptProviderRequest,
  ): Promise<NotificationReceiptProviderObservation>;
  lookup(
    original: NotificationReceiptProviderRequest,
    first?: NotificationReceiptProviderObservation,
  ): Promise<NotificationReceiptProviderObservation | undefined>;
}
export function notificationReceiptRequestDigest(value: NotificationReceiptProviderRequest) {
  try {
    return (
      'sha256:' +
      createHash('sha256')
        .update('pc.notification.receipt-provider-request.v1\0')
        .update(canonicalJson(requestSchema.parse(immutableJsonCopy(value))))
        .digest('hex')
    );
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
/** Pure exact original validation; times are evaluated at the receipt's original
 * start for historical lookup. Current authority must be separately admitted. */
export function validateNotificationReceiptRequest(
  value: unknown,
  trust: NotificationReceiptProviderTrust,
) {
  try {
    const request = immutableJsonCopy(requestSchema.parse(immutableJsonCopy(value)));
    const signer = validateNotificationReceiptSignerInstallation(trust.signer),
      p = signer.pins;
    const payload = Buffer.from(request.payloadHex, 'hex');
    const claims = decodeNotificationClaim('NotificationDeliveryStartedReceiptV1', payload);
    const worker = bindNotificationReceiptSignerWorker(signer, trust.worker, claims.startedAtMs),
      w = worker.profile;
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
      claims.attemptId !== request.deliveryAttemptId ||
      claims.environmentId !== p.environmentId ||
      claims.participantId !== p.participantId ||
      claims.privacyDomainId !== p.privacyDomainId ||
      claims.workerProfileDigest !== p.workerProfileDigest ||
      claims.routingProfileDigest !== w.routingProfileDigest ||
      claims.signerKeyId !== signer.signerKeyId ||
      claims.deadlineAtMs > w.validUntilMs ||
      BigInt(claims.deadlineAtMs) * 1000000n > BigInt(p.validUntilNs)
    )
      throw new Error();
    return {
      request,
      claims,
      worker,
      signer,
      payload,
      requestDigest: notificationReceiptRequestDigest(request),
    };
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
/** Requires original persisted payload/identity inputs from the eventual signing
 * preparation owner. A digest or this pure constructor is not durable admission. */
export function createNotificationReceiptRequest(
  trust: NotificationReceiptProviderTrust,
  value: { payloadHex: string; deliveryPreparationDigest: string },
) {
  try {
    const signer = validateNotificationReceiptSignerInstallation(trust.signer),
      p = signer.pins;
    const selected = z
      .strictObject({ payloadHex: hex.max(131072), deliveryPreparationDigest: digest })
      .parse(immutableJsonCopy(value));
    const c = decodeNotificationClaim(
      'NotificationDeliveryStartedReceiptV1',
      Buffer.from(selected.payloadHex, 'hex'),
    );
    return validateNotificationReceiptRequest(
      {
        schemaVersion: 1,
        method: 'SIGN_NOTIFICATION_DELIVERY_STARTED',
        signerInstallationDigest: signer.digest,
        providerId: p.providerId,
        purpose: p.purpose,
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
        signingAttemptId: c.receiptId,
        operationId: c.operationId,
        deliveryAttemptId: c.attemptId,
        ...selected,
      },
      trust,
    ).request;
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
export function validateNotificationReceiptObservation(
  original: NotificationReceiptProviderRequest,
  value: unknown,
  trust: NotificationReceiptProviderTrust,
  first?: NotificationReceiptProviderObservation,
): NotificationReceiptProviderObservation {
  try {
    const { request, claims, worker, payload, requestDigest } = validateNotificationReceiptRequest(
      original,
      trust,
    );
    const observation = immutableJsonCopy(
      notificationReceiptObservationSchema.parse(immutableJsonCopy(value)),
    );
    if (
      observation.providerId !== request.providerId ||
      observation.signingAttemptId !== request.signingAttemptId ||
      observation.requestDigest !== requestDigest
    )
      throw new Error();
    if (observation.outcome === 'SIGNED') {
      if (
        observation.recordedAtMs < claims.startedAtMs ||
        observation.recordedAtMs >= claims.deadlineAtMs
      )
        throw new Error();
      verifyNotificationDeliveryStartedReceipt(
        worker.profile,
        request.workerProfileDigest,
        claims,
        payload,
        Buffer.from(observation.coseHex!, 'hex'),
      );
    }
    // Retained first result is immutable, even when a different randomized ECDSA
    // signature would also verify. The caller supplies its real durable original.
    if (first !== undefined) {
      const prior = validateNotificationReceiptObservation(original, first, trust);
      if (canonicalJson(prior) !== canonicalJson(observation)) throw new Error();
    }
    return observation;
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
export function validateNotificationReceiptLookup(
  original: NotificationReceiptProviderRequest,
  value: unknown,
  trust: NotificationReceiptProviderTrust,
  first?: NotificationReceiptProviderObservation,
) {
  try {
    const { request, requestDigest } = validateNotificationReceiptRequest(original, trust);
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
        result.signingAttemptId !== request.signingAttemptId ||
        result.requestDigest !== requestDigest
      )
        throw new Error();
      return undefined;
    }
    return validateNotificationReceiptObservation(original, result.observation, trust, first);
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
