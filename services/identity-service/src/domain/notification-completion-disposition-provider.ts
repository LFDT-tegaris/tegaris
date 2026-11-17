import { createHash } from 'node:crypto';
import { z } from 'zod';
import { decodeNotificationClaim, verifyNotificationClaim } from '@openpc/security-kernel';
import { canonicalJson } from '../../../control-api/src/configuration/digest.js';
import { immutableJsonCopy } from '../../../control-api/src/privacy-explorer/immutable.js';
import {
  bindNotificationCompletionDispositionSignerWorker,
  validateNotificationCompletionDispositionSignerInstallation,
  notificationCompletionDispositionSigningPurpose,
} from '../../../control-api/src/notifications/completion-disposition-signer.js';
import {
  NotificationReceiptProviderUnknown,
  notificationReceiptObservationSchema,
  type NotificationReceiptProviderObservation,
} from './notification-receipt-provider.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z.uuidv7();
const requestSchema = z.strictObject({
  schemaVersion: z.literal(1),
  method: z.literal('SIGN_NOTIFICATION_COMPLETION_DISPOSITION'),
  purpose: z.literal(notificationCompletionDispositionSigningPurpose),
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
  sourceEventId: uuid,
  attemptChainDigest: digest,
  dispositionPreparationDigest: digest,
  payloadHex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(131072),
});
export type NotificationCompletionDispositionRequest = z.infer<typeof requestSchema>;

export interface NotificationCompletionDispositionProviderTrust {
  readonly signer: Parameters<
    typeof validateNotificationCompletionDispositionSignerInstallation
  >[0];
  readonly worker: Parameters<typeof bindNotificationCompletionDispositionSignerWorker>[1];
}
/** Native transport contract only; no DTO here creates a signing capability.
 * perform requires the original durable exclusive DISPATCHED claim, committed
 * through actual completion-worker Identity and separate effect admission. */
export interface NotificationCompletionDispositionProvider {
  perform(
    request: NotificationCompletionDispositionRequest,
  ): Promise<NotificationReceiptProviderObservation>;
  lookup(
    request: NotificationCompletionDispositionRequest,
  ): Promise<NotificationReceiptProviderObservation | undefined>;
  close(): void;
}
/** Closed historical protocol. Original authenticated event, exhaustive attempt
 * journal, current signer and durable exclusive claim are separate admissions. */
export function validateNotificationCompletionDispositionRequest(
  value: unknown,
  trust: NotificationCompletionDispositionProviderTrust,
) {
  try {
    const request = immutableJsonCopy(requestSchema.parse(immutableJsonCopy(value)));
    const signer = validateNotificationCompletionDispositionSignerInstallation(trust.signer),
      p = signer.pins;
    const payload = Buffer.from(request.payloadHex, 'hex');
    const claims = decodeNotificationClaim('NotificationCompletionDispositionReceiptV1', payload);
    const worker = bindNotificationCompletionDispositionSignerWorker(
      signer,
      trust.worker,
      claims.recordedAtMs,
    );
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
      claims.sourceEventId !== request.sourceEventId ||
      claims.attemptChainDigest !== request.attemptChainDigest ||
      claims.signerInstallationDigest !== signer.digest ||
      claims.workerInstallationDigest !== worker.installationDigest ||
      claims.environmentId !== p.environmentId ||
      claims.participantId !== p.participantId ||
      claims.privacyDomainId !== p.privacyDomainId ||
      claims.workerProfileDigest !== p.workerProfileDigest ||
      claims.producerTrustDigest !== worker.profile.producerTrustDigest ||
      claims.signerKeyId !== signer.signerKeyId
    )
      throw new Error();
    const requestDigest =
      'sha256:' +
      createHash('sha256')
        .update('pc.notification.completion-disposition-provider-request.v1\0')
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

export function createNotificationCompletionDispositionRequest(
  trust: NotificationCompletionDispositionProviderTrust,
  value: { payloadHex: string; dispositionPreparationDigest: string },
) {
  try {
    const signer = validateNotificationCompletionDispositionSignerInstallation(trust.signer),
      p = signer.pins;
    const selected = requestSchema
      .pick({ payloadHex: true, dispositionPreparationDigest: true })
      .parse(immutableJsonCopy(value));
    const claims = decodeNotificationClaim(
      'NotificationCompletionDispositionReceiptV1',
      Buffer.from(selected.payloadHex, 'hex'),
    );
    return validateNotificationCompletionDispositionRequest(
      {
        schemaVersion: 1,
        method: 'SIGN_NOTIFICATION_COMPLETION_DISPOSITION',
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
        sourceEventId: claims.sourceEventId,
        attemptChainDigest: claims.attemptChainDigest,
        ...selected,
      },
      trust,
    ).request;
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}

export function validateNotificationCompletionDispositionObservation(
  original: NotificationCompletionDispositionRequest,
  value: unknown,
  trust: NotificationCompletionDispositionProviderTrust,
  first?: NotificationReceiptProviderObservation,
): NotificationReceiptProviderObservation {
  try {
    const bound = validateNotificationCompletionDispositionRequest(original, trust);
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
      verifyNotificationClaim(
        'NotificationCompletionDispositionReceiptV1',
        Buffer.from(bound.signer.pins.publicKeySpkiHex, 'hex'),
        bound.payload,
        Buffer.from(observation.coseHex!, 'hex'),
      );
    }
    if (
      first !== undefined &&
      canonicalJson(
        validateNotificationCompletionDispositionObservation(original, first, trust),
      ) !== canonicalJson(observation)
    )
      throw new Error();
    return observation;
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}

export function validateNotificationCompletionDispositionLookup(
  original: NotificationCompletionDispositionRequest,
  value: unknown,
  trust: NotificationCompletionDispositionProviderTrust,
  first?: NotificationReceiptProviderObservation,
) {
  try {
    const bound = validateNotificationCompletionDispositionRequest(original, trust);
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
    return validateNotificationCompletionDispositionObservation(
      original,
      result.observation,
      trust,
      first,
    );
  } catch {
    throw new NotificationReceiptProviderUnknown();
  }
}
