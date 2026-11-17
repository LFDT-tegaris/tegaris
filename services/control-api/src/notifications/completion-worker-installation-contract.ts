import { z } from 'zod';
import {
  verifyNotificationCompletionWorkerProfileOriginal,
  verifyInstalledNotificationCompletionWorkerProfile,
} from '../../../../packages/security-kernel/src/notification-gateway/completion-worker-contract.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const positive = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u, { abort: true })
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const text = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$/u);
export const notificationCompletionWorkerInstallation = z.strictObject({
  pins: z.strictObject({
    issuerSpkiHex: hex.length(182),
    signedProfileDigest: digest,
    environmentId: text,
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    profileId: z.uuidv7(),
    revision: positive,
    serviceId: z.literal('LS-CONTROL-WORK'),
    processRole: z.literal('ROLE-CONTROL-WORKER'),
    subscriptionId: z.literal('SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'),
    principalId: z.uuidv7(),
    workloadCredentialId: z.uuidv7(),
    workloadEpoch: positive,
    workloadId: text,
    workloadKeyDigest: digest,
    producerTrustDigest: digest,
  }),
  signed: z.strictObject({ payloadHex: hex.max(131072), coseHex: hex.max(262144) }),
  installationReference: z
    .string()
    .min(1)
    .max(256)
    .refine((v) => v.trim() === v),
});
export class NotificationCompletionWorkerAdmissionError extends Error {
  constructor() {
    super('Notification completion worker admission unavailable');
  }
}
/** Original crypto is distinct from current admission; no caller-selected flag. */
export function validateNotificationCompletionWorkerOriginal(value: unknown) {
  try {
    const input = immutableJsonCopy(
      notificationCompletionWorkerInstallation.parse(immutableJsonCopy(value)),
    );
    const { issuerSpkiHex, ...pins } = input.pins;
    const profile = verifyNotificationCompletionWorkerProfileOriginal(
      { ...pins, issuerSpki: Buffer.from(issuerSpkiHex, 'hex') },
      Buffer.from(input.signed.payloadHex, 'hex'),
      Buffer.from(input.signed.coseHex, 'hex'),
    );
    const bytes = Buffer.from(canonicalJson(input));
    if (bytes.length > 262144) throw new Error();
    return Object.freeze({
      input,
      profile,
      installationDigest: sha256(bytes),
      get bytes() {
        return Buffer.from(bytes);
      },
    });
  } catch {
    throw new NotificationCompletionWorkerAdmissionError();
  }
}
export function validateNotificationCompletionWorkerInstallation(value: unknown, nowMs: number) {
  const original = validateNotificationCompletionWorkerOriginal(value);
  const { issuerSpkiHex, ...pins } = original.input.pins;
  try {
    verifyInstalledNotificationCompletionWorkerProfile(
      { ...pins, issuerSpki: Buffer.from(issuerSpkiHex, 'hex') },
      Buffer.from(original.input.signed.payloadHex, 'hex'),
      Buffer.from(original.input.signed.coseHex, 'hex'),
      nowMs,
    );
    return original;
  } catch {
    throw new NotificationCompletionWorkerAdmissionError();
  }
}
